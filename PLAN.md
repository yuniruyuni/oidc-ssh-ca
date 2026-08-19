# oidc-ssh-ca — 設計計画

GitHub Actions の OIDC トークンを検証し、claim に束縛された**短命 SSH 証明書**を発行する単一バイナリ。

## 解決する問題

VPS へデプロイする CI は、いまだに `SSH_PRIVATE_KEY` のような**長期の秘密鍵**を GitHub secrets に置いている。クラウド各社は OIDC (Workload Identity Federation 等) に移行したのに、**自前サーバへの SSH だけが取り残されている**。

このツールは、その穴を埋める。

- GitHub secrets から長期 credential が消える
- fork / PR / 別ワークフローからの実行は claim 不一致で通らない
- 失効は設定ファイルの 1 行削除
- 証明書に `force-command` を焼けるので、**認証情報の能力そのものを絞れる**

## 位置づけ

| | 認証 | 重さ |
|---|---|---|
| Kamal / Dokku / Coolify | **長期 SSH 鍵 or トークン** | 軽 |
| Teleport Machine ID | OIDC (claim 束縛) | **Auth + Proxy が必要** |
| HashiCorp Vault / OpenBao SSH engine | OIDC (claim 束縛) | **状態あり・unseal 必要** |
| **oidc-ssh-ca** | **OIDC (claim 束縛)** | **単一バイナリ + 設定ファイル** |

「これだけをやる」ものが存在しない、というのが出発点。

## 動作

```
POST /issue
  Authorization: Bearer <GitHub Actions OIDC JWT>
  { "public_key": "ssh-ed25519 AAAA..." }
      |
      v
  1. JWT 検証 (署名 / iss / aud / exp)   -- go-oidc に委譲
  2. claim をルールに照合                 -- 純粋関数。ここが本体
  3. 一致したルールの設定で証明書に署名    -- x/crypto/ssh
      |
      v
  { "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA..." }
```

## 設定例

```toml
[[rule]]
name                = "fighter-deploy"
audience            = "https://ssh-ca.example.net"
repository_id       = "1313852776"
repository_owner_id = "85034901"
workflow_ref        = "owner/repo/.github/workflows/deploy.yml@refs/heads/main"
job_workflow_ref    = "owner/repo/.github/workflows/deploy.yml@refs/heads/main"
environment         = "production"

principals    = ["fighter"]
force_command = "/usr/local/bin/app-deploy"
extensions    = []      # 既定で全部剥がす
validity      = "5m"
```

## セキュリティ不変条件

**これを外すと全部無意味になる。実装とレビューはここを最優先で見る。**

1. **リクエストボディを認可判断に一切使わない。**
   `principals` / `force_command` / `validity` は必ず**一致したルール由来**。
   クライアントが指定できるのは公開鍵だけ。

2. **fail closed。**
   claim の欠落、パース失敗、未知のルール項目 → すべて deny。
   「必須項目が 1 つでも欠けたら deny」の向きで書く。項目の追加忘れが fail-open にならないように。

3. **`repository` ではなく `repository_id` を使う。**
   リポジトリのリネームと、解放された名前の再取得に強い。
   `repository_owner_id` も同様。

4. **`workflow_ref` と `job_workflow_ref` の両方を束縛できること。**
   前者は起点のワークフロー、後者は実際に実行中の再利用ワークフロー。
   片方だけだと、再利用ワークフローが別の呼び出し元から叩かれる隙が残る。

5. **完全一致のみ。正規表現・前方一致を既定にしない。**
   この種のツールの事故はほぼここから出る。

6. **`alg` は RS256 に固定し `none` を明示的に拒否。**

7. **証明書の有効期限に上限。** 既定 5 分、上限 15 分。

8. **不在と空文字を型で区別する。**
   Go のゼロ値は罠。`""` と「claim 不在」が誤って一致してはいけない。

9. **発行のたびに claim 一式・principals・証明書 serial を記録。**

10. **`aud` は再生防止であって認可の主役ではない。**
    GitHub の audience は呼び出し側が選べる。主たる制御は repo / workflow claim。

## 実装方針

- **claim 照合は I/O を含まない純粋関数**に切り出す。テストしやすさが唯一の実質的な防御。
- **否定ケースのテーブル駆動テスト**を最初に書く:
  repo 違い / owner 違い / workflow 違い / environment 違い / ref 違い /
  期限切れ / aud 違い / claim 欠落 / 空文字 / `alg: none` / 署名不正。
- JWT の署名検証・JWKS の取得とローテーションは **`coreos/go-oidc`** に委譲する。
  `golang-jwt/jwt` は歴史的に alg 混同の事故があるため使わない。
- 証明書の組み立ては **`golang.org/x/crypto/ssh`**。
  Vault の SSH secrets engine と Teleport の先行実装を参照する。

## v1 スコープ

**入れる**
- GitHub Actions OIDC の検証
- ルールによる claim 束縛
- ユーザ証明書の発行（principals / force-command / extensions / validity）
- 設定ファイル (TOML)
- 構造化ログ
- 連携用 GitHub Action（鍵生成 → トークン取得 → 発行要求 → `~/.ssh` 設定）

**入れない**
- ホスト証明書
- GitHub 以外の issuer（拡張可能な構造にはするが実装しない）
- 失効リスト（短寿命で代替）
- Web UI / マルチテナント
- CA 鍵の HSM 連携（署名をインターフェースとして切り、後から差し替え可能にする）

## マイルストーン

1. **claim 照合 + 否定ケーステスト**  ← ここから始める
2. 設定ファイルの読み込みと検証（起動時に不正な設定を落とす）
3. JWT 検証 (`go-oidc`) の組み込み
4. SSH 証明書の署名
5. HTTP サーバと構造化ログ
6. 統合テスト（実際に sshd に食わせて受理/拒否を確認する）
7. GitHub Action 側のヘルパー
8. NixOS モジュール

**サーバ単体では誰も使わない。**7 まで到達して初めて `ssh host deploy $DIGEST` と書ける。

## 未決

- 名前（`oidc-ssh-ca` は仮）
- リプレイ対策として `jti` の単回使用を強制するか（v1 に入れるか v2 か）
- CA 鍵の保持方法（v1 はプロセス内。署名をインターフェース化して後で隔離）
