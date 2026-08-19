# oidc-ssh-ca

GitHub Actions の OIDC トークンを検証し、claim に束縛された**短命 SSH 証明書**を発行する単一バイナリ。

CI から自前サーバへ SSH するために、`SSH_PRIVATE_KEY` のような**長期の秘密鍵を GitHub secrets へ置くのをやめる**ためのもの。

## なぜ

クラウド各社は OIDC（Workload Identity Federation 等）に移行したのに、**自前サーバへの SSH だけが取り残されている**。Kamal も Dokku も Coolify も、いまだに長期の鍵かトークンを CI に置かせる。

Teleport や Vault/OpenBao は同じことをやるが、Auth サーバや unseal を伴う。VPS 1 台には過剰。

## できること

```yaml
permissions:
  id-token: write        # これが要る

steps:
  # 認可を担う action なので commit SHA で固定することを推奨する。
  - uses: yuniruyuni/oidc-ssh-ca/action@<commit-sha>  # v0.1.0
    with:
      endpoint: https://ssh-ca.example.net
      host: prod
      hostname: prod.example.net
      ssh-user: deploy
      known-hosts: ${{ vars.PROD_KNOWN_HOSTS }}

  - run: ssh prod deploy "$DIGEST"
```

鍵と証明書は**ジョブ終了時に削除される**。

### action の入出力

| 入力 | 必須 | 説明 |
|---|---|---|
| `endpoint` | ✓ | oidc-ssh-ca の URL |
| `audience` | | 既定は `endpoint` と同じ値 |
| `known-hosts` | | `known_hosts` へ追記する行。ホスト鍵か `@cert-authority` 行 |
| `host` / `hostname` / `ssh-user` | | 指定すると `ssh_config` に接続設定を書く |

| 出力 | 説明 |
|---|---|
| `key-path` / `certificate-path` | 生成物のパス |
| `principals` / `valid-before` | 証明書の内容 |

> `host` を使うのに `known-hosts` を指定しないと警告する。
> クライアント側の資格情報を短命にしても、**接続先を検証しなければ
> 中間者にそのまま渡すことになる**。

サーバ側は、**どのリポジトリのどのワークフローに、どの principal と `force-command` を与えるか**だけを書く。

```toml
listen      = "127.0.0.1:8129"
ca_key_path = "/etc/oidc-ssh-ca/ca"

[[rule]]
name                = "fighter-deploy"
audience            = "https://ssh-ca.example.net"
repository_id       = "1313852776"
repository_owner_id = "85034901"
job_workflow_ref    = "owner/repo/.github/workflows/deploy.yml@refs/heads/main"
environment         = "production"

principals    = ["fighter"]
force_command = "/usr/local/bin/app-deploy"
validity      = "5m"
```

得られる性質:

- **GitHub secrets から長期 credential が消える**
- fork / PR / 別ワークフローからの実行は claim 不一致で通らない
- 失効は設定 1 行の削除
- `force-command` を証明書に焼けるため、**認証情報の能力そのもの**を絞れる。
  鍵が漏れても「決められたスクリプトを実行する」以上のことはできない

## セットアップ

```bash
# 1. CA 鍵を作る
ssh-keygen -t ed25519 -N '' -C oidc-ssh-ca -f /etc/oidc-ssh-ca/ca

# 2. 設定を書いて検証する
oidc-ssh-ca -config /etc/oidc-ssh-ca/config.toml -check-config

# 3. sshd に置く CA 公開鍵を取り出す
oidc-ssh-ca -config /etc/oidc-ssh-ca/config.toml -show-ca-key
```

`sshd_config`:

```
TrustedUserCAKeys        /etc/ssh/oidc-ssh-ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

`endpoint` はインターネットへ直接晒さず、Cloudflare Tunnel などの背後に置くことを想定している。

NixOS モジュールは [`nix/module.nix`](./nix/module.nix)。

## 設定

| キー | 必須 | 説明 |
|---|---|---|
| `listen` | | 待ち受けアドレス（既定 `127.0.0.1:8080`） |
| `ca_key_path` | ✓ | CA 秘密鍵 |
| `issuer` | | 既定は GitHub |

ルール（`[[rule]]`）:

| キー | 必須 | 説明 |
|---|---|---|
| `name` | ✓ | ログに出る識別子 |
| `audience` | ✓ | トークンの `aud`。他サービス向けトークンの持ち込みを防ぐ |
| `repository_id` | ✓ | **数値 ID**。リネームと名前の再取得に強い |
| `repository_owner_id` | | 数値 ID |
| `workflow_ref` | ※ | 起点のワークフロー |
| `job_workflow_ref` | ※ | 実際に実行中の（再利用）ワークフロー |
| `environment` | | GitHub Environment |
| `ref` | | `refs/heads/main` など |
| `principals` | ✓ | 発行する principal |
| `force_command` | | 絶対パス。指定すると SSH でこれ以外実行できない |
| `extensions` | | 既定は空。`permit-pty` などを明示的に許可する場合のみ |
| `validity` | ✓ | 上限 15 分 |

※ `workflow_ref` と `job_workflow_ref` の**少なくとも一方**が必要。
両方指定すれば、再利用ワークフローが別の呼び出し元から叩かれる経路も塞げる。

**設定された制約はすべて完全一致**で評価される。前方一致も正規表現も無い。
不正な設定ではプロセスが起動しない。

## 設計

判断の分担:

| 層 | 問い |
|---|---|
| `internal/verify` | トークンは本物か（署名・issuer・有効期限） |
| `internal/rule` | その本物のトークンに発行してよいか |
| `internal/ca` | 証明書をどう組み立てるか |
| `internal/server` | 上記を繋いで HTTP に載せる |

**`internal/rule` がこのツールで唯一「自分で判断を下す」部分**なので、I/O を持たない純粋関数にして否定ケースを網羅している。
署名検証・JWKS のローテーション・証明書の組み立ては成熟ライブラリに委譲する。

詳細と、そう決めた理由は [PLAN.md](./PLAN.md)。

## 検査

```bash
go test ./...                      # 単体 + e2e
OIDC_SSH_CA_SKIP_E2E=1 go test ./...  # sshd を起動しない
```

- **単体テスト** — claim 照合の否定ケース、設定の検証、証明書の組み立て、JWT 検証（`alg: none`・HS256・未知の署名鍵・期限切れ・issuer 違い）
- **e2e** — 実際の OpenSSH `sshd` を起動し、`force-command` の強制、証明書無し・principal 違い・信頼していない CA の拒否を確認
- **action の単体テスト** — 失敗時の出力にトークンが混ざらないこと（400/401/403/500 と接続失敗の全経路）、応答の検証、`ssh_config` の追記と除去
- **self test**（[`.github/workflows/selftest.yml`](./.github/workflows/selftest.yml)）— **本物の GitHub OIDC トークン**で証明書を取得し、実際の sshd へ接続する。claim 名や形式の思い違いはここで露見する

`dist/` はコミットされている。CI がソースとの同期を検査するため、`action/src` を変更したら `npm run build` の結果も commit する。

## 状態

**動作するが、実運用の実績はまだ無い。** インターフェースは変わりうる。

**このツールは SSH の認可を担う。** 利用前に [SECURITY.md](./SECURITY.md) の
「防がないもの」と「既知の制限」に目を通すこと。特に以下は範囲外:

- 接続先ホストの検証 (`known_hosts` は利用者の責任)
- `force-command` の先で実行されるスクリプトの安全性
- レート制限 (トンネルやリバースプロキシの背後に置くこと)

`nix/` 配下は**未検証**。`nix build` を通していない。

## ライセンス

MIT
