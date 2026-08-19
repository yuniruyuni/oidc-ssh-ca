# oidc-ssh-ca

GitHub Actions の OIDC トークンを検証し、claim に束縛された**短命 SSH 証明書**を発行する単一バイナリ。

CI から自前サーバへ SSH するために、`SSH_PRIVATE_KEY` のような長期の秘密鍵を GitHub secrets へ置くのをやめるためのもの。

```
- name: Get SSH certificate
  uses: yuniruyuni/oidc-ssh-ca/action@v1
  with:
    endpoint: https://ssh-ca.example.net

- run: ssh fighter-vm deploy "$DIGEST"
```

サーバ側は、どのリポジトリのどのワークフローに、どの principal と `force-command` を与えるかだけを書く。

```toml
[[rule]]
repository_id    = "1313852776"
job_workflow_ref = "owner/repo/.github/workflows/deploy.yml@refs/heads/main"
environment      = "production"

principals    = ["fighter"]
force_command = "/usr/local/bin/app-deploy"
validity      = "5m"
```

- GitHub secrets から長期 credential が消える
- fork / PR / 別ワークフローからの実行は claim 不一致で通らない
- 失効は設定 1 行の削除
- 証明書に `force-command` を焼けるため、認証情報の**能力そのもの**を絞れる

## 状態

**開発中。まだ動かない。** 設計と方針は [PLAN.md](./PLAN.md) を参照。

## ライセンス

MIT
