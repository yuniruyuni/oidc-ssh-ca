// Command oidc-ssh-ca は、GitHub Actions の OIDC トークンを検証し、
// claim に束縛された短命 SSH 証明書を発行するサーバ。
//
// 実装は PLAN.md のマイルストーン順に進める。現時点では claim 照合
// (internal/rule) のみが実装されている。
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "oidc-ssh-ca: not implemented yet (see PLAN.md)")
	os.Exit(1)
}
