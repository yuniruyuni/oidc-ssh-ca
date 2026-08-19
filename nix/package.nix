# oidc-ssh-ca のパッケージ定義。CI (Nix build ジョブ) で検証している。
{ lib, buildGoModule }:

buildGoModule {
  pname = "oidc-ssh-ca";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  # 依存を変更したら CI が報告する値へ更新すること。
  vendorHash = "sha256-WPuhVJ6l+f82dei3Az7tk34vTj4Kih60h0+a2Jmcd3k=";

  # e2e は sshd の起動を伴うためビルドサンドボックス内では実行しない。
  checkFlags = [ "-skip" "TestE2E" ];

  meta = {
    description = "Issue short-lived, claim-bound SSH certificates from GitHub Actions OIDC";
    license = lib.licenses.mit;
    mainProgram = "oidc-ssh-ca";
  };
}
