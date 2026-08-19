# oidc-ssh-ca のパッケージ定義。
{ lib, buildGoModule }:

buildGoModule {
  pname = "oidc-ssh-ca";
  version = "0.1.0";

  src = lib.cleanSource ../.;

  # `nix build` が報告する値に置き換えること。
  vendorHash = lib.fakeHash;

  # e2e は sshd の起動を伴うためビルドサンドボックス内では実行しない。
  checkFlags = [ "-skip" "TestE2E" ];

  meta = {
    description = "Issue short-lived, claim-bound SSH certificates from GitHub Actions OIDC";
    license = lib.licenses.mit;
    mainProgram = "oidc-ssh-ca";
  };
}
