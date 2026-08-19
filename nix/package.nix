# oidc-ssh-ca のパッケージ定義。
#
# ⚠️ このファイルは未検証です。`nix build` を通していません。
#
# vendorHash が lib.fakeHash のままなので、このままではビルドが失敗します
# (fakeHash は「実際の値を教えるためにわざと失敗させる」ための placeholder)。
# 一度ビルドを走らせ、エラーに表示される got: の値へ置き換えてください。
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
