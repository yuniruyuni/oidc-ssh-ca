# oidc-ssh-ca の NixOS モジュール。
#
# 設定は Nix の属性で書き、TOML を生成する。ルールをここに宣言的に置く
# ことで、「どのリポジトリのどのワークフローに、どの principal と
# force-command を与えるか」が構成管理の対象になる。
#
# CI で評価と設定生成を検証している。実サーバでの運用実績はまだ無い。
{ config, lib, pkgs, ... }:

let
  cfg = config.services.oidc-ssh-ca;

  # rule の属性をそのまま TOML へ写す。値の妥当性はサーバ側が起動時に
  # 検証するため、ここでは形だけを整える。
  # 生成モードでは StateDirectory 上の鍵を、agenix 等から渡す場合は
  # systemd credential として渡された鍵を使う。
  caKeyPath =
    if cfg.generateCAKey
    then "/var/lib/oidc-ssh-ca/ca"
    else "/run/credentials/oidc-ssh-ca.service/ca";

  settings = {
    inherit (cfg) listen;
    ca_key_path = caKeyPath;
    issuer = cfg.issuer;
    rule = cfg.rules;
  };

  # 鍵が無ければ作る。既にあれば触らない。
  generateScript = pkgs.writeShellScript "oidc-ssh-ca-generate" ''
    set -eu
    key=/var/lib/oidc-ssh-ca/ca
    if [ ! -f "$key" ]; then
      ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -C "oidc-ssh-ca" -f "$key"
      echo "CA 鍵を生成した。sshd の TrustedUserCAKeys に $key.pub を設定すること。"
    fi
  '';

  configFile = (pkgs.formats.toml { }).generate "oidc-ssh-ca.toml" settings;
in
{
  options.services.oidc-ssh-ca = {
    enable = lib.mkEnableOption "oidc-ssh-ca";

    package = lib.mkOption {
      type = lib.types.package;
      description = "使用する oidc-ssh-ca パッケージ";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8129";
      description = ''
        待ち受けアドレス。インターネットへ直接晒さず、トンネルや
        リバースプロキシの背後に置くことを想定している。
      '';
    };

    issuer = lib.mkOption {
      type = lib.types.str;
      default = "https://token.actions.githubusercontent.com";
      description = "OIDC issuer";
    };

    caKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        CA 秘密鍵のパス。agenix 等で復号したパスを指定する。
        systemd の LoadCredential 経由で渡すため、サービスユーザに
        直接の読み取り権限は不要。

        null かつ generateCAKey = true の場合は、初回起動時に自動生成する。
      '';
    };

    generateCAKey = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        CA 鍵が無ければ初回起動時に生成する。

        検証やブートストラップ向け。鍵が宣言的な管理の外に出るため、
        再構築で失われると sshd 側の TrustedUserCAKeys も入れ替えが要る。
        本番では caKeyFile で agenix 管理の鍵を渡すこと。
      '';
    };

    caPublicKeyPath = lib.mkOption {
      type = lib.types.str;
      readOnly = true;
      default = "/var/lib/oidc-ssh-ca/ca.pub";
      description = ''
        生成した CA 公開鍵の出力先。sshd の TrustedUserCAKeys に指定する。
        generateCAKey = true のときのみ意味を持つ。
      '';
    };

    rules = lib.mkOption {
      type = lib.types.listOf (lib.types.attrsOf lib.types.anything);
      default = [ ];
      example = lib.literalExpression ''
        [{
          name = "fighter-deploy";
          audience = "https://ssh-ca.example.net";
          repository_id = "1313852776";
          repository_owner_id = "85034901";
          job_workflow_ref = "owner/repo/.github/workflows/deploy.yml@refs/heads/main";
          environment = "production";
          principals = [ "fighter" ];
          force_command = "/run/current-system/sw/bin/app-deploy";
          validity = "5m";
        }]
      '';
      description = "発行ルール。設定の妥当性はサーバが起動時に検証する。";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.rules != [ ];
        message = "services.oidc-ssh-ca.rules が空。ルールが 1 つも無いと起動しない。";
      }
      {
        assertion = (cfg.caKeyFile != null) != cfg.generateCAKey;
        message = "services.oidc-ssh-ca: caKeyFile と generateCAKey はどちらか一方を指定する。";
      }
    ];

    systemd.services.oidc-ssh-ca = {
      description = "OIDC SSH certificate authority";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        ExecStartPre = lib.mkIf cfg.generateCAKey [ "${generateScript}" ];
        ExecStart = "${cfg.package}/bin/oidc-ssh-ca -config ${configFile}";
        StateDirectory = "oidc-ssh-ca";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "5s";

        DynamicUser = true;
        # CA 鍵は systemd が読み、サービスには credential として渡す。
        # サービスユーザにファイルの読み取り権限を与えなくて済む。
        LoadCredential = lib.mkIf (cfg.caKeyFile != null) [ "ca:${toString cfg.caKeyFile}" ];

        # このサービスは鍵に署名して HTTP で返すだけ。それ以外は何も要らない。
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ReadWritePaths = lib.mkIf cfg.generateCAKey [ "/var/lib/oidc-ssh-ca" ];
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
        # JWKS の取得と待ち受けに TCP が要る。
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        CapabilityBoundingSet = "";
        UMask = "0077";
      };
    };
  };
}
