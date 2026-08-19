// action の本体。OIDC トークンを取得し、証明書を受け取って配置する。

import * as core from "@actions/core";

import { requestCertificate } from "./issue.ts";
import {
  appendHostConfig,
  appendKnownHosts,
  describeCertificate,
  generateKey,
  readPublicKey,
  writeCertificate,
} from "./ssh.ts";

async function run(): Promise<void> {
  const endpoint = core.getInput("endpoint", { required: true });
  const audience = core.getInput("audience") || endpoint;
  const host = core.getInput("host");
  const hostname = core.getInput("hostname");
  const sshUser = core.getInput("ssh-user");
  const knownHosts = core.getInput("known-hosts");

  if (host && (!hostname || !sshUser)) {
    throw new Error("host を指定する場合は hostname と ssh-user も必要");
  }

  // getIDToken は取得したトークンを自動でマスクする。手で curl するより
  // 事故が起きにくいので、こちらを使う。
  let token: string;
  try {
    token = await core.getIDToken(audience);
  } catch (e) {
    throw new Error(
      "OIDC トークンを取得できない。workflow に 'permissions: id-token: write' が必要。" +
        ` (${e instanceof Error ? e.message : String(e)})`,
    );
  }

  const paths = generateKey(
    `oidc-ssh-ca ${process.env["GITHUB_REPOSITORY"] ?? ""}#${process.env["GITHUB_RUN_ID"] ?? ""}`,
  );
  // 失敗しても post で必ず消せるよう、生成直後に記録する。
  core.saveState("keyDir", paths.dir);

  const response = await requestCertificate(endpoint, token, readPublicKey(paths));
  writeCertificate(paths, response.certificate);

  // 証明書は秘密ではない。有効期限と principal が見えないと切り分けができない。
  core.info(describeCertificate(paths));

  if (knownHosts) {
    appendKnownHosts(knownHosts);
    core.saveState("knownHostsWritten", "1");
  } else if (host) {
    core.warning(
      "known-hosts が未指定。接続先ホスト鍵を検証できないため、" +
        "中間者攻撃を防げない。ホスト鍵か @cert-authority 行を known-hosts に渡すこと。",
    );
  }

  if (host) {
    appendHostConfig({ host, hostname, user: sshUser }, paths);
    core.saveState("host", host);
  }

  core.setOutput("key-path", paths.key);
  core.setOutput("certificate-path", paths.cert);
  core.setOutput("principals", response.principals.join(","));
  core.setOutput("valid-before", String(response.valid_before));
}

run().catch((e: unknown) => {
  core.setFailed(e instanceof Error ? e.message : String(e));
});

