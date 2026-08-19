import assert from "node:assert/strict";
import { test } from "node:test";

import { renderHostConfig, stripHostConfig } from "./ssh.ts";

const paths = { dir: "/tmp/x", key: "/tmp/x/id_ed25519", cert: "/tmp/x/id_ed25519-cert.pub" };

test("ssh_config の区画を組み立てる", () => {
  const out = renderHostConfig({ host: "prod", hostname: "prod.example.net", user: "deploy" }, paths);
  assert.match(out, /Host prod/);
  assert.match(out, /HostName prod\.example\.net/);
  assert.match(out, /User deploy/);
  assert.match(out, /IdentitiesOnly yes/);
});

test("書いた区画だけを取り除く", () => {
  const before = "Host other\n  HostName other.example.net\n";
  const contents = before + renderHostConfig({ host: "prod", hostname: "h", user: "u" }, paths);

  const after = stripHostConfig(contents, "prod");
  assert.ok(!after.includes("Host prod"), "自分の区画が残っている");
  assert.ok(after.includes("Host other"), "他の設定を巻き込んで消している");
});

test("対象が無ければ何も変えない", () => {
  const contents = "Host other\n  HostName other.example.net\n";
  assert.equal(stripHostConfig(contents, "prod"), contents);
});
