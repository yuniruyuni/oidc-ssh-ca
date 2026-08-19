// post ステップ。ジョブが終わったら鍵と証明書を消す。
//
// GitHub ホストのランナーは使い捨てなので実害は小さいが、self-hosted では
// 次のジョブに残る。証明書は短命でも、鍵が残ること自体が不必要な露出。

import * as core from "@actions/core";
import * as fs from "node:fs";
import * as path from "node:path";

import { removeKey, sshDir, stripHostConfig } from "./ssh.ts";

function run(): void {
  const dir = core.getState("keyDir");
  if (dir) {
    removeKey(dir);
    core.debug(`削除した: ${dir}`);
  }

  const host = core.getState("host");
  if (host) {
    const file = path.join(sshDir(), "config");
    try {
      const contents = fs.readFileSync(file, "utf8");
      fs.writeFileSync(file, stripHostConfig(contents, host), { mode: 0o600 });
    } catch (e) {
      core.debug(`ssh_config を戻せなかった: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}

try {
  run();
} catch (e) {
  // 後始末の失敗でジョブを落とさない。
  core.warning(`後始末に失敗: ${e instanceof Error ? e.message : String(e)}`);
}
