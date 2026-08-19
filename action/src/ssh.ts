// ~/.ssh の操作。生成した鍵は使い捨てで、post ステップで消す。

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/** 鍵一式の置き場所。cleanup がこの情報だけで後始末できるようにする。 */
export interface KeyPaths {
  dir: string;
  key: string;
  cert: string;
}

export function sshDir(): string {
  return path.join(os.homedir(), ".ssh");
}

/**
 * 使い捨ての ed25519 鍵を作る。
 *
 * Node で鍵を作って OpenSSH 形式に符号化することもできるが、ssh-keygen に
 * 任せる。この action の利用者は必ず ssh を使うので、ssh-keygen が無い環境は
 * そもそも対象外。自前で符号化して形式を間違えるほうが害が大きい。
 */
export function generateKey(comment: string): KeyPaths {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "oidc-ssh-ca-"));
  fs.chmodSync(dir, 0o700);
  const key = path.join(dir, "id_ed25519");

  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", key], {
    stdio: ["ignore", "ignore", "pipe"],
  });

  // OpenSSH は鍵の隣の <key>-cert.pub を自動で読む。この名前に置くことで、
  // 利用側は CertificateFile を指定しなくても証明書が使われる。
  return { dir, key, cert: `${key}-cert.pub` };
}

export function readPublicKey(paths: KeyPaths): string {
  return fs.readFileSync(`${paths.key}.pub`, "utf8").trim();
}

export function writeCertificate(paths: KeyPaths, certificate: string): void {
  fs.writeFileSync(paths.cert, `${certificate}\n`, { mode: 0o600 });
}

/** 証明書の内容を人が読める形で返す。失敗時の切り分けに使う。 */
export function describeCertificate(paths: KeyPaths): string {
  try {
    return execFileSync("ssh-keygen", ["-L", "-f", paths.cert], { encoding: "utf8" });
  } catch {
    return "(証明書を読めなかった)";
  }
}

export interface HostConfig {
  host: string;
  hostname: string;
  user: string;
}

/** ssh_config へ追記する内容を組み立てる。 */
export function renderHostConfig(cfg: HostConfig, paths: KeyPaths): string {
  return [
    "",
    `# added by oidc-ssh-ca action`,
    `Host ${cfg.host}`,
    `  HostName ${cfg.hostname}`,
    `  User ${cfg.user}`,
    `  IdentityFile ${paths.key}`,
    `  CertificateFile ${paths.cert}`,
    `  IdentitiesOnly yes`,
    `  BatchMode yes`,
    "",
  ].join("\n");
}

export function appendHostConfig(cfg: HostConfig, paths: KeyPaths): string {
  const dir = sshDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, "config");
  fs.appendFileSync(file, renderHostConfig(cfg, paths));
  fs.chmodSync(file, 0o600);
  return file;
}

/**
 * known_hosts を追記する。
 *
 * クライアント側の資格情報を短命にしても、接続先の検証を怠れば中間者に
 * そのまま渡すことになる。ホスト鍵の固定は利用者の責任だが、指定された
 * 場合はここで配置する。
 */
export function appendKnownHosts(entries: string): string {
  const dir = sshDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, "known_hosts");
  fs.appendFileSync(file, `${entries.trim()}\n`);
  fs.chmodSync(file, 0o600);
  return file;
}

/** 生成物を消す。post ステップから呼ぶ。 */
export function removeKey(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

/** ssh_config からこの action が書いた区画を取り除く。 */
export function stripHostConfig(contents: string, host: string): string {
  const marker = "# added by oidc-ssh-ca action";
  const lines = contents.split("\n");
  const out: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === marker && lines[i + 1] === `Host ${host}`) {
      // marker から次の空行までを読み飛ばす。
      i++;
      while (i < lines.length && lines[i]!.trim() !== "") i++;
      continue;
    }
    out.push(lines[i]!);
  }
  return out.join("\n");
}
