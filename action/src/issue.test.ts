import assert from "node:assert/strict";
import { test } from "node:test";

import { IssueError, requestCertificate } from "./issue.ts";

function fakeFetch(status: number, body: string): typeof fetch {
  return (async () =>
    new Response(body, { status, headers: { "content-type": "application/json" } })) as typeof fetch;
}

test("成功時に証明書を返す", async () => {
  const got = await requestCertificate(
    "https://ca.example.net",
    "tok",
    "ssh-ed25519 AAAA",
    fakeFetch(200, JSON.stringify({ certificate: "cert-line ", principals: ["fighter"], valid_before: 42 })),
  );
  assert.equal(got.certificate, "cert-line");
  assert.deepEqual(got.principals, ["fighter"]);
  assert.equal(got.valid_before, 42);
});

test("末尾のスラッシュを重複させない", async () => {
  let seen = "";
  const spy = (async (url: string | URL) => {
    seen = String(url);
    return new Response(JSON.stringify({ certificate: "c" }), { status: 200 });
  }) as unknown as typeof fetch;

  await requestCertificate("https://ca.example.net///", "tok", "pk", spy);
  assert.equal(seen, "https://ca.example.net/issue");
});

test("401 は設定の確認を促す", async () => {
  await assert.rejects(
    () => requestCertificate("https://ca.example.net", "tok", "pk", fakeFetch(401, `{"error":"unauthorized"}`)),
    (e: unknown) => e instanceof IssueError && e.status === 401 && /audience/.test(e.message),
  );
});

test("403 はルール不一致として説明する", async () => {
  await assert.rejects(
    () => requestCertificate("https://ca.example.net", "tok", "pk", fakeFetch(403, `{"error":"forbidden"}`)),
    (e: unknown) => e instanceof IssueError && e.status === 403 && /workflow_ref/.test(e.message),
  );
});

// エラー出力にトークンが混ざらないこと。混ざると失敗ログから
// 短命とはいえ有効なトークンが読めてしまう。
test("失敗時のメッセージにトークンを含めない", async () => {
  const token = "SUPER-SECRET-TOKEN-VALUE";
  for (const status of [400, 401, 403, 500]) {
    await assert.rejects(
      () => requestCertificate("https://ca.example.net", token, "pk", fakeFetch(status, "body")),
      (e: unknown) => e instanceof Error && !e.message.includes(token),
    );
  }
});

test("接続できない場合もトークンを含めない", async () => {
  const token = "SUPER-SECRET-TOKEN-VALUE";
  const boom = (async () => {
    throw new Error(`connect failed with ${token}`);
  }) as typeof fetch;
  await assert.rejects(
    () => requestCertificate("https://ca.example.net", token, "pk", boom),
    (e: unknown) => e instanceof Error && !e.message.includes(token),
  );
});

test("JSON でない応答を拒否する", async () => {
  await assert.rejects(
    () => requestCertificate("https://ca.example.net", "tok", "pk", fakeFetch(200, "<html>")),
    (e: unknown) => e instanceof IssueError && /JSON/.test(e.message),
  );
});

test("証明書が空の応答を拒否する", async () => {
  for (const body of [`{}`, `{"certificate":""}`, `{"certificate":"   "}`, `{"certificate":123}`]) {
    await assert.rejects(
      () => requestCertificate("https://ca.example.net", "tok", "pk", fakeFetch(200, body)),
      (e: unknown) => e instanceof IssueError && /証明書/.test(e.message),
    );
  }
});
