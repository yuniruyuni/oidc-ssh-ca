// 発行サーバとのやり取り。副作用を fetch に限定し、テストしやすくしている。

export interface IssueResponse {
  certificate: string;
  principals: string[];
  valid_before: number;
}

export class IssueError extends Error {
  // Node の型ストリップは parameter property を解釈しないため、
  // フィールドを明示的に宣言して代入する。
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "IssueError";
    this.status = status;
  }
}

/** エラー応答から表示してよい情報だけを取り出す。 */
function describe(status: number, body: string): string {
  const trimmed = body.trim().slice(0, 500);
  switch (status) {
    case 401:
      return "OIDC トークンが受理されなかった (401)。issuer と audience の設定を確認する。";
    case 403:
      return (
        "発行を拒否された (403)。サーバ側のルールに一致していない。" +
        "repository_id / workflow_ref / environment / ref を確認する。" +
        "詳細な理由はサーバのログにのみ記録される。"
      );
    case 400:
      return `要求が不正 (400): ${trimmed}`;
    default:
      return `発行に失敗 (${status}): ${trimmed}`;
  }
}

/**
 * 証明書を要求する。
 *
 * token は決してログや例外メッセージに含めない。含めると失敗時の出力から
 * 短命とはいえ有効なトークンが漏れる。
 */
export async function requestCertificate(
  endpoint: string,
  token: string,
  publicKey: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IssueResponse> {
  const url = `${endpoint.replace(/\/+$/, "")}/issue`;

  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ public_key: publicKey }),
    });
  } catch (cause) {
    throw new IssueError(`発行サーバへ接続できない: ${endpoint}`);
  }

  const body = await res.text();
  if (!res.ok) {
    throw new IssueError(describe(res.status, body), res.status);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new IssueError("発行サーバの応答が JSON でない");
  }

  const cert = (parsed as Partial<IssueResponse>)?.certificate;
  if (typeof cert !== "string" || cert.trim() === "") {
    throw new IssueError("発行サーバの応答に証明書が含まれていない");
  }

  const principals = (parsed as Partial<IssueResponse>).principals;
  return {
    certificate: cert.trim(),
    principals: Array.isArray(principals) ? principals : [],
    valid_before: Number((parsed as Partial<IssueResponse>).valid_before ?? 0),
  };
}
