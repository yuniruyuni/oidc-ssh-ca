package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/ca"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/rule"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/testutil"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/verify"
)

type fixture struct {
	idp     *testutil.IDP
	ca      *ca.CA
	handler http.Handler
}

func newFixture(t *testing.T, rules ...rule.Rule) *fixture {
	t.Helper()

	idp := testutil.NewIDP(t)
	v := verify.NewWithKeySet(testutil.Issuer, idp.KeySet())

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	authority := ca.New(signer)

	if len(rules) == 0 {
		rules = []rule.Rule{defaultRule()}
	}
	// テスト出力を汚さないよう破棄する。
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	return &fixture{idp: idp, ca: authority, handler: New(v, rules, authority, log).Handler()}
}

func defaultRule() rule.Rule {
	return rule.Rule{
		Name:              "fighter-deploy",
		Audience:          rule.Present("https://ssh-ca.example.net"),
		RepositoryID:      rule.Present("1313852776"),
		RepositoryOwnerID: rule.Present("85034901"),
		JobWorkflowRef:    rule.Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		Environment:       rule.Present("production"),
		Principals:        []string{"fighter"},
		ForceCommand:      "/usr/local/bin/app-deploy",
		Validity:          5 * time.Minute,
	}
}

func userKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func (f *fixture) issue(t *testing.T, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/issue", bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func keyBody(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(issueRequest{PublicKey: userKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIssue_Success(t *testing.T) {
	f := newFixture(t)
	rec := f.issue(t, f.idp.Sign(t, testutil.Claims()), keyBody(t))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var resp issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("応答を解析できない: %v", err)
	}
	if len(resp.Principals) != 1 || resp.Principals[0] != "fighter" {
		t.Errorf("principals: got %v", resp.Principals)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("証明書を解析できない: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatal("返ってきたのが証明書でない")
	}

	// 発行内容がルール由来であること。
	if got := cert.Permissions.CriticalOptions["force-command"]; got != "/usr/local/bin/app-deploy" {
		t.Errorf("force-command: got %q", got)
	}
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("要求していない extension が付いている: %v", cert.Permissions.Extensions)
	}
	// 監査のため、どのルールとリクエストで出したかが辿れること。
	if !strings.Contains(cert.KeyId, "fighter-deploy") || !strings.Contains(cert.KeyId, "1313852776") {
		t.Errorf("KeyId に発行の手掛かりが無い: %q", cert.KeyId)
	}

	// 実際に認証に使えること。
	//
	// SupportedCriticalOptions を明示しているのは x/crypto/ssh の CertChecker が
	// 知らない critical option を一律拒否するため。OpenSSH 本体は force-command を
	// 解釈するので、これはこちらの証明書の問題ではなくライブラリ側の既定の厳しさ。
	// x/crypto/ssh でサーバを書く場合は同じ宣言が要る、という注意点でもある。
	checker := &ssh.CertChecker{
		SupportedCriticalOptions: []string{"force-command"},
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(f.ca.PublicKey().Marshal())
		},
	}
	if _, err := checker.Authenticate(fakeConn{"fighter"}, cert); err != nil {
		t.Fatalf("発行した証明書で認証できない: %v", err)
	}
}

type fakeConn struct{ user string }

func (f fakeConn) User() string          { return f.user }
func (f fakeConn) SessionID() []byte     { return nil }
func (f fakeConn) ClientVersion() []byte { return nil }
func (f fakeConn) ServerVersion() []byte { return nil }
func (f fakeConn) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (f fakeConn) LocalAddr() net.Addr   { return &net.TCPAddr{} }

func TestIssue_Unauthorized(t *testing.T) {
	f := newFixture(t)

	tests := []struct {
		name  string
		token string
	}{
		{"トークンが無い", ""},
		{"壊れたトークン", "not-a-jwt"},
		{"alg none", testutil.UnsignedToken(t, testutil.Claims())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.issue(t, tt.token, keyBody(t))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d want 401 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIssue_UnauthorizedForOtherSigner(t *testing.T) {
	f := newFixture(t)
	attacker := testutil.NewIDP(t)

	rec := f.issue(t, attacker.Sign(t, testutil.Claims()), keyBody(t))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("別の鍵で署名されたトークンが受理された: %d", rec.Code)
	}
}

// トークンは本物だが、ルールに一致しない場合は 403。
func TestIssue_Forbidden(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"別リポジトリ", func(c map[string]any) { c["repository_id"] = "9999999999" }},
		{"別ワークフロー", func(c map[string]any) {
			c["job_workflow_ref"] = "o/r/.github/workflows/evil.yml@refs/heads/main"
		}},
		{"別environment", func(c map[string]any) { c["environment"] = "staging" }},
		{"別audience", func(c map[string]any) { c["aud"] = "https://other.example.net" }},
		{"environment が無い", func(c map[string]any) { delete(c, "environment") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			c := testutil.Claims()
			tt.mutate(c)
			rec := f.issue(t, f.idp.Sign(t, c), keyBody(t))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status: got %d want 403 (body: %s)", rec.Code, rec.Body.String())
			}
			// 探索の手掛かりを与えないこと。
			if strings.Contains(rec.Body.String(), "fighter-deploy") {
				t.Errorf("応答にルール名が漏れている: %s", rec.Body.String())
			}
		})
	}
}

func TestIssue_BadRequest(t *testing.T) {
	f := newFixture(t)
	token := f.idp.Sign(t, testutil.Claims())

	tests := []struct {
		name string
		body string
	}{
		{"JSON でない", "not json"},
		{"公開鍵が空", `{"public_key":""}`},
		{"壊れた公開鍵", `{"public_key":"ssh-ed25519 not-base64"}`},
		{"公開鍵が複数行", `{"public_key":"` + userKey(t) + `\n` + userKey(t) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := f.issue(t, token, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status: got %d want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// 過大なボディで資源を消費させられないこと。
func TestIssue_BodyTooLarge(t *testing.T) {
	f := newFixture(t)
	token := f.idp.Sign(t, testutil.Claims())

	big := `{"public_key":"` + strings.Repeat("A", maxBodyBytes*2) + `"}`
	rec := f.issue(t, token, big)
	if rec.Code == http.StatusOK {
		t.Fatal("過大なボディが受理された")
	}
}

func TestMethodAndRoutes(t *testing.T) {
	f := newFixture(t)

	t.Run("GET /issue は許可しない", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/issue", nil)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatal("GET が受理された")
		}
	})

	t.Run("healthz", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz: got %d", rec.Code)
		}
	})
}

// 最初に一致したルールが使われること。
func TestIssue_FirstMatchingRuleWins(t *testing.T) {
	first := defaultRule()
	first.Name = "first"
	first.Principals = []string{"first-principal"}

	second := defaultRule()
	second.Name = "second"
	second.Principals = []string{"second-principal"}

	f := newFixture(t, first, second)
	rec := f.issue(t, f.idp.Sign(t, testutil.Claims()), keyBody(t))
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var resp issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Principals[0] != "first-principal" {
		t.Errorf("最初のルールが使われていない: %v", resp.Principals)
	}
}
