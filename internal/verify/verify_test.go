package verify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const testIssuer = "https://token.actions.githubusercontent.com"

// idp はテスト用の OIDC プロバイダ。JWKS を配り、トークンを署名する。
type idp struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &idp{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &key.PublicKey,
			KeyID:     "test-key",
			Algorithm: "RS256",
			Use:       "sig",
		}}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	i.server = httptest.NewServer(mux)
	t.Cleanup(i.server.Close)
	return i
}

func (i *idp) verifier(t *testing.T) *Verifier {
	t.Helper()
	ks := oidc.NewRemoteKeySet(context.Background(), i.server.URL+"/jwks")
	return NewWithKeySet(testIssuer, ks)
}

// sign は claims を RS256 で署名して compact serialization を返す。
func (i *idp) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: i.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// baseClaims は GitHub Actions が実際に載せる形に近い claim 一式。
func baseClaims() map[string]any {
	return map[string]any{
		"iss":                 testIssuer,
		"aud":                 "https://ssh-ca.example.net",
		"exp":                 time.Now().Add(5 * time.Minute).Unix(),
		"iat":                 time.Now().Unix(),
		"nbf":                 time.Now().Add(-time.Minute).Unix(),
		"sub":                 "repo:o@1/r@2:environment:production",
		"repository_id":       "1313852776",
		"repository_owner_id": "85034901",
		"workflow_ref":        "o/r/.github/workflows/deploy.yml@refs/heads/main",
		"job_workflow_ref":    "o/r/.github/workflows/deploy.yml@refs/heads/main",
		"environment":         "production",
		"ref":                 "refs/heads/main",
	}
}

func TestVerify_Valid(t *testing.T) {
	i := newIDP(t)
	got, err := i.verifier(t).Verify(context.Background(), i.sign(t, baseClaims()))
	if err != nil {
		t.Fatalf("正当なトークンが拒否された: %v", err)
	}

	if !got.RepositoryID.IsSet() || got.RepositoryID.String() != "1313852776" {
		t.Errorf("repository_id: %+v", got.RepositoryID)
	}
	if !got.RepositoryOwnerID.IsSet() || got.RepositoryOwnerID.String() != "85034901" {
		t.Errorf("repository_owner_id: %+v", got.RepositoryOwnerID)
	}
	if !got.JobWorkflowRef.IsSet() || !strings.HasSuffix(got.JobWorkflowRef.String(), "deploy.yml@refs/heads/main") {
		t.Errorf("job_workflow_ref: %+v", got.JobWorkflowRef)
	}
	if !got.Environment.IsSet() || got.Environment.String() != "production" {
		t.Errorf("environment: %+v", got.Environment)
	}
	if !got.Audience.IsSet() || got.Audience.String() != "https://ssh-ca.example.net" {
		t.Errorf("aud: %+v", got.Audience)
	}
}

// claim が無い場合は空文字ではなく不在として扱われること。
// ここを空文字にすると、ルール側の空文字制約と一致してしまう。
func TestVerify_AbsentClaimsStayAbsent(t *testing.T) {
	i := newIDP(t)
	c := baseClaims()
	delete(c, "environment")
	delete(c, "ref")

	got, err := i.verifier(t).Verify(context.Background(), i.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if got.Environment.IsSet() {
		t.Error("存在しない environment が存在扱いになっている")
	}
	if got.Ref.IsSet() {
		t.Error("存在しない ref が存在扱いになっている")
	}
	// 存在するものは引き続き存在扱いであること。
	if !got.RepositoryID.IsSet() {
		t.Error("repository_id が不在扱いになっている")
	}
}

// 空文字で存在する claim は「存在する」として扱われること。
func TestVerify_EmptyClaimIsPresent(t *testing.T) {
	i := newIDP(t)
	c := baseClaims()
	c["environment"] = ""

	got, err := i.verifier(t).Verify(context.Background(), i.sign(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Environment.IsSet() {
		t.Fatal("空文字の environment が不在扱いになっている")
	}
	if got.Environment.String() != "" {
		t.Errorf("environment: got %q want empty", got.Environment.String())
	}
}

func TestVerify_Rejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"期限切れ", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"issuer 違い", func(c map[string]any) { c["iss"] = "https://evil.example.net" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := newIDP(t)
			c := baseClaims()
			tt.mutate(c)
			if _, err := i.verifier(t).Verify(context.Background(), i.sign(t, c)); err == nil {
				t.Fatal("拒否されるべきトークンが受理された")
			}
		})
	}
}

func TestVerify_RejectsEmptyToken(t *testing.T) {
	i := newIDP(t)
	if _, err := i.verifier(t).Verify(context.Background(), ""); err == nil {
		t.Fatal("空のトークンが受理された")
	}
}

// 別の鍵で署名されたトークンを拒否すること。
func TestVerify_RejectsUnknownSigningKey(t *testing.T) {
	victim := newIDP(t)
	attacker := newIDP(t)

	// attacker の鍵で署名し、victim の JWKS で検証させる。
	raw := attacker.sign(t, baseClaims())
	if _, err := victim.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("未知の鍵で署名されたトークンが受理された")
	}
}

// alg: none を拒否すること。JWT 実装の古典的な穴。
func TestVerify_RejectsAlgNone(t *testing.T) {
	i := newIDP(t)

	b64 := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	raw := b64(map[string]any{"alg": "none", "typ": "JWT"}) + "." + b64(baseClaims()) + "."

	if _, err := i.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("alg: none のトークンが受理された")
	}
}

// 対称鍵 (HS256) で署名されたトークンを拒否すること。
// 非対称鍵の公開鍵を HMAC の鍵として使わせる alg 混同攻撃への防御。
func TestVerify_RejectsSymmetricAlg(t *testing.T) {
	i := newIDP(t)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(baseClaims())
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := i.verifier(t).Verify(context.Background(), raw); err == nil {
		t.Fatal("HS256 のトークンが受理された")
	}
}

// aud が複数ある場合は不在として扱い、audience を制約するルールに
// 一致させないこと (fail closed)。
func TestVerify_MultipleAudiencesAreAbsent(t *testing.T) {
	i := newIDP(t)
	c := baseClaims()
	c["aud"] = []string{"https://ssh-ca.example.net", "https://other.example.net"}

	got, err := i.verifier(t).Verify(context.Background(), i.sign(t, c))
	if err != nil {
		t.Fatalf("検証自体は通るべき: %v", err)
	}
	if got.Audience.IsSet() {
		t.Fatalf("複数 audience が単一の値として扱われた: %q", got.Audience.String())
	}
}
