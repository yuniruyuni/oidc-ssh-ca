package verify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/testutil"
)

func baseClaims() map[string]any { return testutil.Claims() }

func newIDP(t *testing.T) *testutil.IDP { return testutil.NewIDP(t) }

func verifierFor(t *testing.T, i *testutil.IDP) *Verifier {
	t.Helper()
	return NewWithKeySet(testutil.Issuer, i.KeySet())
}

func TestVerify_Valid(t *testing.T) {
	i := newIDP(t)
	got, err := verifierFor(t, i).Verify(context.Background(), i.Sign(t, baseClaims()))
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

	got, err := verifierFor(t, i).Verify(context.Background(), i.Sign(t, c))
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

	got, err := verifierFor(t, i).Verify(context.Background(), i.Sign(t, c))
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
			if _, err := verifierFor(t, i).Verify(context.Background(), i.Sign(t, c)); err == nil {
				t.Fatal("拒否されるべきトークンが受理された")
			}
		})
	}
}

func TestVerify_RejectsEmptyToken(t *testing.T) {
	i := newIDP(t)
	if _, err := verifierFor(t, i).Verify(context.Background(), ""); err == nil {
		t.Fatal("空のトークンが受理された")
	}
}

// 別の鍵で署名されたトークンを拒否すること。
func TestVerify_RejectsUnknownSigningKey(t *testing.T) {
	victim := newIDP(t)
	attacker := newIDP(t)

	// attacker の鍵で署名し、victim の JWKS で検証させる。
	raw := attacker.Sign(t, baseClaims())
	if _, err := verifierFor(t, victim).Verify(context.Background(), raw); err == nil {
		t.Fatal("未知の鍵で署名されたトークンが受理された")
	}
}

// alg: none を拒否すること。JWT 実装の古典的な穴。
func TestVerify_RejectsAlgNone(t *testing.T) {
	i := newIDP(t)
	raw := testutil.UnsignedToken(t, baseClaims())
	if _, err := verifierFor(t, i).Verify(context.Background(), raw); err == nil {
		t.Fatal("alg: none のトークンが受理された")
	}
}

// 対称鍵 (HS256) で署名されたトークンを拒否すること。
// 非対称鍵の公開鍵を HMAC の鍵として使わせる alg 混同攻撃への防御。
func TestVerify_RejectsSymmetricAlg(t *testing.T) {
	i := newIDP(t)
	raw := i.SignHS256(t, baseClaims())
	if _, err := verifierFor(t, i).Verify(context.Background(), raw); err == nil {
		t.Fatal("HS256 のトークンが受理された")
	}
}

// aud が複数ある場合は不在として扱い、audience を制約するルールに
// 一致させないこと (fail closed)。
func TestVerify_MultipleAudiencesAreAbsent(t *testing.T) {
	i := newIDP(t)
	c := baseClaims()
	c["aud"] = []string{"https://ssh-ca.example.net", "https://other.example.net"}

	got, err := verifierFor(t, i).Verify(context.Background(), i.Sign(t, c))
	if err != nil {
		t.Fatalf("検証自体は通るべき: %v", err)
	}
	if got.Audience.IsSet() {
		t.Fatalf("複数 audience が単一の値として扱われた: %q", got.Audience.String())
	}
}
