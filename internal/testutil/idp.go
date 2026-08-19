// Package testutil はテスト用の補助。本番コードからは使わない。
package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// Issuer はテストで使う issuer。実際の GitHub と同じ値にしておく。
const Issuer = "https://token.actions.githubusercontent.com"

// IDP はテスト用の OIDC プロバイダ。JWKS を配り、トークンを署名する。
type IDP struct {
	key    *rsa.PrivateKey
	server *httptest.Server
}

// NewIDP はテスト用プロバイダを起動する。t.Cleanup で停止する。
func NewIDP(t *testing.T) *IDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	i := &IDP{key: key}

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

// KeySet はこのプロバイダの鍵集合を返す。
func (i *IDP) KeySet() oidc.KeySet {
	return oidc.NewRemoteKeySet(context.Background(), i.server.URL+"/jwks")
}

// Sign は claims を RS256 で署名して compact serialization を返す。
func (i *IDP) Sign(t *testing.T, claims map[string]any) string {
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

// SignHS256 は対称鍵で署名したトークンを返す。alg 混同の否定テスト用。
func (i *IDP) SignHS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
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

// UnsignedToken は alg: none のトークンを組み立てる。go-jose では作れない
// ため手で組む。JWT 実装の古典的な穴に対する否定テスト用。
func UnsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return b64(map[string]any{"alg": "none", "typ": "JWT"}) + "." + b64(claims) + "."
}

// Claims は GitHub Actions が実際に載せる形に近い claim 一式を返す。
func Claims() map[string]any {
	return map[string]any{
		"iss":                 Issuer,
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
