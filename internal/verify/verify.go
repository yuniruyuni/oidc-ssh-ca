// Package verify は GitHub Actions の OIDC トークンを検証し、認可に使う
// claim を取り出す。
//
// 署名検証・JWKS の取得とキャッシュ・鍵のローテーション追従は
// coreos/go-oidc に委譲する。ここが行うのは「取り出した claim を、
// 不在と空文字を区別できる形へ移し替える」ことだけ。
package verify

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/rule"
)

// Verifier はトークンを検証する。
type Verifier struct {
	v *oidc.IDTokenVerifier
}

// config は検証の共通設定。
//
// SkipClientIDCheck を有効にしているのは、audience の照合をルール側で
// 行うため。このツールは複数のルールを持ち、ルールごとに期待する
// audience が異なりうるので、検証層で 1 つに固定できない。
//
// audience が無検証になるわけではない。設定側で audience を必須にし、
// rule.Match が完全一致を要求することで担保している。設定の検証を
// 緩めるとここが穴になるので、両者はセットで維持すること。
func config() *oidc.Config {
	return &oidc.Config{
		SkipClientIDCheck: true,
		// GitHub は RS256 で署名する。ここを開けると alg 混同の余地が出る。
		SupportedSigningAlgs: []string{oidc.RS256},
	}
}

// New は issuer の discovery を行って Verifier を作る。
func New(ctx context.Context, issuer string) (*Verifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider を取得できない: %w", err)
	}
	return &Verifier{v: provider.VerifierContext(ctx, config())}, nil
}

// NewWithKeySet は鍵集合を直接指定して Verifier を作る。テストと、
// discovery を使わない構成のために公開している。
func NewWithKeySet(issuer string, keySet oidc.KeySet) *Verifier {
	return &Verifier{v: oidc.NewVerifier(issuer, keySet, config())}
}

// githubClaims は GitHub Actions の OIDC トークンから読み出す claim。
//
// 全て *string で受ける。claim が無い場合と空文字が入っている場合を
// 区別できないと、ルール側の空文字制約と誤って一致する fail-open になる。
type githubClaims struct {
	RepositoryID      *string `json:"repository_id"`
	RepositoryOwnerID *string `json:"repository_owner_id"`
	WorkflowRef       *string `json:"workflow_ref"`
	JobWorkflowRef    *string `json:"job_workflow_ref"`
	Environment       *string `json:"environment"`
	Ref               *string `json:"ref"`
}

// Verify はトークンの署名・issuer・有効期限を検証し、claim を返す。
func (v *Verifier) Verify(ctx context.Context, raw string) (rule.Claims, error) {
	var zero rule.Claims

	if raw == "" {
		return zero, errors.New("トークンが空")
	}

	tok, err := v.v.Verify(ctx, raw)
	if err != nil {
		return zero, fmt.Errorf("トークンを検証できない: %w", err)
	}

	var gc githubClaims
	if err := tok.Claims(&gc); err != nil {
		return zero, fmt.Errorf("claim を読めない: %w", err)
	}

	return rule.Claims{
		Audience:          audience(tok.Audience),
		RepositoryID:      rule.FromPtr(gc.RepositoryID),
		RepositoryOwnerID: rule.FromPtr(gc.RepositoryOwnerID),
		WorkflowRef:       rule.FromPtr(gc.WorkflowRef),
		JobWorkflowRef:    rule.FromPtr(gc.JobWorkflowRef),
		Environment:       rule.FromPtr(gc.Environment),
		Ref:               rule.FromPtr(gc.Ref),
	}, nil
}

// audience は aud claim を単一の値として取り出す。
//
// GitHub は audience を 1 つだけ入れる。複数入っている場合は想定外なので
// 不在として扱い、audience を制約しているルールには一致させない
// (fail closed)。「どれか 1 つが一致すればよい」という扱いにすると、
// 別サービス向けのトークンに自分向けの audience を紛れ込ませる余地が出る。
func audience(aud []string) rule.Value {
	if len(aud) != 1 {
		return rule.Absent()
	}
	return rule.Present(aud[0])
}
