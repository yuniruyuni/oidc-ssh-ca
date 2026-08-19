package rule

import (
	"testing"
	"time"
)

// validRule はテストの基準となるルール。個々のテストはこれを 1 箇所だけ
// 変えて、その変更が拒否に繋がることを確認する。
func validRule() Rule {
	return Rule{
		Name:              "fighter-deploy",
		Audience:          Present("https://ssh-ca.example.net"),
		RepositoryID:      Present("1313852776"),
		RepositoryOwnerID: Present("85034901"),
		WorkflowRef:       Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		JobWorkflowRef:    Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		Environment:       Present("production"),
		Ref:               Present("refs/heads/main"),
		Principals:        []string{"fighter"},
		ForceCommand:      "/usr/local/bin/app-deploy",
		Validity:          5 * time.Minute,
	}
}

// validClaims は validRule を満たす claim。
func validClaims() Claims {
	return Claims{
		Audience:          Present("https://ssh-ca.example.net"),
		RepositoryID:      Present("1313852776"),
		RepositoryOwnerID: Present("85034901"),
		WorkflowRef:       Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		JobWorkflowRef:    Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		Environment:       Present("production"),
		Ref:               Present("refs/heads/main"),
	}
}

func TestMatch_Allows(t *testing.T) {
	if got := validRule().Match(validClaims()); !got.Allowed {
		t.Fatalf("基準ケースが拒否された: %+v", got)
	}
}

// 制約された claim が 1 つでも違えば拒否されること。
func TestMatch_DeniesOnMismatch(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*Claims)
	}{
		{"別リポジトリ", "repository_id", func(c *Claims) { c.RepositoryID = Present("9999999999") }},
		{"別オーナー", "repository_owner_id", func(c *Claims) { c.RepositoryOwnerID = Present("1") }},
		{"別ワークフロー", "workflow_ref", func(c *Claims) {
			c.WorkflowRef = Present("o/r/.github/workflows/evil.yml@refs/heads/main")
		}},
		{"別の再利用ワークフロー", "job_workflow_ref", func(c *Claims) {
			c.JobWorkflowRef = Present("o/r/.github/workflows/evil.yml@refs/heads/main")
		}},
		{"別environment", "environment", func(c *Claims) { c.Environment = Present("staging") }},
		{"別ブランチ", "ref", func(c *Claims) { c.Ref = Present("refs/heads/attacker") }},
		{"別audience", "aud", func(c *Claims) { c.Audience = Present("https://other.example.net") }},

		// ワークフローファイルは同じだが別ブランチから発行されたトークン。
		// workflow_ref は @ 以降まで含めて一致させる必要がある。
		{"同ファイル別ref", "workflow_ref", func(c *Claims) {
			c.WorkflowRef = Present("o/r/.github/workflows/deploy.yml@refs/heads/topic")
		}},
		// 前方一致で許してしまうと通ってしまうケース。
		{"リポジトリIDの前方一致", "repository_id", func(c *Claims) { c.RepositoryID = Present("13137") }},
		{"リポジトリIDの後方一致", "repository_id", func(c *Claims) { c.RepositoryID = Present("11313852776") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validClaims()
			tt.mutate(&c)
			got := validRule().Match(c)
			if got.Allowed {
				t.Fatalf("拒否されるべきだが許可された")
			}
			if got.Reason != DenyClaimMismatch {
				t.Fatalf("理由が想定と異なる: got %q want %q", got.Reason, DenyClaimMismatch)
			}
			if got.Field != tt.field {
				t.Fatalf("フィールドが想定と異なる: got %q want %q", got.Field, tt.field)
			}
		})
	}
}

// 制約された claim がトークンに存在しない場合は拒否されること。
// 「不在」を空文字と同一視すると fail-open になる。
func TestMatch_DeniesOnAbsentClaim(t *testing.T) {
	tests := []struct {
		field  string
		mutate func(*Claims)
	}{
		{"aud", func(c *Claims) { c.Audience = Absent() }},
		{"repository_id", func(c *Claims) { c.RepositoryID = Absent() }},
		{"repository_owner_id", func(c *Claims) { c.RepositoryOwnerID = Absent() }},
		{"workflow_ref", func(c *Claims) { c.WorkflowRef = Absent() }},
		{"job_workflow_ref", func(c *Claims) { c.JobWorkflowRef = Absent() }},
		{"environment", func(c *Claims) { c.Environment = Absent() }},
		{"ref", func(c *Claims) { c.Ref = Absent() }},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			c := validClaims()
			tt.mutate(&c)
			got := validRule().Match(c)
			if got.Allowed {
				t.Fatalf("claim 不在なのに許可された")
			}
			if got.Reason != DenyClaimAbsent {
				t.Fatalf("理由が想定と異なる: got %q want %q", got.Reason, DenyClaimAbsent)
			}
			if got.Field != tt.field {
				t.Fatalf("フィールドが想定と異なる: got %q want %q", got.Field, tt.field)
			}
		})
	}
}

// このツールで最も起こりやすい脆弱性。ルール側の制約が空文字で、
// トークン側の claim が不在のとき、ゼロ値比較だと一致してしまう。
func TestMatch_EmptyStringIsNotAbsent(t *testing.T) {
	// ルールが「environment は空文字であること」を要求している状態。
	r := validRule()
	r.Environment = Present("")

	// トークンに environment claim が無い。
	c := validClaims()
	c.Environment = Absent()

	got := r.Match(c)
	if got.Allowed {
		t.Fatal("空文字の制約に対し claim 不在が一致してしまった (fail-open)")
	}
	if got.Reason != DenyClaimAbsent {
		t.Fatalf("理由が想定と異なる: got %q", got.Reason)
	}
}

// 逆向き。ルールに制約が無く、claim が空文字で存在する場合は、
// その項目は評価対象外なので他の制約だけで判定される。
func TestMatch_UnconstrainedFieldIsIgnored(t *testing.T) {
	r := validRule()
	r.Environment = Absent() // environment を制約しない

	c := validClaims()
	c.Environment = Present("") // 空文字で存在

	if got := r.Match(c); !got.Allowed {
		t.Fatalf("制約していない項目で拒否された: %+v", got)
	}
}

// 制約が 1 つも無いルールは何にでも一致してしまうため、必ず拒否する。
func TestMatch_DeniesRuleWithoutConstraints(t *testing.T) {
	r := Rule{
		Name:       "misconfigured",
		Principals: []string{"fighter"},
		Validity:   5 * time.Minute,
	}

	got := r.Match(validClaims())
	if got.Allowed {
		t.Fatal("制約ゼロのルールが許可された (fail-open)")
	}
	if got.Reason != DenyNoConstraints {
		t.Fatalf("理由が想定と異なる: got %q want %q", got.Reason, DenyNoConstraints)
	}
}

// 制約ゼロのルールに空の claim を与えた場合も拒否されること。
// ゼロ値同士の比較が全て一致するため、最も危険な組み合わせ。
func TestMatch_DeniesEmptyRuleWithEmptyClaims(t *testing.T) {
	if got := (Rule{}).Match(Claims{}); got.Allowed {
		t.Fatal("空のルールと空の claim が一致した (fail-open)")
	}
}

// ルールが一部の項目しか制約していない場合、制約した項目だけで判定される。
// environment を使わないワークフローのための正当なケース。
func TestMatch_PartialConstraints(t *testing.T) {
	r := Rule{
		Name:           "no-environment",
		RepositoryID:   Present("1313852776"),
		JobWorkflowRef: Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		Principals:     []string{"fighter"},
		Validity:       5 * time.Minute,
	}

	c := validClaims()
	c.Environment = Absent() // environment を使わないワークフロー

	if got := r.Match(c); !got.Allowed {
		t.Fatalf("制約していない environment の不在で拒否された: %+v", got)
	}

	// ただし制約している項目が違えば当然拒否される。
	c.RepositoryID = Present("9999999999")
	if got := r.Match(c); got.Allowed {
		t.Fatal("別リポジトリなのに許可された")
	}
}
