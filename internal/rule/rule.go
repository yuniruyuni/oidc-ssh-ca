// Package rule は、検証済みの OIDC claim をルールへ照合する。
//
// このパッケージは I/O を一切行わない純粋なロジックに保つ。JWT の署名検証や
// JWKS の取得は上位層の責務で、ここへ到達する時点で「GitHub が署名した本物の
// トークンである」ことは確定している。ここが答えるのは「その本物のトークンに
// 対して証明書を発行してよいか」だけ。
//
// テストしやすさがこのツールの唯一の実質的な防御なので、副作用を持ち込まない。
package rule

import "time"

// Value は claim および制約の値を、不在と空文字を区別して保持する。
//
// Go のゼロ値をそのまま使うと `""` と「claim が存在しない」が同一になり、
// 両方が空のときに誤って一致してしまう。これは fail-open であり、この
// ツールで最も起こりやすい脆弱性なので型で塞ぐ。
type Value struct {
	s   string
	set bool
}

// Present は値が存在することを表す。空文字であっても「存在する」。
func Present(s string) Value { return Value{s: s, set: true} }

// Absent は値が存在しないことを表す。
func Absent() Value { return Value{} }

// IsSet は値が存在するかを返す。
func (v Value) IsSet() bool { return v.set }

// String は値を返す。不在の場合は空文字を返すため、判定には必ず IsSet を使う。
func (v Value) String() string { return v.s }

// Claims は GitHub Actions の OIDC トークンから取り出した、認可判断に使う claim。
//
// repository / repository_owner という名前ベースの claim は意図的に持たない。
// リポジトリはリネームでき、解放された名前は第三者が再取得できるため、
// 数値 ID のみを認可に使う。
type Claims struct {
	Audience          Value // aud
	RepositoryID      Value // repository_id
	RepositoryOwnerID Value // repository_owner_id
	WorkflowRef       Value // workflow_ref     : 起点のワークフロー
	JobWorkflowRef    Value // job_workflow_ref : 実際に実行中の(再利用)ワークフロー
	Environment       Value // environment
	Ref               Value // ref
}

// Rule は 1 つの発行許可。設定ファイルの [[rule]] に対応する。
//
// 制約(Value 型のフィールド)は「設定されていれば完全一致を要求する」。
// 発行内容(Principals 以下)は必ずここから取り、リクエストからは絶対に取らない。
type Rule struct {
	Name string

	// 制約
	Audience          Value
	RepositoryID      Value
	RepositoryOwnerID Value
	WorkflowRef       Value
	JobWorkflowRef    Value
	Environment       Value
	Ref               Value

	// 発行内容
	Principals   []string
	ForceCommand string
	Extensions   []string
	Validity     time.Duration
}

// DenyReason は拒否の理由。ログとテストで使う。
type DenyReason string

const (
	DenyNoConstraints DenyReason = "rule has no constraints"
	DenyClaimAbsent   DenyReason = "required claim is absent"
	DenyClaimMismatch DenyReason = "claim does not match constraint"
)

// Result は照合結果。
type Result struct {
	Allowed bool
	Reason  DenyReason
	// Field は拒否の原因となった claim 名。allow の場合は空。
	Field string
}

func allow() Result { return Result{Allowed: true} }

func deny(reason DenyReason, field string) Result {
	return Result{Allowed: false, Reason: reason, Field: field}
}

// constraint は 1 つの制約と、それに対応する claim の組。
type constraint struct {
	field string
	want  Value
	got   Value
}

// Match は claims がこのルールを満たすかを判定する。
//
// 方針は fail closed:
//   - 制約が 1 つも無いルールは常に拒否する。設定ミスで全許可にならないように。
//   - 設定された制約に対応する claim が不在なら拒否する。
//   - 完全一致のみ。前方一致も正規表現も行わない。
func (r Rule) Match(c Claims) Result {
	cs := []constraint{
		{"aud", r.Audience, c.Audience},
		{"repository_id", r.RepositoryID, c.RepositoryID},
		{"repository_owner_id", r.RepositoryOwnerID, c.RepositoryOwnerID},
		{"workflow_ref", r.WorkflowRef, c.WorkflowRef},
		{"job_workflow_ref", r.JobWorkflowRef, c.JobWorkflowRef},
		{"environment", r.Environment, c.Environment},
		{"ref", r.Ref, c.Ref},
	}

	constrained := 0
	for _, x := range cs {
		if !x.want.IsSet() {
			continue
		}
		constrained++

		// 制約があるのに claim が無い。空文字と同一視してはいけない。
		if !x.got.IsSet() {
			return deny(DenyClaimAbsent, x.field)
		}
		if x.want.String() != x.got.String() {
			return deny(DenyClaimMismatch, x.field)
		}
	}

	// 制約ゼロのルールは何にでも一致してしまう。設定の検証でも弾くが、
	// ここでも拒否して二重に塞ぐ。
	if constrained == 0 {
		return deny(DenyNoConstraints, "")
	}

	return allow()
}
