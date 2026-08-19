// Package config は設定ファイルの読み込みと検証を行う。
//
// 検証は起動時に全て終わらせ、不正な設定ではプロセスを起動させない。
// 実行中に「このルールは壊れているので飛ばす」という判断をさせると、
// 設定ミスが静かな全許可や静かな全拒否に化けるため。
package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/rule"
)

// DefaultIssuer は GitHub Actions の OIDC issuer。
const DefaultIssuer = "https://token.actions.githubusercontent.com"

// MaxValidityLimit は validity に設定できる上限。
//
// 短命であることがこの仕組みの安全性の中心なので、設定でいくらでも
// 延ばせてはいけない。
const MaxValidityLimit = 15 * time.Minute

// allowedExtensions は証明書に付与を許す extension。
//
// 既定では何も付けない。permit-pty すら不要で、デプロイのために必要なのは
// コマンド実行だけ。ポート転送やエージェント転送は踏み台化に繋がるため
// 許可リストにも入れない。
var allowedExtensions = map[string]bool{
	"permit-pty":              true,
	"no-touch-required":       true,
	"permit-user-rc":          false,
	"permit-X11-forwarding":   false,
	"permit-agent-forwarding": false,
	"permit-port-forwarding":  false,
}

// Config はサーバ全体の設定。
type Config struct {
	Listen    string
	CAKeyPath string
	Issuer    string
	Rules     []rule.Rule
}

// ---- TOML の生表現 ----
//
// オプショナルな項目を *string で受けるのは、「キーが無い」と「空文字が
// 書かれている」を区別するため。ここを string で受けると、空文字の制約と
// claim の不在が一致する fail-open を設定側から作り込めてしまう。

type rawConfig struct {
	Listen    string    `toml:"listen"`
	CAKeyPath string    `toml:"ca_key_path"`
	Issuer    string    `toml:"issuer"`
	Rule      []rawRule `toml:"rule"`
}

type rawRule struct {
	Name string `toml:"name"`

	Audience          *string `toml:"audience"`
	RepositoryID      *string `toml:"repository_id"`
	RepositoryOwnerID *string `toml:"repository_owner_id"`
	WorkflowRef       *string `toml:"workflow_ref"`
	JobWorkflowRef    *string `toml:"job_workflow_ref"`
	Environment       *string `toml:"environment"`
	Ref               *string `toml:"ref"`

	Principals   []string `toml:"principals"`
	ForceCommand string   `toml:"force_command"`
	Extensions   []string `toml:"extensions"`
	Validity     string   `toml:"validity"`
}

// Load は設定ファイルを読み込み、検証した上で返す。
// 検証に通らない設定は必ずエラーになる。
func Load(path string) (*Config, error) {
	var raw rawConfig
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("設定ファイルを読めない: %w", err)
	}

	// 綴り間違いを黙って無視すると、意図した制約が抜けたまま起動してしまう。
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("未知の設定キー: %s", strings.Join(keys, ", "))
	}

	return build(raw)
}

// Parse は TOML 文字列から設定を組み立てる。テストと Load から使う。
func Parse(s string) (*Config, error) {
	var raw rawConfig
	md, err := toml.Decode(s, &raw)
	if err != nil {
		return nil, fmt.Errorf("設定を解析できない: %w", err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("未知の設定キー: %s", strings.Join(keys, ", "))
	}
	return build(raw)
}

func build(raw rawConfig) (*Config, error) {
	cfg := &Config{
		Listen:    raw.Listen,
		CAKeyPath: raw.CAKeyPath,
		Issuer:    raw.Issuer,
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8080"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = DefaultIssuer
	}
	if cfg.CAKeyPath == "" {
		return nil, errors.New("ca_key_path が必要")
	}

	if len(raw.Rule) == 0 {
		return nil, errors.New("ルールが 1 つも無い")
	}

	seen := make(map[string]bool, len(raw.Rule))
	for i, rr := range raw.Rule {
		r, err := buildRule(rr)
		if err != nil {
			label := rr.Name
			if label == "" {
				label = fmt.Sprintf("#%d", i)
			}
			return nil, fmt.Errorf("ルール %s: %w", label, err)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("ルール名が重複している: %s", r.Name)
		}
		seen[r.Name] = true
		cfg.Rules = append(cfg.Rules, r)
	}

	return cfg, nil
}

func buildRule(rr rawRule) (rule.Rule, error) {
	var zero rule.Rule

	if strings.TrimSpace(rr.Name) == "" {
		return zero, errors.New("name が必要")
	}

	r := rule.Rule{
		Name:              rr.Name,
		Audience:          rule.FromPtr(rr.Audience),
		RepositoryID:      rule.FromPtr(rr.RepositoryID),
		RepositoryOwnerID: rule.FromPtr(rr.RepositoryOwnerID),
		WorkflowRef:       rule.FromPtr(rr.WorkflowRef),
		JobWorkflowRef:    rule.FromPtr(rr.JobWorkflowRef),
		Environment:       rule.FromPtr(rr.Environment),
		Ref:               rule.FromPtr(rr.Ref),
		ForceCommand:      rr.ForceCommand,
		Extensions:        rr.Extensions,
	}

	// audience は再生防止の要。GitHub の audience は呼び出し側が選べるため
	// これ自体は認可の主役ではないが、他サービス向けに発行されたトークンを
	// そのまま持ち込めてしまうので必須にする。
	if !r.Audience.IsSet() || r.Audience.String() == "" {
		return zero, errors.New("audience が必要")
	}

	// 認可の主役。リポジトリを特定しないルールは作らせない。
	if !r.RepositoryID.IsSet() || r.RepositoryID.String() == "" {
		return zero, errors.New("repository_id が必要")
	}

	// どのワークフローから来たかを縛らないと、同じリポジトリの任意の
	// ワークフローが証明書を取得できてしまう。
	if !r.WorkflowRef.IsSet() && !r.JobWorkflowRef.IsSet() {
		return zero, errors.New("workflow_ref か job_workflow_ref のどちらかが必要")
	}

	if len(rr.Principals) == 0 {
		return zero, errors.New("principals が必要")
	}
	for _, p := range rr.Principals {
		if strings.TrimSpace(p) == "" {
			return zero, errors.New("principals に空の要素がある")
		}
		// OpenSSH の principal にワイルドカードの意味は無いが、
		// 設定者が「全ホスト許可」のつもりで書く事故を防ぐ。
		if strings.ContainsAny(p, "*?") {
			return zero, fmt.Errorf("principal にワイルドカードは使えない: %q", p)
		}
	}
	r.Principals = rr.Principals

	if r.ForceCommand != "" && !filepath.IsAbs(r.ForceCommand) {
		return zero, fmt.Errorf("force_command は絶対パスである必要がある: %q", r.ForceCommand)
	}

	for _, e := range rr.Extensions {
		allowed, known := allowedExtensions[e]
		if !known {
			return zero, fmt.Errorf("未知の extension: %q", e)
		}
		if !allowed {
			return zero, fmt.Errorf("許可されていない extension: %q", e)
		}
	}

	if rr.Validity == "" {
		return zero, errors.New("validity が必要")
	}
	d, err := time.ParseDuration(rr.Validity)
	if err != nil {
		return zero, fmt.Errorf("validity を解析できない: %w", err)
	}
	if d <= 0 {
		return zero, fmt.Errorf("validity は正の値である必要がある: %s", rr.Validity)
	}
	if d > MaxValidityLimit {
		return zero, fmt.Errorf("validity が上限 %s を超えている: %s", MaxValidityLimit, rr.Validity)
	}
	r.Validity = d

	return r, nil
}
