package config

import (
	"strings"
	"testing"
	"time"
)

const validTOML = `
listen = "127.0.0.1:8080"
ca_key_path = "/etc/oidc-ssh-ca/ca"

[[rule]]
name                = "fighter-deploy"
audience            = "https://ssh-ca.example.net"
repository_id       = "1313852776"
repository_owner_id = "85034901"
job_workflow_ref    = "o/r/.github/workflows/deploy.yml@refs/heads/main"
environment         = "production"
principals          = ["fighter"]
force_command       = "/usr/local/bin/app-deploy"
validity            = "5m"
`

func TestParse_Valid(t *testing.T) {
	cfg, err := Parse(validTOML)
	if err != nil {
		t.Fatalf("有効な設定が拒否された: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("ルール数: got %d want 1", len(cfg.Rules))
	}
	r := cfg.Rules[0]
	if r.Validity != 5*time.Minute {
		t.Errorf("validity: got %v want 5m", r.Validity)
	}
	if r.ForceCommand != "/usr/local/bin/app-deploy" {
		t.Errorf("force_command: got %q", r.ForceCommand)
	}
	// 書かれていない制約は不在として扱われること。
	if r.Ref.IsSet() {
		t.Error("ref は設定されていないのに IsSet が true")
	}
	if r.WorkflowRef.IsSet() {
		t.Error("workflow_ref は設定されていないのに IsSet が true")
	}
	// 書かれている制約は存在として扱われること。
	if !r.Environment.IsSet() || r.Environment.String() != "production" {
		t.Errorf("environment が正しく読めていない: %+v", r.Environment)
	}
}

func TestParse_Defaults(t *testing.T) {
	cfg, err := Parse(`
ca_key_path = "/etc/ca"
[[rule]]
name = "r"
audience = "https://a"
repository_id = "1"
job_workflow_ref = "w"
principals = ["p"]
validity = "5m"
`)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Issuer != DefaultIssuer {
		t.Errorf("issuer の既定値: got %q want %q", cfg.Issuer, DefaultIssuer)
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("listen の既定値: got %q", cfg.Listen)
	}
}

// 不正な設定が起動時に確実に落ちること。
// ここを通してしまうと、実行時に静かな全許可や静かな全拒否になる。
func TestParse_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name:    "ca_key_path が無い",
			toml:    "[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "ca_key_path",
		},
		{
			name:    "ルールが無い",
			toml:    `ca_key_path = "/etc/ca"`,
			wantErr: "ルールが 1 つも無い",
		},
		{
			name:    "name が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "name が必要",
		},
		{
			name:    "audience が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "audience が必要",
		},
		{
			name:    "audience が空文字",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "audience が必要",
		},
		{
			name:    "repository_id が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "repository_id が必要",
		},
		{
			name:    "repository_id が空文字",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "repository_id が必要",
		},
		{
			name:    "ワークフロー制約が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "workflow_ref か job_workflow_ref",
		},
		{
			name:    "principals が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nvalidity=\"5m\"",
			wantErr: "principals が必要",
		},
		{
			name:    "principals に空要素",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"\"]\nvalidity=\"5m\"",
			wantErr: "空の要素",
		},
		{
			name:    "principal にワイルドカード",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"*\"]\nvalidity=\"5m\"",
			wantErr: "ワイルドカード",
		},
		{
			name:    "force_command が相対パス",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nforce_command=\"app-deploy\"\nvalidity=\"5m\"",
			wantErr: "絶対パス",
		},
		{
			name:    "validity が無い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]",
			wantErr: "validity が必要",
		},
		{
			name:    "validity が上限超過",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"24h\"",
			wantErr: "上限",
		},
		{
			name:    "validity が負",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"-5m\"",
			wantErr: "正の値",
		},
		{
			name:    "危険な extension",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nextensions=[\"permit-port-forwarding\"]\nvalidity=\"5m\"",
			wantErr: "許可されていない extension",
		},
		{
			name:    "未知の extension",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nextensions=[\"permit-everything\"]\nvalidity=\"5m\"",
			wantErr: "未知の extension",
		},
		{
			name: "ルール名の重複",
			toml: "ca_key_path=\"/etc/ca\"\n" +
				"[[rule]]\nname=\"dup\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"\n" +
				"[[rule]]\nname=\"dup\"\naudience=\"a\"\nrepository_id=\"2\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"",
			wantErr: "重複",
		},
		{
			name:    "設定キーの綴り間違い",
			toml:    "ca_key_path=\"/etc/ca\"\n[[rule]]\nname=\"r\"\naudience=\"a\"\nrepository_id=\"1\"\njob_workflow_ref=\"w\"\nprincipals=[\"p\"]\nvalidity=\"5m\"\nrepositroy_owner_id=\"85034901\"",
			wantErr: "未知の設定キー",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.toml)
			if err == nil {
				t.Fatal("拒否されるべき設定が受理された")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("エラー内容が想定と異なる:\n got: %v\nwant contains: %s", err, tt.wantErr)
			}
		})
	}
}
