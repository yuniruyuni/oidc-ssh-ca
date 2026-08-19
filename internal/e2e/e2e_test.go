// Package e2e は、実際の OpenSSH sshd に対する end-to-end 検査。
//
// 単体テストは x/crypto/ssh で証明書を作り x/crypto/ssh で検証している。
// 同じ実装同士なので、extension や critical option の名前を間違えても
// 通ってしまう。本物の sshd に食わせて初めて「使える証明書か」が分かる。
package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/ca"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/rule"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/server"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/testutil"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/verify"
)

const forcedMarker = "FORCED-COMMAND-RAN"

func requireTools(t *testing.T) string {
	t.Helper()
	if os.Getenv("OIDC_SSH_CA_SKIP_E2E") != "" {
		t.Skip("OIDC_SSH_CA_SKIP_E2E が設定されている")
	}
	for _, bin := range []string{"ssh-keygen", "ssh"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s が無いので skip", bin)
		}
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	t.Skip("sshd が無いので skip")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// env は e2e に必要な一式を用意する。
type env struct {
	dir      string
	caPubKey string
	port     int
	user     string
	issuer   *httptest.Server
	idp      *testutil.IDP
}

func setup(t *testing.T, allowedPrincipal, issuedPrincipal string) *env {
	t.Helper()
	sshdPath := requireTools(t)

	dir := t.TempDir()
	// sshd は StrictModes を切っても親ディレクトリの権限に厳しいので緩めない。
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	// CA 鍵とホスト鍵。
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test-ca", "-f", filepath.Join(dir, "ca"))
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "host", "-f", filepath.Join(dir, "host"))

	// force-command から実行されるスクリプト。
	// 元のコマンドは SSH_ORIGINAL_COMMAND に入るだけで実行されないこと、
	// を確認するために両方を出力する。
	script := filepath.Join(dir, "forced.sh")
	if err := os.WriteFile(script, []byte(
		"#!/bin/sh\necho "+forcedMarker+"\necho \"original=[$SSH_ORIGINAL_COMMAND]\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// principal ファイル。ログインユーザに対して許可する principal を書く。
	principalsFile := filepath.Join(dir, "principals")
	if err := os.WriteFile(principalsFile, []byte(allowedPrincipal+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	sshdConfig := filepath.Join(dir, "sshd_config")
	cfg := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s/host
PidFile %s/sshd.pid
LogLevel VERBOSE
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
StrictModes no
PrintMotd no
TrustedUserCAKeys %s/ca.pub
AuthorizedPrincipalsFile %s
AuthorizedKeysFile /dev/null
Subsystem sftp /bin/false
`, port, dir, dir, dir, principalsFile)
	if err := os.WriteFile(sshdConfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshdPath, "-D", "-e", "-f", sshdConfig)
	var sshdLog bytes.Buffer
	cmd.Stdout = &sshdLog
	cmd.Stderr = &sshdLog
	if err := cmd.Start(); err != nil {
		t.Fatalf("sshd を起動できない: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("sshd log:\n%s", sshdLog.String())
		}
	})

	// 起動待ち。
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			// ここで skip すると e2e が黙って無効化され、壊れていても
			// 気づけない。環境要因で動かせない場合は明示的に
			// OIDC_SSH_CA_SKIP_E2E=1 を指定する。
			t.Fatalf("sshd が起動しない:\n%s", sshdLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// 発行サーバ。CA 鍵は sshd が信頼しているものと同一。
	authority, err := ca.LoadFile(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	idp := testutil.NewIDP(t)
	v := verify.NewWithKeySet(testutil.Issuer, idp.KeySet())
	r := rule.Rule{
		Name:           "e2e",
		Audience:       rule.Present("https://ssh-ca.example.net"),
		RepositoryID:   rule.Present("1313852776"),
		JobWorkflowRef: rule.Present("o/r/.github/workflows/deploy.yml@refs/heads/main"),
		Principals:     []string{issuedPrincipal},
		ForceCommand:   script,
		Validity:       5 * time.Minute,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	issuer := httptest.NewServer(server.New(v, []rule.Rule{r}, authority, log).Handler())
	t.Cleanup(issuer.Close)

	return &env{dir: dir, port: port, user: u.Username, issuer: issuer, idp: idp}
}

// bareKey は証明書を伴わない鍵を作る。
func (e *env) bareKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bare_ed25519")
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "bare", "-f", path)
	return path
}

// issueCert は発行サーバから証明書を取得し、鍵と証明書のパスを返す。
func (e *env) issueCert(t *testing.T) (keyPath, certPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}

	keyPath = filepath.Join(e.dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(map[string]string{
		"public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, e.issuer.URL+"/issue", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.idp.Sign(t, testutil.Claims()))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("発行に失敗: %d %s", resp.StatusCode, b)
	}

	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	certPath = keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(out.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, certPath
}

func (e *env) ssh(t *testing.T, keyPath, certPath, command string) (string, error) {
	t.Helper()
	args := []string{
		"-p", fmt.Sprint(e.port),
		"-i", keyPath,
		"-o", "CertificateFile=" + certPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "PreferredAuthentications=publickey",
		fmt.Sprintf("%s@127.0.0.1", e.user),
		command,
	}
	out, err := exec.Command("ssh", args...).CombinedOutput()
	return string(out), err
}

// 正当な証明書で認証でき、force-command が実際に強制されること。
func TestE2E_ForceCommandIsEnforced(t *testing.T) {
	e := setup(t, "fighter", "fighter")
	keyPath, certPath := e.issueCert(t)

	out, err := e.ssh(t, keyPath, certPath, "echo SHOULD_NOT_RUN")
	if err != nil {
		t.Fatalf("SSH に失敗: %v\n%s", err, out)
	}

	if !strings.Contains(out, forcedMarker) {
		t.Errorf("force-command が実行されていない:\n%s", out)
	}
	// 要求したコマンドは実行されず、SSH_ORIGINAL_COMMAND に入るだけ。
	if strings.Contains(out, "\nSHOULD_NOT_RUN\n") {
		t.Errorf("要求したコマンドが実行されてしまった:\n%s", out)
	}
	if !strings.Contains(out, "original=[echo SHOULD_NOT_RUN]") {
		t.Errorf("SSH_ORIGINAL_COMMAND が渡っていない:\n%s", out)
	}
}

// 証明書が無ければ認証できないこと。
//
// 証明書は発行せず、素の鍵だけで接続する。鍵と同じディレクトリに
// <key>-cert.pub を置くと OpenSSH が自動で読み込むため、証明書を
// 一切作らない別パスの鍵を使う。
func TestE2E_NoCertificateIsRejected(t *testing.T) {
	e := setup(t, "fighter", "fighter")
	keyPath := e.bareKey(t)

	args := []string{
		"-p", fmt.Sprint(e.port),
		"-i", keyPath,
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "PreferredAuthentications=publickey",
		fmt.Sprintf("%s@127.0.0.1", e.user),
		"true",
	}
	out, err := exec.Command("ssh", args...).CombinedOutput()
	if err == nil {
		t.Fatalf("証明書無しで認証が通ってしまった:\n%s", out)
	}
	// 「接続できなかった」で通ってしまうと、この検査は何も確かめていない。
	// 認証の段階で拒否されたことを確認する。
	assertAuthRejected(t, out)
}

// assertAuthRejected は、失敗が認証拒否によるものであることを確認する。
// 接続断や sshd 未起動で「失敗したから合格」としないためのもの。
func assertAuthRejected(t *testing.T, out []byte) {
	t.Helper()
	s := string(out)
	for _, bad := range []string{"Connection refused", "Connection reset", "No route to host"} {
		if strings.Contains(s, bad) {
			t.Fatalf("認証以前の理由で失敗している (この検査は無意味になっている):\n%s", s)
		}
	}
	if !strings.Contains(s, "Permission denied") {
		t.Fatalf("認証拒否として失敗していない:\n%s", s)
	}
}

// principal が合わない証明書では認証できないこと。
func TestE2E_WrongPrincipalIsRejected(t *testing.T) {
	// sshd は "fighter" のみを許可し、発行サーバは "intruder" を発行する。
	e := setup(t, "fighter", "intruder")

	keyPath, certPath := e.issueCert(t)
	out, err := e.ssh(t, keyPath, certPath, "true")
	if err == nil {
		t.Fatalf("許可されていない principal で認証が通ってしまった:\n%s", out)
	}
	assertAuthRejected(t, []byte(out))
}

// sshd が信頼していない CA で署名された証明書を拒否すること。
//
// principal も force-command も正しいが、署名者だけが違う。ここが通ると
// 「証明書さえ持っていれば入れる」ことになり、CA を信頼する意味が消える。
func TestE2E_UntrustedCAIsRejected(t *testing.T) {
	e := setup(t, "fighter", "fighter")

	// sshd が信頼していない別の CA を用意する。
	otherDir := t.TempDir()
	otherCAPath := filepath.Join(otherDir, "ca")
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "other-ca", "-f", otherCAPath)
	other, err := ca.LoadFile(otherCAPath)
	if err != nil {
		t.Fatal(err)
	}

	// クライアント鍵を作り、別 CA で署名する。
	keyPath := filepath.Join(otherDir, "id_ed25519")
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "client", "-f", keyPath)
	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ca.ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := other.Issue(ca.Request{
		PublicKey:  pub,
		KeyID:      "untrusted",
		Principals: []string{"fighter"},
		Validity:   5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	certPath := keyPath + "-cert.pub"
	if err := os.WriteFile(certPath, []byte(ca.Marshal(cert)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := e.ssh(t, keyPath, certPath, "true")
	if err == nil {
		t.Fatalf("信頼していない CA の証明書で認証が通ってしまった:\n%s", out)
	}
	assertAuthRejected(t, []byte(out))
}
