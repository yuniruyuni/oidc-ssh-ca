package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return New(signer)
}

func testUserKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func authorizedKey(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func TestIssue_Fields(t *testing.T) {
	c := testCA(t)
	pub := testUserKey(t)

	cert, err := c.Issue(Request{
		PublicKey:    pub,
		KeyID:        "run-123",
		Principals:   []string{"fighter"},
		ForceCommand: "/usr/local/bin/app-deploy",
		Validity:     5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("発行に失敗: %v", err)
	}

	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType: got %d want UserCert", cert.CertType)
	}
	if got := cert.ValidPrincipals; len(got) != 1 || got[0] != "fighter" {
		t.Errorf("ValidPrincipals: got %v", got)
	}
	if cert.KeyId != "run-123" {
		t.Errorf("KeyId: got %q", cert.KeyId)
	}
	if got := cert.Permissions.CriticalOptions["force-command"]; got != "/usr/local/bin/app-deploy" {
		t.Errorf("force-command: got %q", got)
	}
	// 既定で extension は 1 つも付かないこと。
	if len(cert.Permissions.Extensions) != 0 {
		t.Errorf("既定で extension が付いている: %v", cert.Permissions.Extensions)
	}
	// 有効期間が想定どおりであること。
	span := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Unix(int64(cert.ValidAfter), 0))
	want := 5*time.Minute + clockSkew
	if span != want {
		t.Errorf("有効期間: got %v want %v", span, want)
	}
}

// fakeConn は CertChecker.Authenticate に渡す最小の ConnMetadata。
// 認可判断に使われるのは User() だけ。
type fakeConn struct{ user string }

func (f fakeConn) User() string          { return f.user }
func (f fakeConn) SessionID() []byte     { return nil }
func (f fakeConn) ClientVersion() []byte { return nil }
func (f fakeConn) ServerVersion() []byte { return nil }
func (f fakeConn) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (f fakeConn) LocalAddr() net.Addr   { return &net.TCPAddr{} }

func checkerFor(c *CA) *ssh.CertChecker {
	return &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(c.PublicKey().Marshal())
		},
	}
}

// サーバ側の認可入口である Authenticate で検証する。
//
// CertChecker.CheckCert は署名を検証するが IsUserAuthority を呼ばない。
// 「どの CA を信頼するか」を確かめられるのは Authenticate のほうなので、
// そちらを使わないと別 CA の証明書を弾けているか確認できない。
func TestAuthenticate(t *testing.T) {
	c := testCA(t)
	cert, err := c.Issue(Request{
		PublicKey:  testUserKey(t),
		Principals: []string{"fighter"},
		Validity:   5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("正当な principal と CA", func(t *testing.T) {
		if _, err := checkerFor(c).Authenticate(fakeConn{user: "fighter"}, cert); err != nil {
			t.Fatalf("認証に失敗: %v", err)
		}
	})

	t.Run("別 principal", func(t *testing.T) {
		if _, err := checkerFor(c).Authenticate(fakeConn{user: "stream-tag-inventory"}, cert); err == nil {
			t.Fatal("別 principal で認証が通ってしまった")
		}
	})

	t.Run("別 CA を権威とする", func(t *testing.T) {
		other := testCA(t)
		if _, err := checkerFor(other).Authenticate(fakeConn{user: "fighter"}, cert); err == nil {
			t.Fatal("信頼していない CA の証明書で認証が通ってしまった")
		}
	})
}

func TestIssue_Expired(t *testing.T) {
	c := testCA(t)
	// 発行時刻を過去に固定し、期限切れの証明書を作る。
	c.now = func() time.Time { return time.Now().Add(-1 * time.Hour) }

	cert, err := c.Issue(Request{
		PublicKey:  testUserKey(t),
		Principals: []string{"fighter"},
		Validity:   5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := checkerFor(c).Authenticate(fakeConn{user: "fighter"}, cert); err == nil {
		t.Fatal("期限切れの証明書が通ってしまった")
	}
}

func TestIssue_Rejects(t *testing.T) {
	c := testCA(t)
	pub := testUserKey(t)

	tests := []struct {
		name string
		req  Request
	}{
		{"公開鍵が無い", Request{Principals: []string{"p"}, Validity: time.Minute}},
		{"principals が空", Request{PublicKey: pub, Validity: time.Minute}},
		{"validity が 0", Request{PublicKey: pub, Principals: []string{"p"}}},
		{"validity が負", Request{PublicKey: pub, Principals: []string{"p"}, Validity: -time.Minute}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := c.Issue(tt.req); err == nil {
				t.Fatal("拒否されるべき要求が受理された")
			}
		})
	}
}

// 証明書を公開鍵として提出されても署名しないこと。
// 通すと「証明書の証明書」ができ、意味論が壊れる。
func TestIssue_RejectsCertificateAsInput(t *testing.T) {
	c := testCA(t)
	cert, err := c.Issue(Request{
		PublicKey:  testUserKey(t),
		Principals: []string{"fighter"},
		Validity:   time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Issue(Request{
		PublicKey:  cert,
		Principals: []string{"fighter"},
		Validity:   time.Minute,
	}); err == nil {
		t.Fatal("証明書に署名してしまった")
	}

	// 文字列経由でも同様に拒否されること。
	if _, err := ParsePublicKey(Marshal(cert)); err == nil {
		t.Fatal("証明書が公開鍵として受理された")
	}
}

func TestParsePublicKey(t *testing.T) {
	valid := authorizedKey(t, testUserKey(t))

	t.Run("正当な ed25519 鍵", func(t *testing.T) {
		if _, err := ParsePublicKey(valid); err != nil {
			t.Fatalf("正当な鍵が拒否された: %v", err)
		}
	})

	t.Run("前後の空白は許容", func(t *testing.T) {
		if _, err := ParsePublicKey("  " + valid + "\n"); err != nil {
			t.Fatalf("空白付きの鍵が拒否された: %v", err)
		}
	})

	t.Run("空文字", func(t *testing.T) {
		if _, err := ParsePublicKey(""); err == nil {
			t.Fatal("空文字が受理された")
		}
	})

	t.Run("壊れた鍵", func(t *testing.T) {
		if _, err := ParsePublicKey("ssh-ed25519 not-base64"); err == nil {
			t.Fatal("壊れた鍵が受理された")
		}
	})

	// 2 行目を紛れ込ませられないこと。
	t.Run("複数行", func(t *testing.T) {
		if _, err := ParsePublicKey(valid + "\n" + valid); err == nil {
			t.Fatal("複数行が受理された")
		}
	})

	t.Run("短い RSA 鍵", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Skipf("1024bit RSA を生成できない: %v", err)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePublicKey(authorizedKey(t, pub)); err == nil {
			t.Fatal("1024bit の RSA 鍵が受理された")
		}
	})

	t.Run("十分な長さの RSA 鍵", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParsePublicKey(authorizedKey(t, pub)); err != nil {
			t.Fatalf("2048bit の RSA 鍵が拒否された: %v", err)
		}
	})
}

// 実際の OpenSSH が我々の証明書を解釈できることを確認する。
//
// x/crypto/ssh は署名と検証の両方を同じ実装で行うため、それだけでは
// 「OpenSSH が受け入れるか」の保証にならない。extension や critical
// options の名前を間違えても自己検証は通ってしまう。
func TestIssue_ParsedByOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen が無い")
	}

	c := testCA(t)
	cert, err := c.Issue(Request{
		PublicKey:    testUserKey(t),
		KeyID:        "run-456",
		Principals:   []string{"fighter", "fighter-migration"},
		ForceCommand: "/usr/local/bin/app-deploy",
		Extensions:   []string{"permit-pty"},
		Validity:     5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(path, []byte(Marshal(cert)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("ssh-keygen", "-L", "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen が証明書を解釈できない: %v\n%s", err, out)
	}
	got := string(out)

	for _, want := range []string{
		"Type: ssh-ed25519-cert-v01@openssh.com user certificate",
		"run-456",
		"fighter",
		"fighter-migration",
		"force-command",
		"/usr/local/bin/app-deploy",
		"permit-pty",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ssh-keygen の出力に %q が含まれない:\n%s", want, got)
		}
	}

	// 明示していない extension が紛れ込んでいないこと。
	for _, unwanted := range []string{
		"permit-port-forwarding",
		"permit-agent-forwarding",
		"permit-X11-forwarding",
		"permit-user-rc",
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("要求していない extension %q が付与されている:\n%s", unwanted, got)
		}
	}
}
