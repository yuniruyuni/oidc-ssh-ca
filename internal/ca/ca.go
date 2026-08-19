// Package ca は SSH ユーザ証明書の発行を行う。
//
// 証明書の意味論を間違えると、テストで気づきにくい形で権限が広がる
// (extension を消し忘れる、critical options の名前を間違える、有効期限の
// 向きを誤る)。そのため組み立ては golang.org/x/crypto/ssh に任せ、この
// パッケージは「何を渡すか」の判断だけを持つ。
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// minRSABits は受け付ける RSA 公開鍵の最小ビット数。
const minRSABits = 2048

// clockSkew は ValidAfter を過去にずらす幅。
//
// 発行側と検証側の時刻がわずかにずれていると、発行直後の証明書が
// "not yet valid" で弾かれる。短命証明書ではこれが実害になるため
// 少しだけ遡らせる。広げすぎると有効期間が延びるので最小限にする。
const clockSkew = 30 * time.Second

// allowedKeyTypes は証明書を発行してよいクライアント公開鍵の種類。
//
// ssh-dss は OpenSSH で既定無効の弱い方式なので受け付けない。
var allowedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoRSA:        true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoSKECDSA256: true,
}

// CA は署名鍵を保持する。
type CA struct {
	signer ssh.Signer
	// now はテストから時刻を差し替えるためのフック。
	now func() time.Time
}

// New は署名器から CA を作る。
func New(signer ssh.Signer) *CA {
	return &CA{signer: signer, now: time.Now}
}

// LoadFile は PEM 形式の秘密鍵ファイルから CA を作る。
// パスフレーズ付きの鍵は扱わない (自動起動できないため)。
func LoadFile(path string) (*CA, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("CA 鍵を読めない: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("CA 鍵を解析できない: %w", err)
	}
	return New(signer), nil
}

// PublicKey は CA の公開鍵を返す。sshd の TrustedUserCAKeys に置く値。
func (c *CA) PublicKey() ssh.PublicKey { return c.signer.PublicKey() }

// Request は 1 件の発行要求。
//
// ここに入る値は全て「一致したルール」由来でなければならない。
// リクエストボディ由来の値を混ぜてはいけない。
type Request struct {
	PublicKey    ssh.PublicKey
	KeyID        string
	Principals   []string
	ForceCommand string
	Extensions   []string
	Validity     time.Duration
}

// ParsePublicKey はクライアントが提出した公開鍵を検証して返す。
//
// authorized_keys 形式を受け取り、証明書と弱い鍵を拒否する。
func ParsePublicKey(s string) (ssh.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("公開鍵が空")
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("公開鍵を解析できない: %w", err)
	}
	// 複数行を渡して 2 行目以降を紛れ込ませる余地を残さない。
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("公開鍵は 1 つだけ指定する")
	}

	// 証明書を提出されると、こちらが署名した「証明書の証明書」ができる。
	// 意味論が壊れるので明示的に拒否する。
	if _, ok := pub.(*ssh.Certificate); ok {
		return nil, errors.New("証明書ではなく公開鍵を指定する")
	}

	if !allowedKeyTypes[pub.Type()] {
		return nil, fmt.Errorf("許可されていない鍵種別: %s", pub.Type())
	}

	// RSA は鍵長が短いと弱いため下限を設ける。
	if ck, ok := pub.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
			if bits := rk.N.BitLen(); bits < minRSABits {
				return nil, fmt.Errorf("RSA 鍵長が短い: %d bit (最小 %d bit)", bits, minRSABits)
			}
		}
	}

	return pub, nil
}

// Issue は証明書を発行する。
func (c *CA) Issue(req Request) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, errors.New("公開鍵が無い")
	}
	if _, ok := req.PublicKey.(*ssh.Certificate); ok {
		return nil, errors.New("証明書には署名しない")
	}
	if len(req.Principals) == 0 {
		// principal の無い証明書は OpenSSH では「全 principal で有効」と
		// 解釈されうる。空のまま発行してはいけない。
		return nil, errors.New("principals が空")
	}
	if req.Validity <= 0 {
		return nil, errors.New("validity が正でない")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := c.now()
	cert := &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: append([]string(nil), req.Principals...),
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(now.Add(req.Validity).Unix()),
	}

	// 既定では extension を一切付けない。permit-pty すら不要で、
	// デプロイに必要なのはコマンド実行だけ。
	cert.Permissions.Extensions = map[string]string{}
	for _, e := range req.Extensions {
		cert.Permissions.Extensions[e] = ""
	}

	if req.ForceCommand != "" {
		cert.Permissions.CriticalOptions = map[string]string{
			"force-command": req.ForceCommand,
		}
	}

	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("証明書に署名できない: %w", err)
	}
	return cert, nil
}

// Marshal は証明書を authorized_keys 形式の 1 行にする。
func Marshal(cert *ssh.Certificate) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("シリアルを生成できない: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
