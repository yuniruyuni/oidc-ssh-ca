// Package server は発行エンドポイントを提供する。
//
// このパッケージは認可の判断を持たない。判断は verify (トークンが本物か) と
// rule (そのトークンに発行してよいか) にあり、ここは両者を繋いで結果を
// HTTP に載せるだけ。
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/ca"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/rule"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/verify"
)

// maxBodyBytes はリクエストボディの上限。公開鍵 1 つが入れば足りる。
const maxBodyBytes = 8 << 10

// Server は発行エンドポイント。
type Server struct {
	verifier *verify.Verifier
	rules    []rule.Rule
	ca       *ca.CA
	log      *slog.Logger
}

// New はサーバを組み立てる。
func New(v *verify.Verifier, rules []rule.Rule, authority *ca.CA, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{verifier: v, rules: rules, ca: authority, log: log}
}

// Handler はルーティング済みの http.Handler を返す。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /issue", s.handleIssue)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

type issueRequest struct {
	PublicKey string `json:"public_key"`
}

type issueResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	ValidBefore int64    `json:"valid_before"`
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	reqID := requestID()
	log := s.log.With("request_id", reqID)

	token, err := bearerToken(r)
	if err != nil {
		log.Warn("認証情報が無い", "error", err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body issueRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		log.Warn("リクエストボディを解析できない", "error", err)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// トークンが本物であること。ここを通っても、発行してよいかは未確定。
	claims, err := s.verifier.Verify(r.Context(), token)
	if err != nil {
		// トークン本体は決してログに出さない。
		log.Warn("トークンを検証できない", "error", err)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	matched, ok := s.match(claims, log)
	if !ok {
		// どのルールにどう外れたかは応答に含めない。探索の手掛かりになる。
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	pub, err := ca.ParsePublicKey(body.PublicKey)
	if err != nil {
		log.Warn("公開鍵が不正", "rule", matched.Name, "error", err)
		writeError(w, http.StatusBadRequest, "invalid public key")
		return
	}

	// 発行内容は全て matched 由来。リクエストからは公開鍵しか使わない。
	cert, err := s.ca.Issue(ca.Request{
		PublicKey:    pub,
		KeyID:        keyID(matched.Name, claims, reqID),
		Principals:   matched.Principals,
		ForceCommand: matched.ForceCommand,
		Extensions:   matched.Extensions,
		Validity:     matched.Validity,
	})
	if err != nil {
		log.Error("証明書を発行できない", "rule", matched.Name, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Info("証明書を発行した",
		"rule", matched.Name,
		"repository_id", claims.RepositoryID.String(),
		"job_workflow_ref", claims.JobWorkflowRef.String(),
		"environment", claims.Environment.String(),
		"principals", matched.Principals,
		"serial", cert.Serial,
		"valid_before", cert.ValidBefore,
	)

	writeJSON(w, http.StatusOK, issueResponse{
		Certificate: ca.Marshal(cert),
		Principals:  matched.Principals,
		ValidBefore: int64(cert.ValidBefore),
	})
}

// match は最初に一致したルールを返す。
// 一致しなかった場合、どのルールがどの項目で外れたかをログに残す。
func (s *Server) match(claims rule.Claims, log *slog.Logger) (rule.Rule, bool) {
	for _, r := range s.rules {
		res := r.Match(claims)
		if res.Allowed {
			return r, true
		}
		log.Debug("ルールに一致しない", "rule", r.Name, "reason", string(res.Reason), "field", res.Field)
	}
	log.Warn("一致するルールが無い",
		"repository_id", claims.RepositoryID.String(),
		"job_workflow_ref", claims.JobWorkflowRef.String(),
		"environment", claims.Environment.String(),
	)
	return rule.Rule{}, false
}

// keyID は証明書に埋める識別子。sshd のログと発行側のログを突き合わせる
// ために使う。
func keyID(ruleName string, claims rule.Claims, reqID string) string {
	return fmt.Sprintf("%s repo=%s req=%s", ruleName, claims.RepositoryID.String(), reqID)
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("Authorization ヘッダが無い")
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", errors.New("Bearer スキームではない")
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", errors.New("トークンが空")
	}
	return tok, nil
}

func requestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// Timeouts は http.Server に設定する既定のタイムアウト。
// 発行は数ミリ秒で終わるので短くてよい。
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 10 * time.Second
	IdleTimeout       = 30 * time.Second
)
