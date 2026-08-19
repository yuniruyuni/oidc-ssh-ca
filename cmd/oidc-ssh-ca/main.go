// Command oidc-ssh-ca は、GitHub Actions の OIDC トークンを検証し、
// claim に束縛された短命 SSH 証明書を発行するサーバ。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/yuniruyuni/oidc-ssh-ca/internal/ca"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/config"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/server"
	"github.com/yuniruyuni/oidc-ssh-ca/internal/verify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "oidc-ssh-ca: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "/etc/oidc-ssh-ca/config.toml", "設定ファイルのパス")
		showCAKey   = flag.Bool("show-ca-key", false, "CA の公開鍵を表示して終了する (sshd の TrustedUserCAKeys に置く値)")
		checkConfig = flag.Bool("check-config", false, "設定を検証して終了する")
	)
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	authority, err := ca.LoadFile(cfg.CAKeyPath)
	if err != nil {
		return err
	}

	if *showCAKey {
		fmt.Print(string(ssh.MarshalAuthorizedKey(authority.PublicKey())))
		return nil
	}

	if *checkConfig {
		fmt.Printf("設定は妥当。ルール %d 件\n", len(cfg.Rules))
		for _, r := range cfg.Rules {
			fmt.Printf("  %s -> principals=%v validity=%s\n", r.Name, r.Principals, r.Validity)
		}
		return nil
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// discovery はネットワークに出るのでタイムアウトを付ける。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	verifier, err := verify.New(ctx, cfg.Issuer)
	cancel()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(verifier, cfg.Rules, authority, log).Handler(),
		ReadHeaderTimeout: server.ReadHeaderTimeout,
		ReadTimeout:       server.ReadTimeout,
		WriteTimeout:      server.WriteTimeout,
		IdleTimeout:       server.IdleTimeout,
	}

	// SIGTERM を受けたら進行中のリクエストを捌いてから終了する。
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Info("起動した", "listen", cfg.Listen, "issuer", cfg.Issuer, "rules", len(cfg.Rules))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-shutdown:
		log.Info("終了する")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
