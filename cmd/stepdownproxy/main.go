package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quentinmayo/StepDownproxy/internal/gateway"
)

func main() {
	config := flag.String("config", "config.json", "configuration path")
	admin := flag.String("admin-listen", "", "optional management listener; use a private or loopback address")
	adminToken := flag.String("admin-token-file", "", "mounted admin credential; otherwise STEPDOWN_ADMIN_TOKEN")
	state := flag.String("state", "", "asset state file for optional console")
	cert := flag.String("tls-cert", "", "server TLS certificate for both listeners")
	key := flag.String("tls-key", "", "server TLS key for both listeners")
	check := flag.Bool("check", false, "validate configuration and caller credentials, then exit")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fatal := func(message string) { logger.Error(message); os.Exit(1) }
	if (*cert == "") != (*key == "") {
		fatal("TLS certificate and key must be supplied together")
	}
	c, err := gateway.LoadConfig(*config)
	if err != nil {
		fatal(err.Error())
	}
	m, err := gateway.NewManager(c, *state, &gateway.Audit{Logger: logger})
	if err != nil {
		fatal(err.Error())
	}
	servers := []*http.Server{}
	add := func(addr string, h http.Handler) {
		servers = append(servers, &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)})
	}
	add(c.Listen, m)
	if *admin != "" {
		ref := gateway.SecretRef{Provider: "env", Ref: "STEPDOWN_ADMIN_TOKEN"}
		if *adminToken != "" {
			ref = gateway.SecretRef{Provider: "file", Ref: *adminToken}
		}
		h, err := m.Admin(ref)
		if err != nil {
			fatal(err.Error())
		}
		add(*admin, h)
	}
	if *check {
		logger.Info("configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var failed atomic.Bool
	for _, s := range servers {
		go func() {
			logger.Info("listener started", "address", s.Addr)
			var err error
			if *cert != "" {
				err = s.ListenAndServeTLS(*cert, *key)
			} else {
				err = s.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				failed.Store(true)
				logger.Error("listener failed")
				stop()
			}
		}()
	}
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	if failed.Load() {
		os.Exit(1)
	}
}
