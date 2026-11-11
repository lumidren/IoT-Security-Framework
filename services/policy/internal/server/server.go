// Package server wires the HTTP routes of the policy service and runs the listener with graceful
// shutdown.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/policy/internal/problem"
)

// Config lists the handlers mounted on the listener.
type Config struct {
	// Authn serves POST /emqx/authn.
	Authn http.Handler
	// Authz serves POST /emqx/authz.
	Authz http.Handler
	// Revocations serves POST /internal/v1/revocations.
	Revocations http.Handler
	// Metrics serves GET /metrics.
	Metrics http.Handler
	// Register mounts additional routes (the management API).
	Register func(mux *http.ServeMux)
	// HookToken, when set, must be presented by EMQX in X-IronMesh-Hook-Token on /emqx/*.
	HookToken string
	// Ready returns nil when the service may receive traffic.
	Ready  func() error
	Logger *slog.Logger
}

// NewHandler builds the root handler.
func NewHandler(cfg Config) http.Handler {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()
	if cfg.Authn != nil {
		mux.Handle("/emqx/authn", requireHookToken(cfg.HookToken, cfg.Authn))
	}
	if cfg.Authz != nil {
		mux.Handle("/emqx/authz", requireHookToken(cfg.HookToken, cfg.Authz))
	}
	if cfg.Revocations != nil {
		mux.Handle("/internal/v1/revocations", cfg.Revocations)
	}
	if cfg.Metrics != nil {
		mux.Handle("GET /metrics", cfg.Metrics)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Ready != nil {
			if err := cfg.Ready(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": err.Error()})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	if cfg.Register != nil {
		cfg.Register(mux)
	}
	return recoverer(log, securityHeaders(mux))
}

// Run listens on addr and serves h until ctx is cancelled, then shuts down within timeout.
func Run(ctx context.Context, addr string, h http.Handler, timeout time.Duration, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return Serve(ctx, ln, h, timeout, log)
}

// Serve serves h on ln until ctx is cancelled, then shuts down within timeout.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, timeout time.Duration, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", ln.Addr().String())
		errCh <- srv.Serve(ln)
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	log.Info("http server shutting down")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	// After Shutdown, Serve returns http.ErrServerClosed; anything else is a real failure.
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func requireHookToken(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-IronMesh-Hook-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			problem.Write(w, r, http.StatusUnauthorized, "missing or invalid hook token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("handler panic", "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				problem.Write(w, r, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
