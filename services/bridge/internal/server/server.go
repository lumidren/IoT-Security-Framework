// Package server exposes the bridge HTTP surface: metrics, health, readiness and the EMQX events
// webhook.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

// Config lists the handlers mounted on the listener.
type Config struct {
	Metrics http.Handler
	Events  http.Handler
	// Ready returns nil when the bridge may receive traffic (MQTT session up, Kafka reachable).
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
	if cfg.Metrics != nil {
		mux.Handle("GET /metrics", cfg.Metrics)
	}
	if cfg.Events != nil {
		mux.Handle("/emqx/events", cfg.Events)
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
	return recoverer(log, mux)
}

// Run listens on addr and serves h until ctx is cancelled.
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
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	// After Shutdown, Serve returns http.ErrServerClosed; anything else is a real failure.
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("handler panic", "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
