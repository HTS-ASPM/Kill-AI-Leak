package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
)

// requestIDHeader is the canonical header for request tracing.
const requestIDHeader = "X-Request-ID"

// ---- RequestID Middleware ----

// RequestID injects a unique X-Request-ID into every request. If the caller
// already provides one it is preserved.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = generateID()
		}
		w.Header().Set(requestIDHeader, id)

		ctx := logger.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---- Logging Middleware ----

// Logging emits a structured JSON log entry for every completed HTTP
// request including method, path, status, and duration.
func Logging(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			duration := time.Since(start)
			log.Info(r.Context(), "http request completed", map[string]any{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      sw.status,
				"duration_ms": duration.Milliseconds(),
				"bytes":       sw.written,
				"remote_addr": r.RemoteAddr,
				"user_agent":  r.UserAgent(),
			})
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture the status code and
// bytes written.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int64
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.written += int64(n)
	return n, err
}

// ---- Recovery Middleware ----

// Recovery catches panics in downstream handlers, logs them, and returns a
// 500 response so the server keeps running.
func Recovery(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := string(debug.Stack())
					log.Error(r.Context(), "panic recovered", map[string]any{
						"panic": fmt.Sprintf("%v", rec),
						"stack": stack,
					})

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "internal server error",
					})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ---- CORS Middleware ----

// CORSOptions configures the CORS middleware.
type CORSOptions struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int // seconds
}

// DefaultCORSOptions returns a sensible default for development. In
// production the allowed origins should be locked down.
func DefaultCORSOptions() CORSOptions {
	return CORSOptions{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders: []string{"Content-Type", "Authorization", "X-APP-ID", "X-Request-ID"},
		MaxAge:         86400,
	}
}

// CORS handles Cross-Origin Resource Sharing.
func CORS(opts CORSOptions) func(http.Handler) http.Handler {
	origins := strings.Join(opts.AllowedOrigins, ", ")
	methods := strings.Join(opts.AllowedMethods, ", ")
	headers := strings.Join(opts.AllowedHeaders, ", ")
	maxAge := fmt.Sprintf("%d", opts.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origins)
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", maxAge)

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ---- Timeout Middleware ----

// Timeout enforces a per-request timeout. When the deadline is reached the
// context is cancelled and a 504 is returned.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()

			done := make(chan struct{})
			tw := &timeoutWriter{ResponseWriter: w, header: make(http.Header)}

			go func() {
				next.ServeHTTP(tw, r.WithContext(ctx))
				close(done)
			}()

			select {
			case <-done:
				// Copy headers that the handler set.
				for k, v := range tw.header {
					for _, vv := range v {
						w.Header().Add(k, vv)
					}
				}
				if tw.code != 0 {
					w.WriteHeader(tw.code)
				}
				_, _ = w.Write(tw.body)
			case <-ctx.Done():
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGatewayTimeout)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "request timed out",
				})
			}
		})
	}
}

// timeoutWriter buffers the response so we can discard it on timeout.
type timeoutWriter struct {
	http.ResponseWriter
	header http.Header
	body   []byte
	code   int
}

func (tw *timeoutWriter) Header() http.Header {
	return tw.header
}

func (tw *timeoutWriter) WriteHeader(code int) {
	tw.code = code
}

func (tw *timeoutWriter) Write(b []byte) (int, error) {
	tw.body = append(tw.body, b...)
	return len(b), nil
}

// ---- Chain Helper ----

// Chain composes middleware functions left-to-right so the first argument
// is the outermost wrapper.
func Chain(handler http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}

// generateID produces a 16-byte hex-encoded random string.
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to timestamp-based ID.
		return fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
