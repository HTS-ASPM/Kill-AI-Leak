package middleware

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kill-ai-leak/kill-ai-leak/internal/logger"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/config"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// actorKey is an unexported type for the context key that stores the actor.
type actorKey struct{}

// ActorFromContext retrieves the authenticated Actor attached to the request
// context by the Auth middleware.
func ActorFromContext(ctx context.Context) *models.Actor {
	if v, ok := ctx.Value(actorKey{}).(*models.Actor); ok {
		return v
	}
	return nil
}

// ServiceRegistry maps APP-ID values to service identity information.
// In production this would back onto a database or config store; here we
// provide a simple in-memory implementation.
type ServiceRegistry struct {
	services map[string]*ServiceIdentity
}

// ServiceIdentity represents a registered service and its associated actor.
type ServiceIdentity struct {
	AppID     string
	Name      string
	Namespace string
	Team      string
	Labels    map[string]string
}

// NewServiceRegistry creates a registry pre-populated from configuration.
func NewServiceRegistry(authCfg config.AuthConfig) *ServiceRegistry {
	reg := &ServiceRegistry{
		services: make(map[string]*ServiceIdentity, len(authCfg.ServiceKeys)),
	}
	for appID, name := range authCfg.ServiceKeys {
		reg.services[appID] = &ServiceIdentity{
			AppID: appID,
			Name:  name,
		}
	}
	return reg
}

// Lookup returns the identity for the given APP-ID, or nil if not found.
func (r *ServiceRegistry) Lookup(appID string) *ServiceIdentity {
	return r.services[appID]
}

// Register adds or updates a service identity.
func (r *ServiceRegistry) Register(identity *ServiceIdentity) {
	r.services[identity.AppID] = identity
}

// Auth returns middleware that validates the APP-ID header, resolves the
// service identity, and attaches the Actor to the request context.
// When auth is disabled in config the middleware is a no-op pass-through.
func Auth(cfg config.AuthConfig, registry *ServiceRegistry, log *logger.Logger) func(http.Handler) http.Handler {
	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "X-APP-ID"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			appID := r.Header.Get(headerName)
			if appID == "" {
				log.Warn(r.Context(), "missing APP-ID header", map[string]any{
					"header":    headerName,
					"remote_ip": r.RemoteAddr,
				})
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "missing " + headerName + " header",
				})
				return
			}

			identity := registry.Lookup(appID)
			if identity == nil {
				log.Warn(r.Context(), "unknown APP-ID", map[string]any{
					"app_id":    appID,
					"remote_ip": r.RemoteAddr,
				})
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "unrecognized APP-ID",
				})
				return
			}

			actor := &models.Actor{
				Type:      models.ActorServiceAccount,
				ID:        identity.AppID,
				Name:      identity.Name,
				Namespace: identity.Namespace,
				Team:      identity.Team,
				Labels:    identity.Labels,
			}

			ctx := context.WithValue(r.Context(), actorKey{}, actor)
			ctx = logger.WithFields(ctx, map[string]any{
				"app_id":       identity.AppID,
				"service_name": identity.Name,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
