// Command server is a net/http service with log/slog, request IDs, trusted-proxy client IP
// and Bower security events for sign-in and authorisation. Run a Bower collector with the
// owasp-asvs-app-logging pack, then: BOWER_INGEST_TOKEN=... go run ./cmd/server
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"example.com/bower-asvs-logging/bowerevents"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIPKey
)

var (
	app   = bowerevents.App{Name: "go-example", Environment: envOr("APP_ENV", "development"), Version: "1.0.0"}
	bower = bowerevents.NewClient()
	// No proxy is trusted unless TRUSTED_PROXIES names it (for example your load balancer CIDR).
	trusted = parsePrefixes(os.Getenv("TRUSTED_PROXIES"))
	// Application logs: JSON, UTC, and a ReplaceAttr that drops secret-named attributes.
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: redactAttr}))
)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func parsePrefixes(list string) []netip.Prefix {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(item); err == nil {
			// A bare address is a single host, as in the other examples.
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

func redactAttr(_ []string, a slog.Attr) slog.Attr {
	switch strings.ToLower(a.Key) {
	case "password", "token", "authorization", "cookie", "body":
		return slog.String(a.Key, "[removed]")
	}
	if a.Value.Kind() == slog.KindString {
		// Values are JSON-encoded by the handler; strip line breaks for text sinks too (V16.4.1).
		return slog.String(a.Key, strings.NewReplacer("\r", " ", "\n", " ").Replace(a.Value.String()))
	}
	return a
}

// withContext adds a request ID (honouring a W3C traceparent) and the trusted client IP.
func withContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := bowerevents.NewEventID()
		if tp := r.Header.Get("traceparent"); len(tp) == 55 {
			id = tp[3:35]
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := bowerevents.ClientIP(host, r.Header.Get("X-Forwarded-For"), trusted)
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(context.WithValue(r.Context(), requestIDKey, id), clientIPKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func emit(r *http.Request, route string, spec bowerevents.Spec) {
	spec.SourceIP, _ = r.Context().Value(clientIPKey).(string)
	spec.UserAgent = r.UserAgent()
	spec.Route = route
	id, _ := r.Context().Value(requestIDKey).(string)
	spec.Request = map[string]any{"correlationId": id, "method": r.Method, "path": r.URL.Path}
	event := bowerevents.Build(app, spec, "", time.Now())
	// Detach from the request so a slow collector never delays the response.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if status := bower.Send(ctx, event); status == 0 || status >= 400 {
			logger.Warn("bower event not accepted", "status", status, "eventType", spec.EventType, "requestId", id)
		}
	}()
}

func login(w http.ResponseWriter, r *http.Request) {
	var body struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		emit(r, "/login", bowerevents.Spec{EventCategory: "application-security", EventType: "input_validation_failure",
			EventAction: "validation.reject", EventResult: "failure", EventSeverity: "low", Reason: "MalformedJson"})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Demo credential check; use your identity provider.
	ok := subtle.ConstantTimeCompare([]byte(body.Username+":"+body.Password), []byte("demo:demo-password")) == 1
	if !ok {
		emit(r, "/login", bowerevents.Spec{EventCategory: "authentication", EventType: "authentication_failure",
			EventAction: "authentication.attempt", EventResult: "failure", EventSeverity: "low", Reason: "InvalidCredentials",
			Actor: map[string]any{"username": body.Username}})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	emit(r, "/login", bowerevents.Spec{EventCategory: "authentication", EventType: "authentication_success",
		EventAction: "authentication.login", EventResult: "success", Actor: map[string]any{"userId": "user-demo", "username": body.Username},
		Labels: map[string]string{"authMethod": "password"}})
	w.WriteHeader(http.StatusNoContent)
}

func admin(w http.ResponseWriter, r *http.Request) {
	// Demo: everyone is denied.
	emit(r, "/admin/users", bowerevents.Spec{EventCategory: "authorisation", EventType: "authorisation_failure",
		EventAction: "authz.function", EventResult: "denied", EventSeverity: "medium",
		Actor: map[string]any{"userId": "user-demo", "role": "member"}, Target: map[string]any{"type": "function", "id": "admin.users.list"},
		Labels: map[string]string{"requiredPermission": "users.read"}})
	http.Error(w, "forbidden", http.StatusForbidden)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", login)
	mux.HandleFunc("GET /admin/users", admin)
	server := &http.Server{Addr: envOr("LISTEN", "127.0.0.1:8080"), Handler: withContext(mux), ReadHeaderTimeout: 5 * time.Second}
	logger.Info("listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		logger.Error("server stopped", "error", err)
	}
}
