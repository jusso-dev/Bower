// Package bowerevents builds Bower envelope 1.0.0 security events for Go services, sanitises
// them before they leave the process and posts them to a Bower collector. Standard library
// only. The collector redacts again; this is defence in depth.
package bowerevents

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

var (
	control         = regexp.MustCompile(`[\x00-\x1f\x7f\x{2028}\x{2029}]+`)
	nonAlnum        = regexp.MustCompile(`[^a-z0-9]`)
	secretFragments = []string{"password", "passwd", "passphrase", "secret", "token", "apikey", "cookie",
		"authorization", "credential", "privatekey", "signature"}
	secretNames = map[string]bool{"body": true, "rawbody": true, "requestbody": true, "responsebody": true,
		"headers": true, "payload": true, "otp": true, "otpcode": true, "totp": true, "mfacode": true,
		"verificationcode": true, "recoverycode": true, "backupcode": true, "stacktrace": true,
		"exceptionmessage": true, "statement": true, "querytext": true, "sqltext": true, "querystring": true, "rawquery": true}
	limits = map[string]int{"eventOutcomeReason": 1024, "path": 2048}
)

// App identifies the emitting application.
type App struct {
	Name, Environment, Version, Instance string
}

// Spec describes one event. Map-typed fields hold JSON-compatible values.
type Spec struct {
	EventCategory, EventType, EventAction, EventResult, EventSeverity string
	Reason, SourceIP, UserAgent, Route, TenantID                      string
	Actor, Target, Request, Attributes, Change                        map[string]any
	Labels                                                            map[string]string
}

func isSecret(name string) bool {
	normal := nonAlnum.ReplaceAllString(strings.ToLower(name), "")
	if secretNames[normal] {
		return true
	}
	for _, fragment := range secretFragments {
		if strings.Contains(normal, fragment) {
			return true
		}
	}
	return false
}

func truncate(text string, limit int) string {
	runes := []rune(text)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return text
}

func clean(value any, key string) any {
	switch v := value.(type) {
	case string:
		limit, ok := limits[key]
		if !ok {
			limit = 256
		}
		return truncate(control.ReplaceAllString(v, " "), limit)
	case map[string]string:
		out := map[string]any{}
		for name, item := range v {
			out[name] = item
		}
		return clean(out, key)
	case map[string]any:
		out := map[string]any{}
		for name, item := range v {
			if isSecret(name) || item == nil {
				continue
			}
			cleaned := clean(item, name)
			if m, ok := cleaned.(map[string]any); ok && len(m) == 0 {
				continue
			}
			out[truncate(control.ReplaceAllString(name, " "), 128)] = cleaned
		}
		return out
	case []any:
		if len(v) > 64 {
			v = v[:64]
		}
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = clean(item, "")
		}
		return out
	default:
		return v
	}
}

// FormatTime returns UTC with millisecond precision and a Z suffix (ASVS 5.0 V16.2.2).
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// NewEventID returns a random UUID v4.
func NewEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Build returns a sanitised envelope.
func Build(app App, spec Spec, eventID string, now time.Time) map[string]any {
	if eventID == "" {
		eventID = NewEventID()
	}
	application := map[string]any{"name": app.Name, "environment": app.Environment}
	if app.Version != "" {
		application["version"] = app.Version
	}
	if app.Instance != "" {
		application["instance"] = app.Instance
	}
	if spec.TenantID != "" {
		application["tenantId"] = spec.TenantID
	}
	severity := spec.EventSeverity
	if severity == "" {
		severity = "informational"
	}
	event := map[string]any{
		"schemaVersion": SchemaVersion, "eventId": eventID, "timeGenerated": FormatTime(now),
		"eventCategory": spec.EventCategory, "eventType": spec.EventType, "eventAction": spec.EventAction,
		"eventResult": spec.EventResult, "eventSeverity": severity, "application": application,
	}
	if spec.Reason != "" {
		event["eventOutcomeReason"] = spec.Reason
	}
	if len(spec.Actor) > 0 {
		event["actor"] = copyMap(spec.Actor)
	}
	if len(spec.Target) > 0 {
		event["target"] = copyMap(spec.Target)
	}
	if spec.SourceIP != "" {
		event["source"] = map[string]any{"ipAddress": spec.SourceIP}
	}
	request := copyMap(spec.Request)
	if path, ok := request["path"].(string); ok {
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			request["path"] = path[:i]
		}
	}
	if len(request) > 0 {
		event["request"] = request
	}
	labels := map[string]any{}
	for k, v := range spec.Labels {
		labels[k] = v
	}
	if spec.UserAgent != "" {
		labels["userAgent"] = spec.UserAgent
	}
	if spec.Route != "" {
		labels["route"] = spec.Route
	}
	if len(labels) > 0 {
		event["labels"] = labels
	}
	if len(spec.Attributes) > 0 {
		event["attributes"] = copyMap(spec.Attributes)
	}
	change := copyMap(spec.Change)
	// Before and after values of settings and credentials never leave the process.
	if len(change) > 0 && spec.EventType != "role_membership_changed" {
		if field, ok := change["field"]; ok {
			change = map[string]any{"field": field}
		} else {
			change = map[string]any{}
		}
	}
	if len(change) > 0 {
		event["change"] = change
	}
	return clean(event, "").(map[string]any)
}

// ClientIP returns the original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For
// is read only when the direct peer is a trusted proxy, right to left, skipping trusted hops.
func ClientIP(remote, forwardedFor string, trusted []netip.Prefix) string {
	isTrusted := func(address string) bool {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return false
		}
		for _, prefix := range trusted {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if forwardedFor == "" || !isTrusted(remote) {
		return remote
	}
	var hops []string
	for _, hop := range strings.Split(forwardedFor, ",") {
		if hop = strings.TrimSpace(hop); hop != "" {
			hops = append(hops, hop)
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !isTrusted(hops[i]) {
			if ip, err := netip.ParseAddr(hops[i]); err == nil {
				return ip.String()
			}
			return remote
		}
	}
	if len(hops) > 0 {
		return hops[0]
	}
	return remote
}

// Client posts events to a Bower collector. Send never panics into the request path.
type Client struct {
	Endpoint, Token string
	HTTP            *http.Client
}

// NewClient reads BOWER_COLLECTOR_URL and BOWER_INGEST_TOKEN.
func NewClient() *Client {
	endpoint := os.Getenv("BOWER_COLLECTOR_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4319"
	}
	return &Client{Endpoint: strings.TrimRight(endpoint, "/"), Token: os.Getenv("BOWER_INGEST_TOKEN"),
		HTTP: &http.Client{Timeout: 2 * time.Second}}
}

// Send posts one event and returns the HTTP status, or 0 when the collector is unreachable.
func (c *Client) Send(ctx context.Context, event map[string]any) int {
	body, err := json.Marshal(event)
	if err != nil {
		return 0
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/v1/events", bytes.NewReader(body))
	if err != nil {
		return 0
	}
	request.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}
