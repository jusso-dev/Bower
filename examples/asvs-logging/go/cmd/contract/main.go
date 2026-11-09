// Command contract prints the contract events and proxy results as JSON lines (see ../../../contract).
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"example.com/bower-asvs-logging/bowerevents"
)

type cases struct {
	App   struct{ Name, Environment, Version string } `json:"app"`
	Now   string                                      `json:"now"`
	Cases []struct {
		EventID string         `json:"eventId"`
		Spec    map[string]any `json:"spec"`
	} `json:"cases"`
	ProxyCases []struct {
		Remote       string   `json:"remote"`
		ForwardedFor *string  `json:"forwardedFor"`
		Trusted      []string `json:"trusted"`
		Expect       string   `json:"expect"`
	} `json:"proxyCases"`
}

func str(m map[string]any, k string) string         { s, _ := m[k].(string); return s }
func obj(m map[string]any, k string) map[string]any { o, _ := m[k].(map[string]any); return o }

// pyJSON writes sorted keys with ", " and ": " separators, like Python's json.dumps.
func pyJSON(v any) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = pyJSON(k) + ": " + pyJSON(t[k])
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(t))
		for i, item := range t {
			parts[i] = pyJSON(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprint(t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var c cases
	if err := json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	now, _ := time.Parse(time.RFC3339Nano, c.Now)
	app := bowerevents.App{Name: c.App.Name, Environment: c.App.Environment, Version: c.App.Version}
	for _, item := range c.Cases {
		s := item.Spec
		labels := map[string]string{}
		for k, v := range obj(s, "labels") {
			labels[k] = fmt.Sprint(v)
		}
		spec := bowerevents.Spec{
			EventCategory: str(s, "eventCategory"), EventType: str(s, "eventType"), EventAction: str(s, "eventAction"),
			EventResult: str(s, "eventResult"), EventSeverity: str(s, "eventSeverity"), Reason: str(s, "reason"),
			SourceIP: str(s, "sourceIp"), UserAgent: str(s, "userAgent"), Route: str(s, "route"), TenantID: str(s, "tenantId"),
			Actor: obj(s, "actor"), Target: obj(s, "target"), Request: obj(s, "request"), Attributes: obj(s, "attributes"),
			Change: obj(s, "change"), Labels: labels,
		}
		fmt.Println(pyJSON(bowerevents.Build(app, spec, item.EventID, now)))
	}
	for _, p := range c.ProxyCases {
		var prefixes []netip.Prefix
		for _, cidr := range p.Trusted {
			prefixes = append(prefixes, netip.MustParsePrefix(cidr))
		}
		forwarded := ""
		if p.ForwardedFor != nil {
			forwarded = *p.ForwardedFor
		}
		fmt.Println(pyJSON(map[string]any{"clientIp": bowerevents.ClientIP(p.Remote, forwarded, prefixes)}))
	}
}
