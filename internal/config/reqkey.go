package config

import (
	"net"
	"net/http"
	"strings"
)

// ResolveRequestKey returns a string identifying the caller for per-client tracking.
//
//   - "api_key"  — x-llm-api-key header, then Authorization Bearer token; falls back to IP
//   - "global"   — constant; all callers share one bucket
//   - "" / "ip"  — X-Real-IP (set by reverse proxy), then RemoteAddr
func ResolveRequestKey(r *http.Request, keyBy string) string {
	switch keyBy {
	case "api_key":
		if k := strings.TrimSpace(r.Header.Get("x-llm-api-key")); k != "" {
			return "k:" + k
		}
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return "k:" + strings.TrimSpace(auth[7:])
		}
		// No key found — fall through to IP
	case "global":
		return "global"
	}
	// Prefer X-Real-IP — set by nginx/Caddy and cannot be spoofed by the client.
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
