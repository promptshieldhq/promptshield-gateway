package config

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	trustedProxyCIDROnce sync.Once
	trustedProxyCIDRs    []*net.IPNet
)

// ResolveRequestKey returns a string identifying the caller for per-client tracking.
//
//   - "api_key"  — x-llm-api-key header, then Authorization Bearer token; falls back to IP
//   - "global"   — constant; all callers share one bucket
//   - "" / "ip"  — X-Real-IP (trusted proxy only), then RemoteAddr
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
	// Trust X-Real-IP only when the direct peer is a trusted proxy.
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" && isTrustedProxyPeer(r.RemoteAddr) {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isTrustedProxyPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}

	trustedProxyCIDROnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("PROMPTSHIELD_TRUST_PROXY_CIDRS"))
		if raw == "" {
			return
		}
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			_, cidr, parseErr := net.ParseCIDR(entry)
			if parseErr != nil {
				continue
			}
			trustedProxyCIDRs = append(trustedProxyCIDRs, cidr)
		}
	})

	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
