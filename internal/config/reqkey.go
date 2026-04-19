package config

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

var (
	trustedForwardCIDROnce sync.Once
	trustedForwardCIDRs    []*net.IPNet
)

// ResolveRequestKey returns the per-client tracking key.
// "api_key" uses request keys first, "global" shares one bucket,
// everything else falls back to client IP.
func ResolveRequestKey(r *http.Request, keyBy string) string {
	switch keyBy {
	case "api_key":
		if k := strings.TrimSpace(r.Header.Get("x-llm-api-key")); k != "" {
			return "k:" + k
		}
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return "k:" + strings.TrimSpace(auth[7:])
		}
		// No key found; fall back to IP.
	case "global":
		return "global"
	}
	// Only trust X-Real-IP from a trusted forwarding peer.
	if realIP := parseSingleIP(r.Header.Get("X-Real-IP")); realIP != "" && isTrustedForwardPeer(r.RemoteAddr) {
		return realIP
	}
	if host := normalizedRemoteIP(r.RemoteAddr); host != "" {
		return host
	}

	return "unknown"
}

func parseSingleIP(raw string) string {
	candidate := strings.TrimSpace(strings.Split(raw, ",")[0])
	if ip := net.ParseIP(candidate); ip != nil {
		return ip.String()
	}
	return ""
}

func normalizedRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}

// ClientIPFromRequest returns the best-effort client IP for audit logging.
// Forwarded headers (X-Forwarded-For, X-Real-IP) are only trusted when the
// direct peer is a configured trusted forwarding peer or loopback address.
func ClientIPFromRequest(r *http.Request) string {
	if isTrustedForwardPeer(r.RemoteAddr) {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			first := xff
			if idx := strings.IndexByte(xff, ','); idx != -1 {
				first = strings.TrimSpace(xff[:idx])
			}
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
		if realIP := parseSingleIP(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	if host := normalizedRemoteIP(r.RemoteAddr); host != "" {
		return host
	}
	return r.RemoteAddr
}

func isTrustedForwardPeer(remoteAddr string) bool {
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

	trustedForwardCIDROnce.Do(func() {
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
				fmt.Fprintf(os.Stderr, "warning: PROMPTSHIELD_TRUST_PROXY_CIDRS: skipping invalid CIDR %q: %v\n", entry, parseErr)
				continue
			}
			trustedForwardCIDRs = append(trustedForwardCIDRs, cidr)
		}
	})

	for _, cidr := range trustedForwardCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
