package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	zlog "github.com/rs/zerolog/log"
)

const (
	envHMACSecret      = "PROMPTSHIELD_KEY_HMAC_SECRET"
	envTrustProxyCIDRs = "PROMPTSHIELD_TRUST_PROXY_CIDRS"
	requestKeyPrefix   = "k:"

	keyByAPIKey = "api_key"
	keyByGlobal = "global"
)

type trustedCIDRCache struct {
	raw   string
	cidrs []*net.IPNet
}

var (
	hmacKeyOnce sync.Once
	hmacKey     []byte

	trustedCIDRCacheValue atomic.Value // trustedCIDRCache
)

func getHMACKey() []byte {
	hmacKeyOnce.Do(func() {
		if k := strings.TrimSpace(os.Getenv(envHMACSecret)); k != "" {
			hmacKey = []byte(k)
			return
		}
		zlog.Warn().Msg("PROMPTSHIELD_KEY_HMAC_SECRET not set — using ephemeral key; set it for stable Redis keys across restarts")
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic("promptshield: crypto/rand unavailable — cannot generate HMAC key: " + err.Error())
		}
		hmacKey = b
	})
	return hmacKey
}

// ResolveRequestKey returns a per-client key for rate limiting and budgets.
func ResolveRequestKey(r *http.Request, keyBy string) string {
	switch keyBy {
	case keyByAPIKey:
		if key := requestAPIKey(r); key != "" {
			return requestKeyPrefix + hashKey(key)
		}
		// No key found; fall back to IP.
	case keyByGlobal:
		return keyByGlobal
	}

	// Only trust X-Real-IP from a trusted forwarding peer.
	if isTrustedForwardPeer(r.RemoteAddr) {
		if realIP := parseSingleIP(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
	}
	if host := normalizedRemoteIP(r.RemoteAddr); host != "" {
		return host
	}

	return "unknown"
}

func requestAPIKey(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("x-llm-api-key")); k != "" {
		return k
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
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
func ClientIPFromRequest(r *http.Request) string {
	if isTrustedForwardPeer(r.RemoteAddr) {
		if xffIP := parseSingleIP(r.Header.Get("X-Forwarded-For")); xffIP != "" {
			return xffIP
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

	raw := strings.TrimSpace(os.Getenv(envTrustProxyCIDRs))
	cidrs := trustedForwardCIDRs(raw)

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// trustedForwardCIDRs returns parsed CIDRs, re-parsing only when the env value changes.
func trustedForwardCIDRs(raw string) []*net.IPNet {
	if cachedAny := trustedCIDRCacheValue.Load(); cachedAny != nil {
		if cached, ok := cachedAny.(trustedCIDRCache); ok && cached.raw == raw {
			return cached.cidrs
		}
	}

	cidrs := parseTrustedForwardCIDRs(raw)
	trustedCIDRCacheValue.Store(trustedCIDRCache{raw: raw, cidrs: cidrs})
	return cidrs
}

func parseTrustedForwardCIDRs(raw string) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, cidr, parseErr := net.ParseCIDR(entry)
		if parseErr != nil {
			zlog.Warn().Str("env", envTrustProxyCIDRs).Str("cidr", entry).Err(parseErr).Msg("skipping invalid CIDR in trusted proxy list")
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

// hashKey returns a 32-char hex HMAC-SHA256 prefix to avoid logging raw API keys.
func hashKey(key string) string {
	mac := hmac.New(sha256.New, getHMACKey())
	if _, err := mac.Write([]byte(key)); err != nil {
		panic("promptshield: hmac write failed: " + err.Error())
	}
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
