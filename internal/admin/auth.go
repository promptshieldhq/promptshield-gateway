package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// maxAdminAuthBuckets caps in-memory entries to prevent memory exhaustion.
const maxAdminAuthBuckets = 10_000

func (l *adminAuthLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(now)

	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		if len(l.buckets) >= maxAdminAuthBuckets {
			l.evictOldestLocked()
		}
		l.buckets[key] = adminAuthWindow{count: 0, reset: now.Add(adminAuthFailureWindow)}
		return true
	}

	return b.count < adminAuthFailureLimit
}

func (l *adminAuthLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(now)

	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		if len(l.buckets) >= maxAdminAuthBuckets {
			l.evictOldestLocked()
		}
		l.buckets[key] = adminAuthWindow{count: 1, reset: now.Add(adminAuthFailureWindow)}
		return
	}

	b.count++
	l.buckets[key] = b
}

func (l *adminAuthLimiter) reset(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.buckets, key)
	l.cleanupLocked(now)
}

func (l *adminAuthLimiter) cleanupLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.After(b.reset) {
			delete(l.buckets, k)
		}
	}
}

// evictOldestLocked removes the entry expiring soonest. Caller must hold l.mu.
func (l *adminAuthLimiter) evictOldestLocked() {
	var oldest string
	var oldestReset time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.reset.Before(oldestReset) {
			oldest = k
			oldestReset = b.reset
			first = false
		}
	}
	if oldest != "" {
		delete(l.buckets, oldest)
	}
}

func (a *API) requireAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	// IP check first to prevent timing-based token enumeration.
	if !a.isAllowedAdminSource(r) {
		writeError(w, http.StatusForbidden, "admin API is restricted to private/internal networks")
		return false
	}

	clientKey := adminAuthClientKey(r)
	now := time.Now()
	if !a.authLimiter.allow(clientKey, now) {
		writeError(w, http.StatusTooManyRequests, "too many authentication attempts")
		return false
	}

	if a.adminToken == "" {
		writeError(w, http.StatusServiceUnavailable, "admin token is not configured")
		return false
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		a.authLimiter.fail(clientKey, now)
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return false
	}

	token := auth
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[7:])
	}

	// Hash both sides so comparison is constant-time regardless of token length.
	tokenHash := sha256.Sum256([]byte(token))
	adminHash := sha256.Sum256([]byte(a.adminToken))
	if subtle.ConstantTimeCompare(tokenHash[:], adminHash[:]) != 1 {
		a.authLimiter.fail(clientKey, now)
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return false
	}

	a.authLimiter.reset(clientKey, now)

	return true
}

func adminAuthClientKey(r *http.Request) string {
	if ip := remotePeerIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *API) isAllowedAdminSource(r *http.Request) bool {
	ip := remotePeerIP(r.RemoteAddr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	for _, cidr := range a.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func parseAdminAllowedCIDRs(log zerolog.Logger, raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var cidrs []*net.IPNet
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			log.Warn().Str("env", adminAllowedCIDRsEnv).Str("cidr", entry).Err(err).Msg("skipping invalid CIDR in admin allowed list")
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return cidrs
}

func remotePeerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	return net.ParseIP(host)
}
