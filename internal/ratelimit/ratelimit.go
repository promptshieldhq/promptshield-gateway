package ratelimit

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

// maxBuckets caps per-client entries to prevent memory exhaustion when an attacker cycles through many unique api_key tokens.
const maxBuckets = 100_000

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rpm      float64 // requests per minute refill rate
	burst    float64 // max bucket size
	keyBy    string  // "ip" | "api_key"
	done     chan struct{}
	stopOnce sync.Once
}

// New returns a token bucket limiter. keyBy is "ip" (default) or "api_key".
func New(rpm, burst int, keyBy string) *Limiter {
	if keyBy == "" {
		keyBy = "ip"
	}
	l := &Limiter{
		buckets: make(map[string]*bucket),
		rpm:     float64(rpm),
		burst:   float64(burst),
		keyBy:   keyBy,
		done:    make(chan struct{}),
	}
	go l.evictLoop()
	return l
}

// Stop terminates the background eviction goroutine. Safe to call multiple times.
func (l *Limiter) Stop() {
	l.stopOnce.Do(func() { close(l.done) })
}

func (l *Limiter) Allow(r *http.Request) bool {
	key := l.extractKey(r)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			fmt.Fprintf(os.Stderr, "ratelimit: bucket table full (%d entries) — evicting LRU; possible key-cycling attack\n", maxBuckets)
			l.evictLRU()
		}
		b = &bucket{tokens: l.burst, lastCheck: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * l.rpm / 60.0
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastCheck = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.evict()
		case <-l.done:
			return
		}
	}
}

func (l *Limiter) evict() {
	cutoff := time.Now().Add(-10 * time.Minute)
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if b.lastCheck.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}

// evictLRU removes the least-recently-used bucket. Must be called with l.mu held.
func (l *Limiter) evictLRU() {
	var lruKey string
	var lruTime time.Time
	first := true
	for k, b := range l.buckets {
		if first || b.lastCheck.Before(lruTime) {
			lruKey = k
			lruTime = b.lastCheck
			first = false
		}
	}
	if lruKey != "" {
		delete(l.buckets, lruKey)
	}
}

func (l *Limiter) extractKey(r *http.Request) string {
	return config.ResolveRequestKey(r, l.keyBy)
}

// KeyBy returns the key strategy ("ip" or "api_key") this limiter uses.
func (l *Limiter) KeyBy() string { return l.keyBy }

// LimiterSnapshot is a point-in-time copy of bucket state for migration.
type LimiterSnapshot struct {
	KeyBy   string
	Buckets map[string]bucket
}

// Snapshot returns a copy of current bucket state. Used to migrate counters to a
// new limiter when policy reloads so per-client allowances are not reset.
func (l *Limiter) Snapshot() LimiterSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	snap := LimiterSnapshot{
		KeyBy:   l.keyBy,
		Buckets: make(map[string]bucket, len(l.buckets)),
	}
	for k, b := range l.buckets {
		snap.Buckets[k] = *b
	}
	return snap
}

// MigrateFrom pre-loads bucket state from a previous limiter's snapshot.
// Only migrates when the key strategy is unchanged; clamps tokens to the new burst limit.
// Must be called before the limiter handles any requests.
func (l *Limiter) MigrateFrom(snap LimiterSnapshot) {
	if snap.KeyBy != l.keyBy {
		return // key strategy changed; old keys no longer meaningful
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range snap.Buckets {
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		l.buckets[k] = &bucket{tokens: b.tokens, lastCheck: b.lastCheck}
	}
}
