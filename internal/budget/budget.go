// Package budget tracks per-client token usage in daily/weekly/monthly windows.
package budget

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
)

// State is in memory and resets on restart.

// Max number of tracked client entries.
const maxEntries = 100_000

type entry struct {
	total       int64
	windowStart time.Time
}

// Tracker enforces token budgets per client.
// Safe for concurrent use.
type Tracker struct {
	mu       sync.Mutex
	entries  map[string]*entry
	policy   *policy.TokenBudgetPolicy
	done     chan struct{}
	stopOnce sync.Once
}

// New creates a tracker and starts background eviction.
func New(p *policy.TokenBudgetPolicy) *Tracker {
	t := &Tracker{
		entries: make(map[string]*entry),
		policy:  p,
		done:    make(chan struct{}),
	}
	go t.evictLoop()
	return t
}

// Stop ends background eviction. Safe to call multiple times.
func (t *Tracker) Stop() {
	t.stopOnce.Do(func() { close(t.done) })
}

// Check reports whether the request is still within budget.
func (t *Tracker) Check(r *http.Request) (bool, string) {
	now := time.Now().UTC()
	p := t.policy

	t.mu.Lock()
	defer t.mu.Unlock()

	if p.Daily != nil && p.Daily.Tokens > 0 {
		key := "d:" + resolveKey(r, p.Daily.KeyBy)
		e := t.getOrReset(key, dailyWindowStart(now))
		if e.total >= int64(p.Daily.Tokens) {
			return false, fmt.Sprintf("daily token budget of %d exceeded", p.Daily.Tokens)
		}
	}
	if p.Weekly != nil && p.Weekly.Tokens > 0 {
		key := "w:" + resolveKey(r, p.Weekly.KeyBy)
		e := t.getOrReset(key, weeklyWindowStart(now))
		if e.total >= int64(p.Weekly.Tokens) {
			return false, fmt.Sprintf("weekly token budget of %d exceeded", p.Weekly.Tokens)
		}
	}
	if p.Monthly != nil && p.Monthly.Tokens > 0 {
		key := "m:" + resolveKey(r, p.Monthly.KeyBy)
		e := t.getOrReset(key, monthlyWindowStart(now))
		if e.total >= int64(p.Monthly.Tokens) {
			return false, fmt.Sprintf("monthly token budget of %d exceeded", p.Monthly.Tokens)
		}
	}

	return true, ""
}

// Record adds tokens to all active budget windows.
func (t *Tracker) Record(r *http.Request, tokens int) {
	if tokens <= 0 {
		return
	}
	now := time.Now().UTC()
	p := t.policy

	t.mu.Lock()
	defer t.mu.Unlock()

	if p.Daily != nil && p.Daily.Tokens > 0 {
		key := "d:" + resolveKey(r, p.Daily.KeyBy)
		t.getOrReset(key, dailyWindowStart(now)).total += int64(tokens)
	}
	if p.Weekly != nil && p.Weekly.Tokens > 0 {
		key := "w:" + resolveKey(r, p.Weekly.KeyBy)
		t.getOrReset(key, weeklyWindowStart(now)).total += int64(tokens)
	}
	if p.Monthly != nil && p.Monthly.Tokens > 0 {
		key := "m:" + resolveKey(r, p.Monthly.KeyBy)
		t.getOrReset(key, monthlyWindowStart(now)).total += int64(tokens)
	}
}

// getOrReset returns the entry for key and resets it when the window changes.
// Caller must hold t.mu.
func (t *Tracker) getOrReset(key string, windowStart time.Time) *entry {
	e, ok := t.entries[key]
	if !ok || e.windowStart.Before(windowStart) {
		if !ok && len(t.entries) >= maxEntries {
			t.evictOldest()
		}
		e = &entry{windowStart: windowStart}
		t.entries[key] = e
	}
	return e
}

// evictOldest removes the oldest window entry.
// Caller must hold t.mu.
func (t *Tracker) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, e := range t.entries {
		if first || e.windowStart.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.windowStart
			first = false
		}
	}
	if oldestKey != "" {
		delete(t.entries, oldestKey)
	}
}

func resolveKey(r *http.Request, keyBy string) string {
	return config.ResolveRequestKey(r, keyBy)
}

// TrackerSnapshot is a copy of tracker state for reload migration.
type TrackerSnapshot struct {
	Entries map[string]entry
}

// Snapshot copies current budget entries.
func (t *Tracker) Snapshot() TrackerSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	snap := TrackerSnapshot{Entries: make(map[string]entry, len(t.entries))}
	for k, e := range t.entries {
		snap.Entries[k] = *e
	}
	return snap
}

// MigrateFrom loads prior state so budgets survive policy reload.
// Call before serving requests.
func (t *Tracker) MigrateFrom(snap TrackerSnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range snap.Entries {
		t.entries[k] = &e
	}
}

func (t *Tracker) evictLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.evict()
		case <-t.done:
			return
		}
	}
}

// evict removes entries older than 32 days.
func (t *Tracker) evict() {
	cutoff := time.Now().UTC().AddDate(0, 0, -32)
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, e := range t.entries {
		if e.windowStart.Before(cutoff) {
			delete(t.entries, key)
		}
	}
}

func dailyWindowStart(now time.Time) time.Time {
	y, m, d := now.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func weeklyWindowStart(now time.Time) time.Time {
	wd := int(now.Weekday())
	daysToMonday := (wd - int(time.Monday) + 7) % 7
	y, m, d := now.AddDate(0, 0, -daysToMonday).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func monthlyWindowStart(now time.Time) time.Time {
	y, m, _ := now.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
}
