package budget

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
)

var budgetRedisErrors = promauto.NewCounter(prometheus.CounterOpts{
	Name: "promptshield_budget_redis_errors_total",
	Help: "Number of Redis errors in budget tracker; falls back to in-memory.",
})

// budgetCheckIncrScript atomically increments a budget counter, sets TTL on first write,
// and enforces the limit. Returns the new total, or -1 if the limit is exceeded.
// Uses TTL() instead of EXPIRE NX so it is compatible with Redis 6.x and 7.x.
//
// KEYS[1] = budget key
// ARGV[1] = delta (tokens to add)
// ARGV[2] = TTL in seconds
// ARGV[3] = budget limit
var budgetCheckIncrScript = redis.NewScript(`
local new_val = redis.call('INCRBY', KEYS[1], tonumber(ARGV[1]))
if redis.call('TTL', KEYS[1]) == -1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
if new_val > tonumber(ARGV[3]) then return -1 end
return new_val
`)

// RedisTracker is a distributed token budget tracker; falls back to in-memory on Redis error.
type RedisTracker struct {
	client   *redis.Client
	policy   *policy.TokenBudgetPolicy
	fallback *InMemoryTracker
}

// budgetWindow holds per-window metadata used in Check and Record.
type budgetWindow struct {
	key    string
	limit  int64
	ttl    time.Duration
	reason string
}

func NewRedisTracker(p *policy.TokenBudgetPolicy, redisURL string) (*RedisTracker, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("budget: invalid REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("budget: cannot reach Redis: %w", err)
	}

	return &RedisTracker{
		client:   client,
		policy:   p,
		fallback: New(p),
	}, nil
}

// Check reads all active budget windows in one MGET round-trip.
// Falls back to in-memory on Redis error.
func (t *RedisTracker) Check(r *http.Request) (bool, string) {
	now := time.Now().UTC()
	windows := t.activeWindows(r, now)
	if len(windows) == 0 {
		return true, ""
	}

	keys := make([]string, len(windows))
	for i, w := range windows {
		keys[i] = w.key
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	vals, err := t.client.MGet(ctx, keys...).Result()
	if err != nil {
		budgetRedisErrors.Inc()
		return t.fallback.Check(r)
	}

	for i, w := range windows {
		if vals[i] == nil {
			continue
		}

		n, parseErr := parseRedisCounter(vals[i])
		if parseErr != nil {
			budgetRedisErrors.Inc()
			return t.fallback.Check(r)
		}
		if n >= w.limit {
			return false, w.reason
		}
	}
	return true, ""
}

func parseRedisCounter(v any) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	case []byte:
		return strconv.ParseInt(string(x), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected Redis counter type %T", v)
	}
}

// Record atomically increments each budget window; each window gets its own timeout.
// Window-boundary TOCTOU (Check near midnight, Record after) is accepted and bounded to one request.
func (t *RedisTracker) Record(r *http.Request, tokens int) {
	if tokens <= 0 {
		return
	}
	now := time.Now().UTC()
	windows := t.activeWindows(r, now)
	redisOK := true

	for _, w := range windows {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := budgetCheckIncrScript.Run(ctx, t.client, []string{w.key},
			int64(tokens), int64(w.ttl.Seconds()), w.limit,
		).Int64()
		cancel()
		if err != nil {
			budgetRedisErrors.Inc()
			redisOK = false
		}
		// result == -1 means this increment pushed the counter over the limit.
		// The current request is already committed; future Check() calls will
		// see the over-limit counter and block subsequent requests.
	}

	if !redisOK {
		t.fallback.Record(r, tokens)
	}
}

func (t *RedisTracker) Stop() {
	t.fallback.Stop()
	t.client.Close()
}

// Snapshot and MigrateFrom are no-ops: state lives in Redis.
func (t *RedisTracker) Snapshot() TrackerSnapshot     { return TrackerSnapshot{} }
func (t *RedisTracker) MigrateFrom(_ TrackerSnapshot) {}

// activeWindows returns the configured budget windows for this request at time now.
func (t *RedisTracker) activeWindows(r *http.Request, now time.Time) []budgetWindow {
	p := t.policy
	var windows []budgetWindow
	if p.Daily != nil && p.Daily.Tokens > 0 {
		windows = append(windows, budgetWindow{
			key:    t.dailyKey(r, now, p.Daily.KeyBy),
			limit:  int64(p.Daily.Tokens),
			ttl:    48 * time.Hour,
			reason: fmt.Sprintf("daily token budget of %d exceeded", p.Daily.Tokens),
		})
	}
	if p.Weekly != nil && p.Weekly.Tokens > 0 {
		windows = append(windows, budgetWindow{
			key:    t.weeklyKey(r, now, p.Weekly.KeyBy),
			limit:  int64(p.Weekly.Tokens),
			ttl:    14 * 24 * time.Hour,
			reason: fmt.Sprintf("weekly token budget of %d exceeded", p.Weekly.Tokens),
		})
	}
	if p.Monthly != nil && p.Monthly.Tokens > 0 {
		windows = append(windows, budgetWindow{
			key:    t.monthlyKey(r, now, p.Monthly.KeyBy),
			limit:  int64(p.Monthly.Tokens),
			ttl:    62 * 24 * time.Hour,
			reason: fmt.Sprintf("monthly token budget of %d exceeded", p.Monthly.Tokens),
		})
	}
	return windows
}

func (t *RedisTracker) dailyKey(r *http.Request, now time.Time, keyBy string) string {
	return fmt.Sprintf("ps:budget:d:%s:%s", now.Format("2006-01-02"), t.resolveKey(r, keyBy))
}

func (t *RedisTracker) weeklyKey(r *http.Request, now time.Time, keyBy string) string {
	year, week := now.ISOWeek()
	return fmt.Sprintf("ps:budget:w:%d-%02d:%s", year, week, t.resolveKey(r, keyBy))
}

func (t *RedisTracker) monthlyKey(r *http.Request, now time.Time, keyBy string) string {
	return fmt.Sprintf("ps:budget:m:%s:%s", now.Format("2006-01"), t.resolveKey(r, keyBy))
}

func (t *RedisTracker) resolveKey(r *http.Request, keyBy string) string {
	return config.ResolveRequestKey(r, keyBy)
}
