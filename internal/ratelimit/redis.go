package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

// slidingWindowScript: weighted two-window sliding limiter. Returns 1=allow, 0=deny.
// KEYS[1]=curr window, KEYS[2]=prev window; ARGV[1]=limit, ARGV[2]=window_sec, ARGV[3]=now_ms.
var slidingWindowScript = redis.NewScript(`
local curr_key  = KEYS[1]
local prev_key  = KEYS[2]
local limit     = tonumber(ARGV[1])
local window    = tonumber(ARGV[2])
local now_ms    = tonumber(ARGV[3])

local curr = tonumber(redis.call('GET', curr_key) or 0)
local prev = tonumber(redis.call('GET', prev_key) or 0)

local elapsed_fraction = (now_ms % (window * 1000)) / (window * 1000)
local weighted = math.floor(prev * (1 - elapsed_fraction) + curr)

if weighted >= limit then
  return 0
end

local new_val = redis.call('INCR', curr_key)
if new_val == 1 then
  redis.call('EXPIRE', curr_key, window * 2)
end
return 1
`)

var redisErrors = promauto.NewCounter(prometheus.CounterOpts{
	Name: "promptshield_ratelimit_redis_errors_total",
	Help: "Number of Redis errors in rate limiter; falls back to allow.",
})

// RedisLimiter is a distributed sliding-window rate limiter; fails open on Redis error.
type RedisLimiter struct {
	client   *redis.Client
	rpm      int
	burst    int
	keyBy    string
	fallback *Limiter // in-memory fallback when Redis is unavailable
}

func NewRedisLimiter(rpm, burst int, keyBy, redisURL string) (*RedisLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: invalid REDIS_URL: %w", err)
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("ratelimit: cannot reach Redis: %w", err)
	}

	return &RedisLimiter{
		client:   client,
		rpm:      rpm,
		burst:    burst,
		keyBy:    keyBy,
		fallback: New(rpm, 1, keyBy), // burst=1: limits sudden burst when falling back from Redis

	}, nil
}

func (l *RedisLimiter) Allow(r *http.Request) bool {
	key := config.ResolveRequestKey(r, l.keyBy)
	now := time.Now()
	windowSec := 60 // 1-minute fixed window, weighted across two

	nowMS := now.UnixMilli()
	windowStart := now.Unix() / int64(windowSec) * int64(windowSec)
	prevWindowStart := windowStart - int64(windowSec)

	currKey := fmt.Sprintf("ps:rl:%s:%d", key, windowStart)
	prevKey := fmt.Sprintf("ps:rl:%s:%d", key, prevWindowStart)

	// Use Background so a client disconnect cannot force fail-open via context cancellation.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := slidingWindowScript.Run(ctx, l.client,
		[]string{currKey, prevKey},
		l.rpm, windowSec, nowMS,
	).Int()
	if err != nil {
		redisErrors.Inc()
		// Fail open: use local in-memory bucket as fallback.
		return l.fallback.Allow(r)
	}
	return result == 1
}

func (l *RedisLimiter) Stop() {
	l.fallback.Stop()
	l.client.Close()
}

func (l *RedisLimiter) KeyBy() string { return l.keyBy }

// Snapshot and MigrateFrom are no-ops: state lives in Redis across reloads.
func (l *RedisLimiter) Snapshot() LimiterSnapshot {
	return LimiterSnapshot{KeyBy: l.keyBy}
}

func (l *RedisLimiter) MigrateFrom(_ LimiterSnapshot) {}
