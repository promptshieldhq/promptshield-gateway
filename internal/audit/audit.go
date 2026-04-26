package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

// Event is emitted as NDJSON on stdout; app logs stay on stderr.
type Event struct {
	RequestID         string   `json:"request_id"`
	Timestamp         string   `json:"timestamp"`
	Action            string   `json:"action"`
	Provider          string   `json:"provider"`
	Model             string   `json:"model,omitempty"`
	ClientIP          string   `json:"client_ip,omitempty"`
	InjectionDetected bool     `json:"injection_detected"`
	InjectionReason   string   `json:"injection_reason,omitempty"`
	DetectedLanguage  string   `json:"detected_language,omitempty"`
	EntitiesDetected  []string `json:"entities_detected"`
	Reasons           []string `json:"reasons,omitempty"`
	ResponseScanned   bool     `json:"response_scanned"`
	PromptTokens      int      `json:"prompt_tokens"`
	CompletionTokens  int      `json:"completion_tokens"`
	TotalTokens       int      `json:"total_tokens"`
	LatencyMS         int64    `json:"latency_ms"`
	PolicyHash        string   `json:"policy_hash"`
}

// Max in-flight audit pushes; extra events are dropped with a warning.
const maxConcurrentPushes = 32

var fallbackRequestIDCounter uint64

type Logger struct {
	log        zerolog.Logger
	mu         sync.Mutex
	ingestURL  string
	ingestKey  string
	httpClient *http.Client
	pushSem    chan struct{} // nil when HTTP push is off
}

// NewLogger optionally enables direct HTTP push when PROMPTSHIELD_AUDIT_URL is set.
func NewLogger(log zerolog.Logger) *Logger {
	l := &Logger{log: log.With().Str("component", "audit").Logger()}
	if raw := strings.TrimSpace(os.Getenv("PROMPTSHIELD_AUDIT_URL")); raw != "" {
		if !strings.HasPrefix(strings.ToLower(raw), "https://") {
			l.log.Warn().Msg("PROMPTSHIELD_AUDIT_URL must use HTTPS — HTTP push disabled")
		} else if err := config.ValidateURL(raw); err != nil {
			l.log.Warn().Err(err).Msg("PROMPTSHIELD_AUDIT_URL invalid — HTTP push disabled")
		} else if err := config.ValidateNotLinkLocalURL(raw); err != nil {
			l.log.Warn().Err(err).Msg("PROMPTSHIELD_AUDIT_URL invalid — HTTP push disabled")
		} else {
			l.ingestURL = strings.TrimRight(raw, "/") + "/internal/audit/ingest"
			l.ingestKey = os.Getenv("AUDIT_INGEST_SECRET")
			// Never follow redirects: events must only reach the configured ingest endpoint.
			l.httpClient = &http.Client{
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					DialContext: config.NewBlockingDialer(),
				},
			}
			l.pushSem = make(chan struct{}, maxConcurrentPushes)
			l.log.Info().Str("url", l.ingestURL).Msg("audit HTTP push enabled")
		}
	}
	return l
}

func (l *Logger) Emit(ctx context.Context, e Event) {
	data, err := json.Marshal(e)
	if err != nil {
		l.log.Error().Str("request_id", e.RequestID).Err(err).Msg("failed to encode audit event")
		return
	}

	// mu serializes NDJSON lines; held only for the write syscalls, not for marshal/dispatch.
	l.mu.Lock()
	_, writeErr := os.Stdout.Write(data)
	if writeErr == nil {
		_, writeErr = os.Stdout.WriteString("\n")
	}
	l.mu.Unlock()

	if writeErr != nil {
		l.log.Error().Str("request_id", e.RequestID).Err(writeErr).Msg("failed to write audit event")
		return
	}

	// Optionally push to dashboard with bounded concurrency.
	if l.httpClient != nil {
		select {
		case l.pushSem <- struct{}{}:
			pushCtx := detachedContext(ctx)
			go func(ctx context.Context) {
				defer func() { <-l.pushSem }()
				l.push(ctx, e.RequestID, data)
			}(pushCtx)
		default:
			l.log.Warn().
				Str("request_id", e.RequestID).
				Int("max_slots", maxConcurrentPushes).
				Msg("audit push semaphore full — dropping event")
		}
	}
}

func detachedContext(parent context.Context) context.Context {
	if parent == nil {
		return context.Background()
	}
	return context.WithoutCancel(parent)
}

func (l *Logger) push(parent context.Context, requestID string, body []byte) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.ingestURL, bytes.NewReader(body))
	if err != nil {
		l.log.Error().Str("request_id", requestID).Err(err).Msg("audit push: failed to build request")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if l.ingestKey != "" {
		req.Header.Set("x-ingest-secret", l.ingestKey)
	}
	resp, err := l.httpClient.Do(req)
	if err != nil {
		l.log.Warn().Str("request_id", requestID).Err(err).Msg("audit push failed")
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		l.log.Warn().Str("request_id", requestID).Int("status", resp.StatusCode).Msg("audit push non-2xx response")
	}
}

func NewRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		counter := atomic.AddUint64(&fallbackRequestIDCounter, 1)
		ts := time.Now().UTC().UnixNano()
		zlog.Warn().Err(err).Msg("crypto/rand unavailable — using fallback request ID")
		return fmt.Sprintf("%x%x", ts, counter)
	}
	return hex.EncodeToString(b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
