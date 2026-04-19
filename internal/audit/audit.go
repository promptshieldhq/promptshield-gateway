package audit

import (
	"bytes"
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
	mu         sync.Mutex
	ingestURL  string
	ingestKey  string
	httpClient *http.Client
	pushSem    chan struct{} // nil when HTTP push is off
}

// NewLogger optionally enables direct HTTP push when PROMPTSHIELD_AUDIT_URL is set.
func NewLogger() *Logger {
	l := &Logger{}
	if raw := strings.TrimSpace(os.Getenv("PROMPTSHIELD_AUDIT_URL")); raw != "" {
		if err := config.ValidateURL(raw); err != nil {
			fmt.Fprintf(os.Stderr, "audit: PROMPTSHIELD_AUDIT_URL invalid (%v) — HTTP push disabled\n", err)
		} else if err := config.ValidateNotLinkLocalURL(raw); err != nil {
			fmt.Fprintf(os.Stderr, "audit: PROMPTSHIELD_AUDIT_URL invalid (%v) — HTTP push disabled\n", err)
		} else {
			l.ingestURL = strings.TrimRight(raw, "/") + "/internal/audit/ingest"
			l.ingestKey = os.Getenv("AUDIT_INGEST_SECRET")
			l.httpClient = &http.Client{Timeout: 5 * time.Second}
			l.pushSem = make(chan struct{}, maxConcurrentPushes)
			fmt.Fprintf(os.Stderr, "audit: HTTP push enabled → %s\n", l.ingestURL)
		}
	}
	return l
}

func (l *Logger) Emit(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to encode event %s: %v\n", e.RequestID, err)
		return
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to write event %s: %v\n", e.RequestID, err)
		return
	}
	if _, err := os.Stdout.WriteString("\n"); err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to write newline after event %s: %v\n", e.RequestID, err)
	}

	// Optionally push to dashboard with bounded concurrency.
	if l.httpClient != nil {
		select {
		case l.pushSem <- struct{}{}:
			go func() {
				defer func() { <-l.pushSem }()
				l.push(e.RequestID, data)
			}()
		default:
			fmt.Fprintf(os.Stderr, "audit: push semaphore full (%d slots), dropping event %s\n", maxConcurrentPushes, e.RequestID)
		}
	}
}

func (l *Logger) push(requestID string, body []byte) {
	req, err := http.NewRequest(http.MethodPost, l.ingestURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: push build request error %s: %v\n", requestID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if l.ingestKey != "" {
		req.Header.Set("x-ingest-secret", l.ingestKey)
	}
	resp, err := l.httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: push failed %s: %v\n", requestID, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "audit: push non-2xx %s: %d\n", requestID, resp.StatusCode)
	}
}

func NewRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		counter := atomic.AddUint64(&fallbackRequestIDCounter, 1)
		ts := time.Now().UTC().UnixNano()
		fmt.Fprintf(os.Stderr, "audit: crypto/rand unavailable, using fallback request id: %v\n", err)
		return fmt.Sprintf("%x%x", ts, counter)
	}
	return hex.EncodeToString(b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
