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
	"time"
)

// Event is written as NDJSON to stdout for every request.
// Application logs (zerolog) go to stderr so the two streams can be separated.
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

type Logger struct {
	mu         sync.Mutex
	enc        *json.Encoder
	ingestURL  string
	ingestKey  string
	httpClient *http.Client
}

// NewLogger creates a Logger. If PROMPTSHIELD_AUDIT_URL is set, audit events
// are also pushed directly to the dashboard ingest endpoint — no log-fwd
// process required when running outside docker-compose.
func NewLogger() *Logger {
	l := &Logger{
		enc: json.NewEncoder(os.Stdout),
	}
	if raw := strings.TrimSpace(os.Getenv("PROMPTSHIELD_AUDIT_URL")); raw != "" {
		l.ingestURL = strings.TrimRight(raw, "/") + "/internal/audit/ingest"
		l.ingestKey = os.Getenv("AUDIT_INGEST_SECRET")
		l.httpClient = &http.Client{Timeout: 5 * time.Second}
		fmt.Fprintf(os.Stderr, "audit: HTTP push enabled → %s\n", l.ingestURL)
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
	// Always write to stdout (docker-compose log-fwd picks this up).
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")

	// Also push directly to the dashboard when PROMPTSHIELD_AUDIT_URL is set.
	if l.httpClient != nil {
		go l.push(e.RequestID, data)
	}
}

func (l *Logger) push(requestID string, body []byte) {
	req, err := http.NewRequest(http.MethodPost, l.ingestURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: push build request error %s: %v\n", requestID, err)
		return
	}
	req.Header.Set("Content-Type", "text/plain")
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
		panic(fmt.Sprintf("crypto/rand.Read: %v", err))
	}
	return hex.EncodeToString(b)
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
