package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	mu  sync.Mutex
	enc *json.Encoder
}

func NewLogger() *Logger {
	return &Logger{enc: json.NewEncoder(os.Stdout)}
}

func (l *Logger) Emit(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(e); err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to encode event %s: %v\n", e.RequestID, err)
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
