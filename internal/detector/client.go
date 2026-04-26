package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	zlog "github.com/rs/zerolog/log"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

// requestIDKeyType is private to avoid context key collisions.
type requestIDKeyType struct{}

var requestIDKey = requestIDKeyType{}

// WithRequestID stores a request ID for detector request forwarding.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// requestIDFromContext returns the request ID, or "" if missing.
func requestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

type Entity struct {
	Type  string  `json:"type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

type DetectRequest struct {
	Text     string `json:"text"`
	Language string `json:"language,omitempty"` // BCP-47 hint; empty = auto-detect
}

type DetectResponse struct {
	PIIDetected       bool     `json:"pii_detected"`
	InjectionDetected bool     `json:"injection_detected"`
	InjectionReason   string   `json:"injection_reason,omitempty"`
	Entities          []Entity `json:"entities"`
	Language          string   `json:"language,omitempty"` // detected/used language
}

type Analyzer interface {
	Detect(ctx context.Context, text string) (*DetectResponse, error)
}

type HTTPAnalyzer struct {
	baseURL    string
	apiKey     string // optional; sent as Authorization Bearer
	httpClient *http.Client
}

func NewHTTPAnalyzer(baseURL, apiKey string) *HTTPAnalyzer {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(baseURL)), "https://") {
		zlog.Warn().Str("url", baseURL).Msg("detector URL does not use HTTPS; raw user prompts are sent over plaintext")
	}
	return &HTTPAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			// Never follow redirects: the request body is the raw user prompt.
			// A redirect would re-send it to an unvalidated endpoint.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:         config.NewBlockingDialer(), // SSRF/DNS-rebinding prevention
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// Detect sends text to the detector and returns PII/injection signals.
// The raw prompt is sent before masking, so use a trusted HTTPS endpoint.
func (a *HTTPAnalyzer) Detect(ctx context.Context, text string) (*DetectResponse, error) {
	body, err := json.Marshal(DetectRequest{Text: text})
	if err != nil {
		return nil, fmt.Errorf("marshal detect request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 && ctx.Err() != nil {
			break
		}
		out, retryable, err := a.detectAttempt(ctx, body)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

func (a *HTTPAnalyzer) detectAttempt(ctx context.Context, body []byte) (*DetectResponse, bool, error) {
	req, err := a.newDetectRequest(ctx, body)
	if err != nil {
		return nil, false, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("call detector: %w", err)
	}

	respBody, err := readResponseBody(resp)
	if err != nil {
		return nil, true, err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("detector returned status %d", resp.StatusCode)
		return nil, resp.StatusCode >= 500, err
	}

	out, err := decodeDetectResponse(respBody)
	if err != nil {
		return nil, false, err
	}
	return out, false, nil
}

func (a *HTTPAnalyzer) newDetectRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/detect", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create detect request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}
	if id := requestIDFromContext(ctx); id != "" {
		req.Header.Set("X-Request-ID", id)
	}

	return req, nil
}

func readResponseBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read detector response: %w", err)
	}
	return respBody, nil
}

func decodeDetectResponse(respBody []byte) (*DetectResponse, error) {
	var out DetectResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode detector response: %w", err)
	}

	if out.Entities == nil {
		out.Entities = []Entity{}
	}
	// Drop raw entity text so secret content is not retained in memory.
	for i := range out.Entities {
		out.Entities[i].Text = ""
	}

	return &out, nil
}
