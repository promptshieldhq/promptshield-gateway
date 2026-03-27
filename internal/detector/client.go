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
)

type Entity struct {
	Type  string  `json:"type"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Text  string  `json:"text"`
	Score float64 `json:"score"`
}

type DetectRequest struct {
	Text     string `json:"text"`
	Language string `json:"language,omitempty"` // BCP-47 hint; omitted = engine auto-detects
}

type DetectResponse struct {
	PIIDetected       bool     `json:"pii_detected"`
	InjectionDetected bool     `json:"injection_detected"`
	InjectionReason   string   `json:"injection_reason,omitempty"`
	Entities          []Entity `json:"entities"`
	Language          string   `json:"language,omitempty"` // language detected/used by engine
}

type Analyzer interface {
	Detect(ctx context.Context, text string) (*DetectResponse, error)
}

type HTTPAnalyzer struct {
	baseURL    string
	apiKey     string // optional; sent as "Authorization: Bearer <key>" when non-empty
	httpClient *http.Client
}

func NewHTTPAnalyzer(baseURL, apiKey string) *HTTPAnalyzer {
	return &HTTPAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// Detect sends the prompt to the detection engine and returns PII entities and injection signals.
// Warning: the full prompt transits to the engine before any masking is applied. Use a trusted,
// encrypted endpoint (https).
func (a *HTTPAnalyzer) Detect(ctx context.Context, text string) (*DetectResponse, error) {
	body, err := json.Marshal(DetectRequest{Text: text})
	if err != nil {
		return nil, fmt.Errorf("marshal detect request: %w", err)
	}

	var (
		lastErr error
		out     DetectResponse
	)
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 && ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/detect", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create detect request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if a.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+a.apiKey)
		}

		resp, err := a.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("call detector: %w", err)
			continue
		}

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read detector response: %w", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("detector returned status %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return nil, lastErr // 4xx won't recover on retry
			}
			continue
		}

		if err := json.Unmarshal(respBody, &out); err != nil {
			return nil, fmt.Errorf("decode detector response: %w", err)
		}

		if out.Entities == nil {
			out.Entities = []Entity{}
		}
		// Zero entity text to avoid keeping PII content in heap memory longer than needed.
		for i := range out.Entities {
			out.Entities[i].Text = ""
		}
		return &out, nil
	}
	return nil, lastErr
}
