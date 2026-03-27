package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-proxy/internal/audit"
	"github.com/promptshieldhq/promptshield-proxy/internal/budget"
	"github.com/promptshieldhq/promptshield-proxy/internal/detector"
	"github.com/promptshieldhq/promptshield-proxy/internal/masker"
	"github.com/promptshieldhq/promptshield-proxy/internal/metrics"
	"github.com/promptshieldhq/promptshield-proxy/internal/policy"
	"github.com/promptshieldhq/promptshield-proxy/internal/ratelimit"
	"github.com/rs/zerolog"
)

var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"content-length":      {},
	"set-cookie":          {},
	"location":            {},
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model     string        `json:"model"`
	Messages  []ChatMessage `json:"messages"`
	Stream    bool          `json:"stream"`
	MaxTokens *int          `json:"max_tokens,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type blockResponse struct {
	Blocked bool     `json:"blocked"`
	Action  string   `json:"action"`
	Reasons []string `json:"reasons,omitempty"`
}

const (
	maxBodyBytes = 4 << 20 // 4 MiB — incoming request body
	actionError  = "error"
)

type Handler struct {
	adapter     Adapter
	analyzer    detector.Analyzer
	log         zerolog.Logger
	auditLogger *audit.Logger

	// mu guards the fields below; swapped atomically by ReloadPolicy.
	mu           sync.RWMutex
	evaluator    *policy.Evaluator
	failClosed   bool
	rateLimiter  *ratelimit.Limiter // nil = disabled
	tokenBudget  *budget.Tracker    // nil = disabled
	scanResponse bool
	tokenLimits  *policy.TokenLimitsPolicy // nil = disabled
	policyHash   string
}

func NewHandler(
	adapter Adapter,
	analyzer detector.Analyzer,
	evaluator *policy.Evaluator,
	failClosed bool,
	log zerolog.Logger,
	auditLogger *audit.Logger,
	rateLimiter *ratelimit.Limiter,
	tokenBudget *budget.Tracker,
	scanResponse bool,
	tokenLimits *policy.TokenLimitsPolicy,
	p *policy.Policy,
) *Handler {
	return &Handler{
		adapter:      adapter,
		analyzer:     analyzer,
		evaluator:    evaluator,
		failClosed:   failClosed,
		log:          log,
		auditLogger:  auditLogger,
		rateLimiter:  rateLimiter,
		tokenBudget:  tokenBudget,
		scanResponse: scanResponse,
		tokenLimits:  tokenLimits,
		policyHash:   policy.Hash(p),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Snapshot policy fields so a concurrent ReloadPolicy can't change them mid-request.
	h.mu.RLock()
	evaluator := h.evaluator
	failClosed := h.failClosed
	rateLimiter := h.rateLimiter
	tokenBudget := h.tokenBudget
	scanResponse := h.scanResponse
	tokenLimits := h.tokenLimits
	policyHash := h.policyHash
	h.mu.RUnlock()

	start := time.Now()
	ev := audit.Event{
		RequestID:        audit.NewRequestID(),
		Provider:         h.adapter.Name(),
		Model:            h.adapter.Model(),
		Action:           "allow",
		ClientIP:         clientIP(r),
		EntitiesDetected: []string{},
		PolicyHash:       policyHash,
	}
	defer func() {
		ev.Timestamp = audit.Now()
		ev.LatencyMS = time.Since(start).Milliseconds()
		h.auditLogger.Emit(ev)
		metrics.Record(ev)
	}()

	if r.Method != http.MethodPost {
		ev.Action = actionError
		h.writeJSON(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	if rateLimiter != nil && !rateLimiter.Allow(r) {
		ev.Action = "rate_limited"
		h.writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON request body"})
		return
	}

	if len(req.Messages) == 0 {
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "messages cannot be empty"})
		return
	}

	req.Model = strings.TrimSpace(req.Model)

	adapter := h.selectAdapter(req.Model)
	ev.Provider = adapter.Name()
	if req.Model != "" {
		ev.Model = req.Model
	} else {
		ev.Model = adapter.Model()
	}

	flatText := flattenMessages(req.Messages)

	promptLen := len(flatText)
	if tokenLimits != nil && tokenLimits.MaxPromptLength > 0 && promptLen > tokenLimits.MaxPromptLength {
		ev.Action = string(policy.ActionBlock)
		ev.Reasons = []string{fmt.Sprintf("prompt length %d exceeds policy limit of %d characters", promptLen, tokenLimits.MaxPromptLength)}
		h.writeJSON(w, http.StatusRequestEntityTooLarge, blockResponse{
			Blocked: true,
			Action:  string(policy.ActionBlock),
			Reasons: []string{"prompt exceeds maximum allowed length"},
		})
		return
	}

	decision, detectResult, err := h.enforcePolicy(r.Context(), evaluator, flatText)
	if err != nil {
		if failClosed {
			reasons := []string{"detector unavailable and fail_closed is enabled"}
			ev.Action = string(policy.ActionBlock)
			ev.Reasons = reasons
			h.writeJSON(w, http.StatusForbidden, blockResponse{
				Blocked: true,
				Action:  string(policy.ActionBlock),
				Reasons: reasons,
			})
			return
		}
		// fail_open: mark audit distinctly so detector failures are visible in logs.
		ev.Action = "allow_unscanned"
		ev.Reasons = []string{fmt.Sprintf("detector unavailable: %v", err)}
		h.log.Warn().Err(err).Msg("detector failed and fail_open is enabled — request allowed unscanned")
	}

	if detectResult != nil {
		ev.InjectionDetected = detectResult.InjectionDetected
		ev.InjectionReason = detectResult.InjectionReason
		ev.DetectedLanguage = detectResult.Language
		ev.EntitiesDetected = entityTypes(detectResult.Entities)
	}

	if decision.Action == policy.ActionBlock {
		ev.Action = string(policy.ActionBlock)
		ev.Reasons = decision.Reasons
		h.writeJSON(w, http.StatusForbidden, blockResponse{
			Blocked: true,
			Action:  string(policy.ActionBlock),
			Reasons: sanitiseClientReasons(decision.Reasons), // strip sub-reasons; full detail stays in audit log
		})
		return
	}

	if decision.Action == policy.ActionMask {
		ev.Action = string(policy.ActionMask)
		h.applyMasking(&req, decision.ToMask)
	}

	if tokenLimits != nil && tokenLimits.MaxTokens > 0 {
		if req.MaxTokens == nil || *req.MaxTokens > tokenLimits.MaxTokens {
			capped := tokenLimits.MaxTokens
			req.MaxTokens = &capped
		}
	}

	if req.Model == "" && adapter.Model() == "" {
		ev.Action = actionError
		h.writeJSON(w, http.StatusInternalServerError, errorResponse{
			Error: fmt.Sprintf("provider %q has no model configured — set %s or pass model in the request", adapter.Name(), "PROMPTSHIELD_"+strings.ToUpper(adapter.Name())+"_MODEL"),
		})
		return
	}

	apiKey := adapter.ResolveAPIKey(r)
	if adapter.RequiresKey() && apiKey == "" {
		ev.Action = actionError
		h.writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing provider API key"})
		return
	}

	if tokenBudget != nil {
		// Soft cap: Check and Record are not atomic, so a small overshoot is possible under load.
		if allowed, reason := tokenBudget.Check(r); !allowed {
			ev.Action = "budget_exceeded"
			ev.Reasons = []string{reason} // full reason (with limit) only in audit log
			h.writeJSON(w, http.StatusTooManyRequests, blockResponse{
				Blocked: true,
				Action:  "budget_exceeded",
				Reasons: []string{"token budget exceeded"},
			})
			return
		}
	}

	respStatus, respBody, respHeaders, streamReader, err := adapter.Forward(r.Context(), ev.RequestID, &req, apiKey)
	if err != nil {
		h.log.Error().Err(err).Str("provider", adapter.Name()).Bool("stream", req.Stream).Msg("upstream call failed")
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadGateway, errorResponse{Error: "upstream request failed"})
		return
	}
	if streamReader != nil {
		defer streamReader.Close()
	}

	if req.Stream && streamReader == nil {
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadGateway, errorResponse{Error: "upstream streaming response missing"})
		return
	}

	h.sendResponse(r, w, &ev, &req, adapter, respStatus, respBody, respHeaders, streamReader, tokenBudget, scanResponse)
}

func (h *Handler) sendResponse(r *http.Request, w http.ResponseWriter, ev *audit.Event, req *ChatRequest, adapter Adapter, respStatus int, respBody []byte, respHeaders http.Header, streamReader io.ReadCloser, tokenBudget *budget.Tracker, scanResponse bool) {
	if !req.Stream && len(respBody) > 0 {
		usage := adapter.ExtractTokenUsage(respBody)
		ev.PromptTokens = usage.PromptTokens
		ev.CompletionTokens = usage.CompletionTokens
		ev.TotalTokens = usage.TotalTokens
		if tokenBudget != nil && ev.TotalTokens > 0 {
			tokenBudget.Record(r, ev.TotalTokens)
		}
	}

	if scanResponse && req.Stream {
		// response_scan cannot reassemble a streaming response without buffering it all.
		h.log.Warn().Str("request_id", ev.RequestID).Msg("response_scan is enabled but has no effect on streaming responses")
	}
	if scanResponse && !req.Stream && len(respBody) > 0 {
		respBody = adapter.ScanResponse(r.Context(), respBody, h.maskText)
		ev.ResponseScanned = true
	}

	h.copyResponseHeaders(w.Header(), respHeaders)

	if req.Stream {
		streamUsage, err := h.pipeStream(r.Context(), w, respStatus, streamReader, adapter.ExtractStreamTokenUsage)
		if err != nil {
			h.log.Warn().Err(err).Str("provider", adapter.Name()).Msg("stream piping failed")
			// Preserve any prior policy action in Reasons before overwriting with error.
			if ev.Action != "allow" && ev.Action != "allow_unscanned" && ev.Action != actionError {
				ev.Reasons = append(ev.Reasons, "stream failed after action: "+ev.Action)
			}
			ev.Action = actionError
		}
		if streamUsage.TotalTokens > 0 {
			ev.PromptTokens = streamUsage.PromptTokens
			ev.CompletionTokens = streamUsage.CompletionTokens
			ev.TotalTokens = streamUsage.TotalTokens
			if tokenBudget != nil {
				tokenBudget.Record(r, streamUsage.TotalTokens)
			}
		}
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(respStatus)
	if _, err := w.Write(respBody); err != nil { //nolint:gosec // intentionally proxying upstream LLM response
		h.log.Warn().Err(err).Str("request_id", ev.RequestID).Msg("write response failed")
	}
}

// ReloadPolicy swaps in a new policy without dropping in-flight requests.
// Note: per-client rate-limit and budget counters reset on every reload.
func (h *Handler) ReloadPolicy(p *policy.Policy) {
	var limiter *ratelimit.Limiter
	if rl := p.RateLimit; rl != nil {
		limiter = ratelimit.New(rl.RequestsPerMinute, rl.Burst, rl.KeyBy)
	}
	var tracker *budget.Tracker
	if p.TokenBudget != nil {
		tracker = budget.New(p.TokenBudget)
	}
	h.mu.Lock()
	oldLimiter := h.rateLimiter
	oldTracker := h.tokenBudget
	h.evaluator = policy.NewEvaluator(p)
	h.failClosed = p.OnDetectorError == "fail_closed"
	h.rateLimiter = limiter
	h.tokenBudget = tracker
	h.scanResponse = p.ResponseScan != nil && p.ResponseScan.Enabled
	h.tokenLimits = p.TokenLimits
	h.policyHash = policy.Hash(p)
	h.mu.Unlock()
	if oldLimiter != nil {
		oldLimiter.Stop()
	}
	if oldTracker != nil {
		oldTracker.Stop()
	}
}

// selectAdapter returns h.adapter in single-provider mode, or routes by model in multi-provider mode.
func (h *Handler) selectAdapter(model string) Adapter {
	if model != "" {
		if router, ok := h.adapter.(AdapterRouter); ok {
			selected := router.Route(model)
			h.log.Debug().
				Str("model", model).
				Str("provider", selected.Name()).
				Msg("routed request to provider")
			return selected
		}
	}
	return h.adapter
}

func (h *Handler) enforcePolicy(ctx context.Context, evaluator *policy.Evaluator, text string) (policy.Decision, *detector.DetectResponse, error) {
	if strings.TrimSpace(text) == "" {
		return policy.Decision{Action: policy.ActionAllow}, nil, nil
	}
	detectResult, err := h.analyzer.Detect(ctx, text)
	if err != nil {
		return policy.Decision{Action: policy.ActionAllow}, nil, err
	}
	return evaluator.Evaluate(detectResult), detectResult, nil
}

// applyMasking maps entity offsets from the flattened prompt back to per-message positions.
// Offsets are in rune space (Unicode characters) because the Python detector uses character positions.
func (h *Handler) applyMasking(req *ChatRequest, entities []detector.Entity) {
	if len(req.Messages) == 0 || len(entities) == 0 {
		return
	}

	offset := 0 // rune offset into the flattened text
	first := true
	for i := range req.Messages {
		trimmed := strings.TrimSpace(req.Messages[i].Content)
		if trimmed == "" {
			continue
		}
		if !first {
			offset++ // '\n' separator from flattenMessages
		}
		first = false

		runeLen := len([]rune(trimmed))
		segEnd := offset + runeLen

		var local []detector.Entity
		for _, e := range entities {
			if e.End <= offset || e.Start >= segEnd {
				continue
			}
			start := e.Start - offset
			if start < 0 {
				start = 0
			}
			end := e.End - offset
			if end > runeLen {
				end = runeLen
			}
			if start >= end {
				continue
			}
			local = append(local, detector.Entity{Type: e.Type, Start: start, End: end})
		}

		if len(local) > 0 {
			// Preserve original leading/trailing whitespace (ASCII, so byte indexing is safe).
			original := req.Messages[i].Content
			prefix := original[:len(original)-len(strings.TrimLeft(original, " \t\r\n"))]
			suffix := original[len(strings.TrimRight(original, " \t\r\n")):]
			req.Messages[i].Content = prefix + masker.Mask(trimmed, local) + suffix
		}
		offset = segEnd
	}
}

func (h *Handler) maskText(ctx context.Context, text string) (string, bool) {
	h.mu.RLock()
	evaluator := h.evaluator
	h.mu.RUnlock()

	result, err := h.analyzer.Detect(ctx, text)
	if err != nil {
		return text, false
	}
	decision := evaluator.Evaluate(result)
	if decision.Action == policy.ActionMask && len(decision.ToMask) > 0 {
		return masker.Mask(text, decision.ToMask), true
	}
	return text, false
}

func (h *Handler) copyResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if _, blocked := hopByHopHeaders[strings.ToLower(key)]; blocked {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func (h *Handler) pipeStream(
	ctx context.Context,
	w http.ResponseWriter,
	status int,
	body io.Reader,
	extractUsage func([]byte, TokenUsage) TokenUsage,
) (TokenUsage, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return TokenUsage{}, fmt.Errorf("streaming is not supported by response writer")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	var usage TokenUsage
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 256*1024), 256*1024) // 256 KB per SSE line

	for scanner.Scan() {
		if ctx.Err() != nil {
			return usage, nil // client disconnected
		}
		line := scanner.Bytes()

		// Two writes to avoid appending to scanner's internal buffer slice.
		if _, err := w.Write(line); err != nil {
			return usage, err
		}
		if _, err := w.Write([]byte{'\n'}); err != nil {
			return usage, err
		}
		if len(line) == 0 {
			flusher.Flush() // flush at SSE event boundary
		}
		if extractUsage != nil && bytes.HasPrefix(line, []byte("data: ")) {
			payload := line[6:]
			if !bytes.Equal(payload, []byte("[DONE]")) {
				usage = extractUsage(payload, usage)
			}
		}
	}
	return usage, scanner.Err()
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		h.log.Error().Err(err).Msg("failed to write JSON response")
	}
}

func flattenMessages(messages []ChatMessage) string {
	parts := make([]string, 0, len(messages))
	for _, msg := range messages {
		content := strings.TrimSpace(msg.Content)
		if content != "" {
			parts = append(parts, content)
		}
	}
	return strings.Join(parts, "\n")
}

// sanitiseClientReasons strips sub-details from block reasons before sending them to callers.
// Full reasons are kept in the audit log only.
//   - "prompt injection detected: <technique>" → "prompt injection detected"
//   - "blocked PII entity detected: <TYPE>"    → "blocked PII entity detected"
func sanitiseClientReasons(reasons []string) []string {
	out := make([]string, len(reasons))
	for i, r := range reasons {
		switch {
		case strings.Contains(r, "prompt injection detected:"):
			out[i] = "prompt injection detected"
		case strings.HasPrefix(r, "blocked PII entity detected:"):
			out[i] = "blocked PII entity detected"
		default:
			out[i] = r
		}
	}
	return out
}

func entityTypes(entities []detector.Entity) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, e := range entities {
		if _, ok := seen[e.Type]; !ok {
			seen[e.Type] = struct{}{}
			out = append(out, e.Type)
		}
	}
	return out
}
