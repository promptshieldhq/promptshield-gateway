package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/audit"
	"github.com/promptshieldhq/promptshield-gateway/internal/budget"
	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/detector"
	"github.com/promptshieldhq/promptshield-gateway/internal/masker"
	"github.com/promptshieldhq/promptshield-gateway/internal/metrics"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
	"github.com/promptshieldhq/promptshield-gateway/internal/ratelimit"
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
	redisURL    string // stored so ReloadPolicy can build Redis-backed limiters

	// mu guards the fields below; swapped atomically by ReloadPolicy.
	mu                    sync.RWMutex
	evaluator             *policy.Evaluator
	failClosed            bool
	rateLimiter           ratelimit.RateLimiter // nil = disabled
	tokenBudget           budget.Tracker        // nil = disabled
	scanResponse          bool
	responseScanMaxBuffer int                       // 0 → 2 MiB default
	tokenLimits           *policy.TokenLimitsPolicy // nil = disabled
	policyHash            string
}

func NewHandler(
	adapter Adapter,
	analyzer detector.Analyzer,
	evaluator *policy.Evaluator,
	failClosed bool,
	log zerolog.Logger,
	auditLogger *audit.Logger,
	rateLimiter ratelimit.RateLimiter,
	tokenBudget budget.Tracker,
	scanResponse bool,
	responseScanMaxBuffer int,
	tokenLimits *policy.TokenLimitsPolicy,
	p *policy.Policy,
	redisURL string,
) *Handler {
	return &Handler{
		adapter:               adapter,
		analyzer:              analyzer,
		evaluator:             evaluator,
		failClosed:            failClosed,
		log:                   log,
		auditLogger:           auditLogger,
		rateLimiter:           rateLimiter,
		tokenBudget:           tokenBudget,
		scanResponse:          scanResponse,
		responseScanMaxBuffer: responseScanMaxBuffer,
		tokenLimits:           tokenLimits,
		redisURL:              redisURL,
		policyHash:            policy.Hash(p),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Snapshot policy state for this request.
	h.mu.RLock()
	evaluator := h.evaluator
	failClosed := h.failClosed
	rateLimiter := h.rateLimiter
	tokenBudget := h.tokenBudget
	scanResponse := h.scanResponse
	responseScanMaxBuffer := h.responseScanMaxBuffer
	tokenLimits := h.tokenLimits
	policyHash := h.policyHash
	h.mu.RUnlock()

	start := time.Now()
	requestID := audit.NewRequestID()
	ctx := detector.WithRequestID(r.Context(), requestID)
	r = r.WithContext(ctx)
	// Set request ID header on all responses.
	w.Header().Set("X-Request-ID", requestID)

	ev := audit.Event{
		RequestID:        requestID,
		Provider:         h.adapter.Name(),
		Model:            h.adapter.Model(),
		Action:           "allow",
		ClientIP:         config.ClientIPFromRequest(r),
		EntitiesDetected: []string{},
		PolicyHash:       policyHash,
	}
	defer func() {
		ev.Timestamp = audit.Now()
		ev.LatencyMS = time.Since(start).Milliseconds()
		h.auditLogger.Emit(ctx, ev)
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

	req, ok := h.decodeChatRequest(w, r, &ev)
	if !ok {
		return
	}

	adapter := h.selectAdapter(req.Model)
	ev.Provider = adapter.Name()
	if req.Model != "" {
		ev.Model = req.Model
	} else {
		ev.Model = adapter.Model()
	}

	flatText := flattenMessages(req.Messages)

	if !h.enforcePromptLengthLimit(w, &ev, tokenLimits, flatText) {
		return
	}

	decision, detectResult, err := h.enforcePolicy(ctx, evaluator, flatText)
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
		// fail_open: allow request but mark it in audit.
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
			Reasons: sanitiseClientReasons(decision.Reasons), // keep public reason generic
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
		// Soft cap: Check and Record are separate; small overshoot can happen.
		if allowed, reason := tokenBudget.Check(r); !allowed {
			ev.Action = "budget_exceeded"
			ev.Reasons = []string{reason} // detailed reason stays in audit
			h.writeJSON(w, http.StatusTooManyRequests, blockResponse{
				Blocked: true,
				Action:  "budget_exceeded",
				Reasons: []string{"token budget exceeded"},
			})
			return
		}
	}

	respStatus, respBody, respHeaders, streamReader, err := adapter.Forward(ctx, ev.RequestID, &req, apiKey)
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

	h.sendResponse(r, w, &ev, &req, adapter, respStatus, respBody, respHeaders, streamReader, tokenBudget, scanResponse, responseScanMaxBuffer)
}

func (h *Handler) decodeChatRequest(w http.ResponseWriter, r *http.Request, ev *audit.Event) (ChatRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid JSON request body"})
		return ChatRequest{}, false
	}

	if len(req.Messages) == 0 {
		ev.Action = actionError
		h.writeJSON(w, http.StatusBadRequest, errorResponse{Error: "messages cannot be empty"})
		return ChatRequest{}, false
	}

	req.Model = strings.TrimSpace(req.Model)
	return req, true
}

func (h *Handler) enforcePromptLengthLimit(w http.ResponseWriter, ev *audit.Event, tokenLimits *policy.TokenLimitsPolicy, flatText string) bool {
	promptLen := len(flatText)
	if tokenLimits == nil || tokenLimits.MaxPromptLength <= 0 || promptLen <= tokenLimits.MaxPromptLength {
		return true
	}

	ev.Action = string(policy.ActionBlock)
	ev.Reasons = []string{fmt.Sprintf("prompt length %d exceeds policy limit of %d characters", promptLen, tokenLimits.MaxPromptLength)}
	h.writeJSON(w, http.StatusRequestEntityTooLarge, blockResponse{
		Blocked: true,
		Action:  string(policy.ActionBlock),
		Reasons: []string{"prompt exceeds maximum allowed length"},
	})
	return false
}

const (
	defaultResponseScanMaxBuffer = 2 << 20 // 2 MiB
	maxSSELineBytes              = 1 << 20 // 1 MiB per SSE line
)

func (h *Handler) sendResponse(r *http.Request, w http.ResponseWriter, ev *audit.Event, req *ChatRequest, adapter Adapter, respStatus int, respBody []byte, respHeaders http.Header, streamReader io.ReadCloser, tokenBudget budget.Tracker, scanResponse bool, responseScanMaxBuffer int) {
	if !req.Stream && len(respBody) > 0 {
		usage := adapter.ExtractTokenUsage(respBody)
		ev.PromptTokens = usage.PromptTokens
		ev.CompletionTokens = usage.CompletionTokens
		ev.TotalTokens = usage.TotalTokens
		if tokenBudget != nil && ev.TotalTokens > 0 {
			tokenBudget.Record(r, ev.TotalTokens)
		}
	}

	// For streaming scan, buffer SSE up to max size, mask text, then replay.
	if scanResponse && req.Stream && streamReader != nil {
		maxBuf := responseScanMaxBuffer
		if maxBuf <= 0 {
			maxBuf = defaultResponseScanMaxBuffer
		}
		// Read maxBuf+1 bytes so overflow is detectable.
		buf, err := io.ReadAll(io.LimitReader(streamReader, int64(maxBuf)+1))
		if err == nil && len(buf) <= maxBuf {
			// Replace stream with masked output.
			masked, changed := h.maskSSEStream(r.Context(), buf, adapter.BuildStreamChunk)
			if changed {
				ev.ResponseScanned = true
			}
			streamReader = io.NopCloser(bytes.NewReader(masked))
		} else {
			// Fail closed when stream exceeds scan buffer.
			h.log.Warn().
				Str("request_id", ev.RequestID).
				Int("max_buffer_bytes", maxBuf).
				Msg("response_scan: streaming response exceeds buffer limit — blocking request")
			ev.Action = actionError
			h.writeJSON(w, http.StatusBadGateway, errorResponse{Error: "upstream streaming response exceeds scan buffer"})
			return
		}
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
			// Keep previous action context before overriding with stream error.
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
	if _, err := w.Write(respBody); err != nil {
		h.log.Warn().Err(err).Str("request_id", ev.RequestID).Msg("write response failed")
	}
}

// ReloadPolicy swaps policy and migrates limiter/budget counters.
// For Redis backends, Snapshot/MigrateFrom are no-ops — state already lives in Redis.
func (h *Handler) ReloadPolicy(p *policy.Policy) {
	if p == nil {
		h.log.Warn().Msg("ReloadPolicy called with nil policy — ignoring, keeping previous policy")
		return
	}
	var limiter ratelimit.RateLimiter
	if rl := p.RateLimit; rl != nil {
		var err error
		limiter, err = ratelimit.NewLimiter(rl.RequestsPerMinute, rl.Burst, rl.KeyBy, h.redisURL)
		if err != nil {
			h.log.Warn().Err(err).Msg("policy reload: Redis rate limiter unavailable — falling back to in-memory")
			limiter = ratelimit.New(rl.RequestsPerMinute, rl.Burst, rl.KeyBy)
		}
	}
	var tracker budget.Tracker
	if p.TokenBudget != nil && p.TokenBudget.IsEnabled() {
		var err error
		tracker, err = budget.NewTracker(p.TokenBudget, h.redisURL)
		if err != nil {
			h.log.Warn().Err(err).Msg("policy reload: Redis budget tracker unavailable — falling back to in-memory")
			tracker = budget.New(p.TokenBudget)
		}
	}

	maxBuffer := 0
	if p.ResponseScan != nil {
		maxBuffer = p.ResponseScan.MaxBufferBytes
	}

	h.mu.Lock()
	oldLimiter := h.rateLimiter
	oldTracker := h.tokenBudget

	// Move counters before swapping in new limiter/tracker.
	// For Redis backends this is a no-op — counters already survive in Redis.
	if limiter != nil && oldLimiter != nil {
		limiter.MigrateFrom(oldLimiter.Snapshot())
	}
	if tracker != nil && oldTracker != nil {
		tracker.MigrateFrom(oldTracker.Snapshot())
	}

	h.evaluator = policy.NewEvaluator(p)
	h.failClosed = p.OnDetectorError == "fail_closed"
	h.rateLimiter = limiter
	h.tokenBudget = tracker
	h.scanResponse = p.ResponseScan != nil && p.ResponseScan.Enabled
	h.responseScanMaxBuffer = maxBuffer
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

// maskSSEStream extracts text from SSE chunks, masks it, and rebuilds the stream.
// It supports OpenAI, Anthropic, and Gemini payload formats.
func (h *Handler) maskSSEStream(ctx context.Context, buf []byte, buildChunk func(string) []byte) ([]byte, bool) {
	var hasContent bool
	var fullText strings.Builder

	pos := 0
	for pos < len(buf) {
		nl := bytes.IndexByte(buf[pos:], '\n')
		var line []byte
		if nl < 0 {
			line = buf[pos:]
			pos = len(buf)
		} else {
			line = buf[pos : pos+nl]
			pos = pos + nl + 1
		}
		line = bytes.TrimRight(line, "\r")
		if !bytes.HasPrefix(line, []byte("data: ")) {
			continue
		}
		payload := line[6:]
		if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
			continue
		}
		text := extractSSEText(payload)
		if text == "" {
			continue
		}
		hasContent = true
		fullText.WriteString(text)
	}

	if fullText.Len() == 0 {
		return buf, false
	}

	masked, changed := h.maskText(ctx, fullText.String())
	if !changed {
		return buf, false
	}

	var out bytes.Buffer
	pos = 0
	for pos < len(buf) {
		nl := bytes.IndexByte(buf[pos:], '\n')
		var line []byte
		if nl < 0 {
			line = buf[pos:]
			pos = len(buf)
		} else {
			line = buf[pos : pos+nl]
			pos = pos + nl + 1
		}
		raw := bytes.TrimRight(line, "\r")
		if bytes.HasPrefix(raw, []byte("data: ")) {
			payload := raw[6:]
			if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
				continue // emit DONE once at the end
			}
			if extractSSEText(payload) != "" {
				continue // replaced with one merged chunk below
			}
		}
		out.Write(raw)
		out.WriteByte('\n')
	}

	if hasContent {
		if mergedJSON := buildChunk(masked); mergedJSON != nil {
			out.WriteString("data: ")
			out.Write(mergedJSON)
			out.WriteString("\n\n")
		}
	}
	out.WriteString("data: [DONE]\n\n")
	return out.Bytes(), true
}

// extractSSEText pulls text from one SSE JSON payload.
func extractSSEText(payload []byte) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(payload, &obj) != nil {
		return ""
	}
	// OpenAI-style payload
	if raw, ok := obj["choices"]; ok {
		var arr []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		}
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			return arr[0].Delta.Content
		}
	}
	// Anthropic payload
	if raw, ok := obj["delta"]; ok {
		var d struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &d) == nil && d.Text != "" {
			return d.Text
		}
	}
	// Gemini payload
	if raw, ok := obj["candidates"]; ok {
		var arr []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		}
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 && len(arr[0].Content.Parts) > 0 {
			return arr[0].Content.Parts[0].Text
		}
	}
	return ""
}

// selectAdapter routes by model in multi-provider mode.
func (h *Handler) selectAdapter(model string) Adapter {
	if model != "" {
		if router, ok := h.adapter.(AdapterRouter); ok {
			selected := router.Route(model)
			if selected == nil {
				h.log.Warn().Str("model", model).Msg("no adapter matched model; using fallback adapter")
				return h.adapter
			}
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

// applyMasking maps flattened offsets back into each message.
func (h *Handler) applyMasking(req *ChatRequest, entities []detector.Entity) {
	if len(req.Messages) == 0 || len(entities) == 0 {
		return
	}

	offset := 0 // rune offset in flattened text
	first := true
	for i := range req.Messages {
		trimmed := strings.TrimSpace(req.Messages[i].Content)
		if trimmed == "" {
			continue
		}
		if !first {
			offset++ // newline separator from flattenMessages
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
			// Keep original leading/trailing whitespace.
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

const streamWriteDeadline = 30 * time.Second

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

	rc := http.NewResponseController(w)

	var usage TokenUsage
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, maxSSELineBytes), maxSSELineBytes)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return usage, nil // client disconnected
		}
		line := scanner.Bytes()

		// Reset the write deadline before each chunk so slow but live streams
		// are never killed by a wall-clock WriteTimeout on the server.
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteDeadline)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return usage, err
		}

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

// sanitiseClientReasons removes internal details from block reasons.
func sanitiseClientReasons(reasons []string) []string {
	out := make([]string, len(reasons))
	for i, r := range reasons {
		switch {
		case strings.Contains(r, "prompt injection detected:"):
			out[i] = "prompt injection detected"
		case strings.HasPrefix(r, "blocked PII entity detected:"),
			strings.HasPrefix(r, "blocked unknown entity type:"):
			// Keep entity names and policy internals out of client responses.
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
