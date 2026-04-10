package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/promptshieldhq/promptshield-proxy/internal/config"
	"github.com/promptshieldhq/promptshield-proxy/internal/policy"
	"github.com/rs/zerolog"
)

const (
	maxAdminConfigBodyBytes = 1 << 20 // 1 MiB
	maxAdminPolicyBodyBytes = 1 << 20 // 1 MiB

	modeGateway        = "gateway"
	modeSecurity       = "security"
	providerModeSingle = "single"
	providerModeMulti  = "multi"
)

var safeEnvValuePattern = regexp.MustCompile(`^[A-Za-z0-9_./:@,+-]+$`)

type adminAPI struct {
	log          zerolog.Logger
	policyPath   string
	envFilePath  string
	onPolicyLoad func(*policy.Policy)
	adminToken   string
}

type modelRoute struct {
	Model    string `json:"model"`
	Provider string `json:"provider"`
}

type configUpdateRequest struct {
	Mode         string            `json:"mode"`
	EngineURL    string            `json:"engineUrl"`
	ProviderMode string            `json:"providerMode"`
	Provider     string            `json:"provider"`
	UpstreamURL  string            `json:"upstreamUrl"`
	Providers    []string          `json:"providers"`
	ProviderURLs map[string]string `json:"providerUrls"`
	Models       map[string]string `json:"models"`
	ModelRoutes  []modelRoute      `json:"modelRoutes"`
	Port         string            `json:"port"`
	ChatRoute    string            `json:"chatRoute"`
	PolicyPath   string            `json:"policyPath"`
}

type configResponse struct {
	Mode         string            `json:"mode"`
	EngineURL    string            `json:"engineUrl"`
	Provider     string            `json:"provider"`
	UpstreamURL  string            `json:"upstreamUrl"`
	ProviderMode string            `json:"providerMode"`
	Providers    []string          `json:"providers"`
	ProviderURLs map[string]string `json:"providerUrls"`
	Models       map[string]string `json:"models"`
	ModelRoutes  []modelRoute      `json:"modelRoutes"`
	KeyCounts    map[string]int    `json:"keyCounts"`
	Port         string            `json:"port"`
	ChatRoute    string            `json:"chatRoute"`
	PolicyPath   string            `json:"policyPath"`
}

func newAdminAPI(log zerolog.Logger, policyPath, envFilePath string, onPolicyLoad func(*policy.Policy)) *adminAPI {
	token := strings.TrimSpace(os.Getenv("PROXY_ADMIN_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("PROMPTSHIELD_ADMIN_TOKEN"))
	}
	if envFilePath == "" {
		envFilePath = defaultEnvFile
	}

	adminLog := log.With().Str("component", "admin-api").Logger()
	if token == "" {
		adminLog.Warn().Msg("admin API is enabled but no admin token is configured")
	}

	return &adminAPI{
		log:          adminLog,
		policyPath:   policyPath,
		envFilePath:  envFilePath,
		onPolicyLoad: onPolicyLoad,
		adminToken:   token,
	}
}

func (a *adminAPI) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/config", a.handleGetConfig)
	mux.HandleFunc("PUT /admin/config", a.handleUpdateConfig)
	mux.HandleFunc("POST /admin/config", a.handleUpdateConfig)
	mux.HandleFunc("GET /admin/policy", a.handleGetPolicy)
	mux.HandleFunc("PUT /admin/policy", a.handleUpdatePolicy)
}

func (a *adminAPI) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAuth(w, r) {
		return
	}

	e := os.Getenv
	engineURL := strings.TrimSpace(e("PROMPTSHIELD_ENGINE_URL"))
	mode := modeSecurity
	if engineURL == "" || strings.EqualFold(engineURL, engineURLNone) {
		mode = modeGateway
		engineURL = ""
	}

	providers := splitCSV(e("PROMPTSHIELD_PROVIDERS"))
	providerMode := providerModeSingle
	if len(providers) > 0 {
		providerMode = "multi"
	}

	resp := configResponse{
		Mode:         mode,
		EngineURL:    engineURL,
		Provider:     strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini")),
		UpstreamURL:  strings.TrimSpace(e("PROMPTSHIELD_UPSTREAM_URL")),
		ProviderMode: providerMode,
		Providers:    providers,
		ProviderURLs: map[string]string{
			"gemini":            strings.TrimSpace(e("PROMPTSHIELD_GEMINI_UPSTREAM_URL")),
			"openai":            strings.TrimSpace(e("PROMPTSHIELD_OPENAI_UPSTREAM_URL")),
			"anthropic":         strings.TrimSpace(e("PROMPTSHIELD_ANTHROPIC_UPSTREAM_URL")),
			"selfhosted":        strings.TrimSpace(e("PROMPTSHIELD_SELFHOSTED_UPSTREAM_URL")),
			"openai-compatible": strings.TrimSpace(e("PROMPTSHIELD_OPENAI_COMPATIBLE_UPSTREAM_URL")),
		},
		Models: map[string]string{
			"global":     strings.TrimSpace(e("PROMPTSHIELD_MODEL")),
			"gemini":     strings.TrimSpace(e("PROMPTSHIELD_GEMINI_MODEL")),
			"openai":     strings.TrimSpace(e("PROMPTSHIELD_OPENAI_MODEL")),
			"anthropic":  strings.TrimSpace(e("PROMPTSHIELD_ANTHROPIC_MODEL")),
			"selfhosted": strings.TrimSpace(e("PROMPTSHIELD_SELFHOSTED_MODEL")),
		},
		ModelRoutes: parseModelRoutesList(strings.TrimSpace(e("PROMPTSHIELD_MODEL_ROUTES"))),
		KeyCounts: map[string]int{
			"upstream":  len(splitCSV(e("PROMPTSHIELD_UPSTREAM_API_KEY"))),
			"gemini":    len(splitCSV(e("GEMINI_API_KEY"))),
			"openai":    len(splitCSV(e("OPENAI_API_KEY"))),
			"anthropic": len(splitCSV(e("ANTHROPIC_API_KEY"))),
		},
		Port:       config.GetEnv("PROMPTSHIELD_PORT", "8080"),
		ChatRoute:  config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions"),
		PolicyPath: config.GetEnv("PROMPTSHIELD_POLICY_PATH", "config/policy.yaml"),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *adminAPI) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAuth(w, r) {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdminConfigBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if len(body) > maxAdminConfigBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds size limit")
		return
	}

	var req configUpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	updates, err := buildConfigEnvUpdates(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := a.persistEnvUpdates(updates); err != nil {
		a.log.Error().Err(err).Msg("failed to persist config updates")
		writeError(w, http.StatusInternalServerError, "failed to persist config")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "Config updated. Restart the proxy for all changes to take effect.",
	})
}

func (a *adminAPI) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAuth(w, r) {
		return
	}
	if a.policyPath == "" {
		writeError(w, http.StatusBadRequest, "no policy file is configured")
		return
	}

	content, err := os.ReadFile(a.policyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "policy file not found")
			return
		}
		a.log.Error().Err(err).Str("path", a.policyPath).Msg("failed reading policy file")
		writeError(w, http.StatusInternalServerError, "failed to read policy file")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"content": string(content),
		"yaml":    string(content),
	})
}

func (a *adminAPI) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAuth(w, r) {
		return
	}
	if a.policyPath == "" {
		writeError(w, http.StatusBadRequest, "no policy file is configured")
		return
	}

	content, err := readPolicyPayload(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	parsedPolicy, err := validatePolicyContent(content)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid policy: %v", err))
		return
	}

	if err := os.MkdirAll(filepath.Dir(a.policyPath), 0o755); err != nil {
		a.log.Error().Err(err).Str("path", a.policyPath).Msg("failed to ensure policy directory")
		writeError(w, http.StatusInternalServerError, "failed to write policy file")
		return
	}

	mode := os.FileMode(0o600)
	if info, err := os.Stat(a.policyPath); err == nil {
		mode = info.Mode().Perm()
	}

	if err := os.WriteFile(a.policyPath, []byte(content), mode); err != nil {
		a.log.Error().Err(err).Str("path", a.policyPath).Msg("failed writing policy file")
		writeError(w, http.StatusInternalServerError, "failed to write policy file")
		return
	}

	if a.onPolicyLoad != nil {
		a.onPolicyLoad(parsedPolicy)
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (a *adminAPI) requireAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if a.adminToken == "" {
		writeError(w, http.StatusServiceUnavailable, "admin token is not configured")
		return false
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization")
		return false
	}

	token := auth
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token = strings.TrimSpace(auth[7:])
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(a.adminToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid authorization")
		return false
	}

	return true
}

func buildConfigEnvUpdates(req configUpdateRequest) (map[string]string, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = modeSecurity
	}
	if mode != modeGateway && mode != modeSecurity {
		return nil, fmt.Errorf("mode must be gateway or security")
	}

	providerMode := strings.ToLower(strings.TrimSpace(req.ProviderMode))
	if providerMode == "" {
		providerMode = providerModeSingle
	}
	if providerMode != providerModeSingle && providerMode != providerModeMulti {
		return nil, fmt.Errorf("providerMode must be single or multi")
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = "gemini"
	}
	if err := validProvider(provider); err != nil {
		return nil, err
	}

	engineURL, err := validatedURLOrEmpty(strings.TrimSpace(req.EngineURL), "engineUrl")
	if err != nil {
		return nil, err
	}
	if mode == modeSecurity && engineURL == "" {
		return nil, fmt.Errorf("engineUrl is required when mode=security")
	}

	upstreamURL, err := validatedURLOrEmpty(strings.TrimSpace(req.UpstreamURL), "upstreamUrl")
	if err != nil {
		return nil, err
	}

	updates := map[string]string{
		"PROMPTSHIELD_ENGINE_URL": engineURLNone,
	}
	if mode == modeSecurity {
		updates["PROMPTSHIELD_ENGINE_URL"] = engineURL
	}

	if providerMode == providerModeSingle {
		updates["PROMPTSHIELD_PROVIDER"] = provider
		updates["PROMPTSHIELD_PROVIDERS"] = ""
		updates["PROMPTSHIELD_UPSTREAM_URL"] = upstreamURL
	} else {
		providers, err := normalizeProviders(req.Providers)
		if err != nil {
			return nil, err
		}
		if len(providers) == 0 {
			return nil, fmt.Errorf("providers is required when providerMode=multi")
		}
		updates["PROMPTSHIELD_PROVIDER"] = ""
		updates["PROMPTSHIELD_PROVIDERS"] = strings.Join(providers, ",")
		updates["PROMPTSHIELD_UPSTREAM_URL"] = ""
	}

	providerURLKeys := map[string]string{
		"gemini":            "PROMPTSHIELD_GEMINI_UPSTREAM_URL",
		"openai":            "PROMPTSHIELD_OPENAI_UPSTREAM_URL",
		"anthropic":         "PROMPTSHIELD_ANTHROPIC_UPSTREAM_URL",
		"selfhosted":        "PROMPTSHIELD_SELFHOSTED_UPSTREAM_URL",
		"openai-compatible": "PROMPTSHIELD_OPENAI_COMPATIBLE_UPSTREAM_URL",
	}
	for providerName, envKey := range providerURLKeys {
		urlValue := strings.TrimSpace(req.ProviderURLs[providerName])
		validated, err := validatedURLOrEmpty(urlValue, fmt.Sprintf("providerUrls.%s", providerName))
		if err != nil {
			return nil, err
		}
		updates[envKey] = validated
	}

	modelEnv := map[string]string{
		"global":     "PROMPTSHIELD_MODEL",
		"gemini":     "PROMPTSHIELD_GEMINI_MODEL",
		"openai":     "PROMPTSHIELD_OPENAI_MODEL",
		"anthropic":  "PROMPTSHIELD_ANTHROPIC_MODEL",
		"selfhosted": "PROMPTSHIELD_SELFHOSTED_MODEL",
	}
	for name, envKey := range modelEnv {
		updates[envKey] = strings.TrimSpace(req.Models[name])
	}

	if len(req.ModelRoutes) > 0 {
		routes := make([]string, 0, len(req.ModelRoutes))
		for _, route := range req.ModelRoutes {
			model := strings.TrimSpace(route.Model)
			providerName := strings.ToLower(strings.TrimSpace(route.Provider))
			if model == "" || providerName == "" {
				continue
			}
			if err := validProvider(providerName); err != nil {
				return nil, fmt.Errorf("modelRoutes.%s: %w", model, err)
			}
			routes = append(routes, fmt.Sprintf("%s=%s", model, providerName))
		}
		updates["PROMPTSHIELD_MODEL_ROUTES"] = strings.Join(routes, ",")
	} else {
		updates["PROMPTSHIELD_MODEL_ROUTES"] = ""
	}

	port := strings.TrimSpace(req.Port)
	if port == "" {
		port = config.GetEnv("PROMPTSHIELD_PORT", "8080")
	}
	if err := config.ValidatePort(port); err != nil {
		return nil, fmt.Errorf("port is invalid")
	}
	updates["PROMPTSHIELD_PORT"] = port

	chatRoute := strings.TrimSpace(req.ChatRoute)
	if chatRoute == "" {
		chatRoute = config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions")
	}
	if !strings.HasPrefix(chatRoute, "/") {
		return nil, fmt.Errorf("chatRoute must start with '/'")
	}
	updates["PROMPTSHIELD_CHAT_ROUTE"] = chatRoute

	policyPath := strings.TrimSpace(req.PolicyPath)
	if policyPath == "" {
		policyPath = config.GetEnv("PROMPTSHIELD_POLICY_PATH", "config/policy.yaml")
	}
	updates["PROMPTSHIELD_POLICY_PATH"] = policyPath

	for key, value := range updates {
		if strings.ContainsAny(value, "\n\r\x00") {
			return nil, fmt.Errorf("%s contains unsafe characters", key)
		}
	}

	return updates, nil
}

func (a *adminAPI) persistEnvUpdates(updates map[string]string) error {
	existing, err := os.ReadFile(a.envFilePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	updated := applyEnvUpdates(string(existing), updates)

	if err := os.MkdirAll(filepath.Dir(a.envFilePath), 0o755); err != nil {
		return err
	}

	mode := os.FileMode(0o600)
	if info, statErr := os.Stat(a.envFilePath); statErr == nil {
		mode = info.Mode().Perm()
	}

	if err := os.WriteFile(a.envFilePath, []byte(updated), mode); err != nil { //nolint:gosec // G703: envFilePath is set at startup from a trusted flag or environment variable, not from request input
		return err
	}

	for key, value := range updates {
		if value == "" {
			_ = os.Unsetenv(key)
			continue
		}
		_ = os.Setenv(key, value)
	}

	return nil
}

func applyEnvUpdates(content string, updates map[string]string) string {
	lines := strings.Split(content, "\n")
	seen := make(map[string]bool, len(updates))

	for idx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		eq := strings.Index(trimmed, "=")
		if eq == -1 {
			continue
		}

		key := strings.TrimSpace(trimmed[:eq])
		value, ok := updates[key]
		if !ok {
			continue
		}
		seen[key] = true

		if value == "" {
			lines[idx] = "# " + key + "="
			continue
		}

		lines[idx] = key + "=" + quoteEnvValue(value)
	}

	for key, value := range updates {
		if seen[key] || value == "" {
			continue
		}
		lines = append(lines, key+"="+quoteEnvValue(value))
	}

	return strings.Join(lines, "\n")
}

func quoteEnvValue(value string) string {
	if safeEnvValuePattern.MatchString(value) {
		return value
	}
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func validatedURLOrEmpty(raw, fieldName string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if err := config.ValidateURL(raw); err != nil {
		return "", fmt.Errorf("%s is invalid", fieldName)
	}
	if err := config.ValidateNotLinkLocalURL(raw); err != nil {
		return "", fmt.Errorf("%s is invalid", fieldName)
	}
	return raw, nil
}

func normalizeProviders(input []string) ([]string, error) {
	providers := make([]string, 0, len(input))
	for _, providerName := range input {
		name := strings.ToLower(strings.TrimSpace(providerName))
		if name == "" {
			continue
		}
		if err := validProvider(name); err != nil {
			return nil, err
		}
		if slices.Contains(providers, name) {
			continue
		}
		providers = append(providers, name)
	}
	return providers, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func parseModelRoutesList(value string) []modelRoute {
	parts := splitCSV(value)
	routes := make([]modelRoute, 0, len(parts))
	for _, part := range parts {
		model, providerName, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		model = strings.TrimSpace(model)
		providerName = strings.ToLower(strings.TrimSpace(providerName))
		if model == "" || providerName == "" {
			continue
		}
		routes = append(routes, modelRoute{Model: model, Provider: providerName})
	}
	return routes
}

func readPolicyPayload(r *http.Request) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdminPolicyBodyBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read request body")
	}
	if len(body) > maxAdminPolicyBodyBytes {
		return "", fmt.Errorf("request body exceeds size limit")
	}

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.Contains(contentType, "application/json") {
		var payload struct {
			Content string `json:"content"`
			YAML    string `json:"yaml"`
			Policy  string `json:"policy"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", fmt.Errorf("invalid JSON payload")
		}

		for _, candidate := range []string{payload.Content, payload.YAML, payload.Policy} {
			if strings.TrimSpace(candidate) != "" {
				return candidate, nil
			}
		}
		return "", fmt.Errorf("policy content is required")
	}

	content := string(body)
	if strings.TrimSpace(content) == "" {
		return "", fmt.Errorf("policy content is required")
	}
	return content, nil
}

func validatePolicyContent(content string) (*policy.Policy, error) {
	tmpFile, err := os.CreateTemp("", "promptshield-policy-*.yaml")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		return nil, err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, err
	}

	return policy.Load(tmpPath)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"success":false,"error":"internal encoding error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data) //nolint:errcheck // write errors after headers are sent cannot be communicated to the client
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"success": false,
		"error":   message,
	})
}
