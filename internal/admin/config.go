package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

func (a *API) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAuth(w, r) {
		return
	}

	writeJSON(w, http.StatusOK, buildConfigResponseFromEnv())
}

func buildConfigResponseFromEnv() configResponse {
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
		providerMode = providerModeMulti
	}

	return configResponse{
		Mode:         mode,
		EngineURL:    engineURL,
		Provider:     strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini")),
		UpstreamURL:  strings.TrimSpace(e("PROMPTSHIELD_UPSTREAM_URL")),
		ProviderMode: providerMode,
		Providers:    providers,
		ProviderURLs: currentProviderURLs(e),
		Models:       currentModels(e),
		ModelRoutes:  parseModelRoutesList(strings.TrimSpace(e("PROMPTSHIELD_MODEL_ROUTES"))),
		KeyCounts:    currentKeyCounts(e),
		Port:         config.GetEnv("PROMPTSHIELD_PORT", "8080"),
		ChatRoute:    config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions"),
		PolicyPath:   config.GetEnv("PROMPTSHIELD_POLICY_PATH", "config/policy.yaml"),
	}
}

func currentProviderURLs(getEnv func(string) string) map[string]string {
	urls := make(map[string]string, len(providerURLKeys))
	for providerName, envKey := range providerURLKeys {
		urls[providerName] = strings.TrimSpace(getEnv(envKey))
	}
	return urls
}

func currentModels(getEnv func(string) string) map[string]string {
	models := make(map[string]string, len(modelEnvKeys))
	for modelName, envKey := range modelEnvKeys {
		models[modelName] = strings.TrimSpace(getEnv(envKey))
	}
	return models
}

func currentKeyCounts(getEnv func(string) string) map[string]int {
	return map[string]int{
		"upstream":  len(splitCSV(getEnv("PROMPTSHIELD_UPSTREAM_API_KEY"))),
		"gemini":    len(splitCSV(getEnv("GEMINI_API_KEY"))),
		"openai":    len(splitCSV(getEnv("OPENAI_API_KEY"))),
		"anthropic": len(splitCSV(getEnv("ANTHROPIC_API_KEY"))),
	}
}

func validProvider(provider string) error {
	switch provider {
	case "gemini", "openai", "anthropic", "openai-compatible", "selfhosted":
		return nil
	default:
		return fmt.Errorf("unknown provider %q: must be gemini, openai, anthropic, openai-compatible, or selfhosted", provider)
	}
}

func (a *API) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
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
		"message": "Config updated. Restart the gateway for all changes to take effect.",
	})
}

func buildConfigEnvUpdates(req configUpdateRequest) (map[string]string, error) {
	mode, providerMode, provider, err := resolveConfigModes(req)
	if err != nil {
		return nil, err
	}

	engineURL, upstreamURL, err := validateConfigURLs(req, mode)
	if err != nil {
		return nil, err
	}

	updates := buildBaseUpdates(mode, engineURL)
	if err := applyProviderModeUpdates(updates, req, providerMode, provider, upstreamURL); err != nil {
		return nil, err
	}
	if err := applyProviderURLUpdates(updates, req.ProviderURLs); err != nil {
		return nil, err
	}
	applyModelUpdates(updates, req.Models)

	modelRoutes, err := buildModelRoutesValue(req.ModelRoutes)
	if err != nil {
		return nil, err
	}
	updates["PROMPTSHIELD_MODEL_ROUTES"] = modelRoutes

	if err := applyCoreRuntimeUpdates(updates, req); err != nil {
		return nil, err
	}

	if err := validateUpdateValues(updates); err != nil {
		return nil, err
	}

	return updates, nil
}

func resolveConfigModes(req configUpdateRequest) (string, string, string, error) {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = modeSecurity
	}
	if mode != modeGateway && mode != modeSecurity {
		return "", "", "", fmt.Errorf("mode must be gateway or security")
	}

	providerMode := strings.ToLower(strings.TrimSpace(req.ProviderMode))
	if providerMode == "" {
		providerMode = providerModeSingle
	}
	if providerMode != providerModeSingle && providerMode != providerModeMulti {
		return "", "", "", fmt.Errorf("providerMode must be single or multi")
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = "gemini"
	}
	if err := validProvider(provider); err != nil {
		return "", "", "", err
	}

	return mode, providerMode, provider, nil
}

func validateConfigURLs(req configUpdateRequest, mode string) (string, string, error) {
	engineURL, err := validatedURLOrEmpty(strings.TrimSpace(req.EngineURL), "engineUrl")
	if err != nil {
		return "", "", err
	}
	if mode == modeSecurity && engineURL == "" {
		return "", "", fmt.Errorf("engineUrl is required when mode=security")
	}

	upstreamURL, err := validatedURLOrEmpty(strings.TrimSpace(req.UpstreamURL), "upstreamUrl")
	if err != nil {
		return "", "", err
	}

	return engineURL, upstreamURL, nil
}

func buildBaseUpdates(mode, engineURL string) map[string]string {
	updates := map[string]string{"PROMPTSHIELD_ENGINE_URL": engineURLNone}
	if mode == modeSecurity {
		updates["PROMPTSHIELD_ENGINE_URL"] = engineURL
	}
	return updates
}

func applyProviderModeUpdates(updates map[string]string, req configUpdateRequest, providerMode, provider, upstreamURL string) error {
	if providerMode == providerModeSingle {
		updates["PROMPTSHIELD_PROVIDER"] = provider
		updates["PROMPTSHIELD_PROVIDERS"] = ""
		updates["PROMPTSHIELD_UPSTREAM_URL"] = upstreamURL
		return nil
	}

	providers, err := normalizeProviders(req.Providers)
	if err != nil {
		return err
	}
	if len(providers) == 0 {
		return fmt.Errorf("providers is required when providerMode=multi")
	}
	updates["PROMPTSHIELD_PROVIDER"] = ""
	updates["PROMPTSHIELD_PROVIDERS"] = strings.Join(providers, ",")
	updates["PROMPTSHIELD_UPSTREAM_URL"] = ""
	return nil
}

func applyProviderURLUpdates(updates, providerURLs map[string]string) error {
	for providerName, envKey := range providerURLKeys {
		urlValue := strings.TrimSpace(providerURLs[providerName])
		validated, err := validatedURLOrEmpty(urlValue, fmt.Sprintf("providerUrls.%s", providerName))
		if err != nil {
			return err
		}
		updates[envKey] = validated
	}
	return nil
}

func applyModelUpdates(updates, models map[string]string) {
	for name, envKey := range modelEnvKeys {
		updates[envKey] = strings.TrimSpace(models[name])
	}
}

func buildModelRoutesValue(routes []modelRoute) (string, error) {
	if len(routes) == 0 {
		return "", nil
	}

	encoded := make([]string, 0, len(routes))
	for _, route := range routes {
		model := strings.TrimSpace(route.Model)
		providerName := strings.ToLower(strings.TrimSpace(route.Provider))
		if model == "" || providerName == "" {
			continue
		}
		if err := validProvider(providerName); err != nil {
			return "", fmt.Errorf("modelRoutes.%s: %w", model, err)
		}
		encoded = append(encoded, fmt.Sprintf("%s=%s", model, providerName))
	}

	return strings.Join(encoded, ","), nil
}

func applyCoreRuntimeUpdates(updates map[string]string, req configUpdateRequest) error {
	port := strings.TrimSpace(req.Port)
	if port == "" {
		port = config.GetEnv("PROMPTSHIELD_PORT", "8080")
	}
	if err := config.ValidatePort(port); err != nil {
		return fmt.Errorf("port is invalid")
	}
	updates["PROMPTSHIELD_PORT"] = port

	chatRoute := strings.TrimSpace(req.ChatRoute)
	if chatRoute == "" {
		chatRoute = config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions")
	}
	if !strings.HasPrefix(chatRoute, "/") {
		return fmt.Errorf("chatRoute must start with '/'")
	}
	updates["PROMPTSHIELD_CHAT_ROUTE"] = chatRoute

	policyPath := strings.TrimSpace(req.PolicyPath)
	if policyPath == "" {
		policyPath = config.GetEnv("PROMPTSHIELD_POLICY_PATH", "config/policy.yaml")
	}
	updates["PROMPTSHIELD_POLICY_PATH"] = policyPath

	return nil
}

func validateUpdateValues(updates map[string]string) error {
	for key, value := range updates {
		if strings.ContainsAny(value, "\n\r\x00") {
			return fmt.Errorf("%s contains unsafe characters", key)
		}
	}
	return nil
}
