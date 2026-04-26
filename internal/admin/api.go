package admin

import (
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
	"github.com/rs/zerolog"
)

const (
	maxAdminConfigBodyBytes = 1 << 20 // 1 MiB
	maxAdminPolicyBodyBytes = 1 << 20 // 1 MiB

	modeGateway          = "gateway"
	modeSecurity         = "security"
	providerModeSingle   = "single"
	providerModeMulti    = "multi"
	adminAllowedCIDRsEnv = "PROMPTSHIELD_ADMIN_ALLOWED_CIDRS"

	adminAuthFailureWindow = time.Minute
	adminAuthFailureLimit  = 10

	engineURLNone  = "none"
	defaultEnvFile = ".env"
)

var safeEnvValuePattern = regexp.MustCompile(`^[A-Za-z0-9_./:@,+-]+$`)

var providerURLKeys = map[string]string{
	"gemini":            "PROMPTSHIELD_GEMINI_UPSTREAM_URL",
	"openai":            "PROMPTSHIELD_OPENAI_UPSTREAM_URL",
	"anthropic":         "PROMPTSHIELD_ANTHROPIC_UPSTREAM_URL",
	"selfhosted":        "PROMPTSHIELD_SELFHOSTED_UPSTREAM_URL",
	"openai-compatible": "PROMPTSHIELD_OPENAI_COMPATIBLE_UPSTREAM_URL",
}

var modelEnvKeys = map[string]string{
	"global":     "PROMPTSHIELD_MODEL",
	"gemini":     "PROMPTSHIELD_GEMINI_MODEL",
	"openai":     "PROMPTSHIELD_OPENAI_MODEL",
	"anthropic":  "PROMPTSHIELD_ANTHROPIC_MODEL",
	"selfhosted": "PROMPTSHIELD_SELFHOSTED_MODEL",
}

type API struct {
	log          zerolog.Logger
	policyPath   string
	envFilePath  string
	onPolicyLoad func(*policy.Policy)
	adminToken   string
	authLimiter  *adminAuthLimiter
	envMu        sync.Mutex
	allowedCIDRs []*net.IPNet // parsed once at startup from PROMPTSHIELD_ADMIN_ALLOWED_CIDRS
}

type adminAuthWindow struct {
	count int
	reset time.Time
}

type adminAuthLimiter struct {
	mu      sync.Mutex
	buckets map[string]adminAuthWindow
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

func New(log zerolog.Logger, policyPath, envFilePath string, onPolicyLoad func(*policy.Policy)) *API {
	token := strings.TrimSpace(os.Getenv("PROMPTSHIELD_ADMIN_TOKEN"))
	if token == "" {
		// Backward compatibility for older deployments.
		token = strings.TrimSpace(os.Getenv("PROXY_ADMIN_TOKEN"))
	}
	if envFilePath == "" {
		envFilePath = defaultEnvFile
	}

	adminLog := log.With().Str("component", "admin-api").Logger()
	if token == "" {
		adminLog.Warn().Msg("admin API is enabled but no admin token is configured")
	}

	return &API{
		log:          adminLog,
		policyPath:   policyPath,
		envFilePath:  envFilePath,
		onPolicyLoad: onPolicyLoad,
		adminToken:   token,
		authLimiter:  newAdminAuthLimiter(),
		allowedCIDRs: parseAdminAllowedCIDRs(adminLog, os.Getenv(adminAllowedCIDRsEnv)),
	}
}

func newAdminAuthLimiter() *adminAuthLimiter {
	return &adminAuthLimiter{buckets: make(map[string]adminAuthWindow)}
}

func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/config", a.handleGetConfig)
	mux.HandleFunc("PUT /admin/config", a.handleUpdateConfig)
	mux.HandleFunc("POST /admin/config", a.handleUpdateConfig)
	mux.HandleFunc("GET /admin/policy", a.handleGetPolicy)
	mux.HandleFunc("PUT /admin/policy", a.handleUpdatePolicy)
}
