package main

import (
	"os"
	"strings"
)

const engineURLNone = "none"

const (
	keyByAPIKey = "api_key"
	keyByGlobal = "global"

	allowDefaultPolicyEnv = "PROMPTSHIELD_ALLOW_DEFAULT_POLICY"
	publicMetricsEnv      = "PROMPTSHIELD_EXPOSE_METRICS_ON_MAIN_PORT"

	defaultEnvFile = ".env"
)

func envTruthy(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
