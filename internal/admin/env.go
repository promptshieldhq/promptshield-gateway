package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

func (a *API) persistEnvUpdates(updates map[string]string) error {
	a.envMu.Lock()
	defer a.envMu.Unlock()

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

	if err := writeFileAtomically(a.envFilePath, []byte(updated), mode); err != nil {
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

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
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
