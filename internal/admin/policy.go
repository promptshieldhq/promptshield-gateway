package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
)

func (a *API) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
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

func (a *API) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
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

	if err := writeFileAtomically(a.policyPath, []byte(content), mode); err != nil {
		a.log.Error().Err(err).Str("path", a.policyPath).Msg("failed writing policy file")
		writeError(w, http.StatusInternalServerError, "failed to write policy file")
		return
	}

	if a.onPolicyLoad != nil {
		a.onPolicyLoad(parsedPolicy)
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
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
