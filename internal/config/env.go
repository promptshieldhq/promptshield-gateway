package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func LoadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB — handles long comma-separated key lists
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = unquoteEnvValue(value)
		if key == "" || os.Getenv(key) != "" {
			continue
		}

		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// unquoteEnvValue strips surrounding quotes or inline comments from a raw .env value.
func unquoteEnvValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	if idx := strings.Index(v, " #"); idx >= 0 {
		v = strings.TrimSpace(v[:idx])
	}
	return v
}

// ResolvePolicyPath returns the policy file path to use.
// If configuredPath is set and the file is missing, that is an error.
// If no path is configured, searches well-known locations; returns ("", nil) when nothing is found.
func ResolvePolicyPath(configuredPath, fallback string) (string, error) {
	if configuredPath != "" {
		p := filepath.Clean(configuredPath)
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("policy file %q not found", p)
		}
		return p, nil
	}

	var candidates []string
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, fallback))
	}
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		candidates = append(candidates,
			filepath.Join(execDir, fallback),
			filepath.Join(execDir, "..", fallback),
		)
	}

	for _, candidate := range candidates {
		resolved := filepath.Clean(candidate)
		if _, err := os.Stat(resolved); err == nil {
			return resolved, nil
		}
	}

	return "", nil
}

func ValidatePort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}
	return nil
}

func ValidateURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid url: %s", raw)
	}
	return nil
}

// ValidateNotLinkLocalURL rejects URLs that resolve to a link-local address (169.254.0.0/16,
// fe80::/10). These are used by cloud metadata services (IMDS) and are never valid upstreams.
// RFC-1918 private addresses are allowed for self-hosted LLMs.
//
// Limitation: DNS is resolved once at startup. A DNS rebinding attack can bypass this check.
// Mitigate with IMDSv2 (AWS), metadata server hop-limit (GCP), or equivalent platform protections.
func ValidateNotLinkLocalURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	host := u.Hostname()

	if ip := net.ParseIP(host); ip != nil {
		if isLinkLocalIP(ip) {
			return fmt.Errorf("url %q targets a link-local address — possible cloud metadata service (IMDS) exposure", raw)
		}
		return nil
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil // DNS failure: allow and let the connection attempt fail naturally
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isLinkLocalIP(ip) {
			return fmt.Errorf("url hostname %q resolves to link-local address %s — possible cloud metadata service (IMDS) exposure", host, addr)
		}
	}
	return nil
}

// linkLocalNets contains the link-local CIDR ranges used by cloud metadata services.
var linkLocalNets = func() []net.IPNet {
	ranges := []string{"169.254.0.0/16", "fe80::/10"}
	nets := make([]net.IPNet, 0, len(ranges))
	for _, cidr := range ranges {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid built-in CIDR " + cidr + ": " + err.Error())
		}
		nets = append(nets, *n)
	}
	return nets
}()

func isLinkLocalIP(ip net.IP) bool {
	for _, n := range linkLocalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
