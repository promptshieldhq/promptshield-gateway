package config

import (
	"bufio"
	"context"
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
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MiB for long key lists
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

// unquoteEnvValue removes wrapping quotes and inline comments.
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

// ResolvePolicyPath returns the policy path.
// If configuredPath is set, it must exist.
// If not set, known locations are checked; returns ("", nil) when none exist.
func ResolvePolicyPath(configuredPath, fallback string) (string, error) {
	if configuredPath != "" {
		p := filepath.Clean(configuredPath)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("policy file %q not found", p)
			}
			return "", fmt.Errorf("policy file %q is not accessible: %w", p, err)
		}
		return p, nil
	}

	for _, candidate := range policyPathCandidates(fallback) {
		resolved := filepath.Clean(candidate)
		if _, err := os.Stat(resolved); err == nil {
			return resolved, nil
		}
	}

	return "", nil
}

func policyPathCandidates(fallback string) []string {
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
	return candidates
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

// ValidateNotLinkLocalURL rejects upstreams resolving to link-local or IMDS ranges.
func ValidateNotLinkLocalURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	host := u.Hostname()

	return validateHostNotLinkLocal(raw, host)
}

func validateHostNotLinkLocal(raw, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isLinkLocalIP(ip) {
			return fmt.Errorf("url %q targets a link-local address — possible cloud metadata service (IMDS) exposure", raw)
		}
		return nil
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("url hostname %q could not be resolved for link-local safety check: %w", host, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isLinkLocalIP(ip) {
			return fmt.Errorf("url hostname %q resolves to link-local address %s — possible cloud metadata service (IMDS) exposure", host, addr)
		}
	}
	return nil
}

// blockedUpstreamNets holds link-local and IMDS ranges blocked as upstream targets.
var linkLocalNets = func() []net.IPNet {
	ranges := []string{
		"169.254.0.0/16",   // IPv4 link-local (AWS/GCP IMDS, APIPA)
		"fe80::/10",        // IPv6 link-local
		"168.63.129.16/32", // Azure IMDS — not link-local but must be blocked
	}
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

// NewBlockingDialer returns a DialContext that validates each resolved IP against blocked ranges (SSRF/DNS-rebinding prevention).
func NewBlockingDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// Literal IP: validate and connect directly without re-resolution.
		if ip := net.ParseIP(host); ip != nil {
			if isLinkLocalIP(ip) {
				return nil, fmt.Errorf("connection to %s blocked (SSRF prevention)", host)
			}
			return d.DialContext(ctx, network, addr)
		}

		// Hostname: resolve, validate all IPs, connect to the first safe address.
		resolved, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("dns lookup %s: %w", host, err)
		}

		var safeTarget string
		for _, a := range resolved {
			ip := net.ParseIP(a)
			if ip != nil && isLinkLocalIP(ip) {
				return nil, fmt.Errorf("connection to %s (%s) blocked (SSRF prevention)", host, a)
			}
			if safeTarget == "" {
				safeTarget = net.JoinHostPort(a, port)
			}
		}

		if safeTarget == "" {
			return nil, fmt.Errorf("no valid addresses resolved for %s", host)
		}

		// Dial the specific resolved IP to prevent a second DNS lookup that could
		// return a different (attacker-controlled) address.
		return d.DialContext(ctx, network, safeTarget)
	}
}
