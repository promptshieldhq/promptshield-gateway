package detector

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// GitleaksAnalyzer scans text for secrets using the default gitleaks ruleset.
type GitleaksAnalyzer struct {
	detector *detect.Detector
}

// NewGitleaksAnalyzer creates a gitleaks-backed analyzer.
func NewGitleaksAnalyzer() (*GitleaksAnalyzer, error) {
	d, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("gitleaks: load default config: %w", err)
	}
	return &GitleaksAnalyzer{detector: d}, nil
}

// Detect returns secret findings as Entity spans.
// Injection and language detection are handled upstream.
func (a *GitleaksAnalyzer) Detect(_ context.Context, text string) (*DetectResponse, error) {
	findings := a.detector.DetectString(text)
	entities := make([]Entity, 0, len(findings))
	for i := range findings {
		e, ok := findingToEntity(&findings[i], text)
		if ok {
			entities = append(entities, e)
		}
	}
	return &DetectResponse{
		PIIDetected: len(entities) > 0,
		Entities:    entities,
	}, nil
}

// findingToEntity converts a gitleaks finding to rune-based [Start, End) offsets.
func findingToEntity(f *report.Finding, text string) (Entity, bool) {
	if f.Secret == "" {
		return Entity{}, false
	}

	// Keep newlines so byte offsets stay accurate.
	lines := strings.SplitAfter(text, "\n")
	if f.StartLine < 0 || f.StartLine >= len(lines) {
		return Entity{}, false
	}

	byteLineStart := 0
	for i := 0; i < f.StartLine; i++ {
		byteLineStart += len(lines[i])
	}

	// gitleaks StartColumn is measured from the preceding '\n' (position 0),
	// so byteStart = index_of_newline + StartColumn - 1.
	// For line 0 there is no preceding '\n', so prevNewLine stays 0 and
	// StartColumn acts as a 1-indexed offset from the string start.
	prevNewLine := 0
	if f.StartLine > 0 {
		prevNewLine = byteLineStart - 1
	}

	byteStart := prevNewLine + f.StartColumn - 1
	byteEnd := byteStart + len(f.Secret)

	if byteStart < 0 || byteEnd > len(text) {
		return Entity{}, false
	}

	// Convert byte offsets to rune offsets for masking.
	runeStart := utf8.RuneCountInString(text[:byteStart])
	runeEnd := runeStart + utf8.RuneCountInString(f.Secret)

	return Entity{
		Type:  ruleIDToEntityType(f.RuleID),
		Start: runeStart,
		End:   runeEnd,
		Score: 0.95,
	}, true
}

// ruleIDToEntityType converts kebab-case to UPPER_SNAKE_CASE.
func ruleIDToEntityType(ruleID string) string {
	return strings.ToUpper(strings.ReplaceAll(ruleID, "-", "_"))
}
