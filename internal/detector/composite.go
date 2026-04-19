package detector

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/rs/zerolog"
)

// entityKey deduplicates by (Type, Start, End).
type entityKey struct {
	Type  string
	Start int
	End   int
}

type upResult struct {
	resp *DetectResponse
	err  error
}

// CompositeAnalyzer runs local secrets scanning and optional upstream detection in parallel.
type CompositeAnalyzer struct {
	secrets  Analyzer // nil = no secrets backend
	upstream Analyzer // nil = no upstream PII/injection engine
	log      zerolog.Logger
}

func NewCompositeAnalyzer(secrets, upstream Analyzer, log zerolog.Logger) *CompositeAnalyzer {
	return &CompositeAnalyzer{secrets: secrets, upstream: upstream, log: log}
}

// Detect runs both analyzers in parallel and merges their results.
// Secrets backend failures are logged and skipped; upstream errors are returned.
func (c *CompositeAnalyzer) Detect(ctx context.Context, text string) (*DetectResponse, error) {
	secretsCh := c.startSecretsDetection(ctx, text)
	upCh := c.startUpstreamDetection(ctx, text)

	secretEntities := collectSecretEntities(secretsCh)
	base, err := collectUpstreamResponse(upCh)
	if err != nil {
		return nil, err
	}

	mergeEntities(base, secretEntities)
	return base, nil
}

func (c *CompositeAnalyzer) startSecretsDetection(ctx context.Context, text string) <-chan []Entity {
	if c.secrets == nil {
		return nil
	}

	out := make(chan []Entity, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				c.log.Error().
					Str("panic", fmt.Sprintf("%v", p)).
					Str("stack", string(debug.Stack())).
					Msg("secrets backend panicked — request continues unscanned for secrets")
				out <- nil
			}
		}()

		resp, err := c.secrets.Detect(ctx, text)
		if err != nil {
			c.log.Warn().Err(err).Msg("secrets backend error — continuing without secrets scan")
			out <- nil
			return
		}
		if resp == nil {
			out <- nil
			return
		}
		out <- resp.Entities
	}()

	return out
}

func (c *CompositeAnalyzer) startUpstreamDetection(ctx context.Context, text string) <-chan upResult {
	if c.upstream == nil {
		return nil
	}

	out := make(chan upResult, 1)
	go func() {
		resp, err := c.upstream.Detect(ctx, text)
		out <- upResult{resp: resp, err: err}
	}()
	return out
}

func collectSecretEntities(ch <-chan []Entity) []Entity {
	if ch == nil {
		return nil
	}
	return <-ch
}

func collectUpstreamResponse(ch <-chan upResult) (*DetectResponse, error) {
	if ch == nil {
		return &DetectResponse{Entities: []Entity{}}, nil
	}

	res := <-ch
	if res.err != nil {
		return nil, res.err
	}
	if res.resp == nil {
		return &DetectResponse{Entities: []Entity{}}, nil
	}
	return res.resp, nil
}

func mergeEntities(base *DetectResponse, secretEntities []Entity) {
	if len(secretEntities) == 0 {
		return
	}

	seen := make(map[entityKey]struct{}, len(base.Entities))
	for _, e := range base.Entities {
		seen[entityKey{Type: e.Type, Start: e.Start, End: e.End}] = struct{}{}
	}

	for _, e := range secretEntities {
		k := entityKey{Type: e.Type, Start: e.Start, End: e.End}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		base.Entities = append(base.Entities, e)
	}
	base.PIIDetected = base.PIIDetected || len(secretEntities) > 0
}

// MultiSecretsAnalyzer runs multiple secrets backends in parallel.
type MultiSecretsAnalyzer struct {
	backends []Analyzer
	log      zerolog.Logger
}

func NewMultiSecretsAnalyzer(log zerolog.Logger, backends ...Analyzer) *MultiSecretsAnalyzer {
	return &MultiSecretsAnalyzer{backends: backends, log: log}
}

// Detect runs all backends and merges unique findings.
func (m *MultiSecretsAnalyzer) Detect(ctx context.Context, text string) (*DetectResponse, error) {
	results := make(chan []Entity, len(m.backends))

	for _, backend := range m.backends {
		backend := backend
		go func() {
			results <- m.detectBackendEntities(ctx, backend, text)
		}()
	}

	merged := mergeEntitySets(results, len(m.backends))
	return &DetectResponse{PIIDetected: len(merged) > 0, Entities: merged}, nil
}

func (m *MultiSecretsAnalyzer) detectBackendEntities(ctx context.Context, backend Analyzer, text string) []Entity {
	defer func() {
		if p := recover(); p != nil {
			m.log.Error().
				Str("panic", fmt.Sprintf("%v", p)).
				Str("stack", string(debug.Stack())).
				Msg("secrets backend panicked in MultiSecretsAnalyzer")
		}
	}()

	resp, err := backend.Detect(ctx, text)
	if err != nil {
		m.log.Warn().Err(err).Msg("secrets backend error in MultiSecretsAnalyzer")
		return nil
	}
	if resp == nil {
		return nil
	}
	return resp.Entities
}

func mergeEntitySets(results <-chan []Entity, expected int) []Entity {
	seen := make(map[entityKey]struct{})
	merged := make([]Entity, 0)

	for i := 0; i < expected; i++ {
		for _, e := range <-results {
			k := entityKey{Type: e.Type, Start: e.Start, End: e.End}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			merged = append(merged, e)
		}
	}

	return merged
}
