package detector

import "context"

// PassthroughAnalyzer is a no-op detector for gateway mode (PROMPTSHIELD_ENGINE_URL=none).
type PassthroughAnalyzer struct{}

func NewPassthroughAnalyzer() *PassthroughAnalyzer {
	return &PassthroughAnalyzer{}
}

func (a *PassthroughAnalyzer) Detect(_ context.Context, _ string) (*DetectResponse, error) {
	return &DetectResponse{Entities: []Entity{}}, nil
}
