// Package mlinjection provides an ML-enhanced injection scorer that calls
// the sidecar inference server. It wraps the base InferenceClient with
// injection-specific logic and graceful fallback.
package mlinjection

import (
	"context"
	"errors"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/ml"
)

// MLInjectionScorer uses the sidecar ML inference server to score text for
// prompt injection probability. When the server is unavailable, Score
// returns -1 to signal that callers should fall back to regex-only scoring.
type MLInjectionScorer struct {
	client *ml.InferenceClient
}

// NewMLInjectionScorer creates a scorer backed by the given InferenceClient.
func NewMLInjectionScorer(client *ml.InferenceClient) *MLInjectionScorer {
	return &MLInjectionScorer{client: client}
}

// Score returns a probability between 0 and 1 indicating how likely text
// is a prompt injection attack. If the ML server is unreachable, it returns
// -1 (and a nil error) so the caller can fall back to regex scoring.
func (s *MLInjectionScorer) Score(ctx context.Context, text string) (float64, error) {
	resp, err := s.client.Predict(ctx, ml.PredictRequest{
		Text:      text,
		ModelType: ml.ModelTypeInjection,
	})
	if err != nil {
		if errors.Is(err, ml.ErrServerUnavailable) {
			// Graceful fallback: ML server is down.
			return -1, nil
		}
		return -1, err
	}

	// Clamp to [0, 1].
	score := resp.Score
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score, nil
}
