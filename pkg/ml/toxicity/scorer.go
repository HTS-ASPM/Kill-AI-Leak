// Package mltoxicity provides an ML-enhanced toxicity scorer that calls the
// sidecar inference server. It wraps the base InferenceClient with
// toxicity-specific logic including per-category score extraction and
// graceful fallback.
package mltoxicity

import (
	"context"
	"errors"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/ml"
)

// Toxicity categories returned by the ML model. These align with the
// categories recognized by the keyword-based detector plus additional
// ones the ML model can distinguish.
const (
	CategoryHateSpeech = "hate_speech"
	CategoryViolence   = "violence"
	CategorySelfHarm   = "self_harm"
	CategorySexual     = "sexual"
	CategoryProfanity  = "profanity"
	CategoryBias       = "bias"
)

// AllCategories lists every toxicity category the ML scorer can return.
var AllCategories = []string{
	CategoryHateSpeech,
	CategoryViolence,
	CategorySelfHarm,
	CategorySexual,
	CategoryProfanity,
	CategoryBias,
}

// MLToxicityScorer uses the sidecar ML inference server to produce
// per-category toxicity scores. When the server is unavailable it returns
// nil scores so callers can fall back to keyword-only detection.
type MLToxicityScorer struct {
	client *ml.InferenceClient
}

// NewMLToxicityScorer creates a scorer backed by the given InferenceClient.
func NewMLToxicityScorer(client *ml.InferenceClient) *MLToxicityScorer {
	return &MLToxicityScorer{client: client}
}

// Score returns per-category toxicity scores (0-1) for the given text.
// If the ML server is unreachable, it returns (nil, nil) so the caller
// can fall back to keyword scoring.
func (s *MLToxicityScorer) Score(ctx context.Context, text string) (map[string]float64, error) {
	resp, err := s.client.Predict(ctx, ml.PredictRequest{
		Text:      text,
		ModelType: ml.ModelTypeToxicity,
	})
	if err != nil {
		if errors.Is(err, ml.ErrServerUnavailable) {
			// Graceful fallback: ML server is down.
			return nil, nil
		}
		return nil, err
	}

	// Use the Labels map from the response which contains per-category scores.
	scores := make(map[string]float64, len(AllCategories))
	for _, cat := range AllCategories {
		if v, ok := resp.Labels[cat]; ok {
			scores[cat] = clamp01(v)
		} else {
			scores[cat] = 0
		}
	}

	return scores, nil
}

// clamp01 constrains v to the range [0, 1].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
