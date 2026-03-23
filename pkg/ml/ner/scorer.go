// Package mlner provides an ML-enhanced Named Entity Recognition scorer
// that calls the sidecar inference server to detect PII that regex-based
// patterns cannot reliably catch (person names, organizations, locations).
package mlner

import (
	"context"
	"errors"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/ml"
)

// Entity type constants returned by the NER model, mapped to human-readable
// labels used in PII findings.
const (
	TypePersonName   = "person_name"
	TypeOrganization = "organization"
	TypeLocation     = "location"
	TypeMisc         = "misc"
)

// nerTypeMap maps the raw NER entity types (PER, ORG, LOC, MISC) from the
// BERT-NER model to the labels used by the PII detection pipeline.
var nerTypeMap = map[string]string{
	"PER":  TypePersonName,
	"ORG":  TypeOrganization,
	"LOC":  TypeLocation,
	"MISC": TypeMisc,
}

// Entity represents a single named entity detected by the NER model.
type Entity struct {
	// Type is the mapped entity type (person_name, organization, location, misc).
	Type string
	// Value is the entity text as it appears in the input.
	Value string
	// Start is the byte offset of the entity start in the original text.
	Start int
	// End is the byte offset of the entity end in the original text.
	End int
	// Score is the model's confidence for this entity (0-1).
	Score float64
}

// NERResult holds the aggregate result of NER inference on a text input.
type NERResult struct {
	// Entities contains all detected named entities.
	Entities []Entity
	// HasPII is true if any person names or organizations were detected.
	HasPII bool
	// MaxScore is the highest confidence score across all entities.
	MaxScore float64
}

// MLNERScorer uses the sidecar ML inference server to detect named entities
// in text. When the server is unavailable, Score returns nil (and a nil
// error) so callers can continue with regex-only PII detection.
type MLNERScorer struct {
	client *ml.InferenceClient
}

// NewMLNERScorer creates a scorer backed by the given InferenceClient.
func NewMLNERScorer(client *ml.InferenceClient) *MLNERScorer {
	return &MLNERScorer{client: client}
}

// Score sends the text to the NER model and returns detected entities.
// If the ML server is unreachable it returns (nil, nil) for graceful
// fallback to regex-only PII detection.
func (s *MLNERScorer) Score(ctx context.Context, text string) (*NERResult, error) {
	resp, err := s.client.Predict(ctx, ml.PredictRequest{
		Text:      text,
		ModelType: ml.ModelTypeNER,
	})
	if err != nil {
		if errors.Is(err, ml.ErrServerUnavailable) {
			return nil, nil
		}
		return nil, err
	}

	result := &NERResult{}

	for _, raw := range resp.Entities {
		mappedType, ok := nerTypeMap[raw.Type]
		if !ok {
			mappedType = TypeMisc
		}

		score := clamp01(raw.Score)

		result.Entities = append(result.Entities, Entity{
			Type:  mappedType,
			Value: raw.Value,
			Start: raw.Start,
			End:   raw.End,
			Score: score,
		})

		if score > result.MaxScore {
			result.MaxScore = score
		}

		if mappedType == TypePersonName || mappedType == TypeOrganization {
			result.HasPII = true
		}
	}

	return result, nil
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
