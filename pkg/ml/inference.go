// Package ml provides a client for communicating with a sidecar ML inference
// server. The inference server runs Python models (e.g. scikit-learn,
// ONNX Runtime) behind a simple HTTP/JSON API. If the server is unavailable
// the client returns ErrServerUnavailable so callers can fall back to
// rule-based scoring.
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ErrServerUnavailable is returned when the ML inference server cannot be
// reached. Callers should treat this as a non-fatal condition and fall back
// to regex/keyword-only scoring.
var ErrServerUnavailable = errors.New("ml inference server unavailable")

// ModelType enumerates the model types supported by the inference server.
const (
	ModelTypeInjection = "injection"
	ModelTypeToxicity  = "toxicity"
	ModelTypeJailbreak = "jailbreak"
	ModelTypeNER       = "ner"
)

// PredictRequest is the JSON body sent to the /predict endpoint.
type PredictRequest struct {
	Text      string `json:"text"`
	ModelType string `json:"model_type"`
}

// PredictResponse is the JSON body returned by the /predict endpoint.
type PredictResponse struct {
	Label    string             `json:"label"`
	Score    float64            `json:"score"`
	Labels   map[string]float64 `json:"labels,omitempty"`
	Entities []RawEntity        `json:"entities,omitempty"`
}

// RawEntity represents a single named entity returned by the NER model.
type RawEntity struct {
	Type  string  `json:"type"`
	Value string  `json:"value"`
	Start int     `json:"start"`
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

// InferenceClient communicates with the sidecar ML inference server over
// HTTP/JSON.
type InferenceClient struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewInferenceClient creates a new client that talks to the inference server
// at baseURL (e.g. "http://localhost:5000"). timeout controls per-request
// deadlines.
func NewInferenceClient(baseURL string, timeout time.Duration) *InferenceClient {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &InferenceClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		timeout: timeout,
	}
}

// Predict sends a single prediction request and returns the response. If the
// server is unreachable, ErrServerUnavailable is returned.
func (c *InferenceClient) Predict(ctx context.Context, req PredictRequest) (*PredictResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ml: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/predict", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ml: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if isConnectionError(err) {
			return nil, ErrServerUnavailable
		}
		return nil, fmt.Errorf("ml: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ml: server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ml: decode response: %w", err)
	}

	return &result, nil
}

// PredictBatch sends multiple prediction requests in a single HTTP call.
func (c *InferenceClient) PredictBatch(ctx context.Context, reqs []PredictRequest) ([]PredictResponse, error) {
	body, err := json.Marshal(reqs)
	if err != nil {
		return nil, fmt.Errorf("ml: marshal batch request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/predict/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ml: build batch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if isConnectionError(err) {
			return nil, ErrServerUnavailable
		}
		return nil, fmt.Errorf("ml: batch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ml: server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var results []PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("ml: decode batch response: %w", err)
	}

	return results, nil
}

// Health checks whether the inference server is reachable and healthy.
func (c *InferenceClient) Health(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("ml: build health request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		if isConnectionError(err) {
			return ErrServerUnavailable
		}
		return fmt.Errorf("ml: health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ml: health check returned %d", resp.StatusCode)
	}

	return nil
}

// isConnectionError returns true if err is a network-level connectivity
// failure (connection refused, timeout, DNS resolution, etc.). These
// indicate the inference server is down rather than a bug in the request.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	// Connection refused, timeout, DNS failures.
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// Context deadline exceeded or canceled also counts when the
	// underlying cause is the server not responding.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}
