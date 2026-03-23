// Package siem provides SIEM export capabilities for forwarding security
// events to external SIEM platforms. Supported backends include generic
// webhooks, Splunk HEC, Elasticsearch Bulk API, and CEF-formatted syslog.
// All exporters are async with buffered channels and configurable batch
// flushing.
package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// SIEMExporter interface
// ---------------------------------------------------------------------------

// SIEMExporter defines the interface for exporting events to SIEM platforms.
type SIEMExporter interface {
	// Export sends a single event to the SIEM backend.
	Export(event models.Event) error
	// ExportBatch sends a batch of events to the SIEM backend.
	ExportBatch(events []models.Event) error
	// Close flushes remaining events and shuts down the exporter.
	Close() error
}

// SIEMConfig holds configuration for a SIEM exporter.
type SIEMConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Type      string `json:"type" yaml:"type"`           // "webhook", "splunk", "elastic", "syslog"
	Endpoint  string `json:"endpoint" yaml:"endpoint"`   // Target URL or host:port
	Token     string `json:"token" yaml:"token"`         // Auth token (HEC token, API key, etc.)
	Index     string `json:"index" yaml:"index"`         // Target index/sourcetype
	BatchSize int    `json:"batch_size" yaml:"batch_size"`
	FlushSecs int    `json:"flush_interval_secs" yaml:"flush_interval_secs"`
}

// NewSIEMExporterFromConfig creates the appropriate SIEMExporter from config.
// Returns nil if SIEM export is disabled or the type is unrecognized.
func NewSIEMExporterFromConfig(cfg SIEMConfig) SIEMExporter {
	if !cfg.Enabled || cfg.Endpoint == "" {
		return nil
	}

	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	flushInterval := time.Duration(cfg.FlushSecs) * time.Second
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	switch strings.ToLower(cfg.Type) {
	case "webhook":
		return newBufferedExporter(&WebhookExporter{
			endpoint: cfg.Endpoint,
			token:    cfg.Token,
			client:   &http.Client{Timeout: 10 * time.Second},
		}, batchSize, flushInterval)
	case "splunk":
		return newBufferedExporter(&SplunkHEC{
			endpoint: strings.TrimSuffix(cfg.Endpoint, "/") + "/services/collector/event",
			token:    cfg.Token,
			index:    cfg.Index,
			client:   &http.Client{Timeout: 10 * time.Second},
		}, batchSize, flushInterval)
	case "elastic":
		return newBufferedExporter(&ElasticExporter{
			endpoint: strings.TrimSuffix(cfg.Endpoint, "/") + "/_bulk",
			token:    cfg.Token,
			index:    cfg.Index,
			client:   &http.Client{Timeout: 10 * time.Second},
		}, batchSize, flushInterval)
	case "syslog":
		return newBufferedExporter(&SyslogExporter{
			endpoint: cfg.Endpoint,
		}, batchSize, flushInterval)
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// batchSender — internal interface for unbuffered send
// ---------------------------------------------------------------------------

// batchSender is implemented by each concrete exporter to send a batch of
// events without buffering. The bufferedExporter wraps a batchSender to
// provide async buffered delivery.
type batchSender interface {
	sendBatch(events []models.Event) error
}

// ---------------------------------------------------------------------------
// bufferedExporter — async batching wrapper
// ---------------------------------------------------------------------------

type bufferedExporter struct {
	sender   batchSender
	ch       chan models.Event
	done     chan struct{}
	wg       sync.WaitGroup
	batch    int
	interval time.Duration
}

func newBufferedExporter(sender batchSender, batchSize int, flushInterval time.Duration) *bufferedExporter {
	b := &bufferedExporter{
		sender:   sender,
		ch:       make(chan models.Event, batchSize*2),
		done:     make(chan struct{}),
		batch:    batchSize,
		interval: flushInterval,
	}
	b.wg.Add(1)
	go b.loop()
	return b
}

func (b *bufferedExporter) loop() {
	defer b.wg.Done()

	buf := make([]models.Event, 0, b.batch)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		// Best-effort: errors are silently dropped in the async path.
		_ = b.sender.sendBatch(buf)
		buf = buf[:0]
	}

	for {
		select {
		case ev := <-b.ch:
			buf = append(buf, ev)
			if len(buf) >= b.batch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.done:
			// Drain remaining events from the channel.
			for {
				select {
				case ev := <-b.ch:
					buf = append(buf, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (b *bufferedExporter) Export(event models.Event) error {
	select {
	case b.ch <- event:
		return nil
	default:
		return fmt.Errorf("siem: export buffer full, event dropped")
	}
}

func (b *bufferedExporter) ExportBatch(events []models.Event) error {
	for _, ev := range events {
		if err := b.Export(ev); err != nil {
			return err
		}
	}
	return nil
}

func (b *bufferedExporter) Close() error {
	close(b.done)
	b.wg.Wait()
	return nil
}

// ---------------------------------------------------------------------------
// WebhookExporter — generic JSON HTTP POST
// ---------------------------------------------------------------------------

// WebhookExporter sends events as JSON POST requests to any HTTP endpoint.
// Compatible with Splunk HEC, Elastic, and custom SIEM webhook receivers.
type WebhookExporter struct {
	endpoint string
	token    string
	client   *http.Client
}

func (w *WebhookExporter) sendBatch(events []models.Event) error {
	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("siem webhook: marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("siem webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem webhook: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("siem webhook: server returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SplunkHEC — Splunk HTTP Event Collector
// ---------------------------------------------------------------------------

// SplunkHEC formats and sends events to the Splunk HTTP Event Collector.
// Events are wrapped in the HEC JSON envelope with sourcetype, index, and
// host metadata.
type SplunkHEC struct {
	endpoint string
	token    string
	index    string
	client   *http.Client
}

type splunkEvent struct {
	Time       int64       `json:"time"`
	Host       string      `json:"host"`
	Source     string      `json:"source"`
	Sourcetype string      `json:"sourcetype"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event"`
}

func (s *SplunkHEC) sendBatch(events []models.Event) error {
	var buf bytes.Buffer

	for _, ev := range events {
		se := splunkEvent{
			Time:       ev.Timestamp.Unix(),
			Host:       ev.Actor.Name,
			Source:     "kill-ai-leak",
			Sourcetype: "kill_ai_leak:event",
			Index:      s.index,
			Event:      ev,
		}
		data, err := json.Marshal(se)
		if err != nil {
			continue
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequest(http.MethodPost, s.endpoint, &buf)
	if err != nil {
		return fmt.Errorf("siem splunk: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem splunk: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("siem splunk: server returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// ElasticExporter — Elasticsearch Bulk API
// ---------------------------------------------------------------------------

// ElasticExporter formats events for the Elasticsearch Bulk API.
// Each event is written as an action/metadata line followed by the source
// document line, per the Bulk API specification.
type ElasticExporter struct {
	endpoint string
	token    string
	index    string
	client   *http.Client
}

func (e *ElasticExporter) sendBatch(events []models.Event) error {
	var buf bytes.Buffer

	idx := e.index
	if idx == "" {
		idx = "kill-ai-leak-events"
	}

	for _, ev := range events {
		// Action line: index with _index and _id.
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": idx,
				"_id":    ev.ID,
			},
		}
		actionLine, err := json.Marshal(action)
		if err != nil {
			continue
		}
		buf.Write(actionLine)
		buf.WriteByte('\n')

		// Source line: the event document.
		sourceLine, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		buf.Write(sourceLine)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequest(http.MethodPost, e.endpoint, &buf)
	if err != nil {
		return fmt.Errorf("siem elastic: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if e.token != "" {
		req.Header.Set("Authorization", "ApiKey "+e.token)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("siem elastic: post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("siem elastic: server returned %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------------
// SyslogExporter — CEF (Common Event Format) over TCP/UDP
// ---------------------------------------------------------------------------

// SyslogExporter formats events as CEF syslog messages and sends them
// over TCP or UDP to the configured syslog endpoint.
type SyslogExporter struct {
	endpoint string // host:port, optionally prefixed with "tcp://" or "udp://"
}

func (s *SyslogExporter) sendBatch(events []models.Event) error {
	network := "tcp"
	addr := s.endpoint

	if strings.HasPrefix(addr, "udp://") {
		network = "udp"
		addr = strings.TrimPrefix(addr, "udp://")
	} else if strings.HasPrefix(addr, "tcp://") {
		addr = strings.TrimPrefix(addr, "tcp://")
	}

	conn, err := net.DialTimeout(network, addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("siem syslog: dial %s: %w", addr, err)
	}
	defer conn.Close()

	for _, ev := range events {
		msg := formatCEF(ev)
		if _, err := fmt.Fprintf(conn, "%s\n", msg); err != nil {
			return fmt.Errorf("siem syslog: write: %w", err)
		}
	}
	return nil
}

// formatCEF converts an event into a CEF (Common Event Format) syslog
// message string.
func formatCEF(ev models.Event) string {
	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
	//             Signature ID|Name|Severity|Extensions
	severity := cefSeverity(string(ev.Severity))

	name := "AI Security Event"
	sigID := "generic"
	if len(ev.Guardrails) > 0 {
		sigID = ev.Guardrails[0].RuleID
		name = ev.Guardrails[0].RuleName
	}

	extensions := fmt.Sprintf(
		"src=%s dst=%s dpt=%s act=%s msg=%s rt=%d",
		ev.Actor.Name,
		ev.Target.Provider,
		ev.Target.Model,
		string(ev.Action.Type),
		ev.ID,
		ev.Timestamp.UnixMilli(),
	)

	return fmt.Sprintf(
		"CEF:0|KillAILeak|Gateway|0.1.0|%s|%s|%s|%s",
		sigID, name, severity, extensions,
	)
}

// cefSeverity maps internal severity to CEF severity (0-10 scale).
func cefSeverity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "10"
	case "high":
		return "8"
	case "medium":
		return "5"
	case "low":
		return "3"
	default:
		return "1"
	}
}
