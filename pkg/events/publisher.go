package events

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// PublisherConfig holds configuration for the async event publisher.
type PublisherConfig struct {
	// BufferSize is the capacity of the internal publish channel. Events
	// are dropped when the channel is full (back-pressure).
	BufferSize int

	// Workers is the number of goroutines draining the publish channel.
	Workers int

	// PublishTimeout is the per-event timeout for the underlying bus Publish.
	PublishTimeout time.Duration
}

// DefaultPublisherConfig returns a PublisherConfig with sensible defaults.
func DefaultPublisherConfig() PublisherConfig {
	return PublisherConfig{
		BufferSize:     4096,
		Workers:        4,
		PublishTimeout: 5 * time.Second,
	}
}

// pendingEvent pairs an event with its destination subject.
type pendingEvent struct {
	subject string
	event   *models.Event
}

// Publisher provides convenience methods for asynchronously publishing
// different event types through the EventBus.
type Publisher struct {
	bus    EventBus
	cfg    PublisherConfig
	logger *slog.Logger

	ch     chan pendingEvent
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// NewPublisher creates a Publisher that buffers events in an internal
// channel and publishes them via background workers.
func NewPublisher(bus EventBus, cfg PublisherConfig, logger *slog.Logger) *Publisher {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultPublisherConfig().BufferSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultPublisherConfig().Workers
	}
	if cfg.PublishTimeout <= 0 {
		cfg.PublishTimeout = DefaultPublisherConfig().PublishTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{
		bus:    bus,
		cfg:    cfg,
		logger: logger,
		ch:     make(chan pendingEvent, cfg.BufferSize),
		cancel: cancel,
	}

	p.wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go p.worker(ctx, i)
	}

	return p
}

// worker drains the pending channel until the context is cancelled and
// the channel is empty.
func (p *Publisher) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	for {
		select {
		case pe, ok := <-p.ch:
			if !ok {
				return
			}
			p.publish(pe)
		case <-ctx.Done():
			// Drain remaining items after cancellation.
			for {
				select {
				case pe, ok := <-p.ch:
					if !ok {
						return
					}
					p.publish(pe)
				default:
					return
				}
			}
		}
	}
}

// publish sends a single event to the bus with a timeout.
func (p *Publisher) publish(pe pendingEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.PublishTimeout)
	defer cancel()

	if err := p.bus.Publish(ctx, pe.subject, pe.event); err != nil {
		p.logger.Error("async publish failed",
			"subject", pe.subject,
			"event_id", pe.event.ID,
			"error", err,
		)
	}
}

// enqueue adds an event to the internal buffer. Returns an error if the
// buffer is full (back-pressure signal).
func (p *Publisher) enqueue(subject string, event *models.Event) error {
	select {
	case p.ch <- pendingEvent{subject: subject, event: event}:
		return nil
	default:
		p.logger.Warn("publish buffer full, event dropped",
			"subject", subject,
			"event_id", event.ID,
		)
		return fmt.Errorf("publish buffer full, event dropped: %s", event.ID)
	}
}

// PublishGuardrailEvent publishes an event that resulted from guardrail
// evaluation (e.g. a blocked prompt, anonymised content, etc.).
func (p *Publisher) PublishGuardrailEvent(event *models.Event) error {
	if event.ID == "" {
		event.ID = GenerateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return p.enqueue(SubjectGuardrail, event)
}

// PublishDiscoveryEvent publishes an event about a newly discovered or
// updated AI service.
func (p *Publisher) PublishDiscoveryEvent(event *models.Event) error {
	if event.ID == "" {
		event.ID = GenerateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return p.enqueue(SubjectDiscovery, event)
}

// PublishAlertEvent publishes a high-severity alert event that should
// trigger notifications.
func (p *Publisher) PublishAlertEvent(event *models.Event) error {
	if event.ID == "" {
		event.ID = GenerateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return p.enqueue(SubjectAlert, event)
}

// Close signals all workers to stop, waits for in-flight publishes to
// complete, and closes the channel.
func (p *Publisher) Close() error {
	p.cancel()
	close(p.ch)
	p.wg.Wait()
	return nil
}
