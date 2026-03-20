// Package events provides an event bus abstraction and a NATS JetStream
// implementation for publishing and subscribing to security events.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Subject constants for the NATS topic hierarchy.
const (
	SubjectPrefix    = "killaileaK.events"
	SubjectGuardrail = SubjectPrefix + ".guardrail"
	SubjectDiscovery = SubjectPrefix + ".discovery"
	SubjectAlert     = SubjectPrefix + ".alert"
	SubjectAll       = SubjectPrefix + ".>"

	StreamName = "KILLAILEAAK_EVENTS"
)

// EventHandler is a callback invoked when an event is received.
type EventHandler func(ctx context.Context, event *models.Event) error

// EventBus is the interface for publishing and subscribing to security events.
type EventBus interface {
	// Publish sends an event to the bus. The subject is derived from the
	// event source and severity automatically.
	Publish(ctx context.Context, subject string, event *models.Event) error

	// Subscribe registers a handler for a subject pattern. The consumer
	// group ensures each event is processed by exactly one instance in the
	// group (queue semantics).
	Subscribe(ctx context.Context, subject string, consumerGroup string, handler EventHandler) error

	// Close shuts down the event bus, draining in-flight messages.
	Close() error
}

// NATSConfig holds configuration for the NATS event bus.
type NATSConfig struct {
	// URL is the NATS server URL (e.g. "nats://localhost:4222").
	URL string

	// Name is the client connection name reported to NATS.
	Name string

	// MaxReconnects controls how many reconnect attempts are made before
	// giving up. Use -1 for unlimited.
	MaxReconnects int

	// ReconnectWait is the duration between reconnect attempts.
	ReconnectWait time.Duration

	// StreamMaxAge is the maximum age of messages retained in the stream.
	// Zero means no age limit.
	StreamMaxAge time.Duration

	// StreamMaxBytes is the maximum total size of the stream. Zero means
	// no size limit.
	StreamMaxBytes int64
}

// DefaultNATSConfig returns a NATSConfig with sensible defaults.
func DefaultNATSConfig() NATSConfig {
	return NATSConfig{
		URL:            nats.DefaultURL,
		Name:           "kill-ai-leak",
		MaxReconnects:  -1,
		ReconnectWait:  2 * time.Second,
		StreamMaxAge:   7 * 24 * time.Hour,
		StreamMaxBytes: 1 << 30, // 1 GiB
	}
}

// NATSEventBus implements EventBus on top of NATS JetStream.
type NATSEventBus struct {
	cfg    NATSConfig
	nc     *nats.Conn
	js     jetstream.JetStream
	stream jetstream.Stream
	logger *slog.Logger

	mu       sync.Mutex
	closed   bool
	consumers []jetstream.ConsumeContext
}

// NewNATSEventBus creates a new NATSEventBus, connects to NATS, and
// ensures the JetStream stream exists.
func NewNATSEventBus(ctx context.Context, cfg NATSConfig, logger *slog.Logger) (*NATSEventBus, error) {
	if logger == nil {
		logger = slog.Default()
	}

	bus := &NATSEventBus{
		cfg:    cfg,
		logger: logger,
	}

	if err := bus.connect(ctx); err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	return bus, nil
}

// connect establishes the NATS connection and initialises JetStream.
func (b *NATSEventBus) connect(ctx context.Context) error {
	opts := []nats.Option{
		nats.Name(b.cfg.Name),
		nats.MaxReconnects(b.cfg.MaxReconnects),
		nats.ReconnectWait(b.cfg.ReconnectWait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			b.logger.Warn("nats disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			b.logger.Info("nats reconnected", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(_ *nats.Conn) {
			b.logger.Info("nats connection closed")
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			b.logger.Error("nats async error", "error", err)
		}),
	}

	nc, err := nats.Connect(b.cfg.URL, opts...)
	if err != nil {
		return fmt.Errorf("nats.Connect: %w", err)
	}
	b.nc = nc

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return fmt.Errorf("jetstream.New: %w", err)
	}
	b.js = js

	if err := b.ensureStream(ctx); err != nil {
		nc.Close()
		return fmt.Errorf("ensureStream: %w", err)
	}

	return nil
}

// ensureStream creates or updates the JetStream stream.
func (b *NATSEventBus) ensureStream(ctx context.Context) error {
	streamCfg := jetstream.StreamConfig{
		Name:        StreamName,
		Description: "Kill-AI-Leak security events",
		Subjects:    []string{SubjectAll},
		Retention:   jetstream.LimitsPolicy,
		Storage:     jetstream.FileStorage,
		Replicas:    1,
		Discard:     jetstream.DiscardOld,
	}

	if b.cfg.StreamMaxAge > 0 {
		streamCfg.MaxAge = b.cfg.StreamMaxAge
	}
	if b.cfg.StreamMaxBytes > 0 {
		streamCfg.MaxBytes = b.cfg.StreamMaxBytes
	}

	stream, err := b.js.CreateOrUpdateStream(ctx, streamCfg)
	if err != nil {
		return fmt.Errorf("create/update stream: %w", err)
	}
	b.stream = stream

	b.logger.Info("jetstream stream ready",
		"name", StreamName,
		"subjects", streamCfg.Subjects,
	)
	return nil
}

// Publish serialises the event to JSON and publishes it to the given subject.
func (b *NATSEventBus) Publish(ctx context.Context, subject string, event *models.Event) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return fmt.Errorf("event bus is closed")
	}
	b.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	_, err = b.js.Publish(ctx, subject, data,
		jetstream.WithMsgID(event.ID),
	)
	if err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}

	b.logger.Debug("event published",
		"subject", subject,
		"event_id", event.ID,
		"source", event.Source,
		"severity", event.Severity,
	)
	return nil
}

// Subscribe creates a durable consumer and dispatches events to the handler.
// The consumerGroup parameter ensures queue-group semantics: each event is
// delivered to exactly one subscriber in the group.
func (b *NATSEventBus) Subscribe(ctx context.Context, subject string, consumerGroup string, handler EventHandler) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return fmt.Errorf("event bus is closed")
	}
	b.mu.Unlock()

	consumer, err := b.js.CreateOrUpdateConsumer(ctx, StreamName, jetstream.ConsumerConfig{
		Durable:       consumerGroup,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subject,
		DeliverPolicy: jetstream.DeliverNewPolicy,
		MaxDeliver:    5,
		AckWait:       30 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create consumer %s: %w", consumerGroup, err)
	}

	consumeCtx, err := consumer.Consume(func(msg jetstream.Msg) {
		var event models.Event
		if err := json.Unmarshal(msg.Data(), &event); err != nil {
			b.logger.Error("unmarshal event failed",
				"consumer", consumerGroup,
				"error", err,
			)
			// Terminate redelivery for malformed messages.
			_ = msg.Term()
			return
		}

		if err := handler(ctx, &event); err != nil {
			b.logger.Error("handler failed",
				"consumer", consumerGroup,
				"event_id", event.ID,
				"error", err,
			)
			// NAK so NATS redelivers with backoff.
			_ = msg.Nak()
			return
		}

		_ = msg.Ack()
	})
	if err != nil {
		return fmt.Errorf("consume %s: %w", consumerGroup, err)
	}

	b.mu.Lock()
	b.consumers = append(b.consumers, consumeCtx)
	b.mu.Unlock()

	b.logger.Info("subscribed",
		"subject", subject,
		"consumer_group", consumerGroup,
	)
	return nil
}

// Close drains all consumers and closes the NATS connection.
func (b *NATSEventBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	for _, c := range b.consumers {
		c.Stop()
	}
	b.consumers = nil

	if b.nc != nil {
		if err := b.nc.Drain(); err != nil {
			b.logger.Warn("nats drain error", "error", err)
		}
		b.nc.Close()
	}

	b.logger.Info("event bus closed")
	return nil
}
