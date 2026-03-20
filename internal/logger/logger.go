package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Level represents a log severity level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the human-readable level name.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLevel converts a string to a Level. Defaults to LevelInfo for
// unrecognised strings.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error", "err":
		return LevelError
	default:
		return LevelInfo
	}
}

// ctxKey is an unexported type used as context key to avoid collisions.
type ctxKey struct{}

var (
	requestIDKey = ctxKey{}
	traceIDKey   = struct{ ctxKey }{}
	fieldsKey    = struct{ k ctxKey }{}
)

// WithRequestID attaches a request ID to the context.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// WithTraceID attaches a trace ID to the context.
func WithTraceID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, traceIDKey, id)
}

// TraceIDFromContext extracts the trace ID from context.
func TraceIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey).(string); ok {
		return v
	}
	return ""
}

// WithFields attaches extra structured fields to the context. These fields
// are merged into every log entry emitted with that context.
func WithFields(ctx context.Context, fields map[string]any) context.Context {
	existing := FieldsFromContext(ctx)
	merged := make(map[string]any, len(existing)+len(fields))
	for k, v := range existing {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return context.WithValue(ctx, fieldsKey, merged)
}

// FieldsFromContext returns the fields stored on the context, or nil.
func FieldsFromContext(ctx context.Context) map[string]any {
	if v, ok := ctx.Value(fieldsKey).(map[string]any); ok {
		return v
	}
	return nil
}

// entry is a single structured log record.
type entry struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	Caller    string         `json:"caller,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Logger is a structured JSON logger.
type Logger struct {
	mu     sync.Mutex
	out    io.Writer
	level  Level
	fields map[string]any
}

// New creates a new Logger with the given level and output.
func New(level Level, out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{
		out:   out,
		level: level,
	}
}

// WithField returns a child logger that always includes the given field.
func (l *Logger) WithField(key string, value any) *Logger {
	child := &Logger{
		out:    l.out,
		level:  l.level,
		fields: make(map[string]any, len(l.fields)+1),
	}
	for k, v := range l.fields {
		child.fields[k] = v
	}
	child.fields[key] = value
	return child
}

// Debug logs at debug level.
func (l *Logger) Debug(ctx context.Context, msg string, fields ...map[string]any) {
	l.log(ctx, LevelDebug, msg, fields...)
}

// Info logs at info level.
func (l *Logger) Info(ctx context.Context, msg string, fields ...map[string]any) {
	l.log(ctx, LevelInfo, msg, fields...)
}

// Warn logs at warn level.
func (l *Logger) Warn(ctx context.Context, msg string, fields ...map[string]any) {
	l.log(ctx, LevelWarn, msg, fields...)
}

// Error logs at error level.
func (l *Logger) Error(ctx context.Context, msg string, fields ...map[string]any) {
	l.log(ctx, LevelError, msg, fields...)
}

func (l *Logger) log(ctx context.Context, lvl Level, msg string, extra ...map[string]any) {
	if lvl < l.level {
		return
	}

	e := entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     lvl.String(),
		Message:   msg,
		RequestID: RequestIDFromContext(ctx),
		TraceID:   TraceIDFromContext(ctx),
	}

	// Caller info (skip 2 frames: log -> Debug/Info/Warn/Error).
	if _, file, line, ok := runtime.Caller(2); ok {
		// Trim to last two path components for readability.
		parts := strings.Split(file, "/")
		if len(parts) > 2 {
			file = strings.Join(parts[len(parts)-2:], "/")
		}
		e.Caller = fmt.Sprintf("%s:%d", file, line)
	}

	// Merge fields: logger-level -> context-level -> call-site.
	merged := make(map[string]any, len(l.fields)+8)
	for k, v := range l.fields {
		merged[k] = v
	}
	if ctxFields := FieldsFromContext(ctx); ctxFields != nil {
		for k, v := range ctxFields {
			merged[k] = v
		}
	}
	for _, m := range extra {
		for k, v := range m {
			merged[k] = v
		}
	}
	if len(merged) > 0 {
		e.Fields = merged
	}

	data, err := json.Marshal(e)
	if err != nil {
		// Fallback: write the message directly so we never silently drop logs.
		data = []byte(fmt.Sprintf(`{"level":"%s","message":"%s","error":"marshal_failed"}`, lvl.String(), msg))
	}
	data = append(data, '\n')

	l.mu.Lock()
	_, _ = l.out.Write(data)
	l.mu.Unlock()
}
