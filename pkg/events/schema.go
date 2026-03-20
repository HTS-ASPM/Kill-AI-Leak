package events

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// validSources is the set of recognised event sources.
var validSources = map[models.EventSource]bool{
	models.SourceKernelObserver: true,
	models.SourceInlineGateway:  true,
	models.SourceBrowser:        true,
	models.SourceIDE:            true,
	models.SourceMCPGateway:     true,
	models.SourceCICD:           true,
}

// validSeverities is the set of recognised severity levels.
var validSeverities = map[models.Severity]bool{
	models.SeverityInfo:     true,
	models.SeverityLow:      true,
	models.SeverityMedium:   true,
	models.SeverityHigh:     true,
	models.SeverityCritical: true,
}

// validActorTypes is the set of recognised actor types.
var validActorTypes = map[models.ActorType]bool{
	models.ActorPod:            true,
	models.ActorUser:           true,
	models.ActorServiceAccount: true,
	models.ActorBrowserUser:    true,
	models.ActorAgent:          true,
}

// validTargetTypes is the set of recognised target types.
var validTargetTypes = map[models.TargetType]bool{
	models.TargetLLMProvider: true,
	models.TargetMCPServer:   true,
	models.TargetDatabase:    true,
	models.TargetFilesystem:  true,
	models.TargetAPI:         true,
}

// validActionTypes is the set of recognised action types.
var validActionTypes = map[models.ActionType]bool{
	models.ActionAPICall:      true,
	models.ActionToolExec:     true,
	models.ActionFileAccess:   true,
	models.ActionProcessSpawn: true,
	models.ActionDBQuery:      true,
}

// validDirections is the set of recognised traffic directions.
var validDirections = map[models.Direction]bool{
	models.DirectionOutbound: true,
	models.DirectionInbound:  true,
}

// ValidationError collects one or more field-level validation failures.
type ValidationError struct {
	Fields []FieldError
}

// FieldError describes a single validation failure.
type FieldError struct {
	Field   string
	Message string
}

func (ve *ValidationError) Error() string {
	msgs := make([]string, len(ve.Fields))
	for i, f := range ve.Fields {
		msgs[i] = fmt.Sprintf("%s: %s", f.Field, f.Message)
	}
	return "validation failed: " + strings.Join(msgs, "; ")
}

// add appends a field error.
func (ve *ValidationError) add(field, msg string) {
	ve.Fields = append(ve.Fields, FieldError{Field: field, Message: msg})
}

// hasErrors returns true if at least one field error has been recorded.
func (ve *ValidationError) hasErrors() bool {
	return len(ve.Fields) > 0
}

// ValidateEvent validates an event against the schema and returns a
// *ValidationError if any fields are invalid. Returns nil on success.
func ValidateEvent(event *models.Event) error {
	ve := &ValidationError{}

	if event.ID == "" {
		ve.add("id", "must not be empty")
	}
	if event.Timestamp.IsZero() {
		ve.add("timestamp", "must not be zero")
	}
	if !validSources[event.Source] {
		ve.add("source", fmt.Sprintf("invalid source %q", event.Source))
	}
	if !validSeverities[event.Severity] {
		ve.add("severity", fmt.Sprintf("invalid severity %q", event.Severity))
	}

	// Actor
	if !validActorTypes[event.Actor.Type] {
		ve.add("actor.type", fmt.Sprintf("invalid actor type %q", event.Actor.Type))
	}
	if event.Actor.ID == "" {
		ve.add("actor.id", "must not be empty")
	}

	// Target
	if !validTargetTypes[event.Target.Type] {
		ve.add("target.type", fmt.Sprintf("invalid target type %q", event.Target.Type))
	}
	if event.Target.ID == "" {
		ve.add("target.id", "must not be empty")
	}

	// Action
	if !validActionTypes[event.Action.Type] {
		ve.add("action.type", fmt.Sprintf("invalid action type %q", event.Action.Type))
	}
	if !validDirections[event.Action.Direction] {
		ve.add("action.direction", fmt.Sprintf("invalid direction %q", event.Action.Direction))
	}

	// Guardrails (optional, but validate if present)
	for i, gr := range event.Guardrails {
		prefix := fmt.Sprintf("guardrails[%d]", i)
		if gr.RuleID == "" {
			ve.add(prefix+".rule_id", "must not be empty")
		}
		if gr.Confidence < 0 || gr.Confidence > 1 {
			ve.add(prefix+".confidence", "must be between 0 and 1")
		}
	}

	if ve.hasErrors() {
		return ve
	}
	return nil
}

// NormalizeEvent fills in default/derived fields on the event in place.
// It generates an ID if missing, sets the timestamp if zero, and trims
// whitespace from string fields.
func NormalizeEvent(event *models.Event) {
	if event.ID == "" {
		event.ID = GenerateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	event.Actor.ID = strings.TrimSpace(event.Actor.ID)
	event.Actor.Name = strings.TrimSpace(event.Actor.Name)
	event.Actor.Namespace = strings.TrimSpace(event.Actor.Namespace)
	event.Target.ID = strings.TrimSpace(event.Target.ID)
	event.Target.Provider = strings.TrimSpace(event.Target.Provider)
	event.Target.Endpoint = strings.TrimSpace(event.Target.Endpoint)
	event.Target.Model = strings.TrimSpace(event.Target.Model)

	if event.Content.PromptText != "" {
		event.Content.PromptText = strings.TrimSpace(event.Content.PromptText)
	}
	if event.Content.ResponseText != "" {
		event.Content.ResponseText = strings.TrimSpace(event.Content.ResponseText)
	}
}

// ---- ULID generation (Crockford Base32, lexicographically sortable) ----

// crockfordBase32 is the encoding alphabet for ULIDs.
const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// GenerateEventID generates a ULID (Universally Unique Lexicographically
// Sortable Identifier) suitable for use as an event ID. The first 48 bits
// encode the Unix millisecond timestamp; the remaining 80 bits are
// cryptographically random.
func GenerateEventID() string {
	now := uint64(time.Now().UnixMilli())

	var entropy [10]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		// Fall back to a timestamp-only ID on entropy failure (extremely
		// unlikely). In practice rand.Read never fails on supported
		// platforms.
		return fmt.Sprintf("%013d", now)
	}

	var ulid [26]byte

	// Encode 48-bit timestamp (10 chars in Crockford Base32).
	ulid[0] = crockfordBase32[(now>>45)&0x1F]
	ulid[1] = crockfordBase32[(now>>40)&0x1F]
	ulid[2] = crockfordBase32[(now>>35)&0x1F]
	ulid[3] = crockfordBase32[(now>>30)&0x1F]
	ulid[4] = crockfordBase32[(now>>25)&0x1F]
	ulid[5] = crockfordBase32[(now>>20)&0x1F]
	ulid[6] = crockfordBase32[(now>>15)&0x1F]
	ulid[7] = crockfordBase32[(now>>10)&0x1F]
	ulid[8] = crockfordBase32[(now>>5)&0x1F]
	ulid[9] = crockfordBase32[now&0x1F]

	// Encode 80-bit random part (16 chars in Crockford Base32).
	// Pack entropy bytes into two uint64 values for bit-shifting.
	hi := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, entropy[0:5]...))
	lo := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, entropy[5:10]...))

	ulid[10] = crockfordBase32[(hi>>35)&0x1F]
	ulid[11] = crockfordBase32[(hi>>30)&0x1F]
	ulid[12] = crockfordBase32[(hi>>25)&0x1F]
	ulid[13] = crockfordBase32[(hi>>20)&0x1F]
	ulid[14] = crockfordBase32[(hi>>15)&0x1F]
	ulid[15] = crockfordBase32[(hi>>10)&0x1F]
	ulid[16] = crockfordBase32[(hi>>5)&0x1F]
	ulid[17] = crockfordBase32[hi&0x1F]

	ulid[18] = crockfordBase32[(lo>>35)&0x1F]
	ulid[19] = crockfordBase32[(lo>>30)&0x1F]
	ulid[20] = crockfordBase32[(lo>>25)&0x1F]
	ulid[21] = crockfordBase32[(lo>>20)&0x1F]
	ulid[22] = crockfordBase32[(lo>>15)&0x1F]
	ulid[23] = crockfordBase32[(lo>>10)&0x1F]
	ulid[24] = crockfordBase32[(lo>>5)&0x1F]
	ulid[25] = crockfordBase32[lo&0x1F]

	return string(ulid[:])
}
