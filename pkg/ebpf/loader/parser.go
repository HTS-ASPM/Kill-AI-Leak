package loader

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Raw kernel event structures (wire format from BPF ring buffers)
// ---------------------------------------------------------------------------

// rawTCPEvent is the wire format of struct tcp_event_t from tcp_trace.c.
type rawTCPEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	UID         uint32
	Comm        [16]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Bytes       uint32
	EventType   uint8
	_           [1]byte // padding
	Family      uint16
	SAddr6      [16]byte
	DAddr6      [16]byte
}

// rawSSLEvent is the wire format of struct ssl_event_t from ssl_trace.c.
// The data field is variable-length; we read the header first and then
// extract captured_len bytes of plaintext.
type rawSSLEventHeader struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	UID         uint32
	Comm        [16]byte
	EventType   uint8
	_           [3]byte // padding to align data_len
	DataLen     uint32
	CapturedLen uint32
}

// rawExecEvent is the wire format of struct exec_event_t from exec_trace.c.
type rawExecEvent struct {
	TimestampNS uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	Comm        [16]byte
	Filename    [256]byte
	Argv        [6][128]byte
	Argc        uint8
	EventType   uint8
}

// rawFileEvent is the wire format of struct file_event_t from file_trace.c.
type rawFileEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	UID         uint32
	Comm        [16]byte
	Filename    [256]byte
	Flags       uint32
	DirFD       int32
	FileClass   uint8
	EventType   uint8
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// ParseTCPEvent parses raw bytes from the tcp_events ring buffer into a
// models.Event.
func ParseTCPEvent(raw []byte) (*models.Event, error) {
	if len(raw) < int(binary.Size(rawTCPEvent{})) {
		return nil, fmt.Errorf("tcp event too short: %d bytes", len(raw))
	}

	var re rawTCPEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil, fmt.Errorf("decode tcp event: %w", err)
	}

	comm := cstring(re.Comm[:])
	srcIP := ipv4String(re.SAddr)
	dstIP := ipv4String(re.DAddr)
	if re.Family == 10 { // AF_INET6
		srcIP = net.IP(re.SAddr6[:]).String()
		dstIP = net.IP(re.DAddr6[:]).String()
	}

	direction := models.DirectionOutbound
	if re.EventType == EventTypeTCPRecv {
		direction = models.DirectionInbound
	}

	evt := &models.Event{
		ID:        generateEventID(),
		Timestamp: kernelTSToTime(re.TimestampNS),
		Source:    models.SourceKernelObserver,
		Severity:  models.SeverityInfo,
		Actor: models.Actor{
			Type: models.ActorPod,
			ID:   fmt.Sprintf("pid:%d", re.PID),
			Name: comm,
		},
		Target: models.Target{
			Type:     models.TargetLLMProvider,
			ID:       fmt.Sprintf("%s:%d", dstIP, re.DPort),
			Endpoint: fmt.Sprintf("%s:%d", dstIP, re.DPort),
		},
		Action: models.Action{
			Type:      models.ActionAPICall,
			Direction: direction,
			Protocol:  "tcp",
		},
		Metadata: map[string]string{
			"pid":       fmt.Sprintf("%d", re.PID),
			"tid":       fmt.Sprintf("%d", re.TID),
			"uid":       fmt.Sprintf("%d", re.UID),
			"comm":      comm,
			"src_addr":  fmt.Sprintf("%s:%d", srcIP, re.SPort),
			"dst_addr":  fmt.Sprintf("%s:%d", dstIP, re.DPort),
			"bytes":     fmt.Sprintf("%d", re.Bytes),
			"direction": string(direction),
		},
	}

	// Attempt provider identification from destination IP/port.
	if provider := identifyProviderByAddr(dstIP, re.DPort); provider != "" {
		evt.Target.Provider = provider
	}

	return evt, nil
}

// ParseSSLEvent parses raw bytes from the ssl_events ring buffer into a
// models.Event.  It extracts HTTP headers from the plaintext capture when
// possible.
func ParseSSLEvent(raw []byte) (*models.Event, error) {
	headerSize := binary.Size(rawSSLEventHeader{})
	if len(raw) < headerSize {
		return nil, fmt.Errorf("ssl event too short: %d bytes", len(raw))
	}

	var hdr rawSSLEventHeader
	if err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("decode ssl header: %w", err)
	}

	// Extract captured plaintext.
	capturedLen := int(hdr.CapturedLen)
	if capturedLen > len(raw)-headerSize {
		capturedLen = len(raw) - headerSize
	}
	plaintext := raw[headerSize : headerSize+capturedLen]

	comm := cstring(hdr.Comm[:])

	direction := models.DirectionOutbound
	if hdr.EventType == EventTypeSSLRead {
		direction = models.DirectionInbound
	}

	evt := &models.Event{
		ID:        generateEventID(),
		Timestamp: kernelTSToTime(hdr.TimestampNS),
		Source:    models.SourceKernelObserver,
		Severity:  models.SeverityInfo,
		Actor: models.Actor{
			Type: models.ActorPod,
			ID:   fmt.Sprintf("pid:%d", hdr.PID),
			Name: comm,
		},
		Target: models.Target{
			Type: models.TargetLLMProvider,
			ID:   fmt.Sprintf("ssl:pid:%d", hdr.PID),
		},
		Action: models.Action{
			Type:      models.ActionAPICall,
			Direction: direction,
			Protocol:  "https",
		},
		Metadata: map[string]string{
			"pid":          fmt.Sprintf("%d", hdr.PID),
			"tid":          fmt.Sprintf("%d", hdr.TID),
			"uid":          fmt.Sprintf("%d", hdr.UID),
			"comm":         comm,
			"data_len":     fmt.Sprintf("%d", hdr.DataLen),
			"captured_len": fmt.Sprintf("%d", hdr.CapturedLen),
		},
	}

	// Try to extract HTTP metadata from the plaintext.
	httpMeta := extractHTTPMetadata(plaintext)
	if httpMeta != nil {
		if httpMeta.Host != "" {
			evt.Target.Endpoint = httpMeta.Host + httpMeta.Path
			evt.Target.ID = httpMeta.Host
			evt.Metadata["http_host"] = httpMeta.Host
		}
		if httpMeta.Path != "" {
			evt.Metadata["http_path"] = httpMeta.Path
		}
		if httpMeta.Method != "" {
			evt.Action.Method = httpMeta.Method
			evt.Metadata["http_method"] = httpMeta.Method
		}
		if httpMeta.ContentType != "" {
			evt.Metadata["content_type"] = httpMeta.ContentType
		}
		if httpMeta.Authorization != "" {
			// Store only the type prefix, not the full token.
			parts := strings.SplitN(httpMeta.Authorization, " ", 2)
			evt.Metadata["auth_type"] = parts[0]
		}

		// AI metadata extraction.
		aiMeta := ExtractAIMetadata(httpMeta)
		if aiMeta.Provider != "" {
			evt.Target.Provider = aiMeta.Provider
		}
		if aiMeta.Model != "" {
			evt.Target.Model = aiMeta.Model
			evt.Content.Model = aiMeta.Model
		}
		if aiMeta.Endpoint != "" {
			evt.Target.Endpoint = aiMeta.Endpoint
		}

		// Extract prompt text from request bodies.
		if direction == models.DirectionOutbound && httpMeta.Body != "" {
			if prompt := ExtractPromptFromHTTP(httpMeta.Body, aiMeta.Provider); prompt != "" {
				evt.Content.HasPrompt = true
				evt.Content.PromptText = prompt
			}
		}

		// Bump severity if we detected an AI provider.
		if aiMeta.Provider != "" {
			evt.Severity = models.SeverityLow
		}
	}

	return evt, nil
}

// ParseExecEvent parses raw bytes from the exec_events ring buffer.
func ParseExecEvent(raw []byte) (*models.Event, error) {
	if len(raw) < binary.Size(rawExecEvent{}) {
		return nil, fmt.Errorf("exec event too short: %d bytes", len(raw))
	}

	var re rawExecEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil, fmt.Errorf("decode exec event: %w", err)
	}

	comm := cstring(re.Comm[:])
	filename := cstring(re.Filename[:])

	// Build argv list.
	args := make([]string, 0, int(re.Argc))
	for i := 0; i < int(re.Argc) && i < 6; i++ {
		arg := cstring(re.Argv[i][:])
		if arg != "" {
			args = append(args, arg)
		}
	}

	evt := &models.Event{
		ID:        generateEventID(),
		Timestamp: kernelTSToTime(re.TimestampNS),
		Source:    models.SourceKernelObserver,
		Severity:  models.SeverityInfo,
		Actor: models.Actor{
			Type: models.ActorPod,
			ID:   fmt.Sprintf("pid:%d", re.PID),
			Name: comm,
		},
		Target: models.Target{
			Type: models.TargetAPI,
			ID:   filename,
		},
		Action: models.Action{
			Type:      models.ActionProcessSpawn,
			Direction: models.DirectionOutbound,
		},
		Metadata: map[string]string{
			"pid":      fmt.Sprintf("%d", re.PID),
			"ppid":     fmt.Sprintf("%d", re.PPID),
			"uid":      fmt.Sprintf("%d", re.UID),
			"gid":      fmt.Sprintf("%d", re.GID),
			"comm":     comm,
			"filename": filename,
			"argc":     fmt.Sprintf("%d", re.Argc),
		},
	}

	// Store argv in metadata.
	for i, arg := range args {
		evt.Metadata[fmt.Sprintf("argv%d", i)] = arg
	}

	// Detect AI-related library usage from argv.
	aiLib := detectAILibraryFromArgs(filename, args)
	if aiLib != "" {
		evt.Severity = models.SeverityLow
		evt.Metadata["ai_library"] = aiLib
	}

	return evt, nil
}

// ParseFileEvent parses raw bytes from the file_events ring buffer.
func ParseFileEvent(raw []byte) (*models.Event, error) {
	if len(raw) < binary.Size(rawFileEvent{}) {
		return nil, fmt.Errorf("file event too short: %d bytes", len(raw))
	}

	var re rawFileEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil, fmt.Errorf("decode file event: %w", err)
	}

	comm := cstring(re.Comm[:])
	filename := cstring(re.Filename[:])

	// Determine the file class label.
	var fileClassLabel string
	switch re.FileClass {
	case 1:
		fileClassLabel = "model_file"
	case 2:
		fileClassLabel = "credential_file"
	default:
		fileClassLabel = "unknown"
	}

	targetType := models.TargetFilesystem
	severity := models.SeverityInfo

	if re.FileClass == 1 {
		severity = models.SeverityLow
	} else if re.FileClass == 2 {
		severity = models.SeverityMedium
	}

	// Determine flags string.
	flagStr := openatFlagsString(re.Flags)

	evt := &models.Event{
		ID:        generateEventID(),
		Timestamp: kernelTSToTime(re.TimestampNS),
		Source:    models.SourceKernelObserver,
		Severity:  severity,
		Actor: models.Actor{
			Type: models.ActorPod,
			ID:   fmt.Sprintf("pid:%d", re.PID),
			Name: comm,
		},
		Target: models.Target{
			Type: targetType,
			ID:   filename,
		},
		Action: models.Action{
			Type:      models.ActionFileAccess,
			Direction: models.DirectionOutbound,
		},
		Metadata: map[string]string{
			"pid":        fmt.Sprintf("%d", re.PID),
			"tid":        fmt.Sprintf("%d", re.TID),
			"uid":        fmt.Sprintf("%d", re.UID),
			"comm":       comm,
			"filename":   filename,
			"flags":      flagStr,
			"flags_raw":  fmt.Sprintf("0x%x", re.Flags),
			"file_class": fileClassLabel,
		},
	}

	// Add model format metadata for model files.
	if re.FileClass == 1 {
		ext := fileExtension(filename)
		if ext != "" {
			evt.Metadata["model_format"] = ext
		}
	}

	return evt, nil
}

// ---------------------------------------------------------------------------
// HTTP metadata extraction
// ---------------------------------------------------------------------------

// HTTPMetadata holds parsed HTTP header fields from SSL plaintext.
type HTTPMetadata struct {
	Method        string
	Path          string
	Host          string
	ContentType   string
	Authorization string
	UserAgent     string
	Body          string
}

// extractHTTPMetadata attempts to parse HTTP/1.1 request or response
// headers from the captured TLS plaintext.
func extractHTTPMetadata(plaintext []byte) *HTTPMetadata {
	if len(plaintext) == 0 {
		return nil
	}

	text := string(plaintext)

	// Check if this looks like an HTTP message.
	if !looksLikeHTTP(text) {
		return nil
	}

	meta := &HTTPMetadata{}

	// Split headers from body.
	headerEnd := strings.Index(text, "\r\n\r\n")
	var headerSection, bodySection string
	if headerEnd >= 0 {
		headerSection = text[:headerEnd]
		bodySection = text[headerEnd+4:]
	} else {
		headerSection = text
	}

	lines := strings.Split(headerSection, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse the request line (e.g. "POST /v1/chat/completions HTTP/1.1").
	requestLine := lines[0]
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 2 {
		method := parts[0]
		if isHTTPMethod(method) {
			meta.Method = method
			meta.Path = parts[1]
		}
	}

	// Parse headers.
	for _, line := range lines[1:] {
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		switch strings.ToLower(name) {
		case "host":
			meta.Host = value
		case "content-type":
			meta.ContentType = value
		case "authorization":
			meta.Authorization = value
		case "user-agent":
			meta.UserAgent = value
		case "x-api-key":
			// Anthropic-style API key header.
			if meta.Authorization == "" {
				meta.Authorization = "ApiKey " + value
			}
		}
	}

	meta.Body = bodySection
	return meta
}

// looksLikeHTTP returns true if the text starts with an HTTP method or
// response status.
func looksLikeHTTP(text string) bool {
	prefixes := []string{
		"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ",
		"HTTP/1.0", "HTTP/1.1", "HTTP/2",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(text, p) {
			return true
		}
	}
	return false
}

func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// AI metadata extraction
// ---------------------------------------------------------------------------

// AIMetadata holds provider/model information extracted from HTTP headers.
type AIMetadata struct {
	Provider string
	Model    string
	Endpoint string
}

// providerDomainMap maps host substrings to provider names.
var providerDomainMap = map[string]string{
	"api.openai.com":                         "openai",
	"openai.azure.com":                       "azure_openai",
	"api.anthropic.com":                      "anthropic",
	"generativelanguage.googleapis.com":      "google_gemini",
	"aiplatform.googleapis.com":              "google_vertex",
	"api.cohere.ai":                          "cohere",
	"api.cohere.com":                         "cohere",
	"api-inference.huggingface.co":           "huggingface",
	"api.together.xyz":                       "together_ai",
	"api.together.ai":                        "together_ai",
	"api.fireworks.ai":                       "fireworks_ai",
	"api.groq.com":                           "groq",
	"api.mistral.ai":                         "mistral",
	"api.deepseek.com":                       "deepseek",
	"bedrock-runtime":                        "aws_bedrock",
	"api.replicate.com":                      "replicate",
	"api.perplexity.ai":                      "perplexity",
	"localhost:11434":                         "ollama",
	"127.0.0.1:11434":                        "ollama",
}

// ExtractAIMetadata determines the AI provider, model, and endpoint from
// HTTP headers.
func ExtractAIMetadata(http *HTTPMetadata) AIMetadata {
	if http == nil {
		return AIMetadata{}
	}

	meta := AIMetadata{}

	// Match provider by host.
	host := strings.ToLower(http.Host)
	for domain, provider := range providerDomainMap {
		if strings.Contains(host, domain) {
			meta.Provider = provider
			break
		}
	}

	// Fallback: match by authorization header patterns.
	if meta.Provider == "" {
		auth := http.Authorization
		switch {
		case strings.HasPrefix(auth, "Bearer sk-ant-"):
			meta.Provider = "anthropic"
		case strings.HasPrefix(auth, "Bearer sk-"):
			meta.Provider = "openai"
		case strings.HasPrefix(auth, "Bearer hf_"):
			meta.Provider = "huggingface"
		case strings.HasPrefix(auth, "Bearer gsk_"):
			meta.Provider = "groq"
		}
	}

	// Build endpoint.
	if http.Host != "" && http.Path != "" {
		meta.Endpoint = http.Host + http.Path
	}

	// Extract model from path for known patterns.
	meta.Model = extractModelFromPath(meta.Provider, http.Path)

	// If no model from path, try the request body.
	if meta.Model == "" && http.Body != "" {
		meta.Model = extractModelFromBody(http.Body)
	}

	return meta
}

// extractModelFromPath extracts the model name from the URL path based on
// provider-specific patterns.
func extractModelFromPath(provider, path string) string {
	if path == "" {
		return ""
	}

	switch provider {
	case "google_gemini":
		// /v1/models/{model}:generateContent
		if strings.Contains(path, "/models/") {
			parts := strings.Split(path, "/models/")
			if len(parts) > 1 {
				model := parts[1]
				if idx := strings.IndexByte(model, ':'); idx > 0 {
					model = model[:idx]
				}
				if idx := strings.IndexByte(model, '/'); idx > 0 {
					model = model[:idx]
				}
				return model
			}
		}
	case "aws_bedrock":
		// /model/{model}/invoke
		if strings.Contains(path, "/model/") {
			parts := strings.Split(path, "/model/")
			if len(parts) > 1 {
				model := parts[1]
				if idx := strings.IndexByte(model, '/'); idx > 0 {
					model = model[:idx]
				}
				return model
			}
		}
	case "huggingface":
		// /models/{org}/{model}
		if strings.Contains(path, "/models/") {
			parts := strings.Split(path, "/models/")
			if len(parts) > 1 {
				return parts[1]
			}
		}
	}

	return ""
}

// extractModelFromBody extracts the model name from a JSON request body.
func extractModelFromBody(body string) string {
	// Quick check before attempting JSON parse.
	if !strings.Contains(body, `"model"`) {
		return ""
	}

	// Parse just enough of the JSON to find the model field.
	var payload struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		// Body might be truncated — try a substring search.
		idx := strings.Index(body, `"model"`)
		if idx < 0 {
			return ""
		}
		rest := body[idx:]
		// Find the value: "model":"<value>"
		colonIdx := strings.IndexByte(rest, ':')
		if colonIdx < 0 {
			return ""
		}
		afterColon := strings.TrimSpace(rest[colonIdx+1:])
		if len(afterColon) < 2 || afterColon[0] != '"' {
			return ""
		}
		endQuote := strings.IndexByte(afterColon[1:], '"')
		if endQuote < 0 {
			return ""
		}
		return afterColon[1 : endQuote+1]
	}
	return payload.Model
}

// ExtractPromptFromHTTP parses the request body (JSON) and extracts the
// user's prompt text.  Supports OpenAI, Anthropic, and generic formats.
func ExtractPromptFromHTTP(body string, provider string) string {
	if body == "" {
		return ""
	}

	switch provider {
	case "openai", "azure_openai", "groq", "together_ai", "fireworks_ai",
		"mistral", "deepseek", "ollama":
		return extractOpenAIPrompt(body)
	case "anthropic":
		return extractAnthropicPrompt(body)
	case "google_gemini", "google_vertex":
		return extractGeminiPrompt(body)
	default:
		// Try OpenAI format first (most common), then Anthropic.
		if p := extractOpenAIPrompt(body); p != "" {
			return p
		}
		return extractAnthropicPrompt(body)
	}
}

// extractOpenAIPrompt extracts the last user message from an OpenAI-format
// chat completion request.
func extractOpenAIPrompt(body string) string {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"` // string or array
		} `json:"messages"`
		Prompt string `json:"prompt"` // legacy completions endpoint
	}

	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return ""
	}

	// Chat completions — find the last user message.
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			switch v := req.Messages[i].Content.(type) {
			case string:
				return v
			case []any:
				// Multi-modal content array — extract text parts.
				var texts []string
				for _, item := range v {
					if m, ok := item.(map[string]any); ok {
						if t, ok := m["text"].(string); ok {
							texts = append(texts, t)
						}
					}
				}
				return strings.Join(texts, "\n")
			}
		}
	}

	// Legacy completions endpoint.
	if req.Prompt != "" {
		return req.Prompt
	}

	return ""
}

// extractAnthropicPrompt extracts the last user message from an Anthropic
// messages API request.
func extractAnthropicPrompt(body string) string {
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"` // string or array of content blocks
		} `json:"messages"`
	}

	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return ""
	}

	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			switch v := req.Messages[i].Content.(type) {
			case string:
				return v
			case []any:
				var texts []string
				for _, item := range v {
					if m, ok := item.(map[string]any); ok {
						if m["type"] == "text" {
							if t, ok := m["text"].(string); ok {
								texts = append(texts, t)
							}
						}
					}
				}
				return strings.Join(texts, "\n")
			}
		}
	}

	return ""
}

// extractGeminiPrompt extracts the user prompt from a Gemini generateContent
// request.
func extractGeminiPrompt(body string) string {
	var req struct {
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}

	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return ""
	}

	for i := len(req.Contents) - 1; i >= 0; i-- {
		if req.Contents[i].Role == "user" || req.Contents[i].Role == "" {
			var texts []string
			for _, part := range req.Contents[i].Parts {
				if part.Text != "" {
					texts = append(texts, part.Text)
				}
			}
			if len(texts) > 0 {
				return strings.Join(texts, "\n")
			}
		}
	}

	return ""
}

// ---------------------------------------------------------------------------
// Process / exec event helpers
// ---------------------------------------------------------------------------

// aiLibraryPatterns maps command patterns to AI library names.
var aiLibraryPatterns = map[string]string{
	"openai":       "openai",
	"anthropic":    "anthropic",
	"langchain":    "langchain",
	"llama_index":  "llama_index",
	"llamaindex":   "llama_index",
	"transformers": "transformers",
	"torch":        "pytorch",
	"tensorflow":   "tensorflow",
	"keras":        "keras",
	"ollama":       "ollama",
	"vllm":         "vllm",
	"huggingface":  "huggingface",
	"cohere":       "cohere",
	"replicate":    "replicate",
	"groq":         "groq",
	"mistralai":    "mistral",
	"google.generativeai": "google_genai",
	"vertexai":     "google_vertex",
	"boto3":        "aws_sdk",
	"bedrock":      "aws_bedrock",
	"autogen":      "autogen",
	"crewai":       "crewai",
	"semantic_kernel": "semantic_kernel",
	"guidance":     "guidance",
	"dspy":         "dspy",
	"litellm":      "litellm",
}

// detectAILibraryFromArgs checks if the executed command involves known AI
// libraries or frameworks.
func detectAILibraryFromArgs(filename string, args []string) string {
	// Check the binary name itself.
	binBase := baseName(filename)
	for pattern, lib := range aiLibraryPatterns {
		if strings.Contains(strings.ToLower(binBase), pattern) {
			return lib
		}
	}

	// Check arguments (e.g. "python -m openai", "python -c 'import anthropic'").
	allArgs := strings.Join(args, " ")
	lowerArgs := strings.ToLower(allArgs)
	for pattern, lib := range aiLibraryPatterns {
		if strings.Contains(lowerArgs, pattern) {
			return lib
		}
	}

	// Check for pip/npm install of AI packages.
	if strings.Contains(lowerArgs, "pip install") || strings.Contains(lowerArgs, "pip3 install") ||
		strings.Contains(lowerArgs, "npm install") || strings.Contains(lowerArgs, "npm i ") {
		for pattern, lib := range aiLibraryPatterns {
			if strings.Contains(lowerArgs, pattern) {
				return lib + " (install)"
			}
		}
	}

	return ""
}

// baseName extracts the last path component from a file path.
func baseName(path string) string {
	if path == "" {
		return ""
	}
	i := len(path) - 1
	for i > 0 && path[i] != '/' {
		i--
	}
	if path[i] == '/' {
		i++
	}
	return path[i:]
}

// ---------------------------------------------------------------------------
// Provider identification by IP address
// ---------------------------------------------------------------------------

// knownAIPortMap maps ports to likely provider names.
var knownAIPortMap = map[uint16]string{
	11434: "ollama",
}

// identifyProviderByAddr attempts to identify an AI provider from the
// destination IP address and port.  This is a heuristic; DNS-based
// resolution in the main observer provides more accurate results.
func identifyProviderByAddr(ip string, port uint16) string {
	if provider, ok := knownAIPortMap[port]; ok {
		return provider
	}

	// Port 443 is generic HTTPS — we cannot determine the provider
	// from the IP alone without a reverse DNS lookup or prior mapping.
	// Return empty and let the SSL probe provide the real identification.
	return ""
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

// cstring extracts a null-terminated C string from a byte slice.
func cstring(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		n = len(b)
	}
	return string(b[:n])
}

// ipv4String converts a uint32 in network byte order to a dotted-decimal
// string.
func ipv4String(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF,
		(addr>>8)&0xFF,
		(addr>>16)&0xFF,
		(addr>>24)&0xFF,
	)
}

// kernelTSToTime converts a bpf_ktime_get_ns() timestamp (nanoseconds
// since boot) to a wall-clock time.  This is approximate — the kernel
// monotonic clock drifts from wall time.  A production implementation
// calibrates using /proc/uptime at startup.
func kernelTSToTime(ns uint64) time.Time {
	// Approximation: use current time minus monotonic offset.
	// In production, bootTimeOffset is calibrated once at startup.
	bootTimeOffset := getBootTimeOffset()
	return time.Unix(0, int64(ns)).Add(bootTimeOffset)
}

// bootTimeOnce ensures we only compute the offset once.
var (
	bootTimeOnce      sync.Once
	bootTimeOffsetVal time.Duration
)

func getBootTimeOffset() time.Duration {
	bootTimeOnce.Do(func() {
		// Best-effort: read /proc/stat for btime or use current time.
		// This is a placeholder — real implementation reads boot time
		// from the kernel.
		bootTimeOffsetVal = time.Duration(time.Now().UnixNano())
	})
	return bootTimeOffsetVal
}

// fileExtension returns the file extension (e.g. ".gguf") from a path.
func fileExtension(filename string) string {
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			return filename[i:]
		}
		if filename[i] == '/' {
			break
		}
	}
	return ""
}

// openatFlagsString returns a human-readable representation of openat flags.
func openatFlagsString(flags uint32) string {
	var parts []string

	access := flags & 0x3
	switch access {
	case 0:
		parts = append(parts, "O_RDONLY")
	case 1:
		parts = append(parts, "O_WRONLY")
	case 2:
		parts = append(parts, "O_RDWR")
	}

	if flags&0x40 != 0 {
		parts = append(parts, "O_CREAT")
	}
	if flags&0x200 != 0 {
		parts = append(parts, "O_TRUNC")
	}
	if flags&0x400 != 0 {
		parts = append(parts, "O_APPEND")
	}
	if flags&0x800 != 0 {
		parts = append(parts, "O_NONBLOCK")
	}

	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", flags)
	}
	return strings.Join(parts, "|")
}

// generateEventID creates a unique event ID using the same ULID approach
// as the events package.  We inline a simplified version to avoid a
// circular import.
func generateEventID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("ebpf-%d-%d", now, time.Now().UnixMicro()%100000)
}
