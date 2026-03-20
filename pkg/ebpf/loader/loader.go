// Package loader provides the userspace component for loading, attaching,
// and reading events from the Kill-AI-Leak eBPF programs.  It abstracts
// the underlying eBPF library (cilium/ebpf) behind interfaces so the
// package compiles and tests run without the CGo dependency or a Linux
// kernel.
package loader

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// eBPF abstraction interfaces
// ---------------------------------------------------------------------------

// BPFProgram represents a loaded eBPF program.
type BPFProgram interface {
	// FD returns the file descriptor of the loaded program.
	FD() int
	// Close unloads the program.
	Close() error
}

// BPFMap represents an eBPF map (ring buffer, hash, array, etc.).
type BPFMap interface {
	// FD returns the file descriptor of the map.
	FD() int
	// Close releases the map.
	Close() error
	// Update sets a key-value pair.  flags corresponds to BPF_ANY / BPF_NOEXIST.
	Update(key, value []byte, flags uint64) error
	// Lookup reads the value for a key.
	Lookup(key []byte) ([]byte, error)
}

// BPFLink represents an attached probe (kprobe, uprobe, tracepoint, etc.).
type BPFLink interface {
	// Close detaches the probe.
	Close() error
}

// RingBuffer reads events from a BPF ring buffer map.
type RingBuffer interface {
	// Read blocks until an event is available or the context is cancelled.
	// Returns the raw event bytes.
	Read(ctx context.Context) ([]byte, error)
	// Close releases the reader.
	Close() error
}

// BPFLoader is the interface for loading compiled eBPF object files and
// attaching programs to kernel hooks.  A real implementation wraps
// cilium/ebpf; the placeholder implementation in this package enables
// compilation and testing without the dependency.
type BPFLoader interface {
	// LoadObject loads a compiled eBPF .o file and returns handles to its
	// programs and maps.
	LoadObject(path string) (ObjectHandle, error)

	// AttachTracepoint attaches a program to a kernel tracepoint.
	AttachTracepoint(prog BPFProgram, group, name string) (BPFLink, error)

	// AttachKprobe attaches a program to a kprobe.
	AttachKprobe(prog BPFProgram, symbol string) (BPFLink, error)

	// AttachKretprobe attaches a program to a kretprobe.
	AttachKretprobe(prog BPFProgram, symbol string) (BPFLink, error)

	// AttachUprobe attaches a program to a uprobe on the given binary/symbol.
	AttachUprobe(prog BPFProgram, binaryPath, symbol string, pid int) (BPFLink, error)

	// AttachUretprobe attaches a program to a uretprobe.
	AttachUretprobe(prog BPFProgram, binaryPath, symbol string, pid int) (BPFLink, error)

	// NewRingBuffer creates a reader for a ring buffer map.
	NewRingBuffer(m BPFMap) (RingBuffer, error)
}

// ObjectHandle provides access to the programs and maps within a loaded
// eBPF object file.
type ObjectHandle interface {
	// Program returns the program with the given section/function name.
	Program(name string) (BPFProgram, error)
	// Map returns the map with the given name.
	Map(name string) (BPFMap, error)
	// Close releases all resources.
	Close() error
}

// ---------------------------------------------------------------------------
// Event type constants — must match the BPF C headers.
// ---------------------------------------------------------------------------

const (
	EventTypeTCPSend  uint8 = 1
	EventTypeTCPRecv  uint8 = 2
	EventTypeSSLWrite uint8 = 3
	EventTypeSSLRead  uint8 = 4
	EventTypeExec     uint8 = 5
	EventTypeExit     uint8 = 6
	EventTypeFileOpen uint8 = 7
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// ObserverConfig holds configuration for the eBPF observer.
type ObserverConfig struct {
	// ProbesDir is the directory containing compiled BPF object files
	// (tcp_trace.o, ssl_trace.o, exec_trace.o, file_trace.o).
	ProbesDir string

	// SSLLibPaths are filesystem paths to libssl.so variants to uprobe.
	// If empty, the loader attempts auto-discovery.
	SSLLibPaths []string

	// TargetPID restricts SSL uprobes to a specific process.  Zero means
	// system-wide.
	TargetPID int

	// MaxCaptureBytes controls the SSL plaintext capture size (default 4096).
	MaxCaptureBytes uint32

	// FilterMode controls kernel-side filtering.
	// 0 = capture all, 1 = AI-related only.
	FilterMode uint64

	// RingBufferSize overrides the ring buffer size for each probe.
	// Zero uses the compiled-in default.
	RingBufferSize uint32

	// AIBinaries is the set of binary names considered AI-related for
	// the exec probe filter.
	AIBinaries []string
}

// DefaultObserverConfig returns an ObserverConfig with production defaults.
func DefaultObserverConfig() ObserverConfig {
	return ObserverConfig{
		ProbesDir:       "/etc/kill-ai-leak/probes",
		MaxCaptureBytes: 4096,
		FilterMode:      1, // AI-related only
		AIBinaries: []string{
			"python", "python3", "python3.11", "python3.12", "python3.13",
			"node", "npm", "npx", "bun", "deno",
			"java", "javac",
			"go", "ollama", "llama-server", "llama-cli",
			"llamafile", "whisper", "stable-diffusion",
			"vllm", "tritonserver", "tgi",
			"ruby", "perl", "php", "dotnet",
			"kubectl", "helm", "docker", "podman",
			"curl", "wget", "httpie",
		},
		SSLLibPaths: []string{
			"/usr/lib/x86_64-linux-gnu/libssl.so.3",
			"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
			"/usr/lib/aarch64-linux-gnu/libssl.so.3",
			"/usr/lib/libssl.so",
			"/lib64/libssl.so.3",
		},
	}
}

// ---------------------------------------------------------------------------
// ObserverLoader
// ---------------------------------------------------------------------------

// probeSet groups the handles for a single BPF object file.
type probeSet struct {
	object  ObjectHandle
	links   []BPFLink
	readers []RingBuffer
}

// ObserverLoader manages the lifecycle of all eBPF probes.  It loads the
// compiled BPF object files, attaches them to kernel hooks, reads events
// from ring buffers, and converts raw bytes into models.Event values.
type ObserverLoader struct {
	cfg    ObserverConfig
	bpf    BPFLoader
	logger *slog.Logger

	mu     sync.Mutex
	probes []probeSet
	closed bool

	// Metrics counters.
	eventsTotal atomic.Uint64
	errorsTotal atomic.Uint64

	// Event output channel.
	eventCh chan *models.Event
}

// NewObserverLoader creates a new loader.  Call LoadAndAttach to start
// the probes.
func NewObserverLoader(cfg ObserverConfig, bpfLoader BPFLoader, logger *slog.Logger) *ObserverLoader {
	if logger == nil {
		logger = slog.Default()
	}
	return &ObserverLoader{
		cfg:     cfg,
		bpf:     bpfLoader,
		logger:  logger,
		eventCh: make(chan *models.Event, 4096),
	}
}

// LoadAndAttach loads all BPF programs, populates filter maps, and attaches
// probes.  It returns an error if any critical probe fails to load; non-
// critical failures (e.g. SSL uprobes when libssl is not found) are logged
// as warnings.
func (o *ObserverLoader) LoadAndAttach(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return errors.New("observer loader is closed")
	}

	var errs []error

	// 1. TCP trace.
	if err := o.loadTCPTrace(ctx); err != nil {
		errs = append(errs, fmt.Errorf("tcp_trace: %w", err))
	}

	// 2. SSL trace.
	if err := o.loadSSLTrace(ctx); err != nil {
		// Non-fatal — SSL uprobes may not be available.
		o.logger.Warn("ssl_trace load failed (non-fatal)", "error", err)
	}

	// 3. Exec trace.
	if err := o.loadExecTrace(ctx); err != nil {
		errs = append(errs, fmt.Errorf("exec_trace: %w", err))
	}

	// 4. File trace.
	if err := o.loadFileTrace(ctx); err != nil {
		errs = append(errs, fmt.Errorf("file_trace: %w", err))
	}

	if len(errs) > 0 {
		// Return a combined error but keep successfully loaded probes running.
		return fmt.Errorf("partial load failures: %v", errs)
	}

	o.logger.Info("all eBPF probes loaded and attached",
		"probes_dir", o.cfg.ProbesDir,
		"probe_count", len(o.probes),
	)
	return nil
}

// loadTCPTrace loads and attaches the TCP tracing BPF program.
func (o *ObserverLoader) loadTCPTrace(ctx context.Context) error {
	objPath := filepath.Join(o.cfg.ProbesDir, "tcp_trace.o")
	obj, err := o.bpf.LoadObject(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}

	ps := probeSet{object: obj}

	// Set configuration: enabled = 1.
	if cfgMap, err := obj.Map("tcp_config"); err == nil {
		key := make([]byte, 4)
		val := make([]byte, 8)
		binary.LittleEndian.PutUint32(key, 0)
		binary.LittleEndian.PutUint64(val, 1) // enabled
		_ = cfgMap.Update(key, val, 0)
	}

	// Attach kprobes.
	if prog, err := obj.Program("kprobe_tcp_sendmsg"); err == nil {
		if link, err := o.bpf.AttachKprobe(prog, "tcp_sendmsg"); err == nil {
			ps.links = append(ps.links, link)
		} else {
			o.logger.Warn("attach kprobe/tcp_sendmsg failed, trying tracepoint", "error", err)
			// Fallback to tp_btf.
			if tpProg, err := obj.Program("tp_tcp_sendmsg"); err == nil {
				if link, err := o.bpf.AttachTracepoint(tpProg, "tcp", "tcp_sendmsg"); err == nil {
					ps.links = append(ps.links, link)
				}
			}
		}
	}

	// Attach fexit for tcp_recvmsg.
	if prog, err := obj.Program("fexit_tcp_recvmsg"); err == nil {
		if link, err := o.bpf.AttachKretprobe(prog, "tcp_recvmsg"); err == nil {
			ps.links = append(ps.links, link)
		}
	}

	// Set up ring buffer reader.
	if rbMap, err := obj.Map("tcp_events"); err == nil {
		if reader, err := o.bpf.NewRingBuffer(rbMap); err == nil {
			ps.readers = append(ps.readers, reader)
			go o.readLoop(ctx, reader, "tcp")
		}
	}

	o.probes = append(o.probes, ps)
	o.logger.Info("tcp_trace loaded", "links", len(ps.links))
	return nil
}

// loadSSLTrace loads and attaches the SSL/TLS uprobes.
func (o *ObserverLoader) loadSSLTrace(ctx context.Context) error {
	objPath := filepath.Join(o.cfg.ProbesDir, "ssl_trace.o")
	obj, err := o.bpf.LoadObject(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}

	ps := probeSet{object: obj}

	// Configure: enabled = 1, max capture bytes.
	if cfgMap, err := obj.Map("ssl_config"); err == nil {
		key := make([]byte, 4)
		val := make([]byte, 8)

		// Key 0: enabled.
		binary.LittleEndian.PutUint32(key, 0)
		binary.LittleEndian.PutUint64(val, 1)
		_ = cfgMap.Update(key, val, 0)

		// Key 1: max capture bytes.
		binary.LittleEndian.PutUint32(key, 1)
		binary.LittleEndian.PutUint64(val, uint64(o.cfg.MaxCaptureBytes))
		_ = cfgMap.Update(key, val, 0)
	}

	// Discover libssl paths.
	sslPaths := o.discoverSSLLibs()

	for _, libPath := range sslPaths {
		// SSL_write.
		if prog, err := obj.Program("uprobe_ssl_write"); err == nil {
			if link, err := o.bpf.AttachUprobe(prog, libPath, "SSL_write", o.cfg.TargetPID); err == nil {
				ps.links = append(ps.links, link)
			} else {
				o.logger.Debug("attach uprobe/SSL_write failed", "lib", libPath, "error", err)
			}
		}
		if prog, err := obj.Program("uretprobe_ssl_write"); err == nil {
			if link, err := o.bpf.AttachUretprobe(prog, libPath, "SSL_write", o.cfg.TargetPID); err == nil {
				ps.links = append(ps.links, link)
			}
		}
		// SSL_read.
		if prog, err := obj.Program("uprobe_ssl_read"); err == nil {
			if link, err := o.bpf.AttachUprobe(prog, libPath, "SSL_read", o.cfg.TargetPID); err == nil {
				ps.links = append(ps.links, link)
			}
		}
		if prog, err := obj.Program("uretprobe_ssl_read"); err == nil {
			if link, err := o.bpf.AttachUretprobe(prog, libPath, "SSL_read", o.cfg.TargetPID); err == nil {
				ps.links = append(ps.links, link)
			}
		}
	}

	if len(ps.links) == 0 {
		obj.Close()
		return fmt.Errorf("no SSL uprobes attached (checked %d lib paths)", len(sslPaths))
	}

	// Ring buffer reader.
	if rbMap, err := obj.Map("ssl_events"); err == nil {
		if reader, err := o.bpf.NewRingBuffer(rbMap); err == nil {
			ps.readers = append(ps.readers, reader)
			go o.readLoop(ctx, reader, "ssl")
		}
	}

	o.probes = append(o.probes, ps)
	o.logger.Info("ssl_trace loaded", "links", len(ps.links), "libs", len(sslPaths))
	return nil
}

// loadExecTrace loads the process execution tracing program.
func (o *ObserverLoader) loadExecTrace(ctx context.Context) error {
	objPath := filepath.Join(o.cfg.ProbesDir, "exec_trace.o")
	obj, err := o.bpf.LoadObject(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}

	ps := probeSet{object: obj}

	// Configure: enabled = 1, filter mode.
	if cfgMap, err := obj.Map("exec_config"); err == nil {
		key := make([]byte, 4)
		val := make([]byte, 8)

		binary.LittleEndian.PutUint32(key, 0)
		binary.LittleEndian.PutUint64(val, 1) // enabled
		_ = cfgMap.Update(key, val, 0)

		binary.LittleEndian.PutUint32(key, 1)
		binary.LittleEndian.PutUint64(val, o.cfg.FilterMode)
		_ = cfgMap.Update(key, val, 0)
	}

	// Populate the AI binary filter map.
	if filterMap, err := obj.Map("ai_binary_filter"); err == nil {
		for _, bin := range o.cfg.AIBinaries {
			key := make([]byte, 16) // TASK_COMM_LEN
			copy(key, []byte(bin))
			val := []byte{1}
			_ = filterMap.Update(key, val, 0)
		}
	}

	// Attach tracepoint.
	if prog, err := obj.Program("tracepoint_sys_enter_execve"); err == nil {
		if link, err := o.bpf.AttachTracepoint(prog, "syscalls", "sys_enter_execve"); err == nil {
			ps.links = append(ps.links, link)
		}
	}

	// Ring buffer.
	if rbMap, err := obj.Map("exec_events"); err == nil {
		if reader, err := o.bpf.NewRingBuffer(rbMap); err == nil {
			ps.readers = append(ps.readers, reader)
			go o.readLoop(ctx, reader, "exec")
		}
	}

	o.probes = append(o.probes, ps)
	o.logger.Info("exec_trace loaded", "links", len(ps.links),
		"ai_binaries", len(o.cfg.AIBinaries))
	return nil
}

// loadFileTrace loads the file access tracing program.
func (o *ObserverLoader) loadFileTrace(ctx context.Context) error {
	objPath := filepath.Join(o.cfg.ProbesDir, "file_trace.o")
	obj, err := o.bpf.LoadObject(objPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", objPath, err)
	}

	ps := probeSet{object: obj}

	// Configure.
	if cfgMap, err := obj.Map("file_config"); err == nil {
		key := make([]byte, 4)
		val := make([]byte, 8)

		binary.LittleEndian.PutUint32(key, 0)
		binary.LittleEndian.PutUint64(val, 1) // enabled
		_ = cfgMap.Update(key, val, 0)

		binary.LittleEndian.PutUint32(key, 1)
		binary.LittleEndian.PutUint64(val, o.cfg.FilterMode)
		_ = cfgMap.Update(key, val, 0)
	}

	// Populate suffix filter map.
	if suffixMap, err := obj.Map("suffix_filter"); err == nil {
		modelSuffixes := []string{
			".gguf", ".safetensors", ".pt", ".pth", ".onnx",
			".bin", ".h5", ".tflite", ".mlmodel", ".pb",
			".ckpt", ".mar", ".engine", ".plan",
		}
		for _, s := range modelSuffixes {
			key := make([]byte, 16) // SUFFIX_KEY_LEN
			copy(key, []byte(s))
			val := []byte{1} // class 1 = model file
			_ = suffixMap.Update(key, val, 0)
		}

		credSuffixes := []string{
			".env", ".pem", ".key", ".crt", ".p12",
			".jks", ".keystore",
		}
		for _, s := range credSuffixes {
			key := make([]byte, 16)
			copy(key, []byte(s))
			val := []byte{2} // class 2 = credential file
			_ = suffixMap.Update(key, val, 0)
		}
	}

	// Attach tracepoint.
	if prog, err := obj.Program("tracepoint_sys_enter_openat"); err == nil {
		if link, err := o.bpf.AttachTracepoint(prog, "syscalls", "sys_enter_openat"); err == nil {
			ps.links = append(ps.links, link)
		}
	}

	// Ring buffer.
	if rbMap, err := obj.Map("file_events"); err == nil {
		if reader, err := o.bpf.NewRingBuffer(rbMap); err == nil {
			ps.readers = append(ps.readers, reader)
			go o.readLoop(ctx, reader, "file")
		}
	}

	o.probes = append(o.probes, ps)
	o.logger.Info("file_trace loaded", "links", len(ps.links))
	return nil
}

// readLoop continuously reads raw events from a ring buffer, parses them,
// and sends the resulting models.Event values to the event channel.
func (o *ObserverLoader) readLoop(ctx context.Context, rb RingBuffer, probeType string) {
	o.logger.Info("ring buffer read loop started", "probe", probeType)

	for {
		select {
		case <-ctx.Done():
			o.logger.Info("ring buffer read loop stopping", "probe", probeType)
			return
		default:
		}

		raw, err := rb.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled — clean shutdown
			}
			o.errorsTotal.Add(1)
			o.logger.Error("ring buffer read error",
				"probe", probeType,
				"error", err,
			)
			continue
		}

		if len(raw) == 0 {
			continue
		}

		evt, err := o.parseRawEvent(probeType, raw)
		if err != nil {
			o.errorsTotal.Add(1)
			o.logger.Debug("parse raw event failed",
				"probe", probeType,
				"error", err,
				"raw_len", len(raw),
			)
			continue
		}

		o.eventsTotal.Add(1)

		select {
		case o.eventCh <- evt:
		default:
			// Channel full — drop the event.  A production system would
			// use a lossy ring or emit a metric.
			o.logger.Warn("event channel full, dropping event",
				"probe", probeType,
				"event_id", evt.ID,
			)
		}
	}
}

// parseRawEvent dispatches to the appropriate parser based on probe type.
func (o *ObserverLoader) parseRawEvent(probeType string, raw []byte) (*models.Event, error) {
	switch probeType {
	case "tcp":
		return ParseTCPEvent(raw)
	case "ssl":
		return ParseSSLEvent(raw)
	case "exec":
		return ParseExecEvent(raw)
	case "file":
		return ParseFileEvent(raw)
	default:
		return nil, fmt.Errorf("unknown probe type: %s", probeType)
	}
}

// ReadEvents returns a read-only channel of parsed events.
func (o *ObserverLoader) ReadEvents() <-chan *models.Event {
	return o.eventCh
}

// Metrics returns current metric counters.
func (o *ObserverLoader) Metrics() (eventsTotal, errorsTotal uint64) {
	return o.eventsTotal.Load(), o.errorsTotal.Load()
}

// ActiveProbes returns the number of successfully attached probe sets.
func (o *ObserverLoader) ActiveProbes() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	count := 0
	for _, ps := range o.probes {
		if len(ps.links) > 0 {
			count++
		}
	}
	return count
}

// Close detaches all probes, stops ring buffer readers, and releases
// resources.
func (o *ObserverLoader) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.closed {
		return nil
	}
	o.closed = true

	var errs []error

	for i := range o.probes {
		ps := &o.probes[i]

		// Close ring buffer readers first.
		for _, r := range ps.readers {
			if err := r.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close reader: %w", err))
			}
		}

		// Detach links.
		for _, l := range ps.links {
			if err := l.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close link: %w", err))
			}
		}

		// Close the object handle.
		if ps.object != nil {
			if err := ps.object.Close(); err != nil {
				errs = append(errs, fmt.Errorf("close object: %w", err))
			}
		}
	}
	o.probes = nil

	close(o.eventCh)

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	o.logger.Info("observer loader closed")
	return nil
}

// discoverSSLLibs finds libssl.so paths on the system.
func (o *ObserverLoader) discoverSSLLibs() []string {
	if len(o.cfg.SSLLibPaths) > 0 {
		var found []string
		for _, p := range o.cfg.SSLLibPaths {
			if _, err := os.Stat(p); err == nil {
				found = append(found, p)
			}
		}
		if len(found) > 0 {
			return found
		}
	}

	// Auto-discovery: check common locations.
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib/aarch64-linux-gnu/libssl.so.3",
		"/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3",
		"/usr/lib/libssl.so",
	}

	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
		}
	}
	return found
}

// ---------------------------------------------------------------------------
// Placeholder BPF loader — compiles without cilium/ebpf
// ---------------------------------------------------------------------------

// PlaceholderLoader is a no-op BPFLoader that returns errors for all
// operations.  It exists so the package compiles without the cilium/ebpf
// CGo dependency.  In production, replace it with CiliumLoader which wraps
// the real library.
type PlaceholderLoader struct{}

var _ BPFLoader = (*PlaceholderLoader)(nil)

var errNotImplemented = errors.New("ebpf: placeholder loader — real cilium/ebpf loader required")

func (PlaceholderLoader) LoadObject(string) (ObjectHandle, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) AttachTracepoint(BPFProgram, string, string) (BPFLink, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) AttachKprobe(BPFProgram, string) (BPFLink, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) AttachKretprobe(BPFProgram, string) (BPFLink, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) AttachUprobe(BPFProgram, string, string, int) (BPFLink, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) AttachUretprobe(BPFProgram, string, string, int) (BPFLink, error) {
	return nil, errNotImplemented
}
func (PlaceholderLoader) NewRingBuffer(BPFMap) (RingBuffer, error) {
	return nil, errNotImplemented
}

// ---------------------------------------------------------------------------
// Placeholder ring buffer reader (for testing)
// ---------------------------------------------------------------------------

// ChannelRingBuffer implements RingBuffer backed by a Go channel, useful
// for unit testing the read loop and parser without a real eBPF ring buffer.
type ChannelRingBuffer struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

// NewChannelRingBuffer creates a test ring buffer.
func NewChannelRingBuffer(bufSize int) *ChannelRingBuffer {
	return &ChannelRingBuffer{
		ch:     make(chan []byte, bufSize),
		closed: make(chan struct{}),
	}
}

// Push enqueues raw event bytes (test helper).
func (c *ChannelRingBuffer) Push(data []byte) {
	select {
	case c.ch <- data:
	case <-c.closed:
	}
}

func (c *ChannelRingBuffer) Read(ctx context.Context) ([]byte, error) {
	select {
	case data := <-c.ch:
		return data, nil
	case <-c.closed:
		return nil, errors.New("ring buffer closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *ChannelRingBuffer) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

