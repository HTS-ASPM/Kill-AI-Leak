// Package enrichment provides Kubernetes metadata enrichment for security
// events. It resolves pod/service information from IPs, inodes, and cgroup
// paths, and maintains an in-memory cache with configurable TTL to avoid
// excessive API calls.
package enrichment

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// K8sEnricherConfig holds the tunables for the enricher.
type K8sEnricherConfig struct {
	// CacheTTL is the time-to-live for cached pod/service entries.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// CleanupInterval controls how often expired entries are reaped.
	// Default: 1 minute.
	CleanupInterval time.Duration

	// ProcRoot is the path to /proc on the host. It can be overridden
	// when the host proc filesystem is mounted at an alternate path
	// (e.g., /host/proc in a container). Default: "/proc".
	ProcRoot string

	// Logger is the structured logger to use. If nil slog.Default() is used.
	Logger *slog.Logger
}

// DefaultK8sEnricherConfig returns a config with sensible defaults.
func DefaultK8sEnricherConfig() K8sEnricherConfig {
	return K8sEnricherConfig{
		CacheTTL:        5 * time.Minute,
		CleanupInterval: 1 * time.Minute,
		ProcRoot:        "/proc",
		Logger:          slog.Default(),
	}
}

// ---------------------------------------------------------------------------
// Cache types
// ---------------------------------------------------------------------------

// cacheEntry wraps a value with an expiration time.
type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

// ttlCache is a generic, thread-safe, TTL-based in-memory cache.
type ttlCache[T any] struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry[T]
	ttl     time.Duration
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{
		entries: make(map[string]cacheEntry[T]),
		ttl:     ttl,
	}
}

func (c *ttlCache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		var zero T
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry[T]{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *ttlCache[T]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Cleanup removes all expired entries and returns the number removed.
func (c *ttlCache[T]) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for k, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// Len returns the number of entries currently in the cache (including
// expired entries that have not yet been reaped).
func (c *ttlCache[T]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ---------------------------------------------------------------------------
// Kubernetes metadata types
// ---------------------------------------------------------------------------

// PodMetadata holds enrichment data for a single pod.
type PodMetadata struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Node            string            `json:"node,omitempty"`
	IP              string            `json:"ip,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	ServiceAccount  string            `json:"service_account,omitempty"`
	OwnerKind       string            `json:"owner_kind,omitempty"`       // Deployment, DaemonSet, StatefulSet, Job, etc.
	OwnerName       string            `json:"owner_name,omitempty"`       // Name of the owning resource.
	ContainerImages []string          `json:"container_images,omitempty"` // Images running in the pod.
	StartTime       time.Time         `json:"start_time,omitempty"`
}

// NamespaceMetadata holds enrichment data for a namespace.
type NamespaceMetadata struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Team        string            `json:"team,omitempty"` // Derived from labels/annotations.
}

// ServiceInfo describes a Kubernetes service and the pods it selects.
type ServiceInfo struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type,omitempty"` // ClusterIP, NodePort, LoadBalancer
	Selector  map[string]string `json:"selector,omitempty"`
	ClusterIP string            `json:"cluster_ip,omitempty"`
	Ports     []ServicePort     `json:"ports,omitempty"`
}

// ServicePort represents a single port on a Kubernetes service.
type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort int32  `json:"target_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// ServiceEdge represents a directional relationship between two services
// in the service graph.
type ServiceEdge struct {
	Source      string `json:"source"`      // "namespace/service"
	Destination string `json:"destination"` // "namespace/service"
	Protocol    string `json:"protocol,omitempty"`
	Port        int32  `json:"port,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
}

// ServiceGraph is the collection of nodes and edges that make up the
// inter-service communication map.
type ServiceGraph struct {
	Nodes []ServiceInfo `json:"nodes"`
	Edges []ServiceEdge `json:"edges"`
	BuiltAt time.Time   `json:"built_at"`
}

// ---------------------------------------------------------------------------
// Pod change watcher callback
// ---------------------------------------------------------------------------

// PodEventType describes what happened to a pod.
type PodEventType string

const (
	PodAdded    PodEventType = "ADDED"
	PodModified PodEventType = "MODIFIED"
	PodDeleted  PodEventType = "DELETED"
)

// PodWatchEvent is delivered when a pod changes.
type PodWatchEvent struct {
	Type PodEventType
	Pod  PodMetadata
}

// PodWatchHandler is a callback for pod change events.
type PodWatchHandler func(event PodWatchEvent)

// ---------------------------------------------------------------------------
// K8sEnricher
// ---------------------------------------------------------------------------

// K8sEnricher enriches security events with Kubernetes metadata. It
// maintains in-memory caches for pod-by-IP, pod-by-name, service, and
// namespace lookups. All public methods are safe for concurrent use.
type K8sEnricher struct {
	cfg K8sEnricherConfig

	podsByIP   *ttlCache[PodMetadata]
	podsByName *ttlCache[PodMetadata]        // key: "namespace/name"
	services   *ttlCache[ServiceInfo]         // key: "namespace/name"
	namespaces *ttlCache[NamespaceMetadata]   // key: namespace name

	mu           sync.RWMutex
	edges        []ServiceEdge       // observed service-to-service edges
	watchHandler PodWatchHandler      // optional watcher callback
	stopCleanup  chan struct{}
	stopped      bool

	logger *slog.Logger
}

// NewK8sEnricher constructs a new enricher with the given configuration
// and starts a background cleanup goroutine.
func NewK8sEnricher(cfg K8sEnricherConfig) *K8sEnricher {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = 1 * time.Minute
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}

	e := &K8sEnricher{
		cfg:         cfg,
		podsByIP:    newTTLCache[PodMetadata](cfg.CacheTTL),
		podsByName:  newTTLCache[PodMetadata](cfg.CacheTTL),
		services:    newTTLCache[ServiceInfo](cfg.CacheTTL),
		namespaces:  newTTLCache[NamespaceMetadata](cfg.CacheTTL),
		edges:       make([]ServiceEdge, 0, 256),
		stopCleanup: make(chan struct{}),
		logger:      cfg.Logger,
	}

	go e.cleanupLoop()
	return e
}

// Stop terminates the background cleanup goroutine.
func (e *K8sEnricher) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.stopped {
		close(e.stopCleanup)
		e.stopped = true
	}
}

// cleanupLoop periodically purges expired cache entries.
func (e *K8sEnricher) cleanupLoop() {
	ticker := time.NewTicker(e.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCleanup:
			return
		case <-ticker.C:
			ip := e.podsByIP.Cleanup()
			name := e.podsByName.Cleanup()
			svc := e.services.Cleanup()
			ns := e.namespaces.Cleanup()
			if ip+name+svc+ns > 0 {
				e.logger.Debug("cache cleanup",
					"pods_by_ip", ip,
					"pods_by_name", name,
					"services", svc,
					"namespaces", ns,
				)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Cache population helpers (called by watch / sync goroutines)
// ---------------------------------------------------------------------------

// IndexPod adds or refreshes a pod in the cache. This is typically called
// from WatchPods or a periodic reconciliation loop.
func (e *K8sEnricher) IndexPod(pod PodMetadata) {
	nameKey := pod.Namespace + "/" + pod.Name
	e.podsByName.Set(nameKey, pod)
	if pod.IP != "" {
		e.podsByIP.Set(pod.IP, pod)
	}
}

// IndexService adds or refreshes a service in the cache.
func (e *K8sEnricher) IndexService(svc ServiceInfo) {
	key := svc.Namespace + "/" + svc.Name
	e.services.Set(key, svc)
}

// IndexNamespace adds or refreshes a namespace in the cache.
func (e *K8sEnricher) IndexNamespace(ns NamespaceMetadata) {
	e.namespaces.Set(ns.Name, ns)
}

// RemovePod evicts a pod from all caches.
func (e *K8sEnricher) RemovePod(namespace, name, ip string) {
	e.podsByName.Delete(namespace + "/" + name)
	if ip != "" {
		e.podsByIP.Delete(ip)
	}
}

// RecordEdge records an observed communication between two services.
func (e *K8sEnricher) RecordEdge(edge ServiceEdge) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.edges = append(e.edges, edge)
}

// ---------------------------------------------------------------------------
// Event enrichment
// ---------------------------------------------------------------------------

// EnrichEvent augments an event with Kubernetes metadata. It resolves the
// actor's pod by IP (falling back to the actor ID), attaches labels, the
// owning deployment/daemonset, service account, and team ownership from
// the namespace.
func (e *K8sEnricher) EnrichEvent(event *models.Event) {
	if event == nil {
		return
	}

	// Attempt to resolve the pod for the actor.
	var pod PodMetadata
	var found bool

	// Try IP-based resolution first.
	if ip := extractIP(event); ip != "" {
		pod, found = e.ResolvePodFromIP(ip)
	}

	// Fall back to name-based lookup.
	if !found && event.Actor.Namespace != "" && event.Actor.Name != "" {
		pod, found = e.GetPodMetadata(event.Actor.Name, event.Actor.Namespace)
	}

	if found {
		event.Actor.Type = models.ActorPod
		event.Actor.Name = pod.Name
		event.Actor.Namespace = pod.Namespace
		event.Actor.Node = pod.Node
		event.Actor.ServiceAccount = pod.ServiceAccount
		if event.Actor.Labels == nil {
			event.Actor.Labels = make(map[string]string)
		}
		for k, v := range pod.Labels {
			event.Actor.Labels[k] = v
		}

		// Add owner metadata.
		if event.Metadata == nil {
			event.Metadata = make(map[string]string)
		}
		if pod.OwnerKind != "" {
			event.Metadata["k8s.owner.kind"] = pod.OwnerKind
			event.Metadata["k8s.owner.name"] = pod.OwnerName
		}

		// Resolve service from pod labels.
		if svc, svcFound := e.MapToService(pod); svcFound {
			event.Metadata["k8s.service"] = svc.Namespace + "/" + svc.Name
		}

		// Enrich with namespace-level team ownership.
		if ns, nsFound := e.GetNamespaceMetadata(pod.Namespace); nsFound {
			if ns.Team != "" {
				event.Actor.Team = ns.Team
			}
		}
	}
}

// extractIP attempts to pull an IP address from the event. It looks at
// the metadata map first ("source_ip"), then falls back to interpreting
// the actor ID as an IP.
func extractIP(event *models.Event) string {
	if event.Metadata != nil {
		if ip, ok := event.Metadata["source_ip"]; ok {
			return ip
		}
	}
	// Check if actor ID looks like an IP.
	if net.ParseIP(event.Actor.ID) != nil {
		return event.Actor.ID
	}
	return ""
}

// ---------------------------------------------------------------------------
// IP / inode resolution
// ---------------------------------------------------------------------------

// ResolvePodFromIP looks up the cached pod for the given IP address.
func (e *K8sEnricher) ResolvePodFromIP(ip string) (PodMetadata, bool) {
	return e.podsByIP.Get(ip)
}

// ResolvePodFromInode maps a socket inode to a pod by reading
// /proc/net/tcp (and tcp6) on the host to find which local address owns
// the inode, then walks /proc/<pid>/cgroup to extract the pod UID, and
// finally looks up the pod in the name cache.
//
// This is inherently Linux-specific and best-effort. On failure the
// second return value is false.
func (e *K8sEnricher) ResolvePodFromInode(inode uint64) (PodMetadata, bool) {
	ip, found := e.inodeToLocalIP(inode)
	if !found {
		return PodMetadata{}, false
	}

	if pod, ok := e.podsByIP.Get(ip); ok {
		return pod, true
	}

	// Try extracting pod UID from cgroup of the owning pid.
	pid, pidFound := e.inodeToPID(inode)
	if !pidFound {
		return PodMetadata{}, false
	}

	podUID, cgFound := e.pidToPodUID(pid)
	if !cgFound {
		return PodMetadata{}, false
	}

	// Search the podsByName cache for a matching UID in labels.
	e.podsByName.mu.RLock()
	defer e.podsByName.mu.RUnlock()
	for _, entry := range e.podsByName.entries {
		if time.Now().After(entry.expiresAt) {
			continue
		}
		if uid, ok := entry.value.Labels["pod-uid"]; ok && uid == podUID {
			return entry.value, true
		}
	}

	return PodMetadata{}, false
}

// inodeToLocalIP parses /proc/net/tcp and /proc/net/tcp6 looking for a
// socket matching the given inode and returns the local IP address.
func (e *K8sEnricher) inodeToLocalIP(inode uint64) (string, bool) {
	inodeStr := strconv.FormatUint(inode, 10)
	for _, proto := range []string{"tcp", "tcp6"} {
		path := filepath.Join(e.cfg.ProcRoot, "net", proto)
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum == 1 {
				continue // skip header
			}
			line := strings.TrimSpace(scanner.Text())
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// Field index 9 is the inode.
			if fields[9] == inodeStr {
				ip := parseHexIP(fields[1]) // local_address field
				f.Close()
				if ip != "" {
					return ip, true
				}
				return "", false
			}
		}
		f.Close()
	}
	return "", false
}

// parseHexIP parses a "XXXXXXXX:PPPP" formatted address from /proc/net/tcp
// and returns the dotted-decimal IP (port is discarded).
func parseHexIP(addrPort string) string {
	parts := strings.Split(addrPort, ":")
	if len(parts) != 2 {
		return ""
	}
	hexIP := parts[0]

	// Handle IPv4 (8 hex chars).
	if len(hexIP) == 8 {
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 4 {
			return ""
		}
		// /proc/net/tcp stores the IP in little-endian on little-endian hosts.
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	// IPv6 (32 hex chars) - return the hex as-is for now.
	if len(hexIP) == 32 {
		b, err := hex.DecodeString(hexIP)
		if err != nil || len(b) != 16 {
			return ""
		}
		return net.IP(b).String()
	}
	return ""
}

// inodeToPID walks /proc/<pid>/fd looking for a symlink that matches
// "socket:[<inode>]". Returns the PID that owns the socket.
func (e *K8sEnricher) inodeToPID(inode uint64) (int, bool) {
	target := fmt.Sprintf("socket:[%d]", inode)
	procDir := e.cfg.ProcRoot

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return 0, false
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a numeric PID directory
		}

		fdDir := filepath.Join(procDir, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, true
			}
		}
	}
	return 0, false
}

// pidToPodUID reads /proc/<pid>/cgroup and extracts the pod UID from the
// cgroup path. Kubernetes uses cgroup paths containing the pod UID such as
// "/kubepods/burstable/pod<UID>/...".
func (e *K8sEnricher) pidToPodUID(pid int) (string, bool) {
	cgroupPath := filepath.Join(e.cfg.ProcRoot, strconv.Itoa(pid), "cgroup")
	f, err := os.Open(cgroupPath)
	if err != nil {
		return "", false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Look for "pod" followed by the UID in the cgroup path.
		idx := strings.Index(line, "/pod")
		if idx == -1 {
			continue
		}
		rest := line[idx+4:]
		// The UID runs until the next "/" or end of string.
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			rest = rest[:slashIdx]
		}
		rest = strings.TrimSpace(rest)
		if rest != "" {
			return rest, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Metadata lookups
// ---------------------------------------------------------------------------

// GetPodMetadata returns the cached metadata for a pod, identified by name
// and namespace. The second return value indicates whether the pod was found.
func (e *K8sEnricher) GetPodMetadata(podName, namespace string) (PodMetadata, bool) {
	key := namespace + "/" + podName
	return e.podsByName.Get(key)
}

// GetNamespaceMetadata returns the cached metadata for a namespace. The
// team ownership is derived from the "team" or "owner" label or the
// "team.example.com/name" annotation if present.
func (e *K8sEnricher) GetNamespaceMetadata(namespace string) (NamespaceMetadata, bool) {
	return e.namespaces.Get(namespace)
}

// ---------------------------------------------------------------------------
// Service resolution and graph
// ---------------------------------------------------------------------------

// MapToService resolves a pod to the Kubernetes service that selects it.
// It iterates over cached services in the same namespace and checks
// whether the pod's labels are a superset of the service's selector.
func (e *K8sEnricher) MapToService(pod PodMetadata) (ServiceInfo, bool) {
	e.services.mu.RLock()
	defer e.services.mu.RUnlock()

	now := time.Now()
	for _, entry := range e.services.entries {
		if now.After(entry.expiresAt) {
			continue
		}
		svc := entry.value
		if svc.Namespace != pod.Namespace {
			continue
		}
		if len(svc.Selector) == 0 {
			continue
		}
		if labelsMatch(pod.Labels, svc.Selector) {
			return svc, true
		}
	}
	return ServiceInfo{}, false
}

// labelsMatch returns true if podLabels contains every key-value pair in
// selector.
func labelsMatch(podLabels, selector map[string]string) bool {
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// BuildServiceGraph constructs a ServiceGraph from the currently cached
// services and the observed communication edges.
func (e *K8sEnricher) BuildServiceGraph() ServiceGraph {
	e.services.mu.RLock()
	now := time.Now()
	nodes := make([]ServiceInfo, 0, len(e.services.entries))
	for _, entry := range e.services.entries {
		if now.After(entry.expiresAt) {
			continue
		}
		nodes = append(nodes, entry.value)
	}
	e.services.mu.RUnlock()

	e.mu.RLock()
	edges := make([]ServiceEdge, len(e.edges))
	copy(edges, e.edges)
	e.mu.RUnlock()

	return ServiceGraph{
		Nodes:   nodes,
		Edges:   edges,
		BuiltAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Pod watcher
// ---------------------------------------------------------------------------

// WatchPods registers a handler that is invoked whenever the enricher
// receives a pod change event (via HandlePodEvent). In a production
// deployment this handler would typically be driven by the Kubernetes
// informer; the enricher acts as the callback sink.
func (e *K8sEnricher) WatchPods(handler PodWatchHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.watchHandler = handler
}

// HandlePodEvent should be called by the Kubernetes informer (or any
// other source of truth) whenever a pod is created, updated, or deleted.
// It updates the internal caches and, if registered, invokes the watch
// handler.
func (e *K8sEnricher) HandlePodEvent(eventType PodEventType, pod PodMetadata) {
	switch eventType {
	case PodAdded, PodModified:
		e.IndexPod(pod)
	case PodDeleted:
		e.RemovePod(pod.Namespace, pod.Name, pod.IP)
	}

	e.mu.RLock()
	handler := e.watchHandler
	e.mu.RUnlock()

	if handler != nil {
		handler(PodWatchEvent{Type: eventType, Pod: pod})
	}

	e.logger.Debug("pod event processed",
		"type", string(eventType),
		"pod", pod.Namespace+"/"+pod.Name,
	)
}

// ---------------------------------------------------------------------------
// Cache statistics (for observability)
// ---------------------------------------------------------------------------

// CacheStats reports the number of entries in each cache.
type CacheStats struct {
	PodsByIP   int `json:"pods_by_ip"`
	PodsByName int `json:"pods_by_name"`
	Services   int `json:"services"`
	Namespaces int `json:"namespaces"`
	Edges      int `json:"edges"`
}

// Stats returns current cache sizes.
func (e *K8sEnricher) Stats() CacheStats {
	e.mu.RLock()
	edgeCount := len(e.edges)
	e.mu.RUnlock()

	return CacheStats{
		PodsByIP:   e.podsByIP.Len(),
		PodsByName: e.podsByName.Len(),
		Services:   e.services.Len(),
		Namespaces: e.namespaces.Len(),
		Edges:      edgeCount,
	}
}
