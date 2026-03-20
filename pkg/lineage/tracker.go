// Package lineage provides data lineage tracking for AI services. It
// records data flow edges between sources (databases, APIs), services,
// and LLM providers, detects PII in those flows, highlights risky paths
// where sensitive data reaches external LLMs, and exports the graph in
// DOT format for visualization.
package lineage

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// NodeType classifies a node in the lineage graph.
type NodeType string

const (
	NodeDatabase    NodeType = "database"
	NodeAPI         NodeType = "api"
	NodeService     NodeType = "service"
	NodeLLMProvider NodeType = "llm_provider"
	NodeFilesystem  NodeType = "filesystem"
	NodeUser        NodeType = "user"
)

// LineageNode represents a vertex in the data lineage graph.
type LineageNode struct {
	// ID is a stable unique identifier for this node (e.g., "db:postgres-main" or "llm:openai").
	ID string `json:"id"`

	// Name is the human-readable name.
	Name string `json:"name"`

	// Type classifies the node.
	Type NodeType `json:"type"`

	// Namespace is the Kubernetes namespace, if applicable.
	Namespace string `json:"namespace,omitempty"`

	// Provider is the LLM provider name for NodeLLMProvider nodes.
	Provider string `json:"provider,omitempty"`

	// Labels holds arbitrary key-value metadata.
	Labels map[string]string `json:"labels,omitempty"`

	// IsExternal is true for nodes outside the organisation's infrastructure
	// (e.g., third-party LLM APIs).
	IsExternal bool `json:"is_external,omitempty"`
}

// DataType classifies what kind of data flows along an edge.
type DataType string

const (
	DataGeneral      DataType = "general"
	DataPII          DataType = "pii"
	DataCredentials  DataType = "credentials"
	DataSourceCode   DataType = "source_code"
	DataFinancial    DataType = "financial"
	DataHealthcare   DataType = "healthcare"
	DataConfidential DataType = "confidential"
)

// LineageEdge represents a directed data flow between two nodes.
type LineageEdge struct {
	// ID is a stable unique identifier for this edge.
	ID string `json:"id"`

	// SourceID is the ID of the source node.
	SourceID string `json:"source_id"`

	// DestinationID is the ID of the destination node.
	DestinationID string `json:"destination_id"`

	// DataTypes lists the types of data observed on this edge.
	DataTypes []DataType `json:"data_types"`

	// PIITypes lists specific PII types detected on this edge.
	PIITypes []string `json:"pii_types,omitempty"`

	// VolumeBytes is the approximate total data volume observed.
	VolumeBytes int64 `json:"volume_bytes,omitempty"`

	// CallCount is the number of observed data flow events.
	CallCount int64 `json:"call_count"`

	// FirstSeen is when this edge was first observed.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is when this edge was most recently observed.
	LastSeen time.Time `json:"last_seen"`

	// Labels holds arbitrary key-value metadata.
	Labels map[string]string `json:"labels,omitempty"`
}

// LineageGraph is the full data flow graph for a scope (service, namespace,
// or the entire organisation).
type LineageGraph struct {
	Nodes   []LineageNode `json:"nodes"`
	Edges   []LineageEdge `json:"edges"`
	BuiltAt time.Time     `json:"built_at"`
}

// RiskyPath describes a data path where sensitive data reaches an external
// LLM provider.
type RiskyPath struct {
	// Path is the ordered list of node IDs from source to destination.
	Path []string `json:"path"`

	// DataTypes are the sensitive data types observed on this path.
	DataTypes []DataType `json:"data_types"`

	// PIITypes lists specific PII types flowing along this path.
	PIITypes []string `json:"pii_types,omitempty"`

	// RiskScore is a computed risk score (0-1).
	RiskScore float64 `json:"risk_score"`

	// Description is a human-readable summary.
	Description string `json:"description"`
}

// ---------------------------------------------------------------------------
// LineageTracker
// ---------------------------------------------------------------------------

// LineageTracker records data flow edges and builds lineage graphs. All
// public methods are safe for concurrent use.
type LineageTracker struct {
	mu    sync.RWMutex
	nodes map[string]*LineageNode // keyed by node ID
	edges map[string]*LineageEdge // keyed by edge ID

	logger loggerFunc
}

// loggerFunc is a minimal logging interface (Printf-style).
type loggerFunc func(format string, args ...any)

// defaultLogger is a no-op logger.
func defaultLogger(string, ...any) {}

// NewLineageTracker creates a new tracker.
func NewLineageTracker() *LineageTracker {
	return &LineageTracker{
		nodes:  make(map[string]*LineageNode),
		edges:  make(map[string]*LineageEdge),
		logger: defaultLogger,
	}
}

// SetLogger configures a Printf-style logger for debug output.
func (lt *LineageTracker) SetLogger(fn loggerFunc) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.logger = fn
}

// ---------------------------------------------------------------------------
// Node registration
// ---------------------------------------------------------------------------

// RegisterNode adds or updates a node in the graph. If a node with the
// same ID already exists, its fields are merged (labels are unioned).
func (lt *LineageTracker) RegisterNode(node LineageNode) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	existing, ok := lt.nodes[node.ID]
	if !ok {
		n := node
		if n.Labels == nil {
			n.Labels = make(map[string]string)
		}
		lt.nodes[node.ID] = &n
		return
	}

	// Merge: update non-empty fields.
	if node.Name != "" {
		existing.Name = node.Name
	}
	if node.Namespace != "" {
		existing.Namespace = node.Namespace
	}
	if node.Provider != "" {
		existing.Provider = node.Provider
	}
	if node.IsExternal {
		existing.IsExternal = true
	}
	if existing.Labels == nil {
		existing.Labels = make(map[string]string)
	}
	for k, v := range node.Labels {
		existing.Labels[k] = v
	}
}

// ---------------------------------------------------------------------------
// Data flow tracking
// ---------------------------------------------------------------------------

// TrackDataFlow records a directed data flow edge from source to
// destination. If the edge already exists, it updates call counts, volume,
// and data types. If the source or destination nodes don't exist, minimal
// stub nodes are created.
func (lt *LineageTracker) TrackDataFlow(sourceID, destinationID string, dataType DataType) error {
	if sourceID == "" || destinationID == "" {
		return fmt.Errorf("lineage: sourceID and destinationID must not be empty")
	}

	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Ensure source and destination nodes exist.
	lt.ensureNode(sourceID)
	lt.ensureNode(destinationID)

	edgeID := edgeKey(sourceID, destinationID)
	edge, ok := lt.edges[edgeID]
	if !ok {
		edge = &LineageEdge{
			ID:            edgeID,
			SourceID:      sourceID,
			DestinationID: destinationID,
			DataTypes:     []DataType{dataType},
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			CallCount:     1,
			Labels:        make(map[string]string),
		}
		lt.edges[edgeID] = edge
		return nil
	}

	edge.LastSeen = time.Now()
	edge.CallCount++

	// Add data type if not already present.
	if !containsDataType(edge.DataTypes, dataType) {
		edge.DataTypes = append(edge.DataTypes, dataType)
	}

	return nil
}

// TrackDataFlowWithDetails records a data flow with additional metadata.
func (lt *LineageTracker) TrackDataFlowWithDetails(sourceID, destinationID string, dataType DataType, piiTypes []string, volumeBytes int64) error {
	if err := lt.TrackDataFlow(sourceID, destinationID, dataType); err != nil {
		return err
	}

	lt.mu.Lock()
	defer lt.mu.Unlock()

	edgeID := edgeKey(sourceID, destinationID)
	edge := lt.edges[edgeID]

	edge.VolumeBytes += volumeBytes

	// Merge PII types.
	for _, pii := range piiTypes {
		if !containsString(edge.PIITypes, pii) {
			edge.PIITypes = append(edge.PIITypes, pii)
		}
	}

	// Auto-upgrade data type to PII if PII was detected.
	if len(piiTypes) > 0 && !containsDataType(edge.DataTypes, DataPII) {
		edge.DataTypes = append(edge.DataTypes, DataPII)
	}

	return nil
}

// ensureNode creates a stub node if one doesn't exist. Must be called
// with lt.mu held.
func (lt *LineageTracker) ensureNode(id string) {
	if _, ok := lt.nodes[id]; ok {
		return
	}
	lt.nodes[id] = &LineageNode{
		ID:     id,
		Name:   id,
		Type:   guessNodeType(id),
		Labels: make(map[string]string),
	}
}

// guessNodeType attempts to infer the node type from its ID prefix.
func guessNodeType(id string) NodeType {
	switch {
	case strings.HasPrefix(id, "db:"):
		return NodeDatabase
	case strings.HasPrefix(id, "api:"):
		return NodeAPI
	case strings.HasPrefix(id, "svc:"):
		return NodeService
	case strings.HasPrefix(id, "llm:"):
		return NodeLLMProvider
	case strings.HasPrefix(id, "fs:"):
		return NodeFilesystem
	case strings.HasPrefix(id, "user:"):
		return NodeUser
	default:
		return NodeService
	}
}

// edgeKey returns a stable edge ID for the source->destination pair.
func edgeKey(sourceID, destID string) string {
	return sourceID + " -> " + destID
}

// ---------------------------------------------------------------------------
// Graph queries
// ---------------------------------------------------------------------------

// BuildLineageGraph constructs the full data flow graph for a given
// service. If serviceID is empty, the entire graph is returned. Otherwise,
// only nodes and edges reachable from (or to) the specified service are
// included.
func (lt *LineageTracker) BuildLineageGraph(serviceID string) LineageGraph {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if serviceID == "" {
		return lt.fullGraph()
	}

	// Find all reachable nodes via BFS in both directions.
	reachable := make(map[string]bool)
	lt.bfs(serviceID, reachable, true)  // downstream
	lt.bfs(serviceID, reachable, false) // upstream
	reachable[serviceID] = true

	nodes := make([]LineageNode, 0, len(reachable))
	for id := range reachable {
		if n, ok := lt.nodes[id]; ok {
			nodes = append(nodes, *n)
		}
	}

	edges := make([]LineageEdge, 0, len(lt.edges))
	for _, e := range lt.edges {
		if reachable[e.SourceID] && reachable[e.DestinationID] {
			edges = append(edges, *e)
		}
	}

	return LineageGraph{
		Nodes:   nodes,
		Edges:   edges,
		BuiltAt: time.Now(),
	}
}

// fullGraph returns the complete graph. Must be called with lt.mu held.
func (lt *LineageTracker) fullGraph() LineageGraph {
	nodes := make([]LineageNode, 0, len(lt.nodes))
	for _, n := range lt.nodes {
		nodes = append(nodes, *n)
	}
	edges := make([]LineageEdge, 0, len(lt.edges))
	for _, e := range lt.edges {
		edges = append(edges, *e)
	}
	return LineageGraph{
		Nodes:   nodes,
		Edges:   edges,
		BuiltAt: time.Now(),
	}
}

// bfs performs a breadth-first search from startID, collecting reachable
// node IDs. If forward is true, it follows edges from source to
// destination; if false, from destination to source.
func (lt *LineageTracker) bfs(startID string, visited map[string]bool, forward bool) {
	queue := []string{startID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, e := range lt.edges {
			var next string
			if forward && e.SourceID == current {
				next = e.DestinationID
			} else if !forward && e.DestinationID == current {
				next = e.SourceID
			} else {
				continue
			}

			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// PII detection and risky path analysis
// ---------------------------------------------------------------------------

// DetectPIIFlows returns all edges that carry PII data.
func (lt *LineageTracker) DetectPIIFlows() []LineageEdge {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	result := make([]LineageEdge, 0, len(lt.edges)/4)
	for _, e := range lt.edges {
		if containsDataType(e.DataTypes, DataPII) || len(e.PIITypes) > 0 {
			result = append(result, *e)
		}
	}
	return result
}

// HighlightRiskyPaths finds paths where sensitive data (PII, credentials,
// healthcare, financial) reaches external LLM provider nodes.
func (lt *LineageTracker) HighlightRiskyPaths() []RiskyPath {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	// Identify all external LLM nodes.
	externalLLMs := make(map[string]bool)
	for id, n := range lt.nodes {
		if n.Type == NodeLLMProvider && n.IsExternal {
			externalLLMs[id] = true
		}
	}
	if len(externalLLMs) == 0 {
		return nil
	}

	// Identify all edges carrying sensitive data.
	sensitiveTypes := map[DataType]bool{
		DataPII:          true,
		DataCredentials:  true,
		DataFinancial:    true,
		DataHealthcare:   true,
		DataConfidential: true,
	}

	// Build an adjacency list from sensitive edges.
	adj := make(map[string][]LineageEdge)
	for _, e := range lt.edges {
		hasSensitive := false
		for _, dt := range e.DataTypes {
			if sensitiveTypes[dt] {
				hasSensitive = true
				break
			}
		}
		if hasSensitive || len(e.PIITypes) > 0 {
			adj[e.SourceID] = append(adj[e.SourceID], *e)
		}
	}

	// DFS from each non-LLM source node to find paths to external LLMs.
	var riskyPaths []RiskyPath
	for startID, node := range lt.nodes {
		if node.Type == NodeLLMProvider {
			continue
		}
		// DFS.
		visited := map[string]bool{startID: true}
		lt.dfsRiskyPaths(startID, []string{startID}, nil, nil, adj, externalLLMs, visited, &riskyPaths)
	}

	// Sort by risk score descending.
	sort.Slice(riskyPaths, func(i, j int) bool {
		return riskyPaths[i].RiskScore > riskyPaths[j].RiskScore
	})

	return riskyPaths
}

// dfsRiskyPaths is a recursive DFS that accumulates risky paths.
func (lt *LineageTracker) dfsRiskyPaths(
	current string,
	path []string,
	dataTypes []DataType,
	piiTypes []string,
	adj map[string][]LineageEdge,
	externalLLMs map[string]bool,
	visited map[string]bool,
	results *[]RiskyPath,
) {
	for _, edge := range adj[current] {
		next := edge.DestinationID
		if visited[next] {
			continue
		}

		newPath := make([]string, len(path)+1)
		copy(newPath, path)
		newPath[len(path)] = next

		newDataTypes := mergeDataTypes(dataTypes, edge.DataTypes)
		newPII := mergeStrings(piiTypes, edge.PIITypes)

		if externalLLMs[next] {
			riskScore := computePathRisk(newDataTypes, newPII, len(newPath))
			*results = append(*results, RiskyPath{
				Path:        newPath,
				DataTypes:   newDataTypes,
				PIITypes:    newPII,
				RiskScore:   riskScore,
				Description: fmt.Sprintf("Sensitive data flows from %s to external LLM %s via %d hops", newPath[0], next, len(newPath)-1),
			})
		}

		visited[next] = true
		lt.dfsRiskyPaths(next, newPath, newDataTypes, newPII, adj, externalLLMs, visited, results)
		visited[next] = false
	}
}

// computePathRisk computes a risk score for a data path.
func computePathRisk(dataTypes []DataType, piiTypes []string, hops int) float64 {
	score := 0.0

	typeWeights := map[DataType]float64{
		DataPII:          0.3,
		DataCredentials:  0.4,
		DataFinancial:    0.3,
		DataHealthcare:   0.35,
		DataConfidential: 0.25,
	}

	for _, dt := range dataTypes {
		if w, ok := typeWeights[dt]; ok {
			score += w
		}
	}

	// More PII types = higher risk.
	score += float64(len(piiTypes)) * 0.05

	// Shorter paths (direct flows) are arguably more risky (more data volume).
	if hops <= 2 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// ---------------------------------------------------------------------------
// DOT export
// ---------------------------------------------------------------------------

// ExportDOT exports the lineage graph in Graphviz DOT format.
func (lt *LineageTracker) ExportDOT(serviceID string) string {
	graph := lt.BuildLineageGraph(serviceID)
	return GraphToDOT(graph)
}

// GraphToDOT converts a LineageGraph to Graphviz DOT format.
func GraphToDOT(g LineageGraph) string {
	var sb strings.Builder
	sb.WriteString("digraph lineage {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled];\n\n")

	// Node styling by type.
	typeColors := map[NodeType]string{
		NodeDatabase:    "#4A90D9",
		NodeAPI:         "#7B68EE",
		NodeService:     "#50C878",
		NodeLLMProvider: "#FF6347",
		NodeFilesystem:  "#DEB887",
		NodeUser:        "#FFD700",
	}

	// Write nodes.
	for _, n := range g.Nodes {
		color := typeColors[n.Type]
		if color == "" {
			color = "#CCCCCC"
		}
		fontColor := "#FFFFFF"
		if n.Type == NodeUser || n.Type == NodeFilesystem {
			fontColor = "#000000"
		}

		label := n.Name
		if n.Namespace != "" {
			label = n.Namespace + "/" + n.Name
		}
		if n.IsExternal {
			label += " (external)"
		}

		sb.WriteString(fmt.Sprintf("  %q [label=%q, fillcolor=%q, fontcolor=%q];\n",
			n.ID, label, color, fontColor))
	}

	sb.WriteString("\n")

	// Write edges.
	for _, e := range g.Edges {
		label := strings.Join(dataTypeStrings(e.DataTypes), ",")
		if len(e.PIITypes) > 0 {
			label += fmt.Sprintf(" [PII: %s]", strings.Join(e.PIITypes, ","))
		}

		color := "#333333"
		if containsDataType(e.DataTypes, DataPII) || len(e.PIITypes) > 0 {
			color = "#FF0000"
		} else if containsDataType(e.DataTypes, DataCredentials) {
			color = "#FF8C00"
		}

		sb.WriteString(fmt.Sprintf("  %q -> %q [label=%q, color=%q];\n",
			e.SourceID, e.DestinationID, label, color))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

// Stats returns summary statistics for the lineage graph.
type Stats struct {
	TotalNodes       int `json:"total_nodes"`
	TotalEdges       int `json:"total_edges"`
	DatabaseNodes    int `json:"database_nodes"`
	ServiceNodes     int `json:"service_nodes"`
	LLMProviderNodes int `json:"llm_provider_nodes"`
	ExternalNodes    int `json:"external_nodes"`
	PIIEdges         int `json:"pii_edges"`
}

// GetStats returns current lineage graph statistics.
func (lt *LineageTracker) GetStats() Stats {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	s := Stats{
		TotalNodes: len(lt.nodes),
		TotalEdges: len(lt.edges),
	}

	for _, n := range lt.nodes {
		switch n.Type {
		case NodeDatabase:
			s.DatabaseNodes++
		case NodeService:
			s.ServiceNodes++
		case NodeLLMProvider:
			s.LLMProviderNodes++
		}
		if n.IsExternal {
			s.ExternalNodes++
		}
	}

	for _, e := range lt.edges {
		if containsDataType(e.DataTypes, DataPII) || len(e.PIITypes) > 0 {
			s.PIIEdges++
		}
	}

	return s
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsDataType(types []DataType, target DataType) bool {
	for _, t := range types {
		if t == target {
			return true
		}
	}
	return false
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func mergeDataTypes(existing, new []DataType) []DataType {
	result := make([]DataType, len(existing))
	copy(result, existing)
	for _, dt := range new {
		if !containsDataType(result, dt) {
			result = append(result, dt)
		}
	}
	return result
}

func mergeStrings(existing, new []string) []string {
	result := make([]string, len(existing))
	copy(result, existing)
	for _, s := range new {
		if !containsString(result, s) {
			result = append(result, s)
		}
	}
	return result
}

func dataTypeStrings(types []DataType) []string {
	result := make([]string, len(types))
	for i, dt := range types {
		result[i] = string(dt)
	}
	return result
}
