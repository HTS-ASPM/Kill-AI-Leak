package policy

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

// Loader reads and validates AISecurityPolicy resources from YAML files. It
// also supports watching a directory for changes and hot-reloading without
// restarting the process.
type Loader struct {
	mu     sync.RWMutex
	logger *slog.Logger

	// watcher is non-nil while watching for file changes.
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
	watching bool
}

// NewLoader creates a Loader with a default logger.
func NewLoader() *Loader {
	return &Loader{
		logger: slog.Default(),
	}
}

// NewLoaderWithLogger creates a Loader with the provided logger.
func NewLoaderWithLogger(logger *slog.Logger) *Loader {
	return &Loader{
		logger: logger,
	}
}

// ---------------------------------------------------------------------------
// Single-file loading
// ---------------------------------------------------------------------------

// LoadFile reads a single YAML file and returns the parsed policy. The file
// must contain exactly one AISecurityPolicy document.
func (l *Loader) LoadFile(path string) (*models.AISecurityPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy loader: read %s: %w", path, err)
	}

	var policy models.AISecurityPolicy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("policy loader: parse %s: %w", path, err)
	}

	if err := Validate(&policy); err != nil {
		return nil, fmt.Errorf("policy loader: validate %s: %w", path, err)
	}

	return &policy, nil
}

// ---------------------------------------------------------------------------
// Directory loading
// ---------------------------------------------------------------------------

// LoadDir reads all .yaml and .yml files in the given directory (non-recursive)
// and returns all successfully parsed policies. Files that fail validation are
// logged and skipped rather than aborting the entire load.
func (l *Loader) LoadDir(dir string) ([]*models.AISecurityPolicy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("policy loader: read dir %s: %w", dir, err)
	}

	var policies []*models.AISecurityPolicy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		p, err := l.LoadFile(fullPath)
		if err != nil {
			l.logger.Warn("skipping invalid policy file",
				"path", fullPath,
				"error", err,
			)
			continue
		}
		policies = append(policies, p)
	}

	l.logger.Info("loaded policies from directory",
		"dir", dir,
		"count", len(policies),
	)
	return policies, nil
}

// LoadPath loads a single file or an entire directory depending on whether
// path points to a file or directory.
func (l *Loader) LoadPath(path string) ([]*models.AISecurityPolicy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy loader: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return l.LoadDir(path)
	}
	p, err := l.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return []*models.AISecurityPolicy{p}, nil
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Validate checks that a parsed AISecurityPolicy is structurally correct.
func Validate(p *models.AISecurityPolicy) error {
	if p.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if p.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if p.Kind != "AISecurityPolicy" {
		return fmt.Errorf("unexpected kind %q, expected AISecurityPolicy", p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}

	// Validate enforcement mode if set.
	if p.Spec.Mode != "" {
		switch p.Spec.Mode {
		case models.ModeOff, models.ModeDiscover, models.ModeMonitor, models.ModeEnforce:
			// ok
		default:
			return fmt.Errorf("invalid enforcement mode %q", p.Spec.Mode)
		}
	}

	// Validate provider policy: deny and allow should not both contain the
	// same entry.
	if pp := p.Spec.Providers; pp != nil {
		if overlap := listOverlap(pp.Allow, pp.Deny); overlap != "" {
			return fmt.Errorf("provider %q appears in both allow and deny lists", overlap)
		}
	}

	// Validate model policy similarly.
	if mp := p.Spec.Models; mp != nil {
		if overlap := listOverlap(mp.Allow, mp.Deny); overlap != "" {
			return fmt.Errorf("model %q appears in both allow and deny lists", overlap)
		}
	}

	// Rate limit values must be non-negative.
	if rl := p.Spec.RateLimits; rl != nil {
		if err := validateRateLimit("per_user", rl.PerUser); err != nil {
			return err
		}
		if err := validateRateLimit("per_service", rl.PerService); err != nil {
			return err
		}
		if err := validateRateLimit("per_namespace", rl.PerNamespace); err != nil {
			return err
		}
	}

	return nil
}

// listOverlap returns the first element that appears in both lists, or "".
func listOverlap(a, b []string) string {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return v
		}
	}
	return ""
}

// validateRateLimit checks that individual limit values are non-negative.
func validateRateLimit(label string, rl *models.RateLimit) error {
	if rl == nil {
		return nil
	}
	if rl.RequestsPerMinute < 0 {
		return fmt.Errorf("rate_limits.%s.requests_per_minute must be >= 0", label)
	}
	if rl.RequestsPerHour < 0 {
		return fmt.Errorf("rate_limits.%s.requests_per_hour must be >= 0", label)
	}
	if rl.RequestsPerDay < 0 {
		return fmt.Errorf("rate_limits.%s.requests_per_day must be >= 0", label)
	}
	if rl.TokensPerDay < 0 {
		return fmt.Errorf("rate_limits.%s.tokens_per_day must be >= 0", label)
	}
	if rl.CostPerDayUSD < 0 {
		return fmt.Errorf("rate_limits.%s.cost_per_day_usd must be >= 0", label)
	}
	if rl.CostPerMonthUSD < 0 {
		return fmt.Errorf("rate_limits.%s.cost_per_month_usd must be >= 0", label)
	}
	return nil
}

// ---------------------------------------------------------------------------
// File watching / hot-reload
// ---------------------------------------------------------------------------

// Watch starts monitoring the given directory for file changes. When a YAML
// file is created, modified, or removed the callback is invoked with the
// freshly loaded policy set. The caller should use the callback to swap
// policies in the engine (e.g. via PolicyEngine.SetPolicies).
//
// Only one watch can be active at a time. Call StopWatch to stop.
func (l *Loader) Watch(dir string, onChange func([]*models.AISecurityPolicy)) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.watching {
		return fmt.Errorf("policy loader: already watching")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("policy loader: create watcher: %w", err)
	}

	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("policy loader: watch %s: %w", dir, err)
	}

	l.watcher = watcher
	l.stopCh = make(chan struct{})
	l.watching = true

	go l.watchLoop(dir, onChange)

	l.logger.Info("watching policy directory for changes", "dir", dir)
	return nil
}

// StopWatch stops the file watcher. It is safe to call even if no watcher is
// running.
func (l *Loader) StopWatch() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.watching {
		return
	}
	close(l.stopCh)
	l.watcher.Close()
	l.watching = false
	l.logger.Info("stopped policy directory watcher")
}

// watchLoop is the background goroutine that processes fsnotify events.
func (l *Loader) watchLoop(dir string, onChange func([]*models.AISecurityPolicy)) {
	for {
		select {
		case <-l.stopCh:
			return

		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			// Only react to YAML files.
			ext := strings.ToLower(filepath.Ext(event.Name))
			if ext != ".yaml" && ext != ".yml" {
				continue
			}

			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}

			l.logger.Info("policy file changed, reloading",
				"file", event.Name,
				"op", event.Op.String(),
			)

			policies, err := l.LoadDir(dir)
			if err != nil {
				l.logger.Error("hot-reload failed", "error", err)
				continue
			}
			onChange(policies)

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			l.logger.Error("policy watcher error", "error", err)
		}
	}
}
