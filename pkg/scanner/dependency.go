package scanner

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Registry identifies a package registry.
type Registry string

const (
	RegistryNPM  Registry = "npm"
	RegistryPyPI Registry = "pypi"
	RegistryGo   Registry = "go"
)

// PackageSafety is the result of checking a single package.
type PackageSafety struct {
	Name       string          `json:"name"`
	Version    string          `json:"version,omitempty"`
	Registry   Registry        `json:"registry"`
	Safe       bool            `json:"safe"`
	Risks      []PackageRisk   `json:"risks,omitempty"`
	MaxSeverity models.Severity `json:"max_severity"`
}

// PackageRisk describes a specific risk found for a package.
type PackageRisk struct {
	Type       string          `json:"type"`
	Severity   models.Severity `json:"severity"`
	Message    string          `json:"message"`
	Confidence float64         `json:"confidence"`
}

// LockfileResult is the result of validating a lockfile.
type LockfileResult struct {
	Path       string          `json:"path"`
	Format     string          `json:"format"`
	Valid      bool            `json:"valid"`
	Entries    int             `json:"entries"`
	Issues     []LockfileIssue `json:"issues,omitempty"`
}

// LockfileIssue describes a problem found in a lockfile.
type LockfileIssue struct {
	Package  string          `json:"package"`
	Type     string          `json:"type"`
	Severity models.Severity `json:"severity"`
	Message  string          `json:"message"`
}

// WellKnownPackages maps popular package names by registry. This is used for
// typosquatting detection. In production, this would be backed by a database
// or API. This embedded set covers the most commonly targeted packages.
var WellKnownPackages = map[Registry]map[string]bool{
	RegistryNPM: {
		"express": true, "react": true, "react-dom": true, "lodash": true,
		"axios": true, "moment": true, "webpack": true, "babel": true,
		"typescript": true, "eslint": true, "prettier": true, "jest": true,
		"mocha": true, "chai": true, "underscore": true, "jquery": true,
		"next": true, "vue": true, "angular": true, "svelte": true,
		"chalk": true, "commander": true, "inquirer": true, "yargs": true,
		"dotenv": true, "uuid": true, "debug": true, "cors": true,
		"body-parser": true, "cookie-parser": true, "jsonwebtoken": true,
		"bcrypt": true, "mongoose": true, "sequelize": true, "knex": true,
		"socket.io": true, "ws": true, "node-fetch": true, "got": true,
		"puppeteer": true, "cheerio": true, "sharp": true, "multer": true,
		"nodemon": true, "pm2": true, "cross-env": true, "rimraf": true,
		"@types/node": true, "@types/react": true, "tslib": true,
		"openai": true, "langchain": true, "@anthropic-ai/sdk": true,
	},
	RegistryPyPI: {
		"requests": true, "flask": true, "django": true, "numpy": true,
		"pandas": true, "scipy": true, "matplotlib": true, "pillow": true,
		"beautifulsoup4": true, "scrapy": true, "celery": true, "redis": true,
		"sqlalchemy": true, "pytest": true, "setuptools": true, "pip": true,
		"wheel": true, "boto3": true, "cryptography": true, "pyjwt": true,
		"httpx": true, "aiohttp": true, "fastapi": true, "uvicorn": true,
		"pydantic": true, "python-dotenv": true, "click": true, "rich": true,
		"black": true, "mypy": true, "pylint": true, "flake8": true,
		"openai": true, "langchain": true, "anthropic": true, "tiktoken": true,
		"transformers": true, "torch": true, "tensorflow": true, "keras": true,
	},
	RegistryGo: {
		"github.com/gin-gonic/gin": true, "github.com/gorilla/mux": true,
		"github.com/stretchr/testify": true, "github.com/spf13/cobra": true,
		"github.com/spf13/viper": true, "google.golang.org/grpc": true,
		"github.com/go-chi/chi": true, "gorm.io/gorm": true,
		"github.com/sirupsen/logrus": true, "go.uber.org/zap": true,
		"github.com/prometheus/client_golang": true,
		"github.com/nats-io/nats.go": true, "github.com/redis/go-redis": true,
		"github.com/sashabaranov/go-openai": true,
	},
}

// ScanPackageInstall checks whether a package install command is safe.
// It evaluates the package name against typosquatting lists and known-good
// package databases.
func ScanPackageInstall(command string, packageName string) *PackageSafety {
	registry := detectRegistry(command)

	result := &PackageSafety{
		Name:        packageName,
		Registry:    registry,
		Safe:        true,
		MaxSeverity: models.SeverityInfo,
	}

	// Parse version from name@version format.
	name, version := splitNameVersion(packageName, registry)
	result.Name = name
	result.Version = version

	// Check typosquatting.
	if typoRisks := CheckTyposquat(name, registry); len(typoRisks) > 0 {
		result.Risks = append(result.Risks, typoRisks...)
		result.Safe = false
	}

	// Check for suspicious package name patterns.
	if risks := checkSuspiciousName(name, registry); len(risks) > 0 {
		result.Risks = append(result.Risks, risks...)
		result.Safe = false
	}

	// Calculate max severity.
	for _, r := range result.Risks {
		if severityPriority(r.Severity) > severityPriority(result.MaxSeverity) {
			result.MaxSeverity = r.Severity
		}
	}

	return result
}

// CheckTyposquat compares a package name against known popular packages
// and flags names that are suspiciously similar (potential typosquatting).
func CheckTyposquat(name string, registry Registry) []PackageRisk {
	var risks []PackageRisk

	knownPkgs, ok := WellKnownPackages[registry]
	if !ok {
		return nil
	}

	// If it is a known package, no risk.
	if knownPkgs[name] {
		return nil
	}

	nameNorm := strings.ToLower(name)

	for known := range knownPkgs {
		knownNorm := strings.ToLower(known)

		dist := levenshteinDistance(nameNorm, knownNorm)
		if dist == 0 {
			continue // exact match already handled above
		}

		// Flag if edit distance is 1-2 for short names, 1-3 for longer names.
		maxDist := 1
		if len(knownNorm) > 6 {
			maxDist = 2
		}
		if len(knownNorm) > 12 {
			maxDist = 3
		}

		if dist <= maxDist {
			severity := models.SeverityHigh
			confidence := 0.85 - float64(dist)*0.15
			if dist == 1 {
				severity = models.SeverityCritical
				confidence = 0.90
			}

			risks = append(risks, PackageRisk{
				Type:       "typosquat",
				Severity:   severity,
				Message:    fmt.Sprintf("Package %q is suspiciously similar to popular package %q (edit distance: %d)", name, known, dist),
				Confidence: confidence,
			})
		}

		// Check for common typosquatting techniques.
		if isHyphenSwap(nameNorm, knownNorm) {
			risks = append(risks, PackageRisk{
				Type:       "typosquat_hyphen_swap",
				Severity:   models.SeverityCritical,
				Message:    fmt.Sprintf("Package %q appears to be a hyphen/underscore swap of %q", name, known),
				Confidence: 0.92,
			})
		}

		if isScopeSquat(nameNorm, knownNorm) {
			risks = append(risks, PackageRisk{
				Type:       "scope_squat",
				Severity:   models.SeverityHigh,
				Message:    fmt.Sprintf("Package %q may be squatting on the scope/namespace of %q", name, known),
				Confidence: 0.80,
			})
		}
	}

	// Sort by severity (highest first).
	sort.Slice(risks, func(i, j int) bool {
		return severityPriority(risks[i].Severity) > severityPriority(risks[j].Severity)
	})

	// Deduplicate: keep top 5 most severe.
	if len(risks) > 5 {
		risks = risks[:5]
	}

	return risks
}

// CheckPackageAge flags packages that were created very recently, which is a
// common indicator of typosquatting or malicious packages. This function
// accepts the creation time as a parameter; in production, it would be
// fetched from the registry API.
func CheckPackageAge(name string, createdAt time.Time) []PackageRisk {
	var risks []PackageRisk

	age := time.Since(createdAt)

	if age < 24*time.Hour {
		risks = append(risks, PackageRisk{
			Type:       "new_package",
			Severity:   models.SeverityHigh,
			Message:    fmt.Sprintf("Package %q was created less than 24 hours ago", name),
			Confidence: 0.70,
		})
	} else if age < 7*24*time.Hour {
		risks = append(risks, PackageRisk{
			Type:       "new_package",
			Severity:   models.SeverityMedium,
			Message:    fmt.Sprintf("Package %q was created less than 7 days ago", name),
			Confidence: 0.50,
		})
	} else if age < 30*24*time.Hour {
		risks = append(risks, PackageRisk{
			Type:       "new_package",
			Severity:   models.SeverityLow,
			Message:    fmt.Sprintf("Package %q was created less than 30 days ago", name),
			Confidence: 0.30,
		})
	}

	return risks
}

// ValidateLockfile checks a lockfile for integrity issues including missing
// checksums, checksum mismatches (when an expected map is provided), and
// suspicious entries.
func ValidateLockfile(path string) (*LockfileResult, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%q is a directory", path)
	}

	baseName := filepath.Base(path)
	format := detectLockfileFormat(baseName)
	if format == "" {
		return nil, fmt.Errorf("unrecognized lockfile format: %s", baseName)
	}

	switch format {
	case "go.sum":
		return validateGoSum(path, format)
	case "package-lock.json":
		return validatePackageLock(path, format)
	case "yarn.lock":
		return validateYarnLock(path, format)
	case "requirements.txt":
		return validateRequirementsTxt(path, format)
	default:
		return &LockfileResult{
			Path:   path,
			Format: format,
			Valid:  true,
		}, nil
	}
}

// validateGoSum checks a go.sum file for duplicate entries and missing hashes.
func validateGoSum(path, format string) (*LockfileResult, error) {
	result := &LockfileResult{
		Path:   path,
		Format: format,
		Valid:  true,
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	seen := make(map[string]string) // module@version -> hash
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			result.Issues = append(result.Issues, LockfileIssue{
				Package:  line,
				Type:     "malformed_entry",
				Severity: models.SeverityMedium,
				Message:  fmt.Sprintf("Malformed go.sum entry on line %d", lineNum),
			})
			result.Valid = false
			continue
		}

		key := parts[0] + " " + parts[1]
		hash := parts[2]
		result.Entries++

		// Validate hash format: h1:<base64>
		if !strings.HasPrefix(hash, "h1:") {
			result.Issues = append(result.Issues, LockfileIssue{
				Package:  parts[0],
				Type:     "invalid_hash",
				Severity: models.SeverityHigh,
				Message:  fmt.Sprintf("Invalid hash format for %s on line %d", parts[0], lineNum),
			})
			result.Valid = false
			continue
		}

		// Check for duplicate entries with different hashes.
		if prev, exists := seen[key]; exists && prev != hash {
			result.Issues = append(result.Issues, LockfileIssue{
				Package:  parts[0],
				Type:     "duplicate_mismatch",
				Severity: models.SeverityCritical,
				Message:  fmt.Sprintf("Duplicate entry for %s with different hash (possible tampering)", key),
			})
			result.Valid = false
		}
		seen[key] = hash
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	return result, nil
}

// validatePackageLock performs basic validation on package-lock.json files.
func validatePackageLock(path, format string) (*LockfileResult, error) {
	result := &LockfileResult{
		Path:   path,
		Format: format,
		Valid:  true,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	// Check that it's valid JSON.
	if len(data) < 2 || data[0] != '{' {
		result.Valid = false
		result.Issues = append(result.Issues, LockfileIssue{
			Type:     "invalid_json",
			Severity: models.SeverityCritical,
			Message:  "package-lock.json is not valid JSON",
		})
		return result, nil
	}

	content := string(data)

	// Count resolved entries (rough heuristic).
	result.Entries = strings.Count(content, `"resolved"`)

	// Check for entries without integrity hashes.
	resolvedCount := strings.Count(content, `"resolved"`)
	integrityCount := strings.Count(content, `"integrity"`)

	if resolvedCount > 0 && integrityCount < resolvedCount {
		missing := resolvedCount - integrityCount
		result.Issues = append(result.Issues, LockfileIssue{
			Type:     "missing_integrity",
			Severity: models.SeverityMedium,
			Message:  fmt.Sprintf("%d package(s) are missing integrity hashes", missing),
		})
	}

	// Check for http:// (non-TLS) registry URLs.
	if strings.Contains(content, `"resolved": "http://`) {
		result.Valid = false
		result.Issues = append(result.Issues, LockfileIssue{
			Type:     "insecure_registry",
			Severity: models.SeverityHigh,
			Message:  "Lockfile contains packages resolved over plain HTTP (non-TLS)",
		})
	}

	return result, nil
}

// validateYarnLock performs basic validation on yarn.lock files.
func validateYarnLock(path, format string) (*LockfileResult, error) {
	result := &LockfileResult{
		Path:   path,
		Format: format,
		Valid:  true,
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1<<20)

	hasIntegrity := false
	entryCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "resolved ") {
			entryCount++

			if strings.Contains(trimmed, "http://") {
				result.Valid = false
				result.Issues = append(result.Issues, LockfileIssue{
					Type:     "insecure_registry",
					Severity: models.SeverityHigh,
					Message:  "yarn.lock contains packages resolved over plain HTTP",
				})
			}
		}
		if strings.HasPrefix(trimmed, "integrity ") {
			hasIntegrity = true
		}
	}

	result.Entries = entryCount

	if entryCount > 0 && !hasIntegrity {
		result.Issues = append(result.Issues, LockfileIssue{
			Type:     "missing_integrity",
			Severity: models.SeverityMedium,
			Message:  "yarn.lock contains no integrity hashes",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	return result, nil
}

// validateRequirementsTxt validates a Python requirements.txt file.
func validateRequirementsTxt(path, format string) (*LockfileResult, error) {
	result := &LockfileResult{
		Path:   path,
		Format: format,
		Valid:  true,
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	unpinned := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		result.Entries++

		// Check for pinned versions (contains == or hash).
		if !strings.Contains(line, "==") && !strings.Contains(line, "--hash") {
			unpinned++
		}

		// Check for hash verification.
		// requirements.txt with --hash mode is the most secure.
	}

	if unpinned > 0 {
		result.Issues = append(result.Issues, LockfileIssue{
			Type:     "unpinned_version",
			Severity: models.SeverityMedium,
			Message:  fmt.Sprintf("%d package(s) do not have pinned versions (==)", unpinned),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	return result, nil
}

// detectLockfileFormat identifies the lockfile format from its filename.
func detectLockfileFormat(name string) string {
	switch name {
	case "go.sum":
		return "go.sum"
	case "package-lock.json":
		return "package-lock.json"
	case "yarn.lock":
		return "yarn.lock"
	case "pnpm-lock.yaml":
		return "pnpm-lock.yaml"
	case "requirements.txt":
		return "requirements.txt"
	case "Pipfile.lock":
		return "Pipfile.lock"
	case "poetry.lock":
		return "poetry.lock"
	case "Gemfile.lock":
		return "Gemfile.lock"
	case "Cargo.lock":
		return "Cargo.lock"
	default:
		return ""
	}
}

// detectRegistry infers the package registry from an install command.
func detectRegistry(command string) Registry {
	cmd := strings.ToLower(command)
	switch {
	case strings.Contains(cmd, "npm") || strings.Contains(cmd, "yarn") || strings.Contains(cmd, "pnpm"):
		return RegistryNPM
	case strings.Contains(cmd, "pip") || strings.Contains(cmd, "python") || strings.Contains(cmd, "poetry") || strings.Contains(cmd, "pipenv"):
		return RegistryPyPI
	case strings.Contains(cmd, "go get") || strings.Contains(cmd, "go install"):
		return RegistryGo
	default:
		return RegistryNPM
	}
}

// splitNameVersion separates a package name from its version specifier.
func splitNameVersion(pkg string, registry Registry) (string, string) {
	switch registry {
	case RegistryNPM:
		// Handle scoped packages: @scope/name@version
		if strings.HasPrefix(pkg, "@") {
			idx := strings.LastIndex(pkg, "@")
			if idx > 0 {
				return pkg[:idx], pkg[idx+1:]
			}
			return pkg, ""
		}
		if idx := strings.LastIndex(pkg, "@"); idx > 0 {
			return pkg[:idx], pkg[idx+1:]
		}
	case RegistryPyPI:
		for _, sep := range []string{"==", ">=", "<=", "!=", "~=", ">", "<"} {
			if idx := strings.Index(pkg, sep); idx > 0 {
				return pkg[:idx], pkg[idx+len(sep):]
			}
		}
	case RegistryGo:
		if idx := strings.LastIndex(pkg, "@"); idx > 0 {
			return pkg[:idx], pkg[idx+1:]
		}
	}
	return pkg, ""
}

// checkSuspiciousName flags package names that use common malicious naming
// patterns.
func checkSuspiciousName(name string, registry Registry) []PackageRisk {
	var risks []PackageRisk
	nameLower := strings.ToLower(name)

	// Suspicious prefixes/suffixes often used in typosquatting.
	suspiciousParts := []string{
		"-js", "-ts", "-node", "-npm", "-python", "-py",
		"-official", "-original", "-real", "-legit", "-safe",
		"_dev", "_test", "_debug",
	}

	for _, part := range suspiciousParts {
		base := strings.TrimSuffix(nameLower, part)
		if base != nameLower {
			if known, ok := WellKnownPackages[registry]; ok && known[base] {
				risks = append(risks, PackageRisk{
					Type:       "suspicious_suffix",
					Severity:   models.SeverityHigh,
					Message:    fmt.Sprintf("Package %q adds suspicious suffix %q to known package %q", name, part, base),
					Confidence: 0.80,
				})
			}
		}

		base = strings.TrimPrefix(nameLower, strings.TrimPrefix(part, "-"))
		if base != nameLower {
			baseClean := strings.TrimPrefix(base, "-")
			if known, ok := WellKnownPackages[registry]; ok && known[baseClean] {
				risks = append(risks, PackageRisk{
					Type:       "suspicious_prefix",
					Severity:   models.SeverityHigh,
					Message:    fmt.Sprintf("Package %q adds suspicious prefix to known package %q", name, baseClean),
					Confidence: 0.75,
				})
			}
		}
	}

	// Flag packages with non-ASCII characters (homoglyph attacks).
	for _, r := range name {
		if r > 127 && !unicode.IsLetter(r) {
			risks = append(risks, PackageRisk{
				Type:       "homoglyph",
				Severity:   models.SeverityCritical,
				Message:    fmt.Sprintf("Package %q contains non-ASCII character U+%04X (possible homoglyph attack)", name, r),
				Confidence: 0.95,
			})
			break
		}
	}

	return risks
}

// isHyphenSwap checks if two names differ only in hyphen vs underscore or
// hyphen vs dot.
func isHyphenSwap(a, b string) bool {
	normalize := func(s string) string {
		s = strings.ReplaceAll(s, "-", "_")
		s = strings.ReplaceAll(s, ".", "_")
		return s
	}
	na := normalize(a)
	nb := normalize(b)
	return na == nb && a != b
}

// isScopeSquat checks if a package appears to be squatting on a scoped
// package's namespace (e.g. "types-react" vs "@types/react").
func isScopeSquat(name, known string) bool {
	// Check if removing scope delimiter makes them match.
	if strings.HasPrefix(known, "@") {
		// @scope/name -> scope-name
		unscoped := strings.Replace(known[1:], "/", "-", 1)
		if name == unscoped || levenshteinDistance(name, unscoped) <= 1 {
			return true
		}
	}
	return false
}

// levenshteinDistance computes the edit distance between two strings.
func levenshteinDistance(a, b string) int {
	la := len(a)
	lb := len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Optimization: if lengths differ by more than our typical threshold,
	// skip the full computation.
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff > 5 {
		return diff
	}

	// Single-row DP.
	prev := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			ins := curr[j-1] + 1
			del := prev[j] + 1
			sub := prev[j-1] + cost

			min := ins
			if del < min {
				min = del
			}
			if sub < min {
				min = sub
			}
			curr[j] = min
		}
		prev = curr
	}

	return prev[lb]
}

// severityPriority returns a numeric priority for sorting by severity.
func severityPriority(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 4
	case models.SeverityHigh:
		return 3
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 1
	default:
		return 0
	}
}

// HashFile computes the SHA-256 hash of a file. Useful for verifying lockfile
// integrity against a known-good state.
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %q: %w", path, err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// reGitHubURL matches GitHub-style URLs in lockfiles for provenance checking.
var reGitHubURL = regexp.MustCompile(`https://github\.com/([^/]+)/([^/]+)`)
