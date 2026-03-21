// Package calibration provides confidence score calibration utilities for
// detection rules. It adjusts raw scores based on text characteristics and
// match diversity to reduce false positives and improve signal quality.
package calibration

import "math"

// CalibrateConfidence adjusts a raw detection score based on the number of
// matches, the length of the scanned text, and the number of distinct
// pattern categories that matched. The returned value is clamped to [0, 1].
//
// Calibration rules:
//   - Short texts (<20 chars) with a single match: dampen score by 0.7
//   - Long texts (>500 chars) with multiple matches: boost by 1.1 (cap 1.0)
//   - Multiple diverse category matches: boost by 0.1 per additional category
func CalibrateConfidence(rawScore float64, matchCount int, textLength int, categoryCount int) float64 {
	score := rawScore

	// Short text dampening: a single hit in a very short string is likely
	// a false positive or low-confidence match.
	if textLength < 20 && matchCount <= 1 {
		score *= 0.7
	}

	// Long text with multiple matches: the repeated signal is stronger
	// evidence of a real threat.
	if textLength > 500 && matchCount > 1 {
		score *= 1.1
	}

	// Category diversity boost: matches across different pattern families
	// are a strong indicator of intentional attack.
	if categoryCount > 1 {
		score += 0.1 * float64(categoryCount-1)
	}

	// Clamp to [0, 1].
	score = math.Max(0, math.Min(score, 1.0))

	return score
}
