// Package analysis provides statistical analysis functions for vulnerability data.
// It includes the Mann-Whitney U test for comparing EPSS score distributions.
package analysis

import (
	"fmt"
	"math"
	"sort"
)

// DescriptiveStats holds descriptive statistics for a sample.
type DescriptiveStats struct {
	N      int     // Sample size
	Min    float64 // Minimum value
	Max    float64 // Maximum value
	Mean   float64 // Arithmetic mean
	Median float64 // Median (50th percentile)
	StdDev float64 // Standard deviation (sample)
	Q1     float64 // First quartile (25th percentile)
	Q3     float64 // Third quartile (75th percentile)
	IQR    float64 // Interquartile range (Q3 - Q1)
	Sum    float64 // Sum of all values
}

// MannWhitneyResult holds the results of a Mann-Whitney U test.
type MannWhitneyResult struct {
	U1         float64 // U statistic for sample 1
	U2         float64 // U statistic for sample 2
	U          float64 // Smaller of U1 and U2
	Z          float64 // Z-score (standardized)
	PValue     float64 // Two-tailed p-value
	N1         int     // Size of sample 1
	N2         int     // Size of sample 2
	EffectSize float64 // Effect size (r = Z / sqrt(N))
}

// Compute calculates descriptive statistics for a slice of float64 values.
// Returns an error if the input slice is empty.
func Compute(data []float64) (DescriptiveStats, error) {
	if len(data) == 0 {
		return DescriptiveStats{}, fmt.Errorf("cannot compute statistics on empty data")
	}

	// Create a sorted copy
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	n := len(sorted)
	stats := DescriptiveStats{
		N:   n,
		Min: sorted[0],
		Max: sorted[n-1],
	}

	// Sum and mean
	for _, v := range sorted {
		stats.Sum += v
	}
	stats.Mean = stats.Sum / float64(n)

	// Standard deviation (sample)
	if n > 1 {
		var sumSquares float64
		for _, v := range sorted {
			diff := v - stats.Mean
			sumSquares += diff * diff
		}
		stats.StdDev = math.Sqrt(sumSquares / float64(n-1))
	}

	// Median
	stats.Median = percentile(sorted, 0.5)

	// Quartiles
	stats.Q1 = percentile(sorted, 0.25)
	stats.Q3 = percentile(sorted, 0.75)
	stats.IQR = stats.Q3 - stats.Q1

	return stats, nil
}

// percentile calculates the p-th percentile using linear interpolation.
// Assumes data is already sorted.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 1 {
		return sorted[0]
	}

	// Use linear interpolation between closest ranks
	rank := p * float64(n-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))

	if lower == upper {
		return sorted[lower]
	}

	frac := rank - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// rankedObservation is used internally for Mann-Whitney U test calculations.
type rankedObservation struct {
	value  float64
	sample int // 1 or 2
}

// MannWhitneyU performs the Mann-Whitney U test (Wilcoxon rank-sum test).
// This is a non-parametric test to compare two independent samples.
// It tests whether the distributions of the two samples are equal.
// Returns an error if either sample is empty.
func MannWhitneyU(sample1, sample2 []float64) (MannWhitneyResult, error) {
	n1, n2 := len(sample1), len(sample2)

	if n1 == 0 || n2 == 0 {
		return MannWhitneyResult{}, fmt.Errorf("both samples must be non-empty")
	}

	// Combine samples and track origin
	combined := make([]rankedObservation, 0, n1+n2)
	for _, v := range sample1 {
		combined = append(combined, rankedObservation{value: v, sample: 1})
	}
	for _, v := range sample2 {
		combined = append(combined, rankedObservation{value: v, sample: 2})
	}

	// Sort by value
	sort.Slice(combined, func(i, j int) bool {
		return combined[i].value < combined[j].value
	})

	// Assign ranks (handle ties by using average rank)
	ranks := make([]float64, len(combined))
	i := 0
	for i < len(combined) {
		// Find all tied values
		j := i
		for j < len(combined) && combined[j].value == combined[i].value {
			j++
		}

		// Average rank for ties
		avgRank := float64(i+j+1) / 2.0 // +1 because ranks are 1-indexed
		for k := i; k < j; k++ {
			ranks[k] = avgRank
		}
		i = j
	}

	// Sum ranks for each sample
	var r1, r2 float64
	for i, obs := range combined {
		if obs.sample == 1 {
			r1 += ranks[i]
		} else {
			r2 += ranks[i]
		}
	}

	// Calculate U statistics
	// U1 = n1*n2 + n1*(n1+1)/2 - R1
	// U2 = n1*n2 + n2*(n2+1)/2 - R2
	u1 := float64(n1*n2) + float64(n1*(n1+1))/2 - r1
	u2 := float64(n1*n2) + float64(n2*(n2+1))/2 - r2

	// Smaller U is the test statistic
	u := math.Min(u1, u2)

	// For large samples, U is approximately normal
	// Mean: μU = n1*n2/2
	// Std: σU = sqrt(n1*n2*(n1+n2+1)/12)
	n := float64(n1 + n2)
	meanU := float64(n1*n2) / 2

	// Tie correction factor
	tieCorrection := tieCorrectionFactor(combined)
	stdU := math.Sqrt(float64(n1*n2) * ((n + 1) - tieCorrection/(n*(n-1))) / 12)

	// Z-score with continuity correction
	var z float64
	if stdU > 0 {
		// Apply continuity correction
		if u > meanU {
			z = (u - 0.5 - meanU) / stdU
		} else {
			z = (u + 0.5 - meanU) / stdU
		}
	}

	// Two-tailed p-value using normal approximation
	pValue := 2 * normalCDF(-math.Abs(z))

	// Effect size: r = Z / sqrt(N)
	effectSize := z / math.Sqrt(n)

	return MannWhitneyResult{
		U1:         u1,
		U2:         u2,
		U:          u,
		Z:          z,
		PValue:     pValue,
		N1:         n1,
		N2:         n2,
		EffectSize: math.Abs(effectSize),
	}, nil
}

// tieCorrectionFactor calculates the tie correction for the variance.
// Returns sum of (t^3 - t) for each group of ties.
func tieCorrectionFactor(sorted []rankedObservation) float64 {
	var correction float64
	i := 0
	for i < len(sorted) {
		// Count ties
		j := i
		for j < len(sorted) && sorted[j].value == sorted[i].value {
			j++
		}
		t := float64(j - i)
		if t > 1 {
			correction += t*t*t - t
		}
		i = j
	}
	return correction
}

// normalCDF calculates the cumulative distribution function of the standard normal.
func normalCDF(x float64) float64 {
	return 0.5 * (1 + erf(x/math.Sqrt2))
}

// erf calculates the error function using Horner's method approximation.
// This is accurate to about 1.5×10^-7.
func erf(x float64) float64 {
	// Constants
	a1 := 0.254829592
	a2 := -0.284496736
	a3 := 1.421413741
	a4 := -1.453152027
	a5 := 1.061405429
	p := 0.3275911

	// Save the sign
	sign := 1.0
	if x < 0 {
		sign = -1
	}
	x = math.Abs(x)

	// A&S formula 7.1.26
	t := 1.0 / (1.0 + p*x)
	y := 1.0 - (((((a5*t+a4)*t)+a3)*t+a2)*t+a1)*t*math.Exp(-x*x)

	return sign * y
}

// EffectSizeInterpretation returns a string interpretation of the effect size.
// Based on Cohen's conventions: small (0.1), medium (0.3), large (0.5).
func EffectSizeInterpretation(r float64) string {
	r = math.Abs(r)
	switch {
	case r < 0.1:
		return "negligible"
	case r < 0.3:
		return "small"
	case r < 0.5:
		return "medium"
	default:
		return "large"
	}
}

// SignificanceLevel returns a string representation of the p-value significance.
func SignificanceLevel(p float64) string {
	switch {
	case p < 0.001:
		return "***"
	case p < 0.01:
		return "**"
	case p < 0.05:
		return "*"
	default:
		return "ns"
	}
}

// CategoryComparison holds the results of comparing two categories.
type CategoryComparison struct {
	Category1  string
	Category2  string
	Stats1     DescriptiveStats
	Stats2     DescriptiveStats
	TestResult MannWhitneyResult
}

// CompareCategoryDistributions compares EPSS score distributions between two categories.
func CompareCategoryDistributions(
	category1 string, scores1 []float64,
	category2 string, scores2 []float64,
) (CategoryComparison, error) {
	stats1, err := Compute(scores1)
	if err != nil {
		return CategoryComparison{}, fmt.Errorf("computing stats for %s: %w", category1, err)
	}

	stats2, err := Compute(scores2)
	if err != nil {
		return CategoryComparison{}, fmt.Errorf("computing stats for %s: %w", category2, err)
	}

	testResult, err := MannWhitneyU(scores1, scores2)
	if err != nil {
		return CategoryComparison{}, fmt.Errorf("Mann-Whitney U test: %w", err)
	}

	return CategoryComparison{
		Category1:  category1,
		Category2:  category2,
		Stats1:     stats1,
		Stats2:     stats2,
		TestResult: testResult,
	}, nil
}

// IsSignificant returns true if the Mann-Whitney U test result is significant at the given alpha level.
func (r MannWhitneyResult) IsSignificant(alpha float64) bool {
	return r.PValue < alpha
}

// String returns a formatted string representation of the comparison.
func (c CategoryComparison) String() string {
	sig := SignificanceLevel(c.TestResult.PValue)
	effect := EffectSizeInterpretation(c.TestResult.EffectSize)

	return fmt.Sprintf(
		"%s (n=%d, median=%.4f) vs %s (n=%d, median=%.4f): U=%.1f, Z=%.3f, p=%.4f %s, r=%.3f (%s)",
		c.Category1, c.Stats1.N, c.Stats1.Median,
		c.Category2, c.Stats2.N, c.Stats2.Median,
		c.TestResult.U, c.TestResult.Z, c.TestResult.PValue, sig,
		c.TestResult.EffectSize, effect,
	)
}
