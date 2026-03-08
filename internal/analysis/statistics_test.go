package analysis

import (
	"math"
	"testing"
)

func TestCompute(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		_, err := Compute([]float64{})
		if err == nil {
			t.Error("expected error for empty data")
		}
	})

	t.Run("single value", func(t *testing.T) {
		stats, err := Compute([]float64{5.0})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stats.N != 1 {
			t.Errorf("expected N=1, got %d", stats.N)
		}
		if stats.Mean != 5.0 {
			t.Errorf("expected Mean=5.0, got %f", stats.Mean)
		}
		if stats.Median != 5.0 {
			t.Errorf("expected Median=5.0, got %f", stats.Median)
		}
		if stats.Min != 5.0 {
			t.Errorf("expected Min=5.0, got %f", stats.Min)
		}
		if stats.Max != 5.0 {
			t.Errorf("expected Max=5.0, got %f", stats.Max)
		}
	})

	t.Run("known values", func(t *testing.T) {
		// Data: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
		data := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		stats, err := Compute(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if stats.N != 10 {
			t.Errorf("expected N=10, got %d", stats.N)
		}
		if stats.Min != 1.0 {
			t.Errorf("expected Min=1.0, got %f", stats.Min)
		}
		if stats.Max != 10.0 {
			t.Errorf("expected Max=10.0, got %f", stats.Max)
		}
		if stats.Sum != 55.0 {
			t.Errorf("expected Sum=55.0, got %f", stats.Sum)
		}
		if stats.Mean != 5.5 {
			t.Errorf("expected Mean=5.5, got %f", stats.Mean)
		}
		if stats.Median != 5.5 {
			t.Errorf("expected Median=5.5, got %f", stats.Median)
		}

		// Q1 should be around 3.25, Q3 should be around 7.75
		if math.Abs(stats.Q1-3.25) > 0.01 {
			t.Errorf("expected Q1~3.25, got %f", stats.Q1)
		}
		if math.Abs(stats.Q3-7.75) > 0.01 {
			t.Errorf("expected Q3~7.75, got %f", stats.Q3)
		}
		if math.Abs(stats.IQR-4.5) > 0.01 {
			t.Errorf("expected IQR~4.5, got %f", stats.IQR)
		}

		// Standard deviation for 1-10 is approximately 3.0277
		if math.Abs(stats.StdDev-3.0277) > 0.01 {
			t.Errorf("expected StdDev~3.0277, got %f", stats.StdDev)
		}
	})

	t.Run("unsorted input", func(t *testing.T) {
		// Input is not sorted
		data := []float64{5, 1, 9, 3, 7, 2, 8, 4, 6, 10}
		stats, err := Compute(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if stats.Min != 1.0 {
			t.Errorf("expected Min=1.0, got %f", stats.Min)
		}
		if stats.Max != 10.0 {
			t.Errorf("expected Max=10.0, got %f", stats.Max)
		}
		if stats.Mean != 5.5 {
			t.Errorf("expected Mean=5.5, got %f", stats.Mean)
		}
	})
}

func TestMannWhitneyU(t *testing.T) {
	t.Run("empty samples", func(t *testing.T) {
		_, err := MannWhitneyU([]float64{}, []float64{1, 2, 3})
		if err == nil {
			t.Error("expected error for empty sample1")
		}

		_, err = MannWhitneyU([]float64{1, 2, 3}, []float64{})
		if err == nil {
			t.Error("expected error for empty sample2")
		}
	})

	t.Run("identical distributions", func(t *testing.T) {
		// Two samples from the same distribution should have high p-value
		sample1 := []float64{1, 2, 3, 4, 5}
		sample2 := []float64{1, 2, 3, 4, 5}

		result, err := MannWhitneyU(sample1, sample2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// P-value should be high (not significant)
		if result.PValue < 0.05 {
			t.Errorf("expected high p-value for identical distributions, got %f", result.PValue)
		}
	})

	t.Run("significantly different distributions", func(t *testing.T) {
		// Sample 1: low values, Sample 2: high values
		sample1 := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		sample2 := []float64{11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

		result, err := MannWhitneyU(sample1, sample2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// P-value should be very low (significant)
		if result.PValue > 0.01 {
			t.Errorf("expected low p-value for different distributions, got %f", result.PValue)
		}

		// Effect size should be large
		if result.EffectSize < 0.5 {
			t.Errorf("expected large effect size, got %f", result.EffectSize)
		}
	})

	t.Run("known U statistic", func(t *testing.T) {
		// Small example with known values
		// Sample 1: 1, 2, 3
		// Sample 2: 4, 5, 6
		// Ranks: 1=1, 2=2, 3=3, 4=4, 5=5, 6=6
		// R1 = 1+2+3 = 6
		// U1 = 3*3 + 3*4/2 - 6 = 9 + 6 - 6 = 9
		// U2 = 3*3 + 3*4/2 - (4+5+6) = 9 + 6 - 15 = 0
		// U = min(9, 0) = 0
		sample1 := []float64{1, 2, 3}
		sample2 := []float64{4, 5, 6}

		result, err := MannWhitneyU(sample1, sample2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.U != 0 {
			t.Errorf("expected U=0, got %f", result.U)
		}
		if result.N1 != 3 || result.N2 != 3 {
			t.Errorf("expected N1=3, N2=3, got N1=%d, N2=%d", result.N1, result.N2)
		}
	})

	t.Run("with ties", func(t *testing.T) {
		// Samples with tied values
		sample1 := []float64{1, 2, 2, 3, 4}
		sample2 := []float64{2, 3, 3, 4, 5}

		result, err := MannWhitneyU(sample1, sample2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Just verify it runs without error and produces reasonable values
		if result.PValue < 0 || result.PValue > 1 {
			t.Errorf("p-value out of range: %f", result.PValue)
		}
	})
}

func TestEffectSizeInterpretation(t *testing.T) {
	tests := []struct {
		r        float64
		expected string
	}{
		{0.05, "negligible"},
		{0.09, "negligible"},
		{0.15, "small"},
		{0.29, "small"},
		{0.35, "medium"},
		{0.49, "medium"},
		{0.55, "large"},
		{0.80, "large"},
		{-0.35, "medium"}, // Should handle negative values
	}

	for _, tc := range tests {
		result := EffectSizeInterpretation(tc.r)
		if result != tc.expected {
			t.Errorf("EffectSizeInterpretation(%f): expected %s, got %s", tc.r, tc.expected, result)
		}
	}
}

func TestSignificanceLevel(t *testing.T) {
	tests := []struct {
		p        float64
		expected string
	}{
		{0.0001, "***"},
		{0.001, "**"},
		{0.005, "**"},
		{0.01, "*"},
		{0.03, "*"},
		{0.05, "ns"},
		{0.10, "ns"},
		{0.50, "ns"},
	}

	for _, tc := range tests {
		result := SignificanceLevel(tc.p)
		if result != tc.expected {
			t.Errorf("SignificanceLevel(%f): expected %s, got %s", tc.p, tc.expected, result)
		}
	}
}

func TestIsSignificant(t *testing.T) {
	result := MannWhitneyResult{PValue: 0.03}
	if !result.IsSignificant(0.05) {
		t.Error("expected significant at alpha=0.05")
	}
	if result.IsSignificant(0.01) {
		t.Error("expected not significant at alpha=0.01")
	}
}

func TestCompareCategoryDistributions(t *testing.T) {
	scores1 := []float64{0.1, 0.2, 0.15, 0.12, 0.18}
	scores2 := []float64{0.5, 0.6, 0.55, 0.52, 0.58}

	comparison, err := CompareCategoryDistributions(
		"LowRisk", scores1,
		"HighRisk", scores2,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if comparison.Category1 != "LowRisk" {
		t.Errorf("expected Category1=LowRisk, got %s", comparison.Category1)
	}
	if comparison.Category2 != "HighRisk" {
		t.Errorf("expected Category2=HighRisk, got %s", comparison.Category2)
	}
	if comparison.Stats1.N != 5 {
		t.Errorf("expected Stats1.N=5, got %d", comparison.Stats1.N)
	}
	if comparison.Stats2.N != 5 {
		t.Errorf("expected Stats2.N=5, got %d", comparison.Stats2.N)
	}

	// The distributions are clearly different, so should be significant
	if comparison.TestResult.PValue > 0.05 {
		t.Errorf("expected significant difference, got p=%f", comparison.TestResult.PValue)
	}

	// Test String() method
	s := comparison.String()
	if s == "" {
		t.Error("expected non-empty string representation")
	}
}

func TestCompareCategoryDistributions_Errors(t *testing.T) {
	t.Run("empty first category", func(t *testing.T) {
		_, err := CompareCategoryDistributions(
			"Empty", []float64{},
			"Valid", []float64{1, 2, 3},
		)
		if err == nil {
			t.Error("expected error for empty first category")
		}
	})

	t.Run("empty second category", func(t *testing.T) {
		_, err := CompareCategoryDistributions(
			"Valid", []float64{1, 2, 3},
			"Empty", []float64{},
		)
		if err == nil {
			t.Error("expected error for empty second category")
		}
	})
}

// TestNormalCDF verifies our normal CDF implementation against known values.
func TestNormalCDF(t *testing.T) {
	tests := []struct {
		x        float64
		expected float64
		tol      float64
	}{
		{0.0, 0.5, 0.001},
		{1.0, 0.8413, 0.001},
		{-1.0, 0.1587, 0.001},
		{2.0, 0.9772, 0.001},
		{-2.0, 0.0228, 0.001},
		{1.96, 0.975, 0.001},
	}

	for _, tc := range tests {
		result := normalCDF(tc.x)
		if math.Abs(result-tc.expected) > tc.tol {
			t.Errorf("normalCDF(%f): expected ~%f, got %f", tc.x, tc.expected, result)
		}
	}
}
