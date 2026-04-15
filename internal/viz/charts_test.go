package viz

import (
	"os"
	"path/filepath"
	"testing"

	"gonum.org/v1/plot/vg"
)

func TestCreateSeverityPieData(t *testing.T) {
	dist := SeverityDistribution{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
		Unknown:  1,
	}

	data := CreateSeverityPieData(dist)
	if len(data) != 5 {
		t.Fatalf("expected 5 bars, got %d", len(data))
	}

	if data[0].Label != "Critical" || data[0].Value != 1 {
		t.Errorf("unexpected Critical bar: %+v", data[0])
	}

	if data[len(data)-1].Label != "Unknown" {
		t.Errorf("expected Unknown bar, got %s", data[len(data)-1].Label)
	}
}

func TestBucketScores(t *testing.T) {
	scores := []float64{0.10, 0.30, 0.60, 0.80}
	buckets := BucketScores(scores)

	if buckets.Low != 1 || buckets.Medium != 1 || buckets.High != 1 || buckets.Critical != 1 {
		t.Errorf("unexpected buckets: %+v", buckets)
	}
}

func TestCalculateSummaryStats(t *testing.T) {
	scores := []float64{0.10, 0.90}
	stats := CalculateSummaryStats(scores, 1, 0, 1)

	if stats.TotalVulnerabilities != 2 {
		t.Errorf("TotalVulnerabilities = %d, want 2", stats.TotalVulnerabilities)
	}
	if stats.UniqueVulnerabilities != 2 {
		t.Errorf("UniqueVulnerabilities = %d, want 2", stats.UniqueVulnerabilities)
	}
	if stats.MeanEPSS != 0.50 {
		t.Errorf("MeanEPSS = %.2f, want 0.50", stats.MeanEPSS)
	}
	if stats.MedianEPSS != 0.50 {
		t.Errorf("MedianEPSS = %.2f, want 0.50", stats.MedianEPSS)
	}
	if stats.HighRiskCount != 1 {
		t.Errorf("HighRiskCount = %d, want 1", stats.HighRiskCount)
	}
	if stats.CriticalRiskCount != 1 {
		t.Errorf("CriticalRiskCount = %d, want 1", stats.CriticalRiskCount)
	}
}

func TestCreateConsensusBarData(t *testing.T) {
	dist := ConsensusTypeDistribution{Consensus: 2, Partial: 1, Unique: 3}
	data := CreateConsensusBarData(dist)

	if len(data) != 3 {
		t.Fatalf("expected 3 bars, got %d", len(data))
	}
	if data[0].Label != "Consensus" || data[0].Value != 2 {
		t.Errorf("unexpected Consensus bar: %+v", data[0])
	}
}

func TestCreatePlotsAndSave(t *testing.T) {
	dir := t.TempDir()

	hist, err := CreateHistogram([]float64{0.1, 0.2, 0.3}, DefaultHistogramConfig())
	if err != nil {
		t.Fatalf("CreateHistogram failed: %v", err)
	}
	if err := SavePlot(hist, filepath.Join(dir, "hist.png"), 4*vg.Inch, 3*vg.Inch); err != nil {
		t.Fatalf("SavePlot histogram failed: %v", err)
	}

	bar, err := CreateBarChart([]BarData{{Label: "A", Value: 1}, {Label: "B", Value: 2}}, DefaultBarChartConfig())
	if err != nil {
		t.Fatalf("CreateBarChart failed: %v", err)
	}
	if err := SavePlot(bar, filepath.Join(dir, "bar.png"), 4*vg.Inch, 3*vg.Inch); err != nil {
		t.Fatalf("SavePlot bar failed: %v", err)
	}

	scatter, err := CreateScatterPlot([]Point{{X: 1, Y: 2}, {X: 2, Y: 3}}, DefaultScatterConfig())
	if err != nil {
		t.Fatalf("CreateScatterPlot failed: %v", err)
	}
	if err := SavePlot(scatter, filepath.Join(dir, "scatter.png"), 4*vg.Inch, 3*vg.Inch); err != nil {
		t.Fatalf("SavePlot scatter failed: %v", err)
	}

	box, err := CreateBoxPlot([]CategoryData{{Name: "A", Scores: []float64{0.1, 0.2}}}, DefaultBoxPlotConfig())
	if err != nil {
		t.Fatalf("CreateBoxPlot failed: %v", err)
	}
	if err := SavePlot(box, filepath.Join(dir, "box.png"), 4*vg.Inch, 3*vg.Inch); err != nil {
		t.Fatalf("SavePlot box failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	if len(entries) < 4 {
		t.Fatalf("expected plot files to be created")
	}
}
