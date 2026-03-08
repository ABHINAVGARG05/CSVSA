// Package viz provides visualization functions for vulnerability analysis data.
// It uses gonum/plot for generating charts and graphs.
package viz

import (
	"fmt"
	"image/color"
	"sort"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

// Colors for different categories
var (
	ColorConsensus = color.RGBA{R: 76, G: 175, B: 80, A: 255}  // Green
	ColorPartial   = color.RGBA{R: 255, G: 193, B: 7, A: 255}  // Amber
	ColorUnique    = color.RGBA{R: 244, G: 67, B: 54, A: 255}  // Red
	ColorDefault   = color.RGBA{R: 33, G: 150, B: 243, A: 255} // Blue
)

// CategoryData represents data for a single category.
type CategoryData struct {
	Name   string
	Scores []float64
	Color  color.Color
}

// BoxPlotConfig configures box plot generation.
type BoxPlotConfig struct {
	Title    string
	YLabel   string
	Width    vg.Length
	Height   vg.Length
	FileName string
}

// DefaultBoxPlotConfig returns default box plot configuration.
func DefaultBoxPlotConfig() BoxPlotConfig {
	return BoxPlotConfig{
		Title:  "EPSS Score Distribution by Category",
		YLabel: "EPSS Score",
		Width:  8 * vg.Inch,
		Height: 6 * vg.Inch,
	}
}

// CreateBoxPlot creates a box plot comparing EPSS score distributions across categories.
func CreateBoxPlot(categories []CategoryData, config BoxPlotConfig) (*plot.Plot, error) {
	if len(categories) == 0 {
		return nil, fmt.Errorf("no categories provided")
	}

	p := plot.New()
	p.Title.Text = config.Title
	p.Y.Label.Text = config.YLabel
	p.Y.Min = 0
	p.Y.Max = 1

	// Create box plots for each category
	var names []string
	for i, cat := range categories {
		if len(cat.Scores) == 0 {
			continue
		}

		values := make(plotter.Values, len(cat.Scores))
		copy(values, cat.Scores)

		box, err := plotter.NewBoxPlot(vg.Points(40), float64(i), values)
		if err != nil {
			return nil, fmt.Errorf("creating box plot for %s: %w", cat.Name, err)
		}

		if cat.Color != nil {
			box.FillColor = cat.Color
		}

		p.Add(box)
		names = append(names, cat.Name)
	}

	p.NominalX(names...)

	return p, nil
}

// SavePlot saves a plot to a file.
func SavePlot(p *plot.Plot, filename string, width, height vg.Length) error {
	return p.Save(width, height, filename)
}

// HistogramConfig configures histogram generation.
type HistogramConfig struct {
	Title    string
	XLabel   string
	YLabel   string
	Bins     int
	Width    vg.Length
	Height   vg.Length
	FileName string
}

// DefaultHistogramConfig returns default histogram configuration.
func DefaultHistogramConfig() HistogramConfig {
	return HistogramConfig{
		Title:  "EPSS Score Distribution",
		XLabel: "EPSS Score",
		YLabel: "Frequency",
		Bins:   20,
		Width:  8 * vg.Inch,
		Height: 6 * vg.Inch,
	}
}

// CreateHistogram creates a histogram of EPSS scores.
func CreateHistogram(scores []float64, config HistogramConfig) (*plot.Plot, error) {
	if len(scores) == 0 {
		return nil, fmt.Errorf("no scores provided")
	}

	p := plot.New()
	p.Title.Text = config.Title
	p.X.Label.Text = config.XLabel
	p.Y.Label.Text = config.YLabel

	values := make(plotter.Values, len(scores))
	copy(values, scores)

	h, err := plotter.NewHist(values, config.Bins)
	if err != nil {
		return nil, fmt.Errorf("creating histogram: %w", err)
	}

	h.FillColor = ColorDefault
	p.Add(h)

	return p, nil
}

// BarChartConfig configures bar chart generation.
type BarChartConfig struct {
	Title    string
	XLabel   string
	YLabel   string
	Width    vg.Length
	Height   vg.Length
	FileName string
}

// DefaultBarChartConfig returns default bar chart configuration.
func DefaultBarChartConfig() BarChartConfig {
	return BarChartConfig{
		Title:  "Vulnerability Counts by Category",
		XLabel: "Category",
		YLabel: "Count",
		Width:  8 * vg.Inch,
		Height: 6 * vg.Inch,
	}
}

// BarData represents a single bar in a bar chart.
type BarData struct {
	Label string
	Value float64
	Color color.Color
}

// CreateBarChart creates a bar chart.
func CreateBarChart(data []BarData, config BarChartConfig) (*plot.Plot, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	p := plot.New()
	p.Title.Text = config.Title
	p.X.Label.Text = config.XLabel
	p.Y.Label.Text = config.YLabel

	values := make(plotter.Values, len(data))
	names := make([]string, len(data))
	for i, d := range data {
		values[i] = d.Value
		names[i] = d.Label
	}

	bars, err := plotter.NewBarChart(values, vg.Points(40))
	if err != nil {
		return nil, fmt.Errorf("creating bar chart: %w", err)
	}

	bars.Color = ColorDefault
	p.Add(bars)
	p.NominalX(names...)

	return p, nil
}

// ScatterConfig configures scatter plot generation.
type ScatterConfig struct {
	Title    string
	XLabel   string
	YLabel   string
	Width    vg.Length
	Height   vg.Length
	FileName string
}

// DefaultScatterConfig returns default scatter plot configuration.
func DefaultScatterConfig() ScatterConfig {
	return ScatterConfig{
		Title:  "EPSS Score vs CVSS Score",
		XLabel: "CVSS Score",
		YLabel: "EPSS Score",
		Width:  8 * vg.Inch,
		Height: 6 * vg.Inch,
	}
}

// Point represents a 2D point.
type Point struct {
	X, Y float64
}

// CreateScatterPlot creates a scatter plot.
func CreateScatterPlot(points []Point, config ScatterConfig) (*plot.Plot, error) {
	if len(points) == 0 {
		return nil, fmt.Errorf("no points provided")
	}

	p := plot.New()
	p.Title.Text = config.Title
	p.X.Label.Text = config.XLabel
	p.Y.Label.Text = config.YLabel

	pts := make(plotter.XYs, len(points))
	for i, pt := range points {
		pts[i].X = pt.X
		pts[i].Y = pt.Y
	}

	scatter, err := plotter.NewScatter(pts)
	if err != nil {
		return nil, fmt.Errorf("creating scatter plot: %w", err)
	}

	scatter.Color = ColorDefault
	p.Add(scatter)

	return p, nil
}

// SeverityDistribution represents vulnerability counts by severity.
type SeverityDistribution struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// CreateSeverityPieData prepares data for severity distribution visualization.
func CreateSeverityPieData(dist SeverityDistribution) []BarData {
	data := []BarData{
		{Label: "Critical", Value: float64(dist.Critical), Color: color.RGBA{R: 139, G: 0, B: 0, A: 255}},
		{Label: "High", Value: float64(dist.High), Color: color.RGBA{R: 255, G: 0, B: 0, A: 255}},
		{Label: "Medium", Value: float64(dist.Medium), Color: color.RGBA{R: 255, G: 165, B: 0, A: 255}},
		{Label: "Low", Value: float64(dist.Low), Color: color.RGBA{R: 255, G: 255, B: 0, A: 255}},
	}

	if dist.Unknown > 0 {
		data = append(data, BarData{
			Label: "Unknown",
			Value: float64(dist.Unknown),
			Color: color.RGBA{R: 128, G: 128, B: 128, A: 255},
		})
	}

	return data
}

// ConsensusTypeDistribution represents vulnerability counts by consensus type.
type ConsensusTypeDistribution struct {
	Consensus int
	Partial   int
	Unique    int
}

// CreateConsensusBarData prepares data for consensus type distribution.
func CreateConsensusBarData(dist ConsensusTypeDistribution) []BarData {
	return []BarData{
		{Label: "Consensus", Value: float64(dist.Consensus), Color: ColorConsensus},
		{Label: "Partial", Value: float64(dist.Partial), Color: ColorPartial},
		{Label: "Unique", Value: float64(dist.Unique), Color: ColorUnique},
	}
}

// EPSSPercentileBuckets groups EPSS scores into percentile buckets.
type EPSSPercentileBuckets struct {
	Low      int // 0-25th percentile
	Medium   int // 25-50th percentile
	High     int // 50-75th percentile
	Critical int // 75-100th percentile
}

// BucketScores groups EPSS scores into percentile buckets.
func BucketScores(scores []float64) EPSSPercentileBuckets {
	var buckets EPSSPercentileBuckets

	for _, score := range scores {
		switch {
		case score < 0.25:
			buckets.Low++
		case score < 0.50:
			buckets.Medium++
		case score < 0.75:
			buckets.High++
		default:
			buckets.Critical++
		}
	}

	return buckets
}

// CreateEPSSBucketData prepares data for EPSS bucket distribution.
func CreateEPSSBucketData(buckets EPSSPercentileBuckets) []BarData {
	return []BarData{
		{Label: "Low (0-25%)", Value: float64(buckets.Low), Color: color.RGBA{R: 76, G: 175, B: 80, A: 255}},
		{Label: "Medium (25-50%)", Value: float64(buckets.Medium), Color: color.RGBA{R: 255, G: 235, B: 59, A: 255}},
		{Label: "High (50-75%)", Value: float64(buckets.High), Color: color.RGBA{R: 255, G: 152, B: 0, A: 255}},
		{Label: "Critical (75-100%)", Value: float64(buckets.Critical), Color: color.RGBA{R: 244, G: 67, B: 54, A: 255}},
	}
}

// SummaryStats contains statistics for a report.
type SummaryStats struct {
	TotalVulnerabilities  int
	UniqueVulnerabilities int
	ConsensusCount        int
	PartialCount          int
	UniqueCount           int
	MeanEPSS              float64
	MedianEPSS            float64
	HighRiskCount         int // EPSS > 0.5
	CriticalRiskCount     int // EPSS > 0.75
}

// CalculateSummaryStats calculates summary statistics from EPSS scores and consensus counts.
func CalculateSummaryStats(epssScores []float64, consensus, partial, unique int) SummaryStats {
	stats := SummaryStats{
		TotalVulnerabilities:  consensus + partial + unique,
		UniqueVulnerabilities: len(epssScores),
		ConsensusCount:        consensus,
		PartialCount:          partial,
		UniqueCount:           unique,
	}

	if len(epssScores) == 0 {
		return stats
	}

	// Calculate mean
	var sum float64
	for _, score := range epssScores {
		sum += score
		if score > 0.5 {
			stats.HighRiskCount++
		}
		if score > 0.75 {
			stats.CriticalRiskCount++
		}
	}
	stats.MeanEPSS = sum / float64(len(epssScores))

	// Calculate median
	sorted := make([]float64, len(epssScores))
	copy(sorted, epssScores)
	sort.Float64s(sorted)

	n := len(sorted)
	if n%2 == 0 {
		stats.MedianEPSS = (sorted[n/2-1] + sorted[n/2]) / 2
	} else {
		stats.MedianEPSS = sorted[n/2]
	}

	return stats
}
