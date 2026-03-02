# CSVSA - Container Security Vulnerability Scanner Analyzer

A production-ready CLI tool that orchestrates multiple container vulnerability scanners, aggregates their findings, and computes consensus metrics to provide high-confidence vulnerability assessments.

## Overview

CSVSA addresses a critical challenge in container security: **different vulnerability scanners often produce different results for the same container image**. By running multiple scanners in parallel and computing consensus metrics, CSVSA helps security teams:

- Identify vulnerabilities confirmed by multiple scanners (high confidence)
- Discover scanner-specific findings that might be missed
- Understand the overlap and agreement between scanning tools
- Generate comprehensive reports for compliance and remediation

## Features

- **Multi-Scanner Orchestration**: Run Trivy and Grype in parallel with configurable timeouts
- **Fault Tolerance**: Continues analysis even if one scanner fails
- **Consensus Analysis**: Computes intersection, unique findings, and overlap percentage
- **Confidence Scoring**: Labels vulnerabilities as HIGH/MEDIUM/LOW confidence based on scanner agreement
- **Multiple Output Formats**: CLI table, JSON, and styled HTML reports
- **Severity Filtering**: Focus on vulnerabilities above a minimum severity threshold

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                           CLI Layer                              │
│                    (cmd/csvsa, internal/cli)                     │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Scanner Orchestrator                       │
│                     (internal/scanner)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Trivy     │  │   Grype     │  │  (Future)   │              │
│  │  Adapter    │  │  Adapter    │  │  Scanners   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Normalizer                               │
│                    (internal/normalizer)                        │
│         Converts scanner-specific JSON to unified format        │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Consensus Engine                            │
│                    (internal/consensus)                         │
│    Computes: Intersection, Unique Sets, Overlap %, Confidence   │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Report Generators                           │
│                     (internal/report)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Table     │  │    JSON     │  │    HTML     │              │
│  │  Generator  │  │  Generator  │  │  Generator  │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Go 1.21 or later
- At least one of the following scanners installed:
  - [Trivy](https://github.com/aquasecurity/trivy) (recommended)
  - [Grype](https://github.com/anchore/grype)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ABHINAVGARG05/CSVSA.git
cd CSVSA

# Build the binary
make build

# Or build directly with Go
go build -o csvsa ./cmd/csvsa
```

### Cross-Platform Builds

```bash
# Build for all platforms
make build-all

# Platform-specific builds
make build-linux
make build-darwin
make build-windows
```

## Usage

### Basic Scan

```bash
# Scan a container image
csvsa scan alpine:3.18

# Scan with specific output format
csvsa scan alpine:3.18 --format json

# Scan with HTML report output
csvsa scan alpine:3.18 --format html --output report.html
```

### Advanced Options

```bash
# Use specific scanners only
csvsa scan alpine:3.18 --scanners trivy,grype

# Set custom timeout (default: 5 minutes)
csvsa scan alpine:3.18 --timeout 10m

# Filter by minimum severity
csvsa scan alpine:3.18 --min-severity high

# Verbose output for debugging
csvsa scan alpine:3.18 --verbose

# Exit with error code if vulnerabilities found (for CI/CD)
csvsa scan alpine:3.18 --fail-on-vuln
```

### Check Available Scanners

```bash
# List installed scanners and their versions
csvsa scanners
```

### Help

```bash
# General help
csvsa --help

# Command-specific help
csvsa scan --help
```

## Output Formats

### Table (Default)

Human-readable CLI output with severity-based organization:

```
================================================================================
                    CSVSA - Vulnerability Consensus Report
================================================================================
Target: alpine:3.18
Scanners: trivy, grype
Analysis Time: 2024-01-15 10:30:45

CONSENSUS VULNERABILITIES (Found by ALL scanners)
--------------------------------------------------------------------------------
CVE              PACKAGE     VERSION     SEVERITY   FIXED VERSION
--------------------------------------------------------------------------------
CVE-2023-5363   libssl3     3.1.2-r0    HIGH       3.1.4-r0
CVE-2023-5678   libcrypto3  3.1.2-r0    MEDIUM     3.1.4-r1

UNIQUE TO TRIVY
--------------------------------------------------------------------------------
CVE-2024-0727   libssl3     3.1.2-r0    LOW        3.1.4-r5

STATISTICS
--------------------------------------------------------------------------------
Total Unique Vulnerabilities: 5
Consensus Count: 2
Overlap Percentage: 40.0%
```

### JSON

Machine-readable structured output for integration with other tools:

```json
{
  "target": "alpine:3.18",
  "scanners": ["trivy", "grype"],
  "consensus": [...],
  "unique_findings": {...},
  "statistics": {
    "total": 5,
    "consensus_count": 2,
    "overlap_percentage": 40.0
  }
}
```

### HTML

Rich visual report with styling, suitable for sharing and documentation.

## Consensus Algorithm

CSVSA uses set theory to compute consensus:

```
Given vulnerability sets from n scanners: V₁, V₂, ..., Vₙ

Consensus (Intersection):  C = V₁ ∩ V₂ ∩ ... ∩ Vₙ
Union (All):               U = V₁ ∪ V₂ ∪ ... ∪ Vₙ  
Unique to scanner i:       Uᵢ = Vᵢ - (U - Vᵢ)
Overlap Percentage:        |C| / |U| × 100
```

### Confidence Levels

| Level  | Criteria                       | Interpretation                    |
|--------|--------------------------------|-----------------------------------|
| HIGH   | Found by ALL scanners          | Very likely a real vulnerability  |
| MEDIUM | Found by >50% of scanners      | Probably real, worth investigating|
| LOW    | Found by only ONE scanner      | May be false positive, verify     |

## Project Structure

```
CSVSA/
├── cmd/csvsa/           # Application entry point
│   └── main.go
├── internal/
│   ├── cli/             # CLI implementation (Cobra)
│   ├── scanner/         # Scanner interface and adapters
│   │   ├── scanner.go   # Interface definition
│   │   ├── trivy.go     # Trivy adapter
│   │   ├── grype.go     # Grype adapter
│   │   └── orchestrator.go
│   ├── normalizer/      # Data normalization
│   ├── consensus/       # Consensus algorithm
│   ├── report/          # Report generators
│   │   ├── table.go
│   │   ├── json.go
│   │   └── html.go
│   └── models/          # Core data structures
├── tests/
│   ├── integration_test.go
│   └── testdata/        # Scanner output fixtures
├── docs/
│   └── uml/             # PlantUML diagrams
├── Makefile
├── go.mod
└── README.md
```

## Development

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make coverage

# Run specific package tests
go test ./internal/consensus/... -v
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run all checks
make check
```

### Adding a New Scanner

1. Create a new file in `internal/scanner/` (e.g., `snyk.go`)
2. Implement the `Scanner` interface:
   ```go
   type Scanner interface {
       Name() string
       Scan(ctx context.Context, target string) (*models.ScanResult, error)
       IsAvailable() bool
   }
   ```
3. Register the scanner in the orchestrator
4. Add test fixtures in `tests/testdata/`

## Performance Characteristics

| Operation           | Time Complexity | Space Complexity |
|-------------------- |-----------------|------------------|
| Scanner Execution   | O(1) per scanner| O(m) per scanner |
| Normalization       | O(n × m)        | O(n × m)         |
| Consensus Analysis  | O(n × m)        | O(n × m)         |
| Report Generation   | O(m)            | O(m)             |

Where: n = number of scanners, m = average vulnerabilities per scanner

## Limitations

- Requires scanners to be pre-installed on the system
- Scanner-specific features (e.g., Trivy's secret scanning) not fully utilized
- No built-in vulnerability database update mechanism
- HTML reports require a browser for viewing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) by Aqua Security
- [Grype](https://github.com/anchore/grype) by Anchore
- [Cobra](https://github.com/spf13/cobra) for CLI framework

---
