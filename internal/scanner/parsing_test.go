package scanner

import (
	"context"
	"testing"
)

func TestTrivyParseOutputForTest(t *testing.T) {
	scanner := NewTrivyScanner()

	_, err := scanner.ParseOutputForTest([]byte("{"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	vulns, err := scanner.ParseOutputForTest([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(vulns))
	}

	data := []byte(`{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"pkg","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH","Title":"title","Description":"desc","References":["ref1"]}]}]}`)
	vulns, err = scanner.ParseOutputForTest(data)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].CVE != "CVE-1" || vulns[0].Severity != "HIGH" {
		t.Errorf("unexpected parsed vulnerability: %+v", vulns[0])
	}
}

func TestGrypeParseOutputForTest(t *testing.T) {
	scanner := NewGrypeScanner()

	_, err := scanner.ParseOutputForTest([]byte("{"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	vulns, err := scanner.ParseOutputForTest([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", len(vulns))
	}

	data := []byte(`{"matches":[{"vulnerability":{"id":"CVE-2","severity":"negligible","description":"desc","urls":["ref1"],"fix":{"versions":["2.0"]}},"artifact":{"name":"pkg2","version":"2.0"}}]}`)
	vulns, err = scanner.ParseOutputForTest(data)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].Severity != "LOW" {
		t.Errorf("expected LOW severity, got %s", vulns[0].Severity)
	}
}

func TestScannerInfoUnavailable(t *testing.T) {
	trivy := NewTrivyScannerWithPath("definitely-not-a-command")
	info, err := trivy.Info(context.Background())
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	if info.Available {
		t.Error("expected trivy info to be unavailable")
	}
	if trivy.IsAvailable() {
		t.Error("expected trivy to be unavailable")
	}

	grype := NewGrypeScannerWithPath("definitely-not-a-command")
	info, err = grype.Info(context.Background())
	if err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	if info.Available {
		t.Error("expected grype info to be unavailable")
	}
	if grype.IsAvailable() {
		t.Error("expected grype to be unavailable")
	}
}
