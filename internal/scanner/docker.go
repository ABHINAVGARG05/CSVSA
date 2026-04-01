package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ABHINAVGARG05/CSVSA/internal/models"
)

const (
	trivyDockerImage = "aquasec/trivy:latest"
	grypeDockerImage = "anchore/grype:latest"
)

type DockerTrivyScanner struct {
	image  string 
	parser *TrivyScanner
}

func NewDockerTrivyScanner() *DockerTrivyScanner {
	return &DockerTrivyScanner{
		image:  trivyDockerImage,
		parser: NewTrivyScanner(),
	}
}

func (d *DockerTrivyScanner) Name() string { return "trivy" }

func (d *DockerTrivyScanner) Scan(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:  d.Name(),
		Target:   target,
		ScanTime: startTime,
		Success:  false,
	}


	args := []string{
		"run", "--rm",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		d.image,
		"image", "--format", "json", "--quiet",
		target,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "scanner execution timed out"
			return result, models.NewScanError(d.Name(), target, "scan", models.ErrScannerTimeout)
		}
		if stdout.Len() == 0 {
			result.Error = fmt.Sprintf("docker trivy failed: %s", stderr.String())
			return result, models.NewScanError(d.Name(), target, "scan",
				fmt.Errorf("%w: %s", models.ErrScannerFailed, stderr.String()))
		}
	}

	result.RawOutput = stdout.Bytes()

	vulnerabilities, parseErr := d.parser.parseOutput(stdout.Bytes())
	if parseErr != nil {
		result.Error = fmt.Sprintf("failed to parse output: %v", parseErr)
		return result, parseErr
	}

	result.Vulnerabilities = vulnerabilities
	result.Duration = time.Since(startTime)
	result.Success = true
	return result, nil
}

func (d *DockerTrivyScanner) Info(ctx context.Context) (*models.ScannerInfo, error) {
	info := &models.ScannerInfo{
		Name:      d.Name(),
		Available: d.IsAvailable(),
		Version:   "docker:" + d.image,
	}
	return info, nil
}

func (d *DockerTrivyScanner) IsAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}


type DockerGrypeScanner struct {
	image  string
	parser *GrypeScanner
}

func NewDockerGrypeScanner() *DockerGrypeScanner {
	return &DockerGrypeScanner{
		image:  grypeDockerImage,
		parser: NewGrypeScanner(),
	}
}

func (d *DockerGrypeScanner) Name() string { return "grype" }

func (d *DockerGrypeScanner) Scan(ctx context.Context, target string) (*models.ScanResult, error) {
	startTime := time.Now()

	result := &models.ScanResult{
		Scanner:  d.Name(),
		Target:   target,
		ScanTime: startTime,
		Success:  false,
	}

	args := []string{
		"run", "--rm",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		d.image,
		target, "-o", "json", "--quiet",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "scanner execution timed out"
			return result, models.NewScanError(d.Name(), target, "scan", models.ErrScannerTimeout)
		}
		if stdout.Len() == 0 {
			result.Error = fmt.Sprintf("docker grype failed: %s", stderr.String())
			return result, models.NewScanError(d.Name(), target, "scan",
				fmt.Errorf("%w: %s", models.ErrScannerFailed, stderr.String()))
		}
	}

	result.RawOutput = stdout.Bytes()

	vulnerabilities, parseErr := d.parser.parseOutput(stdout.Bytes())
	if parseErr != nil {
		result.Error = fmt.Sprintf("failed to parse output: %v", parseErr)
		return result, parseErr
	}

	result.Vulnerabilities = vulnerabilities
	result.Duration = time.Since(startTime)
	result.Success = true
	return result, nil
}

func (d *DockerGrypeScanner) Info(ctx context.Context) (*models.ScannerInfo, error) {
	info := &models.ScannerInfo{
		Name:      d.Name(),
		Available: d.IsAvailable(),
		Version:   "docker:" + d.image,
	}
	return info, nil
}

func (d *DockerGrypeScanner) IsAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func SmartRegistry() *Registry {
	registry := NewRegistry()

	localTrivy := NewTrivyScanner()
	if localTrivy.IsAvailable() {
		registry.Register(localTrivy)
	} else {
		dockerTrivy := NewDockerTrivyScanner()
		if dockerTrivy.IsAvailable() {
			registry.Register(dockerTrivy)
		}
	}

	localGrype := NewGrypeScanner()
	if localGrype.IsAvailable() {
		registry.Register(localGrype)
	} else {
		dockerGrype := NewDockerGrypeScanner()
		if dockerGrype.IsAvailable() {
			registry.Register(dockerGrype)
		}
	}

	return registry
}

func dockerAvailable() bool {
	_, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func DescribeRegistry(reg *Registry) string {
	var parts []string
	for _, s := range reg.GetAll() {
		source := "local"
		switch s.(type) {
		case *DockerTrivyScanner:
			source = "docker"
		case *DockerGrypeScanner:
			source = "docker"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", s.Name(), source))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
