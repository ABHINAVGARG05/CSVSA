$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$artifacts = Join-Path $repoRoot "artifacts"

New-Item -ItemType Directory -Path $artifacts -Force | Out-Null

$testJson = Join-Path $artifacts "test-report.json"
$coverage = Join-Path $artifacts "coverage.out"
$coverageHtml = Join-Path $artifacts "coverage.html"
$summary = Join-Path $artifacts "test-report.md"

Push-Location $repoRoot
try {
    go test ./... -json -coverprofile="$coverage" | Tee-Object -FilePath $testJson | Out-Null

    $events = Get-Content $testJson | ForEach-Object {
        if ($_.Trim().Length -gt 0) { $_ | ConvertFrom-Json }
    }

    $testEvents = $events | Where-Object { $_.Test -and ($_.Action -eq "pass" -or $_.Action -eq "fail") }
    $passCount = ($testEvents | Where-Object { $_.Action -eq "pass" }).Count
    $failCount = ($testEvents | Where-Object { $_.Action -eq "fail" }).Count

    $packagePass = ($events | Where-Object { -not $_.Test -and $_.Action -eq "pass" }).Count
    $packageFail = ($events | Where-Object { -not $_.Test -and $_.Action -eq "fail" }).Count

    $summaryContent = @(
        "# Test Report",
        "",
        "- Total tests: $($passCount + $failCount)",
        "- Passed: $passCount",
        "- Failed: $failCount",
        "- Packages passed: $packagePass",
        "- Packages failed: $packageFail",
        "- Coverage profile: $coverage",
        "- Coverage HTML: $coverageHtml"
    )

    Set-Content -Path $summary -Value $summaryContent

    if (-not (Test-Path $coverage)) {
        throw "Coverage file not found: $coverage"
    }

    go tool cover -html="$coverage" -o "$coverageHtml"

    Write-Host "Reports written to $artifacts"
}
finally {
    Pop-Location
}
