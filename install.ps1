# Cybernova portable setup for Windows PowerShell 5.1+ / Docker Desktop.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
if (-not $root) { throw "Run from a saved Git checkout." }
foreach ($cmd in @("git", "docker")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "CYBERNOVA_SETUP_ERROR: missing dependency $cmd"
    }
}
$origin = (& git -C $root remote get-url origin 2>$null)
if ($LASTEXITCODE -ne 0) { throw "CYBERNOVA_SETUP_ERROR: not a Git checkout" }
$approvedRemotes = @(
    "git@github.com:4oker12/cybernoc",
    "git@github.com:4oker12/cybernoc.git",
    "https://github.com/4oker12/cybernoc",
    "https://github.com/4oker12/cybernoc.git"
)
if ($approvedRemotes -cnotcontains $origin.Trim()) {
    throw "CYBERNOVA_SETUP_ERROR: unexpected Git remote"
}
& docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "CYBERNOVA_SETUP_ERROR: Docker Compose v2 required" }
$sha = (& git -C $root rev-parse --verify HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw "CYBERNOVA_SETUP_ERROR: cannot resolve revision" }
if ($env:CYBERNOVA_EXPECTED_SHA -and $env:CYBERNOVA_EXPECTED_SHA -cne $sha) {
    throw "CYBERNOVA_SETUP_ERROR: source revision does not match expected SHA"
}
Write-Host "Cybernova source: $sha"
Write-Host "Nothing will be installed or downloaded without confirmation in the wizard."
$portable = Join-Path $root "cybernova\research-platform\portable"
Push-Location $portable
try {
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        & py -3 manage.py wizard
    } else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) { throw "CYBERNOVA_SETUP_ERROR: Python 3 required" }
        & python manage.py wizard
    }
    if ($LASTEXITCODE -ne 0) { throw "CYBERNOVA_SETUP_ERROR: wizard failed ($LASTEXITCODE)" }
} finally {
    Pop-Location
}
