$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $repoRoot
Set-Location $repoRoot

if (-not $env:NSM_PROFILE) {
  $env:NSM_PROFILE = "office"
}

python .\main.py --live --profile $env:NSM_PROFILE --no-dashboard
