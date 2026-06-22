$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $repoRoot
Set-Location $repoRoot

if (-not $env:NSM_PROFILE) {
  $env:NSM_PROFILE = "office"
}

$venvNsmPs1 = Join-Path $repoRoot ".venv\Scripts\nsm.ps1"
$venvNsmCmd = Join-Path $repoRoot ".venv\Scripts\nsm.cmd"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"

if (Test-Path $venvNsmPs1) {
  & $venvNsmPs1 --live --profile $env:NSM_PROFILE --no-dashboard
} elseif (Test-Path $venvNsmCmd) {
  & $venvNsmCmd --live --profile $env:NSM_PROFILE --no-dashboard
} elseif (Test-Path $venvPython) {
  & $venvPython .\main.py --live --profile $env:NSM_PROFILE --no-dashboard
} else {
  python .\main.py --live --profile $env:NSM_PROFILE --no-dashboard
}
