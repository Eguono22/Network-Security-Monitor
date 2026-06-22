$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $repoRoot
Set-Location $repoRoot
$artifactDir = Join-Path $repoRoot ".tmp\first-run-demo"

function Write-CliShim {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$ModuleName
  )

  $content = "@echo off`r`n`"$PythonPath`" -m $ModuleName %*`r`n"
  Set-Content -LiteralPath $Path -Value $content -Encoding ASCII
}

function Write-PowerShellShim {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [Parameter(Mandatory = $true)][string]$ModuleName
  )

  $content = "& `"$PythonPath`" -m $ModuleName @args`r`n"
  Set-Content -LiteralPath $Path -Value $content -Encoding ASCII
}

function Get-BasePython {
  if (Get-Command py -ErrorAction SilentlyContinue) {
    return @("py", "-3")
  }
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return @("python")
  }
  throw "Python 3 is required to bootstrap this project."
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
  $basePython = Get-BasePython
  if ($basePython.Length -gt 1) {
    & $basePython[0] $basePython[1] -m venv .venv
  } else {
    & $basePython[0] -m venv .venv
  }
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
& $venvPython -c "import importlib.util, sys; sys.exit(0 if importlib.util.find_spec('setuptools') else 1)"
$shimNames = @(
  @{ Name = "nsm"; Module = "network_security_monitor" },
  @{ Name = "nsm-smoke"; Module = "network_security_monitor.smoke_test" }
)
if ($LASTEXITCODE -eq 0) {
  & $venvPython -m pip install --no-build-isolation -e .
  if ($LASTEXITCODE -ne 0) {
    Write-Host "Editable install unavailable in this environment. Falling back to repo-local execution."
    foreach ($shim in $shimNames) {
      Write-CliShim -Path (Join-Path $repoRoot ".venv\Scripts\$($shim.Name).cmd") -PythonPath $venvPython -ModuleName $shim.Module
      Write-PowerShellShim -Path (Join-Path $repoRoot ".venv\Scripts\$($shim.Name).ps1") -PythonPath $venvPython -ModuleName $shim.Module
    }
  }
} else {
  Write-Host "Setuptools is unavailable in this environment. Falling back to repo-local execution."
  foreach ($shim in $shimNames) {
    Write-CliShim -Path (Join-Path $repoRoot ".venv\Scripts\$($shim.Name).cmd") -PythonPath $venvPython -ModuleName $shim.Module
    Write-PowerShellShim -Path (Join-Path $repoRoot ".venv\Scripts\$($shim.Name).ps1") -PythonPath $venvPython -ModuleName $shim.Module
  }
}
$env:PYTHONPATH = if ($env:PYTHONPATH) { "$repoRoot;$env:PYTHONPATH" } else { $repoRoot }
& $venvPython -m network_security_monitor.smoke_test --artifact-dir $artifactDir
