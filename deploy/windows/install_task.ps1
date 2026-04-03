$ErrorActionPreference = "Stop"

$taskName = "NetworkSecurityMonitor"
$scriptPath = Join-Path $PSScriptRoot "run_nsm.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Runs NSM at startup" -Force
Write-Host "Installed scheduled task: $taskName"
