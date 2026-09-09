# Start N.E.K.O via scheduled task in SessionId=1
$ErrorActionPreference = "Stop"

$taskName = "NEKO_Start_$(Get-Random)"

# Create action
$action = New-ScheduledTaskAction -Execute "D:\Games\Steam\steamapps\common\n.e.k.o\N.E.K.O.exe"

# Create trigger (immediate)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)

# Run as interactive user (SessionId=1) - use win11 explicitly
$principal = New-ScheduledTaskPrincipal -UserId "win11" -LogonType Interactive

# Settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

# Register and start
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "Started N.E.K.O via scheduled task: $taskName"

# Wait for it to be ready
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugins" -TimeoutSec 2 -UseBasicParsing
        if ($r.StatusCode -eq 200) {
            Write-Host "N.E.K.O ready after $($i*2) seconds"
            break
        }
    } catch { }
}

# Cleanup task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# Check discord_adapter log
Start-Sleep -Seconds 10
$logPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\logs\plugin\N.E.K.O_Plugin_discord_adapter_20260827.log"
if (Test-Path $logPath) {
    Get-Content $logPath -Tail 25
} else {
    Write-Host "Log file not found yet"
}
