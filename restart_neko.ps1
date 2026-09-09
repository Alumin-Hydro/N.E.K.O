# Restart N.E.K.O completely to clear all caches
$ErrorActionPreference = "Stop"

Write-Host "Stopping N.E.K.O..."
Get-Process projectneko_server -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 3

# Clear all plugin caches
Write-Host "Clearing plugin caches..."
$pluginDir = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter"
if (Test-Path "$pluginDir\__pycache__") {
    Remove-Item -Recurse -Force "$pluginDir\__pycache__"
    Write-Host "Cleared __pycache__"
}

# Clear any .pyc in parent
Get-ChildItem "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins" -Recurse -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
Write-Host "Cleared all .pyc files"

# Start N.E.K.O via scheduled task (SessionId=1)
Write-Host "Starting N.E.K.O..."
$action = New-ScheduledTaskAction -Execute "D:\Games\Steam\steamapps\common\n.e.k.o\N.E.K.O.exe"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
$principal = New-ScheduledTaskPrincipal -UserId "win11" -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "NEKO_Restart_$(Get-Random)" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-Sleep -Seconds 5

# Wait for port 48916
Write-Host "Waiting for N.E.K.O to be ready..."
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugins" -TimeoutSec 2 -UseBasicParsing
        if ($r.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch { }
    Start-Sleep -Seconds 2
}

if ($ready) {
    Write-Host "N.E.K.O is ready"
    # Check discord_adapter status
    Start-Sleep -Seconds 10
    $logPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\logs\plugin\N.E.K.O_Plugin_discord_adapter_20260827.log"
    Get-Content $logPath -Tail 20
} else {
    Write-Host "N.E.K.O failed to start"
}
