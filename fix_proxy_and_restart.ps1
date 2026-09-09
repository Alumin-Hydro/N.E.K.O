# Set proxy_url and restart discord_adapter listener
$ErrorActionPreference = "Stop"

$configPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\config\plugin.toml"

# Read and update config
$content = Get-Content $configPath -Raw
$content = $content -replace 'proxy_url = ""', 'proxy_url = "http://127.0.0.1:7890"'
Set-Content -Path $configPath -Value $content -NoNewline

# Verify
$line = Get-Content $configPath | Select-String "proxy_url"
Write-Host "Config updated: $line"

# Stop listener
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/stop_listening" -Method POST -TimeoutSec 5 -UseBasicParsing
    Write-Host "Stop: $($r.StatusCode)"
} catch { Write-Host "Stop: $_" }

Start-Sleep -Seconds 2

# Start listener
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/start_listening" -Method POST -TimeoutSec 5 -UseBasicParsing
    Write-Host "Start: $($r.StatusCode)"
} catch { Write-Host "Start: $_" }

# Check status
Start-Sleep -Seconds 3
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/status" -TimeoutSec 5 -UseBasicParsing
    $json = $r.Content | ConvertFrom-Json
    Write-Host "Status: $($json.status), Gateway: $($json.gateway)"
} catch { Write-Host "Status check failed: $_" }
