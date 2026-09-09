# Fix proxy_url in all discord_adapter config locations
$ErrorActionPreference = "Stop"

# 1. Fix .neko-package-profiles/default.toml
$profilePath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\.neko-package-profiles\discord_adapter\default.toml"
$content = Get-Content $profilePath -Encoding UTF8 -Raw
$content = $content -replace 'proxy_url = ""', 'proxy_url = "http://127.0.0.1:7890"'
[System.IO.File]::WriteAllText($profilePath, $content, [System.Text.Encoding]::UTF8)
Write-Host "Fixed profile: $profilePath"

# 2. Verify business_config.json
$bizPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\data\business_config.json"
$biz = Get-Content $bizPath -Encoding UTF8 -Raw | ConvertFrom-Json
Write-Host "business_config proxy_url: $($biz.proxy_url)"

# 3. Reload plugin
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}

# 4. Check log
Start-Sleep -Seconds 5
$logPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\logs\plugin\N.E.K.O_Plugin_discord_adapter_20260827.log"
Get-Content $logPath -Tail 15
