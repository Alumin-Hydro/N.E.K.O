# Fix proxy_url in business_config.json
$ErrorActionPreference = "Stop"

$configPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\data\business_config.json"

# Read JSON
$json = Get-Content $configPath -Encoding UTF8 -Raw | ConvertFrom-Json

# Update proxy_url
$json.proxy_url = "http://127.0.0.1:7890"

# Write back as UTF-8
$jsonString = $json | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($configPath, $jsonString, [System.Text.Encoding]::UTF8)

# Verify
$verify = Get-Content $configPath -Encoding UTF8 -Raw | ConvertFrom-Json
Write-Host "proxy_url: $($verify.proxy_url)"

# Reload plugin
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}
