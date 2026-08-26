# Fix config encoding and set proxy_url
$ErrorActionPreference = "Stop"

$configPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\config\plugin.toml"

# Read raw bytes and decode as UTF-16 (what PowerShell wrote)
$bytes = [System.IO.File]::ReadAllBytes($configPath)
$content = [System.Text.Encoding]::Unicode.GetString($bytes)

# Fix proxy_url
$content = $content -replace 'proxy_url\s*=\s*""', 'proxy_url = "http://127.0.0.1:7890"'

# Write back as UTF-8
[System.IO.File]::WriteAllText($configPath, $content, [System.Text.Encoding]::UTF8)

# Verify
$line = Get-Content $configPath -Encoding UTF8 | Select-String "proxy_url"
Write-Host "Fixed: $line"

# Reload plugin
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}
