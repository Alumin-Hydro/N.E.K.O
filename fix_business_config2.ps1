# Fix business_config.json with pure Python (no PowerShell JSON mangling)
$ErrorActionPreference = "Stop"

$script = @'
import json

config_path = r"D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\data\business_config.json"

# Read current config
with open(config_path, "r", encoding="utf-8") as f:
    config = json.load(f)

# Fix proxy_url
config["proxy_url"] = "http://127.0.0.1:7890"

# Write back with proper formatting
with open(config_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)

print(f"proxy_url set to: {config['proxy_url']}")
print(f"bot_token preserved: {bool(config.get('bot_token'))}")
'@

$scriptPath = "E:\Workspace\fix_config.py"
[System.IO.File]::WriteAllText($scriptPath, $script, [System.Text.Encoding]::UTF8)

# Run with system Python
& python $scriptPath

# Reload plugin
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}
