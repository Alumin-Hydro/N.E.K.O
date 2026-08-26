# Fix business_config.json with utf-8-sig handling
$ErrorActionPreference = "Stop"

$script = @'
import json

config_path = r"D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\data\business_config.json"

# Read with utf-8-sig to handle BOM
with open(config_path, "r", encoding="utf-8-sig") as f:
    config = json.load(f)

# Fix proxy_url
config["proxy_url"] = "http://127.0.0.1:7890"

# Write back without BOM
with open(config_path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)

print(f"proxy_url: {config['proxy_url']}")
print(f"bot_token: {'*' * 20 if config.get('bot_token') else 'MISSING'}")
'@

$scriptPath = "E:\Workspace\fix_config2.py"
[System.IO.File]::WriteAllText($scriptPath, $script, [System.Text.Encoding]::UTF8)

& python $scriptPath

# Reload
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}

# Check log
Start-Sleep -Seconds 5
$logPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\logs\plugin\N.E.K.O_Plugin_discord_adapter_20260827.log"
Get-Content $logPath -Tail 10
