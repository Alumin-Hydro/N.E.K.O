# Rewrite discord_adapter config as clean UTF-8
$ErrorActionPreference = "Stop"

$configPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\config\plugin.toml"

# Clean UTF-8 content
$content = @'
[plugin]
id = "discord_adapter"
name = "Discord 适配器"
description = "接入 Discord，让猫娘在服务器频道和私信中回复文字、图片和文档。"
short_description = "Discord 服务器频道与私信的猫娘接入，支持图片与文档。"
keywords = ["discord", "im", "聊天", "gateway"]
passive = true
version = "0.1.0"
type = "plugin"
entry = "plugin.plugins.discord_adapter:DiscordAdapterPlugin"

[plugin.author]
name = "N.E.K.O. Community"

[plugin.sdk]
recommended = ">=0.1.0,<0.2.0"
supported = ">=0.1.0,<0.3.0"

[plugin.i18n]
default_locale = "zh-CN"
locales_dir = "i18n"

[plugin.store]
enabled = true

[plugin.ui]
enabled = true

[[plugin.ui.panel]]
id = "main"
title = "Discord 适配器"
entry = "static/index.html"
context = "discord_adapter"
permissions = ["state:read", "action:call"]

[[plugin.ui.guide]]
id = "quickstart"
title = "快速开始"
entry = "README.md"
permissions = ["state:read"]

[plugin_runtime]
enabled = true
auto_start = true

[discord_adapter]
bot_token = ""
trigger_mode = "mention"
admin_user_ids = ""
channel_whitelist = ""
guild_whitelist = ""
permission_mode = "allow_list"
max_concurrent_messages = 3
ai_connect_timeout_seconds = 10.0
ai_turn_timeout_seconds = 60.0
max_attachment_bytes = 10485760
max_total_attachment_bytes = 20971520
max_attachments_per_message = 3
reconnect_backoff_seconds = 3.0
max_reconnect_attempts = 5
proxy_url = "http://127.0.0.1:7890"
'@

# Write as UTF-8 without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($configPath, $content, $utf8NoBom)

# Verify
$firstLine = Get-Content $configPath -Encoding UTF8 -TotalCount 1
Write-Host "First line: $firstLine"

$proxyLine = Get-Content $configPath -Encoding UTF8 | Select-String "proxy_url"
Write-Host "Proxy: $proxyLine"

# Reload
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload: $_"
}
