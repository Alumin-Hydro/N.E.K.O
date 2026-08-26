# Rewrite discord_adapter config with ASCII only (frozen runtime TOML parser issue)
$ErrorActionPreference = "Stop"

$configPath = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter\config\plugin.toml"

$lines = @(
    '[plugin]',
    'id = "discord_adapter"',
    'name = "Discord Adapter"',
    'description = "Connects to Discord so the catgirl replies to text, images and documents in server channels and DMs."',
    'short_description = "Catgirl integration for Discord channels and DMs, with image and document support."',
    'keywords = ["discord", "im", "chat", "gateway"]',
    'passive = true',
    'version = "0.1.0"',
    'type = "plugin"',
    'entry = "plugin.plugins.discord_adapter:DiscordAdapterPlugin"',
    '',
    '[plugin.author]',
    'name = "N.E.K.O. Community"',
    '',
    '[plugin.sdk]',
    'recommended = ">=0.1.0,<0.2.0"',
    'supported = ">=0.1.0,<0.3.0"',
    '',
    '[plugin.i18n]',
    'default_locale = "zh-CN"',
    'locales_dir = "i18n"',
    '',
    '[plugin.store]',
    'enabled = true',
    '',
    '[plugin.ui]',
    'enabled = true',
    '',
    '[[plugin.ui.panel]]',
    'id = "main"',
    'title = "Discord Adapter"',
    'entry = "static/index.html"',
    'context = "discord_adapter"',
    'permissions = ["state:read", "action:call"]',
    '',
    '[[plugin.ui.guide]]',
    'id = "quickstart"',
    'title = "Quick Start"',
    'entry = "README.md"',
    'permissions = ["state:read"]',
    '',
    '[plugin_runtime]',
    'enabled = true',
    'auto_start = true',
    '',
    '[discord_adapter]',
    'bot_token = ""',
    'trigger_mode = "mention"',
    'admin_user_ids = ""',
    'channel_whitelist = ""',
    'guild_whitelist = ""',
    'permission_mode = "allow_list"',
    'max_concurrent_messages = 3',
    'ai_connect_timeout_seconds = 10.0',
    'ai_turn_timeout_seconds = 60.0',
    'max_attachment_bytes = 10485760',
    'max_total_attachment_bytes = 20971520',
    'max_attachments_per_message = 3',
    'reconnect_backoff_seconds = 3.0',
    'max_reconnect_attempts = 5',
    'proxy_url = "http://127.0.0.1:7890"',
    ''
)

$content = $lines -join "`n"
$bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
[System.IO.File]::WriteAllBytes($configPath, $bytes)

$raw = [System.IO.File]::ReadAllText($configPath, [System.Text.Encoding]::UTF8)
$proxyLine = ($raw.Split("`n") | Select-String "proxy_url")
Write-Host "Proxy: $proxyLine"

try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
    Start-Sleep -Seconds 3
    $status = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/status" -TimeoutSec 5 -UseBasicParsing
    Write-Host "Status: $($status.Content)"
} catch {
    Write-Host "Reload: $_"
}
