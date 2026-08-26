# Deploy discord_adapter to 5090 N.E.K.O runtime
$ErrorActionPreference = "Stop"

$src = "E:\Workspace\discord_adapter_deploy"
$dst = "D:\Apps\NEKO\N.E.K.O\Data\N.E.K.O\plugins\discord_adapter"

# Clean and create temp
if (Test-Path $src) { Remove-Item -Recurse -Force $src }
New-Item -ItemType Directory -Force -Path $src | Out-Null

# Copy plugin files
Copy-Item "E:\Workspace\neko-plugin\discord_adapter\*" -Destination $src -Recurse -Force

# Stop on error
if (-not (Test-Path "$src\__init__.py")) { Write-Error "Source not ready"; exit 1 }

# Deploy: move __init__.py to bypass lock, copy all, restore
Push-Location $dst
try {
    if (Test-Path "__init__.py") {
        Move-Item "__init__.py" "__init__.py.bak" -Force
    }
    Copy-Item "$src\*" -Destination . -Recurse -Force
    if (Test-Path "__init__.py.bak") {
        Remove-Item "__init__.py.bak" -Force
    }
    Write-Host "Deployed to $dst"
} finally {
    Pop-Location
}

# Verify
$size = (Get-Item "$dst\__init__.py").Length
Write-Host "__init__.py size: $size bytes"

# Hot reload
try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:48916/plugin/discord_adapter/reload" -Method POST -TimeoutSec 10 -UseBasicParsing
    Write-Host "Reload: $($r.StatusCode)"
} catch {
    Write-Host "Reload failed: $_"
}
