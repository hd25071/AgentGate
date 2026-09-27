param(
    [string]$TargetHost = "zhiyuan-pgy",
    [string]$RemoteDir = "/home/zhiyuan/agentgate-demo",
    [int]$Port = 18081,
    [switch]$RunDemo,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

if ($RemoteDir -notmatch '^/(opt|home)/[A-Za-z0-9._/-]+$') {
    throw "RemoteDir must be an absolute path under /opt or /home."
}
if ($Port -lt 1024 -or $Port -gt 65535) {
    throw "Port must be between 1024 and 65535."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$tar = Get-Command tar.exe -ErrorAction SilentlyContinue
if (-not $tar) {
    $tar = Get-Command tar -ErrorAction SilentlyContinue
}
if (-not $tar) {
    throw "tar is required."
}

$token = [guid]::NewGuid().ToString("N")
$bundle = Join-Path $env:TEMP "agentgate-prod-demo-$token.tgz"
$installer = Join-Path $env:TEMP "agentgate-prod-demo-install-$token.sh"
$remoteBundle = "/tmp/agentgate-prod-demo-$token.tgz"
$remoteInstaller = "/tmp/agentgate-prod-demo-install-$token.sh"

$archiveItems = @(
    "Dockerfile",
    "go.mod",
    "go.sum",
    "cmd",
    "internal",
    "policies",
    "web",
    "eval",
    "docker-compose.yml",
    "deploy/production-demo"
)

& $tar.Source -czf $bundle -C $repoRoot @archiveItems
if ($LASTEXITCODE -ne 0) {
    throw "Could not create deployment bundle."
}
Copy-Item -LiteralPath (Join-Path $scriptDir "install.sh") -Destination $installer -Force

scp -o BatchMode=yes $bundle "${TargetHost}:$remoteBundle"
if ($LASTEXITCODE -ne 0) {
    throw "Could not upload deployment bundle."
}
scp -o BatchMode=yes $installer "${TargetHost}:$remoteInstaller"
if ($LASTEXITCODE -ne 0) {
    throw "Could not upload installer."
}

$runDemoArg = if ($RunDemo) { " --run-demo" } else { "" }
$skipBuildArg = if ($SkipBuild) { " --skip-build" } else { "" }
$remoteCommand = "bash '$remoteInstaller' --bundle '$remoteBundle' --dest '$RemoteDir' --port '$Port'$runDemoArg$skipBuildArg"
ssh -o BatchMode=yes $TargetHost $remoteCommand
exit $LASTEXITCODE
