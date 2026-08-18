[CmdletBinding()]
param(
    [string]$VpsHost = '209.182.217.141',
    [string]$VpsUser = 'Administrator'
)

$ErrorActionPreference = 'Stop'
$sourceRoot = $PSScriptRoot
$keyPath = Join-Path $env:USERPROFILE '.ssh\anthrax_vps_ed25519'
$workRoot = Join-Path $env:TEMP ("kvc-vps-sync-{0}" -f $PID)
$payloadRoot = Join-Path $workRoot 'payload'
$archivePath = Join-Path $workRoot 'kvc-sync.zip'

if (-not (Test-Path -LiteralPath $keyPath)) { throw "SSH deploy key missing: $keyPath" }
New-Item -ItemType Directory -Path $payloadRoot -Force | Out-Null

try {
    Write-Host 'Staging KVC...'
    & robocopy.exe $sourceRoot $payloadRoot /E /COPY:DAT /DCOPY:DAT /R:2 /W:2 /XD .vs bin obj x64 /NFL /NDL /NJH /NJS /NP
    if ($LASTEXITCODE -ge 8) { throw "Staging failed with robocopy exit code $LASTEXITCODE." }

    Write-Host 'Creating update archive...'
    & tar.exe -a -cf $archivePath -C $payloadRoot .
    if ($LASTEXITCODE -ne 0) { throw "Archive creation failed with exit code $LASTEXITCODE." }

    $destination = "${VpsUser}@${VpsHost}"
    Write-Host 'Uploading to VPS...'
    & scp.exe -i $keyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new $archivePath "${destination}:C:/Users/Administrator/Desktop/kvc-sync.zip"
    if ($LASTEXITCODE -ne 0) { throw "Upload failed with exit code $LASTEXITCODE." }

    $remoteScript = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$archive = 'C:\Users\Administrator\Desktop\kvc-sync.zip'
$target = 'C:\Users\Administrator\Desktop\Coding Sync\kvc-main'
$staging = 'C:\Users\Administrator\Desktop\kvc-sync-stage'

if (Test-Path -LiteralPath $staging) {
    $resolved = [IO.Path]::GetFullPath($staging)
    if ($resolved -ne 'C:\Users\Administrator\Desktop\kvc-sync-stage') { throw "Unexpected staging path: $resolved" }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $staging -Force
New-Item -ItemType Directory -Path $target -Force | Out-Null

& robocopy.exe $staging $target /MIR /COPY:DAT /DCOPY:DAT /R:2 /W:2 /XD .vs bin obj x64 /NFL /NDL /NJH /NJS /NP
if ($LASTEXITCODE -ge 8) { throw "VPS mirror failed with robocopy exit code $LASTEXITCODE." }

Remove-Item -LiteralPath $staging -Recurse -Force
Remove-Item -LiteralPath $archive -Force
Write-Output 'KVC is synced to the VPS desktop.'
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remoteScript))
    & ssh.exe -i $keyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new $destination "powershell -NoProfile -OutputFormat Text -EncodedCommand $encoded"
    if ($LASTEXITCODE -ne 0) { throw "Remote sync failed with exit code $LASTEXITCODE." }
} finally {
    if (Test-Path -LiteralPath $workRoot) { Remove-Item -LiteralPath $workRoot -Recurse -Force }
}

Write-Host 'KVC VPS sync complete.' -ForegroundColor Green
