[CmdletBinding()]
param(
    [ValidateSet("All", "Standard", "Driver")]
    [string]$Profile = "All",
    [string]$Name,
    [switch]$CurrentUser,
    [switch]$Remove
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$UtilityRoot = $PSScriptRoot
$RepoRoot = Split-Path -Parent $UtilityRoot
$CertDir = Join-Path $UtilityRoot "cert"
$BinDir = Join-Path $RepoRoot "bin"
$ConfigPath = Join-Path $CertDir "signing.config.json"

function Write-Info([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Step([string]$Message) {
    Write-Host $Message -ForegroundColor DarkGray
}

function Write-Success([string]$Message) {
    Write-Host $Message -ForegroundColor Green
}

function Write-WarningLine([string]$Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Write-Failure([string]$Message) {
    Write-Host $Message -ForegroundColor Red
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-DefaultConfig {
    return [ordered]@{
        Profiles = [ordered]@{
            Standard = [ordered]@{
                Name = "Microsoft Windows"
            }
            Driver = [ordered]@{
                Name = "Microsoft Windows OS"
            }
        }
    }
}

function Save-Config([hashtable]$Config) {
    $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigPath -Encoding ASCII
}

function Load-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Convert-ConfigToHashtable([object]$ConfigObject) {
    $config = New-DefaultConfig
    if (-not $ConfigObject) {
        return $config
    }

    if ($ConfigObject.PSObject.Properties.Name -contains "Profiles") {
        foreach ($profileName in @("Standard", "Driver")) {
            $profileConfig = $ConfigObject.Profiles.$profileName
            if ($profileConfig -and -not [string]::IsNullOrWhiteSpace($profileConfig.Name)) {
                $config.Profiles[$profileName].Name = $profileConfig.Name
            }
        }

        return $config
    }

    if ($ConfigObject.PSObject.Properties.Name -contains "Name" -and -not [string]::IsNullOrWhiteSpace($ConfigObject.Name)) {
        $config.Profiles.Standard.Name = $ConfigObject.Name
    }

    return $config
}

function Load-Config {
    $configObject = Load-JsonFile -Path $ConfigPath
    $config = Convert-ConfigToHashtable -ConfigObject $configObject
    Save-Config -Config $config
    return $config
}

function Get-Slug([string]$Value) {
    $slug = ($Value -replace '[^A-Za-z0-9]+', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($slug)) {
        throw "The certificate name produced an empty file prefix."
    }

    return $slug
}

function Get-ConfiguredName([hashtable]$Config, [string]$ResolvedProfile, [string]$ExplicitName) {
    if (-not [string]::IsNullOrWhiteSpace($ExplicitName)) {
        return $ExplicitName
    }

    return $Config.Profiles[$ResolvedProfile].Name
}

function Get-PathsForProfile([string]$BaseName, [string]$ResolvedProfile) {
    $slug = Get-Slug $BaseName
    $profileTag = $ResolvedProfile.ToLowerInvariant()
    $prefix = "$slug-$profileTag"

    return [ordered]@{
        Name = $BaseName
        Profile = $ResolvedProfile
        RootCerPath = Join-Path $CertDir "$prefix-root.cer"
        SignerCerPath = Join-Path $CertDir "$prefix-signing.cer"
        LegacyRootCerPath = Join-Path $CertDir "$slug-root.cer"
        LegacySignerCerPath = Join-Path $CertDir "$slug-signing.cer"
    }
}

function Normalize-CertificateFiles([hashtable]$Paths) {
    $moves = @(
        @{ From = $Paths.LegacyRootCerPath; To = $Paths.RootCerPath },
        @{ From = $Paths.LegacySignerCerPath; To = $Paths.SignerCerPath }
    )

    foreach ($move in $moves) {
        if (($move.From -ne $move.To) -and (-not (Test-Path -LiteralPath $move.To)) -and (Test-Path -LiteralPath $move.From)) {
            Move-Item -LiteralPath $move.From -Destination $move.To -Force
        }
    }
}

function Get-StoreTargets {
    if ($CurrentUser) {
        return [ordered]@{
            RootStorePath = "Cert:\CurrentUser\Root"
            PublisherStorePath = "Cert:\CurrentUser\TrustedPublisher"
            ScopeLabel = "CurrentUser"
        }
    }

    if (-not (Test-IsAdministrator)) {
        throw "LocalMachine certificate import requires an elevated PowerShell session. Re-run as Administrator or use -CurrentUser."
    }

    return [ordered]@{
        RootStorePath = "Cert:\LocalMachine\Root"
        PublisherStorePath = "Cert:\LocalMachine\TrustedPublisher"
        ScopeLabel = "LocalMachine"
    }
}

function Get-CertificateThumbprint([string]$CertificatePath) {
    return ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)).Thumbprint
}

function Import-Certificates([hashtable]$Paths, [hashtable]$Stores) {
    Import-Certificate -FilePath $Paths.RootCerPath -CertStoreLocation $Stores.RootStorePath | Out-Null
    Import-Certificate -FilePath $Paths.SignerCerPath -CertStoreLocation $Stores.PublisherStorePath | Out-Null
}

function Remove-Certificates([hashtable]$Paths, [hashtable]$Stores) {
    $targets = @(
        @{
            StorePath = $Stores.RootStorePath
            Thumbprint = Get-CertificateThumbprint -CertificatePath $Paths.RootCerPath
            Label = "root certificate"
        },
        @{
            StorePath = $Stores.PublisherStorePath
            Thumbprint = Get-CertificateThumbprint -CertificatePath $Paths.SignerCerPath
            Label = "signing certificate"
        }
    )

    foreach ($target in $targets) {
        $itemPath = Join-Path $target.StorePath $target.Thumbprint
        if (Test-Path -LiteralPath $itemPath) {
            Remove-Item -LiteralPath $itemPath -DeleteKey -Force
            Write-Success "Removed $($target.Label) for $($Paths.Profile) from $($target.StorePath)."
        }
        else {
            Write-WarningLine "Certificate not present in $($target.StorePath): $($target.Thumbprint)"
        }
    }
}

function Test-CertificatePresent([string]$StorePath, [string]$CertificatePath) {
    $thumbprint = Get-CertificateThumbprint -CertificatePath $CertificatePath
    return Test-Path -LiteralPath (Join-Path $StorePath $thumbprint)
}

function Show-TrustStatus([hashtable]$Paths, [hashtable]$Stores) {
    $rootPresent = Test-CertificatePresent -StorePath $Stores.RootStorePath -CertificatePath $Paths.RootCerPath
    $signerPresent = Test-CertificatePresent -StorePath $Stores.PublisherStorePath -CertificatePath $Paths.SignerCerPath

    Write-Step "$($Paths.Profile) root certificate present: $rootPresent"
    Write-Step "$($Paths.Profile) signing certificate present: $signerPresent"
}

function Show-SignedFileStatus {
    if (-not (Test-Path -LiteralPath $BinDir)) {
        return
    }

    $statusTargets = @(
        (Join-Path $BinDir "kvc.exe"),
        (Join-Path $BinDir "kvcstrm.sys")
    )

    $signedFiles = @(
        $statusTargets | Where-Object { Test-Path -LiteralPath $_ }
        Get-ChildItem -LiteralPath $BinDir -File |
            Where-Object { $_.BaseName -match '(?i)_signed$' } |
            Select-Object -ExpandProperty FullName
    ) | Sort-Object -Unique

    foreach ($file in $signedFiles) {
        $signature = Get-AuthenticodeSignature -FilePath $file
        Write-Step "$([System.IO.Path]::GetFileName($file)): $($signature.Status)"
    }
}

try {
    if (-not (Test-Path -LiteralPath $CertDir)) {
        throw "The cert directory does not exist: $CertDir"
    }

    $config = Load-Config
    $stores = Get-StoreTargets

    $profilesToHandle = if ($Profile -eq "All") { @("Standard", "Driver") } else { @($Profile) }
    if (($profilesToHandle.Count -gt 1) -and (-not [string]::IsNullOrWhiteSpace($Name))) {
        throw "Use -Profile Standard or -Profile Driver together with -Name."
    }

    foreach ($resolvedProfile in $profilesToHandle) {
        $effectiveName = Get-ConfiguredName -Config $config -ResolvedProfile $resolvedProfile -ExplicitName $Name
        $paths = Get-PathsForProfile -BaseName $effectiveName -ResolvedProfile $resolvedProfile
        Normalize-CertificateFiles -Paths $paths

        if ((-not (Test-Path -LiteralPath $paths.RootCerPath)) -or (-not (Test-Path -LiteralPath $paths.SignerCerPath))) {
            Write-WarningLine "Skipping $resolvedProfile because certificate files are missing for '$effectiveName'."
            continue
        }

        $actionLabel = if ($Remove) { "Removing" } else { "Importing" }
        Write-Info "$actionLabel trusted certificates for $resolvedProfile."
        Write-Step "Root store: $($stores.RootStorePath)"
        Write-Step "Trusted publisher store: $($stores.PublisherStorePath)"

        if ($Remove) {
            Remove-Certificates -Paths $paths -Stores $stores
        }
        else {
            Import-Certificates -Paths $paths -Stores $stores
            Write-Success "Certificates imported for $resolvedProfile."
        }

        Show-TrustStatus -Paths $paths -Stores $stores
    }

    Show-SignedFileStatus
}
catch {
    Write-Failure $_.Exception.Message
    exit 1
}
