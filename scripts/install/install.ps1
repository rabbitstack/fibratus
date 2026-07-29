#Requires -Version 5.1
<#
.SYNOPSIS
    Installs or upgrades Fibratus from the latest GitHub release.

.DESCRIPTION
    Downloads the latest Fibratus MSI from https://github.com/rabbitstack/fibratus/releases,
    checks for an existing installation/service, verifies the download against the published
    .sha256 checksum, prompts for license acceptance, and performs a silent msiexec install.
    Intended for irm https://install.fibratus.io/ | iex

.PARAMETER Version
    Install a specific release tag (e.g. "v2.4.0") instead of the latest one.

.PARAMETER Force
    Skip the upgrade confirmation and license prompts (non-interactive mode).
    By using -Force you are indicating that you accept the license agreement.

.PARAMETER InstallDir
    Passes INSTALLDIR to msiexec so Fibratus is installed to a custom directory.

.PARAMETER SkipSignatureCheck
    Skip Authenticode signature verification. Checksum verification still runs. Not
    recommended; only intended as an escape hatch for air-gapped/offline test environments
    where Windows cannot reach a CRL/OCSP endpoint to validate the certificate chain.
 
.PARAMETER ExpectedSignerThumbprint
    Optional. If set, the MSI's signing certificate thumbprint must match this value exactly,
    in addition to passing normal chain-of-trust validation. Use this to pin to a specific
    SignPath-issued certificate rather than accepting any validly-chained signer. Leave unset
    to accept any certificate that chains to a trusted root (the default, and the safer choice
    across certificate rotations unless you're actively tracking SignPath's current thumbprint).
#>

[CmdletBinding()]
param(
    [string]$Version,
    [switch]$Force,
    [string]$InstallDir,
    [switch]$SkipSignatureCheck,
    [string]$ExpectedSignerThumbprint
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# Ensure modern TLS for Windows PowerShell 5.1 hosts
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$script:Repo        = 'rabbitstack/fibratus'
$script:ServiceName = 'fibratus'
$script:LicenseUrl  = 'https://github.com/rabbitstack/fibratus/blob/master/LICENSE'

function Write-Step    { param([string]$Message) Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok      { param([string]$Message) Write-Host "[OK]   $Message" -ForegroundColor Green }
function Write-Warn    { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Err     { param([string]$Message) Write-Host "[FAIL] $Message" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Spinner (only animates on an interactive console; degrades to a static
# message when output is redirected, e.g. piped through `iex` inside a
# non-interactive CI runner where a real console buffer isn't available)
# ---------------------------------------------------------------------------
 
$script:SpinnerFrames = @('|', '/', '-', '\')
 
function Write-SpinnerFrame {
    param([int]$FrameIndex, [string]$Message)
    if ([Console]::IsOutputRedirected) { return }
    $frame = $script:SpinnerFrames[$FrameIndex % $script:SpinnerFrames.Length]
    Write-Host -NoNewline "`r$Message $frame "
}

function Clear-SpinnerLine {
    param([string]$Message)
    if ([Console]::IsOutputRedirected) { return }
    Write-Host -NoNewline ("`r" + (' ' * ($Message.Length + 4)) + "`r")
}

function Invoke-WithSpinner {
    <#
        Runs $ScriptBlock in a background job and animates a spinner next to
        $Message until it completes, then returns whatever the job produced.
        Falls back to a plain synchronous call (no job, no animation) when
        output is redirected, since a spinner is pointless in a log file.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [string]$Message = 'Working...'
    )
 
    if ([Console]::IsOutputRedirected) {
        Write-Host $Message
        return & $ScriptBlock @ArgumentList
    }
 
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    $frame = 0
    try {
        while ($job.State -eq 'Running') {
            Write-SpinnerFrame -FrameIndex $frame -Message $Message
            Start-Sleep -Milliseconds 120
            $frame++
        }
    } finally {
        Clear-SpinnerLine -Message $Message
    }
 
    try {
        return Receive-Job -Job $job -ErrorAction Stop
    } finally {
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}


# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-InstalledProduct {
    <#
        Scans the uninstall registry hive instead of Win32_Product (which is slow and
        triggers a consistency-check repair against every installed MSI on the box).
    #>
    $hive = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'

    $entry = Get-ItemProperty -Path $hive -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like 'Fibratus*' } |
        Select-Object -First 1
    if ($entry) {
        return [pscustomobject]@{
            Version     = $entry.DisplayVersion
            ProductCode = $entry.PSChildName
            UninstallString = $entry.UninstallString
        }
    }
    
    return $null
}

function Get-ServiceStatus {
    Get-Service -Name $script:ServiceName -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# GitHub release resolution
# ---------------------------------------------------------------------------

function Get-Release {
    param([string]$Tag)

    $uri = if ($Tag) {
        "https://api.github.com/repos/$($script:Repo)/releases/tags/$Tag"
    } else {
        "https://api.github.com/repos/$($script:Repo)/releases/latest"
    }

    try {
        Invoke-RestMethod -Uri $uri -Headers @{ 'User-Agent' = 'fibratus'; 'Accept' = 'application/vnd.github+json' }
    } catch {
        throw "could not reach GitHub releases API ($uri): $($_.Exception.Message)"
    }
}

function Get-MsiAsset {
    param($Release)

    $asset = $Release.assets | Where-Object { $_.name -match '(?i)amd64.*\.msi$|x64.*\.msi$' } | Select-Object -First 1
    if (-not $asset) {
        $asset = $Release.assets | Where-Object { $_.name -match '(?i)\.msi$' } | Select-Object -First 1
    }
    return $asset
}

function Get-NormalizedVersion {
    param([string]$Raw)
    $trimmed = $Raw.TrimStart('v', 'V')
    # keep only the numeric dotted portion in case of pre-release suffixes like "2.4.0-rc1"
    if ($trimmed -match '^\d+(\.\d+){1,3}') { return $Matches[0] }
    return $trimmed
}

function Get-RemoteTextContent {
    param([string]$Uri)
 
    $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing
 
    # GitHub serves release assets (including .sha256 files) as application/octet-stream.
    # Windows PowerShell 5.1 decodes .Content to a string regardless; PowerShell 7+ returns
    # a raw byte[] for non-text content types. Handle both explicitly.
    if ($response.Content -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($response.Content)
    }
    return [string]$response.Content
}


function Get-ChecksumAsset {
    param($Release, $MsiAsset)

    # Every release publishes a "<msi-name>.sha256" artifact alongside the MSI itself,
    # e.g. fibratus-3.0.0-amd64.msi.sha256
    return $Release.assets | Where-Object { $_.name -eq "$($MsiAsset.name).sha256" } | Select-Object -First 1
}

function Get-ExpectedHashFromChecksumFile {
    param([string]$Content, [string]$ExpectedFileName)

    # Checksum files are typically either a bare hash, or the coreutils-style
    # "<hash>  <filename>" format. Extract the first 64-char hex token either way.
    if ($Content -match '([0-9a-fA-F]{64})') {
        return $Matches[1].ToLowerInvariant()
    }
    throw "checksum file did not contain a recognizable SHA-256 hash for $ExpectedFileName"
}

function Test-MsiSignature {
    param([string]$Path, [string]$ExpectedThumbprint)
 
    $sig = Get-AuthenticodeSignature -FilePath $Path
 
    switch ($sig.Status) {
        'Valid' {
            $thumbprint = $sig.SignerCertificate.Thumbprint
            if ($ExpectedThumbprint -and $thumbprint -ne $ExpectedThumbprint) {
                return [pscustomobject]@{
                    Ok      = $false
                    Message = "Certificate is validly chained and trusted, but its thumbprint ($thumbprint) does not match the pinned thumbprint ($ExpectedThumbprint). This may mean the signing certificate was rotated. Verify the new thumbprint out-of-band before updating -ExpectedSignerThumbprint."
                }
            }
            return [pscustomobject]@{
                Ok      = $true
                Message = 'Signature is valid.'
                Signer  = $sig.SignerCertificate.Subject
                Issuer  = $sig.SignerCertificate.Issuer
                Thumbprint = $thumbprint
            }
        }
        'NotSigned' {
            return [pscustomobject]@{ Ok = $false; Message = 'The MSI is not signed at all.' }
        }
        'HashMismatch' {
            return [pscustomobject]@{ Ok = $false; Message = 'The signed hash does not match the file contents (tampered after signing).' }
        }
        'NotTrusted' {
            return [pscustomobject]@{ Ok = $false; Message = "The signing certificate chain does not chain to a trusted root on this machine: $($sig.StatusMessage)" }
        }
        default {
            return [pscustomobject]@{ Ok = $false; Message = "Signature status: $($sig.Status) $($sig.StatusMessage)" }
        }
    }
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-IsAdministrator)) {
    Write-Err 'This script must be run from an elevated (Administrator) PowerShell session.'
    exit 1
}

Write-Step 'Checking for an existing Fibratus installation...'
$installed = Get-InstalledProduct
$service   = Get-ServiceStatus

if ($installed) {
    Write-Host "    Installed version : $($installed.Version)" -ForegroundColor White
} else {
    Write-Host '    No existing installation found.' -ForegroundColor DarkGray
}

Write-Step 'Resolving latest release...'
$release = Get-Release -Tag $Version
$latestVersion = Get-NormalizedVersion $release.tag_name
Write-Host "    Target version    : $latestVersion ($($release.tag_name))" -ForegroundColor White

if ($installed) {
    $upgrade = $true
    try {
        if ([version](Get-NormalizedVersion $installed.Version) -ge [version]$latestVersion) {
            $upgrade = $false
        }
    } catch {
        # non-parseable version string, fall through and offer the upgrade anyway
    }

    if (-not $upgrade -and -not $Force) {
        Write-Ok "Fibratus is already up to date ($($installed.Version))."
        exit 0
    }

    if (-not $Force) {
        $answer = Read-Host "Upgrade Fibratus $($installed.Version) -> $latestVersion ? [Y/n]"
        if ($answer -match '^(n|no)$') {
            Write-Host 'Installation cancelled.'
            exit 0
        }
    }

    if ($service -and $service.Status -eq 'Running') {
        Write-Step 'Stopping the Fibratus service before upgrade...'
        try {
            Stop-Service -Name $script:ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', (New-TimeSpan -Seconds 30))
            Write-Ok 'Service stopped.'
        } catch {
            Write-Err "Failed to stop the Fibratus service: $($_.Exception.Message)"
            Write-Err 'Close any running Fibratus processes and re-run the installer.'
            exit 1
        }
    }
} else {
    Write-Host ''
}

if (-not $Force) {
    Write-Host ''
    Write-Host "Fibratus is distributed under the terms of its license:" -ForegroundColor White
    Write-Host "    $script:LicenseUrl" -ForegroundColor White
    $agree = Read-Host 'Do you accept the license agreement? [y/N]'
    if ($agree -notmatch '^(y|yes)$') {
        Write-Err 'License agreement not accepted. Aborting installation.'
        exit 1
    }
    Write-Host ''
}

$asset = Get-MsiAsset -Release $release
if (-not $asset) {
    Write-Err "No installer was found on release $($release.tag_name)."
    exit 1
}

$msiPath = Join-Path $env:TEMP $asset.name
Write-Step "Downloading $($asset.name)..."
try {
    Invoke-WithSpinner -Message "Downloading $($asset.name)" -ArgumentList @($asset.browser_download_url, $msiPath) -ScriptBlock {
        param($Uri, $OutFile)
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    } | Out-Null
    Write-Ok "Downloaded to $msiPath"
} catch {
    Write-Err "Download failed: $($_.Exception.Message)"
    exit 1
}

Write-Step 'Verifying MSI checksum...'
$checksumAsset = Get-ChecksumAsset -Release $release -MsiAsset $asset
if (-not $checksumAsset) {
    Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
    Write-Err "No .sha256 checksum asset was found for $($asset.name) on release $($release.tag_name)."
    Write-Err 'Refusing to install an unverified MSI.'
    exit 1
}

try {
    $checksumContent = Get-RemoteTextContent -Uri $checksumAsset.browser_download_url
    $expectedHash = Get-ExpectedHashFromChecksumFile -Content $checksumContent -ExpectedFileName $asset.name
} catch {
    Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
    Write-Err "Failed to retrieve or parse the checksum file: $($_.Exception.Message)"
    exit 1
}

$actualHash = (Get-FileHash -Path $msiPath -Algorithm SHA256).Hash.ToLowerInvariant()

if ($actualHash -ne $expectedHash) {
    Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
    Write-Err 'Checksum verification FAILED. The downloaded file does not match the published SHA-256 hash.'
    Write-Err "    Expected : $expectedHash"
    Write-Err "    Actual   : $actualHash"
    Write-Err 'The download may be corrupted or tampered with. Aborting installation.'
    exit 1
}

Write-Ok "Checksum verified (SHA-256: $actualHash)"

if ($SkipSignatureCheck) {
    Write-Warn 'Authenticode signature check skipped (-SkipSignatureCheck).'
} else {
    Write-Step 'Verifying MSI signature...'
    $sigResult = Test-MsiSignature -Path $msiPath -ExpectedThumbprint $ExpectedSignerThumbprint
    if (-not $sigResult.Ok) {
        Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
        Write-Err "Signature verification FAILED: $($sigResult.Message)"
        Write-Err 'Aborting installation.'
        exit 1
    }
    Write-Ok "Signature valid. Signed by: $($sigResult.Signer)"
    Write-Host "    Certificate thumbprint: $($sigResult.Thumbprint)" -ForegroundColor DarkGray
}

Write-Step 'Installing Fibratus...'
$logPath = Join-Path $env:TEMP 'fibratus-install.log'
$msiexecArgs = @('/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$logPath`"")
if ($InstallDir) {
    $msiexecArgs += "INSTALLDIR=`"$InstallDir`""
}

$proc = Start-Process -FilePath msiexec.exe -ArgumentList $msiexecArgs -PassThru
$frame = 0
while (-not $proc.HasExited) {
    Write-SpinnerFrame -FrameIndex $frame -Message 'Installing Fibratus'
    Start-Sleep -Milliseconds 120
    $frame++
}
Clear-SpinnerLine -Message 'Installing Fibratus'
$proc.Refresh()

switch ($proc.ExitCode) {
    0 {
        Write-Ok 'MSI installation completed successfully.'
    }
    3010 {
        Write-Warn 'Installation completed successfully, but a reboot is required.'
    }
    1603 {
        Write-Err "A fatal error occurred during installation. See the log: $logPath"
        exit 1
    }
    1618 {
        Write-Err 'Another installation is already in progress. Please retry once it finishes.'
        exit 1
    }
    1602 {
        Write-Err 'Installation was cancelled by the user.'
        exit 1
    }
    default {
        Write-Err "msiexec exited with code $($proc.ExitCode). See the log: $logPath"
        exit 1
    }
}

$timeoutSeconds = 30
$elapsed = 0
$svc = $null
while (-not $svc -and $elapsed -lt $timeoutSeconds) {
    Start-Sleep -Seconds 1
    $elapsed++
    $svc = Get-ServiceStatus
}

if (-not $svc) {
    Write-Err "The '$script:ServiceName' service was not found after installation."
    Write-Err "Check the MSI log for details: $logPath"
    exit 1
}

if ($svc.Status -ne 'Running') {
    Write-Step 'Starting the Fibratus service...'
    try {
        Start-Service -Name $script:ServiceName -ErrorAction Stop
        $svc.WaitForStatus('Running', (New-TimeSpan -Seconds 20))
    } catch {
        Write-Warn "Fibratus was installed, but the service could not be started automatically: $($_.Exception.Message)"
        Write-Warn "Try starting it manually: Start-Service -Name $script:ServiceName"
        exit 0
    }
}

$svc.Refresh()
if ($svc.Status -eq 'Running') {
    Write-Ok "Fibratus service is running."
} else {
    Write-Warn "Fibratus service status is currently '$($svc.Status)'."
}

Write-Host ''
Write-Host "Fibratus $latestVersion was installed successfully." -ForegroundColor Green
Write-Host "Check the docs at https://www.fibratus.io/docs to get started." -ForegroundColor White
Write-Host ''

Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
