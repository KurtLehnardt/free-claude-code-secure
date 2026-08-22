# Supply-chain-hardened Windows installer for Free Claude Code -- the PowerShell
# counterpart of scripts/install.sh, sharing the scripts/install.checksums
# manifest.
#
# Every remotely downloaded installer script or release artifact is verified
# against a pinned sha256 in scripts/install.checksums BEFORE it is executed or
# extracted: the vendor *.ps1 installers (Claude, Codex, Pi, Hermes, Grok), the
# pinned uv release archive, the OpenCode Windows release archive, RTK, and the
# npm-distributed agents (Cline, DeepSeek Harness). The installer is FAIL-CLOSED:
# a component whose expected checksum is missing or the literal token REPLACE_ME
# is refused unless -AllowUnpinned is passed. Free Claude Code itself is installed
# from a git checkout pinned to an exact commit (matching install.sh's
# FCC_COMMIT), not an unversioned archive.
#
# npm-distributed agents are pinned to an exact version (never a floating
# "latest") and are fetched via `npm pack` into an isolated temp dir -- a plain
# artifact download that runs no lifecycle scripts -- so the downloaded tarball
# can be sha256-verified against the same manifest and FAIL-CLOSED policy as every
# other component before anything is installed. Residual trust: this verifies the
# package ARTIFACT; it does not and cannot sandbox the package's own preinstall/
# postinstall scripts, which still run with your user's privileges during the
# final `npm install -g <verified-tarball>` step, same as any npm package.
#
# -RefreshChecksums downloads each installer/artifact, prints "id=<sha256>" lines
# to stdout, and exits -- it executes nothing and never edits the manifest. Use it
# (or scripts/install.sh --refresh-checksums) to compute a hash, review it against
# a trusted source, and paste it into install.checksums.
param(
    [switch] $VoiceNim,
    [switch] $VoiceLocal,
    [switch] $VoiceAll,
    [string] $TorchBackend = "",
    [switch] $Rtk,
    [string] $FccRef = "",
    [string] $Checksums = "",
    [switch] $AllowUnpinned,
    [switch] $RefreshChecksums,
    [switch] $DryRun,
    [switch] $Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]] $RemainingArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Enforce TLS 1.2+ before any network call. On Windows PowerShell 5.1 over older
# .NET, Invoke-RestMethod can otherwise negotiate down to TLS 1.0/1.1, weakening
# the transport-integrity backstop that protects downloads (most important on the
# -AllowUnpinned path, where the sha256 gate is relaxed). -bor so we ADD TLS 1.2
# without clobbering TLS 1.3 where the platform already enables it.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$FccRepoUrl = "https://github.com/alishahryar1/free-claude-code"
# Default pinned Free Claude Code commit. MUST match install.sh's FCC_COMMIT so
# both installers pin the exact same source tree (real, verified main HEAD).
$FccCommit = "9372cfa5e2dc48fe1adf9743473f3763b3b08592"
# Windows on ARM emulates x64, whose Python package ecosystem has broader wheel support.
$PythonRequest = "cpython-3.14.0-windows-x86_64-none"
$MinUvVersion = "0.11.16"
# uv is pinned to a versioned astral-sh/uv release artifact (not the rolling
# astral.sh/uv/install.ps1 script). Windows on ARM emulates x64, so -- like the
# pinned Python request and RTK asset above/below -- uv is pinned to the x86_64
# msvc release .zip. Its sha256 lives in the manifest.
$UvVersion = "0.11.16"
$UvReleaseBaseUrl = "https://github.com/astral-sh/uv/releases/download/$UvVersion"
$UvWindowsTarget = "x86_64-pc-windows-msvc"
$UvWindowsAssetName = "uv-$UvWindowsTarget.zip"
$ClaudeInstallUrl = "https://claude.ai/install.ps1"
$CodexInstallUrl = "https://chatgpt.com/codex/install.ps1"
$PiInstallUrl = "https://pi.dev/install.ps1"
$OpenCodeReleaseBaseUrl = "https://github.com/anomalyco/opencode/releases/latest/download"
$MinOpenCodeVersion = "1.18.18"
$MinClineVersion = "3.0.55"
# Exact npm pin for fresh Cline installs (no floating "latest"). An
# already-installed Cline satisfying >=MinClineVersion is left unchanged;
# see Ensure-Cline. Pinned to the same version because it is also the oldest
# version this installer has verified compatible.
$ClinePackage = "cline@$MinClineVersion"
$HermesInstallUrl = "https://hermes-agent.nousresearch.com/install.ps1"
$MinHermesVersion = "0.20.4"
$DshVersion = "0.1.0-rc.8"
$DshPackage = "@deepseek-ai/dsh@$DshVersion"
$GrokInstallUrl = "https://x.ai/cli/install.ps1"
$MinGrokVersion = "1.0.5"
$MinMuseVersion = "0.2.1"
$RtkVersion = "0.44.2"
$RtkReleaseBaseUrl = "https://github.com/rtk-ai/rtk/releases/download/v$RtkVersion"
$RtkWindowsTarget = "x86_64-pc-windows-msvc"
$RtkWindowsAssetName = "rtk-$RtkWindowsTarget.zip"
# Resolved once at startup; see Resolve-ChecksumsFile / the main flow below.
$script:ChecksumsFile = ""
$script:FccRef = ""
$script:InstallClaudeCode = $true
$script:InstallCodex = $true
$script:InstallPi = $true
$script:InstallOpenCode = $true
$script:InstallCline = $false
$script:InstallHermes = $true
$script:InstallDsh = $true
$script:InstallGrok = $true
$script:InstallMuse = $true
$script:PiAvailable = $false
$script:MuseAvailable = $false
$script:EnableRtk = $Rtk.IsPresent
$FccCommands = @(
    # Include retired entry points so updates reject older FCC processes before replacement.
    "fcc-desktop",
    "fcc-server",
    "fcc-claude",
    "fcc-codex",
    "fcc-pi",
    "fcc-opencode",
    "fcc-cline",
    "fcc-hermes",
    "fcc-dsh",
    "fcc-grok",
    "fcc-muse",
    "fcc-init",
    "free-claude-code"
)

function Show-Usage {
    @"
Usage: install.ps1 [options]

Installs or updates Free Claude Code and lets you choose which coding agents to install or verify.
Every downloaded installer script and release artifact -- the vendor *.ps1 installers, the pinned uv
release, the OpenCode Windows release, RTK, and npm-distributed agents (Cline, DeepSeek Harness), which
are pinned to an exact version and packed via `npm pack` for verification before install -- is
checksum-verified against a pinned manifest (scripts/install.checksums) before it runs. Free Claude
Code itself is installed from a git checkout pinned to an exact commit. Unpinned components are refused
unless you explicitly pass -AllowUnpinned.

Options:
  -VoiceNim              Install NVIDIA NIM voice transcription support.
  -VoiceLocal            Install local Whisper voice transcription support.
  -VoiceAll              Install all voice transcription backends.
  -TorchBackend VALUE    Use a uv PyTorch backend, such as cu130. Requires local voice.
  -Rtk                   Install and configure RTK for the selected coding agents.
  -FccRef SHA            Install Free Claude Code at this git commit (default: pinned commit).
  -Checksums PATH        Path to the checksum manifest (default: install.checksums beside this script).
  -AllowUnpinned         Execute components without a pinned checksum. INSECURE; prints a warning.
  -RefreshChecksums      Download each installer/artifact, print id=sha256 lines, and exit.
                         Does NOT execute anything and does NOT modify the manifest.
  -DryRun                Print commands without running them.
  -Help                  Show this help text.
"@
}

function Write-Step {
    param([string] $Message)

    Write-Host ""
    Write-Host "==> $Message"
}

function Test-InteractiveInstaller {
    return (-not [Console]::IsInputRedirected) -and (-not [Console]::IsOutputRedirected)
}

function Read-YesNo {
    param(
        [string] $Prompt,
        [bool] $DefaultYes = $true
    )

    while ($true) {
        $hint = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
        $answer = ([string] (Read-Host "$Prompt $hint")).Trim().ToLowerInvariant()
        if ($answer -eq "") {
            return $DefaultYes
        }
        if ($answer -in @("y", "yes")) {
            return $true
        }
        if ($answer -in @("n", "no")) {
            return $false
        }
        Write-Host "Please answer Y or N."
    }
}

function Select-CodingAgents {
    while ($true) {
        $script:InstallClaudeCode = Read-YesNo "Install or verify Claude Code for fcc-claude?"
        $script:InstallCodex = Read-YesNo "Install or verify Codex for fcc-codex?"
        $script:InstallPi = Read-YesNo "Install or verify Pi for fcc-pi?"
        $script:InstallOpenCode = Read-YesNo "Install or verify OpenCode for fcc-opencode?"
        $script:InstallCline = Read-YesNo `
            -Prompt "Install or verify Cline CLI for fcc-cline?" `
            -DefaultYes $script:InstallCline
        $script:InstallHermes = Read-YesNo `
            -Prompt "Install or verify Hermes Agent for fcc-hermes?" `
            -DefaultYes $script:InstallHermes
        $script:InstallDsh = Read-YesNo `
            -Prompt "Install or verify DeepSeek Harness for fcc-dsh?" `
            -DefaultYes $script:InstallDsh
        $script:InstallGrok = Read-YesNo `
            -Prompt "Install or verify Grok Build for fcc-grok?" `
            -DefaultYes $script:InstallGrok
        $script:InstallMuse = Read-YesNo `
            -Prompt "Install or verify Muse Code for fcc-muse?" `
            -DefaultYes $script:InstallMuse

        if ($script:InstallClaudeCode -or $script:InstallCodex -or $script:InstallPi -or $script:InstallOpenCode -or $script:InstallCline -or $script:InstallHermes -or $script:InstallDsh -or $script:InstallGrok -or $script:InstallMuse) {
            break
        }
        Write-Host "Select at least one coding agent."
        Write-Host ""
    }

    if (-not $script:EnableRtk) {
        $script:EnableRtk = Read-YesNo `
            -Prompt "Enable RTK token optimization globally for the selected coding agents?" `
            -DefaultYes $false
    }
}

function Format-Argument {
    param([string] $Value)

    if ($Value -match '^[A-Za-z0-9_./:@%+=,\[\]\\-]+$') {
        return $Value
    }

    return "'" + ($Value -replace "'", "''") + "'"
}

function Format-Command {
    param(
        [string] $FilePath,
        [string[]] $Arguments = @()
    )

    $parts = @($FilePath) + $Arguments
    return ($parts | ForEach-Object { Format-Argument ([string] $_) }) -join " "
}

function Invoke-NativeCommand {
    param(
        [string] $FilePath,
        [string[]] $Arguments = @()
    )

    $commandText = Format-Command -FilePath $FilePath -Arguments $Arguments
    Write-Host "+ $commandText"
    if ($DryRun) {
        return
    }

    $global:LASTEXITCODE = 0
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $commandText"
    }
}

function Invoke-Utf8NativeCapture {
    param(
        [string] $FilePath,
        [string[]] $Arguments = @()
    )

    $commandText = Format-Command -FilePath $FilePath -Arguments $Arguments
    Write-Host "+ $commandText"
    $originalOutputEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $global:LASTEXITCODE = 0
        $output = & $FilePath @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        [Console]::OutputEncoding = $originalOutputEncoding
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $commandText"
    }

    return ($output | Out-String).Trim()
}

function Get-ApplicationCommand {
    param([string] $Name)

    $commands = @(Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue)
    if ($commands.Count -eq 0) {
        return $null
    }

    return $commands[0]
}

# Resolve the checksum manifest path once (CLI -Checksums > FCC_CHECKSUMS_FILE env
# var > install.checksums beside this script), mirroring install.sh's
# resolve_checksums_file. Stored in $script:ChecksumsFile for every later lookup.
function Resolve-ChecksumsFile {
    if (-not [string]::IsNullOrWhiteSpace($Checksums)) {
        $script:ChecksumsFile = $Checksums
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:FCC_CHECKSUMS_FILE)) {
        $script:ChecksumsFile = $env:FCC_CHECKSUMS_FILE
    }
    else {
        $scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $script:ChecksumsFile = Join-Path $scriptDirectory "install.checksums"
    }
}

# Compute the lowercase-hex sha256 of a file, matching the format stored in the
# manifest and printed by install.sh's compute_sha256.
function Get-FileSha256 {
    param([string] $Path)

    $sha256 = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try {
        return [BitConverter]::ToString($sha256.ComputeHash($stream)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha256.Dispose()
    }
}

# Reads scripts/install.checksums (the same manifest install.sh uses; path from
# Resolve-ChecksumsFile) and returns the pinned sha256 for $ComponentId, or $null
# if the file or the row is missing. Format: "<component-id>=<sha256>"; blank
# lines and lines starting with '#' are ignored, matching install.sh's parser.
function Get-PinnedChecksum {
    param([string] $ComponentId)

    $manifestPath = $script:ChecksumsFile
    if ([string]::IsNullOrWhiteSpace($manifestPath) -or (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf))) {
        return $null
    }

    foreach ($line in Get-Content -LiteralPath $manifestPath) {
        $trimmedLine = $line.Trim()
        if (($trimmedLine.Length -eq 0) -or $trimmedLine.StartsWith("#")) {
            continue
        }
        $separatorIndex = $trimmedLine.IndexOf("=")
        if ($separatorIndex -lt 0) {
            continue
        }
        # Strip ALL whitespace from key and value (not just the ends) to match
        # install.sh's `tr -d '[:space:]'`, so both parsers agree on every row.
        $key = $trimmedLine.Substring(0, $separatorIndex) -replace '\s', ''
        if ($key -ne $ComponentId) {
            continue
        }
        $value = $trimmedLine.Substring($separatorIndex + 1)
        $commentIndex = $value.IndexOf("#")
        if ($commentIndex -ge 0) {
            $value = $value.Substring(0, $commentIndex)
        }
        return ($value -replace '\s', '')
    }

    return $null
}

# Loud multi-line stderr banner shown once when -AllowUnpinned is set, mirroring
# install.sh's print_unpinned_banner.
function Write-UnpinnedBanner {
    $lines = @(
        '********************************************************************************',
        '*                   SECURITY WARNING: -AllowUnpinned is set                  *',
        '*                                                                            *',
        '* Checksum verification is DISABLED for every component whose sha256 is      *',
        '* missing or REPLACE_ME in the manifest. Downloaded installer scripts and    *',
        '* release artifacts will be EXECUTED WITHOUT integrity verification.         *',
        '* This exposes you to supply-chain tampering and man-in-the-middle attacks.  *',
        '* Only continue if you fully trust your network path and every upstream      *',
        '* vendor. Prefer pinning real hashes via -RefreshChecksums instead.          *',
        '********************************************************************************'
    )
    foreach ($line in $lines) {
        [Console]::Error.WriteLine($line)
    }
}

# Verify an already-downloaded file for a component against the pinned manifest,
# mirroring install.sh's resolve_component_checksum + verify_downloaded_file:
#   * a real pinned hash    -> verify; a mismatch is fatal (even with
#                              -AllowUnpinned -- the escape hatch never bypasses a
#                              real pin).
#   * REPLACE_ME / missing  -> FAIL CLOSED, refusing to run unverified code,
#                              UNLESS -AllowUnpinned, which warns (printing the
#                              observed sha256) and proceeds.
# Throws on any verification failure; returns normally when the caller may
# proceed to execute/extract the file.
function Confirm-PinnedFile {
    param(
        [string] $Path,
        [string] $Label,
        [string] $ComponentId
    )

    $actualHash = Get-FileSha256 -Path $Path
    $expectedHash = Get-PinnedChecksum -ComponentId $ComponentId

    if ($expectedHash -and ($expectedHash -ne "REPLACE_ME")) {
        if ($actualHash -ne $expectedHash) {
            throw "Checksum verification failed for $Label (component id: $ComponentId): expected $expectedHash, computed $actualHash. Refusing to continue."
        }
        Write-Host "Verified $Label against pinned sha256 (component id: $ComponentId)."
        return
    }

    if ($AllowUnpinned) {
        Write-Warning "$Label executed without verification; computed sha256=$actualHash (component id: $ComponentId). -AllowUnpinned is set."
        return
    }

    if (-not (Test-Path -LiteralPath $script:ChecksumsFile -PathType Leaf)) {
        throw "Checksum manifest not found at $($script:ChecksumsFile). This hardened installer refuses to run downloaded code without it. Run from a repository checkout, set FCC_CHECKSUMS_FILE, pass -Checksums <path>, or re-run with -AllowUnpinned (NOT recommended)."
    }

    throw "No pinned sha256 for component `"$ComponentId`" ($Label) in $($script:ChecksumsFile) (value is missing or REPLACE_ME). Refusing to run unverified code. Run 'install.ps1 -RefreshChecksums' (or scripts/install.sh --refresh-checksums) to compute it, review it against a trusted source, paste the id=hash line into the manifest, then rerun; or re-run with -AllowUnpinned to bypass verification (NOT recommended)."
}

# Fetches the exact published npm tarball for $PackageSpec via `npm pack`
# into an isolated temp dir. `npm pack` on a registry spec is a plain
# artifact download -- it does not run the target package's lifecycle
# scripts -- so the downloaded bytes can be sha256-verified against
# scripts/install.checksums (via Confirm-PinnedFile) before anything is
# installed, fail-closed by the same -AllowUnpinned policy as every other
# component. Only after that check does it install globally FROM the verified
# local tarball, so the bytes that get installed are exactly the bytes that
# were hashed (no second, unverified registry round-trip).
#
# Residual trust: this verifies the package ARTIFACT. It does not sandbox
# the npm package's own preinstall/postinstall scripts, which still run
# with the invoking user's privileges during the final `npm install -g`,
# same as any npm package.
function Install-NpmPackageVerified {
    param(
        [string] $PackageSpec,
        [string] $Label,
        [string] $ComponentId
    )

    if ($DryRun) {
        Write-Host "+ npm pack $PackageSpec --pack-destination <temporary-dir> --ignore-scripts"
        Write-Host "+ verify sha256 of the packed $Label tarball against $($script:ChecksumsFile) (component: $ComponentId)"
        Write-Host "+ npm install -g --no-fund --no-audit=false <verified-tarball>"
        return
    }

    $npm = Get-ApplicationCommand "npm"
    if (-not $npm) {
        throw "$Label installation requires npm."
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-npm-pack-" + [guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

        Invoke-NativeCommand -FilePath $npm.Source -Arguments @("pack", $PackageSpec, "--pack-destination", $temporaryRoot, "--ignore-scripts")

        $tarballs = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter "*.tgz")
        if ($tarballs.Count -eq 0) {
            throw "npm pack did not produce a tarball for $Label ($PackageSpec)."
        }
        $tarballPath = $tarballs[0].FullName

        Confirm-PinnedFile -Path $tarballPath -Label $Label -ComponentId $ComponentId

        Invoke-NativeCommand -FilePath $npm.Source -Arguments @("install", "-g", "--no-fund", "--no-audit=false", $tarballPath)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-PowerShellExecutable {
    param([string] $PowerShellHome = $PSHOME)

    $executableName = if ($PSVersionTable.PSEdition -eq "Core") {
        "pwsh.exe"
    }
    else {
        "powershell.exe"
    }
    $bundledExecutable = Join-Path $PowerShellHome $executableName
    if (Test-Path -LiteralPath $bundledExecutable -PathType Leaf) {
        return $bundledExecutable
    }

    $pathCommand = Get-ApplicationCommand ([IO.Path]::GetFileNameWithoutExtension($executableName))
    if ($pathCommand) {
        return $pathCommand.Source
    }

    throw "Unable to locate a PowerShell executable for the downloaded installer."
}

function Add-PathEntry {
    param([string] $PathEntry)

    if ([string]::IsNullOrWhiteSpace($PathEntry)) {
        return
    }

    $separator = [IO.Path]::PathSeparator
    $entries = @()
    if (-not [string]::IsNullOrEmpty($env:Path)) {
        $entries = $env:Path -split [regex]::Escape([string] $separator)
    }

    if ($entries -notcontains $PathEntry) {
        $env:Path = "$PathEntry$separator$env:Path"
    }
}

function Add-KnownBinDirectories {
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Add-PathEntry (Join-Path $env:USERPROFILE ".local\bin")
        Add-PathEntry (Join-Path $env:USERPROFILE ".opencode\bin")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Add-PathEntry (Join-Path $env:LOCALAPPDATA "hermes\hermes-agent\bin")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Add-PathEntry (Join-Path $env:LOCALAPPDATA "Programs\OpenAI\Codex\bin")
        Add-PathEntry (Join-Path $env:LOCALAPPDATA "pi-node\current")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        Add-PathEntry (Join-Path $env:APPDATA "npm")
    }
}

function Add-NpmBinDirectories {
    if ($DryRun) {
        return
    }

    Add-KnownBinDirectories
    $npm = Get-ApplicationCommand "npm"
    if (-not $npm) {
        return
    }

    $prefix = (& $npm.Source prefix -g 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($prefix)) {
        $prefix = (& $npm.Source config get prefix 2>$null | Out-String).Trim()
    }
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($prefix)) {
        Add-PathEntry $prefix
    }
}

function Assert-NoFccProcessesRunning {
    $running = @()
    foreach ($commandName in $FccCommands) {
        $processes = @(Get-Process -Name $commandName -ErrorAction SilentlyContinue)
        foreach ($process in $processes) {
            $running += "$commandName (PID $($process.Id))"
        }
    }

    if ($running.Count -gt 0) {
        throw "Free Claude Code is still running ($($running -join ', ')). Stop those processes, then rerun the installer."
    }
}

function Invoke-DownloadedPowerShellInstaller {
    param(
        [string] $Url,
        [string] $Name,
        [string] $ComponentId,
        [switch] $NonInteractive,
        [string[]] $ScriptArguments = @()
    )

    if ($DryRun) {
        Write-Host "+ irm $Url -OutFile <temporary-script>"
        Write-Host "+ verify sha256 of <temporary-script> against $($script:ChecksumsFile) (component: $ComponentId)"
        $prefix = if ($NonInteractive) { "CODEX_NON_INTERACTIVE=1 " } else { "" }
        $suffix = if ($ScriptArguments.Count -gt 0) {
            " " + (($ScriptArguments | ForEach-Object { Format-Argument $_ }) -join " ")
        }
        else {
            ""
        }
        Write-Host "+ ${prefix}powershell -NoProfile -ExecutionPolicy Bypass -File <temporary-script>$suffix"
        return
    }

    $temporaryScript = Join-Path ([IO.Path]::GetTempPath()) ("fcc-install-" + [guid]::NewGuid().ToString("N") + ".ps1")
    try {
        Write-Host "+ irm $Url -OutFile $(Format-Argument $temporaryScript)"
        Invoke-RestMethod -Uri $Url -OutFile $temporaryScript -ErrorAction Stop
        if ((-not (Test-Path -LiteralPath $temporaryScript)) -or ((Get-Item -LiteralPath $temporaryScript).Length -eq 0)) {
            throw "The downloaded $Name installer was empty."
        }

        # Fail-closed integrity gate: verify the downloaded bytes against the
        # pinned manifest BEFORE parsing or executing them.
        Confirm-PinnedFile -Path $temporaryScript -Label "$Name installer" -ComponentId $ComponentId

        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $temporaryScript,
            [ref] $tokens,
            [ref] $parseErrors
        ) | Out-Null
        if ($parseErrors.Count -gt 0) {
            throw "The downloaded $Name installer from '$Url' is not valid PowerShell. A network proxy or filter may have replaced it with an HTML response."
        }

        $powerShellPath = Get-PowerShellExecutable

        $hadNonInteractive = Test-Path Env:CODEX_NON_INTERACTIVE
        $previousNonInteractive = $env:CODEX_NON_INTERACTIVE
        try {
            if ($NonInteractive) {
                $env:CODEX_NON_INTERACTIVE = "1"
            }
            $installerArguments = @(
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                $temporaryScript
            ) + $ScriptArguments
            Invoke-NativeCommand -FilePath $powerShellPath -Arguments $installerArguments
        }
        finally {
            if ($hadNonInteractive) {
                $env:CODEX_NON_INTERACTIVE = $previousNonInteractive
            }
            else {
                Remove-Item Env:CODEX_NON_INTERACTIVE -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryScript -Force -ErrorAction SilentlyContinue
    }
}

function Confirm-Application {
    param(
        [string] $CommandName,
        [string] $DisplayName
    )

    if ($DryRun) {
        Write-Host "+ $CommandName --version"
        return
    }

    $command = Get-ApplicationCommand $CommandName
    if (-not $command) {
        throw "$DisplayName was installed, but '$CommandName' is not available on PATH."
    }
    Invoke-NativeCommand -FilePath $command.Source -Arguments @("--version")
}

function Test-PiApplication {
    param($Command)

    try {
        $helpOutput = (& $Command.Source --help 2>$null | Out-String)
    }
    catch {
        return $false
    }
    return (
        $LASTEXITCODE -eq 0 -and
        $helpOutput.Contains("--extension") -and
        $helpOutput.Contains("--models")
    )
}

function Confirm-PiApplication {
    if ($DryRun) {
        Write-Host "+ pi --help (verify --extension and --models support)"
        Write-Host "+ pi --version"
        return
    }

    $command = Get-ApplicationCommand "pi"
    if (-not $command) {
        throw "Pi was installed, but 'pi' is not available on PATH."
    }
    if (-not (Test-PiApplication $command)) {
        throw "The 'pi' command at '$($command.Source)' is not a compatible Pi Coding Agent."
    }
    Invoke-NativeCommand -FilePath $command.Source -Arguments @("--version")
}

function Install-Rtk {
    $archiveUrl = "$RtkReleaseBaseUrl/$RtkWindowsAssetName"
    $componentId = "rtk-$RtkVersion-$RtkWindowsTarget"
    if ($DryRun) {
        Write-Host "+ irm $archiveUrl -OutFile <temporary-archive>"
        Write-Host "+ verify sha256 for $RtkWindowsAssetName against $($script:ChecksumsFile) (component: $componentId)"
        Write-Host "+ extract and install rtk.exe to ~/.local/bin"
        return
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-rtk-" + [guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $temporaryRoot $RtkWindowsAssetName
    $extractPath = Join-Path $temporaryRoot "extracted"
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

        Write-Host "+ irm $archiveUrl -OutFile $(Format-Argument $archivePath)"
        Invoke-RestMethod -Uri $archiveUrl -OutFile $archivePath -ErrorAction Stop
        if ((-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) -or ((Get-Item -LiteralPath $archivePath).Length -eq 0)) {
            throw "The RTK release archive was empty."
        }

        # Fail-closed integrity gate before extracting the archive.
        Confirm-PinnedFile -Path $archivePath -Label "RTK $RtkVersion archive ($RtkWindowsAssetName)" -ComponentId $componentId

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath
        $extractedExecutable = Join-Path $extractPath "rtk.exe"
        if (-not (Test-Path -LiteralPath $extractedExecutable -PathType Leaf)) {
            throw "The verified RTK archive did not contain rtk.exe."
        }

        $installDirectory = Join-Path $env:USERPROFILE ".local\bin"
        New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
        Copy-Item -LiteralPath $extractedExecutable -Destination (Join-Path $installDirectory "rtk.exe") -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryRoot) {
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-RtkCommand {
    param([string[]] $Arguments)

    if ($DryRun) {
        Write-Host "+ RTK_TELEMETRY_DISABLED=1 $(Format-Command -FilePath 'rtk' -Arguments $Arguments)"
        return
    }

    $command = Get-ApplicationCommand "rtk"
    if (-not $command) {
        throw "RTK was installed, but 'rtk' is not available on PATH."
    }

    $hadTelemetryDisabled = Test-Path Env:RTK_TELEMETRY_DISABLED
    $previousTelemetryDisabled = $env:RTK_TELEMETRY_DISABLED
    try {
        $env:RTK_TELEMETRY_DISABLED = "1"
        Invoke-NativeCommand -FilePath $command.Source -Arguments $Arguments
    }
    finally {
        if ($hadTelemetryDisabled) {
            $env:RTK_TELEMETRY_DISABLED = $previousTelemetryDisabled
        }
        else {
            Remove-Item Env:RTK_TELEMETRY_DISABLED -ErrorAction SilentlyContinue
        }
    }
}

function Ensure-RtkClaudeConfigDirectory {
    $claudeConfigDirectory = $env:CLAUDE_CONFIG_DIR
    if ([string]::IsNullOrWhiteSpace($claudeConfigDirectory)) {
        $claudeConfigDirectory = Join-Path $env:USERPROFILE ".claude"
    }

    if ($DryRun) {
        Write-Host "+ mkdir $(Format-Argument $claudeConfigDirectory)"
        return
    }

    New-Item -ItemType Directory -Force -Path $claudeConfigDirectory | Out-Null
}

function Confirm-RtkApplication {
    if ($DryRun) {
        Invoke-RtkCommand -Arguments @("--version")
        Invoke-RtkCommand -Arguments @("gain")
        return
    }

    $command = Get-ApplicationCommand "rtk"
    if (-not $command) {
        throw "RTK was installed, but 'rtk' is not available on PATH."
    }

    try {
        Invoke-RtkCommand -Arguments @("--version")
        Invoke-RtkCommand -Arguments @("gain")
    }
    catch {
        throw "The 'rtk' command at '$($command.Source)' is not a compatible Rust Token Killer installation. Remove the conflicting command from PATH, then rerun the installer. $($_.Exception.Message)"
    }
}

function Ensure-Rtk {
    if (Get-ApplicationCommand "rtk") {
        Write-Host "RTK already found on PATH; verifying it without updating it."
    }
    else {
        Install-Rtk
        Add-KnownBinDirectories
    }

    Confirm-RtkApplication
}

function Configure-RtkForSelectedAgents {
    if (-not $script:EnableRtk) {
        return
    }

    Write-Step "Installing and configuring RTK token optimization"
    Ensure-Rtk

    if ($script:InstallClaudeCode) {
        Ensure-RtkClaudeConfigDirectory
        Invoke-RtkCommand -Arguments @("init", "--global", "--auto-patch")
    }
    if ($script:InstallCodex) {
        Invoke-RtkCommand -Arguments @("init", "--global", "--codex")
    }
    if ($script:InstallPi -and $script:PiAvailable) {
        Invoke-RtkCommand -Arguments @("init", "--global", "--agent", "pi")
    }
    if ($script:InstallOpenCode) {
        Invoke-RtkCommand -Arguments @("init", "--global", "--opencode")
    }
    if ($script:InstallCline) {
        Write-Host "Optional for each project: cd <project>; `$env:RTK_TELEMETRY_DISABLED='1'; rtk init --agent cline"
    }
}

function Ensure-ClaudeCode {
    if (Get-ApplicationCommand "claude") {
        Write-Host "Claude Code already found on PATH; verifying it."
    }
    else {
        Invoke-DownloadedPowerShellInstaller -Url $ClaudeInstallUrl -Name "Claude Code" -ComponentId "claude-installer-ps1"
        Add-KnownBinDirectories
    }

    Confirm-Application -CommandName "claude" -DisplayName "Claude Code"
}

function Ensure-Codex {
    if (Get-ApplicationCommand "codex") {
        Write-Host "Codex already found on PATH; verifying it."
    }
    else {
        Invoke-DownloadedPowerShellInstaller -Url $CodexInstallUrl -Name "Codex" -ComponentId "codex-installer-ps1" -NonInteractive
        Add-KnownBinDirectories
    }

    Confirm-Application -CommandName "codex" -DisplayName "Codex"
}

function Ensure-Pi {
    $script:PiAvailable = $false
    Add-NpmBinDirectories
    $existingPi = Get-ApplicationCommand "pi"
    if ($existingPi -and ($DryRun -or (Test-PiApplication $existingPi))) {
        Write-Host "Pi already found on PATH; verifying it."
    }
    else {
        if ($existingPi) {
            Write-Host "The existing 'pi' command at '$($existingPi.Source)' is not Pi Coding Agent; installing Pi."
        }
        Invoke-DownloadedPowerShellInstaller -Url $PiInstallUrl -Name "Pi" -ComponentId "pi-installer-ps1"
        Add-NpmBinDirectories

        if (-not $DryRun) {
            $currentPi = Get-ApplicationCommand "pi"
            $unchangedIncompatiblePi = (
                $currentPi -and
                $existingPi -and
                $currentPi.Source -eq $existingPi.Source -and
                -not (Test-PiApplication $currentPi)
            )
            if ((-not $currentPi) -or $unchangedIncompatiblePi) {
                Write-Host "Pi was not installed; continuing without it."
                return
            }
        }
    }

    Confirm-PiApplication
    $script:PiAvailable = $true
}

function Convert-SemanticVersionOutput {
    param([string] $Output)

    if ([string]::IsNullOrWhiteSpace($Output)) {
        return ""
    }
    if ($Output -match '(?m)^\s*(?:(?:uv|opencode|cline|dsh|grok|node)(?:\s+version)?\s+|Hermes Agent\s+v?|v)?(?<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)(?:\s+\([^\r\n]*\))?\s*$') {
        return $Matches["version"]
    }
    return ""
}

function Test-SupportedStableVersion {
    param(
        [string] $Version,
        [string] $Minimum
    )

    $parsedVersion = Convert-SemanticVersionOutput $Version
    $parsedMinimum = Convert-SemanticVersionOutput $Minimum
    if ([string]::IsNullOrWhiteSpace($parsedVersion) -or [string]::IsNullOrWhiteSpace($parsedMinimum)) {
        throw "Unable to compare semantic versions."
    }
    if ($parsedVersion.Contains("-")) {
        return $false
    }

    $normalizedVersion = $parsedVersion -replace '\+.*$', ''
    $normalizedMinimum = $parsedMinimum -replace '\+.*$', ''
    return ([version] $normalizedVersion) -ge ([version] $normalizedMinimum)
}

function Get-OpenCodeVersion {
    param([string] $OpenCodePath)

    $output = Invoke-Utf8NativeCapture -FilePath $OpenCodePath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "OpenCode is present, but 'opencode --version' did not return a valid semantic version."
    }
    return $version
}

function Confirm-OpenCodeApplication {
    if ($DryRun) {
        Write-Host "+ opencode --version"
        return
    }

    $command = Get-ApplicationCommand "opencode"
    if (-not $command) {
        throw "OpenCode was installed, but 'opencode' is not available on PATH."
    }
    $version = Get-OpenCodeVersion $command.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinOpenCodeVersion)) {
        throw "Stable OpenCode V1 $MinOpenCodeVersion or newer is required; found OpenCode $version after installation."
    }
    Write-Host "Verified OpenCode $version."
}

function Get-OpenCodeWindowsAssetName {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }

    switch ($architecture.ToUpperInvariant()) {
        "ARM64" { return "opencode-windows-arm64.zip" }
        "AMD64" { return "opencode-windows-x64-baseline.zip" }
        "X64" { return "opencode-windows-x64-baseline.zip" }
        "X86_64" { return "opencode-windows-x64-baseline.zip" }
        default { throw "OpenCode does not provide a supported Windows release for architecture '$architecture'." }
    }
}

function Install-OpenCode {
    $assetName = Get-OpenCodeWindowsAssetName
    $componentId = ($assetName -replace '\.zip$', '')
    $archiveUrl = "$OpenCodeReleaseBaseUrl/$assetName"
    $installDirectory = Join-Path $env:USERPROFILE ".opencode\bin"
    if ($DryRun) {
        Write-Host "+ irm $archiveUrl -OutFile <temporary-archive>"
        Write-Host "+ verify sha256 for $assetName against $($script:ChecksumsFile) (component: $componentId)"
        Write-Host "+ extract and install opencode.exe to $(Format-Argument $installDirectory)"
        return
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-opencode-" + [guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $temporaryRoot $assetName
    $extractPath = Join-Path $temporaryRoot "extracted"
    $temporaryInstallPath = Join-Path $installDirectory (".opencode-" + [guid]::NewGuid().ToString("N") + ".exe")
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        Write-Host "+ irm $archiveUrl -OutFile $(Format-Argument $archivePath)"
        Invoke-RestMethod -Uri $archiveUrl -OutFile $archivePath -ErrorAction Stop
        if ((-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) -or ((Get-Item -LiteralPath $archivePath).Length -eq 0)) {
            throw "The OpenCode release archive was empty."
        }

        # Fail-closed integrity gate before extracting the archive.
        Confirm-PinnedFile -Path $archivePath -Label "OpenCode Windows release ($assetName)" -ComponentId $componentId

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath
        $executables = @(Get-ChildItem -LiteralPath $extractPath -Recurse -File -Filter "opencode.exe")
        if ($executables.Count -ne 1) {
            throw "The OpenCode release archive did not contain exactly one opencode.exe."
        }

        New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
        Copy-Item -LiteralPath $executables[0].FullName -Destination $temporaryInstallPath
        if ((-not (Test-Path -LiteralPath $temporaryInstallPath -PathType Leaf)) -or ((Get-Item -LiteralPath $temporaryInstallPath).Length -eq 0)) {
            throw "The extracted OpenCode executable was empty."
        }
        Move-Item -LiteralPath $temporaryInstallPath -Destination (Join-Path $installDirectory "opencode.exe") -Force
    }
    finally {
        Remove-Item -LiteralPath $temporaryInstallPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-OpenCode {
    if ($DryRun) {
        if (Get-ApplicationCommand "opencode") {
            Write-Host "+ opencode --version"
            Write-Host "A compatible OpenCode will be preserved; an older version will be upgraded with opencode upgrade."
        }
        else {
            Install-OpenCode
        }
        Confirm-OpenCodeApplication
        return
    }

    $command = Get-ApplicationCommand "opencode"
    if ($command) {
        $version = Get-OpenCodeVersion $command.Source
        if (Test-SupportedStableVersion -Version $version -Minimum $MinOpenCodeVersion) {
            Write-Host "OpenCode $version already satisfies >=$MinOpenCodeVersion; leaving it unchanged."
            return
        }
        Write-Host "OpenCode $version does not satisfy stable V1 >=$MinOpenCodeVersion; upgrading it with OpenCode."
        Invoke-NativeCommand -FilePath $command.Source -Arguments @("upgrade")
        Add-KnownBinDirectories
    }
    else {
        Install-OpenCode
        Add-KnownBinDirectories
    }

    Confirm-OpenCodeApplication
}

function Get-ClineVersion {
    param([string] $ClinePath)

    $output = Invoke-Utf8NativeCapture -FilePath $ClinePath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Cline is present, but 'cline --version' did not return a valid semantic version."
    }
    return $version
}

function Confirm-ClineApplication {
    if ($DryRun) {
        Write-Host "+ cline --version"
        return
    }

    $command = Get-ApplicationCommand "cline"
    if (-not $command) {
        throw "Cline was installed, but 'cline' is not available on PATH."
    }
    $version = Get-ClineVersion $command.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinClineVersion)) {
        throw "Stable Cline $MinClineVersion or newer is required; found Cline $version after installation."
    }
    Write-Host "Verified Cline $version."
}

function Ensure-Cline {
    Add-NpmBinDirectories

    if ($DryRun) {
        if (Get-ApplicationCommand "cline") {
            Write-Host "+ cline --version"
            Write-Host "A compatible Cline will be preserved; an older version will be upgraded with cline update."
        }
        elseif (Get-ApplicationCommand "npm") {
            Install-NpmPackageVerified -PackageSpec $ClinePackage -Label "Cline $MinClineVersion" -ComponentId "npm-cline-$MinClineVersion"
        }
        else {
            throw "Cline installation requires npm. Install Node.js from https://nodejs.org/en/download, then rerun the installer."
        }
        Confirm-ClineApplication
        return
    }

    $command = Get-ApplicationCommand "cline"
    if ($command) {
        $version = Get-ClineVersion $command.Source
        if (Test-SupportedStableVersion -Version $version -Minimum $MinClineVersion) {
            Write-Host "Cline $version already satisfies >=$MinClineVersion; leaving it unchanged."
            return
        }
        Write-Host "Cline $version does not satisfy stable >=$MinClineVersion; upgrading it with Cline."
        Invoke-NativeCommand -FilePath $command.Source -Arguments @("update")
    }
    else {
        if (-not (Get-ApplicationCommand "npm")) {
            throw "Cline installation requires npm. Install Node.js from https://nodejs.org/en/download, then rerun the installer."
        }
        Install-NpmPackageVerified -PackageSpec $ClinePackage -Label "Cline $MinClineVersion" -ComponentId "npm-cline-$MinClineVersion"
    }

    Add-NpmBinDirectories
    Confirm-ClineApplication
}

function Get-HermesVersion {
    param([string] $HermesPath)

    $output = Invoke-Utf8NativeCapture -FilePath $HermesPath -Arguments @("--version")
    if ($output -match '(?im)^\s*Hermes Agent\s+v?(?<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)(?=\s|$)') {
        return $Matches["version"]
    }

    throw "Hermes Agent is present, but 'hermes --version' did not return a valid semantic version."
}

function Confirm-HermesArchitecture {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }
    if ($architecture.ToUpperInvariant() -notin @("ARM64", "AMD64", "X64", "X86_64")) {
        throw "Hermes Agent does not provide a supported Windows release for architecture '$architecture'."
    }
}

function Confirm-HermesApplication {
    if ($DryRun) {
        Write-Host "+ hermes --version"
        return
    }

    $command = Get-ApplicationCommand "hermes"
    if (-not $command) {
        throw "Hermes Agent was installed, but 'hermes' is not available on PATH."
    }
    $version = Get-HermesVersion $command.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinHermesVersion)) {
        throw "Hermes Agent $MinHermesVersion or newer is required; found Hermes $version after installation."
    }
    Write-Host "Verified Hermes Agent $version."
}

function Install-Hermes {
    Confirm-HermesArchitecture
    Invoke-DownloadedPowerShellInstaller `
        -Url $HermesInstallUrl `
        -Name "Hermes Agent" `
        -ComponentId "hermes-installer-ps1" `
        -ScriptArguments @("-NonInteractive", "-SkipSetup")
    Add-KnownBinDirectories
}

function Ensure-Hermes {
    if ($DryRun) {
        if (Get-ApplicationCommand "hermes") {
            Write-Host "+ hermes --version"
            Write-Host "A compatible Hermes Agent will be preserved; an older version will be upgraded with the official installer."
        }
        else {
            Install-Hermes
        }
        Confirm-HermesApplication
        return
    }

    $command = Get-ApplicationCommand "hermes"
    if ($command) {
        $version = Get-HermesVersion $command.Source
        if (Test-SupportedStableVersion -Version $version -Minimum $MinHermesVersion) {
            Write-Host "Hermes Agent $version already satisfies >=$MinHermesVersion; leaving it unchanged."
            return
        }
        Write-Host "Hermes Agent $version does not satisfy >=$MinHermesVersion; upgrading it with the official installer."
    }

    Install-Hermes
    Confirm-HermesApplication
}

function Get-GrokVersion {
    param([string] $GrokPath)

    $output = Invoke-Utf8NativeCapture -FilePath $GrokPath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Grok Build is present, but 'grok --version' did not return a valid semantic version."
    }
    return $version
}

function Confirm-GrokApplication {
    if ($DryRun) {
        Write-Host "+ grok --version"
        return
    }

    $command = Get-ApplicationCommand "grok"
    if (-not $command) {
        throw "Grok Build was installed, but 'grok' is not available on PATH."
    }
    $version = Get-GrokVersion $command.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinGrokVersion)) {
        throw "Stable Grok Build $MinGrokVersion or newer is required; found Grok Build $version after installation."
    }
    Write-Host "Verified Grok Build $version."
}

function Install-Grok {
    Invoke-DownloadedPowerShellInstaller -Url $GrokInstallUrl -Name "Grok Build" -ComponentId "grok-installer-ps1"
    Add-KnownBinDirectories
}

function Ensure-Grok {
    if ($DryRun) {
        if (Get-ApplicationCommand "grok") {
            Write-Host "+ grok --version"
            Write-Host "A compatible Grok Build will be preserved; an older version will be upgraded with the official installer."
        }
        else {
            Install-Grok
        }
        Confirm-GrokApplication
        return
    }

    $command = Get-ApplicationCommand "grok"
    if ($command) {
        $version = Get-GrokVersion $command.Source
        if (Test-SupportedStableVersion -Version $version -Minimum $MinGrokVersion) {
            Write-Host "Grok Build $version already satisfies >=$MinGrokVersion; leaving it unchanged."
            return
        }
        Write-Host "Grok Build $version does not satisfy stable >=$MinGrokVersion; upgrading it with the official installer."
    }

    Install-Grok
    Confirm-GrokApplication
}

function Get-MuseVersion {
    param([string] $MusePath)

    $output = Invoke-Utf8NativeCapture -FilePath $MusePath -Arguments @("--version")
    if ($output -match '(?m)^\s*Muse Code\s+(?<version>\d+\.\d+\.\d+)(?:\s+\([^\r\n]+\))?\s*$') {
        return $Matches["version"]
    }

    throw "Muse Code is present, but 'muse --version' did not return the expected 'Muse Code x.y.z' version."
}

function Ensure-Muse {
    $script:MuseAvailable = $false
    $command = Get-ApplicationCommand "muse"
    if (-not $command) {
        Write-Host "Muse Code is not installed. Meta does not currently publish an official Windows installer; fcc-muse will be ready when a compatible Muse binary is on PATH."
        return
    }

    if ($DryRun) {
        Write-Host "+ muse --version"
        Write-Host "A compatible preinstalled Muse Code will be preserved; FCC does not update Muse on Windows."
        $script:MuseAvailable = $true
        return
    }

    $version = Get-MuseVersion $command.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinMuseVersion)) {
        throw "Muse Code $MinMuseVersion or newer is required; found Muse Code $version. Meta does not currently publish an official Windows updater."
    }
    Write-Host "Verified Muse Code $version."
    $script:MuseAvailable = $true
}

function Get-DshVersion {
    param([string] $DshPath)

    $output = Invoke-Utf8NativeCapture -FilePath $DshPath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version) -or (-not $version.Contains("-"))) {
        throw "DeepSeek Harness is present, but 'dsh --version' did not return its preview semantic version."
    }
    return $version
}

function Get-DshNodeVersion {
    param([string] $NodePath)

    $output = Invoke-Utf8NativeCapture -FilePath $NodePath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "DeepSeek Harness requires a readable Node.js version."
    }
    return $version
}

function Test-DshNodeVersion {
    param([string] $Version)

    try {
        $parsed = [version] (($Version -replace '^v', '') -replace '[-+].*$', '')
    }
    catch {
        return $false
    }
    return (
        (($parsed.Major -eq 22) -and ($parsed.Minor -ge 19)) -or
        ($parsed.Major -ge 24)
    )
}

function Test-DshToolchain {
    $node = Get-ApplicationCommand "node"
    $npm = Get-ApplicationCommand "npm"
    if ((-not $node) -or (-not $npm)) {
        return $false
    }
    try {
        return (Test-DshNodeVersion -Version (Get-DshNodeVersion $node.Source))
    }
    catch {
        return $false
    }
}

function Confirm-DshToolchain {
    $node = Get-ApplicationCommand "node"
    if (-not $node) {
        throw "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0 and npm. Install Node.js, then rerun the installer."
    }
    $npm = Get-ApplicationCommand "npm"
    if (-not $npm) {
        throw "DeepSeek Harness requires npm. Install npm, then rerun the installer."
    }
    $version = Get-DshNodeVersion $node.Source
    if (-not (Test-DshNodeVersion $version)) {
        throw "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0; found Node.js $version."
    }
    return $npm.Source
}

function Confirm-DshApplication {
    if ($DryRun) {
        Write-Host "+ dsh --version"
        return
    }

    $command = Get-ApplicationCommand "dsh"
    if (-not $command) {
        throw "DeepSeek Harness was installed, but 'dsh' is not available on PATH."
    }
    $version = Get-DshVersion $command.Source
    if ($version -ne $DshVersion) {
        throw "DeepSeek Harness $DshVersion is required; found $version after installation."
    }
    Write-Host "Verified DeepSeek Harness $version."
}

function Install-Dsh {
    [void] (Confirm-DshToolchain)
    Install-NpmPackageVerified -PackageSpec $DshPackage -Label "DeepSeek Harness $DshVersion" -ComponentId "npm-dsh-$DshVersion"
    Add-NpmBinDirectories
}

function Ensure-Dsh {
    Add-NpmBinDirectories

    if ($DryRun) {
        if (Get-ApplicationCommand "dsh") {
            Write-Host "+ dsh --version"
            Write-Host "The exact supported DeepSeek Harness preview will be preserved; another version will be replaced."
        }
        else {
            $node = Get-ApplicationCommand "node"
            $npm = Get-ApplicationCommand "npm"
            if ((-not $node) -or (-not $npm)) {
                throw "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0 and npm. Install Node.js, then rerun the installer."
            }
            Install-NpmPackageVerified -PackageSpec $DshPackage -Label "DeepSeek Harness $DshVersion" -ComponentId "npm-dsh-$DshVersion"
        }
        Confirm-DshApplication
        return
    }

    [void] (Confirm-DshToolchain)
    $command = Get-ApplicationCommand "dsh"
    if ($command) {
        $version = Get-DshVersion $command.Source
        if ($version -eq $DshVersion) {
            Write-Host "DeepSeek Harness $version already matches the supported preview; leaving it unchanged."
            return
        }
        Write-Host "DeepSeek Harness $version does not match $DshVersion; replacing it with the supported preview."
    }

    Install-Dsh
    Confirm-DshApplication
}

function Ensure-SelectedCodingAgents {
    if ($script:InstallClaudeCode) {
        Write-Step "Ensuring Claude Code is installed"
        Ensure-ClaudeCode
    }

    if ($script:InstallCodex) {
        Write-Step "Ensuring Codex is installed"
        Ensure-Codex
    }

    if ($script:InstallPi) {
        Write-Step "Checking or installing Pi"
        Ensure-Pi
    }

    if ($script:InstallOpenCode) {
        Write-Step "Ensuring OpenCode is installed"
        Ensure-OpenCode
    }

    if ($script:InstallCline) {
        Write-Step "Ensuring Cline CLI is installed"
        Ensure-Cline
    }

    if ($script:InstallHermes) {
        Write-Step "Ensuring Hermes Agent is installed"
        Ensure-Hermes
    }

    if ($script:InstallDsh) {
        Write-Step "Ensuring DeepSeek Harness is installed"
        Ensure-Dsh
    }

    if ($script:InstallGrok) {
        Write-Step "Ensuring Grok Build is installed"
        Ensure-Grok
    }

    if ($script:InstallMuse) {
        Write-Step "Checking for Muse Code"
        Ensure-Muse
    }

    if ((-not $script:InstallClaudeCode) -and (-not $script:InstallCodex) -and (-not $script:PiAvailable) -and (-not $script:InstallOpenCode) -and (-not $script:InstallCline) -and (-not $script:InstallHermes) -and (-not $script:InstallDsh) -and (-not $script:InstallGrok) -and (-not $script:MuseAvailable)) {
        throw "No selected coding agent was installed. Re-run the installer and choose at least one."
    }
}

function Get-UvVersion {
    param([string] $UvPath)

    $output = Invoke-Utf8NativeCapture -FilePath $UvPath -Arguments @("--version")
    $version = Convert-SemanticVersionOutput $output
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "uv is present, but 'uv --version' did not return a valid version."
    }

    return $version
}

function Confirm-Uv {
    if ($DryRun) {
        Write-Host "+ uv --version"
        return
    }

    $uvCommand = Get-ApplicationCommand "uv"
    if (-not $uvCommand) {
        throw "uv was installed, but it is not available on PATH."
    }

    $version = Get-UvVersion $uvCommand.Source
    if (-not (Test-SupportedStableVersion -Version $version -Minimum $MinUvVersion)) {
        throw "Stable uv $MinUvVersion or newer is required; found uv $version after installation."
    }
    Write-Host "Verified uv $version."
}

# Download the pinned uv release .zip, verify it against the manifest, and
# extract uv.exe (and uvx.exe when present) into ~/.local/bin. Replaces the
# rolling astral.sh/uv/install.ps1 script, mirroring install.sh's
# install_uv_pinned.
function Install-UvPinned {
    $assetName = $UvWindowsAssetName
    $componentId = "uv-$UvVersion-$UvWindowsTarget"
    $archiveUrl = "$UvReleaseBaseUrl/$assetName"
    $installDirectory = Join-Path $env:USERPROFILE ".local\bin"
    if ($DryRun) {
        Write-Host "+ irm $archiveUrl -OutFile <temporary-archive>"
        Write-Host "+ verify sha256 for $assetName against $($script:ChecksumsFile) (component: $componentId)"
        Write-Host "+ extract and install uv.exe to $(Format-Argument (Join-Path $installDirectory 'uv.exe'))"
        return
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-uv-" + [guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $temporaryRoot $assetName
    $extractPath = Join-Path $temporaryRoot "extracted"
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        Write-Host "+ irm $archiveUrl -OutFile $(Format-Argument $archivePath)"
        Invoke-RestMethod -Uri $archiveUrl -OutFile $archivePath -ErrorAction Stop
        if ((-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) -or ((Get-Item -LiteralPath $archivePath).Length -eq 0)) {
            throw "The uv release archive was empty."
        }

        # Fail-closed integrity gate before extracting the archive.
        Confirm-PinnedFile -Path $archivePath -Label "uv $UvVersion archive ($assetName)" -ComponentId $componentId

        Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath
        $uvExecutables = @(Get-ChildItem -LiteralPath $extractPath -Recurse -File -Filter "uv.exe")
        if ($uvExecutables.Count -ne 1) {
            throw "The verified uv archive did not contain exactly one uv.exe."
        }

        New-Item -ItemType Directory -Force -Path $installDirectory | Out-Null
        # Copy uv.exe (and uvx.exe when present) via a temp name + Move-Item so a
        # concurrent PATH lookup never sees a half-written binary.
        $binaries = @(@{ Name = "uv.exe"; Source = $uvExecutables[0].FullName })
        $uvxExecutables = @(Get-ChildItem -LiteralPath $extractPath -Recurse -File -Filter "uvx.exe")
        if ($uvxExecutables.Count -eq 1) {
            $binaries += @{ Name = "uvx.exe"; Source = $uvxExecutables[0].FullName }
        }
        foreach ($binary in $binaries) {
            $temporaryInstallPath = Join-Path $installDirectory ("." + $binary.Name + "-" + [guid]::NewGuid().ToString("N"))
            Copy-Item -LiteralPath $binary.Source -Destination $temporaryInstallPath
            if ((-not (Test-Path -LiteralPath $temporaryInstallPath -PathType Leaf)) -or ((Get-Item -LiteralPath $temporaryInstallPath).Length -eq 0)) {
                Remove-Item -LiteralPath $temporaryInstallPath -Force -ErrorAction SilentlyContinue
                throw "The extracted $($binary.Name) was empty."
            }
            Move-Item -LiteralPath $temporaryInstallPath -Destination (Join-Path $installDirectory $binary.Name) -Force
        }
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-Uv {
    if ($DryRun) {
        if (Get-ApplicationCommand "uv") {
            Write-Host "+ uv --version"
            Write-Host "A compatible existing uv will be left unchanged; an obsolete one will be replaced by the pinned uv $UvVersion release artifact."
        }
        else {
            Write-Host "uv is not installed; the pinned uv $UvVersion release artifact would be installed."
            Install-UvPinned
            Confirm-Uv
        }
        return
    }

    $uvCommand = Get-ApplicationCommand "uv"
    if ($uvCommand) {
        $version = Get-UvVersion $uvCommand.Source
        if (Test-SupportedStableVersion -Version $version -Minimum $MinUvVersion) {
            Write-Host "uv $version already satisfies >=$MinUvVersion; leaving it unchanged."
            return
        }
        Write-Host "uv $version does not satisfy stable >=$MinUvVersion; installing the pinned uv $UvVersion release artifact."
    }
    else {
        Write-Host "uv is not installed; installing the pinned uv $UvVersion release artifact."
    }

    Install-UvPinned
    Add-KnownBinDirectories
    Confirm-Uv
}

function Get-PackageSpec {
    param([string] $SourceUrl)

    $includeNim = $VoiceNim
    $includeLocal = $VoiceLocal

    if ($VoiceAll) {
        $includeNim = $true
        $includeLocal = $true
    }

    if ($includeNim -and $includeLocal) {
        return "free-claude-code[voice,voice_local] @ $SourceUrl"
    }
    if ($includeNim) {
        return "free-claude-code[voice] @ $SourceUrl"
    }
    if ($includeLocal) {
        return "free-claude-code[voice_local] @ $SourceUrl"
    }
    return "free-claude-code @ $SourceUrl"
}

# True when $Ref is a full 40-hex-character commit SHA (cryptographically
# pinnable). Mirrors install.sh's fcc_ref_is_full_sha.
function Test-FccRefIsFullSha {
    param([string] $Ref)

    return ($Ref.Length -eq 40) -and ($Ref -match '^[0-9a-fA-F]{40}$')
}

# True when the installed uv accepts --locked on 'uv tool install', mirroring
# install.sh's uv_locked_supported (a read-only capability probe).
function Test-UvLockedSupported {
    param([string] $UvPath)

    try {
        $help = (& $UvPath tool install --help 2>$null | Out-String)
    }
    catch {
        return $false
    }
    return ($help -match '--locked')
}

# Clone Free Claude Code, detach onto the pinned commit, and verify HEAD equals
# it, mirroring install.sh's clone_and_pin_fcc. Returns the checkout directory
# (real run) or $null (dry-run). A full-40-hex -FccRef is cryptographically
# pinned (mismatch is fatal); any other ref resolves with a loud warning.
function Invoke-CloneAndPinFcc {
    if ($DryRun) {
        Write-Host "+ git clone $FccRepoUrl <temporary-checkout>"
        Write-Host "+ git -C <temporary-checkout> checkout --detach $($script:FccRef)"
        Write-Host "+ git -C <temporary-checkout> rev-parse HEAD"
        if (Test-FccRefIsFullSha $script:FccRef) {
            Write-Host "+ verify HEAD equals pinned commit $($script:FccRef)"
        }
        else {
            Write-Host "+ warn: -FccRef $($script:FccRef) is not a full 40-hex commit SHA (not cryptographically pinned)"
        }
        return $null
    }

    $git = Get-ApplicationCommand "git"
    if (-not $git) {
        throw "git is required to install Free Claude Code from a pinned commit. Install Git for Windows from https://git-scm.com/download/win, then rerun the installer."
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-src-" + [guid]::NewGuid().ToString("N"))
    $checkoutDir = Join-Path $temporaryRoot "free-claude-code"
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Invoke-NativeCommand -FilePath $git.Source -Arguments @("clone", $FccRepoUrl, $checkoutDir)
    Invoke-NativeCommand -FilePath $git.Source -Arguments @("-C", $checkoutDir, "checkout", "--detach", $script:FccRef)
    $headCommit = Invoke-Utf8NativeCapture -FilePath $git.Source -Arguments @("-C", $checkoutDir, "rev-parse", "HEAD")
    if ([string]::IsNullOrWhiteSpace($headCommit)) {
        throw "Could not resolve the checked-out Free Claude Code commit."
    }

    if (Test-FccRefIsFullSha $script:FccRef) {
        # git rev-parse emits lowercase hex; normalize both sides so an uppercase
        # -FccRef still compares equal instead of confusingly failing closed.
        if ($headCommit.Trim().ToLowerInvariant() -ne $script:FccRef.Trim().ToLowerInvariant()) {
            throw "Free Claude Code commit verification failed: expected $($script:FccRef), checked out $headCommit."
        }
        Write-Host "Pinned Free Claude Code to verified commit $headCommit."
    }
    else {
        Write-Warning "-FccRef '$($script:FccRef)' is not a full 40-hex commit SHA; resolved to $headCommit but NOT cryptographically pinned."
    }

    return $checkoutDir
}

function Install-FreeClaudeCode {
    Assert-NoFccProcessesRunning
    $checkoutDir = Invoke-CloneAndPinFcc

    if ($DryRun) {
        $sourceUrl = "file://<temporary-checkout>"
    }
    else {
        # A local directory PEP 508 direct reference; AbsoluteUri yields the
        # canonical file:///C:/... form uv accepts on Windows.
        $sourceUrl = ([uri] $checkoutDir).AbsoluteUri
    }
    $packageSpec = Get-PackageSpec -SourceUrl $sourceUrl

    $uvPath = "uv"
    if (-not $DryRun) {
        $uvCommand = Get-ApplicationCommand "uv"
        if (-not $uvCommand) {
            throw "uv is not available for the Free Claude Code installation."
        }
        $uvPath = $uvCommand.Source
    }

    $arguments = @(
        "tool",
        "install",
        "--force",
        "--refresh-package",
        "free-claude-code",
        "--python",
        $PythonRequest
    )
    # Pin FCC's full dependency closure by honoring the checkout's uv.lock, but
    # only when the installed uv advertises --locked (capability check), so an
    # older/newer uv that does not accept the flag never breaks the install.
    if ((-not $DryRun) -and (Test-UvLockedSupported -UvPath $uvPath)) {
        $arguments += "--locked"
    }
    if (-not [string]::IsNullOrWhiteSpace($TorchBackend)) {
        $arguments += @("--torch-backend", $TorchBackend)
    }
    $arguments += $packageSpec

    try {
        Invoke-NativeCommand -FilePath $uvPath -Arguments $arguments
    }
    finally {
        if ((-not $DryRun) -and $checkoutDir) {
            $checkoutParent = Split-Path -Parent $checkoutDir
            if ((-not [string]::IsNullOrWhiteSpace($checkoutParent)) -and (Test-Path -LiteralPath $checkoutParent)) {
                Remove-Item -LiteralPath $checkoutParent -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Export-FccDesktopIcon {
    param(
        [string] $DesktopCommand,
        [string] $IconPath
    )

    $arguments = @("--export-icon", $IconPath)
    $commandText = Format-Command -FilePath $DesktopCommand -Arguments $arguments
    Write-Host "+ $commandText"
    if ($DryRun) {
        return
    }

    # PowerShell does not wait when directly invoking a Windows GUI executable, so
    # Start-Process -Wait is required. -ArgumentList passes a single command line
    # that the child re-parses, so the path is wrapped in double quotes to survive
    # spaces in $env:USERPROFILE. $IconPath here is a fixed, installer-controlled
    # path ("<USERPROFILE>\.fcc\app-icon.ico"): it never ends in a backslash and
    # Windows paths cannot contain a double quote, so this quoting is exact for
    # every valid value. (Do not feed an untrusted/user-typed path here without
    # full CommandLineToArgvW-style escaping of trailing backslashes and quotes.)
    $quotedIconArgument = '"' + $IconPath + '"'
    $process = Start-Process `
        -FilePath $DesktopCommand `
        -ArgumentList @("--export-icon", $quotedIconArgument) `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    try {
        $exitCode = $process.ExitCode
    }
    finally {
        $process.Dispose()
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code ${exitCode}: $commandText"
    }
    if (-not (Test-Path -LiteralPath $IconPath -PathType Leaf)) {
        throw "Free Claude Code did not export its Windows app icon to '$IconPath'."
    }
}

function Configure-AndConfirmFreeClaudeCode {
    $iconPath = Join-Path $env:USERPROFILE ".fcc\app-icon.ico"
    if ($DryRun) {
        Write-Host "+ uv tool update-shell"
        Write-Host "+ uv tool dir --bin"
        Write-Host "+ verify fcc-desktop, fcc-server, fcc-claude, fcc-codex, fcc-pi, fcc-opencode, fcc-cline, fcc-hermes, fcc-dsh, fcc-grok, and fcc-muse in the uv tool bin directory"
        Write-Host "+ fcc-server --version"
        Export-FccDesktopIcon `
            -DesktopCommand "<uv-tool-bin>\fcc-desktop.exe" `
            -IconPath $iconPath
        Install-FccDesktopShortcuts `
            -DesktopCommand "<uv-tool-bin>\fcc-desktop.exe" `
            -IconPath $iconPath
        return
    }

    $uvCommand = Get-ApplicationCommand "uv"
    if (-not $uvCommand) {
        throw "uv is not available for PATH configuration."
    }
    Invoke-NativeCommand -FilePath $uvCommand.Source -Arguments @("tool", "update-shell")
    $toolBin = Invoke-Utf8NativeCapture -FilePath $uvCommand.Source -Arguments @("tool", "dir", "--bin")
    if ([string]::IsNullOrWhiteSpace($toolBin)) {
        throw "uv returned an empty tool bin directory."
    }

    Add-PathEntry $toolBin
    $toolBinPath = ([IO.Path]::GetFullPath($toolBin)).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $installedCommands = @{}
    foreach ($commandName in @("fcc-desktop", "fcc-server", "fcc-claude", "fcc-codex", "fcc-pi", "fcc-opencode", "fcc-cline", "fcc-hermes", "fcc-dsh", "fcc-grok", "fcc-muse")) {
        $command = Get-ApplicationCommand $commandName
        if (-not $command) {
            throw "Free Claude Code installation did not create '$commandName'."
        }
        $commandDirectory = ([IO.Path]::GetFullPath((Split-Path -Parent $command.Source))).TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )
        if (-not $commandDirectory.Equals($toolBinPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "'$commandName' resolved outside the uv tool bin directory: $($command.Source)"
        }
        $installedCommands[$commandName] = $command.Source
    }

    Invoke-NativeCommand -FilePath $installedCommands["fcc-server"] -Arguments @("--version")
    Export-FccDesktopIcon `
        -DesktopCommand $installedCommands["fcc-desktop"] `
        -IconPath $iconPath
    Install-FccDesktopShortcuts `
        -DesktopCommand $installedCommands["fcc-desktop"] `
        -IconPath $iconPath
}

function Test-EquivalentPath {
    param(
        [string] $Left,
        [string] $Right
    )

    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    try {
        return [string]::Equals(
            [IO.Path]::GetFullPath($Left),
            [IO.Path]::GetFullPath($Right),
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    catch {
        return $false
    }
}

function Install-FccDesktopShortcuts {
    param(
        [string] $DesktopCommand,
        [string] $IconPath
    )

    $shortcutPaths = @(
        (Join-Path $env:USERPROFILE "Desktop\Free Claude Code.lnk"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Free Claude Code.lnk")
    )
    foreach ($shortcutPath in $shortcutPaths) {
        Write-Host "+ create shortcut $(Format-Argument $shortcutPath) -> $(Format-Argument $DesktopCommand)"
    }
    if ($DryRun) {
        return
    }

    $shell = New-Object -ComObject WScript.Shell
    foreach ($shortcutPath in $shortcutPaths) {
        if (Test-Path -LiteralPath $shortcutPath) {
            try {
                $existingShortcut = $shell.CreateShortcut($shortcutPath)
                $isFccShortcut = Test-EquivalentPath -Left $existingShortcut.TargetPath -Right $DesktopCommand
            }
            catch {
                $isFccShortcut = $false
            }
            if (-not $isFccShortcut) {
                Write-Host "A shortcut not managed by Free Claude Code already exists at $shortcutPath; leaving it unchanged."
                continue
            }
        }
        $parent = Split-Path -Parent $shortcutPath
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $DesktopCommand
        $shortcut.WorkingDirectory = $env:USERPROFILE
        $shortcut.IconLocation = "$IconPath,0"
        $shortcut.Description = "Run Free Claude Code in the background"
        $shortcut.Save()
    }
}

# -RefreshChecksums support: download an artifact (or `npm pack` a package) into a
# temp file, print "id=<sha256>" to stdout, and clean up. Executes nothing.
# Failures print a "# id: reason" comment to stderr and continue, mirroring
# install.sh's refresh_one / refresh_npm_pack.
function Invoke-RefreshOne {
    param([string] $Id, [string] $Url)

    $temporaryFile = Join-Path ([IO.Path]::GetTempPath()) ("fcc-refresh-" + [guid]::NewGuid().ToString("N"))
    try {
        try {
            Invoke-RestMethod -Uri $Url -OutFile $temporaryFile -ErrorAction Stop
        }
        catch {
            [Console]::Error.WriteLine("# ${Id}: download failed ($Url)")
            return
        }
        if ((-not (Test-Path -LiteralPath $temporaryFile -PathType Leaf)) -or ((Get-Item -LiteralPath $temporaryFile).Length -eq 0)) {
            [Console]::Error.WriteLine("# ${Id}: downloaded file was empty ($Url)")
            return
        }
        Write-Output ("{0}={1}" -f $Id, (Get-FileSha256 -Path $temporaryFile))
    }
    finally {
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RefreshNpmPack {
    param([string] $Id, [string] $Spec)

    $npm = Get-ApplicationCommand "npm"
    if (-not $npm) {
        [Console]::Error.WriteLine("# ${Id}: npm not available; skipping")
        return
    }

    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("fcc-refresh-npm-" + [guid]::NewGuid().ToString("N"))
    try {
        New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
        $global:LASTEXITCODE = 0
        & $npm.Source pack $Spec --pack-destination $temporaryRoot --ignore-scripts *> $null
        if ($LASTEXITCODE -ne 0) {
            [Console]::Error.WriteLine("# ${Id}: npm pack failed ($Spec)")
            return
        }
        $tarballs = @(Get-ChildItem -LiteralPath $temporaryRoot -Filter "*.tgz")
        if ($tarballs.Count -eq 0) {
            [Console]::Error.WriteLine("# ${Id}: npm pack did not produce a tarball ($Spec)")
            return
        }
        Write-Output ("{0}={1}" -f $Id, (Get-FileSha256 -Path $tarballs[0].FullName))
    }
    finally {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RefreshAllChecksums {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    }

    Write-Output "# install.ps1 -RefreshChecksums output."
    Write-Output "# Review every hash against a trusted source (vendor release page / published"
    Write-Output "# checksums) before pasting it into $($script:ChecksumsFile), replacing REPLACE_ME."
    Write-Output "# Platform: Windows $architecture"
    Invoke-RefreshOne -Id "claude-installer-ps1" -Url $ClaudeInstallUrl
    Invoke-RefreshOne -Id "codex-installer-ps1" -Url $CodexInstallUrl
    Invoke-RefreshOne -Id "pi-installer-ps1" -Url $PiInstallUrl
    Invoke-RefreshOne -Id "hermes-installer-ps1" -Url $HermesInstallUrl
    Invoke-RefreshOne -Id "grok-installer-ps1" -Url $GrokInstallUrl
    try {
        $openCodeAsset = Get-OpenCodeWindowsAssetName
        Invoke-RefreshOne -Id ($openCodeAsset -replace '\.zip$', '') -Url "$OpenCodeReleaseBaseUrl/$openCodeAsset"
    }
    catch {
        [Console]::Error.WriteLine("# opencode-windows: $($_.Exception.Message)")
    }
    Invoke-RefreshOne -Id "uv-$UvVersion-$UvWindowsTarget" -Url "$UvReleaseBaseUrl/$UvWindowsAssetName"
    Invoke-RefreshOne -Id "rtk-$RtkVersion-$RtkWindowsTarget" -Url "$RtkReleaseBaseUrl/$RtkWindowsAssetName"
    Invoke-RefreshNpmPack -Id "npm-cline-$MinClineVersion" -Spec $ClinePackage
    Invoke-RefreshNpmPack -Id "npm-dsh-$DshVersion" -Spec $DshPackage
}

if ($Help) {
    Show-Usage
    return
}

if ($RemainingArgs.Count -gt 0) {
    Show-Usage
    throw "Unknown option: $($RemainingArgs -join ' ')"
}

if ((-not [string]::IsNullOrWhiteSpace($TorchBackend)) -and (-not ($VoiceLocal -or $VoiceAll))) {
    throw "-TorchBackend requires -VoiceLocal or -VoiceAll."
}

Resolve-ChecksumsFile
$script:FccRef = if ([string]::IsNullOrWhiteSpace($FccRef)) { $FccCommit } else { $FccRef }

if ($RefreshChecksums) {
    Write-Step "Refreshing checksums (no code will be executed)"
    Invoke-RefreshAllChecksums
    [Console]::Error.WriteLine("")
    [Console]::Error.WriteLine("Review each hash above against a trusted source, then paste the id=hash lines into $($script:ChecksumsFile).")
    return
}

if ($AllowUnpinned) {
    Write-UnpinnedBanner
}

Add-KnownBinDirectories
$script:InstallCline = [bool] ((Get-ApplicationCommand "cline") -or (Get-ApplicationCommand "npm"))
Write-Step "Checking for running Free Claude Code processes"
Assert-NoFccProcessesRunning

if (-not (Test-InteractiveInstaller)) {
    $hasDsh = [bool] (Get-ApplicationCommand "dsh")
    $hasDryRunToolchain = [bool] (
        $DryRun -and
        (Get-ApplicationCommand "node") -and
        (Get-ApplicationCommand "npm")
    )
    $script:InstallDsh = $hasDsh -or $hasDryRunToolchain -or (Test-DshToolchain)
}

if (Test-InteractiveInstaller) {
    Write-Step "Choosing coding agents"
    Select-CodingAgents
}

# Free Claude Code is always installed from a pinned git checkout, so git is
# always required. Fail fast before installing any coding agents.
if ((-not $DryRun) -and (-not (Get-ApplicationCommand "git"))) {
    throw "git is required to install Free Claude Code from a pinned commit. Install Git for Windows from https://git-scm.com/download/win, then rerun the installer."
}

Ensure-SelectedCodingAgents
Configure-RtkForSelectedAgents

Write-Step "Ensuring uv $MinUvVersion or newer is installed"
Ensure-Uv

Write-Step "Installing or updating Free Claude Code"
Install-FreeClaudeCode

Write-Step "Configuring PATH and verifying Free Claude Code"
Configure-AndConfirmFreeClaudeCode

Write-Host ""
if ($DryRun) {
    Write-Host "Dry run complete. No changes were made."
}
else {
    Write-Host "Free Claude Code is installed and verified. Open the Free Claude Code desktop shortcut to run it in the background."
    Write-Host "For terminal use, start the proxy with: fcc-server"
    if ($script:InstallClaudeCode) {
        Write-Host "Run Claude Code with: fcc-claude"
    }
    if ($script:InstallCodex) {
        Write-Host "Run Codex with: fcc-codex"
    }
    if ($script:PiAvailable) {
        Write-Host "Run Pi with: fcc-pi"
    }
    if ($script:InstallOpenCode) {
        Write-Host "Run OpenCode with: fcc-opencode"
    }
    if ($script:InstallCline) {
        Write-Host "Run Cline with: fcc-cline"
    }
    else {
        Write-Host "The fcc-cline wrapper is ready after you install Cline CLI."
    }
    if ($script:InstallHermes) {
        Write-Host "Run Hermes Agent with: fcc-hermes"
    }
    else {
        Write-Host "The fcc-hermes wrapper is ready after you install Hermes Agent."
    }
    if ($script:InstallDsh) {
        Write-Host "Run DeepSeek Harness with: fcc-dsh"
    }
    else {
        Write-Host "The fcc-dsh wrapper is ready after you install DeepSeek Harness $DshVersion."
    }
    if ($script:InstallGrok) {
        Write-Host "Run Grok Build with: fcc-grok"
    }
    else {
        Write-Host "The fcc-grok wrapper is ready after you install Grok Build $MinGrokVersion or newer."
    }
    if ($script:MuseAvailable) {
        Write-Host "Run Muse Code with: fcc-muse"
    }
    else {
        Write-Host "The fcc-muse wrapper is ready after you install Muse Code $MinMuseVersion or newer."
    }
}
