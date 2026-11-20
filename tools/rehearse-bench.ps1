[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Output,
    [int] $Seconds = 3,
    [ValidateRange(1, 16)] [int] $Pairs = 3
)

$ErrorActionPreference = 'Stop'
# Resolve hashing and JSON from this PowerShell installation.
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1')
if ($Seconds -lt 1) { throw 'Each rehearsal trial needs at least one second.' }
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$cli = Join-Path $root 'ethercat-workbench-cli.exe'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
    $cli = Join-Path $root 'target/x86_64-pc-windows-msvc/release/ethercat-workbench-cli.exe'
}
$sample = Join-Path $root 'samples/virtual.json'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf) -or -not (Test-Path -LiteralPath $sample -PathType Leaf)) {
    throw 'The Windows x64 CLI and samples/virtual.json are required. Use the portable package or build the source checkout.'
}
$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $destination) { throw "Rehearsal destination already exists: $destination" }

function Invoke-Workbench([string[]] $Arguments) {
    $result = & $cli @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Workbench $($Arguments[0]) exited with code $LASTEXITCODE. Check the artifacts already written to $destination."
    }
    $result -join "`n"
}

function Write-NewJson([string] $Path, $Record) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Record | ConvertTo-Json -Depth 8) + "`n")
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
}

$version = Invoke-Workbench @('--version')
$cliHash = (Get-FileHash -LiteralPath $cli -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory -Path $destination | Out-Null
$profilePath = Join-Path $destination 'profile.json'
[IO.File]::Copy($sample, $profilePath, $false)
$profile = Invoke-Workbench @('validate', $profilePath) | ConvertFrom-Json
$trials = @()
$scheduleOrder = @()

for ($pair = 0; $pair -lt $Pairs; $pair++) {
    $schedulers = @('deadline', 'relative')
    if ($pair % 2 -eq 1) { [array]::Reverse($schedulers) }
    foreach ($scheduler in $schedulers) {
        $stem = '{0:D2}-{1}' -f ($trials.Count + 1), $scheduler
        $reportName = "$stem.run.json"
        $csvName = "$stem.csv"
        Write-Verbose "Running $scheduler as trial $($trials.Count + 1)"
        Invoke-Workbench @(
            'run', $profilePath, '--backend', 'virtual', '--virtual-model', 'coe',
            '--scheduler', $scheduler, '--seconds', [string]$Seconds, '--csv',
            (Join-Path $destination $csvName), '--report', (Join-Path $destination $reportName)
        ) | Out-Null
        $trials += [ordered]@{ report = $reportName; csv = $csvName }
        $scheduleOrder += $scheduler
    }
}

$trialSetPath = Join-Path $destination 'trials.json'
$comparisonPath = Join-Path $destination 'comparison.json'
$bundlePath = Join-Path $destination 'evidence'
Write-NewJson $trialSetPath ([ordered]@{ schema = 1; audit_csv = $true; trials = $trials })
Invoke-Workbench @('compare-runs', '--trial-set', $trialSetPath, '--out', $comparisonPath) | Out-Null
Invoke-Workbench @('bundle-comparison', $comparisonPath, '--out', $bundlePath) | Out-Null
$check = Invoke-Workbench @('verify-bundle', $bundlePath) | ConvertFrom-Json
$summary = [ordered]@{
    schema = 1
    source = 'virtual_coe'
    cli_version = $version
    cli_sha256 = $cliHash
    profile = 'profile.json'
    profile_file_sha256 = (Get-FileHash -LiteralPath $profilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    requested_cycle_us = $profile.requested_cycle_us
    seconds_per_trial = $Seconds
    scheduler_order = $scheduleOrder
    trial_set = 'trials.json'
    comparison = 'comparison.json'
    evidence_bundle = 'evidence'
    bundle_receipt_sha256 = $check.receipt_sha256
    reports = $check.receipt.reports
    csv_parts = $check.receipt.csv_parts
}
Write-NewJson (Join-Path $destination 'rehearsal.json') $summary
$summary | ConvertTo-Json -Depth 8
