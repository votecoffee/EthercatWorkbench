param(
    [string] $Destination,
    [string] $AppRoot
)

$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../skills/ethercat-workbench')).Path
if (-not $AppRoot) { $AppRoot = Join-Path $PSScriptRoot '..' }
$AppRoot = (Resolve-Path -LiteralPath $AppRoot).Path
foreach ($relative in @('AGENTS.md', 'docs/operations.md', 'docs/development.md')) {
    if (-not (Test-Path -LiteralPath (Join-Path $AppRoot $relative) -PathType Leaf)) {
        throw "Application root is missing $relative"
    }
}
if (-not $Destination) {
    $skillBase = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }
    $Destination = Join-Path $skillBase 'skills/ethercat-workbench'
}
$Destination = [IO.Path]::GetFullPath($Destination)
$receiptPath = Join-Path $Destination '.ethercat-workbench-skill.json'
$old = $null
if (Test-Path -LiteralPath $Destination) {
    $item = Get-Item -LiteralPath $Destination
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Skill destination must be an ordinary directory'
    }
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        throw 'Existing skill directory is not managed by this installer; preserve it and choose a new destination'
    }
    if ((Get-Item -LiteralPath $receiptPath).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Skill ownership receipt cannot be a reparse point' }
    $old = [IO.File]::ReadAllText($receiptPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
    if ($old.schema -ne 1 -or $old.application -ne 'EthercatWorkbench') { throw 'Invalid skill ownership receipt' }
}
$utf8 = [Text.UTF8Encoding]::new($false)
$payloads = [ordered]@{
    'SKILL.md' = [IO.File]::ReadAllBytes((Join-Path $source 'SKILL.md'))
    'agents/openai.yaml' = [IO.File]::ReadAllBytes((Join-Path $source 'agents/openai.yaml'))
    '.application-root' = $utf8.GetBytes($AppRoot + "`n")
}
function Hash-Bytes([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
$hashes = [ordered]@{}
foreach ($relative in $payloads.Keys) {
    $target = Join-Path $Destination $relative
    $parent = Split-Path -Parent $target
    foreach ($candidate in @($parent, $target)) {
        if ((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Refuse a reparse point in managed skill path: $candidate"
        }
    }
    $hashes[$relative] = Hash-Bytes $payloads[$relative]
    if (Test-Path -LiteralPath $target) {
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Managed file path is a directory: $target" }
        $actual = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        $previous = if ($old) { $old.files.PSObject.Properties[$relative].Value } else { $null }
        if ($actual -ne $hashes[$relative] -and $actual -ne $previous) {
            throw "Managed skill file was modified; preserved without overwriting: $relative"
        }
    }
}
# All preservation checks finish before any file is written. Unknown files are never removed.
foreach ($relative in $payloads.Keys) {
    $target = Join-Path $Destination $relative
    [IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
    if (-not (Test-Path -LiteralPath $target) -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hashes[$relative]) {
        [IO.File]::WriteAllBytes($target, $payloads[$relative])
    }
}
$receipt = [ordered]@{ schema = 1; application = 'EthercatWorkbench'; app_root = $AppRoot; files = $hashes }
[IO.File]::WriteAllText($receiptPath, (($receipt | ConvertTo-Json -Depth 5) + "`n"), $utf8)
Write-Output "Installed EtherCAT Workbench skill: $Destination"
Write-Output "Application root: $AppRoot"
