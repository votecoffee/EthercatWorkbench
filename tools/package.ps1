param(
    [Parameter(Mandatory)] [string] $Zip
)

$ErrorActionPreference = 'Stop'
$Zip = [IO.Path]::GetFullPath($Zip)
if (Test-Path -LiteralPath $Zip) { throw "Package already exists: $Zip" }

Push-Location (Join-Path $PSScriptRoot '..')
try {
    $target = 'x86_64-pc-windows-msvc'
    $release = "target/$target/release"
    $notices = '.local/THIRD-PARTY-NOTICES.txt'
    New-Item -ItemType Directory -Force .local | Out-Null
    cargo build --locked --release --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    cargo about generate --config tools/about.toml --locked --offline --fail --output-file $notices tools/notices.hbs
    if ($LASTEXITCODE -ne 0) { throw 'License generation failed' }

    $metadata = cargo metadata --locked --format-version 1 --filter-platform $target | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Could not locate locked dependencies' }
    $fonts = ($metadata.packages | Where-Object name -eq epaint_default_fonts).manifest_path
    $fontDir = Join-Path (Split-Path -Parent $fonts) fonts
    $rustDocs = Join-Path (rustc --print sysroot) 'share/doc/rust'
    $commit = git rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Could not identify source commit' }
    if (git status --porcelain) { throw 'Package from a clean, committed source tree' }

    $entries = [ordered]@{
        'ethercat-workbench.exe' = "$release/ethercat-workbench.exe"
        'ethercat-workbench-cli.exe' = "$release/ethercat-workbench-cli.exe"
        'README.md' = 'README.md'
        'AGENTS.md' = 'AGENTS.md'
        'docs/operations.md' = 'docs/operations.md'
        'docs/desktop-workspace.md' = 'docs/desktop-workspace.md'
        'docs/runtime-check.md' = 'docs/runtime-check.md'
        'docs/research-brief.md' = 'docs/research-brief.md'
        'docs/development.md' = 'docs/development.md'
        'docs/interfaces-roadmap.md' = 'docs/interfaces-roadmap.md'
        'docs/http-input-feed.md' = 'docs/http-input-feed.md'
        'docs/mqtt-input-feed.md' = 'docs/mqtt-input-feed.md'
        'docs/shared-input-feed.md' = 'docs/shared-input-feed.md'
        'docs/shared-input-review.md' = 'docs/shared-input-review.md'
        'samples/shared-input.json' = 'samples/shared-input.json'
        'examples/read_shared_memory.py' = 'examples/read_shared_memory.py'
        'include/ethercat_input_v1.h' = 'include/ethercat_input_v1.h'
        'samples/mqtt-input.json' = 'samples/mqtt-input.json'
        'samples/http-input.json' = 'samples/http-input.json'
        'skills/ethercat-workbench/SKILL.md' = 'skills/ethercat-workbench/SKILL.md'
        'skills/ethercat-workbench/agents/openai.yaml' = 'skills/ethercat-workbench/agents/openai.yaml'
        'tools/install-skill.ps1' = 'tools/install-skill.ps1'
        'ROADMAP.md' = 'ROADMAP.md'
        'VERIFICATION.md' = 'VERIFICATION.md'
        'LICENSE' = 'LICENSE'
        'docs/ethercrab-review.md' = 'docs/ethercrab-review.md'
        'docs/benchmark-comparison.md' = 'docs/benchmark-comparison.md'
        'docs/capture-audit.md' = 'docs/capture-audit.md'
        'docs/desktop-review.md' = 'docs/desktop-review.md'
        'docs/esc-diagnostics.md' = 'docs/esc-diagnostics.md'
        'docs/pcap-inspection.md' = 'docs/pcap-inspection.md'
        'docs/output-staging.md' = 'docs/output-staging.md'
        'samples/output-staging.json' = 'samples/output-staging.json'
        'samples/esc-diagnostics.json' = 'samples/esc-diagnostics.json'
        'samples/synthetic.esi.xml' = 'samples/synthetic.esi.xml'
        'samples/pdo-choices.esi.xml' = 'samples/pdo-choices.esi.xml'
        'samples/pdo-choices.json' = 'samples/pdo-choices.json'
        'docs/pdo-selection.md' = 'docs/pdo-selection.md'
        'samples/sync-modes.esi.xml' = 'samples/sync-modes.esi.xml'
        'samples/mode-sync-managers.esi.xml' = 'samples/mode-sync-managers.esi.xml'
        'samples/mode-pdo-staging.esi.xml' = 'samples/mode-pdo-staging.esi.xml'
        'samples/sync-review.json' = 'samples/sync-review.json'
        'docs/esi-sync-review.md' = 'docs/esi-sync-review.md'
        'samples/synthetic.json' = 'samples/synthetic.json'
        'samples/virtual.json' = 'samples/virtual.json'
        'samples/virtual-sii.json' = 'samples/virtual-sii.json'
        'samples/virtual-dc.json' = 'samples/virtual-dc.json'
        'samples/virtual-normal.json' = 'samples/virtual-normal.json'
        'samples/virtual-segmented.json' = 'samples/virtual-segmented.json'
        'samples/synthetic-pdo.json' = 'samples/synthetic-pdo.json'
        'samples/synthetic-replay.json' = 'samples/synthetic-replay.json'
        'notices/THIRD-PARTY-NOTICES.txt' = $notices
        'notices/Rust-COPYRIGHT-library.html' = (Join-Path $rustDocs 'COPYRIGHT-library.html')
    }
    foreach ($font in @('emoji-icon-font-mit-license.txt', 'Hack-Regular.txt', 'OFL.txt', 'UFL.txt')) {
        $entries["notices/fonts/$font"] = Join-Path $fontDir $font
    }
    foreach ($license in (Get-ChildItem -LiteralPath (Join-Path $rustDocs 'licenses') -File)) {
        $entries["notices/licenses/$($license.Name)"] = $license.FullName
    }
    $manifest = @("Source commit $commit", "Target $target", (rustc --version), '', 'SHA-256')
    foreach ($name in $entries.Keys) {
        $hash = (Get-FileHash -LiteralPath $entries[$name] -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest += "$hash  $name"
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Zip, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in $entries.Keys) {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive, (Resolve-Path -LiteralPath $entries[$name]).Path, $name,
                [IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
        $writer = [IO.StreamWriter]::new($archive.CreateEntry('BUILD.txt').Open())
        try { $writer.WriteLine(($manifest -join "`n")) }
        finally { $writer.Dispose() }
    }
    finally { $archive.Dispose() }
    Get-FileHash -LiteralPath $Zip -Algorithm SHA256
}
finally { Pop-Location }
