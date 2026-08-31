param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [string]$PhpPath = 'php'
)

$ErrorActionPreference = 'Continue'

$pluginDir     = Split-Path -Parent $PSScriptRoot
$repoRoot      = Split-Path -Parent $pluginDir
$gateScript    = Join-Path $repoRoot 'validation\gate.php'
$buildScript   = Join-Path $PSScriptRoot 'build-wordpress-plugin-zip.ps1'
$releaseDir    = Join-Path $repoRoot "releases\portfolio-guard"
$zipName       = "portfolio-guard-$Version.zip"
$zipPath       = Join-Path $releaseDir $zipName
$sha256Path    = Join-Path $releaseDir "portfolio-guard-$Version.sha256"
$releaseTest   = Join-Path $repoRoot 'validation\release-package-test.php'
$excludePaths  = @('tests', 'scripts', 'README.md')

Write-Output ""
Write-Output "=== Portfolio Guard Release Build v$Version ==="
Write-Output ""

# Step 0: Environment verification
Write-Output "Step 0 -- Environment verification"

$phpOk = $false
try {
    $phpVersion = & $PhpPath -r "echo PHP_VERSION;" 2>$null
    if ($LASTEXITCODE -eq 0 -and $phpVersion -ne '') {
        $phpOk = $true
        Write-Output "  OK: PHP $phpVersion"
    }
} catch {}

if (-not $phpOk) {
    Write-Output ""
    Write-Output "FAIL: PHP executable not found or not working."
    Write-Output "  Checked: $PhpPath"
    Write-Output "  Pass a working PHP path with: -PhpPath <path>"
    Write-Output ""
    Write-Output "Build aborted."
    exit 1
}

$zipArchiveOk = $false
$zipCheckResult = & $PhpPath -r "exit(class_exists('ZipArchive') ? 0 : 1);" 2>$null
if ($LASTEXITCODE -eq 0) {
    $zipArchiveOk = $true
    Write-Output "  OK: ZipArchive extension available"
}

if (-not $zipArchiveOk) {
    Write-Output ""
    Write-Output "FAIL: PHP ZipArchive extension is not available."
    Write-Output ""
    Write-Output "  ReleasePackageTest requires the ZipArchive extension."
    Write-Output ""
    Write-Output "  To resolve:"
    Write-Output "    1. Run:  $PhpPath --ini"
    Write-Output "    2. Locate the active php.ini"
    Write-Output "    3. Uncomment or add:  extension=zip"
    Write-Output "    4. Restart your terminal"
    Write-Output ""
    Write-Output "Build aborted."
    exit 1
}

Write-Output ""

# Step 1: Development gate
Write-Output "Step 1 -- Development gate"

$gitStatusBefore = & git -C $repoRoot status --porcelain

& $PhpPath $gateScript
if ($LASTEXITCODE -ne 0) {
    Write-Error "FAIL: Development gate did not pass (exit $LASTEXITCODE). Build aborted."
    exit 1
}

# Safety check: the gate must execute entirely against disposable fixtures and
# must never leave the working tree different from how it found it. This is
# equivalent to `git status --porcelain` before/after, diffed rather than
# requiring an absolute-empty tree, so pre-existing unrelated WIP in the
# working tree is not misattributed to the gate run.
$gitStatusAfter = & git -C $repoRoot status --porcelain
$treeDiff = Compare-Object -ReferenceObject $gitStatusBefore -DifferenceObject $gitStatusAfter -PassThru

if ($treeDiff) {
    Write-Output ""
    Write-Error "FAIL: The development gate mutated the working tree. This means a test scanned, modified, or deleted real repository files instead of running entirely against disposable fixtures."
    Write-Output "  Changed since the gate started:"
    $treeDiff | ForEach-Object { Write-Output "    $_" }
    Write-Output ""
    Write-Output "Build aborted. Do not package a release from a gate run that mutated the repository."
    exit 1
}

Write-Output "  OK: working tree unchanged by the gate"
Write-Output ""

# Step 2: Version verification
Write-Output "Step 2 -- Version verification"

$pluginFile    = Join-Path $pluginDir 'portfolio-guard.php'
$readmeFile    = Join-Path $pluginDir 'readme.txt'
$pluginContent = Get-Content -Path $pluginFile -Raw
$readmeContent = Get-Content -Path $readmeFile -Raw

$headerVersion   = ''
$constantVersion = ''
$stableTag       = ''

if ($pluginContent -match '(?m)^\s*\*\s*Version:\s*(\S+)') {
    $headerVersion = $Matches[1]
}

$constPattern = 'define\(''MSP_PG_VERSION'',\s*''([^'']+)'''
if ($pluginContent -match $constPattern) {
    $constantVersion = $Matches[1]
}

if ($readmeContent -match '(?m)^Stable tag:\s*(\S+)') {
    $stableTag = $Matches[1]
}

$escapedVersion  = [regex]::Escape($Version)
$changelogEntry  = $readmeContent -match "(?m)^= $escapedVersion ="

$verFailed = $false

if ($headerVersion -ne $Version) {
    Write-Output "  FAIL: Plugin header Version is '$headerVersion', expected '$Version'"
    $verFailed = $true
}
if ($constantVersion -ne $Version) {
    Write-Output "  FAIL: MSP_PG_VERSION constant is '$constantVersion', expected '$Version'"
    $verFailed = $true
}
if ($stableTag -ne $Version) {
    Write-Output "  FAIL: readme.txt Stable tag is '$stableTag', expected '$Version'"
    $verFailed = $true
}
if (-not $changelogEntry) {
    Write-Output "  FAIL: readme.txt missing changelog entry for $Version"
    $verFailed = $true
}

if ($verFailed) {
    Write-Error "FAIL: Version verification failed. Build aborted."
    exit 1
}

Write-Output "  OK: header=$Version, constant=$Version, stable-tag=$Version, changelog present"
Write-Output ""

# Step 3: Build release ZIP
Write-Output "Step 3 -- Build release ZIP"

if (!(Test-Path -LiteralPath $releaseDir -PathType Container)) {
    New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null
}

& $buildScript -SourceDir $pluginDir -DestinationZip $zipPath -ExcludePaths $excludePaths
if ($LASTEXITCODE -ne 0) {
    Write-Error "FAIL: Build script exited $LASTEXITCODE. Build aborted."
    exit 1
}

if (!(Test-Path -LiteralPath $zipPath)) {
    Write-Error "FAIL: ZIP not found at $zipPath after build. Build aborted."
    exit 1
}

$zipSize = (Get-Item -LiteralPath $zipPath).Length
Write-Output "  OK: $zipPath ($($zipSize) bytes)"
Write-Output ""

# Step 4: Release package validation
Write-Output "Step 4 -- Release package validation"
& $PhpPath $releaseTest --zip $zipPath --version $Version
if ($LASTEXITCODE -ne 0) {
    Write-Error "FAIL: ReleasePackageTest did not pass (exit $LASTEXITCODE). Build aborted."
    exit 1
}
Write-Output ""

# Step 5: SHA-256
Write-Output "Step 5 -- SHA-256"
$hash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash *$zipName" | Out-File -FilePath $sha256Path -Encoding ascii -NoNewline
Write-Output "  $hash"
Write-Output "  Written: $sha256Path"
Write-Output ""

# Step 6: Summary
Write-Output "=== Build complete ==="
Write-Output "  Artifact : $zipPath"
Write-Output "  Size     : $($zipSize) bytes"
Write-Output "  SHA-256  : $hash"
Write-Output "  Checksum : $sha256Path"
Write-Output ""
