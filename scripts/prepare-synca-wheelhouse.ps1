# scripts/prepare-synca-wheelhouse.ps1
# Builds the Python wheelhouse used by the offline SyncA UTM ISO installer.

param(
    [string]$OutputDir = "output\wheelhouse",
    [string]$Platform = "manylinux2014_x86_64",
    [string]$PythonVersion = "39",
    [string]$Implementation = "cp",
    [string]$Abi = "cp39"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$requirements = Join-Path $repoRoot "payload\server-gui\requirements.txt"
$target = Join-Path $repoRoot $OutputDir

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "python was not found in PATH"
}

New-Item -ItemType Directory -Force -Path $target | Out-Null
python -m pip download `
    --only-binary=:all: `
    --platform $Platform `
    --python-version $PythonVersion `
    --implementation $Implementation `
    --abi $Abi `
    -r $requirements `
    -d $target
Write-Host "Wheelhouse created: $target"
