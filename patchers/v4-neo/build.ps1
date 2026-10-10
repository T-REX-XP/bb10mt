param(
    [Parameter(Mandatory=$true)][string]$InputFirmware,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
& $Python -B (Join-Path $PSScriptRoot 'build.py') fresh -i $InputFirmware -o $OutputDirectory
exit $LASTEXITCODE
