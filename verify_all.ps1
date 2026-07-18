param(
    [ValidateSet("quick", "full")]
    [string]$Mode = "quick"
)

$bash = Get-Command bash -ErrorAction Stop
& $bash.Source "$PSScriptRoot/verify_all.sh" "--$Mode"
exit $LASTEXITCODE
