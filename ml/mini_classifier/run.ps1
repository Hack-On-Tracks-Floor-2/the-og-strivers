param(
    [Parameter(Position=0)]
    [ValidateSet('train','predict','test')]
    [string]$Action='predict',
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$ScriptArguments
)
$ErrorActionPreference='Stop'
$runtimePython=Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if (-not (Test-Path -LiteralPath $runtimePython)) { $runtimePython='python' }
$entry=if ($Action -eq 'test') { 'test_classifier.py' } else { "$Action.py" }
& $runtimePython (Join-Path $PSScriptRoot $entry) @ScriptArguments
exit $LASTEXITCODE
