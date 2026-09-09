# Exercise the real task action in a child PowerShell process, with a deliberately failing client.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'customer/windows-client.ps1') -Mode Library
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('tsuite diagnostic''s test ' + [guid]::NewGuid().ToString('N'))
$id = '012345abcdef'
$sessionDirectory = Join-Path $testDirectory $id
[void][IO.Directory]::CreateDirectory($sessionDirectory)
function Get-SupportRoot { return $testDirectory }
function New-ScheduledTaskAction { param($Execute, $Argument) return @{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return @{} }
function New-ScheduledTaskSettingsSet {
    param([switch]$StartWhenAvailable, $MultipleInstances, [switch]$AllowStartIfOnBatteries,
        [switch]$DontStopIfGoingOnBatteries, $RestartCount, $RestartInterval, $ExecutionTimeLimit)
    return @{}
}
function New-ScheduledTaskTrigger { param([switch]$AtStartup, [switch]$Once, $At) return @{} }
function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings) $script:capturedAction = $Action }
$originalSystemRoot = $env:SystemRoot
try {
    $env:SystemRoot = $testDirectory
    Write-Utf8 (Join-Path $sessionDirectory 'client.ps1') "throw 'fixture: temporary SSH listener startup failure'"
    Register-SupportTask $id 'Sshd' ([datetime]::Now.AddHours(1))
    $executable = (Get-Process -Id $PID).Path
    $process = Start-Process -FilePath $executable -ArgumentList $script:capturedAction.Argument `
        -PassThru -Wait -RedirectStandardError (Join-Path $testDirectory 'stderr') `
        -RedirectStandardOutput (Join-Path $testDirectory 'stdout')
    if ($process.ExitCode -eq 0) { throw 'The injected startup failure must fail the task.' }
    $log = Join-Path $sessionDirectory 'Sshd.runner.log'
    if (-not (Test-Path -LiteralPath $log)) { throw 'Startup failure is lost: the task did not preserve the original error.' }
    if (-not (Get-Content -LiteralPath $log -Raw).Contains('fixture: temporary SSH listener startup failure')) {
        throw 'The task did not record the original exception.'
    }
    function New-PrivateDirectory([string]$Path) { [void][IO.Directory]::CreateDirectory($Path) }
    function Assert-PrivateDirectory([string]$Path) { }
    function Get-ScheduledTask { param($TaskName, $ErrorAction) return [pscustomobject]@{ State = 'Ready' } }
    function Get-ScheduledTaskInfo { param([Parameter(ValueFromPipeline=$true)]$InputObject)
        return [pscustomobject]@{ LastTaskResult = 1; LastRunTime = [datetime]::Now }
    }
    Write-Utf8 (Join-Path $sessionDirectory 'session.json') 'TEST-SECRET-MUST-NOT-BE-EXPORTED'
    Write-Utf8 (Join-Path $sessionDirectory 'tunnel_ed25519') 'TEST-PRIVATE-KEY-MUST-NOT-BE-EXPORTED'
    Save-StartupDiagnostics $id
    [IO.Directory]::Delete($sessionDirectory, $true)
    $saved = Get-Content (Join-Path $testDirectory "diagnostics/$id-startup.log") -Raw
    if (-not $saved.Contains('last_result=1')) { throw 'Task result code missing from diagnostics.' }
    if (-not $saved.Contains('fixture: temporary SSH listener startup failure')) { throw 'Rollback lost the diagnostic.' }
    if ($saved.Contains('TEST-SECRET') -or $saved.Contains('TEST-PRIVATE-KEY')) { throw 'Diagnostics exported credentials.' }
    Write-Output 'Task startup failure capture and diagnostics surviving rollback passed.'
} finally {
    $env:SystemRoot = $originalSystemRoot
    [IO.Directory]::Delete($testDirectory, $true)
}
