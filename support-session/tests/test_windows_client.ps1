# No real accounts, tasks or services are modified. Works on pwsh/Linux and Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
foreach ($file in Get-ChildItem (Join-Path $root 'customer') -Filter '*.ps1') {
    $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors)
    if ($parseErrors) { throw ($parseErrors | Out-String) }
}
. (Join-Path $root 'customer/windows-client.ps1') -Mode Library
function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
$badIdRejected = $false
try { Assert-SessionId '../not-a-session' } catch { $badIdRejected = $true }
Assert-True $badIdRejected 'Invalid session ID must fail.'

$script:testRoot = Join-Path ([IO.Path]::GetTempPath()) ('tsuite-windows-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($script:testRoot)
$id = '012345abcdef'
$script:testState = [pscustomobject]@{
    session_id = $id; ops_user = 'tsuite-ops-012345ab'; ssh_path = 'ssh.exe'; sshd_path = 'sshd.exe'
}
$script:events = New-Object 'Collections.Generic.List[string]'
$script:description = "TSuite temporary support $id"
$script:failStop = $false
# Override OS boundaries only; the real cleanup/task registration functions remain under test.
function Get-SupportRoot { return $script:testRoot }
function Read-SupportState([string]$Id) { return $script:testState }
function Get-LocalUser { param($Name, $ErrorAction)
    return [pscustomobject]@{ Description = $script:description; SID = [pscustomobject]@{ Value = 'test-sid' } }
}
function Disable-LocalUser { param($SID) $script:events.Add('disable-user') }
function Get-ScheduledTask { param($TaskName, $ErrorAction) return [pscustomobject]@{ TaskName = $TaskName } }
function Stop-ScheduledTask { param($InputObject)
    if ($script:failStop) { throw 'simulated stop failure' }
    $script:events.Add('stop-' + $InputObject.TaskName)
}
function Unregister-ScheduledTask { param($InputObject, $TaskName, [switch]$Confirm, $ErrorAction)
    $script:events.Add('unregister-task')
}
function Get-CimInstance { param($ClassName, $Filter) return @() }
function Remove-LocalUser { param($SID) $script:events.Add('remove-user') }
function Remove-Item { param($LiteralPath, [switch]$Recurse, [switch]$Force)
    $script:events.Add('remove-files')
}
function Remove-CimInstance { param([Parameter(ValueFromPipeline=$true)]$InputObject) }

try {
    Remove-SupportSession $id
    Assert-True ($script:events[0] -eq 'disable-user') 'Cleanup must disable login first.'
    Assert-True ($script:events.IndexOf('remove-user') -lt $script:events.IndexOf('remove-files')) 'Remove user before state.'
    Assert-True ($script:events[$script:events.Count - 1] -eq 'unregister-task') 'Cleanup task must be removed last.'
    $script:events.Clear()
    $script:description = 'Existing account not owned by TSuite'
    $refused = $false
    try { Remove-SupportSession $id } catch { $refused = $true }
    Assert-True $refused 'Do not delete a pre-existing account.'
    Assert-True ($script:events.Count -eq 0) 'Account mismatch must make no changes.'
    $script:description = "TSuite temporary support $id"
    $script:failStop = $true
    $failed = $false
    try { Remove-SupportSession $id } catch { $failed = $true }
    Assert-True $failed 'A failed task stop must not be ignored.'
    Assert-True (-not $script:events.Contains('remove-files')) 'Retain state when cleanup fails.'

    $script:task = $null
    $env:SystemRoot = $script:testRoot
    function New-ScheduledTaskAction { param($Execute, $Argument) return @{ Execute = $Execute; Argument = $Argument } }
    function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) return @{ UserId = $UserId } }
    function New-ScheduledTaskSettingsSet {
        param([switch]$StartWhenAvailable, $MultipleInstances, [switch]$AllowStartIfOnBatteries,
            [switch]$DontStopIfGoingOnBatteries, $RestartCount, $RestartInterval, $ExecutionTimeLimit)
        return @{ StartWhenAvailable = $StartWhenAvailable.IsPresent; RestartCount = $RestartCount }
    }
    function New-ScheduledTaskTrigger { param([switch]$AtStartup, [switch]$Once, $At, $RepetitionInterval)
        return @{ AtStartup = $AtStartup.IsPresent; At = $At }
    }
    function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Principal, $Settings)
        $script:task = @{ Name = $TaskName; Action = $Action; Trigger = $Trigger; Principal = $Principal; Settings = $Settings }
    }
    $expiry = [datetime]::Now.AddHours(2)
    Register-SupportTask $id 'Cleanup' $expiry
    Assert-True ($script:task.Principal.UserId -eq 'S-1-5-18') 'Tasks must run as SYSTEM.'
    Assert-True ($script:task.Trigger.Count -eq 2) 'Cleanup must run at expiry and at reboot.'
    Assert-True ($script:task.Trigger[1].At -eq $expiry) 'Cleanup trigger must match expiry.'
    Assert-True $script:task.Settings.StartWhenAvailable 'Missed cleanup must run when available.'
    $encodedAction = ($script:task.Action.Argument -split ' ')[-1]
    $decodedAction = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedAction))
    Assert-True ($decodedAction.Contains('-Mode Cleanup')) 'Wrong cleanup task action.'
    # A competing failed invocation must never delete the successful invocation's directory.
    $script:events.Clear()
    Complete-SupportBootstrap 'temporary' 'someone-elses-session' $id $false $false $false
    Assert-True ($script:events.Count -eq 1) 'Only the caller-owned temporary directory may be deleted.'
    $script:events.Clear()
    function Remove-Item { param($LiteralPath, [switch]$Recurse, [switch]$Force)
        if ($LiteralPath -eq 'locked-temporary') { throw 'simulated temporary file lock' }
        $script:events.Add('remove-files')
    }
    function Write-Utf8 { param($Path, $Value) $script:events.Add('mark-closing') }
    function Remove-SupportSession { param($Id) $script:events.Add('rollback') }
    $failed = $false
    try { Complete-SupportBootstrap 'locked-temporary' $script:testRoot $id $false $true $true }
    catch { $failed = $true }
    Assert-True $failed 'Temporary deletion failure must remain visible.'
    Assert-True ($script:events.Contains('rollback')) 'Temporary deletion failure must not skip rollback.'
    Write-Output 'PowerShell syntax and isolated lifecycle tests passed.'
} finally {
    [IO.Directory]::Delete($script:testRoot, $true)
}
