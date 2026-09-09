# Windows PowerShell 5.1. This file contains no enrollment credentials.
[CmdletBinding()]
param(
    [ValidateSet('Library', 'Sshd', 'Tunnel', 'Monitor', 'Activity', 'Close', 'Cleanup')]
    [string]$Mode = 'Library',
    [string]$SessionId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SessionId([string]$Value) {
    if ($Value -cnotmatch '^[a-f0-9]{12}$') { throw 'Invalid session ID.' }
}

function Enter-SupportLock([string]$Id, [int]$TimeoutMilliseconds = 0) {
    Assert-SessionId $Id
    $mutex = New-Object Threading.Mutex($false, "Global\TSuiteSupport-$Id")
    try {
        try { $acquired = $mutex.WaitOne($TimeoutMilliseconds) }
        catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Another installation or cleanup is using this session. Retry later.' }
        return $mutex
    } catch {
        $mutex.Dispose()
        throw
    }
}

function Complete-SupportBootstrap(
    [string]$Temporary, [string]$Directory, [string]$Id,
    [bool]$Installed, [bool]$StateWritten, [bool]$DirectoryCreated
) {
    try {
        Remove-Item -LiteralPath $Temporary -Recurse -Force
    } finally {
        # Rollback is independent of temporary credential deletion (e.g. an antivirus file lock).
        if (-not $Installed -and $StateWritten) {
            try { Write-Utf8 (Join-Path $Directory 'closing') 'installation failed' }
            finally { Remove-SupportSession $Id }
        } elseif (-not $Installed -and $DirectoryCreated) {
            Remove-Item -LiteralPath $Directory -Recurse -Force
        }
    }
}

function Write-Utf8([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, (New-Object Text.UTF8Encoding($false)))
}

function Set-ServiceFilePermissions([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Expected a regular service file.'
    }
    # ssh-keygen can assign the interactive user's SID even inside our private directory.
    # SYSTEM-run OpenSSH requires service-owned files, not personal user ownership/grants.
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw "Directory already exists: $Path" }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # .NET Framework overload applies the ACL at creation, before writing secrets.
    [void][IO.Directory]::CreateDirectory($Path, $acl)
}

function Assert-PrivateDirectory([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Support directory must not be a reparse point.'
    }
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw 'Support directory has an untrusted owner.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'Support directory has untrusted permissions.'
        }
    }
}

function Get-SupportRoot {
    $root = Join-Path $env:ProgramData 'TSuiteSupport'
    if (-not (Test-Path -LiteralPath $root)) { New-PrivateDirectory $root }
    Assert-PrivateDirectory $root
    return $root
}

function Register-SupportTask([string]$Id, [string]$ActionMode, [datetime]$Expires) {
    Assert-SessionId $Id
    $directory = Join-Path (Get-SupportRoot) $Id
    $script = Join-Path $directory 'client.ps1'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $runnerLog = Join-Path $directory "$ActionMode.runner.log"
    $quotedScript = $script.Replace("'", "''")
    $quotedLog = $runnerLog.Replace("'", "''")
    # Catch errors outside the client script too (loading/parsing/early state validation).
    $runner = "`$ErrorActionPreference = 'Stop'; try { & '$quotedScript' -Mode $ActionMode -SessionId $Id } catch { " +
        "[IO.File]::AppendAllText('$quotedLog', '[TSuite-startup] ' + `$_.Exception.Message + " +
        "[Environment]::NewLine + `$_.ScriptStackTrace + [Environment]::NewLine); exit 1 }"
    $encodedRunner = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($runner))
    $action = New-ScheduledTaskAction -Execute $powershell -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encodedRunner)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
    $triggers = @(New-ScheduledTaskTrigger -AtStartup)
    if ($ActionMode -eq 'Cleanup') {
        # Also retry cleanup after a reboot or a temporary failure.
        $triggers += New-ScheduledTaskTrigger -Once -At $Expires -RepetitionInterval (New-TimeSpan -Minutes 1)
    }
    Register-ScheduledTask -TaskName "TSuiteSupport-$Id-$ActionMode" -Action $action `
        -Trigger $triggers -Principal $principal -Settings $settings | Out-Null
}

function Read-SupportState([string]$Id) {
    Assert-SessionId $Id
    $directory = Join-Path (Get-SupportRoot) $Id
    Assert-PrivateDirectory $directory
    $state = Get-Content -LiteralPath (Join-Path $directory 'session.json') -Raw | ConvertFrom-Json
    if ($state.session_id -cne $Id -or $state.ops_user -cne "tsuite-ops-$($Id.Substring(0, 8))") {
        throw 'Support state does not match this session.'
    }
    return $state
}

function Remove-SupportSession([string]$Id) {
    $mutex = Enter-SupportLock $Id 30000
    try { Remove-SupportSessionResources $Id }
    finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

function Remove-SupportSessionResources([string]$Id) {
    $state = Read-SupportState $Id
    $directory = Join-Path (Get-SupportRoot) $Id
    # Disable login before stopping tasks or removing credentials. Never remove a pre-existing account.
    $user = Get-LocalUser -Name $state.ops_user -ErrorAction SilentlyContinue
    if ($user) {
        if ($user.Description -cne "TSuite temporary support $Id") { throw 'Account ownership mismatch.' }
        Disable-LocalUser -SID $user.SID
    }
    foreach ($action in @('Monitor', 'Tunnel', 'Sshd')) {
        $task = Get-ScheduledTask -TaskName "TSuiteSupport-$Id-$action" -ErrorAction SilentlyContinue
        if ($task) {
            Stop-ScheduledTask -InputObject $task
            Unregister-ScheduledTask -InputObject $task -Confirm:$false
        }
    }
    # Task Scheduler may leave native child processes behind after terminating the wrapper.
    foreach ($process in Get-CimInstance Win32_Process) {
        if ($process.Name -notin @('ssh.exe', 'sshd.exe') -or -not $process.CommandLine) { continue }
        $configArgument = '"' + (Join-Path $directory 'sshd_config') + '"'
        $keyArgument = '"' + (Join-Path $directory 'tunnel_ed25519') + '"'
        if (($process.ExecutablePath -eq $state.sshd_path -and $process.CommandLine.Contains($configArgument)) -or
            ($process.ExecutablePath -eq $state.ssh_path -and $process.CommandLine.Contains($keyArgument))) {
            & "$env:SystemRoot\System32\taskkill.exe" /PID $process.ProcessId /T /F | Out-Null
            if ($LASTEXITCODE -ne 0 -and (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue)) {
                throw 'Could not stop a session SSH process; cleanup will retry.'
            }
        }
    }
    # Stop SSH session shells as well as the task processes; account expiry alone does not end sessions.
    if ($user) {
        foreach ($process in Get-CimInstance Win32_Process) {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction SilentlyContinue
            if ($owner -and $owner.Sid -eq $user.SID.Value) {
                Invoke-CimMethod -InputObject $process -MethodName Terminate -ErrorAction SilentlyContinue | Out-Null
            }
        }
        Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'" | Remove-CimInstance
        Remove-LocalUser -SID $user.SID
    }
    Remove-Item -LiteralPath $directory -Recurse -Force
    # Keep the cleanup task until all cleanup succeeds, so a partial failure can be retried.
    Unregister-ScheduledTask -TaskName "TSuiteSupport-$Id-Cleanup" -Confirm:$false -ErrorAction SilentlyContinue
}

function Save-StartupDiagnostics([string]$Id) {
    Assert-SessionId $Id
    $root = Get-SupportRoot
    $directory = Join-Path $root $Id
    $diagnostics = Join-Path $root 'diagnostics'
    if (-not (Test-Path -LiteralPath $diagnostics)) { New-PrivateDirectory $diagnostics }
    Assert-PrivateDirectory $diagnostics
    $lines = New-Object 'Collections.Generic.List[string]'
    $lines.Add("[TSuite-startup] session=$Id time=$([DateTimeOffset]::UtcNow.ToString('o'))")
    try {
        $task = Get-ScheduledTask -TaskName "TSuiteSupport-$Id-Sshd" -ErrorAction Stop
        $info = $task | Get-ScheduledTaskInfo -ErrorAction Stop
        $lines.Add("task_state=$($task.State) last_result=$($info.LastTaskResult) last_run=$($info.LastRunTime)")
    } catch { $lines.Add('Task status unavailable: ' + $_.Exception.Message) }
    # Only these non-credential error logs are exported; never serialize session/enrollment state.
    foreach ($name in @('Sshd.runner.log', 'Sshd.stderr.log', 'Sshd.native.log')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) {
            $lines.Add("--- $name ---")
            foreach ($line in Get-Content -LiteralPath $path -Tail 30 -ErrorAction Stop) {
                $lines.Add([string]$line)
            }
        }
    }
    $output = Join-Path $diagnostics "$Id-startup.log"
    Write-Utf8 $output ($lines -join [Environment]::NewLine)
    Write-Host ($lines -join [Environment]::NewLine)
    Write-Host "Startup diagnostics saved: $output"
}

function Invoke-SupportProcess($State, [string]$ActionMode) {
    $directory = Join-Path (Get-SupportRoot) $State.session_id
    while ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt [long](Read-SupportState $State.session_id).expires_at -and -not (Test-Path (Join-Path $directory 'closing'))) {
        if ($ActionMode -eq 'Sshd') {
            $executable = $State.sshd_path
            $arguments = '-D -E "{0}" -f "{1}"' -f (Join-Path $directory 'Sshd.native.log'), (Join-Path $directory 'sshd_config')
        } else {
            $executable = $State.ssh_path
            $arguments = '-NT -F none -i "{0}" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="{1}" -o ExitOnForwardFailure=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -p {2} -R 127.0.0.1:{3}:127.0.0.1:{4} {5}@{6}' -f `
                (Join-Path $directory 'tunnel_ed25519'), (Join-Path $directory 'known_hosts'), `
                $State.bastion_port, $State.remote_port, $State.local_port, $State.tunnel_user, $State.bastion_host
        }
        $process = Start-Process -FilePath $executable -ArgumentList $arguments -PassThru -NoNewWindow `
            -RedirectStandardError (Join-Path $directory "$ActionMode.stderr.log")
        try {
            while (-not $process.WaitForExit(1000)) {
                if ((Test-Path (Join-Path $directory 'closing')) -or
                    [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge [long](Read-SupportState $State.session_id).expires_at) { break }
            }
        } finally {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
        Start-Sleep -Seconds 5
    }
}

function Write-SupportState($State, [string]$Directory) {
    $path = Join-Path $Directory 'session.json'
    $temporary = Join-Path $Directory ('state-' + [guid]::NewGuid().ToString('N'))
    try {
        Write-Utf8 $temporary ($State | ConvertTo-Json -Compress)
        [IO.File]::Replace($temporary, $path, [NullString]::Value)
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Test-SupportActivity($State, $Previous) {
    $directory = Join-Path (Get-SupportRoot) $State.session_id
    $marker = Get-Item -LiteralPath (Join-Path $directory 'activity') -ErrorAction SilentlyContinue
    if (-not $marker) { return @{active = $false; snapshot = $Previous} }
    $age = ([DateTime]::UtcNow - $marker.LastWriteTimeUtc).TotalSeconds
    $stamp = $marker.LastWriteTimeUtc.Ticks
    return @{active = [bool]($stamp -ne $Previous -and $age -ge 0 -and $age -le 45); snapshot = $stamp}
}

function Request-SupportLease($State, [bool]$Active) {
    $directory = Join-Path (Get-SupportRoot) $State.session_id
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $State.ssh_path
    $start.Arguments = '-F none -T -i "{0}" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="{1}" -o ClearAllForwardings=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -p {2} tsuite-enroll@{3} lease' -f `
        (Join-Path $directory 'lease_ed25519'), (Join-Path $directory 'known_hosts'), $State.bastion_port, $State.bastion_host
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine((@{active = $Active} | ConvertTo-Json -Compress))
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(20000)) { $process.Kill(); throw 'Lease request timed out.' }
        if ($process.ExitCode -ne 0) { throw 'Lease request rejected or unavailable.' }
        $reply = $output.Result | ConvertFrom-Json
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($reply.session_id -cne $State.session_id -or $reply.idle_timeout_seconds -ne $State.idle_timeout_seconds -or
            $reply.expires_at -le $now -or $reply.expires_at -gt ($now + $State.idle_timeout_seconds + 30) -or
            $reply.expires_at -lt $State.expires_at) { throw 'Invalid lease response.' }
        return [long]$reply.expires_at
    } finally { $process.Dispose() }
}

function Set-SupportExpiry($State, [long]$Expiry) {
    $directory = Join-Path (Get-SupportRoot) $State.session_id
    $date = [DateTimeOffset]::FromUnixTimeSeconds($Expiry)
    $user = Get-LocalUser -Name $State.ops_user
    if ($user.Description -cne "TSuite temporary support $($State.session_id)") { throw 'Account ownership mismatch.' }
    $path = Join-Path $directory 'authorized_keys'
    $keys = Get-Content -LiteralPath $path -Raw
    if ([regex]::Matches($keys, 'expiry-time="[0-9]{14}Z"').Count -ne 1) { throw 'Invalid key expiry.' }
    $keys = $keys -replace 'expiry-time="[0-9]{14}Z"', ('expiry-time="' + $date.UtcDateTime.ToString('yyyyMMddHHmmssZ') + '"')
    # Native restrictions first; commit the watchdog deadline only after both succeed.
    Write-Utf8 $path $keys
    Set-ServiceFilePermissions $path
    Set-LocalUser -SID $user.SID -AccountExpires $date.LocalDateTime
    $State.expires_at = $Expiry
    Write-SupportState $State $directory
}

function Watch-SupportLease([string]$Id) {
    $previous = $null
    while ($true) {
        $mutex = Enter-SupportLock $Id 30000
        try {
            $state = Read-SupportState $Id
            $directory = Join-Path (Get-SupportRoot) $Id
            if ((Test-Path (Join-Path $directory 'closing')) -or
                [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge [long]$state.expires_at) { return }
            $activity = Test-SupportActivity $state $previous
            $expiry = Request-SupportLease $state $activity.active
            if ($expiry -ne $state.expires_at) { Set-SupportExpiry $state $expiry }
            $previous = $activity.snapshot
            $marker = Join-Path $directory 'activity'
            if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
        } catch {
            Write-Warning 'Support lease check failed; retaining the confirmed expiry.'
        } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
        Start-Sleep -Seconds 15
    }
}

if ($Mode -eq 'Library') { return }
Assert-SessionId $SessionId
$state = Read-SupportState $SessionId
$directory = Join-Path (Get-SupportRoot) $SessionId
switch ($Mode) {
    'Monitor' { Watch-SupportLease $SessionId }
    'Activity' {
        $mutex = Enter-SupportLock $SessionId 30000
        try {
            $state = Read-SupportState $SessionId
            if ((Test-Path (Join-Path $directory 'closing')) -or
                [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge [long]$state.expires_at) { throw 'Session ended.' }
            Write-Utf8 (Join-Path $directory 'activity') 'operator activity'
        } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
    }
    'Close' {
        $mutex = Enter-SupportLock $SessionId 30000
        try { Write-Utf8 (Join-Path $directory 'closing') 'close requested' }
        finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
        Start-ScheduledTask -TaskName "TSuiteSupport-$SessionId-Cleanup"
        Write-Output "cleanup-scheduled:$SessionId"
    }
    'Cleanup' {
        Start-Sleep -Seconds 3
        $mutex = Enter-SupportLock $SessionId 30000
        try {
            $state = Read-SupportState $SessionId
            if (-not (Test-Path (Join-Path $directory 'closing')) -and
                [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt [long]$state.expires_at) { return }
            Write-Utf8 (Join-Path $directory 'closing') 'cleanup requested'
            Remove-SupportSessionResources $SessionId
        } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
    }
    default { Invoke-SupportProcess $state $Mode }
}
