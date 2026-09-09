# Native Windows ACL regression. Uses throwaway files; no accounts or services are changed.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'customer/windows-client.ps1') -Mode Library
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Output 'SKIP: native Windows ACL verification requires Windows.'
    return
}
$directory = Join-Path ([IO.Path]::GetTempPath()) ('tsuite-acl-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
try {
    $path = Join-Path $directory 'ssh_host_ed25519_key'
    [IO.File]::WriteAllText($path, 'test fixture - no private key material')
    $before = New-Object Security.AccessControl.FileSecurity
    $before.SetAccessRuleProtection($true, $false)
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $before.SetOwner($current)
    $before.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($current, 'FullControl', 'Allow')))
    $before.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), 'Read', 'Allow')))
    Set-Acl -LiteralPath $path -AclObject $before
    # Reproduce the keygen-created personal owner plus unwanted explicit grant, then repair.
    Set-ServiceFilePermissions $path
    Set-ServiceFilePermissions $path
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { throw 'The service file still has a personal owner.' }
    if (-not $acl.AreAccessRulesProtected) { throw 'The service file still inherits permissions.' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'Unexpected grants remain on the service file.' }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $rule = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
        if ($rule.Count -ne 1 -or $rule[0].AccessControlType -ne 'Allow' -or
            $rule[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Missing service file access: $sid"
        }
    }
    Write-Output 'Windows service-file ACL normalization and idempotency passed.'
} finally {
    [IO.Directory]::Delete($directory, $true)
}
