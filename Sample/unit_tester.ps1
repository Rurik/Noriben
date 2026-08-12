# Noriben Unit Tester Script
# Version 1.2
#
# Detonates a controlled, predictable sequence of actions inside a Procmon-
# monitored Windows VM to produce a known-good CSV for integration testing.
#
# Each block is labelled with the Noriben event type it exercises.  Add a new
# block here whenever a new parse_csv() feature is added, then re-run in the
# VM, commit the new unit_tester.csv, and update the assertions in
# tests/test_unit_tester_integration.py.
#
# Usage (run via Noriben):
#   python.exe Noriben.py -t 30 --cmd "powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -File C:\path\to\unit_tester.ps1"
#
# Or directly for generating a raw CSV without Noriben automation:
#   powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -File unit_tester.ps1
#
# Expected output file:  Sample\unit_tester.csv  (commit this after the VM run)

$ErrorActionPreference = 'SilentlyContinue'

# -----------------------------------------------------------------------
# Constants — change these if the defaults collide with your approvelist
# -----------------------------------------------------------------------
$TestDir     = "$env:TEMP\NoribenTest"
$TestFile    = "$TestDir\test_file.txt"
$RenameFile  = "$TestDir\test_renamed.txt"
$RegBase     = "HKCU:\Software\NoribenTest"
$RegKey      = "$RegBase\TestKey"
$DnsTarget   = "example.com"
$TcpTarget   = "93.184.216.34"   # example.com — stable, well-known IP
$TcpPort     = 80

Write-Host "[NoribenTest] Starting unit_tester script v1.2"

# -----------------------------------------------------------------------
# 1. PROCESS CREATE + EXIT CODE 0
#    Noriben event: [CreateProcess] ... [Child PID: N]
#    Exit annotation: none (zero exits are suppressed)
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 1. Process Create - exit code 0"
Start-Process -FilePath "cmd.exe" `
              -ArgumentList "/c", "exit 0" `
              -WindowStyle Hidden `
              -Wait

# -----------------------------------------------------------------------
# 2. PROCESS CREATE + EXIT CODE 1  (non-zero)
#    Noriben event: [CreateProcess] ... [Child PID: N] [Exit: 0x00000001 - Generic Error]
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 2. Process Create - exit code 1"
Start-Process -FilePath "cmd.exe" `
              -ArgumentList "/c", "exit 1" `
              -WindowStyle Hidden `
              -Wait

# -----------------------------------------------------------------------
# 3. FILE CREATE
#    Noriben event: [CreateFile] ...NoribenTest\test_file.txt
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 3. File Create"
New-Item -ItemType Directory -Path $TestDir -Force | Out-Null
Set-Content -Path $TestFile -Value "NoribenTest test data"

# -----------------------------------------------------------------------
# 4. FILE RENAME
#    Noriben event: [RenameFile] ...test_file.txt -> ...test_renamed.txt
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 4. File Rename"
Rename-Item -Path $TestFile -NewName "test_renamed.txt" -Force

# -----------------------------------------------------------------------
# 5. FILE DELETE
#    Noriben event: [DeleteFile] ...test_renamed.txt
#    Note: newer Windows versions use SetDispositionInformationEx (not
#    SetDispositionInformationFile) — both are handled by parse_csv().
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 5. File Delete"
Remove-Item -Path $RenameFile -Force

# -----------------------------------------------------------------------
# 6. REGISTRY CREATE KEY
#    Noriben event: [RegCreateKey] HKCU\Software\NoribenTest\TestKey
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 6. Registry Create Key"
New-Item -Path $RegKey -Force | Out-Null

# -----------------------------------------------------------------------
# 7. REGISTRY SET VALUE
#    Noriben event: [RegSetValue] HKCU\Software\NoribenTest\TestKey : TestValue
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 7. Registry Set Value"
Set-ItemProperty -Path $RegKey -Name "TestValue" -Value "NoribenTest"

# -----------------------------------------------------------------------
# 8. REGISTRY DELETE VALUE
#    Noriben event: [RegDeleteValue] HKCU\Software\NoribenTest\TestKey : TestValue
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 8. Registry Delete Value"
Remove-ItemProperty -Path $RegKey -Name "TestValue" -Force

# -----------------------------------------------------------------------
# 9. REGISTRY DELETE KEY
#    Noriben event: [RegDeleteKey] HKCU\Software\NoribenTest
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 9. Registry Delete Key"
Remove-Item -Path $RegBase -Recurse -Force

# -----------------------------------------------------------------------
# 10. DNS QUERY  (UDP Send to :53)
#     Noriben event: [UDP] svchost.exe > DNS_server:53
#     Also contributes to Unique Hosts
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 10. DNS Query"
try {
    [System.Net.Dns]::GetHostAddresses($DnsTarget) | Out-Null
} catch {}

# -----------------------------------------------------------------------
# 11. TCP CONNECTION
#     Noriben event: [TCP] powershell.exe:PID > 93.184.216.34:80
#     Procmon logs the connection as TCP Connect/Reconnect + TCP Send/Receive.
#     Also contributes to Unique Hosts.
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 11. TCP Connection"
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect($TcpTarget, $TcpPort)
    $client.Close()
} catch {}

# -----------------------------------------------------------------------
# 12. MODULE LOAD from unusual path
#     Noriben event: [LoadImage] powershell.exe:PID > %TEMP%\NoribenTest\NoribenTest.dll
#     Copies a known system DLL to an unusual path, then loads it via the
#     native LoadLibrary() Win32 API using P/Invoke.  LoadLibrary() causes
#     a kernel-level image-load notification which Procmon records as a
#     "Load Image" event — unlike .NET reflection loading, which goes through
#     the CLR loader and does not generate that event.
# -----------------------------------------------------------------------
Write-Host "[NoribenTest] 12. Module Load from unusual path"
try {
    # Copy a small, stable system DLL to the test directory (unusual path)
    $dllDst = "$TestDir\NoribenTest.dll"
    Copy-Item "$env:SystemRoot\System32\version.dll" $dllDst -Force

    # Call LoadLibrary() natively via P/Invoke to guarantee a Load Image event
    $sig = '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr LoadLibrary(string lpFileName);'
    $loader = Add-Type -MemberDefinition $sig -Name "NoribenLoader" -Namespace "NoribenTest" -PassThru
    $loader[0]::LoadLibrary($dllDst) | Out-Null
} catch {}

# -----------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------
Remove-Item -Path $TestDir -Recurse -Force

Write-Host "[NoribenTest] Unit tester script complete"
exit 0
