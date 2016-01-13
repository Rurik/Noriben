:Noriben Sandbox Automation Script
:Responsible for:
:* Copying malware into a known VM
:* Running malware sample
:* Copying off results
:
:Ensure you set the environment variables below to match your system
@echo off
if "%1"=="" goto HELP
if not exist "%1" goto HELP
SET CWD=%CD%
SET VMRUN="C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
SET VMX="e:\VMs\WinXP_Malware\WinXP_Malware.vmx"
SET VM_SNAPSHOT="Baseline"
SET VM_USER=Administrator
set VM_PASS=password
set DELAY=10
set FILENAME=%~nx1

%VMRUN% -T ws revertToSnapshot %VMX% %VM_SNAPSHOT%
%VMRUN% -T ws start %VMX%
%VMRUN% -gu %VM_USER%  -gp %VM_PASS% copyFileFromHostToGuest %VMX% "%1" C:\Malware\malware.exe
%VMRUN% -T ws -gu %VM_USER% -gp %VM_PASS% runProgramInGuest %VMX% C:\Python27\Python.exe "C:\Documents and Settings\%VM_USER%\Desktop\Noriben.py" -d -t %DELAY% --cmd "C:\Malware\Malware.exe" --output "C:\Noriben_Logs"
if %ERRORLEVEL%==1 goto ERROR1
%VMRUN% -T ws -gu %VM_USER% -gp %VM_PASS% runProgramInGuest %VMX% C:\Tools\zip.exe -j C:\NoribenReports.zip C:\Noriben_Logs\*.*
%VMRUN% -gu %VM_USER%  -gp %VM_PASS% copyFileFromGuestToHost %VMX% C:\NoribenReports.zip %CWD%\NoribenReports_%FILENAME%.zip
goto END

:ERROR1
echo [!] File did not execute in VM correctly.
goto END

:HELP
echo Please provide executable filename as an argument.
echo For example:
echo %~nx0 C:\Malware\ef8188aa1dfa2ab07af527bab6c8baf7
goto END

:END
