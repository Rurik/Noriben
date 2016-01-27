#!/bin/bash
#Noriben Sandbox Automation Script
#Responsible for:
#* Copying malware into a known VM
#* Running malware sample
#* Copying off results
#
#Ensure you set the environment variables below to match your system
if [ ! -f $1 ]; then
	echo "Please provide executable filename as an argument."
	echo "For example:"
	echo "$0 ~/malware/ef8188aa1dfa2ab07af527bab6c8baf7"
	exit
fi

DELAY=10
MALWAREFILE=$1
VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
VMX="/Users/bbaskin/VMs/RSA Victim.vmwarevm/Windows XP Professional.vmx"
VM_SNAPSHOT="Baseline"
VM_USER=Administrator
VM_PASS=password
FILENAME=$(basename $MALWAREFILE)
NORIBEN_PATH="C:\\Documents and Settings\\$VM_USER\\Desktop\\Noriben.py"
ZIP_PATH=C:\\Tools\\zip.exe
LOG_PATH=C:\\Noriben_Logs


"$VMRUN" -T ws revertToSnapshot "$VMX" $VM_SNAPSHOT
"$VMRUN" -T ws start "$VMX"
"$VMRUN" -gu $VM_USER  -gp $VM_PASS copyFileFromHostToGuest "$VMX" "$MALWAREFILE" C:\\Malware\\malware.exe
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" C:\\Python27\\Python.exe "$NORIBEN_PATH" -d -t $DELAY --cmd "C:\\Malware\\Malware.exe" --output "$LOG_PATH"
if [ $? -gt 0 ]; then
    echo "[!] File did not execute in VM correctly."
    exit
fi
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" "$ZIP_PATH" -j C:\\NoribenReports.zip "$LOG_PATH\\*.*"
if [ $? -eq 12 ]; then
    echo "[!] ERROR: No files found in Noriben output folder to ZIP."
    exit
fi
"$VMRUN" -gu $VM_USER -gp $VM_PASS copyFileFromGuestToHost "$VMX" C:\\NoribenReports.zip $PWD/NoribenReports_$FILENAME.zip
