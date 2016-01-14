#!/bin/bash
#Noriben Sandbox Automation Script
#Responsible for:
#* Copying malware into a known VM
#* Running malware sample
#* Copying off results
#
#Ensure you set the environment variables below to match your system
MALWAREFILE=$1
if [ ! -f $1 ]; then
	echo "Please provide executable filename as an argument."
	echo "For example:"
	echo "$0 ~/malware/ef8188aa1dfa2ab07af527bab6c8baf7"
	exit
fi

VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
VMX="/Users/bbaskin/VMs/RSA Victim.vmwarevm/Windows XP Professional.vmx"
VM_SNAPSHOT="Baseline"
VM_USER=Administrator
VM_PASS=password
DELAY=10
FILENAME=$(basename $MALWAREFILE)


"$VMRUN" -T ws revertToSnapshot "$VMX" $VM_SNAPSHOT
"$VMRUN" -T ws start "$VMX"
"$VMRUN" -gu $VM_USER  -gp $VM_PASS copyFileFromHostToGuest "$VMX" "$MALWAREFILE" C:\\Malware\\malware.exe
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" C:\\Python27\\Python.exe "C:\\Documents and Settings\\$VM_USER\\Desktop\\Noriben.py" -d -t $DELAY --cmd "C:\\Malware\\Malware.exe" --output "C:\\Noriben_Logs"
if [ $? -gt 0 ]; then
    echo "[!] File did not execute in VM correctly."
    exit
fi
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" C:\\Tools\\zip.exe -j C:\\NoribenReports.zip C:\\Noriben_Logs\\*.*
if [ $? -eq 12 ]; then
    echo "[!] ERROR: No files found in Noriben output folder to ZIP."
    exit
fi
"$VMRUN" -gu $VM_USER -gp $VM_PASS copyFileFromGuestToHost "$VMX" C:\\NoribenReports.zip $PWD/NoribenReports_$FILENAME.zip
