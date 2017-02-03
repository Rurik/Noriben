#!/bin/bash
#Noriben Sandbox Automation Script
#Responsible for:
#* Copying malware into a known VM
#* Running malware sample
#* Copying off results
#
#Ensure you set the environment variables below to match your system
NORIBEN_DEBUG=""
DELAY=10
VMRUN=/Applications/VMware\ Fusion.app/Contents/Library/vmrun
VMX=~/VMs/Win7_VICTIM.vmwarevm/Win7_VICTIM.vmx
VM_SNAPSHOT="Baseline"
VM_USER=Admin
VM_PASS=password
NORIBEN_PATH="C:\\Documents and Settings\\$VM_USER\\Desktop\\Noriben.py"
ZIP_PATH=C:\\gnuwin32\\bin\\zip.exe
LOG_PATH=C:\\Noriben_Logs


MALWAREFILE=$1
if [ ! -f $1 ]; then
    echo "Please provide executable filename as an argument."
    echo "For example:"
    echo "$0 ~/malware/ef8188aa1dfa2ab07af527bab6c8baf7"
    exit
fi

FILENAME=$(basename $MALWAREFILE)
if [ ! -z $NORIBEN_DEBUG ]; then echo "$VMRUN" -T ws revertToSnapshot "$VMX" $VM_SNAPSHOT; fi
"$VMRUN" -T ws revertToSnapshot "$VMX" $VM_SNAPSHOT

if [ ! -z $NORIBEN_DEBUG ]; then echo "$VMRUN" -T ws start "$VMX"; fi
"$VMRUN" -T ws start "$VMX"

if [ ! -z $NORIBEN_DEBUG ]; then echo "$VMRUN" -gu $VM_USER  -gp $VM_PASS copyFileFromHostToGuest "$VMX" "$MALWAREFILE" C:\\Malware\\malware.exe; fi
"$VMRUN" -gu $VM_USER  -gp $VM_PASS copyFileFromHostToGuest "$VMX" "$MALWAREFILE" C:\\Malware\\malware.exe

if [ ! -z $NORIBEN_DEBUG ]; then echo "$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" C:\\Python27\\Python.exe "$NORIBEN_PATH" -d -t $DELAY --cmd "C:\\Malware\\Malware.exe" --output "$LOG_PATH"; fi
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" C:\\Python27\\Python.exe "$NORIBEN_PATH" -d -t $DELAY --cmd "C:\\Malware\\Malware.exe" --output "$LOG_PATH"
if [ $? -gt 0 ]; then
    echo "[!] File did not execute in VM correctly."
    exit
fi

if [ ! -z $NORIBEN_DEBUG ]; then "$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" "$ZIP_PATH" -j C:\\NoribenReports.zip "$LOG_PATH\\*.*"; fi
"$VMRUN" -T ws -gu $VM_USER -gp $VM_PASS runProgramInGuest "$VMX" "$ZIP_PATH" -j C:\\NoribenReports.zip "$LOG_PATH\\*.*"
if [ $? -eq 12 ]; then
    echo "[!] ERROR: No files found in Noriben output folder to ZIP."
    exit
fi
"$VMRUN" -gu $VM_USER -gp $VM_PASS copyFileFromGuestToHost "$VMX" C:\\NoribenReports.zip $PWD/NoribenReports_$FILENAME.zip


