# Noriben Sandbox Automation Script
# V 1.0 - 3 Apr 17
# Responsible for:
# * Copying malware into a known VM
# * Running malware sample
# * Copying off results
#
# Ensure you set the environment variables below to match your system. I've left defaults to help.
# This is definitely a work in progress. However, efforts made to make it clear per PyCharm code inspection.

import argparse
import magic  # pip python-magic
import os
import subprocess
import sys
import time

debug = False
timeoutSeconds = 300
VMRUN = os.path.expanduser(r"/Applications/VMware\ Fusion.app/Contents/Library/vmrun")
VMX = os.path.expanduser(r"~/VMs/Windows.vmwarevm/Windows.vmx")
VM_SNAPSHOT = "YourVMSnapshotNameHere
VM_USER = "Admin"
VM_PASS = "password"
noribenPath = "C:\\\\Users\\\\{}\\\\Desktop".format(VM_USER)
guestNoribenPath = '{}\\\\Noriben.py'.format(noribenPath)
procmonConfigPath = '{}\\\\ProcmonConfiguration.pmc'.format(noribenPath)
# reportPathStructure = '{}/NoribenReports_{}.zip'
reportPathStructure = '{}/{}_NoribenReport.zip'  # (hostMalwarePath, hostMalwareNameBase)
hostScreenshotPathStructure = '{}/{}.png'  # (hostMalwarePath, hostMalwareNameBase)
guestLogPath = "C:\\\\Noriben_Logs"
guestZipPath = "C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\zip.exe"
guestPythonPath = "C:\\\\Python27\\\\python.exe"
hostNoribenPath = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'Noriben.py')
guestMalwarePath = "C:\\\\Malware\\\\malware_"


def file_exists(fname):
    return os.path.exists(fname) and os.access(fname, os.F_OK)

def execute(cmd):
    if debug:
        print(cmd)
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()
    return stdout.returncode

def main():
    global debug
    global timeoutSeconds
    global VM_SNAPSHOT

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='filename', required=True)
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Show all commands for debugging',
                        required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('-x', '--dontrun', dest='dontrun', action='store_true', help='Do not run file', required=False)
    parser.add_argument('-xx', '--dontrunnothing', dest='dontrunnothing', action='store_true', help='Run nothing',
                        required=False)
    parser.add_argument('--raw', dest='raw', action='store_true', help='Remove ProcMon filters', required=False)
    parser.add_argument('--net', action='store_true', required=False)
    parser.add_argument('--nolog', action='store_true', required=False)
    parser.add_argument('--norevert', action='store_true', required=False)
    parser.add_argument('--update', action='store_true', required=False)
    parser.add_argument('--screenshot', action='store_true', required=False)
    parser.add_argument('-s', '--snapshot', required=False)
    parser.add_argument('--defense', action='store_true', required=False)  # Particular to Carbon Black Defense

    args = parser.parse_args()

    if args.debug:
        debug = True

    dontrun = False
    if args.dontrun:
        dontrun = True

    if args.snapshot:
        VM_SNAPSHOT = args.snapshot

    if args.dontrunnothing:
        dontrunnothing = True
    else:
        dontrunnothing = False

    malware_file = args.file

    if args.timeout:
        timeoutSeconds = args.timeout

    magic_result = magic.from_file(malware_file)
    if not magic_result.startswith('PE32') or 'DLL' in magic_result:
        if 'DOS batch' not in magic_result:
            dontrun = True
            print('[*] Disabling automatic running due to magic signature: {}'.format(magic_result))

    hostMalwareNameBase = os.path.split(malware_file)[-1].split('.')[0]
    if dontrun:
        filename = '{}{}'.format(guestMalwarePath, hostMalwareNameBase)
    elif 'DOS batch' in magic_result:
        filename = '{}{}.bat'.format(guestMalwarePath, hostMalwareNameBase)
    else:
        filename = '{}{}.exe'.format(guestMalwarePath, hostMalwareNameBase)
    hostMalwarePath = os.path.dirname(malware_file)
    if hostMalwarePath == '':
        hostMalwarePath = '.'

    if not args.screenshot:
        active = '-activeWindow'
    else:
        active = ''
    cmd_base = '{} -T ws -gu {} -gp {} runProgramInGuest {} {} -interactive'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                    active)

    if not args.norevert:
        cmd = "{} -T ws revertToSnapshot \"{}\" {}".format(VMRUN, VMX, VM_SNAPSHOT)
        returncode = execute(cmd)
        if returncode:
            print('[!] Error: Possible unknown snapshot: {}'.format(VM_SNAPSHOT))
            quit()


    cmd = '{} -T ws start "{}"'.format(VMRUN, VMX)
    returncode = execute(cmd)
    if returncode:
        print('[!] Unknown error trying to start VM. Error {}'.format(returncode))
        quit()


    if args.net:
        # Experimental. Doesn't quite work right.
        cmd = '{} -gu {} -gp {} writeVariable ethernet0.startConnected'.format(VMRUN, VM_USER, VM_PASS)
        returncode = execute(cmd)
        quit()

    cmd = '{} -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX, malware_file,
                                                                           filename)
    returncode = execute(cmd)
    if returncode:
        print('[!] Unknown error trying to copy file to guest. Error {}'.format(returncode))
        quit()

    if args.update and file_exists(hostNoribenPath):
        cmd = '{} -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                               hostNoribenPath,
                                                                               guestNoribenPath)
        returncode = execute(cmd)
        if returncode:
            print('[!] Unknown error trying to copy updated Noriben to guest. Continuing. Error {}'.format(returncode))
            quit()

    if dontrunnothing:
        quit()

    time.sleep(5)

    if args.raw:
        cmd = '{} C:\\\\windows\\\\system32\\\\cmd.exe "/c del {}"'.format(cmd_base, procmonConfigPath)
        returncode = execute(cmd)
        if returncode:
            print('[!] Unknown error trying to execute command in guest. Error {}'.format(returncode))
            quit()


    # Run Noriben
    cmd = '{} {} "{}" -t {} --headless'.format(cmd_base, guestPythonPath, guestNoribenPath, timeoutSeconds)

    if not dontrun:
        cmd = '{} --cmd {} --output "{}"'.format(cmd, filename, guestLogPath)

    if debug:
        cmd = '{} -d'.format(cmd)

    returncode = execute(cmd)
    if returncode:
        print('[!] Unknown error in running Noriben. Error {}'.format(returncode))
        quit()

    if not dontrun:
        zipFailed = False
        cmd = '{} "{}" -j C:\\\\NoribenReports.zip {}\\\\*.*'.format(cmd_base, guestZipPath, guestLogPath)
        returncode = execute(cmd)
        if returncode:
            print('[!] Unknown error trying to zip report archive. Error {}'.format(returncode))
            zipFailed = True

        if args.defense and not zipFailed:
            # Get Carbon Black Defense log. This is an example if you want to include additional files.
            cmd = '{} "{}" -j C:\\\\NoribenReports.zip "C:\\\\Program Files\\\\Confer\\\\confer.log"'.format(
                                                                                                        cmd_base,
                                                                                                        guestZipPath,
                                                                                                        guestLogPath)
            returncode = execute(cmd)
            if returncode:
                print('[!] Unknown error trying to add additional file to archive. Continuing. Error {}'.format(returncode))

        if not args.nolog and not zipFailed:
            hostReportPath = reportPathStructure.format(hostMalwarePath, hostMalwareNameBase)
            cmd = '{} -gu {} -gp {} copyFileFromGuestToHost {} C:\\\\NoribenReports.zip {}'.format(VMRUN, VM_USER,
                                                                                                   VM_PASS, VMX,
                                                                                                   hostReportPath)
            returncode = execute(cmd)
            if returncode:
                print('[!] Unknown error trying to copy file from guest. Continuing. Error {}'.format(returncode))

        if args.screenshot:
            hostScreenshotPath = hostScreenshotPathStructure.format(hostMalwarePath, hostMalwareNameBase)
            cmd = '{} -gu {} -gp {} captureScreen {} {}'.format(VMRUN, VM_USER, VM_PASS, VMX, hostScreenshotPath)
            returncode = execute(cmd)
            if returncode:
                print('[!] Unknown error trying to create screenshot. Error {}'.format(returncode))

if __name__ == '__main__':
    main()
