# Noriben Sandbox Automation Script
# V 1.0 - 3 Apr 17
# V 1.1 - 5 Jun 17
# Responsible for:
# * Copying malware into a known VM
# * Running malware sample
# * Copying off results
#
# Ensure you set the environment variables below to match your system. I've left defaults to help.
# This is definitely a work in progress. However, efforts made to make it clear per PyCharm code inspection.

import argparse
import io
import glob
import magic  # pip python-magic and libmagic
import os
import subprocess
import sys
import time

debug = False
timeoutSeconds = 300
VMRUN = os.path.expanduser(r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')
VMX = r'E:\VMs\Windows.vmwarevm\Windows.vmx'
# VMRUN = os.path.expanduser(r'/Applications/VMware Fusion.app/Contents/Library/vmrun')
# VMX = os.path.expanduser(r'~/VMs/Windows.vmwarevm/Windows.vmx')
VM_SNAPSHOT = 'YourVMSnapshotNameHere'
VM_USER = 'Admin'
VM_PASS = 'password'
noribenPath = 'C:\\\\Users\\\\{}\\\\Desktop'.format(VM_USER)
guestNoribenPath = '{}\\\\Noriben.py'.format(noribenPath)
procmonConfigPath = '{}\\\\ProcmonConfiguration.pmc'.format(noribenPath)
reportPathStructure = '{}/{}_NoribenReport.zip'  # (hostMalwarePath, hostMalwareNameBase)
hostScreenshotPathStructure = '{}/{}.png'  # (hostMalwarePath, hostMalwareNameBase)
guestLogPath = 'C:\\\\Noriben_Logs'
guestZipPath = 'C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\zip.exe'
guestPythonPath = 'C:\\\\Python27\\\\python.exe'
hostNoribenPath = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'Noriben.py')
guestMalwarePath = 'C:\\\\Malware\\\\malware_'

dontrun = False


def file_exists(fname):
    return os.path.exists(fname) and os.access(fname, os.F_OK)


def execute(cmd):
    if debug:
        print(cmd)
    time.sleep(2)
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()
    return stdout.returncode

    
def run_file(args, magicResult, malware_file):
    global dontrun
    
    hostMalwareNameBase = os.path.split(malware_file)[-1].split('.')[0]
    if dontrun:
        filename = '{}{}'.format(guestMalwarePath, hostMalwareNameBase)
    elif 'DOS batch' in magicResult:
        filename = '{}{}.bat'.format(guestMalwarePath, hostMalwareNameBase)
    else:
        filename = '{}{}.exe'.format(guestMalwarePath, hostMalwareNameBase)
    hostMalwarePath = os.path.dirname(malware_file)
    if hostMalwarePath == '':
        hostMalwarePath = '.'

    print('[*] Processing: {}'.format(malware_file))

    if not args.screenshot:
        active = '-activeWindow'
    else:
        active = ''
    cmdBase = '"{}" -T ws -gu {} -gp {} runProgramInGuest "{}" {} -interactive'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                       active)
    if not args.norevert:
        cmd = '"{}" -T ws revertToSnapshot "{}" {}'.format(VMRUN, VMX, VM_SNAPSHOT)
        returnCode = execute(cmd)
        if returnCode:
            print('[!] Error: Possible unknown snapshot: {}'.format(VM_SNAPSHOT))
            sys.exit(returnCode)

    cmd = '"{}" -T ws start "{}"'.format(VMRUN, VMX)
    returnCode = execute(cmd)
    if returnCode:
        print('[!] Unknown error trying to start VM. Error {}'.format(hex(returnCode)))
        sys.exit(returnCode)

    cmd = '"{}" -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX, malware_file,
                                                                             filename)
    returnCode = execute(cmd)
    if returnCode:
        print('[!] Unknown error trying to copy file to guest. Error {}'.format(hex(returnCode)))
        sys.exit(returnCode)

    if args.update:
        if file_exists(hostNoribenPath):
            cmd = '"{}" -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                     hostNoribenPath,
                                                                                     guestNoribenPath)
            returnCode = execute(cmd)
            if returnCode:
                print('[!] Unknown error trying to copy updated Noriben to guest. Continuing. Error {}'.format(
                      returnCode))
                sys.exit(returnCode)
        else:
            print('[!] Noriben.py on host not found: {}'.format(hostNoribenPath))
            sys.exit(returnCode)

    if args.dontrunnothing:
        sys.exit(returnCode)

    time.sleep(5)

    if args.raw:
        cmd = '{} C:\\\\windows\\\\system32\\\\cmd.exe "/c del {}"'.format(cmdBase, procmonConfigPath)
        returnCode = execute(cmd)
        if returnCode:
            print('[!] Unknown error trying to execute command in guest. Error {}'.format(hex(returnCode)))
            sys.exit(returnCode)

    # Run Noriben
    cmd = '{} {} "{}" -t {} --headless --output "{}" '.format(cmdBase, guestPythonPath, guestNoribenPath,
                                                              timeoutSeconds, guestLogPath)

    if not dontrun:
        cmd = '{} --cmd {} '.format(cmd, filename)

    if debug:
        cmd = '{} -d'.format(cmd)

    returnCode = execute(cmd)
    if returnCode:
        print('[!] Unknown error in running Noriben. Error {}'.format(hex(returnCode)))
        sys.exit(returnCode)

    if not dontrun:
    
        if args.post and file_exists(args.post):
            runScript(args, cmdBase)
    
        zipFailed = False
        cmd = '{} "{}" -j C:\\\\NoribenReports.zip "{}\\\\*.*"'.format(cmdBase, guestZipPath, guestLogPath)
        returnCode = execute(cmd)
        if returnCode:
            print('[!] Unknown error trying to zip report archive. Error {}'.format(hex(returnCode)))
            zipFailed = True

        if args.defense and not zipFailed:
            defenseFile = "C:\\\\Program Files\\\\Confer\\\\confer.log"
            # Get Carbon Black Defense log. This is an example if you want to include additional files.
            cmd = '{} "{}" -j C:\\\\NoribenReports.zip "{}"'.format(cmdBase, guestZipPath, defenseFile)
            returnCode = execute(cmd)
            if returnCode:
                print(('[!] Unknown error trying to add additional file to archive. Continuing. '
                       'Error {}; File: {}'.format(returnCode, defenseFile)))

        if not args.nolog and not zipFailed:
            hostReportPath = reportPathStructure.format(hostMalwarePath, hostMalwareNameBase)
            cmd = '"{}" -gu {} -gp {} copyFileFromGuestToHost "{}" C:\\\\NoribenReports.zip "{}"'.format(VMRUN, VM_USER,
                                                                                                         VM_PASS, VMX,
                                                                                                         hostReportPath)
            returnCode = execute(cmd)
            if returnCode:
                print('[!] Unknown error trying to copy file from guest. Continuing. Error {}'.format(hex(returnCode)))

        if args.screenshot:
            hostScreenshotPath = hostScreenshotPathStructure.format(hostMalwarePath, hostMalwareNameBase)
            cmd = '"{}" -gu {} -gp {} captureScreen "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX, hostScreenshotPath)
            returnCode = execute(cmd)
            if returnCode:
                print('[!] Unknown error trying to create screenshot. Error {}'.format(hex(returnCode)))


def getMagic(magicHandle, filename):
    try:
        magicResult = magicHandle.from_file(filename)
    except magic.MagicException as err:
        magicResult = ''
        if err.message == b'could not find any magic files!':
            print('[!] Windows Error: magic files not in path. See Dependencies on:',
                  'https://github.com/ahupp/python-magic')
            print('[!] You may need to manually specify magic file location using --magic')
        print('[!] Error in running magic against file: {}'.format(err))
    return magicResult

    
def runScript(args, cmdBase):
    sourcePath = ''

    # if sys.version_info[0] == '2':
    with io.open(args.post, encoding='utf-8') as hScript:
        for line in hScript:
            if debug:
                print('[*] Script: {}'.format(line.strip()))
            if line.startswith('#'):
                pass
            elif line.lower().startswith('collect'):
                try:
                    sourcePath = line.split('collect ')[1].strip()
                except IndexError:
                    print('[!] Ignoring bad script line: {}'.format(line.strip()))
                copyFileToZip(cmdBase, sourcePath)
            else:
                cmd = '{} "{}"'.format(cmdBase, line.strip())
                returnCode = execute(cmd)
                if returnCode:
                    print('[!] Unknown error trying to run script command. Error {}'.format(hex(returnCode)))


def copyFileToZip(cmdBase, filename):
    # This is a two-step process as zip.exe will not allow direct zipping of some system files.
    # Therefore, first copy file to log folder and then add to the zip. 

    cmd = '"{}" -gu {} -gp {} fileExistsInGuest "{}" {}'.format(VMRUN, VM_USER, VM_PASS, VMX, filename)
    returnCode = execute(cmd)
    if returnCode:
        print('[!] File does not exist in guest. Continuing. File: {}'.format(filename))
        return returnCode

    cmd = '{} C:\\\\windows\\\\system32\\\\xcopy.exe {} {}'.format(cmdBase, filename, guestLogPath)
    returnCode = execute(cmd)
    if returnCode:
        print(('[!] Unknown error trying to copy file to log folder. Continuing. '
               'Error {}; File: {}'.format(returnCode, filename)))
    return returnCode

    cmd = '{} "{}" -j C:\\\\NoribenReports.zip {}'.format(cmdBase, guestZipPath, filename)
    returnCode = execute(cmd)
    if returnCode:
        print(('[!] Unknown error trying to add additional file to archive. Continuing. '
               'Error {}; File: {}'.format(returnCode, filename)))
    return returnCode


def main():
    global debug
    global timeoutSeconds
    global VM_SNAPSHOT
    global VMX
    global dontrun

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='filename', required=False)
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help='Show all commands for debugging',
                        required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('-x', '--dontrun', dest='dontrun', action='store_true', help='Do not run file', required=False)
    parser.add_argument('-xx', '--dontrunnothing', dest='dontrunnothing', action='store_true', help='Run nothing',
                        required=False)
    parser.add_argument('--dir', help='Run all executables from a specified directory', required=False)
    parser.add_argument('--recursive', action='store_true', help='Recursively process a directory', required=False)
    parser.add_argument('--magic', help='Specify file magic database (may be necessary for Windows)', required=False)
    parser.add_argument('--nolog', action='store_true', help='Do not extract logs back', required=False)
    parser.add_argument('--norevert', action='store_true', help='Do not revert to snapshot', required=False)
    parser.add_argument('--post', help='post-execution script', required=False)
    parser.add_argument('--raw', action='store_true', help='Remove ProcMon filters', required=False)
    parser.add_argument('--update', action='store_true', help='Update Noriben.py in guest', required=False)
    parser.add_argument('--screenshot', action='store_true', help='Take screenshot after execution (PNG)',
                        required=False)
    parser.add_argument('--skip', action='store_true', help='Skip already executed files', required=False)
    parser.add_argument('-s', '--snapshot', help='Specify VM Snapshot to revert to', required=False)
    parser.add_argument('--vmx', help='Specify VM VMX', required=False)
    parser.add_argument('--nonoriben', action='store_true', help='Do not run Noriben in guest, just malware',
                        required=False)  # Do not run Noriben script
    parser.add_argument('--defense', action='store_true', help='Extract Carbon Black Defense log to host',
                        required=False)  # Particular to Carbon Black Defense. Use as example of adding your own files

    args = parser.parse_args()

    if not args.file and not args.dir:
        print('[!] A filename or directory name are required')
        sys.exit(1)
    
    if args.recursive and not args.dir:
        print('[!] Directory Recursive option specified, but not a directory')
        sys.exit(1)
    
    if not file_exists(VMRUN):
        print('[!] Path to vmrun does not exist: {}'.format(VMRUN))
        sys.exit(1)

    if args.debug:
        debug = True

    try:
        if args.magic and file_exists(args.magic):
            magicHandle = magic.Magic(magic_file=args.magic)
        else:
            magicHandle = magic.Magic()
    except magic.MagicException as err:
        dontrun = True
        if err.message == b'could not find any magic files!':
            print('[!] Windows Error: magic files not in path. See Dependencies on:',
                  'https://github.com/ahupp/python-magic')
            print('[!] You may need to manually specify magic file location using --magic')
        print('[!] Error in running magic against file: {}'.format(err))
        if args.dir:
            print('[!] Directory mode will not function without a magic database. Exiting')
            sys.exit(1)

    if args.dontrun:
        dontrun = True

    if args.snapshot:
        VM_SNAPSHOT = args.snapshot

    if args.vmx:
        if file_exists(os.path.expanduser(args.vmx)):
            VMX = os.path.expanduser(args.vmx)

    if args.timeout:
        timeoutSeconds = args.timeout

    if not args.dir and args.file and file_exists(args.file):
        magicResult = getMagic(magicHandle, args.file)

        if magicResult and (not magicResult.startswith('PE32') or 'DLL' in magicResult):
            if 'DOS batch' not in magicResult:
                dontrun = True
                print('[*] Disabling automatic running due to magic signature: {}'.format(magicResult))
        run_file(args, magicResult, args.file)

    if args.dir:  # and file_exists(args.dir):
        files = list()
        # sys.stdout = io.TextIOWrapper(sys.stdout.detach(), sys.stdout.encoding, 'replace')
        for result in glob.iglob(args.dir):
            for (root, subdirs, filenames) in os.walk(result):
                for fname in filenames:
                    files.append(os.path.join(root, fname))

                if not args.recursive:
                    break

        for filename in files:
            # This is HACKY. MUST FIX SOON
            if args.skip and file_exists(filename + '_NoribenReport.zip'):
                print('[!] Report already run for file: {}'.format(filename))
                continue
            
            # Front load magic processing to avoid unnecessary calls to run_file
            magicResult = getMagic(magicHandle, filename)
            if magicResult and magicResult.startswith('PE32') and 'DLL' not in magicResult:
                if debug:
                    print('{}: {}'.format(filename, magicResult))
                execTime = time.time()
                run_file(args, magicResult, filename)
                execTimeDiff = time.time() - execTime
                print('[*] Completed. Execution Time: {}'.format(execTimeDiff))

if __name__ == '__main__':
    main()
