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
timeout_seconds = 300
VMRUN = os.path.expanduser(r"/Applications/VMware\ Fusion.app/Contents/Library/vmrun")
VMX = os.path.expanduser(r"~/VMs/Win7_VICTIM.vmwarevm/Win7_VICTIM.vmx")
VM_SNAPSHOT = "Ransomware_3.0.0.1208"
VM_USER = "Admin"
VM_PASS = "password"
noribenPath = "C:\\\\Users\\\\{}\\\\Desktop".format(VM_USER)
noribenScript = '{}\\\\Noriben.py'.format(noribenPath)
procmonConfigPath = '{}\\\\ProcmonConfiguration.pmc'.format(noribenPath)
LOG_PATH = "C:\\\\Noriben_Logs"
ZIP_PATH = "C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\zip.exe"
python_path = "C:\\\\Python27\\\\python.exe"
malware_base = "C:\\\\Malware\\\\malware_"
host_noriben = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'Noriben.py')


def file_exists(fname):
    return os.path.exists(fname) and os.access(fname, os.F_OK)


def main():
    global debug
    global timeout_seconds
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
    parser.add_argument('--defense', action='store_true', required=False)  # Particular to Carbon Black Defense

    args = parser.parse_args()

    if args.debug:
        debug = True

    dontrun = False
    if args.dontrun:
        dontrun = True

    if args.dontrunnothing:
        dontrunnothing = True
    else:
        dontrunnothing = False

    malware_file = args.file

    if args.timeout:
        timeout_seconds = args.timeout

    magic_result = magic.from_file(malware_file)
    if not magic_result.startswith('PE32') or 'DLL' in magic_result:
        if 'DOS batch' not in magic_result:
            dontrun = True
            print('[*] Disabling automatic running due to magic signature: {}'.format(magic_result))

    filename_base = os.path.split(malware_file)[-1].split('.')[0]
    if dontrun:
        filename = '{}{}'.format(malware_base, filename_base)
    elif 'DOS batch' in magic_result:
        filename = '{}{}.bat'.format(malware_base, filename_base)
    else:
        filename = '{}{}.exe'.format(malware_base, filename_base)
    filename_path = os.path.dirname(malware_file)

    cmd_base = '{} -T ws -gu {} -gp {} runProgramInGuest {} -activeWindow -interactive'.format(VMRUN, VM_USER, VM_PASS,
                                                                                               VMX)

    if not args.norevert:
        cmd = "{} -T ws revertToSnapshot \"{}\" {}".format(VMRUN, VMX, VM_SNAPSHOT)
        if debug: print(cmd)
        stdout = subprocess.Popen(cmd, shell=True)
        stdout.wait()

    cmd = '{} -T ws start "{}"'.format(VMRUN, VMX)
    if debug: print(cmd)
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()

    if args.net:
        # Experimental. Doesn't quite work right.
        cmd = '{} -gu {} -gp {} writeVariable ethernet0.startConnected'.format(VMRUN, VM_USER, VM_PASS)
        if debug: print(cmd)
        stdout = subprocess.Popen(cmd, shell=True)
        stdout.wait()
        quit()

    cmd = '{} -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX, malware_file,
                                                                           filename)
    if debug: print(cmd)
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()

    if dontrunnothing:
        quit()

    time.sleep(5)

    if args.raw:
        cmd = '{} C:\\\\windows\\\\system32\\\\cmd.exe "/c del {}"'.format(cmd_base, procmonConfigPath)
        if debug: print(cmd)
        stdout = subprocess.Popen(cmd, shell=True)
        stdout.wait()

    if args.update and file_exists(host_noriben):
        cmd = '{} -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                               host_noriben,
                                                                               noribenScript)
        if debug: print(cmd)
        stdout = subprocess.Popen(cmd, shell=True)
        stdout.wait()

    # Run Noriben
    cmd = '{} {} "{}" -t {}'.format(cmd_base, python_path, noribenScript, timeout_seconds)

    if not dontrun:
        cmd = '{} --cmd {} --output "{}"'.format(cmd, filename, LOG_PATH)

    if debug:
        cmd = '{} -d'.format(cmd)

    if debug: print(cmd)
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()

    if not dontrun:
        cmd = '{} "{}" -j C:\\\\NoribenReports.zip {}\\\\*.*'.format(cmd_base, ZIP_PATH, LOG_PATH)
        if debug: print(cmd)
        stdout = subprocess.Popen(cmd, shell=True)
        stdout.wait()

        if args.defense:
            # Get Carbon Black Defense confer.log. This is an example if you want to include additional files.
            cmd = '{} "{}" -j C:\\\\NoribenReports.zip "C:\\\\Program Files\\\\Confer\\\\confer.log"'.format(cmd_base,
                                                                                                             ZIP_PATH,
                                                                                                             LOG_PATH)
            if debug: print(cmd)
            stdout = subprocess.Popen(cmd, shell=True)
            stdout.wait()

        if not args.nolog:
            report_path = '{}/NoribenReports_{}.zip'.format(filename_path, filename_base)
            cmd = '{} -gu {} -gp {} copyFileFromGuestToHost {} C:\\\\NoribenReports.zip {}'.format(VMRUN, VM_USER,
                                                                                                   VM_PASS, VMX,
                                                                                                   report_path)
            if debug: print(cmd)
            stdout = subprocess.Popen(cmd, shell=True)
            stdout.wait()


if __name__ == '__main__':
    main()
