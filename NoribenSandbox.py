# Noriben Sandbox Automation Script
# V 1.0 - 3 Apr 17
# V 1.1 - 5 Jun 17
# V 1.1.1 - 8 Jan 18
# V 1.2 - 14 Jun 18
# V 1.2.1 - 12 Sep 18 - Bug fix to allow for snapshots with spaces in them.
#
# Responsible for:
# * Copying malware into a known VM
# * Running malware sample
# * Copying off results
#
# Ensure you set the environment variables below to match your system. I've left defaults to help.
# This is definitely a work in progress. However, efforts made to make it clear per PyCharm code inspection.
#
# @todo add config settings to NoribenSandboxConfig

import argparse
import io
import glob
import magic  # pip python-magic and libmagic
import os
import subprocess
import sys
import time

vmrun_os = {'windows': os.path.expanduser(r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'),
            'mac': os.path.expanduser(r'/Applications/VMware Fusion.app/Contents/Library/vmrun')}
debug = False
timeout_seconds = 300
VMX = r'E:\VMs\Windows.vmwarevm\Windows.vmx'
# VMX = os.path.expanduser(r'~/VMs/Windows.vmwarevm/Windows.vmx')
VMRUN = vmrun_os['windows']
VM_SNAPSHOT = 'YourVMSnapshotNameHere'
VM_USER = 'Admin'
VM_PASS = 'password'
noriben_path = 'C:\\Users\\{}\\Desktop'.format(VM_USER)
guest_noriben_path = '{}\\Noriben.py'.format(noriben_path)
procmon_config_path = '{}\\ProcmonConfiguration.pmc'.format(noriben_path)
report_path_structure = '{}/{}_NoribenReport.zip'  # (host_malware_path, host_malware_name_base)
host_screenshot_path_structure = '{}/{}.png'  # (host_malware_path, host_malware_name_base)
guest_log_path = 'C:\\Noriben_Logs'
guest_zip_path = 'C:\\Program Files\\VMware\\VMware Tools\\zip.exe'
guest_temp_zip = 'C:\\NoribenReports.zip'
guest_python_path = 'C:\\Python27\\python.exe'
host_noriben_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'Noriben.py')
guest_malware_path = 'C:\\Malware\\malware_'
error_tolerance = 5
dontrun = False

noriben_errors = {1: 'PML file was not found',
                 2: 'Unable to find procmon.exe',
                 3: 'Unable to create output directory',
                 4: 'Windows is refusing execution based upon permissions',
                 5: 'Could not create CSV',
                 6: 'Could not find malware file',
                 7: 'Error creatign CSV',
                 8: 'Error creating PML',
                 9: 'Unknown error',
                 10: 'Invalid arguments given'}

error_count = 0


def get_error(code):
    if code in noriben_errors:
        return noriben_errors[code]
    return 'Unexpected Error'


def file_exists(fname):
    return os.path.exists(fname) and os.access(fname, os.F_OK)


def execute(cmd):
    if debug:
        print(cmd)
    time.sleep(2)  # Extra sleep buffer as vmrun sometimes tripped over itself
    stdout = subprocess.Popen(cmd, shell=True)
    stdout.wait()
    return stdout.returncode


def run_file(args, magic_result, malware_file):
    global dontrun
    global error_count

    host_malware_name_base = os.path.split(malware_file)[-1].split('.')[0]
    if dontrun:
        filename = '{}{}'.format(guest_malware_path, host_malware_name_base)
    elif 'DOS batch' in magic_result:
        filename = '{}{}.bat'.format(guest_malware_path, host_malware_name_base)
    else:
        filename = '{}{}.exe'.format(guest_malware_path, host_malware_name_base)
    host_malware_path = os.path.dirname(malware_file)
    if host_malware_path == '':
        host_malware_path = '.'

    print('[*] Processing: {}'.format(malware_file))

    if not args.screenshot:
        active = '-activeWindow'
    else:
        active = ''
    cmd_base = '"{}" -T ws -gu {} -gp {} runProgramInGuest "{}" {} -interactive'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                        active)
    if not args.norevert:
        cmd = '"{}" -T ws revertToSnapshot "{}" "{}"'.format(VMRUN, VMX, VM_SNAPSHOT)
        return_code = execute(cmd)
        if return_code:
            print('[!] Error: Possible unknown snapshot: {}'.format(VM_SNAPSHOT))
            sys.exit(return_code)

    cmd = '"{}" -T ws start "{}"'.format(VMRUN, VMX)
    return_code = execute(cmd)
    if return_code:
        print('[!] Error trying to start VM. Error {}: {}'.format(hex(return_code), get_error(return_code)))
        error_count += 1
        return return_code

    cmd = '"{}" -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX, malware_file,
                                                                             filename)
    return_code = execute(cmd)
    if return_code:
        print('[!] Error trying to copy file to guest. Error {}: {}'.format(hex(return_code), get_error(return_code)))
        error_count += 1
        return return_code

    if args.update:
        if file_exists(host_noriben_path):
            cmd = '"{}" -gu {} -gp {} copyFileFromHostToGuest "{}" "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                     host_noriben_path,
                                                                                     guest_noriben_path)
            return_code = execute(cmd)
            if return_code:
                print('[!] Error trying to copy updated Noriben to guest. Continuing. Error {}: {}'.format(
                    hex(return_code), get_error(return_code)))

        else:
            print('[!] Noriben.py on host not found: {}'.format(host_noriben_path))
            error_count += 1
            return return_code

    if args.dontrunnothing:
        sys.exit(return_code)

    time.sleep(5)

    if args.raw:
        cmd = '{} C:\\windows\\system32\\cmd.exe "/c del {}"'.format(cmd_base, procmon_config_path)
        return_code = execute(cmd)
        if return_code:
            print('[!] Error trying to execute command in guest. Error {}: {}'.format(hex(return_code),
                                                                                      get_error(return_code)))
            error_count += 1
            return return_code

    # Run Noriben
    cmd = '{} {} "{}" -t {} --headless --output "{}" '.format(cmd_base, guest_python_path, guest_noriben_path,
                                                              timeout_seconds, guest_log_path)

    if not dontrun:
        cmd = '{} --cmd {} '.format(cmd, filename)

    if debug:
        cmd = '{} -d'.format(cmd)

    return_code = execute(cmd)
    if return_code:
        print('[!] Error in running Noriben. Error {}: {}'.format(hex(return_code), get_error(return_code)))
        error_count += 1
        return return_code

    if not dontrun:
        if args.post and file_exists(args.post):
            run_script(args, cmd_base)

        zip_failed = False
        cmd = '{} "{}" -j {} "{}\\*.*"'.format(cmd_base, guest_zip_path, guest_temp_zip, guest_log_path)
        return_code = execute(cmd)
        if return_code:
            print('[!] Error trying to zip report archive. Error {}: {}'.format(hex(return_code),
                                                                                get_error(return_code)))
            zip_failed = True

        if args.defense and not zip_failed:
            cb_defense_file = "C:\\Program Files\\Confer\\confer.log"
            # Get Carbon Black Defense log. This is an example if you want to include additional files.
            cmd = '{} "{}" -j {} "{}"'.format(cmd_base, guest_zip_path, guest_temp_zip, cb_defense_file)
            return_code = execute(cmd)
            if return_code:
                print(('[!] Error trying to add additional file to archive. Continuing. '
                       'Error {}; File: {}'.format(return_code, cb_defense_file)))

        if not args.nolog and not zip_failed:
            host_report_path = report_path_structure.format(host_malware_path, host_malware_name_base)
            cmd = '"{}" -gu {} -gp {} copyFileFromGuestToHost "{}" {} "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                                   guest_temp_zip, host_report_path)
            return_code = execute(cmd)
            if return_code:
                print('[!] Error trying to copy file from guest. Continuing. Error {}: {}'.format(hex(return_code),
                                                                                                  get_error(return_code)))

        if args.screenshot:
            host_screenshot_path = host_screenshot_path_structure.format(host_malware_path, host_malware_name_base)
            cmd = '"{}" -gu {} -gp {} captureScreen "{}" "{}"'.format(VMRUN, VM_USER, VM_PASS, VMX,
                                                                      host_screenshot_path)
            return_code = execute(cmd)
            if return_code:
                print('[!] Error trying to create screenshot. Error {}: {}'.format(hex(return_code),
                                                                                   get_error(return_code)))


def get_magic(magic_handle, filename):
    try:
        magic_result = magic_handle.from_file(filename)
    except magic.MagicException as err:
        magic_result = ''
        if err.message == b'could not find any magic files!':
            print('[!] Windows Error: magic files not in path. See Dependencies on: ',
                  'https://github.com/ahupp/python-magic')
            print('[!] You may need to manually specify magic file location using --magic')
        print('[!] Error in running magic against file: {}'.format(err))
    return magic_result


def run_script(args, cmd_base):
    source_path = ''

    # if sys.version_info[0] == '2':
    with io.open(args.post, encoding='utf-8') as hScript:
        for line in hScript:
            if debug:
                print('[*] Script: {}'.format(line.strip()))
            if line.startswith('#'):
                pass
            elif line.lower().startswith('collect'):
                try:
                    source_path = line.split('collect ')[1].strip()
                except IndexError:
                    print('[!] Ignoring bad script line: {}'.format(line.strip()))
                copy_file_to_zip(cmd_base, source_path)
            else:
                cmd = '{} "{}"'.format(cmd_base, line.strip())
                return_code = execute(cmd)
                if return_code:
                    print('[!] Error trying to run script command. Error {}: {}'.format(hex(return_code),
                                                                                        get_error(return_code)))


def copy_file_to_zip(cmd_base, filename):
    # This is a two-step process as zip.exe will not allow direct zipping of some system files.
    # Therefore, first copy file to log folder and then add to the zip.
    global error_count

    cmd = '"{}" -gu {} -gp {} fileExistsInGuest "{}" {}'.format(VMRUN, VM_USER, VM_PASS, VMX, filename)
    return_code = execute(cmd)
    if return_code:
        print('[!] File does not exist in guest. Continuing. File: {}'.format(filename))
        error_count += 1
        return return_code

    cmd = '{} C:\\windows\\system32\\xcopy.exe {} {}'.format(cmd_base, filename, guest_log_path)
    return_code = execute(cmd)
    if return_code:
        print(('[!] Error trying to copy file to log folder. Continuing. '
               'Error {}; File: {}'.format(return_code, filename)))
        error_count += 1
        return return_code

    cmd = '{} "{}" -j {} {}'.format(cmd_base, guest_zip_path, guest_temp_zip, filename)
    return_code = execute(cmd)
    if return_code:
        print(('[!] Error trying to add additional file to archive. Continuing. '
               'Error {}; File: {}'.format(return_code, filename)))
        error_count += 1
        return return_code


def main():
    global debug
    global timeout_seconds
    global VM_SNAPSHOT
    global VMRUN
    global VMX
    global dontrun
    global error_count

    error_count = 0

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
    parser.add_argument('--ignore', help='Ignore files or folders that contain this term', required=False)
    parser.add_argument('--nonoriben', action='store_true', help='Do not run Noriben in guest, just malware',
                        required=False)  # Do not run Noriben script
    parser.add_argument('--os', help='Specify Windows or Mac for that specific vmrun path', required=False)
    parser.add_argument('--config', help='Optional runtime configuration file', required=False)

    parser.add_argument('--defense', action='store_true', help='Extract Carbon Black Defense log to host',
                        required=False)  # Particular to Carbon Black Defense. Use as example of adding your own files

    args = parser.parse_args()

    if not args.file and not args.dir:
        print('[!] A filename or directory name are required. Run with --help for more options')
        sys.exit(1)

    if args.recursive and not args.dir:
        print('[!] Directory Recursive option specified, but not a directory')
        sys.exit(1)

    if args.os:
        if args.os in vmrun_os:
            try:
                VMRUN = vmrun_os[args.os.lower()]
            except KeyError:
                print('[!] Unable to find vmrun entry for value: {}'.format(args.os))
                sys.exit(1)
        else:
            print('[!] Unable to find vmrun entry for value: {}'.format(args.os))
            sys.exit(1)

    if not file_exists(VMRUN):
        print('[!] Path to vmrun does not exist: {}'.format(VMRUN))
        sys.exit(1)

    if args.debug:
        debug = True

    if not VM_PASS:
        print('[!] VM_PASS must be set. VMware requires guest accounts to have passwords for remote access.')
        sys.exit(1)

    magic_handle = None
    try:
        if args.magic and file_exists(args.magic):
            magic_handle = magic.Magic(magic_file=args.magic)
        else:
            magic_handle = magic.Magic()
    except magic.MagicException as err:
        dontrun = True
        if err.message == b'could not find any magic files!':
            print('[!] Windows Error: magic files not in path. See Dependencies on: ',
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
        timeout_seconds = args.timeout

    if not args.dir and args.file and file_exists(args.file):
        magic_result = get_magic(magic_handle, args.file)

        if magic_result and (not magic_result.startswith('PE32') or 'DLL' in magic_result):
            if 'DOS batch' not in magic_result:
                dontrun = True
                print('[*] Disabling automatic running due to magic signature: {}'.format(magic_result))
        run_file(args, magic_result, args.file)

    if args.dir:  # and file_exists(args.dir):
        files = list()
        # sys.stdout = io.TextIOWrapper(sys.stdout.detach(), sys.stdout.encoding, 'replace')
        for result in glob.iglob(args.dir):
            for (root, subdirs, filenames) in os.walk(result):
                for fname in filenames:
                    ignore = False
                    if args.ignore:
                        for item in args.ignore.split(','):
                            if item.lower() in root.lower() or item.lower() in fname.lower():
                                ignore = True
                    if not ignore:
                        files.append(os.path.join(root, fname))

                if not args.recursive:
                    break

        for filename in files:
            if error_count >= error_tolerance:
                print('[!] Too many errors encountered in this run. Exiting.')
                sys.exit(100)
            # TODO: This is HACKY. MUST FIX SOON
            if args.skip and file_exists(filename + '_NoribenReport.zip'):
                print('[!] Report already run for file: {}'.format(filename))
                continue

            # Front load magic processing to avoid unnecessary calls to run_file
            magic_result = get_magic(magic_handle, filename)
            if magic_result and magic_result.startswith('PE32') and 'DLL' not in magic_result:
                if debug:
                    print('{}: {}'.format(filename, magic_result))
                exec_time = time.time()
                run_file(args, magic_result, filename)
                exec_time_diff = time.time() - exec_time
                print('[*] Completed. Execution Time: {}'.format(exec_time_diff))


if __name__ == '__main__':
    main()
