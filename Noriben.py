# Noriben Malware Analysis Sandbox
# Version 1.0 - 10 Apr 13 - @bbaskin - brian@thebaskins.com
#                           Gracious edits, revisions, and corrections by Daniel Raygoza
# Version 1.1 - 21 Apr 13 - Much improved filters and filter parsing
# Version 1.1a - 1 May 13 - Revamped regular expression support. Added Python 3.x forward compatibility
# Version 1.2 - 28 May 13 - Now reads CSV files line-by-line to handle large files, keep unsuccessful
#                           registry deletes, compartmentalize sections, creates CSV timeline, can reparse PMLs,
#                           can specify alternative PMC filters, changed command line arguments, added global blacklist
# Version 1.3 - 13 Sep 13 - Option to compress file paths in output, option to use a timeout instead of Ctrl-C to end
#                           monitoring, only writes RegSetValue entries if Length > 0
# Version 1.4 - 16 Sep 13 - Fixed string compression on file rename, added ability to Ctrl-C from a timeout, added
#                           specifying malware file from command line, string compression now supports ()'s in
#                           environment variable name (for 64-bit systems).
#
# Directions:
# Just copy Noriben.py to a Windows-based VM alongside the Sysinternals Procmon.exe
#
# Run Noriben.py, then run your malware.
# When the malware has completed its processing, stop Noriben and you'll have a clean text report and timeline
#
# TODO:
# * extract data directly from registry? (may require python-registry - http://www.williballenthin.com/registry/)
# * scan for mutexes, preferably in a way that doesn't require wmi/pywin32

from __future__ import print_function
import codecs
import fileinput
import hashlib
import os
import re
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime
from string import whitespace
from time import sleep
from traceback import format_exc

__VERSION__ = "1.4"
enable_timeline = True
procmon = "procmon.exe"  # Change this if you have a renamed procmon.exe
compress_paths = False  # If true, paths are compressed to their base environment variable, e.g. %WINDIR%
timeout_seconds = 0  # Set to 0 to manually end monitoring with Ctrl-C
path_compress_list = {}

# Rules for creating rules:
# 1. Every rule string must begin with the `r` for regular expressions to work.
# 1.a. This signifies a "raw" string.
# 2. No backslashes at the end of a filter. Either:
# 2.a. truncate the backslash, or
# 2.b. use "\*" to signify "zero or more slashes".
# 3. To find a list of available "%%" variables, type `set` from a command prompt

# These entries are applied to all blacklists
global_blacklist = [r"VMwareUser.exe",
                    r"CaptureBAT.exe",
                    r"SearchIndexer.exe"]

cmd_blacklist = [r"%SystemRoot%\system32\wbem\wmiprvse.exe",
                 r"%SystemRoot%\system32\wscntfy.exe",
                 r"procmon.exe",
                 r"wuauclt.exe",
                 r"jqs.exe",
                 r"TCPView.exe"] + global_blacklist

file_blacklist = [r"procmon.exe",
                  r"Desired Access: Execute/Traverse",
                  r"Desired Access: Synchronize",
                  r"Desired Access: Generic Read/Execute",
                  r"Desired Access: Read EA",
                  r"Desired Access: Read Data/List",
                  r"Desired Access: Generic Read, ",
                  r"Desired Access: Read Attributes",
                  r"wuauclt.exe",
                  r"wmiprvse.exe",
                  r"%AllUsersProfile%\Application Data\Microsoft\OFFICE\DATA",
                  r"%AppData%\Microsoft\Proof\*",
                  r"%AppData%\Microsoft\Templates\*",
                  r"%ProgramFiles%\Capture\*",
                  r"%SystemDrive%\Python",
                  r"%SystemRoot%\assembly",
                  r"%SystemRoot%\Prefetch\*",
                  r"%SystemRoot%\system32\wbem\Logs\*",
                  r"%UserProfile%\Recent\*",
                  r"%UserProfile%\Local Settings\History\History.IE5\*"] + global_blacklist

reg_blacklist = [r"CaptureProcessMonitor",
                 r"procmon.exe",
                 r"verclsid.exe",
                 r"wuauclt.exe",
                 r"wmiprvse.exe",
                 r"wscntfy.exe",
                 r"HKCR\AllFilesystemObjects\shell",
                 r"HKCU\Printers\DevModePerUser",
                 r"HKCU\SessionInformation\ProgramCount",
                 r"HKCU\Software\Microsoft\Office",
                 r"HKCU\Software\Microsoft\Shared Tools",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Applets",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy",
                 r"HKCU\Software\Microsoft\Windows\Shell",
                 r"HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache",
                 r"HKLM\Software\Microsoft\WBEM",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
                 r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\*",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions",
                 r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Prefetcher\*",
                 r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\*",
                 r"HKLM\System\CurrentControlSet\Control\DeviceClasses",
                 r"HKLM\System\CurrentControlSet\Control\MediaProperties",
                 r"HKLM\System\CurrentControlSet\Enum\*",
                 r"HKLM\System\CurrentControlSet\Services\CaptureRegistryMonitor",
                 r"HKLM\System\CurrentControlSet\Services\Eventlog\*",
                 r"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters",
                 r"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters",
                 r"LEGACY_CAPTUREREGISTRYMONITOR",
                 r"Software\Microsoft\Multimedia\Audio$",
                 r"Software\Microsoft\Multimedia\Audio Compression Manager",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder",
                 r"Software\Microsoft\Windows\ShellNoRoam\Bags",
                 r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.doc",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                 r"UserAssist\{5E6AB780-7743-11CF-A12B-00AA004AE837}",
                 r"UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}",
                 r"UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"] + global_blacklist

net_blacklist = [r"hasplms.exe"] + global_blacklist  # Hasp dongle beacons
                 #r"192.168.2.", # Particular to my network
                 #r"Verizon_router.home"]  # Particular to my network


def compress_vars_init():
##########################################################
# Initialize a dictionary with the local system's
# environment variables.
##########################################################
    envvar_list = [r'%AllUsersProfile%',
                   r'%LocalAppData%',
                   r'%AppData%',
                   r'%CommonProgramFiles%',
                   r'%ProgramData%',
                   r'%ProgramFiles%',
                   r'%ProgramFiles(x86)%',
                   r'%Public%',
                   r'%Temp%',
                   r'%UserProfile%',
                   r'%WinDir%']

    global path_compress_list
    path_compress_list = {}
    print("[*] Enabling Windows string compression.")
    for env in envvar_list:
        resolved = os.path.expandvars(env).encode('unicode_escape')
        resolved = resolved.replace('(', '\\(').replace(')', '\\)')
        if not resolved == env:
            path_compress_list[resolved] = env


def compress_var(string):
##########################################################
# Compress a given string to include its environment variable
##########################################################
    if not len(path_compress_list):
        compress_vars_init()  # Maybe you imported Noriben and forgot to call compress_vars_init? No biggie.
    d = path_compress_list  # To get line length under 80 bytes :)
    search = '(?i)' + '|'.join('(%s)' % key for key in d.iterkeys())
    regex = re.compile(search)
    lookup = dict((index + 1, value) for index, value in enumerate(d.itervalues()))
    return regex.sub(lambda match: match.expand(lookup[match.lastindex]), string)


def open_file_with_assoc(fname):
##########################################################
# Opens the specified file with its associated application
##########################################################
    if os.name == 'mac':
        subprocess.call(('open', fname))
    elif os.name == 'nt':
        os.startfile(fname)
    elif os.name == 'posix':
        subprocess.call(('open', fname))


def file_exists(fname):
##########################################################
# Determine if a file exists
##########################################################
    return os.path.exists(fname) and os.access(fname, os.X_OK)


def check_procmon():
##########################################################
# Finds the local path to Procmon
##########################################################
    global procmon

    if file_exists(procmon):
        return procmon
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            if file_exists(os.path.join(path.strip('"'), procmon)):
                return os.path.join(path, procmon)


def md5_file(fname):
##########################################################
# Given a filename, returns the hex MD5 value
##########################################################
    return hashlib.md5(codecs.open(fname, 'rb').read()).hexdigest()


def get_session_name():
##########################################################
# Returns current date and time stamp for file name
##########################################################
    return datetime.now().strftime("%d_%b_%y__%H_%M_%S_%f")


def protocol_replace(text):
##########################################################
# Replaces text name resolutions from domain names
##########################################################
    replacements = [(':https', ':443'),
                    (':http', ':80'),
                    (':domain', ':53')]
    for find, replace in replacements:
        text = text.replace(find, replace)
    return text


def blacklist_scan(blacklist, data):
##########################################################
# Given a blacklist and data string,
# see if data is in blacklist
##########################################################
    for event in data:
        for bad in blacklist:
            bad = os.path.expandvars(bad).replace("\\", "\\\\")
            try:
                if re.search(bad, event, flags=re.IGNORECASE):
                    return True
            except re.error:
                print("Error found while processing filters.\r\nFilter:\t%s\r\nEvent:\t%s" % (bad, event))
                sys.stderr.write(format_exc())
                return False
    return False


def process_PML_to_CSV(procmonexe, pml_file, pmc_file, csv_file, use_pmc):
##########################################################
# Uses Procmon to convert the PML to a CSV file
##########################################################
    print("[*] Converting session to CSV: %s" % csv_file)
    cmdline = "%s /OpenLog %s /saveas %s" % (procmonexe, pml_file, csv_file)
    if use_pmc:
        cmdline += " /LoadConfig %s" % pmc_file
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()


def launch_procmon_capture(procmonexe, pml_file, use_pmc, pmc_file):
##########################################################
# Launch Procmon to begin capturing data
##########################################################
    cmdline = "%s /BackingFile %s /Quiet /Minimized" % (procmonexe, pml_file)
    if use_pmc:
        cmdline += " /LoadConfig %s" % pmc_file
    subprocess.Popen(cmdline)
    sleep(3)


def terminate_procmon(procmonexe):
##########################################################
# Terminate Procmon cleanly
##########################################################
    cmdline = "%s /Terminate" % procmonexe
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()


def parse_csv(csv_file, report, timeline, debug):
##########################################################
# Meat of the program:
# Given the location of CSV and TXT files,
# parse the CSV for notable items
##########################################################
    process_output = list()
    file_output = list()
    reg_output = list()
    net_output = list()
    error_output = list()
    remote_servers = list()

    # Use fileinput.input() now to read data line-by-line
    for original_line in fileinput.input(csv_file, openhook=fileinput.hook_encoded("iso-8859-1")):
        server = ''
        if original_line[0] != '"':  # Ignore lines that begin with Tab. Sysinternals breaks CSV with new processes
            continue
        line = original_line.strip(whitespace + '"')
        field = line.strip().split('","')
        try:
            if field[3] in ["Process Create"] and field[5] == "SUCCESS":
                cmdline = field[6].split("Command line: ")[1]
                if not blacklist_scan(cmd_blacklist, field):
                    if compress_paths:
                        cmdline = compress_var(cmdline)
                    child_pid = field[6].split("PID: ")[1].split(",")[0]
                    outputtext = "[CreateProcess] %s:%s > \"%s\"\t[Child PID: %s]" % (
                        field[1], field[2], cmdline.replace('"', ''), child_pid)
                    timelinetext = "%s,Process,CreateProcess,%s,%s,%s,%s" % (field[0].split()[0].split(".")[0],
                                                                             field[1], field[2],
                                                                             cmdline.replace('"', ''), child_pid)
                    process_output.append(outputtext)
                    timeline.append(timelinetext)

            elif field[3] == "CreateFile" and field[5] == "SUCCESS":
                if not blacklist_scan(file_blacklist, field):
                    path = field[4]
                    if compress_paths:
                        path = compress_var(path)
                    if os.path.isdir(path):
                        outputtext = "[CreateFolder] %s:%s > %s" % (field[1], field[2], field[4])
                        timelinetext = "%s,File,CreateFolder,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                          field[2], path)
                        file_output.append(outputtext)
                        timeline.append(timelinetext)
                    else:
                        try:
                            md5 = md5_file(path)
                            outputtext = "[CreateFile] %s:%s > %s\t[MD5: %s]" % (field[1], field[2], field[4], md5)
                            timelinetext = "%s,File,CreateFile,%s,%s,%s,%s" % (field[0].split()[0].split(".")[0],
                                                                               field[1], field[2], path, md5)
                            file_output.append(outputtext)
                            timeline.append(timelinetext)
                        except (IndexError, IOError):
                            outputtext = "[CreateFile] %s:%s > %s\t[File no longer exists]" % (field[1], field[2], path)
                            timelinetext = "%s,File,CreateFile,%s,%s,%s,N/A" % (field[0].split()[0].split(".")[0],
                                                                                field[1], field[2], path)
                            file_output.append(outputtext)
                            timeline.append(timelinetext)

            elif field[3] == "SetDispositionInformationFile" and field[5] == "SUCCESS":
                if not blacklist_scan(file_blacklist, field):
                    path = field[4]
                    outputtext = "[DeleteFile] %s:%s > %s" % (field[1], field[2], field[4])
                    timelinetext = "%s,File,DeleteFile,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                    field[2], path)
                    file_output.append(outputtext)
                    timeline.append(timelinetext)

            elif field[3] == "SetRenameInformationFile":
                if not blacklist_scan(file_blacklist, field):
                    from_file = field[4]
                    to_file = field[6].split("FileName: ")[1].strip('"')
                    if compress_paths:
                        from_file = compress_var(from_file)
                        to_file = compress_var(to_file)
                    outputtext = "[RenameFile] %s:%s > %s => %s" % (field[1], field[2], from_file, to_file)
                    timelinetext = "%s,File,RenameFile,%s,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                       field[2], from_file, to_file)
                    file_output.append(outputtext)
                    timeline.append(timelinetext)

            elif field[3] == "RegCreateKey" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    outputtext = "[RegCreateKey] %s:%s > %s" % (field[1], field[2], field[4])
                    if not outputtext in reg_output:  # Ignore multiple CreateKeys. Only log the first.
                        timelinetext = "%s,Registry,RegCreateKey,%s,%s,%s" % (field[0].split()[0].split(".")[0],
                                                                              field[1], field[2], field[4])
                        reg_output.append(outputtext)
                        timeline.append(timelinetext)

            elif field[3] == "RegSetValue" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    reg_length = field[6].split("Length:")[1].split(",")[0].strip(whitespace + '"')
                    if int(reg_length):
                        data_field = field[6].split("Data:")[1].strip(whitespace + '"')
                        if len(data_field.split(" ")) == 16:
                            data_field += " ..."
                        outputtext = '[RegSetValue] %s:%s > %s  =  %s' % (field[1], field[2], field[4], data_field)
                        timelinetext = "%s,Registry,RegSetValue,%s,%s,%s,%s" % (field[0].split()[0].split(".")[0],
                                                                                field[1], field[2], field[4],
                                                                                data_field)
                        reg_output.append(outputtext)
                        timeline.append(timelinetext)

            elif field[3] == "RegDeleteValue":  # and field[5] == "SUCCESS":
                # SUCCESS is commented out to allows all attempted deletions, whether or not the value exists
                if not blacklist_scan(reg_blacklist, field):
                    outputtext = '[RegDeleteValue] %s:%s > %s' % (field[1], field[2], field[4])
                    timelinetext = "%s,Registry,RegDeleteValue,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                            field[2], field[4])
                    reg_output.append(outputtext)
                    timeline.append(timelinetext)

            elif field[3] == "RegDeleteKey":  # and field[5] == "SUCCESS":
                # SUCCESS is commented out to allows all attempted deletions, whether or not the value exists
                if not blacklist_scan(reg_blacklist, field):
                    outputtext = '[RegDeleteKey] %s:%s > %s' % (field[1], field[2], field[4])
                    timelinetext = "%s,Registry,RegDeleteKey,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                          field[2], field[4])
                    reg_output.append(outputtext)
                    timeline.append(timelinetext)

            elif field[3] == "UDP Send" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    # TODO: work on this later, once I can verify it better.
                    #if field[6] == "Length: 20":
                    #    output_line = "[DNS Query] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
                    #else:
                    outputtext = "[UDP] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
                    if not outputtext in net_output:
                        timelinetext = "%s,Network,UDP Send,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                         field[2], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(timelinetext)

            elif field[3] == "UDP Receive" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    outputtext = "[UDP] %s > %s:%s" % (protocol_replace(server), field[1], field[2])
                    if not outputtext in net_output:
                        timelinetext = "%s,Network,UDP Receive,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                         field[2])
                        net_output.append(outputtext)
                        timeline.append(timelinetext)

            elif field[3] == "TCP Send" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    outputtext = "[TCP] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
                    if not outputtext in net_output:
                        timelinetext = "%s,Network,TCP Send,%s,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                         field[2], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(timelinetext)

            elif field[3] == "TCP Receive" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    outputtext = "[TCP] %s > %s:%s" % (protocol_replace(server), field[1], field[2])
                    if not outputtext in net_output:
                        timelinetext = "%s,Network,TCP Receive,%s,%s" % (field[0].split()[0].split(".")[0], field[1],
                                                                         field[2])
                        net_output.append(outputtext)
                        timeline.append(timelinetext)

        except IndexError:
            if debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            error_output.append(original_line.strip())

        # Enumerate unique remote hosts into their own section
        if server:
            server = server.split(":")[0]
            if not server in remote_servers and server != "localhost":
                remote_servers.append(server)
    #} End of file input processing

    report.append('Processes Created:')
    report.append('==================')
    for event in process_output:
        report.append(event)

    report.append('')
    report.append('File Activity:')
    report.append('==================')
    for event in file_output:
        report.append(event)

    report.append('')
    report.append('Registry Activity:')
    report.append('==================')
    for event in reg_output:
        report.append(event)

    report.append('')
    report.append('Network Traffic:')
    report.append('==================')
    for event in net_output:
        report.append(event)

    report.append('')
    report.append('Unique Hosts:')
    report.append('==================')
    for server in sorted(remote_servers):
        report.append(protocol_replace(server).strip())

    if error_output:
        report.append("\r\n\r\n\r\n\r\n\r\n\r\nERRORS DETECTED")
        report.append("The following items could not be parsed correctly:")
        for error in error_output:
            report.append(error)
# End of parse_csv()


def main():
##########################################################
# Main routine, parses arguments and calls other routines
##########################################################
    global compress_paths
    global timeout_seconds

    print("--===[ Noriben v%s ]===--" % __VERSION__)
    print("--===[   @bbaskin   ]===--\r\n")

    parser = ArgumentParser()
    parser.add_argument('-c', '--csv', help='Re-analyze an existing Noriben CSV file [input file]', required=False)
    parser.add_argument('-p', '--pml', help='Re-analyze an existing Noriben PML file [input file]', required=False)
    parser.add_argument('-f', '--filter', help='Specify alternate Procmon Filter PMC [input file]', required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('--compress', dest='compress_paths', default=False, action='store_true',
                        help='Compress file paths to their environment variables. Default: %s' % compress_paths,
                        required=False)
    parser.add_argument('--malware', help='Malware command line to execute (in quotes)', required=False)
    parser.add_argument('-d', dest='debug', action='store_true', help='Enable debug tracebacks', required=False)
    args = parser.parse_args()
    report = list()
    timeline = list()

    if args.compress_paths:
        compress_paths = True

    if compress_paths:
        compress_vars_init()

    # First check for a valid filter file
    if args.filter:
        if file_exists(args.filter):
            pmc_file = args.filter
        else:
            pmc_file = 'ProcmonConfiguration.PMC'
    else:
        pmc_file = 'ProcmonConfiguration.PMC'

    if not file_exists(pmc_file):
        use_pmc = False
        print("[!] Filter file %s not found. Continuing without filters." % pmc_file)
    else:
        use_pmc = True
        print("[*] Using filter file: %s" % pmc_file)

    # Find a valid procmon executable.
    procmonexe = check_procmon()
    if not procmonexe:
        print("[!] Unable to find Procmon (%s) in path." % procmon)
        sys.exit(1)

    # Check if user-specified to rescan a PML
    if args.pml:
        if file_exists(args.pml):
            # Reparse an existing PML
            csv_file = os.path.splitext(args.pml)[0] + '.csv'
            txt_file = os.path.splitext(args.pml)[0] + '.txt'
            timeline_file = os.path.splitext(args.pml)[0] + '_timeline.csv'

            process_PML_to_CSV(procmonexe, args.pml, pmc_file, csv_file, use_pmc)
            if not file_exists(csv_file):
                print("[!] Error detected. Could not create CSV file: %s" % csv_file)
                sys.exit()

            parse_csv(csv_file, report, timeline, args.debug)

            print("[*] Saving report to: %s" % txt_file)
            codecs.open(txt_file, 'w', "utf-8").write('\r\n'.join(report))

            print("[*] Saving timeline to: %s" % timeline_file)
            codecs.open(timeline_file, 'w', "utf-8").write('\r\n'.join(timeline))

            open_file_with_assoc(txt_file)
            sys.exit()
        else:
            parser.print_usage()
            sys.exit(1)

    # Check if user-specified to rescan a CSV
    if args.csv:
        if file_exists(args.csv):
            # Reparse an existing CSV
            txt_file = os.path.splitext(args.csv)[0] + '.txt'
            timeline_file = os.path.splitext(args.csv)[0] + '_timeline.csv'
            parse_csv(args.csv, report, timeline, args.debug)

            print("[*] Saving report to: %s" % txt_file)
            codecs.open(txt_file, 'w', "utf-8").write('\r\n'.join(report))

            print("[*] Saving timeline to: %s" % timeline_file)
            codecs.open(timeline_file, 'w', "utf-8").write('\r\n'.join(timeline))

            open_file_with_assoc(txt_file)
            sys.exit()
        else:
            parser.print_usage()
            sys.exit(1)

    if args.timeout:
        timeout_seconds = args.timeout

    if args.malware:
        malware_cmdline = args.malware
    else:
        malware_cmdline = ''

    # Start main data collection and processing
    print("[*] Using procmon EXE: %s" % procmonexe)
    session_id = get_session_name()
    pml_file = "Noriben_%s.pml" % session_id
    csv_file = "Noriben_%s.csv" % session_id
    txt_file = "Noriben_%s.txt" % session_id
    timeline_file = "Noriben_%s_timeline.csv" % session_id
    print("[*] Procmon session saved to: %s" % pml_file)

    print("[*] Launching Procmon ...")
    launch_procmon_capture(procmonexe, pml_file, use_pmc, pmc_file)

    if malware_cmdline:
        print("[*] Launching malware: %s" % malware_cmdline)
        subprocess.Popen(malware_cmdline)
    else:
        print("[*] Procmon is running. Run your malware now.")

    if timeout_seconds:
        print("[*] Running for %d seconds. Press Ctrl-C to stop logging early." % timeout_seconds)
        # Print a small progress indicator, for those REALLY long sleeps.
        try:
            for i in range(timeout_seconds):
                progress = (100 / timeout_seconds) * i
                sys.stdout.write('\r%d%% complete' % progress)
                sys.stdout.flush()
                sleep(1)
        except KeyboardInterrupt:
            pass

    else:
        print("[*] When runtime is complete, press CTRL+C to stop logging.")
        try:
            while True:
                sleep(10)
        except KeyboardInterrupt:
            pass

    print("\n[*] Termination of Procmon commencing... please wait")
    terminate_procmon(procmonexe)

    print("[*] Procmon terminated")
    if not file_exists(pml_file):
        print("[!] Error creating PML file!")
        sys.exit(1)

    # PML created, now convert it to a CSV for parsing
    process_PML_to_CSV(procmonexe, pml_file, pmc_file, csv_file, use_pmc)
    if not file_exists(csv_file):
        print("[!] Error detected. Could not create CSV file: %s" % csv_file)
        sys.exit()

    # Process CSV file, results in "report" and "timeline" output lists
    parse_csv(csv_file, report, timeline, args.debug)
    print("[*] Saving report to: %s" % txt_file)
    codecs.open(txt_file, 'w', "utf-8").write('\r\n'.join(report))

    print("[*] Saving timeline to: %s" % timeline_file)
    codecs.open(timeline_file, 'w', "utf-8").write('\r\n'.join(timeline))

    open_file_with_assoc(txt_file)
    # End of main()

if __name__ == "__main__":
    main()
