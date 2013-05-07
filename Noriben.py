# Noriben Malware Analysis Sandbox
# Version 1.0 - 10 Apr 13 - @bbaskin
# Version 1.1 - 21 Apr 13 - Much improved filters and filter parsing.
# Version 1.1a - 1 May 13 - Revamped regular expression support. Added Python 3.x forward compatibility.
#
# Gracious edits, revisions, and corrections by Daniel Raygoza
#
# Directions:
# Just copy Noriben.py to a Windows-based VM alongside the Sysinternals Procmon.exe
# Run Noriben.py, then run your malware.
# When the malware has completed its processing, stop Noriben and you'll have a clean text report
#
# TODO:
# * parse directly from a given .PML database
# * extract data directly from registry? (requires python-registry - http://www.williballenthin.com/registry/)
# * create a GUI interface with real, actual buttons to push
# * Compartmentalize each activity section, possibly remove dupes from each?

from __future__ import print_function
import os
import subprocess
import sys
import hashlib
import re
import codecs  # Needed to open text files as UTF-8 in Python 2.7 and 3.3
from string import whitespace
from datetime import datetime
from argparse import ArgumentParser
from traceback import format_exc
from time import sleep

__VERSION__ = "1.1"

# Rules for creating rules:
# 1. Every rule string must begin with the `r` for regular expressions to work.
# 1.a. This signifies a "raw" string.
# 2. No backslashes at the end of a filter. Either:
# 2.a. truncate the backslash, or 
# 2.b. use "\*" to signify "zero or more slashes".
# 3. To find a list of available "%%" variables, type `set` from a command prompt

cmd_blacklist = [r"%SystemRoot%\system32\wbem\wmiprvse.exe",
                 r"%SystemRoot%\system32\wscntfy.exe",
                 r"procmon.exe",
                 r"wuauclt.exe",
                 r"jqs.exe",
                 r"TCPView.exe"]

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
                  r"%AppData%\Microsoft\Office",
                  r"%AppData%\Microsoft\Proof\*",
                  r"%AppData%\Microsoft\Templates\*",
                  r"%SystemDrive%\Python",
                  r"%SystemRoot%\assembly",
                  r"%SystemRoot%\Prefetch\*",
                  r"%SystemRoot%\system32\wbem\Logs\*",
                  r"%UserProfile%\Recent\*",
                  r"%UserProfile%\Local Settings\History\History.IE5\*"]

reg_blacklist = [r"procmon.exe",
                 r"wuauclt.exe",
                 r"wmiprvse.exe",
                 r"wscntfy.exe",
                 r"verclsid.exe",
                 r"HKCU\Printers\DevModePerUser",
                 r"HKCU\Software\Microsoft\Multimedia\Audio",
                 r"HKCU\Software\Microsoft\Office",
                 r"HKCU\Software\Microsoft\Shared Tools",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Applets",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy",
                 r"HKCU\Software\Microsoft\Windows\Shell",
                 r"HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache",
                 r"HKCR\AllFilesystemObjects\shell",
                 r"HKLM\Software\Microsoft\WBEM",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
                 r"HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions",
                 r"HKLM\System\CurrentControlSet\Control\DeviceClasses",
                 r"HKLM\System\CurrentControlSet\Control\MediaProperties",
                 r"HKLM\System\CurrentControlSet\Enum\*",
                 r"HKLM\System\CurrentControlSet\Services\CaptureRegistryMonitor",
                 r"HKLM\System\CurrentControlSet\Services\Tcpip\Parameters",
                 r"HKLM\System\CurrentControlSet\Services\WinSock2\Parameters",
                 r"Software\Microsoft\Multimedia\Audio Compression Manager",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder",
                 r"Software\Microsoft\Windows\ShellNoRoam\Bags",
                 r"Software\Microsoft\Windows\ShellNoRoam\BagMRU",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.doc",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
                 r"LEGACY_CAPTUREREGISTRYMONITOR"]

net_blacklist = [r"hasplms.exe"]  # Hasp dongle beacons
                 #r"192.168.2.", # Particular to my network
                 #r"Verizon_router.home"]  # Particular to my network


def open_file_with_assoc(fname):
##########################################################
# Opens the specified file with its associated application
##########################################################
    if os.name == 'mac':
        subprocess.call(('open', fname))
    elif os.name == 'nt':
        os.startfile(fname)
    elif os.name == 'posix':
        subprocess.call(('xdg-open', fname))


def check_procmon():
##########################################################
# Finds the local path to Procmon
##########################################################
    procmon = "procmon.exe"  # Change this if you have a renamed procmon.exe

    def file_there(fname):
        return os.path.exists(fname) and os.access(fname, os.X_OK)

    if file_there(procmon):
        return procmon
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            if file_there(os.path.join(path.strip('"'), procmon)):
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
#                if os.path.expandvars(bad).upper() in os.path.expandvars(event).upper():  # Old way
                if re.search(bad, event, flags=re.IGNORECASE):
                    return True
            except re.error:
                print("Error found while processing filters.\r\nFilter:\t%s\r\nEvent:\t%s" % (bad, event))
                sys.stderr.write(format_exc())
                return False
    return False


def parse_csv(txt_file, csv_file, debug):
##########################################################
# Meat of the program:
# Given the location of CSV and TXT files,
# parse the CSV for notable items
##########################################################
    print("[*] Parsing CSV to text file: %s" % txt_file)
    data = codecs.open(csv_file, 'r', "utf-8").readlines()

    output = list()
    output.append('Processes Created:')
    output.append('==================')

    for line in data:
        if line[0] != '"':  # Ignore lines that begin with Tab. Sysinternals breaks CSV with new processes
            continue
        line = line.strip(whitespace + '"')
        field = line.strip().split('","')
        try:
            if field[3] in ["Process Create"] and field[5] == "SUCCESS":
                cmdline = field[6].split("Command line: ")[1]
                if not blacklist_scan(cmd_blacklist, field):
                    child_pid = field[6].split("PID: ")[1].split(",")[0]
                    output.append("[CreateProcess] %s:%s > \"%s\"\t[Child PID: %s]" % (
                        field[1], field[2], cmdline.replace('"', ''), child_pid))
        except IndexError:
            if debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            continue

    output.append('')
    output.append('File Activity:')
    output.append('==================')

    for line in data:
        if line[0] != '"':  # Ignore lines that begin with Tab. Sysinternals breaks CSV with new processes
            continue
        line = line.strip(whitespace + '"')
        field = line.split('","')
        try:
            if field[3] == "CreateFile" and field[5] == "SUCCESS":
                if not blacklist_scan(file_blacklist, field):
                    if os.path.isdir(field[4]):
                        output.append("[New Folder] %s:%s > %s" % (field[1], field[2], field[4]))
                    else:
                        try:
                            md5 = md5_file(field[4])
                            output.append("[CreateFile] %s:%s > %s\t[MD5: %s]" % (field[1], field[2], field[4], md5))
                        except (IndexError, IOError):
                            output.append("[CreateFile] %s:%s > %s\t[File no longer exists]" %
                                          (field[1], field[2], field[4]))
            elif field[3] == "SetDispositionInformationFile" and field[5] == "SUCCESS":
                if not blacklist_scan(file_blacklist, field):
                    output.append("[DeleteFile] %s:%s > %s" % (field[1], field[2], field[4]))
            elif field[3] == "SetRenameInformationFile":
                if not blacklist_scan(file_blacklist, field):
                    to_file = field[6].split("FileName: ")[1].strip('"')
                    output.append("[RenameFile] %s:%s > %s => %s" % (field[1], field[2], field[4], to_file))
        except IndexError:
            if debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            continue

    output.append('')
    output.append('Registry Activity:')
    output.append('==================')

    for line in data:
        if line[0] != '"':  # Ignore lines that begin with Tab. Sysinternals breaks CSV with new processes
            continue
        line = line.strip(whitespace + '"')
        field = line.split('","')
        try:
            if field[3] == "RegCreateKey" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    outputtext = "[CreateKey] %s:%s > %s" % (field[1], field[2], field[4])
                    if not outputtext in output:  # Ignore multiple CreateKeys. Only log the first.
                        output.append(outputtext)
            elif field[3] == "RegSetValue" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    data_field = field[6].split("Data:")[1].strip(whitespace + '"')
                    if len(data_field.split(" ")) == 16:
                        data_field += " ..."
                    output.append('[Set Value] %s:%s > %s  =  %s' % (field[1], field[2], field[4], data_field))
            elif field[3] == "RegDeleteValue" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    output.append('[DeleteValue] %s:%s > %s' % (field[1], field[2], field[4]))
            elif field[3] == "RegDeleteKey" and field[5] == "SUCCESS":
                if not blacklist_scan(reg_blacklist, field):
                    output.append('[DeleteKey] %s:%s > %s' % (field[1], field[2], field[4]))
        except IndexError:
            if debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            continue

    output.append('')
    output.append('Network Traffic:')
    output.append('==================')
    remote_servers = list()
    #Protolol
    for line in data:
        # We do things different here, as there are so many dupes to remove
        # Now, make sure entry doesn't exist in list before writing it to output
        output_line = ''
        server = ''
        if line[0] != '"':  # Ignore lines that begin with Tab. Sysinternals breaks CSV with new processes
            continue
        line = line.strip(whitespace + '"')
        field = line.split('","')
        try:
            if field[3] == "UDP Send" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    """
                    # TODO: work on this later, once I can verify it better.
                    if field[6] == "Length: 20":
                        output_line = "[DNS Query] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
                    else:
                    """
                    output_line = "[UDP] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
            elif field[3] == "TCP Send" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    output_line = "[TCP] %s:%s > %s" % (field[1], field[2], protocol_replace(server))
            elif field[3] == "TCP Receive" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    output_line = "[TCP] %s > %s:%s" % (protocol_replace(server), field[1], field[2])
            elif field[3] == "UDP Receive" and field[5] == "SUCCESS":
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split("-> ")[1]
                    output_line = "[UDP] %s > %s:%s" % (protocol_replace(server), field[1], field[2])
        except IndexError:
            if debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            continue
        if output_line and not output_line in output:
            output.append(output_line)
        if server:
            server = server.split(":")[0]
            if not server in remote_servers and server != "localhost":
                remote_servers.append(server)

    output.append('')
    output.append('Unique Hosts:')
    output.append('==================')
    for server in sorted(remote_servers):
        output.append(protocol_replace(server).strip())

    codecs.open(txt_file, 'w', "utf-8").write('\r\n'.join(output))
    open_file_with_assoc(txt_file)


def main():
##########################################################
# Main routine, parses arguments and calls other routines
##########################################################
    print("--===[ Noriben v%s ]===--" % __VERSION__)
    print("--===[   @bbaskin   ]===--\r\n")

    parser = ArgumentParser()
    parser.add_argument('-r', dest='read_csv', action='store_true',
                        help='Re-analyze an existing Noriben CSV file [input file]')
    parser.add_argument('input_file', default='', nargs='?',
                        help='-r Noriben_<date>.CSV')
    parser.add_argument('-d', dest='debug', action='store_true', help='Enable debug tracebacks')
    args = parser.parse_args()

    if args.read_csv:
        if os.path.exists(args.input_file):
            txt_file = os.path.splitext(args.input_file)[0] + '.txt'
            parse_csv(txt_file, args.input_file, args.debug)
            sys.exit()
        else:
            parser.print_usage()
            sys.exit(1)


    procmonexe = check_procmon()
    if not procmonexe:
        print("[!] Unable to find procmon.exe in path.")
        sys.exit(1)

    print("[*] Using procmon EXE: %s" % procmonexe)
    session_id = get_session_name()
    pml_file = "Noriben_%s.pml" % session_id
    csv_file = "Noriben_%s.csv" % session_id
    txt_file = "Noriben_%s.txt" % session_id
    pmc_file = 'ProcmonConfiguration.PMC'
    if not os.path.exists(pmc_file):
        use_pmc = False
        print("[!] ProcmonConfiguration.PMC not found. Continuing without filters.")
    else:
        use_pmc = True
        print("[*] Using PMC file: %s" % pmc_file)

    print("[*] Procmon session saved to: %s" % pml_file)
    print("[*] Launching Procmon ...")

    cmdline = "%s /BackingFile %s /Quiet /Minimized" % (procmonexe, pml_file)
    if use_pmc:
        cmdline += " /LoadConfig %s" % pmc_file
    subprocess.Popen(cmdline)
    print("[*] Procmon is running. Run your malware now.")
    print("[*] When runtime is complete, press CTRL+C to stop logging.")

    try:
        while True:
            sleep(10)
    except KeyboardInterrupt:
        pass

    print("[*] Termination of Procmon commencing... please wait")
    cmdline = "%s /Terminate" % procmonexe
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()

    print("[*] Procmon terminated")
    if not os.path.exists(pml_file):
        print("[!] Error creating PML file!")
        sys.exit(1)

    print("[*] Converting session to CSV: %s" % csv_file)
    cmdline = "%s /OpenLog %s /saveas %s" % (procmonexe, pml_file, csv_file)
    if use_pmc:
        cmdline += " /LoadConfig %s" % pmc_file
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()

    parse_csv(txt_file, csv_file, args.debug)


if __name__ == "__main__":
    main()
