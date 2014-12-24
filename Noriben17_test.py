# Noriben Malware Analysis Sandbox
#
# Directions:
# Just copy Noriben.py to a Windows-based VM alongside the Sysinternals Procmon.exe
#
# Run Noriben.py, then run your executable.
# When the executable has completed its processing, stop Noriben and you'll have a clean text report and timeline
#
# Version 1.0 - 10 Apr 13 - @bbaskin - brian@thebaskins.com
#       Gracious edits, revisions, and corrections by Daniel Raygoza
# Version 1.1 - 21 Apr 13 -
#       Much improved filters and filter parsing
# Version 1.1a - 1 May 13 -
#       Revamped regular expression support. Added Python 3.x forward
#       compatibility
# Version 1.2 - 28 May 13 -
#       Now reads CSV files line-by-line to handle large files, keep
#       unsuccessful registry deletes, compartmentalize sections, creates CSV
#       timeline, can reparse PMLs, can specify alternative PMC filters,
#       changed command line arguments, added global blacklist
# Version 1.3 - 13 Sep 13 -
#       Option to generalize file paths in output, option to use a timeout
#       instead of Ctrl-C to end monitoring, only writes RegSetValue entries
#       if Length > 0
# Version 1.4 - 16 Sep 13 -
#       Fixed string generalization on file rename and now supports ()'s in
#       environment name (for 64-bit systems), added ability to Ctrl-C from
#       a timeout, added specifying malware file from command line, added an
#       output directory
# Version 1.5 - 28 Sep 13 -
#       Standardized to single quotes, added YARA scanning of resident files,
#       reformatted function comments to match appropriate docstring format,
#       fixed bug with generalize paths - now generalizes after getting MD5
# Version 1.5b - 1 Oct 13 -
#       Ninja edits to fix a few small bug fixes and change path generalization
#       to an ordered list instead of an unordered dictionary. This lets you
#       prioritize resolutions.
# Version 1.6 - 17 Nov 13 -
#       Integrates VirusTotal results for resident files. A valid VirusTotal
#       API key is required. Added additional filters for Windows 7 activity.
# Version 1.7 - 7 Dec 13 -
#       Complete rewrite to class-based, which would allow for easier future
#       control and updates. Added many more filters to get generic registry
#       writes and Windows 7 activity. Added extensive debug messages.
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

import argparse
from datetime import datetime
from string import whitespace
from time import sleep
from traceback import format_exc

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


# The below are customizable variables. Change these as you see fit.
virustotal_api_key = ''  ## SET THIS
if os.path.exists('virustotal.api'):
    virustotal_api_key = open('virustotal.api', 'r').readlines()[0].strip()
virustotal_upload = True

procmon = 'procmon.exe'  # Change this if you have a renamed procmon.exe
generalize_paths = False  # generalize paths to their base environment variable
enable_timeline = True
use_pmc = False
debug = False
timeout_seconds = 0  # Set to 0 to manually end monitoring with Ctrl-C

# Rules for creating rules:
# 1. Every rule string must begin with the `r` for regular expressions to work.
# 1.a. This signifies a 'raw' string.
# 2. No backslashes at the end of a filter. Either:
# 2.a. truncate the backslash, or
# 2.b. use '\*' to signify 'zero or more slashes'.
# 3. To find a list of available '%%' variables, type `set` from a command prompt

# These entries are applied to all blacklists
global_blacklist = [r'VMwareUser.exe',
                    r'CaptureBAT.exe',
                    r'SearchIndexer.exe']

cmd_blacklist = [r'%SystemRoot%\system32\wbem\wmiprvse.exe',
                 r'%SystemRoot%\system32\wscntfy.exe',
                 r'procmon.exe',
                 r'wuauclt.exe',
                 r'jqs.exe',
                 r'TCPView.exe'] + global_blacklist

file_blacklist = [r'procmon.exe',
                  r'Desired Access: Execute/Traverse',
                  r'Desired Access: Synchronize',
                  r'Desired Access: Generic Read/Execute',
                  r'Desired Access: Read EA',
                  r'Desired Access: Read Data/List',
                  r'Desired Access: Generic Read, ',
                  r'Desired Access: Read Attributes',
                  r'Google\Chrome\User Data\.*.tmp',
                  r'wuauclt.exe',
                  r'wmiprvse.exe',
                  r'Microsoft\Windows\Explorer\thumbcache_.*.db',
                  r'Thumbs.db$',

                  r'%AllUsersProfile%\Application Data\Microsoft\OFFICE\DATA',
                  r'%AppData%\Microsoft\Proof\*',
                  r'%AppData%\Microsoft\Templates\*',
                  r'%LocalAppData%\Google\Drive\sync_config.db*',
                  r'%ProgramFiles%\Capture\*',
                  r'%SystemDrive%\Python',
                  r'%SystemRoot%\assembly',
                  r'%SystemRoot%\Prefetch\*',
                  r'%SystemRoot%\system32\wbem\Logs\*',
                  r'%UserProfile%$',
                  r'%UserProfile%\AppData\LocalLow$',
                  r'%UserProfile%\Recent\*',
                  r'%UserProfile%\Local Settings\History\History.IE5\*'] + global_blacklist

reg_blacklist = [r'CaptureProcessMonitor',
                 r'consent.exe',
                 r'procmon.exe',
                 r'verclsid.exe',
                 r'wmiprvse.exe',
                 r'wscntfy.exe',
                 r'wuauclt.exe',

                 r'HKCR$',
                 r'HKCR\AllFilesystemObjects\shell',

                 r'HKCU$',
                 r'HKCU\Printers\DevModePerUser',
                 r'HKCU\SessionInformation\ProgramCount',
                 r'HKCU\Software$',
                 r'HKCU\Software\Classes\Software\Microsoft\Windows\CurrentVersion\Deployment\SideBySide',
                 r'HKCU\Software\Classes\Local Settings\MuiCache\*',
                 r'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
                 r'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags',
                 r'HKCU\Software\Microsoft\Calc$',
                 r'HKCU\Software\Microsoft\.*\Window_Placement',
                 r'HKCU\Software\Microsoft\Internet Explorer\TypedURLs',
                 r'HKCU\Software\Microsoft\Notepad',
                 r'HKCU\Software\Microsoft\Office',
                 r'HKCU\Software\Microsoft\Shared Tools',
                 r'HKCU\Software\Microsoft\SystemCertificates\Root$',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Applets',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CIDOpen',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Modules',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage2',
                 r'HKCU\Software\Microsoft\Windows\Currentversion\Explorer\StreamMRU',
                 r'HKCU\Software\Microsoft\Windows\Currentversion\Explorer\Streams',
                 r'HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy',
                 r'HKCU\Software\Microsoft\Windows\Shell',
                 r'HKCU\Software\Microsoft\Windows\Shell\BagMRU',
                 r'HKCU\Software\Microsoft\Windows\Shell\Bags',
                 r'HKCU\Software\Microsoft\Windows\ShellNoRoam\MUICache',
                 r'HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU',
                 r'HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags',
                 r'HKCU\Software\Policies$',
                 r'HKCU\Software\Policies\Microsoft$',

                 r'HKLM$',
                 r'HKLM\SOFTWARE$',
                 r'HKLM\SOFTWARE\Microsoft$',
                 r'HKLM\SOFTWARE\Policies$',
                 r'HKLM\SOFTWARE\Policies\Microsoft$',
                 r'HKLM\SOFTWARE\MICROSOFT\SystemCertificates$',
                 r'HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products',
                 r'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\*',
                 r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render',
                 r'HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions',
                 r'HKLM\Software\Microsoft\WBEM',
                 r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher\*',
                 r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Tracing\*',
                 r'HKLM\System\CurrentControlSet\Control\CLASS\{4D36E968-E325-11CE-BFC1-08002BE10318}',
                 r'HKLM\System\CurrentControlSet\Control\DeviceClasses',
                 r'HKLM\System\CurrentControlSet\Control\MediaProperties',
                 r'HKLM\System\CurrentControlSet\Enum\*',
                 r'HKLM\System\CurrentControlSet\Services\CaptureRegistryMonitor',
                 r'HKLM\System\CurrentControlSet\Services\Eventlog\*',
                 r'HKLM\System\CurrentControlSet\Services\Tcpip\Parameters',
                 r'HKLM\System\CurrentControlSet\Services\WinSock2\Parameters',

                 r'LEGACY_CAPTUREREGISTRYMONITOR',
                 r'Software\Microsoft\Multimedia\Audio$',
                 r'Software\Microsoft\Multimedia\Audio Compression Manager',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder',
                 r'Software\Microsoft\Windows\ShellNoRoam\Bags',
                 r'Software\Microsoft\Windows\ShellNoRoam\BagMRU',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.doc',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
                 r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
                 r'UserAssist\{5E6AB780-7743-11CF-A12B-00AA004AE837}',
                 r'UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}',
                 r'UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}'] + global_blacklist

net_blacklist = [r'hasplms.exe'] + global_blacklist  # Hasp dongle beacons
                 #r'192.168.2.',                     # Particular to my network
                 #r'Verizon_router.home']            # Particular to my network


# The below is for global internal variables. Don't touch them.
__VERSION__ = '1.7'
yara_folder = ''
vt_results = {}
has_virustotal = True if virustotal_api_key else False


class Configuration(object):
    """Class to contain all configuration settings."""
    def __init__(self):
        self.procmonexe = None
        self.txt_file = None
        self.csv_file = None
        self.pmc_file = None
        self.pml_file = None
        self.timeline_file = None
        self.output_dir = ''
        self.use_pmc = False
        self.debug = False
        self.errors = None
        self.exe_cmdline = ''
        self.generalize_paths = None
        self.rescan_pml = False
        self.rescan_csv = False
        self.yara_folder = ''
        self.timeout = timeout_seconds

    def __str__(self):
        """Provide string-based printout of class contents."""
        return ''.join("{%s}: %s\n" % item for item in vars(self).items())


class Event(object):
    """Class to contain a specific event."""
    def __init__(self,
                 time=None,
                 group=None,
                 activity=None,
                 process=None,
                 PID=None,
                 process_value=None,
                 md5=None,
                 child_pid=None,
                 hostname=None,
                 virustotal_scanned=False):

        self.time = time
        self.group = group
        self.activity = activity
        self.process = process
        self.PID = PID
        self.process_value = process_value
        self.md5 = md5
        self.child_pid = child_pid
        self.hostname = hostname
        self.virustotal_scanned = virustotal_scanned
        self.tags = {}

    def __str__(self):
        """Provide string-based printout of class contents."""
        for item in vars(self).iteritems():
            if item[1]:
                print('{%s}: %s' % (item[0], item[1]))
            else:
                print('* {%s}' % item[0])
        return ''

    def build_tags(self, tabs=True):
        """Traverse tags, putting into single string. MD5 first."""
        tags = ''
        if tabs:
            tab = '\t'
        else:
            tab = ''
        if self.md5:
            tags += '%s[MD5: %s]' % (tab, self.md5)
        for item, value in self.tags.iteritems():
            tags += '%s[%s: %s]' % (tab, item, value)
        return tags

    def get_csv(self):
        """Provide CSV string of relevant container items."""
        return '%s,%s,%s,%s,%s,%s,%s' % (self.time, self.group, self.activity, self.process,
                                         self.PID, self.process_value, self.build_tags(tabs=False))

    def get_report_string(self):
        """Return the event contents in a format relevant to text report."""
        txt = ''
        if self.activity == 'CreateProcess':
            txt = '[CreateProcess] %s:%s > "%s"\t[Child PID: %s]' % (
                    self.process, self.PID, self.process_value, self.child_pid)
        elif self.activity in ['CreateFile', 'CreateFolder', 'DeleteFile',
                               'RegCreateKey', 'RegDeleteValue', 'RegSetValue',
                               'RenameFile', 'UDP', 'TCP']:
            txt = '[%s] %s:%s > %s' % (self.activity, self.process, self.PID, self.process_value)
        elif self.activity == 'RenameFile':
            txt = '[%s] %s:%s > %s => %s' % (self.activity, self.process, self.PID, from_file, to_file)
        elif self.activity == 'RegSetValue':
            txt = '[%s] %s:%s > %s  =  %s' % (self.activity, self.process, self.PID, self.process_value, data_field)
        else:
            print ('[!] Unknown file activity: %s ' % self.activity)
        if self.tags:
            txt += self.build_tags()
        return txt


def generalize_vars_init():
    """Initialize a dictionary with the local system's environment variables.
    Returns via a global variable, path_general_list
    """
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

    path_general_list = list()
    print('[*] Enabling Windows string generalization.')
    for env in envvar_list:
        resolved = os.path.expandvars(env).encode('unicode_escape')
        resolved = resolved.replace('(', '\\(').replace(')', '\\)')
        if not resolved == env and not resolved == env.replace('(', '\\(').replace(')', '\\)'):
            path_general_list.append([env, resolved])
    Config.path_general_list = path_general_list


def generalize_var(path_string):
    """Generalize a given string to include its environment variable

    Arguments:
        path_string: string value to generalize
    Results:
        string value of a generalized string
    """
    if not len(Config.path_general_list):
        generalize_vars_init()  # Maybe you imported Noriben and forgot to call generalize_vars_init? No biggie.
    for item in Config.path_general_list:
        path_string = re.sub(item[1], item[0], path_string)
    return path_string


def virustotal_scan_events(Container):
    """ XXXXX Submit an MD5/SHA1 value to VirusTotal to check for results.

    Arguments:
        file_id: MD5 or SHA1 of file to retrieve report
    Results:
        String value showing number of positive results
    """
    vt_all_files = {}
    #for event in Container:  XXXXXX
        #if event.md5 and 0 < os.path.getsize(event)
        #    vt_all_files[event.md5] = ''

    for md5 in vt_all_files.iterkeys():
        print(md5)
#    av_hits = virustotal_scan_file(evt.md5)
    av_hits = ''
    if av_hits:
        evt.tags['VirusTotal'] = av_hits
        if Config.debug:
            print('[_] VT: %s' % av_hits)
    print(vt_all_files)
 

def virustotal_scan_file(file_id):
    """Submit an MD5/SHA1 value to VirusTotal to check for results.

    Arguments:
        file_id: MD5 or SHA1 of file to retrieve report
    Results:
        String value showing number of positive results
    """
    import urllib
    import urllib2
    import json

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    if not virustotal_api_key:
        return ''

    # Has the file already been scanned? Return prior result, save API calls
    try:
        result = vt_results[file_id]
        if Config.debug:
            print('[-] Returning cached VirusTotal result: %s ==> %s' % (file_id, vt_results[file_id]))
        return vt_results[file_id]
    except KeyError:
        result = ''

    parameters = {'resource': file_id,
                  'apikey': virustotal_api_key}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json_report = response.read()
    data = json.loads(json_report)

    result = ''
    if data['response_code'] and data['total']:
        result = '%s/%s' % (data['positives'], data['total'])
    else:
        if data['verbose_msg'] == 'The requested resource is not among the finished, queued or pending scans':
            result = 'Not Scanned'
        else:
            result = 'Error'
    vt_results[file_id] = result
    return result


def http_encode_multipart(fields, files=()):
   BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
   CRLF = '\r\n'
   L = []
   for key, value in fields.items():
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"' % key)
      L.append('')
      L.append(value)
   for (key, filename, value) in files:
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
      content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
      L.append('Content-Type: %s' % content_type)
      L.append('')
      L.append(value)
   L.append('--' + BOUNDARY + '--')
   L.append('')
   body = CRLF.join(L)
   content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
   return content_type, body


def http_post_multipart(url, fields, files=()):
   """Transmit HTTP multipart data.

   Arguments:
       url: FQDN URL to transmit to
       fields: HTTP multipart fields
       files: list of files to submit as (key, filename, data)
   Results:
       String value showing number of positive results
   """

   content_type, data = http_encode_multipart(fields, files)
   url_parts = urlparse.urlparse(url)
   if url_parts.scheme == 'http':
      con = httplib.HTTPConnection(url_parts.netloc)
   elif url_parts.scheme == 'https':
      con = httplib.HTTPSConnection(url_parts.netloc)
   path = urlparse.urlunparse(('', '') + url_parts[2:])
   con.request('POST', path, data, {'content-type':content_type})
   return con.getresponse().read()


def yara_rule_check():
    """Scan a folder of YARA rule files to determine which provide syntax errors"""
    for name in os.listdir(Config.yara_folder):
        fname = Config.yara_folder + name
        try:
            rules = yara.compile(filepath=fname)
        except yara.SyntaxError:
            print('[!] YARA Syntax Error in file: %s' % fname)
            print(format_exc())


def yara_import_rules():
    """Import a folder of YARA rule files

    Results:
        rules: a yara.Rules structure of available YARA rules
    """
    yara_files = {}
    print('[*] Loading YARA rules from folder: %s' % Config.yara_folder)
    files = os.listdir(Config.yara_folder)
    for file_name in files:
        if '.yara' in file_name:
            yara_files[file_name.split('.yara')[0]] = Config.yara_folder + file_name
    try:
        rules = yara.compile(filepaths=yara_files)
        print('[*] YARA rules loaded. Total files imported: %d' % len(yara_files))
    except yara.SyntaxError:
        print('[!] Syntax error found in one of the imported YARA files. Error shown below.')
        rules = ''
        yara_rule_check()
        print('[!] YARA rules disabled until all Syntax Errors are fixed.')
    return rules


def yara_filescan(file_path, rules):
    """Scan a given file to see if it matches a given set of YARA rules

    Arguments:
        file_path: full path to a file to scan
        rules: a yara.Rules structure of available YARA rules
    Results:
        results: a string value that's either null (no hits)
                 or formatted with hit results
    """
    if not rules:
        return ''
    path = os.path.expandvars(file_path)
    try:
        matches = rules.match(path)
    except yara.Error:  # If can't open file
        return ''
    if matches:
        results = '%s' % reduce(lambda x, y: str(x) + ', ' + str(y), matches)
    else:
        results = ''
    return results


def open_file_with_assoc(fname):
    """Opens the specified file with its associated application

    Arguments:
        fname: full path to a file to open
    """
    if os.name == 'mac':
        subprocess.call(('open', fname))
    elif os.name == 'nt':
        os.startfile(fname)
    elif os.name == 'posix':
        subprocess.call(('open', fname))


def file_exists(fname):
    """Determine if a file exists

    Arguments:
        fname: path to a file
    Results:
        boolean value if file exists
    """
    path = os.path.expandvars(fname)
    return os.path.exists(path) and os.access(path, os.X_OK)


def check_procmon():
    """Finds the local path to Procmon

    Results:
        folder path to procmon executable
    """
    if file_exists(procmon):
        return procmon
    else:
        for path in os.environ['PATH'].split(os.pathsep):
            if file_exists(os.path.join(path.strip('"'), procmon)):
                return os.path.join(path, procmon)


def md5_file(fname):
    """Given a filename, returns the hex MD5 value

    Arguments:
        fname: path to a file
    Results:
        hex MD5 value of file's contents as a string
    """
    path = os.path.expandvars(fname)
    return hashlib.md5(codecs.open(path, 'rb').read()).hexdigest()


def get_session_name():
    """Returns current date and time stamp for file name

    Results:
        string value of a current timestamp to apply to log file names
    """
    return datetime.now().strftime('%d_%b_%y__%H_%M_%S_%f')


def protocol_replace(text):
    """Replaces text name resolutions from domain names

    Arguments:
        text: string of domain with resolved port name
    Results:
        string value with resolved port name in decimal format
    """
    replacements = [(':https', ':443'),
                    (':http', ':80'),
                    (':domain', ':53')]
    for find, replace in replacements:
        text = text.replace(find, replace)
    return text


def blacklist_scan(blacklist, data):
    """Given a blacklist and data string, see if data is in blacklist

    Arguments:
        blacklist: list of black-listed items
        data: string value to compare against blacklist
    Results:
        boolean value of if item exists in blacklist
    """
    for event in data:
        for bad in blacklist:
            bad = os.path.expandvars(bad).replace('\\', '\\\\')
            try:
                if re.search(bad, event, flags=re.IGNORECASE):
                    return True
            except re.error:
                print('Error found while processing filters.\r\nFilter:\t%s\r\nEvent:\t%s' % (bad, event))
                sys.stderr.write(format_exc())
                return False
    return False


def process_PML_to_CSV():
    """Uses Procmon to convert the PML to a CSV file"""
    print('[*] Converting session to CSV: %s' % Config.csv_file)
    cmdline = '%s /OpenLog %s /saveas %s' % (Config.procmonexe, Config.pml_file, Config.csv_file)
    if Config.use_pmc:
        cmdline += ' /LoadConfig %s' % Config.pmc_file
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()


def launch_procmon_capture():
    """Launch Procmon to begin capturing data"""

    cmdline = '%s /BackingFile %s /Quiet /Minimized' % (Config.procmonexe, Config.pml_file)
    if Config.use_pmc:
        cmdline += ' /LoadConfig %s' % Config.pmc_file
    subprocess.Popen(cmdline)
    sleep(3)


def terminate_procmon():
    """Terminate Procmon cleanly"""

    cmdline = '%s /Terminate' % Config.procmonexe
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()


def parse_csv():
    """Given the location of CSV and TXT files, parse the CSV for notable items"""

    error_output = list()
    Container = list()

    if Config.yara_folder and has_yara:
        yara_rules = yara_import_rules()
    else:
        yara_rules = ''
    if Config.debug:
        print ('[_] Loaded rules:', type(yara_rules))

    # Use fileinput.input() now to read data line-by-line
    if Config.debug:
        print('[_] Parsing in CSV contents...')
    for original_line in fileinput.input(Config.csv_file, openhook=fileinput.hook_encoded('iso-8859-1')):
        evt = None
        server = ''
        # Ignore lines beginning w/ a tab or non-quote.
        if original_line[0] != '"':
            continue
        line = original_line.strip(whitespace + '"')
        field = line.strip().split('","')
        try:
            if field[3] in ['Process Create'] and field[5] == 'SUCCESS':
                cmdline = field[6].split('Command line: ')[1]
                if not blacklist_scan(cmd_blacklist, field):
                    if Config.generalize_paths:
                        cmdline = generalize_var(cmdline)
                    child_pid = field[6].split('PID: ')[1].split(',')[0]
                    evt = Event(time=field[0],
                                group='Process',
                                activity='CreateProcess',
                                process=field[1],
                                PID=field[2],
                                process_value=cmdline.replace('"', ''),
                                child_pid=child_pid)
            elif field[3] == 'CreateFile' and field[5] == 'SUCCESS':
                if not blacklist_scan(file_blacklist, field):
                    path = field[4]
                    if os.path.isdir(path):
                        if Config.generalize_paths:
                            path = generalize_var(path)
                        evt = Event(time=field[0],
                                    group='File',
                                    activity='CreateFolder',
                                    process=field[1],
                                    PID=field[2],
                                    process_value=path)
                    else:
                        yara_hits = ''
                        av_hits = ''

                        if Config.generalize_paths:
                            path = generalize_var(path)

                        evt = Event(time=field[0],
                                    group='File',
                                    activity='CreateFile',
                                    process=field[1],
                                    PID=field[2],
                                    process_value=path)
                        if file_exists(path):
                            if Config.debug:
                                print ('[_] File: %s\texists' % path)
                            try:
                                #md5 = md5_file(path)
                                evt.md5 = '' # XXX
                                if Config.debug:
                                    print('[_]\t%s' % evt.md5)
                            except (IndexError, IOError):
                                evt.md5 = ''
                                if Config.debug:
                                    print('[_]\tMD5 could not be calculated')

                            if Config.yara_folder and yara_rules:
                                print('[*] Scanning with YARA: %s' % path)
                                yara_hits = yara_filescan(path, yara_rules)
                                if yara_hits:
                                    evt.tags['YARA'] = yara_hits
                                    if Config.debug:
                                        print('[_] YARA: %s' % yara_hits)
                                else:
                                    if Config.debug:
                                        print('[_] No YARA hits.')

            elif field[3] == 'SetDispositionInformationFile' and field[5] == 'SUCCESS':
                if not blacklist_scan(file_blacklist, field):
                    path = field[4]
                    if Config.generalize_paths:
                        path = generalize_var(path)

                    evt = Event(time=field[0],
                                group='File',
                                activity='DeleteFile',
                                process=field[1],
                                PID=field[2],
                                process_value=path)
            elif field[3] == 'SetRenameInformationFile':
                if not blacklist_scan(file_blacklist, field):
                    from_file = field[4]
                    to_file = field[6].split('FileName: ')[1].strip('"')
                    if Config.generalize_paths:
                        from_file = generalize_var(from_file)
                        to_file = generalize_var(to_file)

                    evt = Event(time=field[0],
                                group='File',
                                activity='RenameFile',
                                process=field[1],
                                PID=field[2],
                                process_value='%s => %s' % (from_file, to_file))
            elif field[3] == 'RegCreateKey' and field[5] == 'SUCCESS':
                if not blacklist_scan(reg_blacklist, field):
                    evt = Event(time=field[0],
                                group='Registry',
                                activity='RegCreateKey',
                                process=field[1],
                                PID=field[2],
                                process_value=field[4])
            elif field[3] == 'RegSetValue' and field[5] == 'SUCCESS':
                if not blacklist_scan(reg_blacklist, field):
                    reg_length = field[6].split('Length:')[1].split(',')[0].strip(whitespace + '"')
                    if int(reg_length):
                        data_field = field[6].split('Data:')[1].strip(whitespace + '"')
                        if len(data_field.split(' ')) == 16:
                            data_field += ' ...'

                        evt = Event(time=field[0],
                                    group='Registry',
                                    activity='RegSetValue',
                                    process=field[1],
                                    PID=field[2],
                                    process_value='%s = %s' % (field[4], data_field))
            elif field[3] == 'RegDeleteValue':  # and field[5] == 'SUCCESS':
                # SUCCESS is commented out to allows all attempted deletions, whether or not the value exists
                if not blacklist_scan(reg_blacklist, field):
                    evt = Event(time=field[0],
                                group='Registry',
                                activity='RegDeleteValue',
                                process=field[1],
                                PID=field[2],
                                process_value=field[4])
            elif field[3] == 'RegDeleteKey':  # and field[5] == 'SUCCESS':
                # SUCCESS is commented out to allows all attempted deletions, whether or not the value exists
                if not blacklist_scan(reg_blacklist, field):
                    evt = Event(time=field[0],
                                group='Registry',
                                activity='RegDeleteKey',
                                process=field[1],
                                PID=field[2],
                                process_value=field[4])
            elif (field[3] == 'UDP Send' or field[3] == 'UDP Receive') and field[5] == 'SUCCESS':
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split('-> ')[1]
                    hostname = server.split(':')[0]

                    # TODO: work on this later, once I can verify it better.
                    #if field[6] == 'Length: 20':
                    #    output_line = '[DNS Query] %s:%s > %s' % (field[1], field[2], protocol_replace(server))
                    #else:
                    evt = Event(time=field[0],
                                group='Network',
                                activity='UDP',
                                process=field[1],
                                PID=field[2],
                                process_value=protocol_replace(server),
                                hostname=hostname)
            elif (field[3] == 'TCP Send' or field[3] == 'TCP Receive') and field[5] == 'SUCCESS':
                if not blacklist_scan(net_blacklist, field):
                    server = field[4].split('-> ')[1]
                    hostname = server.split(':')[0]

                    evt = Event(time=field[0],
                                group='Network',
                                activity='TCP',
                                process=field[1],
                                PID=field[2],
                                process_value=protocol_replace(server),
                                hostname=hostname)
        except IndexError:
            if Config.debug:
                sys.stderr.write(line)
                sys.stderr.write(format_exc())
            error_output.append(original_line.strip())

        if evt:
            Container.append(evt)

    if error_output:
        error_str = ''
        error_str += '\r\n\r\n\r\n\r\n\r\n\r\nERRORS DETECTED'
        error_str += 'The following items could not be parsed correctly:'
        for error in error_output:
            error_str += error

    #} End of file input processing
    return Container
# End of parse_csv()

def create_timeline(Container):
    """Create and save the CSV timeline structure to a file."""
    report = []
    for event in Container:
        report.append(event.get_csv())

    print('[*] Saving timeline to: %s' % Config.timeline_file)
    codecs.open(Config.timeline_file, 'w', 'utf-8').write('\r\n'.join(report))


def create_report(Container):
    """Create and save the text report to a file."""
    report_events = list()
    remote_servers = list()

    report = []
    report.append('Processes Created:')
    report.append('==================')
    for event in Container:
        if event.activity == 'CreateProcess':
            report.append(event.get_report_string())

    report.append('')
    report.append('File Activity:')
    report.append('==================')
    for event in Container:
        if event.activity in ['CreateFile', 'CreateFolder', 'DeleteFile', 'RenameFile']:
            report.append(event.get_report_string())

    report.append('')
    report.append('Registry Activity:')
    report.append('==================')
    for event in Container:
        if event.activity in ['RegCreateKey', 'RegDeleteKey', 'RegSetValue']:
            report.append(event.get_report_string())

    report.append('')
    report.append('Network Traffic:')
    report.append('==================')
    for event in Container:
        if event.activity in ['TCP', 'UDP']:
            str = event.get_report_string()
            if not str in report:
                report.append(str)
                remote_servers.append(event.hostname)

    report.append('')
    report.append('Unique Hosts:')
    report.append('==================')

    for server in sorted(remote_servers):
        if not server in report:
            report.append(protocol_replace(server).strip())

    print('[*] Saving report to: %s' % Config.txt_file)
    codecs.open(Config.txt_file, 'w', 'utf-8').write('\r\n'.join(report))

def live_capture():
    """Launch procmon and capture new traffic."""
    print('[*] Using procmon EXE: %s' % Config.procmonexe)
    print('[*] Procmon session saved to: %s' % Config.pml_file)
    print('[*] Launching Procmon ...')
    launch_procmon_capture()

    if Config.exe_cmdline:
        print('[*] Launching command line: %s' % Config.exe_cmdline)
        subprocess.Popen(Config.exe_cmdline)
    else:
        print('[*] Procmon is running. Run your executable now.')

    if Config.timeout:
        print('[*] Running for %d seconds. Press Ctrl-C to stop logging early.' % Config.timeout)
        # Print a small progress indicator, for those REALLY long sleeps.
        try:
            for i in range(Config.timeout):
                progress = (100 / Config.timeout) * i
                sys.stdout.write('\r%d%% complete' % progress)
                sys.stdout.flush()
                sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        print('[*] When runtime is complete, press CTRL+C to stop logging.')
        try:
            while True:
                sleep(10)
                dummy_timer = 10 # Dummy call, for a very secret and silly reason
        # This is a hack required by Python 2.
        # See: http://effbot.org/zone/stupid-exceptions-keyboardinterrupt.htm
        except KeyboardInterrupt:
            pass

    print('\n[*] Termination of Procmon commencing... please wait')
    terminate_procmon()

    print('[*] Procmon terminated')
    if not file_exists(Config.pml_file):
        print('[!] Error creating PML file!')
        sys.exit(1)

def parse_args():
    """Parse command line arguments and place into Configuration class container."""
    global generalize_paths
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--csv', help='Re-analyze an existing Noriben CSV file [input file]', required=False)
    parser.add_argument('-p', '--pml', help='Re-analyze an existing Noriben PML file [input file]', required=False)
    parser.add_argument('-f', '--filter', help='Specify alternate Procmon Filter PMC [input file]', required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('--output', help='Folder to store output files', required=False)
    parser.add_argument('--yara', help='Folder containing YARA rules', required=False)
    parser.add_argument('--generalize', dest='generalize_paths', default=False, action='store_true',
                        help='Generalize file paths to their environment variables. Default: %s' % generalize_paths,
                        required=False)
    parser.add_argument('--cmd', help='Command line to execute (in quotes)', required=False)
    parser.add_argument('-d', dest='debug', action='store_true', help='Enable debug tracebacks', required=False)
    args = parser.parse_args()

    # Pull debug from cmdline or global var
    if args.debug or debug:
        Config.debug = True

    if args.timeout:
        Config.timeout = args.timeout

    # Check to see if specified YARA folder exists
    use_yara = False
    if args.yara:
        Config.yara_folder = args.yara
        if not Config.yara_folder[-1] == '\\':
            Config.yara_folder += '\\'
        if not os.path.exists(Config.yara_folder):
            print('[!] YARA rule path not found: %s' % Config.yara_folder)
            Config.yara_folder = ''
            use_yara = False
        else:
            use_yara = True

    # Print feature list
    print('[+] Features: (Debug: %s\tYARA: %s\tVirusTotal: %s)' % (Config.debug, use_yara, has_virustotal))

    # Check to see if string generalization is wanted
    if args.generalize_paths:
        Config.generalize_paths = True

    if Config.generalize_paths:
        generalize_vars_init()

    # Check for a valid filter file
    if args.filter:
        if file_exists(args.filter):
            Config.pmc_file = args.filter
        else:
            Config.pmc_file = 'ProcmonConfiguration.PMC'
    else:
        Config.pmc_file = 'ProcmonConfiguration.PMC'

    if not file_exists(Config.pmc_file):
        Config.use_pmc = False
        print('[!] Filter file %s not found. Continuing without filters.' % Config.pmc_file)
    else:
        Config.use_pmc = True
        print('[*] Using filter file: %s' % Config.pmc_file)

    # Find a valid procmon executable.
    Config.procmonexe = check_procmon()
    if not Config.procmonexe:
        print('[!] Unable to find Procmon (%s) in path.' % procmon)
        sys.exit(1)

    # Check to see if specified output folder exists. If not, make it.
    # This only works one path deep. In future, may make it recursive.
    if args.output:
        Config.output_dir = args.output
        if not os.path.exists(Config.output_dir):
            try:
                os.mkdir(Config.output_dir)
            except WindowsError:
                print('[!] Unable to create directory: %s' % Config.output_dir)
                sys.exit(1)
    else:
        Config.output_dir = ''

    if args.pml:
        Config.pml_file = args.pml
        if file_exists(Config.pml_file):
            Config.rescan_pml = True
        else:
            print('[!] PML file does not exist: %s\n' % Config.pml_file)
            parser.print_usage()
            sys.exit(1)

    if args.csv:
        Config.csv_file = args.csv
        if file_exists(Config.csv_file):
            Config.rescan_csv = True
        else:
            print('[!] PML file does not exist: %s\n' % Config.csv_file)
            parser.print_usage()
            sys.exit(1)

    if args.cmd:
        Config.exe_cmdline = args.cmd


def main():
    """Main routine, parses arguments and calls other routines"""
    global generalize_paths
    global debug

    print('--===[      Noriben v%s     ]===--' % __VERSION__)
    print('--===[ brian @thebaskins.com ]===--\r\n')

    parse_args()

    if Config.rescan_pml:
        if Config.debug:
            print('[_] MODE: Re-Scanning Existing PML')
        # Reparse an existing PML
        Config.csv_file = Config.output_dir + os.path.splitext(Config.pml_file)[0] + '.csv'
        Config.txt_file = Config.output_dir + os.path.splitext(Config.pml_file)[0] + '.txt'
        Config.timeline_file = Config.output_dir + os.path.splitext(Config.pml_file)[0] + '_timeline.csv'
        process_PML_to_CSV()
    elif Config.rescan_csv:
        if Config.debug:
            print('[_] MODE: Re-Scanning Existing CSV')
        # Reparse an existing CSV
        Config.txt_file = os.path.splitext(Config.csv_file)[0] + '.txt'
        Config.timeline_file = os.path.splitext(Config.csv_file)[0] + '_timeline.csv'
    else:
        session_id = get_session_name()
        if Config.debug:
            print('[_] MODE: Starting new session: %s' % session_id)
        Config.pml_file = Config.output_dir + 'Noriben_%s.pml' % session_id
        Config.csv_file = Config.output_dir + 'Noriben_%s.csv' % session_id
        Config.txt_file = Config.output_dir + 'Noriben_%s.txt' % session_id
        Config.timeline_file = Config.output_dir + 'Noriben_%s_timeline.csv' % session_id
        live_capture()
        process_PML_to_CSV()

    if not file_exists(Config.csv_file):
        print('[!] Error detected. Could not create CSV file: %s' % Config.csv_file)
        sys.exit(1)

    events = parse_csv()
    if has_virustotal:
        virustotal_scan_events(events)
    create_report(events)
    create_timeline(events)

    open_file_with_assoc(Config.txt_file)
    # End of main()

if __name__ == '__main__':
    Config=Configuration()
    main()
