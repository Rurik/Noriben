# Noriben Malware Analysis Sandbox
#
# Directions:
# Just copy Noriben.py to a Windows-based VM alongside the SysInternals Procmon.exe
#
# Run Noriben.py, then run your executable.
# When the executable has completed its processing, stop Noriben and view a
# clean text report and timeline
#
# Changelog:
# Version 2.0 - September-ish 2022
#       Major changes to NoribenSandbox host script
#           Updated many of the functions, such as properly deleting files in guest
#           Remove unneeded or obtuse options
#       Move everything to all major settings to a configuration file
#
# Version 1.8.7 - 30 Aug 22
#       Replaced csv.reader with csv.DictReader to have better forward and backward
#       compatibility. Small changes in style, PEP8
# Version 1.8.6 - 26 May 21
#       Fixed a long-standing bug that crashed the script when encountering certain
#       binary data in a registry key
# Version 1.8.5 - 02 May 21
#       Changed terminology from whitelist to approvelist. Updated filters. Added quick
#       fix related to issue #29/#44 for errant ticks in data
# Version 1.8.4 - 22 Nov 19
#       Minor updates. Added ability to run a non-executable, such as a Word document
# Version 1.8.3 - 26 Nov 18
#       Fixed minor bugs in reading hash files and in sleeping between VirusTotal queries
# Version 1.8.2 - 28 Jun 18
#       Fixed minor bug that would crash upon writing out CSV
# Version 1.8.1 - 14 Jun 18
#       Added additional config options, such as output_folder. Added value
#       global_whitelist_append to allow additional filters
# Version 1.8.0 - 9 Jun 18
#       Really, truly, dropping Python 2 support now. Added --config file option to load
#       global variables from external files. Now uses CSV library. Code cleanup
# Version 1.7.6 - 12 Apr 18 -
#       Some auto PEP-8 formatting. Fixed bug where specific output dir wouldn't add
#       to files when specifying a PML or CSV file. Added configuration of new txt
#       extension in cases where ransomware was encrypting files. CSV, however, cannot
#       be changed due to limitations in ProcMon
# Version 1.7.5 - 10 Mar 18 -
#       Another bug fix related to global use of renamed procmon binary. Edge case fix
# Version 1.7.4 - 28 Feb 18 -
#       More bug fixes related to global use of renamed procmon binary. Added filters
# Version 1.7.3b - 7 Jan 18 -
#       Implemented --troubleshoot option to pause the program upon exit so that the
#       error messages can be seen manually
# Version 1.7.3 - 26 Dec 17 -
#       Fixed bug where a changed procmon binary was not added to the whitelist, and
#       would therefore be included in the output
# Version 1.7.2 - 21 Apr 17 -
#       Fixed Debug output to go to a log file continually, so output is stored if
#       unexpected exit. Check for PML and Config file between executions to account
#       for destructive malware that erases during runtime. Added headless option for
#       automated runs, so that screenshot can be grabbed w/o output on screen
# Version 1.7.1 - 3 Apr 17 -
#       Small updates. Change --filter to not find default if a bad one is specified
# Version 1.7.0 - 4 Feb 17 -
#       Default hash method is now SHA256. An argument and global var allow to
#       override hash. Numerous filters added. PEP8 cleanup, multiple small fixes to
#       code and implementation styles
# Version 1.6.4 - 7 Dec 16 -
#       A handful of bug fixes related to bad Internet access. Small variable updates.
# Version 1.6.3 - 13 Jan 16 -
#       Bug fixes to handle path joining. Bug fixes for spaces in all directory
#       names. Added support to find default PMC from script working directory.
# Version 1.6.2 - 9 Apr 15 -
#       Created debug output to file. This now includes full VirusTotal dumps.
#       Currently Noriben only displays number of hits, but additional meta is now
#       dumped for further analysis by users.
# Version 1.6.1 - 16 Mar 15 -
#       Soft fails on Requests import. Lack of module now just disables VirusTotal.
#       Added better YARA handling. Instead of failing over a single error, it
#       will skip the offending file. You can now hard-set the YARA signature
#       folder in the script.
# Version 1.6 - 14 Mar 15 -
#       Long delayed and now forked release. This will be the final release for
#       Python 2.X except for updated rules. Now requires 3rd party libraries.
#       VirusTotal API scanning implemented. Added better filters.
#       Added controls for some registry writes that had size but no data.
#       Added whitelist for MD5 hashes and --hash option for hash file.
#       Renamed 'blacklist' to 'whitelist' because it's supposed to be. LOL
#       Change file handling due to 'read entire file' bug in FileInput.
# Version 1.5b - 1 Oct 13 -
#       Ninja edits to fix a few small bug fixes and change path generalization
#       to an ordered list instead of an unordered dictionary. This lets you
#       prioritize resolutions.
# Version 1.5 - 28 Sep 13 -
#       Standardized to single quotes, added YARA scanning of resident files,
#       reformatted function comments to match appropriate docstring format,
#       fixed bug with generalize paths - now generalizes after getting MD5
# Version 1.4 - 16 Sep 13 -
#       Fixed string generalization on file rename and now supports ()'s in
#       environment name (for 64-bit systems), added ability to Ctrl-C from
#       a timeout, added specifying malware file from command line, added an
#       output directory
# Version 1.3 - 13 Sep 13 -
#       Option to generalize file paths in output, option to use a timeout
#       instead of Ctrl-C to end monitoring, only writes RegSetValue entries
#       if Length > 0
# Version 1.2 - 28 May 13 -
#       Now reads CSV files line-by-line to handle large files, keep
#       unsuccessful registry deletes, compartmentalize sections, creates CSV
#       timeline, can reparse PMLs, can specify alternative PMC filters,
#       changed command line arguments, added global approvelist
# Version 1.1a - 1 May 13 -
#       Revamped regular expression support. Added Python 3.x forward
#       compatibility
# Version 1.1 - 21 Apr 13 -
#       Much improved filters and filter parsing
# Version 1.0 - 10 Apr 13 - @bbaskin - brian [@] thebaskins.com
#       Gracious edits, revisions, and corrections by Daniel Raygoza








#
# TODO:
# * Upload files directly to VirusTotal (2.X feature?)
# * extract data directly from registry? (may require python-registry)
# * scan for mutexes, preferably in a way that doesn't require wmi/pywin32

import argparse
import ast
import codecs
import csv
import datetime
import glob
import hashlib
import os
import re
import subprocess
import string
import sys
import time
import traceback

try:
    import yara  # pip yara-python

    has_yara = True
except ImportError:
    yara = None
    has_yara = False

try:
    import requests
    import json

    has_internet = True
except ImportError:
    requests = None
    json = None
    has_internet = False
    print('[+] Python module "requests" not found. Internet functionality is disabled.')
    print('[+] This is acceptable if you do not wish to upload data to VirusTotal.')

try:
    import configparser
except ImportError:
    print('[!] Python module "configparser" not found. Python 3 required.')
    configparser = None

# Below are global internal variables. Do not edit these. ################
__VERSION__ = '1.8.7'
path_general_list = []
use_pmc = False
vt_results = {}
vt_dump = list()
debug_messages = list()
exe_cmdline = ''
time_exec = 0
time_process = 0
script_cwd = ''
debug_file = ''
valid_hash_types = ['MD5', 'SHA1', 'SHA256']
##########################################################################


noriben_errors = {0: 'Normal exit',
                  1: 'PML file was not found',
                  2: 'Unable to find procmon.exe',
                  3: 'Unable to create output directory',
                  4: 'Windows is refusing execution based upon permissions',
                  5: 'Could not create CSV',
                  6: 'Could not find malware file',
                  7: 'Error creating CSV',
                  8: 'Error creating PML',
                  9: 'Unknown error',
                  10: 'Invalid arguments given'}


def get_error(code):
    """
    Looks up a given code in dictionary set of errors of noriben_errors.

    Arguments:
        code: Integer that corresponds to a pre-set entry
    Results:
         string value of a error code
    """
    if code in noriben_errors:
        return noriben_errors[code]
    return 'Unexpected Error'


def read_config(config_filename):
    """
    Parse an external configuration file.

    Arguments:
        config_filename: String of filename, predetermined if exists
    Result:
        none
    """
    global config
    global use_virustotal
    global global_approvelist, reg_approvelist, file_approvelist, cmd_approvelist
    global net_approvelist, hash_approvelist

    try:
        file_config = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
        with codecs.open(config_filename, 'r', encoding='utf-8') as f:
            file_config.read_file(f)

        config = {}
        options = file_config.options('Noriben')
        for option in options:
            config[option] = file_config.get('Noriben', option)
            if config[option].lower() in ['true', 'false']:
                config[option] = file_config.getboolean('Noriben', option)
            if config[option] == -1:
                print('[*] Invalid configuration option detected: {}'.format(option))
                

        global_approvelist = file_config.get('Filters', 'global_approvelist').replace('\n','').split(',')
        reg_approvelist = file_config.get('Filters', 'reg_approvelist').replace('\n','').split(',')
        file_approvelist = file_config.get('Filters', 'file_approvelist').replace('\n','').split(',')
        cmd_approvelist = file_config.get('Filters', 'cmd_approvelist').replace('\n','').split(',')
        net_approvelist = file_config.get('Filters', 'net_approvelist').replace('\n','').split(',')
        hash_approvelist = file_config.get('Filters', 'hash_approvelist').replace('\n','').split(',')
        
        # Throwing a large one in here to ignore anything that the configured procmon executable creates
        global_approvelist.append(config['procmon'])
        global_approvelist.append(config['procmon'].split('.')[0] + '64.exe')  # Procmon drops embed as <name>+64
        
    except configparser.MissingSectionHeaderError:
        print('[!] Error found in reading config file. Invalid section header detected.')
        sys.exit(12)
    except Exception as e: 
        print(e)
        time.sleep(5)

    if config['virustotal_api_key'] and has_internet:
        use_virustotal = True
    else:
        use_virustotal = False


def human():
    import pyautogui
    import math

    SIZE_X, SIZE_Y = pyautogui.size()
    STEPS = 20
    TIME_STEP = 0

    for i in range(0,STEPS):
        j = (((i/STEPS)*2)*math.pi)
        x = math.cos(j) 
        y = math.sin(j) 
        pyautogui.moveTo( SIZE_X/2 + (SIZE_Y/3)*x
                ,SIZE_Y/2 + (SIZE_Y/3)*y, duration=TIME_STEP)


def terminate_self(error):
    """
    Implemented for better troubleshooting.

    Arguments:
        error: Int of error code to return to system parent
    Result:
        none
    """
    print('[*] Exiting with error code: {}: {}'.format(error, get_error(error)))
    if config['troubleshoot']:
        errormsg = '[*] Paused for troubleshooting. Press enter to close Noriben.'
        input(errormsg)
    sys.exit(error)


def log_debug(msg):
    """
    Logs a passed message. Results are printed and stored in
    a list for later writing to the debug log.

    Arguments:
        msg: Text string of message.
    Results:
        none
    """
    global debug_messages

    # Sanity check in case this is called before configuration is loaded
    try:
        debug = config['debug']
    except KeyError:
        debug = False
    
    if msg and debug:
        if debug_file:  # File already set, check for message buffer
            if debug_messages:  # If buffer, write and erase buffer
                hdbg = open(debug_file, 'a')
                for item in debug_messages:
                    hdbg.write(item)
                hdbg.close()
                debug_messages = list()
            else:
                open(debug_file, 'a').write('{}\n'.format(msg))
        else:  # Output file hasn't been set yet, append to buffer
            debug_messages.append(msg + '\r\n')


def generalize_vars_init():
    """
    Initialize a dictionary with the local system's environment variables.
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

    global path_general_list
    log_debug('[*] Enabling Windows string generalization.')

    for env in envvar_list:
        try:
            resolved = os.path.expandvars(env).replace("\\", "\\\\")

            # TODO: Resolve this issue with Py3 for x86 folder.
            # resolved = resolved.replace(b'(', b'\\(').replace(b')', b'\\)')
            # if not resolved == env and not resolved == env.replace(b'(', b'\\(').replace(b')', b'\\)'):
            path_general_list.append([env, resolved])
        except TypeError:
            if resolved in locals():
                log_debug('[!] generalize_vars_init(): Unable to parse var: {}'.format(resolved))
            continue


def generalize_var(path_string):
    """
    Generalize a given string to include its environment variable

    Arguments:
        path_string: string value to generalize
    Results:
        string value of a generalized string
    """
    if not len(path_general_list):
        generalize_vars_init()  # For edge cases when this isn't previously called.

    for item in path_general_list:
        path_string = re.sub(item[1], item[0], path_string)

    return path_string


def read_hash_file(hash_filename):
    """
    Read a given file of SHA256 hashes and add them to the hash approvelist.

    Arguments:
        hash_filename: path to a text file containing hashes (either flat or sha256deep)
    """
    global hash_approvelist
    hash_file_handle = open(hash_filename, newline='', encoding='utf-8')
    reader = csv.DictReader(hash_file_handle)
    for hash_line in reader:
        hashval = hash_line[0]
        try:
            if int(hashval, 16) and (len(hashval) == 32 or len(hashval) == 40 or len(hashval) == 64):
                hash_approvelist.append(hashval)
        except (TypeError, ValueError):
            pass


def virustotal_query_hash(hashval):
    """
    Submit a given hash to VirusTotal to retrieve number of alerts

    Arguments:
        hashval: SHA256 hash to a given file
    """
    global vt_results
    global vt_dump
    result = ''
    try:
        if not (int(hashval, 16) and (len(hashval) == 32 or len(hashval) == 40 or len(hashval) == 64)):
            return ''
    except (TypeError, ValueError):
        pass

    try:
        previous_result = vt_results[hashval]
        log_debug('[*] VT scan already performed for {}. Returning previous: {}'.format(hashval, previous_result))
        return previous_result
    except KeyError:
        pass

    vt_query_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    post_params = {'apikey': config['virustotal_api_key'],
                   'resource': hashval}
    log_debug('[*] Querying VirusTotal for hash: {}'.format(hashval))
    data = ''
    try:
        http_response = requests.post(vt_query_url, post_params)
    except requests.exceptions.RequestException:
        return ''  # null string to append to output

    if http_response.status_code == 204:
        print('[!] VirusTotal Rate Limit Exceeded. Sleeping for 60 seconds.')
        time.sleep(60)
        return virustotal_query_hash(hashval)
    else:
        try:
            data = http_response.json()
        except ValueError:
            result = 'Error'

        try:
            if data['response_code'] == -2:
                result = ' [VT: Queued]'
            elif data['response_code'] == -1:
                result = ' [VT: Error 001]'
            elif data['response_code'] == 0:
                result = ' [VT: Not Scanned]'
            elif data['response_code'] == 1:
                if data['total']:
                    vt_dump.append(data)
                    result = ' [VT: {}/{}]'.format(data['positives'], data['total'])
                else:
                    result = ' [VT: Error 002]'
        except TypeError:
            result = ' [VT: Error 003]'
    vt_results[hashval] = result
    log_debug('[*] VirusTotal result for hash {}: {}'.format(hashval, result))
    return result


def yara_rule_check(yara_files):
    """
    Scan a dictionary of YARA rule files to determine
    which are valid for compilation.

    Arguments:
        yara_files: path to folder containing rules
    """
    result = dict()
    for yara_id in yara_files:
        fname = yara_files[yara_id]
        try:
            yara.compile(filepath=fname)
            result[yara_id] = fname
        except yara.SyntaxError:
            log_debug('[!] Syntax Error found in YARA file: {}'.format(fname))
            log_debug(traceback.format_exc())
    return result


def yara_import_rules(yara_path):
    """
    Import a folder of YARA rule files

    Arguments:
        yara_path: path to folder containing rules
    Results:
        rules: a yara.Rules structure of available YARA rules
    """
    yara_files = {}
    if not yara_path[-1] == '\\':
        yara_path += '\\'

    print('[*] Loading YARA rules from folder: {}'.format(yara_path))
    files = os.listdir(yara_path)

    for file_name in files:
        file_extension = os.path.splitext(file_name)[1]
        if '.yar' in file_extension:
            yara_files[file_name.split(os.sep)[-1]] = os.path.join(yara_path, file_name)

    yara_files = yara_rule_check(yara_files)
    rules = ''
    if yara_files:
        try:
            rules = yara.compile(filepaths=yara_files)
            print('[*] YARA rules loaded. Total files imported: {}'.format(len(yara_files)))
        except yara.SyntaxError:
            print('[!] YARA: Unknown Syntax Errors found.')
            print('[!] YARA rules disabled until all Syntax Errors are fixed.')
            log_debug('[!] YARA: Unknown Syntax Errors found.')
            log_debug('[!] YARA rules disabled until all Syntax Errors are fixed.')
    return rules


def yara_filescan(file_path, rules):
    """
    Scan a given file to see if it matches a given set of YARA rules

    Arguments:
        file_path: full path to a file to scan
        rules: a yara.Rules structure of available YARA rules
    Results:
        results: a string value that's either null (no hits)
                 or formatted with hit results
    """
    if not rules:
        return ''
    if os.path.isdir(file_path):
        return ''

    try:
        matches = rules.match(file_path)
    except yara.Error:  # If can't open file
        log_debug('[!] YARA can\'t open file: {}'.format(file_path))
        return ''
    if matches:
        results = '\t[YARA: {}]'.format(', '.join(str(x) for x in matches))
    else:
        results = ''
    return results


def open_file_with_assoc(fname):
    """
    Opens the specified file with its associated application

    Arguments:
        fname: full path to a file to open
    Results:
        None
    """
    if config['headless']:
        # Headless is for automated runs, don't open results on VM
        return

    if os.name == 'mac':
        ret = subprocess.call(('open', fname))
    elif os.name == 'nt':
        # os.startfile(fname)
        ret = subprocess.call(('start', fname), shell=True)
    elif os.name == 'posix':
        ret = subprocess.call(('open', fname))

    return ret


def file_exists(fname):
    """
    Determine if a file exists

    Arguments:
        fname: path to a file
    Results:
        boolean value if file exists
    """
    log_debug('[*] Checking for existence of file: {}'.format(fname))
    return os.path.exists(fname) and os.access(fname, os.F_OK) and not os.path.isdir(fname)


def check_procmon():
    """
    Finds the local path to Procmon

    Results:
        folder path to procmon executable
    """
    log_debug('[*] Checking for procmon in the following location: {}'.format(config['procmon']))
    procmon_exe = config['procmon']
    if file_exists(procmon_exe):
        return procmon_exe

    for path in os.environ['PATH'].split(os.pathsep):
        if file_exists(os.path.join(path.strip('"'), procmon_exe)):
            return os.path.join(path, procmon_exe)

    if file_exists(os.path.join(script_cwd, procmon_exe)):
        return os.path.join(script_cwd, procmon_exe)


def hash_file(fname):
    """
    Given a filename, returns the hex hash value

    Arguments:
        fname: path to a file
    Results:
        hex hash value of file's contents as a string
    """
    log_debug('[*] Performing {} hash on file: {}'.format(config['hash_type'], fname))
    if config['hash_type'] == 'MD5':
        return hashlib.md5(codecs.open(fname, 'rb').read()).hexdigest()
    elif config['hash_type'] == 'SHA1':
        return hashlib.sha1(codecs.open(fname, 'rb').read()).hexdigest()
    elif config['hash_type'] == 'SHA256':
        return hashlib.sha256(codecs.open(fname, 'rb').read()).hexdigest()


def get_session_name():
    """
    Returns current date and time stamp for file name

    Results:
        string value of a current timestamp to apply to log file names
    """
    return datetime.datetime.now().strftime('%d_%b_%y__%H_%M_%f')


def protocol_replace(text):
    """
    Replaces text name resolutions from domain names

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


def approvelist_scan(approvelist, data):
    """
    Given a approvelist and data string, see if data is in approvelist

    Arguments:
        approvelist: list of items to ignore
        data: string value to compare against approvelist
    Results:
        boolean value of if item exists in approvelist
    """
    for event in data:
        for bad in approvelist + global_approvelist:
            bad = os.path.expandvars(bad).replace('\\', '\\\\')
            try:
                if re.search(bad, event, flags=re.IGNORECASE):
                    return True
            except re.error:
                log_debug('[!] Error found while processing filters.\r\nFilter:\t{}\r\nEvent:\t{}'.format(bad, event))
                log_debug(traceback.format_exc())
                return False
    return False


def process_pml_to_csv(procmonexe, pml_file, pmc_file, csv_file):
    """
    Uses Procmon to convert the PML to a CSV file

    Arguments:
        procmonexe: path to Procmon executable
        pml_file: path to Procmon PML output file
        pmc_file: path to PMC filter file
        csv_file: path to output CSV file
    Results:
        None
    """
    global time_process
    time_convert_start = time.time()

    log_debug('[*] Converting session to CSV: {}'.format(csv_file))
    if not file_exists(pml_file):
        print('[!] Error detected. PML file was not found: {}'.format(pml_file))
        terminate_self(1)
    cmdline = '"{}" /OpenLog "{}" /SaveApplyFilter /saveas "{}"'.format(procmonexe, pml_file, csv_file)
    if use_pmc and file_exists(pmc_file):
        cmdline += ' /LoadConfig "{}"'.format(pmc_file)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()

    time_convert_end = time.time()
    time_process = time_convert_end - time_convert_start


def launch_procmon_capture(procmonexe, pml_file, pmc_file):
    """
    Launch Procmon to begin capturing data

    Arguments:
        procmonexe: path to Procmon executable
        pml_file: path to Procmon PML output file
        pmc_file: path to PMC filter file
    Results:
        None
    """
    global time_exec
    time_exec = time.time()

    cmdline = '"{}" /BackingFile "{}" /Quiet /Minimized'.format(procmonexe, pml_file)
    if use_pmc and file_exists(pmc_file):
        cmdline += ' /LoadConfig "{}"'.format(pmc_file)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    subprocess.Popen(cmdline)
    time.sleep(3)


def terminate_procmon(procmonexe):
    """
    Terminate Procmon cleanly

    Arguments:
        procmonexe: path to Procmon executable
    Results:
        None
    """
    global time_exec
    time_exec = time.time() - time_exec

    cmdline = '"{}" /Terminate'.format(procmonexe)
    log_debug('[*] Running cmdline: {}'.format(cmdline))
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()


def parse_csv(csv_file, report, timeline):
    """
    Given the location of CSV and TXT files, parse the CSV for notable items

    Arguments:
        csv_file: path to csv output to parse
        report: OUT string text containing the entirety of the text report
        timeline: OUT string text containing the entirety of the CSV report
    """
    log_debug('[*] Processing CSV: {}'.format(csv_file))

    process_output = list()
    file_output = list()
    reg_output = list()
    net_output = list()
    error_output = list()
    remote_servers = list()
    if config['yara_folder'] and has_yara:
        yara_rules = yara_import_rules(config['yara_folder'])
    else:
        yara_rules = ''

    time_parse_csv_start = time.time()

    csv_file_handle = open(csv_file, newline='', encoding='utf-8-sig')
    reader = csv.DictReader(csv_file_handle)

    for original_line in reader:
        server = ''
        field = original_line
        # log_debug('[*] Parse line. Event: {}'.format(field['Operation'])

        date_stamp = field['Time of Day'].split()[0].split('.')[0]

        try:
            if field['Operation'] == 'Process Create' and field['Result'] == 'SUCCESS':
                cmdline = field['Detail'].split('Command line: ')[1]
                if not approvelist_scan(cmd_approvelist, field):
                    log_debug('[*] CreateProcess: {}'.format(cmdline))

                    if config['generalize_paths']:
                        cmdline = generalize_var(cmdline)
                    child_pid = field['Detail'].split('PID: ')[1].split(',')[0]
                    outputtext = '[CreateProcess] {}:{} > "{}"\t[Child PID: {}]'.format(
                        field['Process Name'], field['PID'], cmdline.replace('"', ''), child_pid)
                    tl_text = '{},Process,CreateProcess,{},{},{},{}'.format(date_stamp, field['Process Name'], field['PID'], cmdline.replace('"', ''), child_pid)
                    process_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'CreateFile' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(file_approvelist, field):
                    path = field['Path']
                    log_debug('[*] CreateFile: {}'.format(path))
                    yara_hits = ''
                    if config['yara_folder'] and yara_rules:
                        yara_hits = yara_filescan(path, yara_rules)
                    if os.path.isdir(path):
                        if config['generalize_paths']:
                            path = generalize_var(path)
                        outputtext = '[CreateFolder] {}:{} > {}'.format(field['Process Name'], field['PID'], path)
                        tl_text = '{},File,CreateFolder,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                         field['PID'], path)
                        file_output.append(outputtext)
                        timeline.append(tl_text)
                    else:
                        try:
                            hashval = hash_file(path)
                            if hashval in hash_approvelist:
                                log_debug('[_] Skipping hash: {}'.format(hashval))
                                continue

                            av_hits = ''
                            if use_virustotal and has_internet:
                                av_hits = virustotal_query_hash(hashval)

                            if config['generalize_paths']:
                                path = generalize_var(path)
                            outputtext = '[CreateFile] {}:{} > {}\t[{}: {}]{}{}'.format(field['Process Name'], field['PID'], path,
                                                                                        config['hash_type'], hashval,
                                                                                        yara_hits, av_hits)
                            tl_text = '{},File,CreateFile,{},{},{},{},{},{},{}'.format(date_stamp,
                                                                                       field['Process Name'], field['PID'], path,
                                                                                       config['hash_type'], hashval,
                                                                                       yara_hits, av_hits)
                            file_output.append(outputtext)
                            timeline.append(tl_text)
                        except (IndexError, IOError):
                            if config['generalize_paths']:
                                path = generalize_var(path)
                            outputtext = '[CreateFile] {}:{} > {}\t[File no longer exists]'.format(field['Process Name'], field['PID'],
                                                                                                   path)
                            tl_text = '{},File,CreateFile,{},{},{},N/A'.format(date_stamp,
                                                                               field['Process Name'], field['PID'], path)
                            file_output.append(outputtext)
                            timeline.append(tl_text)

            elif field['Operation'] == 'SetDispositionInformationFile' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(file_approvelist, field):
                    path = field['Path']
                    log_debug('[*] DeleteFile: {}'.format(path))
                    if config['generalize_paths']:
                        path = generalize_var(path)
                    outputtext = '[DeleteFile] {}:{} > {}'.format(field['Process Name'], field['PID'], path)
                    tl_text = '{},File,DeleteFile,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                   field['PID'], path)
                    file_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'SetRenameInformationFile':
                if not approvelist_scan(file_approvelist, field):
                    from_file = field['Path']
                    to_file = field['Detail'].split('FileName: ')[1].strip('"')
                    if config['generalize_paths']:
                        from_file = generalize_var(from_file)
                        to_file = generalize_var(to_file)
                    outputtext = '[RenameFile] {}:{} > {} => {}'.format(field['Process Name'], field['PID'], from_file, to_file)
                    tl_text = '{},File,RenameFile,{},{},{},{}'.format(date_stamp, field['Process Name'],
                                                                      field['PID'], from_file, to_file)
                    file_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'RegCreateKey' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(reg_approvelist, field):
                    path = field['Path']
                    log_debug('[*] RegCreateKey: {}'.format(path))

                    outputtext = '[RegCreateKey] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    if outputtext not in reg_output:  # Ignore multiple CreateKeys. Only log the first.
                        tl_text = '{},Registry,RegCreateKey,{},{},{}'.format(date_stamp,
                                                                             field['Process Name'], field['PID'], field['Path'])
                        reg_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'RegSetValue' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(reg_approvelist, field):
                    reg_length = field['Detail'].split('Length:')[1].split(',')[0].strip(string.whitespace + '"')
                    reg_length = reg_length.replace('’', '')  # Addresses errant ticks found in some data samples
                    try:
                        if int(float(reg_length)):
                            if 'Data:' in field['Detail']:
                                data_field = '  =  {}'.format(field['Detail'].split('Data:')[1].strip(string.whitespace + '"'))
                                if len(data_field.split(' ')) == 16:
                                    data_field += ' ...'
                            elif 'Length:' in field['Detail']:
                                data_field = ''
                            else:
                                continue
                            outputtext = '[RegSetValue] {}:{} > {}{}'.format(field['Process Name'], field['PID'], field['Path'], data_field)
                            tl_text = '{},Registry,RegSetValue,{},{},{},{}'.format(date_stamp,
                                                                                   field['Process Name'], field['PID'], field['Path'],
                                                                                   data_field)
                            reg_output.append(outputtext)
                            timeline.append(tl_text)

                    except (IndexError, ValueError):
                        error_output.append(''.join(original_line))

            elif field['Operation'] == 'RegDeleteValue':  # and field['Result'] == 'SUCCESS':
                # SUCCESS is commented out to allow all attempted deletions, whether or not the value exists
                if not approvelist_scan(reg_approvelist, field):
                    outputtext = '[RegDeleteValue] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    tl_text = '{},Registry,RegDeleteVal ue,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                            field['PID'], field['Path'])
                    reg_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'RegDeleteKey':  # and field['Result'] == 'SUCCESS':
                # SUCCESS is commented out to allow all attempted deletions, whether or not the value exists
                if not approvelist_scan(reg_approvelist, field):
                    outputtext = '[RegDeleteKey] {}:{} > {}'.format(field['Process Name'], field['PID'], field['Path'])
                    tl_text = '{},Registry,RegDeleteKey,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                         field['PID'], field['Path'])
                    reg_output.append(outputtext)
                    timeline.append(tl_text)

            elif field['Operation'] == 'UDP Send' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    # TODO: work on this later, once I can verify it better.
                    # if field['Detail'] == 'Length: 20':
                    #    output_line = '[DNS Query] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    # else:
                    outputtext = '[UDP] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    if outputtext not in net_output:
                        tl_text = '{},Network,UDP Send,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'UDP Receive' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[UDP] {} > {}:{}'.format(protocol_replace(server), field['Process Name'], field['PID'])
                    if outputtext not in net_output:
                        tl_text = '{},Network,UDP Receive,{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'])
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'TCP Send' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[TCP] {}:{} > {}'.format(field['Process Name'], field['PID'], protocol_replace(server))
                    if outputtext not in net_output:
                        tl_text = '{},Network,TCP Send,{},{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'], protocol_replace(server))
                        net_output.append(outputtext)
                        timeline.append(tl_text)

            elif field['Operation'] == 'TCP Receive' and field['Result'] == 'SUCCESS':
                if not approvelist_scan(net_approvelist, field):
                    server = field['Path'].split('-> ')[1]
                    outputtext = '[TCP] {} > {}:{}'.format(protocol_replace(server), field['Process Name'], field['PID'])
                    if outputtext not in net_output:
                        tl_text = '{},Network,TCP Receive,{},{}'.format(date_stamp, field['Process Name'],
                                                                        field['PID'])
                        net_output.append(outputtext)
                        timeline.append(tl_text)

        except IndexError:
            log_debug(original_line)
            log_debug(traceback.format_exc())
            error_output.append(original_line)

        # Enumerate unique remote hosts into their own section
        if server:
            server = server.split(':')[0]
            if server not in remote_servers and server != 'localhost':
                remote_servers.append(server)
    # } End of file input processing

    time_parse_csv_end = time.time()

    report.append('-=] Sandbox Analysis Report generated by Noriben v{}'.format(__VERSION__))
    report.append('-=] https://github.com/Rurik/Noriben')
    report.append('')
    if exe_cmdline:
        report.append('-=] Analysis of command line: {}'.format(exe_cmdline))

    if time_exec:
        report.append('-=] Execution time: %0.2f seconds' % time_exec)
    if time_process:
        report.append('-=] Processing time: %0.2f seconds' % time_process)

    time_analyze = time_parse_csv_end - time_parse_csv_start
    report.append('-=] Analysis time: %0.2f seconds' % time_analyze)
    report.append('')

    report.append('Processes Created:')
    report.append('==================')
    log_debug('[*] Writing {} Process Events results to report'.format(len(process_output)))
    for event in process_output:
        report.append(event)

    report.append('')
    report.append('File Activity:')
    report.append('==================')
    log_debug('[*] Writing {} Filesystem Events results to report'.format(len(file_output)))
    for event in file_output:
        report.append(event)

    report.append('')
    report.append('Registry Activity:')
    report.append('==================')
    log_debug('[*] Writing {} Registry Events results to report'.format(len(reg_output)))
    for event in reg_output:
        report.append(event)

    report.append('')
    report.append('Network Traffic:')
    report.append('==================')
    log_debug('[*] Writing {} Network Events results to report'.format(len(net_output)))
    for event in net_output:
        report.append(event)

    report.append('')
    report.append('Unique Hosts:')
    report.append('==================')
    log_debug('[*] Writing {} Remote Servers results to report'.format(len(remote_servers)))
    for server in sorted(remote_servers):
        report.append(protocol_replace(server).strip())

    if error_output:
        report.append('\r\n\r\n\r\n\r\n\r\n\r\nERRORS DETECTED')
        report.append('The following items could not be parsed correctly:')
        log_debug('[*] Writing {} Output Errors results to report'.format(len(error_output)))
        for error in error_output:
            report.append(error)

    if config['debug'] and vt_dump:
        vt_file = os.path.join(config['output_folder'], os.path.splitext(csv_file)[0] + '.vt.json')
        log_debug('[*] Writing {} VirusTotal results to {}'.format(len(vt_dump), vt_file))
        vt_out = open(vt_file, 'w')
        json.dump(vt_dump, vt_out)
        vt_out.close()

    if config['debug'] and debug_messages:
        debug_out = open(debug_file, 'a')
        for message in debug_messages:
            debug_out.write(message)
        debug_out.close()


# End of parse_csv()


def main():
    """
    Main routine, parses arguments and calls other routines
    """
    global use_pmc
    global exe_cmdline
    global script_cwd
    global debug_file

    print('\n--===[ Noriben v{}'.format(__VERSION__))

    if sys.version_info < (3, 0):
        print('[*] Support for Python 2 is no longer available. Please use Python 3.')
        terminate_self(10)

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--csv', help='Re-analyze an existing Noriben CSV file', required=False)
    parser.add_argument('-p', '--pml', help='Re-analyze an existing Noriben PML file', required=False)
    parser.add_argument('-f', '--filter', help='Specify alternate Procmon Filter PMC', required=False)
    parser.add_argument('--config', help='Specify configuration file', required=False)
    parser.add_argument('--hash', help='Specify hash approvelist file', required=False)
    parser.add_argument('--hashtype', help='Specify hash type', required=False, choices=valid_hash_types)
    parser.add_argument('--headless', action='store_true', help='Do not open results on VM after processing',
                        required=False)
    parser.add_argument('--human', action='store_true', help='Perform human activity', required=False)
    parser.add_argument('-t', '--timeout', help='Number of seconds to collect activity', required=False, type=int)
    parser.add_argument('--output', help='Folder to store output files', required=False)
    parser.add_argument('--yara', help='Folder containing YARA rules', required=False)
    parser.add_argument('--cmd', help='Command line to execute (in quotes)', required=False)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debugging', required=False)
    parser.add_argument('--troubleshoot', action='store_true', help='Pause before exiting for troubleshooting',
                        required=False)
    args = parser.parse_args()
    report = list()
    timeline = list()
    script_cwd = os.path.dirname(os.path.abspath(__file__))

    # Load config file first, then use additional args to override those values if necessary
    default_config_location = os.path.join(script_cwd, 'Noriben.config')
    read_config(default_config_location)
    if args.config:
        if file_exists(args.config):
            read_config(args.config)
        else:
            print('[!] Config file {} not found. Continuing with default values.'.format(args.config))

    if args.debug:
        config['debug'] = True


    if os.path.exists('virustotal.api'):  # Or put it in here
        config['virustotal_api_key'] = open('virustotal.api', 'r').readline().strip()
    virustotal_upload = True if config['virustotal_api_key'] else False  # TODO
    use_virustotal = True if config['virustotal_api_key'] and has_internet else False

    if args.troubleshoot:
        config['troubleshoot'] = True

    # Check to see if string generalization is wanted
    if config['generalize_paths']:
        generalize_vars_init()

    if args.headless:
        config['headless'] = True

    if args.hashtype:
        config['hash_type'] = args.hashtype

    # Load hash approvelist and append to global approve list
    if args.hash:
        if file_exists(args.hash):
            read_hash_file(args.hash)

    # Check for a valid filter file
    if args.filter:
        if file_exists(args.filter):
            pmc_file = args.filter
        else:
            pmc_file = ''
    else:
        pmc_file = 'ProcmonConfiguration.PMC'
    pmc_file_cwd = os.path.join(script_cwd, pmc_file)

    if pmc_file:
        if not file_exists(pmc_file):
            if not file_exists(pmc_file_cwd):
                use_pmc = False
                print('[!] Filter file {} not found. Continuing without filters.'.format(pmc_file))
            else:
                use_pmc = True
                pmc_file = pmc_file_cwd
                print('[*] Using filter file: {}'.format(pmc_file))
        else:
            use_pmc = True
            print('[*] Using filter file: {}'.format(pmc_file))
            log_debug('[*] Using filter file: {}'.format(pmc_file))
    else:
        use_pmc = False

    # Find a valid procmon executable.
    procmonexe = check_procmon()
    if not procmonexe:
        print('[!] Unable to find Procmon ({}) in path.'.format(config['procmon']))
        terminate_self(2)

    # Check to see if specified output folder exists. If not, make it.
    # This only works one path deep. In future, may make it recursive.
    if args.output:
        config['output_folder'] = args.output
        if not os.path.exists(config['output_folder']):
            try:
                os.mkdir(config['output_folder'])
            except WindowsError:
                print('[!] Fatal: Unable to create output directory: {}'.format(config['output_folder']))
                terminate_self(3)
    log_debug('[*] Log output directory: {}'.format(config['output_folder']))

    # Check to see if specified YARA folder exists
    if args.yara or config['yara_folder']:
        if not config['yara_folder']:
            config['yara_folder'] = args.yara
        if not config['yara_folder'][-1] == '\\':
            config['yara_folder'] += '\\'
        if not os.path.exists(config['yara_folder']):
            print('[!] YARA rule path not found: {}'.format(config['yara_folder']))
            config['yara_folder'] = ''
    log_debug('[*] YARA directory: {}'.format(config['yara_folder']))

    # Print feature list
    log_debug(
        '[+] Features: (Debug: {}\tInternet: {}\tVirusTotal: {})'.format(config['debug'], has_internet, use_virustotal))

    # Check if user-specified to rescan a PML
    if args.pml:
        if file_exists(args.pml):
            # Reparse an existing PML
            if not args.output:
                config['output_folder'] = os.path.dirname(args.pml)
            pml_basename = os.path.splitext(os.path.basename(args.pml))[0]
            csv_file = os.path.join(config['output_folder'], pml_basename + '.csv')
            txt_file = os.path.join(config['output_folder'], pml_basename + '.' + config['txt_extension'])
            debug_file = os.path.join(config['output_folder'], pml_basename + '.log')
            timeline_file = os.path.join(config['output_folder'], pml_basename + '_timeline.csv')

            process_pml_to_csv(procmonexe, args.pml, pmc_file, csv_file)
            if not file_exists(csv_file):
                print('[!] Error detected. Could not create CSV file: {}'.format(csv_file))
                terminate_self(5)

            parse_csv(csv_file, report, timeline)

            print('[*] Saving report to: {}'.format(txt_file))
            codecs.open(txt_file, 'w', 'utf-8-sig').write('\r\n'.join(report))

            print('[*] Saving timeline to: {}'.format(timeline_file))
            # codecs.open(timeline_file, 'w', 'utf-8-sig').write('\r\n'.join(timeline))
            with open(timeline_file, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.writer(f)
                writer.writerows(timeline)

            ret = open_file_with_assoc(txt_file)
            terminate_self(0)
        else:
            print('[!] PML file does not exist: {}\n'.format(args.pml))
            parser.print_usage()
            terminate_self(1)

    # Check if user-specified to rescan a CSV
    if args.csv:
        if file_exists(args.csv):
            # Reparse an existing CSV
            if not args.output:
                config['output_folder'] = os.path.dirname(args.csv)
            csv_basename = os.path.splitext(os.path.basename(args.csv))[0]
            txt_file = os.path.join(config['output_folder'], csv_basename + '.' + config['txt_extension'])
            debug_file = os.path.join(config['output_folder'], csv_basename + '.log')
            timeline_file = os.path.join(config['output_folder'], csv_basename + '_timeline.csv')

            parse_csv(args.csv, report, timeline)

            print('[*] Saving report to: {}'.format(txt_file))
            codecs.open(txt_file, 'w', 'utf-8-sig').write('\r\n'.join(report))

            print('[*] Saving timeline to: {}'.format(timeline_file))
            codecs.open(timeline_file, 'w', 'utf-8-sig').write('\r\n'.join(timeline))

            ret = open_file_with_assoc(txt_file)
            terminate_self(0)
        else:
            parser.print_usage()
            terminate_self(10)

    if args.timeout:
        config['timeout_seconds'] = args.timeout

    if args.cmd:
        exe_cmdline = args.cmd
    else:
        exe_cmdline = ''

    # Start main data collection and processing
    print('[*] Using procmon EXE: {}'.format(procmonexe))
    session_id = get_session_name()
    pml_file = os.path.join(config['output_folder'], 'Noriben_{}.pml'.format(session_id))
    csv_file = os.path.join(config['output_folder'], 'Noriben_{}.csv'.format(session_id))
    txt_file = os.path.join(config['output_folder'], 'Noriben_{}.{}'.format(session_id, config['txt_extension']))
    debug_file = os.path.join(config['output_folder'], 'Noriben_{}.log'.format(session_id))

    timeline_file = os.path.join(config['output_folder'], 'Noriben_{}_timeline.csv'.format(session_id))
    print('[*] Procmon session saved to: {}'.format(pml_file))

    if exe_cmdline and not file_exists(exe_cmdline):
        print('[!] Error: Specified malware executable does not exist: {}'.format(exe_cmdline))
        terminate_self(6)

    print('[*] Launching Procmon ...')
    launch_procmon_capture(procmonexe, pml_file, pmc_file)

    if exe_cmdline:
        print('[*] Launching command line: {}'.format(exe_cmdline))
        try:
            subprocess.Popen(exe_cmdline)
        except WindowsError:  # Occurs if VMWare bug removes Owner from file
            print('[*] Execution failed. File is potentially not an executable. Trying to open with associated application.')
            try:
                ret = open_file_with_assoc(exe_cmdline)
            except WindowsError:
                print('\n[*] Unexpected termination of Procmon commencing... please wait')
                print('[!] Error executing file. Windows is refusing execution based upon permissions.')
                terminate_procmon(procmonexe)
                terminate_self(4)

    else:
        print('[*] Procmon is running. Run your executable now.')

    if config['timeout_seconds']:
        print('[*] Running for {} seconds. Press Ctrl-C to stop logging early.'.format(config['timeout_seconds']))
        # Print a small progress indicator, for those REALLY long sleeps.
        try:
            timeout_seconds = int(config['timeout_seconds'])
            for i in range(timeout_seconds):
                progress = (100 / timeout_seconds) * i
                sys.stdout.write('\r%d{} complete'.format(progress))
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    else:
        print('[*] When runtime is complete, press CTRL+C to stop logging.')
        try:
            while True:
                time.sleep(100)
        except KeyboardInterrupt:
            pass

    print('\n[*] Termination of Procmon commencing... please wait')
    terminate_procmon(procmonexe)

    print('[*] Procmon terminated')
    if not file_exists(pml_file):
        print('[!] Error creating PML file!')
        terminate_self(8)

    # PML created, now convert it to a CSV for parsing
    process_pml_to_csv(procmonexe, pml_file, pmc_file, csv_file)
    if not file_exists(csv_file):
        print('[!] Error detected. Could not create CSV file: {}'.format(csv_file))
        terminate_self(7)

    # Process CSV file, results in 'report' and 'timeline' output lists
    parse_csv(csv_file, report, timeline)
    print('[*] Saving report to: {}'.format(txt_file))
    codecs.open(txt_file, 'w', 'utf-8').write('\r\n'.join(report))

    print('[*] Saving timeline to: {}'.format(timeline_file))
    codecs.open(timeline_file, 'w', 'utf-8').write('\r\n'.join(timeline))

    open_file_with_assoc(txt_file)
    terminate_self(0)
    # End of main()


if __name__ == '__main__':
    main()
