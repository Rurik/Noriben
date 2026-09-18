"""
Integration tests for parse_csv().

Each test writes a minimal Procmon-style CSV to a temp file, calls parse_csv(),
and asserts on the returned report list, timeline list, and json_data dict.
"""
import os
import tempfile
import unittest

import Noriben


# ---------------------------------------------------------------------------
# Module-level setup helper (reused across test classes)
# ---------------------------------------------------------------------------

def _setup_globals():
    Noriben.config = {
        'yara_folder': '',
        'generalize_paths': False,
        'virustotal_api_key': '',
        'disable_file_hash': True,
        'disable-file-hash': True,
        'debug': False,
        'output_folder': '',
        'hash_type': 'SHA256',
        'txt_extension': 'txt',
    }
    Noriben.global_approvelist = []
    Noriben.cmd_approvelist = []
    Noriben.file_approvelist = []
    Noriben.reg_approvelist = []
    Noriben.net_approvelist = []
    Noriben.hash_approvelist = []
    Noriben.dll_approvelist = []
    Noriben.exe_cmdline = ''
    Noriben.time_exec = 0.0
    Noriben.time_process = 0.0
    Noriben.path_general_list = []
    Noriben.has_yara = False


CSV_HEADER = '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\r\n'


def _make_csv(rows):
    tf = tempfile.NamedTemporaryFile(
        mode='w', suffix='.csv', delete=False, encoding='utf-8-sig', newline=''
    )
    tf.write(CSV_HEADER)
    for row in rows:
        tf.write(row + '\r\n')
    tf.close()
    return tf.name


def _run(rows, process_tree=False):
    path = _make_csv(rows)
    try:
        report, timeline = [], []
        json_data = Noriben.parse_csv(path, report, timeline, process_tree)
        return report, timeline, json_data
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------

class ReportStructureTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def test_report_contains_section_headers(self):
        report, _, _ = _run([])
        text = '\n'.join(report)
        self.assertIn('Processes Created:', text)
        self.assertNotIn('Module Loads:', text)
        self.assertIn('File Activity:', text)
        self.assertIn('Registry Activity:', text)
        self.assertIn('Network Traffic:', text)
        self.assertIn('Unique Hosts:', text)

    def test_empty_csv_produces_no_events(self):
        _, _, json_data = _run([])
        self.assertEqual(json_data['processes'], [])
        self.assertEqual(json_data['files'], [])
        self.assertEqual(json_data['registry'], [])
        self.assertEqual(json_data['network'], [])

    def test_json_metadata_keys_present(self):
        _, _, json_data = _run([])
        meta = json_data['metadata']
        self.assertIn('noriben_version', meta)
        self.assertIn('analysis_time_seconds', meta)


# ---------------------------------------------------------------------------
# Process Create events
# ---------------------------------------------------------------------------

class ProcessCreateTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _create_row(self, parent='Explorer.EXE', ppid='1000',
                    child_pid='2000', cmdline=r'C:\malware.exe'):
        return (
            f'"8:00:00.0 PM","{parent}","{ppid}","Process Create","","SUCCESS",'
            f'"PID: {child_pid}, Command line: {cmdline}"'
        )

    def test_create_event_appears_in_report(self):
        report, _, _ = _run([self._create_row()])
        lines = [l for l in report if '[CreateProcess]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('Explorer.EXE:1000', lines[0])
        self.assertIn('Child PID: 2000', lines[0])

    def test_create_event_in_json_processes(self):
        _, _, json_data = _run([self._create_row()])
        self.assertEqual(len(json_data['processes']), 1)
        proc = json_data['processes'][0]
        self.assertEqual(proc['process'], 'Explorer.EXE')
        self.assertEqual(proc['pid'], '1000')
        self.assertEqual(proc['child_pid'], '2000')

    def test_create_event_in_timeline(self):
        _, timeline, _ = _run([self._create_row()])
        self.assertTrue(any('CreateProcess' in str(t) for t in timeline))

    def test_approvelist_filters_create_event(self):
        Noriben.cmd_approvelist = ['malware.exe']
        report, _, json_data = _run([self._create_row()])
        lines = [l for l in report if '[CreateProcess]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['processes'], [])

    def test_process_tree_section_added_when_enabled(self):
        report, _, _ = _run([self._create_row()], process_tree=True)
        text = '\n'.join(report)
        self.assertIn('Process Tree:', text)

    def test_process_tree_section_absent_when_disabled(self):
        report, _, _ = _run([self._create_row()], process_tree=False)
        text = '\n'.join(report)
        self.assertNotIn('Process Tree:', text)


# ---------------------------------------------------------------------------
# File events
# ---------------------------------------------------------------------------

class FileActivityTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _create_file_row(self, process='malware.exe', pid='2000',
                         path=r'C:\temp\evil.exe', detail='Desired Access: Write'):
        return (
            f'"8:00:01.0 PM","{process}","{pid}","CreateFile","{path}","SUCCESS",'
            f'"{detail}"'
        )

    def test_file_create_appears_in_report(self):
        report, _, _ = _run([self._create_file_row()])
        lines = [l for l in report if '[CreateFile]' in l]
        self.assertEqual(len(lines), 1)

    def test_file_create_in_json(self):
        _, _, json_data = _run([self._create_file_row()])
        self.assertEqual(len(json_data['files']), 1)
        self.assertEqual(json_data['files'][0]['operation'], 'CreateFile')

    def test_file_approvelist_suppresses_event(self):
        Noriben.file_approvelist = ['evil.exe']
        report, _, json_data = _run([self._create_file_row()])
        lines = [l for l in report if '[CreateFile]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['files'], [])

    def _rename_row(self, process='malware.exe', pid='2000',
                    src=r'C:\temp\old.exe', dest=r'C:\temp\new.exe'):
        return (
            f'"8:00:01.1 PM","{process}","{pid}","SetRenameInformationFile","{src}","SUCCESS",'
            f'"FileName: {dest}"'
        )

    def _delete_row(self, process='malware.exe', pid='2000',
                    path=r'C:\temp\evil.exe', operation='SetDispositionInformationFile'):
        return (
            f'"8:00:01.2 PM","{process}","{pid}","{operation}","{path}","SUCCESS",'
            f'"Delete: True"'
        )

    def test_rename_appears_in_report(self):
        report, _, _ = _run([self._rename_row()])
        lines = [l for l in report if '[RenameFile]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('old.exe', lines[0])
        self.assertIn('new.exe', lines[0])

    def test_rename_in_json(self):
        _, _, json_data = _run([self._rename_row()])
        self.assertEqual(len(json_data['files']), 1)
        self.assertEqual(json_data['files'][0]['operation'], 'RenameFile')

    def test_delete_via_disposition_file_appears_in_report(self):
        report, _, _ = _run([self._delete_row(operation='SetDispositionInformationFile')])
        lines = [l for l in report if '[DeleteFile]' in l]
        self.assertEqual(len(lines), 1)

    def test_delete_via_disposition_ex_appears_in_report(self):
        # Windows 11+ uses SetDispositionInformationEx instead
        report, _, _ = _run([self._delete_row(operation='SetDispositionInformationEx')])
        lines = [l for l in report if '[DeleteFile]' in l]
        self.assertEqual(len(lines), 1)

    def test_delete_in_json(self):
        _, _, json_data = _run([self._delete_row()])
        self.assertEqual(len(json_data['files']), 1)
        self.assertEqual(json_data['files'][0]['operation'], 'DeleteFile')


# ---------------------------------------------------------------------------
# Registry events
# ---------------------------------------------------------------------------

class RegistryActivityTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _reg_set_row(self, process='malware.exe', pid='2000',
                     key=r'HKCU\Software\Evil\Persist',
                     detail='Type: REG_SZ, Length: 8, Data: badvalue'):
        return (
            f'"8:00:02.0 PM","{process}","{pid}","RegSetValue","{key}","SUCCESS",'
            f'"{detail}"'
        )

    def test_reg_set_appears_in_report(self):
        report, _, _ = _run([self._reg_set_row()])
        lines = [l for l in report if '[RegSetValue]' in l]
        self.assertEqual(len(lines), 1)

    def test_reg_set_in_json(self):
        _, _, json_data = _run([self._reg_set_row()])
        self.assertEqual(len(json_data['registry']), 1)
        self.assertEqual(json_data['registry'][0]['operation'], 'RegSetValue')

    def test_reg_approvelist_suppresses_event(self):
        Noriben.reg_approvelist = ['Evil']
        report, _, json_data = _run([self._reg_set_row()])
        lines = [l for l in report if '[RegSetValue]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['registry'], [])

    def _reg_create_row(self, process='malware.exe', pid='2000',
                        key=r'HKCU\Software\Evil\Persist'):
        return (
            f'"8:00:02.1 PM","{process}","{pid}","RegCreateKey","{key}","SUCCESS",""'
        )

    def test_reg_create_appears_in_report(self):
        report, _, _ = _run([self._reg_create_row()])
        lines = [l for l in report if '[RegCreateKey]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn(r'HKCU\Software\Evil\Persist', lines[0])

    def test_reg_create_in_json(self):
        _, _, json_data = _run([self._reg_create_row()])
        self.assertEqual(len(json_data['registry']), 1)
        self.assertEqual(json_data['registry'][0]['operation'], 'RegCreateKey')

    def test_reg_approvelist_suppresses_create(self):
        Noriben.reg_approvelist = ['Evil']
        report, _, json_data = _run([self._reg_create_row()])
        lines = [l for l in report if '[RegCreateKey]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['registry'], [])

    def _reg_delete_key_row(self, process='malware.exe', pid='2000',
                            key=r'HKCU\Software\Evil\Persist'):
        return (
            f'"8:00:02.2 PM","{process}","{pid}","RegDeleteKey","{key}","SUCCESS",""'
        )

    def _reg_delete_value_row(self, process='malware.exe', pid='2000',
                              key=r'HKCU\Software\Evil\Persist\BadValue'):
        return (
            f'"8:00:02.3 PM","{process}","{pid}","RegDeleteValue","{key}","SUCCESS",""'
        )

    def test_reg_delete_key_appears_in_report(self):
        report, _, _ = _run([self._reg_delete_key_row()])
        lines = [l for l in report if '[RegDeleteKey]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn(r'HKCU\Software\Evil\Persist', lines[0])

    def test_reg_delete_key_in_json(self):
        _, _, json_data = _run([self._reg_delete_key_row()])
        self.assertEqual(len(json_data['registry']), 1)
        self.assertEqual(json_data['registry'][0]['operation'], 'RegDeleteKey')

    def test_reg_delete_value_appears_in_report(self):
        report, _, _ = _run([self._reg_delete_value_row()])
        lines = [l for l in report if '[RegDeleteValue]' in l]
        self.assertEqual(len(lines), 1)

    def test_reg_delete_value_in_json(self):
        _, _, json_data = _run([self._reg_delete_value_row()])
        self.assertEqual(len(json_data['registry']), 1)
        self.assertEqual(json_data['registry'][0]['operation'], 'RegDeleteValue')


# ---------------------------------------------------------------------------
# Network events
# ---------------------------------------------------------------------------

class NetworkActivityTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _tcp_row(self, process='malware.exe', pid='2000',
                 dest='1.2.3.4:443'):
        return (
            f'"8:00:03.0 PM","{process}","{pid}","TCP Send",'
            f'"{process} -> {dest}","SUCCESS","Length: 100"'
        )

    def _udp_dns_row(self, process='malware.exe', pid='2000',
                     dest='8.8.8.8:53'):
        return (
            f'"8:00:04.0 PM","{process}","{pid}","UDP Send",'
            f'"{process} -> {dest}","SUCCESS","Length: 20"'
        )

    def test_tcp_send_appears_in_report(self):
        report, _, _ = _run([self._tcp_row()])
        lines = [l for l in report if '[TCP]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('1.2.3.4:443', lines[0])

    def test_tcp_send_in_json(self):
        _, _, json_data = _run([self._tcp_row()])
        self.assertEqual(len(json_data['network']), 1)
        self.assertEqual(json_data['network'][0]['protocol'], 'TCP')

    def test_unique_host_extracted(self):
        _, _, json_data = _run([self._tcp_row()])
        self.assertIn('1.2.3.4', json_data['unique_hosts'])

    def test_localhost_not_in_unique_hosts(self):
        row = self._tcp_row(dest='localhost:8080')
        _, _, json_data = _run([row])
        self.assertNotIn('localhost', json_data['unique_hosts'])

    def test_duplicate_tcp_events_deduplicated_in_report(self):
        row = self._tcp_row()
        report, _, _ = _run([row, row])
        lines = [l for l in report if '[TCP]' in l]
        self.assertEqual(len(lines), 1)

    def test_net_approvelist_suppresses_tcp(self):
        Noriben.net_approvelist = ['malware.exe']
        report, _, json_data = _run([self._tcp_row()])
        lines = [l for l in report if '[TCP]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['network'], [])

    def _tcp_reconnect_row(self, process='malware.exe', pid='2000',
                           dest='1.2.3.4:80', operation='TCP Reconnect'):
        return (
            f'"8:00:03.1 PM","{process}","{pid}","{operation}",'
            f'"{process} -> {dest}","SUCCESS","Length: 0, seqnum: 0, connid: 0"'
        )

    def test_tcp_reconnect_appears_in_report(self):
        # Procmon logs connection establishment as TCP Reconnect, not TCP Send
        report, _, _ = _run([self._tcp_reconnect_row(operation='TCP Reconnect')])
        lines = [l for l in report if '[TCP]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('1.2.3.4:80', lines[0])

    def test_tcp_connect_appears_in_report(self):
        report, _, _ = _run([self._tcp_reconnect_row(operation='TCP Connect')])
        lines = [l for l in report if '[TCP]' in l]
        self.assertEqual(len(lines), 1)

    def test_tcp_reconnect_in_json(self):
        _, _, json_data = _run([self._tcp_reconnect_row()])
        self.assertEqual(len(json_data['network']), 1)
        self.assertEqual(json_data['network'][0]['protocol'], 'TCP')

    def test_tcp_reconnect_unique_host_extracted(self):
        _, _, json_data = _run([self._tcp_reconnect_row()])
        self.assertIn('1.2.3.4', json_data['unique_hosts'])

    def test_udp_send_appears_in_report(self):
        report, _, _ = _run([self._udp_dns_row()])
        lines = [l for l in report if '[UDP]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('8.8.8.8:53', lines[0])

    def test_udp_send_in_json(self):
        _, _, json_data = _run([self._udp_dns_row()])
        self.assertEqual(len(json_data['network']), 1)
        self.assertEqual(json_data['network'][0]['protocol'], 'UDP')
        self.assertEqual(json_data['network'][0]['direction'], 'Send')

    def test_udp_unique_host_extracted(self):
        _, _, json_data = _run([self._udp_dns_row()])
        self.assertIn('8.8.8.8', json_data['unique_hosts'])

    def test_udp_receive_appears_in_report(self):
        row = (
            '"8:00:04.1 PM","malware.exe","2000","UDP Receive",'
            '"malware.exe -> 8.8.8.8:53","SUCCESS","Length: 20"'
        )
        report, _, _ = _run([row])
        lines = [l for l in report if '[UDP]' in l]
        self.assertEqual(len(lines), 1)

    def test_net_approvelist_suppresses_udp(self):
        Noriben.net_approvelist = ['malware.exe']
        report, _, json_data = _run([self._udp_dns_row()])
        lines = [l for l in report if '[UDP]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['network'], [])


# ---------------------------------------------------------------------------
# Module Load (Load Image) events
# ---------------------------------------------------------------------------

class ModuleLoadTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _load_image_row(self, process='malware.exe', pid='2000',
                        path=r'C:\Users\admin\AppData\Roaming\evil.dll',
                        detail='Image Base: 0x7fff00000000, Image Size: 0x1e000'):
        return (
            f'"8:00:05.0 PM","{process}","{pid}","Load Image","{path}","SUCCESS",'
            f'"{detail}"'
        )

    def test_load_image_appears_in_report(self):
        report, _, _ = _run([self._load_image_row()])
        lines = [l for l in report if '[LoadImage]' in l]
        self.assertEqual(len(lines), 1)
        self.assertIn('evil.dll', lines[0])
        self.assertIn('malware.exe:2000', lines[0])

    def test_load_image_in_json(self):
        _, _, json_data = _run([self._load_image_row()])
        self.assertEqual(len(json_data['modules']), 1)
        mod = json_data['modules'][0]
        self.assertEqual(mod['operation'], 'LoadImage')
        self.assertEqual(mod['process'], 'malware.exe')
        self.assertEqual(mod['pid'], '2000')
        self.assertIn('evil.dll', mod['path'])

    def test_load_image_in_timeline(self):
        _, timeline, _ = _run([self._load_image_row()])
        self.assertTrue(any('LoadImage' in str(t) for t in timeline))

    def test_duplicate_loads_deduplicated(self):
        row = self._load_image_row()
        report, _, _ = _run([row, row])
        lines = [l for l in report if '[LoadImage]' in l]
        self.assertEqual(len(lines), 1)

    def test_dll_approvelist_suppresses_event(self):
        Noriben.dll_approvelist = ['evil.dll']
        report, _, json_data = _run([self._load_image_row()])
        lines = [l for l in report if '[LoadImage]' in l]
        self.assertEqual(len(lines), 0)
        self.assertNotIn('Module Loads:', report)
        self.assertEqual(json_data['modules'], [])

    def test_system32_path_suppressed_by_default_approvelist(self):
        Noriben.dll_approvelist = [r'%%WinDir%%\\System32\\', r'System32']
        row = self._load_image_row(path=r'C:\Windows\System32\ntdll.dll')
        report, _, json_data = _run([row])
        lines = [l for l in report if '[LoadImage]' in l]
        self.assertEqual(len(lines), 0)

    def test_module_loads_section_in_report(self):
        report, _, _ = _run([self._load_image_row()])
        text = '\n'.join(report)
        self.assertIn('Module Loads:', text)

    def test_module_loads_section_omitted_when_empty(self):
        report, _, json_data = _run([])
        text = '\n'.join(report)
        self.assertNotIn('Module Loads:', text)
        self.assertEqual(json_data['modules'], [])

    def test_failed_load_ignored(self):
        # Only SUCCESS results should be captured
        row = (
            '"8:00:05.1 PM","malware.exe","2000","Load Image",'
            r'"C:\bad\evil.dll","ACCESS DENIED","Image Base: 0x0"'
        )
        report, _, json_data = _run([row])
        lines = [l for l in report if '[LoadImage]' in l]
        self.assertEqual(len(lines), 0)
        self.assertEqual(json_data['modules'], [])

    def test_system32_process_unusual_path_dll_not_suppressed(self):
        """Regression: dll_approvelist must only filter on the DLL's Path, not on
        the loading process's Image Path.  A DLL from %TEMP% loaded by
        powershell.exe (which lives in System32) must NOT be suppressed.
        """
        Noriben.dll_approvelist = [r'System32']
        # Build a CSV that includes the Image Path column (as real Procmon CSVs do).
        header = ('"Time of Day","Process Name","PID","Operation","Path",'
                  '"Result","Detail","TID","Image Path","Command Line","Description"\r\n')
        # Loading process is in System32; the DLL itself is in %TEMP% (unusual path).
        row = (
            '"8:00:05.0 PM","powershell.exe","9000","Load Image",'
            r'"C:\Users\admin\AppData\Local\Temp\NoribenTest\NoribenTest.dll",'
            '"SUCCESS","Image Base: 0x7fff00000000, Image Size: 0x1000","1234",'
            r'"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",'
            '"powershell.exe -File test.ps1","Windows PowerShell"'
        )
        import tempfile, os as _os
        tf = tempfile.NamedTemporaryFile(
            mode='w', suffix='.csv', delete=False, encoding='utf-8-sig', newline=''
        )
        tf.write(header)
        tf.write(row + '\r\n')
        tf.close()
        try:
            report, _, json_data = [], [], {}
            json_data = Noriben.parse_csv(tf.name, report, [], False)
            lines = [l for l in report if '[LoadImage]' in l]
            self.assertEqual(len(lines), 1,
                             'DLL from unusual path was incorrectly suppressed because '
                             'the loading process lives in System32')
            self.assertIn('NoribenTest.dll', lines[0])
        finally:
            _os.unlink(tf.name)


if __name__ == '__main__':
    unittest.main()
