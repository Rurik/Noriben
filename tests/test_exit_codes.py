import csv
import os
import tempfile
import unittest

import Noriben


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_globals():
    """Initialise Noriben module-level globals to safe test defaults."""
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
    Noriben.exe_cmdline = ''
    Noriben.time_exec = 0.0
    Noriben.time_process = 0.0
    Noriben.path_general_list = []
    Noriben.has_yara = False


CSV_HEADER = '"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\r\n'


def _make_csv(rows):
    """Write rows to a NamedTemporaryFile CSV and return its path.
    Caller is responsible for deletion."""
    tf = tempfile.NamedTemporaryFile(
        mode='w', suffix='.csv', delete=False, encoding='utf-8-sig', newline=''
    )
    tf.write(CSV_HEADER)
    for row in rows:
        tf.write(row + '\r\n')
    tf.close()
    return tf.name


# ---------------------------------------------------------------------------
# NTSTATUS dict tests
# ---------------------------------------------------------------------------

class NTSTATUSNamesTests(unittest.TestCase):

    def test_known_codes_present(self):
        known = [
            0xC0000005,  # Access Violation
            0xC000013A,  # Ctrl+C Exit
            0xC00000FD,  # Stack Overflow
            0xC0000409,  # Stack Buffer Overrun
            0xFFFFFFFF,  # Abnormal Termination
        ]
        for code in known:
            self.assertIn(code, Noriben.NTSTATUS_NAMES,
                          f'0x{code:08X} missing from NTSTATUS_NAMES')

    def test_values_are_nonempty_strings(self):
        for code, name in Noriben.NTSTATUS_NAMES.items():
            self.assertIsInstance(name, str)
            self.assertGreater(len(name), 0, f'Empty name for 0x{code:08X}')

    def test_keys_are_unsigned_32bit_ints(self):
        for code in Noriben.NTSTATUS_NAMES:
            self.assertIsInstance(code, int)
            self.assertGreaterEqual(code, 0)
            self.assertLessEqual(code, 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# Exit code annotation via parse_csv
# ---------------------------------------------------------------------------

class ExitCodeAnnotationTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def _run(self, rows, process_tree=False):
        path = _make_csv(rows)
        try:
            report, timeline = [], []
            Noriben.parse_csv(path, report, timeline, process_tree)
            return report, timeline
        finally:
            os.unlink(path)

    # -- helper to extract CreateProcess lines only
    @staticmethod
    def _create_lines(report):
        return [l for l in report if l.startswith('[CreateProcess]')]

    def test_nonzero_exit_annotated_on_create_line(self):
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\malware.exe"',
            '"8:00:05.0 PM","malware.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: -1, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        report, _ = self._run(rows)
        creates = self._create_lines(report)
        self.assertEqual(len(creates), 1)
        self.assertIn('[Exit:', creates[0])
        self.assertIn('0xffffffff', creates[0])

    def test_zero_exit_produces_no_annotation(self):
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\clean.exe"',
            '"8:00:05.0 PM","clean.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: 0, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        report, _ = self._run(rows)
        creates = self._create_lines(report)
        self.assertEqual(len(creates), 1)
        self.assertNotIn('[Exit:', creates[0])

    def test_known_ntstatus_name_included_in_annotation(self):
        # 0xC0000005 decimal = -1073741819
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\crash.exe"',
            '"8:00:05.0 PM","crash.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: -1073741819, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        report, _ = self._run(rows)
        creates = self._create_lines(report)
        self.assertEqual(len(creates), 1)
        self.assertIn('0xc0000005', creates[0])
        self.assertIn('Access Violation', creates[0])

    def test_unknown_nonzero_exit_shows_hex_only(self):
        # 0x00001234 — not in NTSTATUS_NAMES
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\odd.exe"',
            '"8:00:05.0 PM","odd.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: 4660, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        report, _ = self._run(rows)
        creates = self._create_lines(report)
        self.assertEqual(len(creates), 1)
        self.assertIn('[Exit:', creates[0])
        # Should not contain a dash-separated description
        line = creates[0]
        exit_part = line[line.index('[Exit:'):]
        self.assertNotIn(' - ', exit_part)

    def test_no_exit_event_leaves_create_line_unchanged(self):
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\running.exe"',
        ]
        report, _ = self._run(rows)
        creates = self._create_lines(report)
        self.assertEqual(len(creates), 1)
        self.assertNotIn('[Exit:', creates[0])

    def test_json_exit_code_field_set_for_nonzero(self):
        """parse_csv returns json_data; exits with non-zero code add exit_code to processes."""
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\crash.exe"',
            '"8:00:05.0 PM","crash.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: -1073741819, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        path = _make_csv(rows)
        try:
            report, timeline = [], []
            json_data = Noriben.parse_csv(path, report, timeline)
            procs = json_data['processes']
            self.assertEqual(len(procs), 1)
            self.assertIn('exit_code', procs[0])
            self.assertEqual(procs[0]['exit_code'], '0xc0000005')
        finally:
            os.unlink(path)

    def test_json_no_exit_code_field_for_zero_exit(self):
        rows = [
            '"8:00:00.0 PM","Explorer.EXE","1000","Process Create","","SUCCESS",'
            '"PID: 2000, Command line: C:\\\\clean.exe"',
            '"8:00:05.0 PM","clean.exe","2000","Process Exit","","SUCCESS",'
            '"Exit Status: 0, User Time: 0.0 seconds, Kernel Time: 0.0 seconds, '
            'Private Bytes: 1,000, Peak Private Bytes: 1,000, '
            'Working Set: 1,000, Peak Working Set: 1,000"',
        ]
        path = _make_csv(rows)
        try:
            report, timeline = [], []
            json_data = Noriben.parse_csv(path, report, timeline)
            procs = json_data['processes']
            self.assertEqual(len(procs), 1)
            self.assertNotIn('exit_code', procs[0])
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
