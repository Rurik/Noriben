"""
Unit tests for NoribenSandbox.py.

`magic` (python-magic / libmagic) is an optional C-extension that may not be
present in every environment.  We inject a mock into sys.modules before the
first import so the module loads cleanly regardless.
"""
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch, call

# ---------------------------------------------------------------------------
# Stub out the `magic` C-extension before NoribenSandbox is imported.
# The stub satisfies every use-site: magic.Magic(), magic.MagicException.
# ---------------------------------------------------------------------------
_magic_stub = MagicMock()
_magic_stub.MagicException = type('MagicException', (Exception,), {'message': b''})
sys.modules.setdefault('magic', _magic_stub)

import NoribenSandbox  # noqa: E402  (must come after sys.modules patch)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_config():
    """Return a config dict with the keys NoribenSandbox functions need."""
    return {
        'vmrun':        '/usr/bin/vmrun',
        'vmx':          '/VMs/win.vmx',
        'vm_user':      'Admin',
        'vm_pass':      'password',
        'vbox_uuid':    'abc-123',
        'vboxmanage':   '/usr/bin/VBoxManage',
        'vm_snapshot':  'Clean',
        'guest_noriben_path':   r'C:\Users\{}\Desktop',
        'guest_malware_path':   r'C:\Malware\malware_',
        'guest_log_path':       r'C:\Noriben_Logs',
        'guest_zip_path':       r'C:\Tools\zip.exe',
        'guest_temp_zip':       r'C:\Noriben_Logs\report.zip',
        'guest_python_path':    r'C:\Python39\python.exe',
        'timeout_seconds':      30,
        'report_path_structure':        '{}/{}_NoribenReport.zip',
        'host_screenshot_path_structure': '{}/{}.png',
        'host_noriben_path':    '',
        'error_tolerance':      5,
    }


# ---------------------------------------------------------------------------
# noriben_errors dict
# ---------------------------------------------------------------------------

class NoribenErrorsDictTests(unittest.TestCase):

    def test_all_keys_are_integers(self):
        for key in NoribenSandbox.noriben_errors:
            self.assertIsInstance(key, int)

    def test_all_values_are_nonempty_strings(self):
        for code, msg in NoribenSandbox.noriben_errors.items():
            self.assertIsInstance(msg, str)
            self.assertGreater(len(msg), 0, f'Empty message for code {code}')

    def test_expected_codes_present(self):
        for code in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 50]:
            self.assertIn(code, NoribenSandbox.noriben_errors,
                          f'Code {code} missing from noriben_errors')


# ---------------------------------------------------------------------------
# get_error()
# ---------------------------------------------------------------------------

class GetErrorTests(unittest.TestCase):

    def test_known_code_returns_description(self):
        # Spot-check a handful of known codes
        self.assertEqual(NoribenSandbox.get_error(1), 'PML file was not found')
        self.assertEqual(NoribenSandbox.get_error(6), 'Could not find malware file')
        self.assertEqual(NoribenSandbox.get_error(50), 'General error')

    def test_all_known_codes_return_non_default(self):
        for code in NoribenSandbox.noriben_errors:
            self.assertNotEqual(NoribenSandbox.get_error(code), 'Unexpected Error')

    def test_unknown_code_returns_unexpected_error(self):
        self.assertEqual(NoribenSandbox.get_error(999), 'Unexpected Error')
        self.assertEqual(NoribenSandbox.get_error(0), 'Unexpected Error')
        self.assertEqual(NoribenSandbox.get_error(-1), 'Unexpected Error')


# ---------------------------------------------------------------------------
# file_exists()
# ---------------------------------------------------------------------------

class FileExistsTests(unittest.TestCase):

    def test_existing_file_returns_true(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            self.assertTrue(NoribenSandbox.file_exists(path))
        finally:
            os.unlink(path)

    def test_nonexistent_path_returns_false(self):
        self.assertFalse(NoribenSandbox.file_exists('/nonexistent/path/file.txt'))

    def test_directory_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(NoribenSandbox.file_exists(td))

    def test_empty_string_returns_false(self):
        self.assertFalse(NoribenSandbox.file_exists(''))


# ---------------------------------------------------------------------------
# dir_exists()
# ---------------------------------------------------------------------------

class DirExistsTests(unittest.TestCase):

    def test_existing_directory_returns_true(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertTrue(NoribenSandbox.dir_exists(td))

    def test_nonexistent_path_returns_false(self):
        self.assertFalse(NoribenSandbox.dir_exists('/nonexistent/path/dir'))

    def test_file_returns_false(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            path = tf.name
        try:
            self.assertFalse(NoribenSandbox.dir_exists(path))
        finally:
            os.unlink(path)

    def test_empty_string_returns_false(self):
        self.assertFalse(NoribenSandbox.dir_exists(''))


# ---------------------------------------------------------------------------
# read_config()
# ---------------------------------------------------------------------------

class ReadConfigTests(unittest.TestCase):

    def _write_config(self, content):
        tf = tempfile.NamedTemporaryFile(
            mode='w', suffix='.config', delete=False, encoding='utf-8'
        )
        tf.write(content)
        tf.close()
        return tf.name

    def test_string_values_parsed(self):
        path = self._write_config(
            '[Noriben_host]\n'
            'vm_user = TestAdmin\n'
            'vm_pass = secret\n'
        )
        try:
            NoribenSandbox.read_config(path)
            self.assertEqual(NoribenSandbox.config['vm_user'], 'TestAdmin')
            self.assertEqual(NoribenSandbox.config['vm_pass'], 'secret')
        finally:
            os.unlink(path)

    def test_boolean_true_converted(self):
        path = self._write_config(
            '[Noriben_host]\n'
            'debug = True\n'
        )
        try:
            NoribenSandbox.read_config(path)
            self.assertIs(NoribenSandbox.config['debug'], True)
        finally:
            os.unlink(path)

    def test_boolean_false_converted(self):
        path = self._write_config(
            '[Noriben_host]\n'
            'dontrun = False\n'
        )
        try:
            NoribenSandbox.read_config(path)
            self.assertIs(NoribenSandbox.config['dontrun'], False)
        finally:
            os.unlink(path)

    def test_integer_value_stays_as_string(self):
        # configparser returns strings; numeric conversion is left to callers
        path = self._write_config(
            '[Noriben_host]\n'
            'timeout_seconds = 30\n'
        )
        try:
            NoribenSandbox.read_config(path)
            self.assertEqual(NoribenSandbox.config['timeout_seconds'], '30')
        finally:
            os.unlink(path)

    def test_inline_comments_stripped(self):
        path = self._write_config(
            '[Noriben_host]\n'
            'vm_user = Admin  # the guest account\n'
        )
        try:
            NoribenSandbox.read_config(path)
            self.assertEqual(NoribenSandbox.config['vm_user'], 'Admin')
        finally:
            os.unlink(path)

    def test_missing_section_header_exits(self):
        path = self._write_config('no_section_here = value\n')
        try:
            with self.assertRaises(SystemExit) as cm:
                NoribenSandbox.read_config(path)
            self.assertEqual(cm.exception.code, 12)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# get_magic()
# ---------------------------------------------------------------------------

class GetMagicTests(unittest.TestCase):

    def setUp(self):
        NoribenSandbox.debug = False

    def test_returns_magic_result_string(self):
        handle = MagicMock()
        handle.from_file.return_value = 'PE32 executable (GUI) Intel 80386'
        result = NoribenSandbox.get_magic(handle, 'sample.exe')
        self.assertEqual(result, 'PE32 executable (GUI) Intel 80386')

    def test_magic_exception_returns_empty_string(self):
        err = NoribenSandbox.noriben_errors  # just need a known object; use the real MagicException stub
        MagicExc = _magic_stub.MagicException
        exc = MagicExc()
        exc.message = b'some other error'

        handle = MagicMock()
        handle.from_file.side_effect = exc
        result = NoribenSandbox.get_magic(handle, 'sample.exe')
        self.assertEqual(result, '')

    def test_magic_exception_missing_files_returns_empty_string(self):
        MagicExc = _magic_stub.MagicException
        exc = MagicExc()
        exc.message = b'could not find any magic files!'

        handle = MagicMock()
        handle.from_file.side_effect = exc
        result = NoribenSandbox.get_magic(handle, 'sample.exe')
        self.assertEqual(result, '')

    def test_debug_mode_prints_result(self):
        NoribenSandbox.debug = True
        handle = MagicMock()
        handle.from_file.return_value = 'DOS batch file'
        with patch('builtins.print') as mock_print:
            NoribenSandbox.get_magic(handle, 'run.bat')
        printed = ' '.join(str(a) for call_args in mock_print.call_args_list
                           for a in call_args[0])
        self.assertIn('DOS batch file', printed)


# ---------------------------------------------------------------------------
# run_postexec_script()
# ---------------------------------------------------------------------------

class RunPostexecScriptTests(unittest.TestCase):

    def setUp(self):
        NoribenSandbox.debug = False
        NoribenSandbox.config = _minimal_config()

    def _write_script(self, lines):
        tf = tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False, encoding='utf-8'
        )
        tf.write('\n'.join(lines) + '\n')
        tf.close()
        return tf.name

    def test_comment_lines_skipped(self):
        path = self._write_script(['# this is a comment'])
        try:
            with patch('NoribenSandbox.execute') as mock_exec, \
                 patch('NoribenSandbox.copy_file_to_zip') as mock_copy:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_exec.assert_not_called()
            mock_copy.assert_not_called()
        finally:
            os.unlink(path)

    def test_empty_lines_skipped(self):
        path = self._write_script(['', '   ', ''])
        try:
            with patch('NoribenSandbox.execute') as mock_exec, \
                 patch('NoribenSandbox.copy_file_to_zip') as mock_copy:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_exec.assert_not_called()
            mock_copy.assert_not_called()
        finally:
            os.unlink(path)

    def test_sleep_calls_time_sleep(self):
        path = self._write_script(['sleep 3'])
        try:
            with patch('NoribenSandbox.time.sleep') as mock_sleep:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_sleep.assert_called_once_with(3)
        finally:
            os.unlink(path)

    def test_sleep_bad_value_does_not_raise(self):
        path = self._write_script(['sleep notanumber'])
        try:
            with patch('NoribenSandbox.time.sleep') as mock_sleep:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_sleep.assert_not_called()
        finally:
            os.unlink(path)

    def test_collect_calls_copy_file_to_zip(self):
        path = self._write_script([r'collect C:\Windows\system32\evil.dll'])
        try:
            with patch('NoribenSandbox.copy_file_to_zip') as mock_copy:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_copy.assert_called_once_with('vmrun_cmd', r'C:\Windows\system32\evil.dll')
        finally:
            os.unlink(path)

    def test_exec_calls_execute_with_nowait(self):
        path = self._write_script([r'exec C:\tools\cleanup.exe --silent'])
        try:
            with patch('NoribenSandbox.execute', return_value=0) as mock_exec:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            self.assertEqual(mock_exec.call_count, 1)
            cmd_used = mock_exec.call_args[0][0]
            self.assertIn('-noWait', cmd_used)
        finally:
            os.unlink(path)

    def test_execwait_calls_execute_without_nowait(self):
        path = self._write_script([r'execwait C:\tools\cleanup.exe'])
        try:
            with patch('NoribenSandbox.execute', return_value=0) as mock_exec:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            cmd_used = mock_exec.call_args[0][0]
            self.assertNotIn('-noWait', cmd_used)
        finally:
            os.unlink(path)

    def test_unknown_directive_skipped(self):
        path = self._write_script(['unknown_directive something'])
        try:
            with patch('NoribenSandbox.execute') as mock_exec, \
                 patch('NoribenSandbox.copy_file_to_zip') as mock_copy:
                NoribenSandbox.run_postexec_script(path, 'vmrun_cmd')
            mock_exec.assert_not_called()
            mock_copy.assert_not_called()
        finally:
            os.unlink(path)

    def test_mixed_script_processes_all_directives(self):
        path = self._write_script([
            '# setup',
            '',
            'sleep 1',
            r'collect C:\logs\output.txt',
            r'execwait C:\tools\report.exe',
        ])
        try:
            with patch('NoribenSandbox.time.sleep') as mock_sleep, \
                 patch('NoribenSandbox.copy_file_to_zip') as mock_copy, \
                 patch('NoribenSandbox.execute', return_value=0) as mock_exec:
                NoribenSandbox.run_postexec_script(path, 'base_cmd')
            mock_sleep.assert_called_once_with(1)
            mock_copy.assert_called_once()
            mock_exec.assert_called_once()
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# copy_file_to_zip()
# ---------------------------------------------------------------------------

class CopyFileToZipTests(unittest.TestCase):

    def setUp(self):
        NoribenSandbox.config = _minimal_config()
        NoribenSandbox.error_count = 0

    def test_success_returns_zero(self):
        with patch('NoribenSandbox.execute', return_value=0):
            result = NoribenSandbox.copy_file_to_zip('base_cmd', r'C:\file.txt')
        self.assertEqual(result, 0)

    def test_file_not_in_guest_increments_error_count(self):
        # First execute() call checks fileExistsInGuest — non-zero = not found
        with patch('NoribenSandbox.execute', return_value=1):
            NoribenSandbox.copy_file_to_zip('base_cmd', r'C:\missing.txt')
        self.assertGreater(NoribenSandbox.error_count, 0)

    def test_file_not_in_guest_returns_nonzero(self):
        with patch('NoribenSandbox.execute', return_value=1):
            result = NoribenSandbox.copy_file_to_zip('base_cmd', r'C:\missing.txt')
        self.assertNotEqual(result, 0)

    def test_xcopy_failure_increments_error_count(self):
        # First call succeeds (file exists), second (xcopy) fails
        with patch('NoribenSandbox.execute', side_effect=[0, 1, 0]):
            NoribenSandbox.copy_file_to_zip('base_cmd', r'C:\file.txt')
        self.assertGreater(NoribenSandbox.error_count, 0)

    def test_all_three_execute_calls_made_on_success(self):
        with patch('NoribenSandbox.execute', return_value=0) as mock_exec:
            NoribenSandbox.copy_file_to_zip('base_cmd', r'C:\file.txt')
        self.assertEqual(mock_exec.call_count, 3)


if __name__ == '__main__':
    unittest.main()
