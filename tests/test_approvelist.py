import unittest

import Noriben


def _field(process='test.exe', pid='100', operation='CreateFile',
           path='C:\\test\\file.txt', result='SUCCESS', detail=''):
    """Helper: build a minimal csv.DictReader-style row."""
    return {
        'Process Name': process,
        'PID': pid,
        'Operation': operation,
        'Path': path,
        'Result': result,
        'Detail': detail,
    }


class ApprovelistScanTests(unittest.TestCase):

    def setUp(self):
        # Ensure global_approvelist is empty so tests are isolated
        Noriben.global_approvelist = []
        Noriben.config = {'debug': False}

    def test_no_match_returns_false(self):
        self.assertFalse(Noriben.approvelist_scan(['goodapp.exe'], _field(process='evil.exe')))

    def test_exact_process_name_match_returns_true(self):
        self.assertTrue(Noriben.approvelist_scan(['evil.exe'], _field(process='evil.exe')))

    def test_substring_match_in_path_returns_true(self):
        # Use a backslash-free substring so the double-escape in approvelist_scan
        # doesn't mangle the pattern (backslashes are doubled for regex on Windows paths)
        self.assertTrue(
            Noriben.approvelist_scan(
                ['Temp'],
                _field(path=r'C:\Windows\Temp\payload.exe')
            )
        )

    def test_regex_pattern_matches(self):
        # Dot-star without backslash is safe cross-platform
        self.assertTrue(
            Noriben.approvelist_scan(
                ['evil.*dropper'],
                _field(process='evil_dropper.exe')
            )
        )

    def test_global_approvelist_match_returns_true(self):
        Noriben.global_approvelist = ['globalblock.exe']
        self.assertTrue(Noriben.approvelist_scan([], _field(process='globalblock.exe')))

    def test_global_approvelist_no_match_returns_false(self):
        Noriben.global_approvelist = ['globalblock.exe']
        self.assertFalse(Noriben.approvelist_scan([], _field(process='other.exe')))

    def test_match_is_case_insensitive(self):
        self.assertTrue(Noriben.approvelist_scan(['EVIL.EXE'], _field(process='evil.exe')))

    def test_invalid_regex_returns_false(self):
        # An invalid regex pattern should not raise; approvelist_scan catches re.error
        self.assertFalse(Noriben.approvelist_scan(['[invalid'], _field(process='evil.exe')))

    def test_empty_approvelist_returns_false(self):
        self.assertFalse(Noriben.approvelist_scan([], _field()))

    def test_match_on_detail_field(self):
        self.assertTrue(
            Noriben.approvelist_scan(
                ['Desired Access: Read Attributes'],
                _field(detail='Desired Access: Read Attributes')
            )
        )


if __name__ == '__main__':
    unittest.main()
