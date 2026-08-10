import unittest

import Noriben


class ProcessNameFromCmdlineTests(unittest.TestCase):

    def test_unquoted_bare_executable(self):
        self.assertEqual(Noriben.process_name_from_cmdline('cmd.exe'), 'cmd.exe')

    def test_unquoted_with_path(self):
        self.assertEqual(
            Noriben.process_name_from_cmdline(r'C:\Windows\System32\cmd.exe /c whoami'),
            'cmd.exe'
        )

    def test_quoted_executable(self):
        self.assertEqual(
            Noriben.process_name_from_cmdline(r'"C:\Windows\System32\notepad.exe" file.txt'),
            'notepad.exe'
        )

    def test_quoted_path_with_spaces(self):
        self.assertEqual(
            Noriben.process_name_from_cmdline(r'"C:\Program Files\App\app.exe" --flag'),
            'app.exe'
        )

    def test_empty_string_returns_unknown(self):
        self.assertEqual(Noriben.process_name_from_cmdline(''), '[unknown]')

    def test_whitespace_only_returns_unknown(self):
        self.assertEqual(Noriben.process_name_from_cmdline('   '), '[unknown]')

    def test_no_arguments(self):
        self.assertEqual(
            Noriben.process_name_from_cmdline(r'C:\tools\malware.exe'),
            'malware.exe'
        )

    def test_leading_whitespace_stripped(self):
        self.assertEqual(
            Noriben.process_name_from_cmdline(r'  cmd.exe /k'),
            'cmd.exe'
        )


if __name__ == '__main__':
    unittest.main()
