"""
Unit tests for generalize_vars_init() and generalize_var().

generalize_var() is a Windows-only feature: on macOS/Linux it returns the
input unchanged (early return on sys.platform check).  The substitution logic
is therefore tested by patching sys.platform to 'win32' and pre-populating
path_general_list with known entries, bypassing the generalize_vars_init()
re-initialisation call via a mock.
"""
import sys
import unittest
from unittest.mock import patch

import Noriben


def _setup_globals():
    Noriben.config = {'debug': False}
    Noriben.path_general_list = []


class GeneralizeVarsInitTests(unittest.TestCase):

    def setUp(self):
        _setup_globals()

    def test_populates_path_general_list(self):
        Noriben.generalize_vars_init()
        self.assertGreater(len(Noriben.path_general_list), 0)

    def test_each_entry_is_two_element_list(self):
        Noriben.generalize_vars_init()
        for entry in Noriben.path_general_list:
            self.assertEqual(len(entry), 2,
                             f'Expected [var, resolved] pair, got: {entry}')

    def test_entries_contain_percent_var_names(self):
        Noriben.generalize_vars_init()
        var_names = [entry[0] for entry in Noriben.path_general_list]
        self.assertTrue(any('%' in v for v in var_names),
                        'Expected at least one %%VAR%% name in path_general_list')


class GeneralizeVarNonWindowsTests(unittest.TestCase):
    """On macOS/Linux generalize_var() is a pass-through."""

    def setUp(self):
        _setup_globals()

    def test_returns_path_unchanged_on_darwin(self):
        with patch.object(sys, 'platform', 'darwin'):
            result = Noriben.generalize_var(r'C:\Windows\System32\cmd.exe')
        self.assertEqual(result, r'C:\Windows\System32\cmd.exe')

    def test_returns_path_unchanged_on_linux(self):
        with patch.object(sys, 'platform', 'linux'):
            result = Noriben.generalize_var(r'C:\Users\admin\AppData\Roaming\evil.exe')
        self.assertEqual(result, r'C:\Users\admin\AppData\Roaming\evil.exe')

    def test_empty_string_returned_unchanged(self):
        with patch.object(sys, 'platform', 'darwin'):
            result = Noriben.generalize_var('')
        self.assertEqual(result, '')


class GeneralizeVarSubstitutionTests(unittest.TestCase):
    """Test the regex substitution logic with a manually constructed list."""

    def setUp(self):
        _setup_globals()

    def _run_generalize(self, path, replacements):
        """
        Call generalize_var() with sys.platform patched to win32 and
        path_general_list pre-set to `replacements` (list of [var, pattern]).
        generalize_vars_init() is mocked out to prevent it from overwriting
        the pre-set list.
        """
        Noriben.path_general_list = replacements
        with patch.object(sys, 'platform', 'win32'), \
             patch.object(Noriben, 'generalize_vars_init'):
            return Noriben.generalize_var(path)

    def test_single_substitution(self):
        # generalize_vars_init doubles backslashes so the value is a valid regex
        result = self._run_generalize(
            r'C:\Windows\System32\cmd.exe',
            [['%WinDir%', r'C:\\Windows']],
        )
        self.assertEqual(result, r'%WinDir%\System32\cmd.exe')

    def test_no_match_returns_original(self):
        result = self._run_generalize(
            r'C:\Tools\evil.exe',
            [['%WinDir%', r'C:\\Windows']],
        )
        self.assertEqual(result, r'C:\Tools\evil.exe')

    def test_empty_list_returns_original(self):
        result = self._run_generalize(r'C:\Windows\notepad.exe', [])
        self.assertEqual(result, r'C:\Windows\notepad.exe')

    def test_multiple_replacements_applied(self):
        result = self._run_generalize(
            r'C:\Windows\System32\cmd.exe',
            [
                ['%WinDir%',   r'C:\\Windows'],
                ['%System32%', r'C:\\Windows\\System32'],
            ],
        )
        # Both patterns match; order determines which wins (first match substitutes first)
        self.assertIn('%', result)


if __name__ == '__main__':
    unittest.main()
