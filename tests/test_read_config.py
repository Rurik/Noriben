"""
Unit tests for Noriben.read_config().

Verifies that read_config() correctly populates the module-level Noriben.config
dict and the approvelist globals from a config file.
"""
import os
import tempfile
import unittest

import Noriben

# Minimal valid config — only the [Noriben] section and one [Filters] entry
# needed to exercise the key paths without requiring a real Procmon install.
_MINIMAL_CONFIG = """\
[Noriben]
procmon = Procmon.exe
hash_type = SHA256
generalize_paths = False
debug = False
yara_folder =
virustotal_api_key =
output_folder =
disable_file_hash = True
txt_extension = txt

[Filters]
global_approvelist =
cmd_approvelist =
file_approvelist =
reg_approvelist =
net_approvelist =
hash_approvelist =
dll_approvelist =
"""


def _write_config(content):
    tf = tempfile.NamedTemporaryFile(
        mode='w', suffix='.config', delete=False, encoding='utf-8'
    )
    tf.write(content)
    tf.close()
    return tf.name


class ReadConfigPopulatesConfigTests(unittest.TestCase):

    def setUp(self):
        # Reset to a known empty state before each test
        Noriben.config = {}

    def test_config_dict_populated_after_read(self):
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertGreater(len(Noriben.config), 0,
                               'Noriben.config should be non-empty after read_config()')
        finally:
            os.unlink(path)

    def test_string_value_read(self):
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertEqual(Noriben.config['hash_type'], 'SHA256')
        finally:
            os.unlink(path)

    def test_boolean_false_converted(self):
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertIs(Noriben.config['generalize_paths'], False)
        finally:
            os.unlink(path)

    def test_boolean_true_converted(self):
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertIs(Noriben.config['disable_file_hash'], True)
        finally:
            os.unlink(path)

    def test_debug_key_present(self):
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertIn('debug', Noriben.config)
            self.assertIs(Noriben.config['debug'], False)
        finally:
            os.unlink(path)

    def test_custom_value_read(self):
        content = _MINIMAL_CONFIG.replace('hash_type = SHA256', 'hash_type = MD5')
        path = _write_config(content)
        try:
            Noriben.read_config(path)
            self.assertEqual(Noriben.config['hash_type'], 'MD5')
        finally:
            os.unlink(path)


class ReadConfigPopulatesApprovelistsTests(unittest.TestCase):

    def setUp(self):
        Noriben.config = {}
        Noriben.global_approvelist = []
        Noriben.cmd_approvelist    = []
        Noriben.file_approvelist   = []
        Noriben.reg_approvelist    = []
        Noriben.net_approvelist    = []
        Noriben.hash_approvelist   = []

    def test_global_approvelist_contains_procmon(self):
        # read_config() always appends the configured procmon exe to global_approvelist
        path = _write_config(_MINIMAL_CONFIG)
        try:
            Noriben.read_config(path)
            self.assertIn('Procmon.exe', Noriben.global_approvelist)
        finally:
            os.unlink(path)

    def test_custom_filter_loaded(self):
        content = _MINIMAL_CONFIG.replace(
            'cmd_approvelist =',
            'cmd_approvelist = svchost.exe'
        )
        path = _write_config(content)
        try:
            Noriben.read_config(path)
            self.assertIn('svchost.exe', Noriben.cmd_approvelist)
        finally:
            os.unlink(path)

    def test_missing_section_exits(self):
        path = _write_config('[WrongSection]\nkey = value\n')
        try:
            with self.assertRaises(SystemExit) as cm:
                Noriben.read_config(path)
            self.assertEqual(cm.exception.code, 12)
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
