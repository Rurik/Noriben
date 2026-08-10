import unittest

import Noriben


class ProcessTreeTests(unittest.TestCase):

    def test_nested_processes_and_siblings(self):
        events = [
            {
                'process': 'winword.exe',
                'pid': '100',
                'child_pid': '200',
                'cmdline': r'C:\Windows\System32\cmd.exe /c whoami'
            },
            {
                'process': 'cmd.exe',
                'pid': '200',
                'child_pid': '300',
                'cmdline': r'powershell.exe -EncodedCommand Zg=='
            },
            {
                'process': 'winword.exe',
                'pid': '100',
                'child_pid': '400',
                'cmdline': r'"C:\Windows\System32\notepad.exe" note.txt'
            }
        ]

        self.assertEqual(Noriben.format_process_tree(events), [
            'winword.exe:100',
            '├── cmd.exe:200 > "C:\\Windows\\System32\\cmd.exe /c whoami"',
            '│   └── powershell.exe:300 > "powershell.exe -EncodedCommand Zg=="',
            '└── notepad.exe:400 > "C:\\Windows\\System32\\notepad.exe note.txt"'
        ])

    def test_disconnected_process_families_are_separate_roots(self):
        events = [
            {'process': 'a.exe', 'pid': '1', 'child_pid': '2', 'cmdline': 'b.exe'},
            {'process': 'c.exe', 'pid': '3', 'child_pid': '4', 'cmdline': 'd.exe'}
        ]

        self.assertEqual(Noriben.format_process_tree(events), [
            'a.exe:1',
            '└── b.exe:2 > "b.exe"',
            'c.exe:3',
            '└── d.exe:4 > "d.exe"'
        ])

    def test_empty_event_list_returns_empty(self):
        self.assertEqual(Noriben.format_process_tree([]), [])

    def test_single_parent_single_child(self):
        events = [
            {'process': 'cmd.exe', 'pid': '10', 'child_pid': '20', 'cmdline': 'whoami.exe'}
        ]
        result = Noriben.format_process_tree(events)
        self.assertEqual(result[0], 'cmd.exe:10')
        self.assertIn('└──', result[1])
        self.assertIn('whoami.exe:20', result[1])

    def test_quoted_cmdline_strips_quotes_from_label(self):
        """Quotes in cmdline should be removed from the tree label."""
        events = [
            {
                'process': 'explorer.exe',
                'pid': '1',
                'child_pid': '2',
                'cmdline': r'"C:\Windows\System32\notepad.exe" file.txt'
            }
        ]
        result = Noriben.format_process_tree(events)
        # The label should not contain inner quotes
        self.assertNotIn('""', result[1])
        self.assertIn('notepad.exe', result[1])

    def test_child_pid_equals_parent_pid_not_added_as_child(self):
        """A process that spawns itself should not loop."""
        events = [
            {'process': 'loop.exe', 'pid': '5', 'child_pid': '5', 'cmdline': 'loop.exe'}
        ]
        result = Noriben.format_process_tree(events)
        # Should produce one root line with no child connectors
        self.assertEqual(len(result), 1)


if __name__ == '__main__':
    unittest.main()
