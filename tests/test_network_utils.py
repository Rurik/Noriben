import unittest

import Noriben


class ProtocolReplaceTests(unittest.TestCase):

    def test_https_replaced(self):
        self.assertEqual(Noriben.protocol_replace('1.2.3.4:https'), '1.2.3.4:443')

    def test_http_replaced(self):
        self.assertEqual(Noriben.protocol_replace('1.2.3.4:http'), '1.2.3.4:80')

    def test_domain_replaced(self):
        self.assertEqual(Noriben.protocol_replace('8.8.8.8:domain'), '8.8.8.8:53')

    def test_numeric_port_unchanged(self):
        self.assertEqual(Noriben.protocol_replace('1.2.3.4:8080'), '1.2.3.4:8080')

    def test_no_port_unchanged(self):
        self.assertEqual(Noriben.protocol_replace('example.com'), 'example.com')

    def test_multiple_replacements_in_one_string(self):
        # Unlikely in practice but verifies all replacements run
        result = Noriben.protocol_replace('a:https b:http c:domain')
        self.assertIn('443', result)
        self.assertIn('80', result)
        self.assertIn('53', result)


class NetworkSplitHostPortTests(unittest.TestCase):

    def test_ipv4_with_port(self):
        host, port = Noriben.network_split_host_port('1.2.3.4:443')
        self.assertEqual(host, '1.2.3.4')
        self.assertEqual(port, '443')

    def test_ipv4_without_port(self):
        host, port = Noriben.network_split_host_port('1.2.3.4')
        self.assertEqual(host, '1.2.3.4')
        self.assertIsNone(port)

    def test_hostname_with_port(self):
        host, port = Noriben.network_split_host_port('example.com:80')
        self.assertEqual(host, 'example.com')
        self.assertEqual(port, '80')

    def test_hostname_without_port(self):
        host, port = Noriben.network_split_host_port('example.com')
        self.assertEqual(host, 'example.com')
        self.assertIsNone(port)

    def test_ipv6_bracketed_with_port(self):
        host, port = Noriben.network_split_host_port('[::1]:8080')
        self.assertEqual(host, '::1')
        self.assertEqual(port, '8080')

    def test_ipv6_bracketed_without_port(self):
        host, port = Noriben.network_split_host_port('[::1]')
        self.assertEqual(host, '::1')
        self.assertIsNone(port)

    def test_bare_ipv6_address(self):
        host, port = Noriben.network_split_host_port('::1')
        self.assertEqual(host, '::1')
        self.assertIsNone(port)

    def test_leading_trailing_whitespace_stripped(self):
        host, port = Noriben.network_split_host_port('  1.2.3.4:443  ')
        self.assertEqual(host, '1.2.3.4')
        self.assertEqual(port, '443')


if __name__ == '__main__':
    unittest.main()
