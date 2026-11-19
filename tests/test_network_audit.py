"""Offline packet-parser and opt-in tests. Never sends an external request."""
import contextlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('network_audit', Path(__file__).resolve().parents[1] / 'network-audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
TID = b'123456789012'


def response(address='198.51.100.42', xor=True, before=b'', after=b''):
    raw = ipaddress.ip_address(address).packed
    family = 1 if len(raw) == 4 else 2
    if xor:
        raw = bytes(a ^ b for a, b in zip(raw, audit.COOKIE + TID))
    value = bytes((0, family)) + b'\x1f\x90' + raw
    body = before + struct.pack('!HH', 0x0020 if xor else 0x0001, len(value)) + value + after
    return struct.pack('!HH', 0x0101, len(body)) + audit.COOKIE + TID + body


class ParserTests(unittest.TestCase):
    def test_xor_ipv4(self):
        self.assertEqual(audit.parse_stun(response(), TID), '198.51.100.42')

    def test_plain_ipv4(self):
        self.assertEqual(audit.parse_stun(response(xor=False), TID), '198.51.100.42')

    def test_xor_ipv6(self):
        self.assertEqual(audit.parse_stun(response('2001:db8::1'), TID), '2001:db8::1')

    def test_plain_ipv6(self):
        self.assertEqual(audit.parse_stun(response('2001:db8::1', xor=False), TID), '2001:db8::1')

    def test_wrong_transaction(self):
        self.assertIsNone(audit.parse_stun(response(), b'abcdefghijkl'))

    def test_bad_transaction_length(self):
        self.assertIsNone(audit.parse_stun(response(), b'x'))

    def test_none_is_invalid(self):
        self.assertIsNone(audit.parse_stun(None, TID))

    def test_short_header(self):
        self.assertIsNone(audit.parse_stun(b'\x01\x01', TID))

    def test_bad_cookie(self):
        p = bytearray(response()); p[4] ^= 1
        self.assertIsNone(audit.parse_stun(p, TID))

    def test_wrong_response_type(self):
        p = bytearray(response()); p[0] = 0x11
        self.assertIsNone(audit.parse_stun(p, TID))

    def test_truncated_body(self):
        self.assertIsNone(audit.parse_stun(response()[:-1], TID))

    def test_trailing_bytes(self):
        self.assertIsNone(audit.parse_stun(response() + b'\x00', TID))

    def test_invalid_attribute_length(self):
        p = bytearray(response()); p[23] = 0x20
        self.assertIsNone(audit.parse_stun(p, TID))

    def test_invalid_family(self):
        p = bytearray(response()); p[25] = 3
        self.assertIsNone(audit.parse_stun(p, TID))

    def test_invalid_reserved_byte(self):
        p = bytearray(response()); p[24] = 1
        self.assertIsNone(audit.parse_stun(p, TID))

    def test_unknown_attribute_with_padding(self):
        self.assertEqual(audit.parse_stun(response(before=b'\x80\x22\x00\x01x\x00\x00\x00'), TID), '198.51.100.42')

    def test_later_malformed_attribute_is_not_ignored(self):
        self.assertIsNone(audit.parse_stun(response(after=b'\x80\x22\x00\x08'), TID))


class OptInTests(unittest.TestCase):
    def invoke(self, args, http='8.8.8.8', stun='8.8.8.8'):
        out = io.StringIO()
        with patch.object(audit, 'local_report', return_value={'external_probes_sent': False}), \
                patch.object(audit, 'proxy_exit', return_value=http) as hp, \
                patch.object(audit, 'stun_exit', return_value=stun) as sp, \
                contextlib.redirect_stdout(out):
            code = audit.main(args)
        return code, json.loads(out.getvalue()), hp, sp

    def test_default_sends_no_probe_and_is_unverified(self):
        code, data, hp, sp = self.invoke([])
        self.assertEqual(code, 2)
        self.assertFalse(data['external_probes_sent'])
        hp.assert_not_called(); sp.assert_not_called()

    def test_proxy_only_does_not_send_stun(self):
        code, _, hp, sp = self.invoke(['--proxy-url', 'http://localhost:8080'])
        self.assertEqual(code, 2); hp.assert_called_once(); sp.assert_not_called()

    def test_stun_only_does_not_send_http(self):
        code, _, hp, sp = self.invoke(['--probe-stun'])
        self.assertEqual(code, 2); hp.assert_not_called(); sp.assert_called_once()

    def test_matching_exit_does_not_print_addresses(self):
        code, data, _, _ = self.invoke(['--proxy-url', 'http://localhost:8080', '--probe-stun'])
        self.assertEqual(code, 0)
        self.assertEqual(data['comparison'], 'match')
        self.assertNotIn('8.8.8.8', json.dumps(data))
        self.assertIn('not a browser WebRTC', data['scope'])

    def test_different_exit_is_not_a_pass(self):
        code, data, _, _ = self.invoke(['--proxy-url', 'http://localhost:8080', '--probe-stun'], stun='9.9.9.9')
        self.assertEqual(code, 1); self.assertEqual(data['comparison'], 'different')

    def test_probe_error_is_unverified_and_redacted(self):
        out = io.StringIO()
        with patch.object(audit, 'local_report', return_value={}), \
                patch.object(audit, 'proxy_exit', side_effect=OSError('sensitive context')), \
                patch.object(audit, 'stun_exit', side_effect=socket.timeout()), \
                contextlib.redirect_stdout(out):
            self.assertEqual(audit.main(['--proxy-url', 'http://localhost:8080', '--probe-stun']), 2)
        self.assertNotIn('sensitive context', out.getvalue())

    def test_local_reads_use_only_local_utilities(self):
        outputs = ['Device: en0\n', 'interface: utun0\n', 'nameserver[0] : local\n']
        with patch.object(audit, 'local_read', side_effect=outputs) as reader, \
                patch.object(socket, 'getaddrinfo', side_effect=AssertionError('external DNS forbidden')):
            result = audit.local_report()
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(result['route_class'], 'tunnel-candidate')
        self.assertFalse(result['external_probes_sent'])
        self.assertEqual(result['dns_server_entries'], 1)

    def test_proxy_requires_loopback_without_credentials(self):
        for url in ['http://example.com:8080', 'socks5://localhost:8080', 'http://user:password@localhost:8080',
                    'http://localhost:8080/path', 'http://localhost:bad', 'http://localhost:0']:
            with self.assertRaises(Exception):
                audit.validate_proxy(url)

    def test_curl_is_forced_through_explicit_proxy(self):
        p = subprocess.CompletedProcess([], 0, '8.8.8.8', '')
        with patch.object(subprocess, 'run', return_value=p) as run:
            audit.proxy_exit('http://localhost:8080')
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ['/usr/bin/curl', '--disable'])
        self.assertEqual(args[args.index('--noproxy') + 1], '')
        self.assertEqual(args[args.index('--proxy') + 1], 'http://localhost:8080')
        self.assertNotIn('https_proxy', {k.lower() for k in run.call_args.kwargs['env']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
