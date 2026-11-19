#!/usr/bin/env python3
"""Optional macOS network diagnostics. Default mode performs local reads only."""
import argparse
import ipaddress
import json
import os
import secrets
import socket
import struct
import subprocess
from urllib.parse import urlsplit

COOKIE = b'\x21\x12\xa4\x42'


def parse_stun(packet, transaction):
    """Return an address only for a matching, well-formed Binding response."""
    if (not isinstance(packet, (bytes, bytearray)) or not isinstance(transaction, (bytes, bytearray))
            or len(transaction) != 12 or len(packet) < 20):
        return None
    kind, size = struct.unpack('!HH', packet[:4])
    if (kind != 0x0101 or size % 4 or len(packet) != 20 + size
            or packet[4:8] != COOKIE or packet[8:20] != transaction):
        return None
    offset, mapped = 20, None
    while offset < len(packet):
        if offset + 4 > len(packet):
            return None
        kind, length = struct.unpack('!HH', packet[offset:offset + 4])
        start = offset + 4
        end = start + length
        padded_end = start + ((length + 3) & ~3)
        if padded_end > len(packet):
            return None
        value = packet[start:end]
        if kind in (0x0001, 0x0020):
            if len(value) < 4 or value[0] != 0:
                return None
            family = value[1]
            count = {1: 4, 2: 16}.get(family)
            if count is None or length != count + 4:
                return None
            address = value[4:]
            if kind == 0x0020:
                mask = COOKIE + transaction
                address = bytes(a ^ b for a, b in zip(address, mask))
            parsed = str(ipaddress.ip_address(address))
            if kind == 0x0020:
                mapped = parsed
            elif mapped is None:
                mapped = parsed
        offset = padded_end
    return mapped


def local_read(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def local_report():
    report = {'mode': 'local-only', 'external_probes_sent': False}
    ports = local_read(['/usr/sbin/networksetup', '-listallhardwareports'])
    route = local_read(['/sbin/route', '-n', 'get', 'default'])
    dns = local_read(['/usr/sbin/scutil', '--dns'])
    physical = set()
    if ports is not None:
        for line in ports.splitlines():
            if line.strip().startswith('Device:'):
                name = line.split(':', 1)[1].strip()
                if name.startswith(('en', 'bridge')):
                    physical.add(name)
    interface = None
    if route is not None:
        for line in route.splitlines():
            if line.strip().startswith('interface:'):
                interface = line.split(':', 1)[1].strip()
                break
    report['physical_interfaces_read'] = ports is not None
    report['route_class'] = ('unverified' if interface is None or ports is None else
                             'physical' if interface in physical else
                             'tunnel-candidate' if interface.startswith('utun') else 'other')
    report['dns_config_read'] = dns is not None
    report['dns_server_entries'] = (sum(line.strip().startswith('nameserver[')
                                        for line in dns.splitlines()) if dns is not None else None)
    report['dns_encryption'] = 'unverified: configuration does not prove DoH or remote DNS'
    return report


def validate_proxy(value):
    try:
        uri = urlsplit(value)
        valid = (uri.scheme == 'http' and uri.hostname in ('127.0.0.1', '::1', 'localhost')
                 and uri.port is not None and 1 <= uri.port <= 65535
                 and uri.username is None and uri.password is None
                 and uri.path in ('', '/') and not uri.query and not uri.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise argparse.ArgumentTypeError('use a local HTTP/mixed proxy URL, without credentials')
    return value


def proxy_exit(proxy):
    # Explicit proxy, empty bypass list, no environment proxy fallback.
    env = {k: v for k, v in os.environ.items() if k.lower() not in
           ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    p = subprocess.run(['/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error',
                        '--max-time', '12', '--proxy', proxy, '--noproxy', '',
                        'https://api4.ipify.org'], env=env, capture_output=True,
                       text=True, timeout=15)
    if p.returncode != 0:
        raise ValueError('proxy probe unavailable')
    address = ipaddress.ip_address(p.stdout.strip())
    if address.version != 4 or not address.is_global:
        raise ValueError('invalid echo response')
    return str(address)


def stun_exit(server, port):
    addresses = socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_DGRAM)
    if not addresses:
        raise ValueError('no STUN IPv4 address')
    family, kind, protocol, _, endpoint = addresses[0]
    transaction = secrets.token_bytes(12)
    request = struct.pack('!HH', 1, 0) + COOKIE + transaction
    # A connected UDP socket accepts packets only from the selected endpoint.
    with socket.socket(family, kind, protocol) as udp:
        udp.settimeout(6)
        udp.connect(endpoint)
        udp.send(request)
        address = parse_stun(udp.recv(4096), transaction)
    if address is None:
        raise ValueError('invalid STUN response')
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4 or not parsed.is_global:
        raise ValueError('invalid observed address')
    return address


def main(argv=None):
    parser = argparse.ArgumentParser(description='macOS DNS / HTTP proxy / UDP-STUN diagnostics')
    parser.add_argument('--proxy-url', type=validate_proxy,
                        help='explicitly send an HTTPS echo request through this local HTTP proxy')
    parser.add_argument('--probe-stun', action='store_true',
                        help='opt in to a UDP probe; the STUN server can observe the public source address')
    parser.add_argument('--stun-server', default='stun.l.google.com')
    parser.add_argument('--stun-port', type=int, default=19302)
    args = parser.parse_args(argv)
    if not 1 <= args.stun_port <= 65535:
        parser.error('STUN port must be between 1 and 65535')
    report = local_report()
    report.update(http_proxy_probe='not-tested', udp_stun_probe='not-tested', comparison='unverified')
    http, stun = None, None
    if args.proxy_url:
        report['external_probes_sent'] = True
        try:
            http = proxy_exit(args.proxy_url)
            report['http_proxy_probe'] = 'response-valid'
        except (OSError, ValueError, subprocess.SubprocessError):
            report['http_proxy_probe'] = 'unverified'
    if args.probe_stun:
        report['external_probes_sent'] = True
        try:
            stun = stun_exit(args.stun_server, args.stun_port)
            report['udp_stun_probe'] = 'response-valid'
        except (OSError, ValueError):
            report['udp_stun_probe'] = 'unverified'
    report['mode'] = 'explicit-probes' if report['external_probes_sent'] else 'local-only'
    code = 2
    if http is not None and stun is not None:
        code = 0 if http == stun else 1
        report['comparison'] = 'match' if code == 0 else 'different'
    report['scope'] = 'Only these IPv4 probes; not a browser WebRTC or general leak-safety test'
    report['exit_code'] = code
    # Return conclusions without publishing addresses, credentials or DNS values.
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
