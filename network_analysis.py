"""Bounded, opt-in TCP connectivity checks for owned local/private hosts.

No public IP scanning, service probing, packet crafting, or banner collection.
"""
from __future__ import annotations
import concurrent.futures
from datetime import datetime, timezone
import ipaddress
import socket
import time

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 25: 'SMTP', 53: 'DNS (TCP)', 80: 'HTTP',
    110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 587: 'SMTP submission', 993: 'IMAPS',
    995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle DB', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP alternate', 8443: 'HTTPS alternate',
}
MAX_PORTS = 24
MAX_TIMEOUT = 0.8


def parse_ports(text: str) -> list[int]:
    """Parse at most 24 explicitly enumerated TCP ports (no ranges)."""
    chunks = [p.strip() for p in text.split(',')]
    if not chunks or any(not p.isdecimal() for p in chunks):
        raise ValueError('Enter comma-separated port numbers, e.g. 22,80,443.')
    ports = sorted(set(int(p) for p in chunks))
    if len(ports) > MAX_PORTS or any(p < 1 or p > 65535 for p in ports):
        raise ValueError('Use 1–65535 and at most 24 individual ports.')
    return ports


def validate_target(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Literal loopback/RFC1918/IPv6 ULA only; rejects DNS and special ranges."""
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ValueError('Enter a literal local/private IP address (not a hostname).') from exc
    if isinstance(ip, ipaddress.IPv4Address):
        allowed = ip.is_loopback or any(ip in ipaddress.ip_network(net) for net in (
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    else:
        allowed = ip.is_loopback or ip in ipaddress.ip_network('fc00::/7')
    if not allowed:
        raise ValueError('Only loopback and private-network addresses are supported; public targets are blocked.')
    return ip


def _connect(ip, port: int, timeout: float) -> dict:
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    address = (str(ip), port, 0, 0) if ip.version == 6 else (str(ip), port)
    start = time.monotonic()
    status = 'filtered_or_unreachable'
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex(address)
            if code == 0:
                status = 'open'
            elif code in (61, 111, 10061):
                status = 'closed'
        except (OSError, TimeoutError):
            pass
    return {'port': port, 'protocol': 'TCP', 'service_hint': COMMON_PORTS.get(port, 'Unknown'),
            'status': status, 'elapsed_ms': round((time.monotonic() - start) * 1000, 1)}


def analyze_network(target: str, ports_text: str, authorized: bool = False) -> dict:
    """One target, explicit port list, bounded concurrency and socket timeouts."""
    if not authorized:
        raise ValueError('Confirm that you own or are authorized to assess this host.')
    ip = validate_target(target)
    ports = parse_ports(ports_text)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda p: _connect(ip, p, MAX_TIMEOUT), ports))
    open_ports = [r for r in rows if r['status'] == 'open']
    return {
        'module': 'network', 'target': str(ip), 'ip_version': ip.version,
        'scope': 'Single authorized local/private IP; TCP connect only',
        'checked_at_utc': datetime.now(timezone.utc).isoformat(),
        'ports_checked': len(rows), 'open_count': len(open_ports),
        'closed_count': sum(r['status'] == 'closed' for r in rows),
        'inconclusive_count': sum(r['status'] == 'filtered_or_unreachable' for r in rows),
        'results': rows,
        'note': ('Open means a TCP connection succeeded from the Streamlit server, not that a service '
                 'is vulnerable. Service labels are port-number hints, not verified software. '
                 'Timeouts do not prove filtering; cloud-hosted Streamlit may not reach your LAN.'),
    }
