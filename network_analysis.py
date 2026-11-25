"""Bounded, opt-in TCP connectivity checks for authorized hosts.

Supports literal public and private IPv4/IPv6 targets.
No service probing, packet crafting, banner collection, or vulnerability
exploitation is performed.

Open means that a TCP connection succeeded from the machine running
ThreatNova. It does NOT mean that the service is vulnerable.
"""

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import ipaddress
import socket
import time


# ---------------------------------------------------------
# Common TCP ports
# ---------------------------------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS (TCP)",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
}


# ---------------------------------------------------------
# Safety / performance limits
# ---------------------------------------------------------

# Maximum number of individual ports that can be checked at once.
MAX_PORTS = 24

# Maximum socket wait time for each connection attempt.
MAX_TIMEOUT = 0.8

# Maximum simultaneous TCP connection attempts.
MAX_WORKERS = 4


# ---------------------------------------------------------
# Port parsing
# ---------------------------------------------------------

def parse_ports(text: str) -> list[int]:
    """
    Parse comma-separated TCP ports.

    Example:
        22,80,443

    A maximum of 24 individual ports is permitted.
    Port ranges such as 1-1000 are intentionally unsupported.
    """

    if not isinstance(text, str) or not text.strip():
        raise ValueError(
            "Enter comma-separated port numbers, e.g. 22,80,443."
        )

    chunks = [p.strip() for p in text.split(",")]

    # Reject blank values, non-numeric values and ranges.
    if any(not p or not p.isdecimal() for p in chunks):
        raise ValueError(
            "Enter comma-separated individual port numbers, "
            "e.g. 22,80,443. Port ranges are not supported."
        )

    ports = sorted(set(int(p) for p in chunks))

    if len(ports) > MAX_PORTS:
        raise ValueError(
            f"A maximum of {MAX_PORTS} individual ports can be checked."
        )

    if any(p < 1 or p > 65535 for p in ports):
        raise ValueError(
            "Ports must be between 1 and 65535."
        )

    return ports


# ---------------------------------------------------------
# IP validation
# ---------------------------------------------------------

def validate_target(
    target: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Validate a literal IPv4 or IPv6 address.

    Public IP addresses are permitted.

    Examples accepted:
        127.0.0.1
        192.168.1.10
        10.0.0.5
        1.1.1.1
        8.8.8.8
        2606:4700:4700::1111

    Hostnames such as example.com are intentionally not accepted.
    """

    if not isinstance(target, str) or not target.strip():
        raise ValueError(
            "Enter a valid literal IPv4 or IPv6 address."
        )

    try:
        ip = ipaddress.ip_address(target.strip())

    except ValueError as exc:
        raise ValueError(
            "Enter a valid literal IPv4 or IPv6 address "
            "(not a hostname)."
        ) from exc

    # Reject unspecified addresses such as 0.0.0.0 / ::
    if ip.is_unspecified:
        raise ValueError(
            "Unspecified addresses such as 0.0.0.0 or :: "
            "cannot be assessed."
        )

    # Reject multicast because TCP connectivity checks do not make
    # sense for this application's intended use.
    if ip.is_multicast:
        raise ValueError(
            "Multicast addresses are not supported."
        )

    return ip


# ---------------------------------------------------------
# Individual TCP connection check
# ---------------------------------------------------------

def _connect(ip, port: int, timeout: float) -> dict:
    """
    Attempt a normal TCP connection to one IP/port.

    Possible statuses:

        open
            TCP connection succeeded.

        closed
            Host explicitly refused the TCP connection.

        filtered_or_unreachable
            No definitive response was obtained within the
            bounded connection attempt.

    No application-layer data is sent and no banner is collected.
    """

    family = (
        socket.AF_INET6
        if ip.version == 6
        else socket.AF_INET
    )

    if ip.version == 6:
        address = (str(ip), port, 0, 0)
    else:
        address = (str(ip), port)

    start = time.monotonic()

    status = "filtered_or_unreachable"
    error_code = None

    try:
        with socket.socket(
            family,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            code = sock.connect_ex(address)

            error_code = code

            # Successful TCP connection.
            if code == 0:
                status = "open"

            # Common connection-refused error codes:
            #
            # 61    -> macOS / BSD
            # 111   -> Linux
            # 10061 -> Windows
            #
            # A refusal means the host responded but nothing is
            # accepting TCP connections on that port.
            elif code in (61, 111, 10061):
                status = "closed"

            else:
                status = "filtered_or_unreachable"

    except (OSError, TimeoutError):
        status = "filtered_or_unreachable"

    elapsed_ms = round(
        (time.monotonic() - start) * 1000,
        1
    )

    return {
        "port": port,
        "protocol": "TCP",
        "service_hint": COMMON_PORTS.get(
            port,
            "Unknown"
        ),
        "status": status,
        "elapsed_ms": elapsed_ms,
        "socket_result_code": error_code,
    }


# ---------------------------------------------------------
# Main network-analysis function
# ---------------------------------------------------------

def analyze_network(
    target: str,
    ports_text: str,
    authorized: bool = False,
) -> dict:
    """
    Perform bounded TCP connectivity checks.

    Requirements:
        - User must confirm authorization.
        - Target must be a literal IPv4/IPv6 address.
        - Maximum 24 explicitly listed ports.
        - Maximum four concurrent workers.
        - 0.8 second timeout per TCP connection.

    Public IP addresses are supported, but the user is responsible
    for ensuring they are authorized to assess the target.
    """

    # -----------------------------------------------------
    # Authorization confirmation
    # -----------------------------------------------------

    if not authorized:
        raise ValueError(
            "Confirm that you own or are authorized "
            "to assess this host."
        )

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    ip = validate_target(target)

    ports = parse_ports(ports_text)

    # -----------------------------------------------------
    # Run bounded TCP checks
    # -----------------------------------------------------

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as pool:

        rows = list(
            pool.map(
                lambda port: _connect(
                    ip,
                    port,
                    MAX_TIMEOUT
                ),
                ports,
            )
        )

    # -----------------------------------------------------
    # Summarize results
    # -----------------------------------------------------

    open_ports = [
        row
        for row in rows
        if row["status"] == "open"
    ]

    closed_ports = [
        row
        for row in rows
        if row["status"] == "closed"
    ]

    inconclusive_ports = [
        row
        for row in rows
        if row["status"]
        == "filtered_or_unreachable"
    ]

    # -----------------------------------------------------
    # Determine address type for display
    # -----------------------------------------------------

    if ip.is_loopback:
        address_type = "Loopback"

    elif ip.is_private:
        address_type = "Private"

    else:
        address_type = "Public"

    # -----------------------------------------------------
    # Return structured result
    # -----------------------------------------------------

    return {
        "module": "network",

        "target": str(ip),

        "ip_version": ip.version,

        "address_type": address_type,

        "scope": (
            "Single authorized IPv4/IPv6 address; "
            "bounded TCP connect checks only"
        ),

        "checked_at_utc": (
            datetime.now(timezone.utc).isoformat()
        ),

        "ports_checked": len(rows),

        "open_count": len(open_ports),

        "closed_count": len(closed_ports),

        "inconclusive_count": len(
            inconclusive_ports
        ),

        "results": rows,

        "note": (
            "Open means that a TCP connection succeeded "
            "from the server running ThreatNova. It does "
            "not mean that the service is vulnerable. "
            "Service labels are based only on commonly "
            "associated port numbers and do not verify "
            "which software is actually running. "
            "A timeout or unreachable result does not "
            "prove that a firewall is filtering the port."
        ),
    }
