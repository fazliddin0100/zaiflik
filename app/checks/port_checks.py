import asyncio

import dns.resolver
import dns.reversename

from app.models import Finding, Severity
from app.infrastructure import PortEntry
from app.target import is_ip

COMMON_PORTS: dict[int, tuple[str, bool]] = {
    21: ("FTP", True),
    22: ("SSH", False),
    23: ("Telnet", True),
    25: ("SMTP", False),
    53: ("DNS", False),
    80: ("HTTP", False),
    110: ("POP3", False),
    143: ("IMAP", False),
    443: ("HTTPS", False),
    445: ("SMB", True),
    3306: ("MySQL", True),
    3389: ("RDP", True),
    5432: ("PostgreSQL", True),
    5900: ("VNC", True),
    6379: ("Redis", True),
    8080: ("HTTP-Alt", False),
    8443: ("HTTPS-Alt", False),
    27017: ("MongoDB", True),
}

CRITICAL_PORTS = {6379, 27017}


async def _is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def scan_ports(host: str) -> tuple[list[PortEntry], list[Finding]]:
    findings: list[Finding] = []
    open_ports: list[PortEntry] = []

    tasks = {port: _is_port_open(host, port) for port in COMMON_PORTS}
    results = await asyncio.gather(*tasks.values())
    port_list = list(tasks.keys())

    for port, is_open in zip(port_list, results):
        if is_open:
            service, risky = COMMON_PORTS[port]
            open_ports.append(PortEntry(port=port, service=service, risky=risky, status="ochiq"))

    for entry in open_ports:
        if not entry.risky:
            continue
        sev = Severity.CRITICAL if entry.port in CRITICAL_PORTS else Severity.HIGH
        findings.append(
            Finding(
                title=f"Xavfli ochiq port: {entry.port}/{entry.service}",
                description=f"{entry.service} porti ({entry.port}) internetdan ochiq.",
                severity=sev,
                category="Port skanerlash",
                recommendation=f"{entry.port} portini firewall orqali yoping.",
            )
        )

    return open_ports, findings


async def scan_ports_for_ips(ips: list[str]) -> dict[str, list[PortEntry]]:
    if not ips:
        return {}

    async def scan_one(ip: str) -> tuple[str, list[PortEntry]]:
        ports, _ = await scan_ports(ip)
        return ip, ports

    results = await asyncio.gather(*[scan_one(ip) for ip in ips[:5]])
    return {ip: ports for ip, ports in results if ports}
