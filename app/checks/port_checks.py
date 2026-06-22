import asyncio

from app.models import Finding, Severity

COMMON_PORTS: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.MEDIUM),
    22: ("SSH", Severity.INFO),
    23: ("Telnet", Severity.HIGH),
    25: ("SMTP", Severity.INFO),
    80: ("HTTP", Severity.INFO),
    443: ("HTTPS", Severity.INFO),
    445: ("SMB", Severity.HIGH),
    3306: ("MySQL", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.CRITICAL),
    8080: ("HTTP-Alt", Severity.INFO),
    8443: ("HTTPS-Alt", Severity.INFO),
    27017: ("MongoDB", Severity.CRITICAL),
}

RISKY_PORTS = {21, 23, 445, 3306, 3389, 5432, 5900, 6379, 27017}


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


async def check_open_ports(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    open_ports: list[tuple[int, str, Severity]] = []

    tasks = {
        port: _is_port_open(domain, port)
        for port in COMMON_PORTS
    }
    results = await asyncio.gather(*tasks.values())
    port_list = list(tasks.keys())

    for port, is_open in zip(port_list, results):
        if is_open:
            service, _ = COMMON_PORTS[port]
            open_ports.append((port, service, COMMON_PORTS[port][1]))

    if not open_ports:
        findings.append(
            Finding(
                title="Ochiq portlar topilmadi",
                description="Tekshirilgan umumiy portlar yopiq.",
                severity=Severity.INFO,
                category="Port skanerlash",
            )
        )
        return findings

    port_summary = ", ".join(f"{p}/{s}" for p, s, _ in open_ports)
    findings.append(
        Finding(
            title=f"Ochiq portlar: {len(open_ports)} ta",
            description=port_summary,
            severity=Severity.INFO,
            category="Port skanerlash",
        )
    )

    for port, service, default_sev in open_ports:
        if port in RISKY_PORTS:
            findings.append(
                Finding(
                    title=f"Xavfli ochiq port: {port}/{service}",
                    description=f"{service} porti ({port}) internetdan ochiq — hujum yuzasi keng.",
                    severity=Severity.CRITICAL if port in (6379, 27017) else Severity.HIGH,
                    category="Port skanerlash",
                    recommendation=f"{port} portini firewall orqali yoping yoki faqat ichki tarmoqqa cheklang.",
                )
            )
        elif port not in (80, 443, 22):
            findings.append(
                Finding(
                    title=f"Qo'shimcha ochiq port: {port}/{service}",
                    description=f"{service} xizmati ochiq.",
                    severity=default_sev,
                    category="Port skanerlash",
                    recommendation="Keraksiz portlarni yoping.",
                )
            )

    return findings
