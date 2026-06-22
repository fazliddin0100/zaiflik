import time
import asyncio

from app.models import ScanResult, Finding, Severity, SEVERITY_ORDER
from app.target import parse_target
from app.infrastructure import InfrastructureInfo
from app.checks.http_checks import (
    check_https_redirect,
    check_ssl_certificate,
    check_security_headers,
    check_cookies,
    check_sensitive_paths,
)
from app.checks.dns_checks import gather_dns_info
from app.checks.port_checks import scan_ports, scan_ports_for_ips
from app.checks.xss_checks import check_xss_reflection
from app.checks.subdomain_checks import discover_subdomains

TARGET_LABELS = {
    "domain": "Domen",
    "ip": "IP manzil",
    "url": "URL",
}


class VulnerabilityScanner:
    async def scan(self, target_input: str) -> ScanResult:
        start = time.perf_counter()
        target = parse_target(target_input)
        result = ScanResult(
            domain=target.host,
            url=target.scan_url,
            target_type=target.target_type,
            raw_input=target.raw,
        )

        infra = InfrastructureInfo(host=target.host)

        dns_info, dns_findings = await asyncio.to_thread(gather_dns_info, target.host)
        infra.dns = dns_info
        infra.primary_ips = dns_info.get("a", []) or ([target.host] if target.target_type == "ip" else [])

        port_entries, port_findings = await scan_ports(target.host)
        infra.ports = port_entries

        sub_entries: list = []
        sub_findings: list = []
        if target.target_type != "ip":
            sub_entries, sub_findings = await discover_subdomains(target.base_domain, target.host)
            infra.subdomains = sub_entries

        infra.unique_ips = InfrastructureInfo.collect_unique_ips(infra.primary_ips, sub_entries)

        if len(infra.unique_ips) > 1 or (infra.unique_ips and infra.unique_ips[0] != target.host):
            ports_by_ip = await scan_ports_for_ips(infra.unique_ips)
            if ports_by_ip:
                infra.dns["ports_by_ip"] = {
                    ip: [{"port": p.port, "service": p.service, "risky": p.risky} for p in ports]
                    for ip, ports in ports_by_ip.items()
                }

        result.infrastructure = infra

        result.findings.extend(dns_findings)
        result.findings.extend(port_findings)
        result.findings.extend(sub_findings)

        check_tasks = [
            ("https_redirect", check_https_redirect(target.host)),
            ("ssl", check_ssl_certificate(target.host)),
            ("headers", check_security_headers(target.scan_url)),
            ("cookies", check_cookies(target.scan_url)),
            ("paths", check_sensitive_paths(target.base_url)),
            ("xss", check_xss_reflection(target.scan_url)),
        ]

        gathered = await asyncio.gather(
            *(task for _, task in check_tasks),
            return_exceptions=True,
        )

        for (name, _), item in zip(check_tasks, gathered):
            if isinstance(item, Exception):
                result.findings.append(
                    Finding(
                        title=f"{name} tekshiruvida xatolik",
                        description=str(item),
                        severity=Severity.INFO,
                        category="Tizim",
                    )
                )
            elif isinstance(item, list):
                result.findings.extend(item)

        result.findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
        result.scan_duration_ms = int((time.perf_counter() - start) * 1000)
        return result
