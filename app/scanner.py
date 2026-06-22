import time
import asyncio

from app.models import ScanResult, Finding, Severity, SEVERITY_ORDER
from app.target import parse_target
from app.checks.http_checks import (
    check_https_redirect,
    check_ssl_certificate,
    check_security_headers,
    check_cookies,
    check_sensitive_paths,
)
from app.checks.dns_checks import check_dns_records
from app.checks.port_checks import check_open_ports
from app.checks.xss_checks import check_xss_reflection
from app.checks.subdomain_checks import check_subdomains

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

        result.findings.append(
            Finding(
                title=f"Maqsad turi: {TARGET_LABELS.get(target.target_type, target.target_type)}",
                description=f"Host: {target.host} | Tekshiruv manzili: {target.scan_url}",
                severity=Severity.INFO,
                category="Maqsad",
            )
        )

        check_tasks: list[tuple[str, asyncio.Task | asyncio.Future]] = [
            ("dns", asyncio.to_thread(check_dns_records, target.host)),
            ("https_redirect", check_https_redirect(target.host)),
            ("ssl", check_ssl_certificate(target.host)),
            ("headers", check_security_headers(target.scan_url)),
            ("cookies", check_cookies(target.scan_url)),
            ("paths", check_sensitive_paths(target.base_url)),
            ("ports", check_open_ports(target.host)),
            ("xss", check_xss_reflection(target.scan_url)),
        ]

        if target.target_type != "ip":
            check_tasks.append(
                ("subdomains", check_subdomains(target.base_domain, target.host))
            )

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
