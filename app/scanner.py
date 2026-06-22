import time
import asyncio

from app.models import ScanResult, Finding, Severity, SEVERITY_ORDER
from app.checks.http_checks import (
    normalize_domain,
    normalize_url,
    check_https_redirect,
    check_ssl_certificate,
    check_security_headers,
    check_cookies,
    check_sensitive_paths,
)
from app.checks.dns_checks import check_dns_records
from app.checks.port_checks import check_open_ports
from app.checks.xss_checks import check_xss_reflection


class VulnerabilityScanner:
    async def scan(self, domain: str) -> ScanResult:
        start = time.perf_counter()
        domain = normalize_domain(domain)
        url = normalize_url(domain)
        result = ScanResult(domain=domain, url=url)

        check_tasks = [
            ("dns", asyncio.to_thread(check_dns_records, domain)),
            ("https_redirect", check_https_redirect(domain)),
            ("ssl", check_ssl_certificate(domain)),
            ("headers", check_security_headers(url)),
            ("cookies", check_cookies(url)),
            ("paths", check_sensitive_paths(url)),
            ("ports", check_open_ports(domain)),
            ("xss", check_xss_reflection(url)),
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
