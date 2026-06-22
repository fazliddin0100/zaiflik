import asyncio

import dns.resolver
import dns.reversename

from app.models import Finding, Severity
from app.target import is_ip

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "admin", "api", "dev",
    "staging", "test", "beta", "mobile", "m", "blog", "shop", "cdn",
    "static", "vpn", "panel", "app", "portal", "login", "secure", "git",
    "demo", "old", "new", "support", "docs", "my", "dashboard", "backend",
    "db", "mysql", "cpanel", "web", "ns1", "ns2", "dns", "mx", "remote",
    "img", "images", "media", "upload", "files", "cloud", "sso", "auth",
]


def _resolve_a(fqdn: str) -> list[str] | None:
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3.0)
        return [str(r) for r in answers]
    except Exception:
        return None


async def check_subdomains(base_domain: str, current_host: str) -> list[Finding]:
    findings: list[Finding] = []
    if is_ip(base_domain):
        return findings

    found: list[tuple[str, list[str]]] = []

    async def try_sub(sub: str) -> tuple[str, list[str]] | None:
        fqdn = f"{sub}.{base_domain}"
        ips = await asyncio.to_thread(_resolve_a, fqdn)
        if ips:
            return fqdn, ips
        return None

    results = await asyncio.gather(*[try_sub(sub) for sub in COMMON_SUBDOMAINS])

    seen: set[str] = set()
    for item in results:
        if not item:
            continue
        fqdn, ips = item
        if fqdn in seen:
            continue
        seen.add(fqdn)
        found.append((fqdn, ips))

    if current_host not in seen and not is_ip(current_host):
        ips = await asyncio.to_thread(_resolve_a, current_host)
        if ips:
            found.insert(0, (current_host, ips))

    if not found:
        findings.append(
            Finding(
                title="Qo'shimcha subdomenlar topilmadi",
                description=f"{base_domain} uchun umumiy subdomenlar aniqlanmadi.",
                severity=Severity.INFO,
                category="Subdomenlar",
            )
        )
        return findings

    names = [f[0] for f in found]
    findings.append(
        Finding(
            title=f"Subdomenlar topildi: {len(found)} ta",
            description=", ".join(names[:12]) + ("..." if len(names) > 12 else ""),
            severity=Severity.INFO,
            category="Subdomenlar",
        )
    )

    for fqdn, ips in found:
        sev = Severity.MEDIUM if any(k in fqdn for k in ("admin", "dev", "staging", "test", "db", "vpn")) else Severity.INFO
        findings.append(
            Finding(
                title=f"Subdomen: {fqdn}",
                description=f"IP manzillar: {', '.join(ips)}",
                severity=sev,
                category="Subdomenlar",
                recommendation="Keraksiz subdomenlarni yoping yoki himoyalang." if sev == Severity.MEDIUM else "",
            )
        )

    return findings
