import asyncio

import dns.resolver

from app.models import Finding, Severity
from app.infrastructure import SubdomainEntry
from app.target import is_ip

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "admin", "api", "dev",
    "staging", "test", "beta", "mobile", "m", "blog", "shop", "cdn",
    "static", "vpn", "panel", "app", "portal", "login", "secure", "git",
    "demo", "old", "new", "support", "docs", "my", "dashboard", "backend",
    "db", "mysql", "cpanel", "web", "ns1", "ns2", "dns", "mx", "remote",
    "img", "images", "media", "upload", "files", "cloud", "sso", "auth",
]

RISKY_KEYWORDS = ("admin", "dev", "staging", "test", "db", "vpn", "backend", "cpanel")


def _resolve_a(fqdn: str) -> list[str] | None:
    try:
        answers = dns.resolver.resolve(fqdn, "A", lifetime=3.0)
        return [str(r) for r in answers]
    except Exception:
        return None


async def discover_subdomains(base_domain: str, current_host: str) -> tuple[list[SubdomainEntry], list[Finding]]:
    findings: list[Finding] = []
    if is_ip(base_domain):
        return [], findings

    found: list[SubdomainEntry] = []
    seen: set[str] = set()

    async def try_sub(sub: str) -> SubdomainEntry | None:
        fqdn = f"{sub}.{base_domain}"
        ips = await asyncio.to_thread(_resolve_a, fqdn)
        if not ips:
            return None
        risky = any(k in fqdn for k in RISKY_KEYWORDS)
        return SubdomainEntry(name=fqdn, ips=ips, risky=risky)

    results = await asyncio.gather(*[try_sub(sub) for sub in COMMON_SUBDOMAINS])

    for entry in results:
        if entry and entry.name not in seen:
            seen.add(entry.name)
            found.append(entry)

    if current_host not in seen and not is_ip(current_host):
        ips = await asyncio.to_thread(_resolve_a, current_host)
        if ips:
            risky = any(k in current_host for k in RISKY_KEYWORDS)
            found.insert(0, SubdomainEntry(name=current_host, ips=ips, risky=risky))
            seen.add(current_host)

    for entry in found:
        if entry.risky:
            findings.append(
                Finding(
                    title=f"Xavfli subdomen: {entry.name}",
                    description=f"IP: {', '.join(entry.ips)} — maxsus e'tibor talab qiladi.",
                    severity=Severity.MEDIUM,
                    category="Subdomenlar",
                    recommendation="Keraksiz subdomenlarni yoping yoki himoyalang.",
                )
            )

    return found, findings
