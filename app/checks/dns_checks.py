import dns.resolver
import dns.reversename

from app.models import Finding, Severity
from app.target import is_ip


def check_dns_records(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    if is_ip(domain):
        try:
            rev_name = dns.reversename.from_address(domain)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=3.0)
            ptr = ", ".join(str(r) for r in answers)
            findings.append(
                Finding(
                    title="Teskari DNS (PTR)",
                    description=f"IP {domain} → {ptr}",
                    severity=Severity.INFO,
                    category="DNS",
                )
            )
        except Exception:
            findings.append(
                Finding(
                    title="Teskari DNS (PTR) yo'q",
                    description=f"{domain} uchun PTR yozuvi topilmadi.",
                    severity=Severity.INFO,
                    category="DNS",
                )
            )
        return findings

    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(r) for r in answers]
        findings.append(
            Finding(
                title="DNS A yozuvlari",
                description=f"IP manzillar: {', '.join(ips)}",
                severity=Severity.INFO,
                category="DNS",
            )
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        findings.append(
            Finding(
                title="DNS A yozuvi topilmadi",
                description=f"{domain} uchun A yozuvi mavjud emas.",
                severity=Severity.CRITICAL,
                category="DNS",
                recommendation="Domen DNS sozlamalarini tekshiring.",
            )
        )
    except Exception as e:
        findings.append(
            Finding(
                title="DNS tekshiruvida xatolik",
                description=str(e),
                severity=Severity.INFO,
                category="DNS",
            )
        )

    try:
        dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        findings.append(
            Finding(
                title="DMARC yozuvi mavjud",
                description="Email firibgarligiga qarshi DMARC sozlangan.",
                severity=Severity.INFO,
                category="Email xavfsizligi",
            )
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append(
            Finding(
                title="DMARC yozuvi yo'q",
                description="Email firibgarligi va phishing hujumlariga qarshi himoya zaif.",
                severity=Severity.MEDIUM,
                category="Email xavfsizligi",
                recommendation="DMARC DNS yozuvini sozlang.",
            )
        )

    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_found = any("v=spf1" in str(r).lower() for r in answers)
        if spf_found:
            findings.append(
                Finding(
                    title="SPF yozuvi mavjud",
                    description="Email yuborish uchun SPF sozlangan.",
                    severity=Severity.INFO,
                    category="Email xavfsizligi",
                )
            )
        else:
            findings.append(
                Finding(
                    title="SPF yozuvi yo'q",
                    description="Email spoofing hujumlariga qarshi himoya yo'q.",
                    severity=Severity.MEDIUM,
                    category="Email xavfsizligi",
                    recommendation="SPF DNS yozuvini qo'shing.",
                )
            )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        findings.append(
            Finding(
                title="SPF yozuvi yo'q",
                description="TXT yozuvlari topilmadi.",
                severity=Severity.MEDIUM,
                category="Email xavfsizligi",
                recommendation="SPF DNS yozuvini qo'shing.",
            )
        )

    return findings
