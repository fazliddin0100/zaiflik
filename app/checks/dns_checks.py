import dns.resolver

from app.models import Finding, Severity


def check_dns_records(domain: str) -> list[Finding]:
    findings: list[Finding] = []

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
