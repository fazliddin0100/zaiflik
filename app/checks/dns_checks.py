import dns.resolver
import dns.reversename

from app.models import Finding, Severity
from app.target import is_ip


def gather_dns_info(host: str) -> tuple[dict, list[Finding]]:
    findings: list[Finding] = []
    info: dict = {
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "txt": [],
        "ptr": [],
        "spf": False,
        "dmarc": False,
    }

    if is_ip(host):
        try:
            rev_name = dns.reversename.from_address(host)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=3.0)
            info["ptr"] = [str(r).rstrip(".") for r in answers]
        except Exception:
            info["ptr"] = []
        return info, findings

    try:
        info["a"] = [str(r) for r in dns.resolver.resolve(host, "A", lifetime=3.0)]
    except Exception:
        findings.append(
            Finding(
                title="DNS A yozuvi topilmadi",
                description=f"{host} uchun A yozuvi mavjud emas.",
                severity=Severity.CRITICAL,
                category="DNS",
                recommendation="Domen DNS sozlamalarini tekshiring.",
            )
        )

    try:
        info["aaaa"] = [str(r) for r in dns.resolver.resolve(host, "AAAA", lifetime=3.0)]
    except Exception:
        pass

    try:
        info["mx"] = [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(host, "MX", lifetime=3.0)]
    except Exception:
        pass

    try:
        info["ns"] = [str(r).rstrip(".") for r in dns.resolver.resolve(host, "NS", lifetime=3.0)]
    except Exception:
        pass

    try:
        info["txt"] = [str(r) for r in dns.resolver.resolve(host, "TXT", lifetime=3.0)]
        info["spf"] = any("v=spf1" in t.lower() for t in info["txt"])
    except Exception:
        pass

    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{host}", "TXT", lifetime=3.0)
        info["dmarc"] = True
        info["dmarc_record"] = [str(r) for r in dmarc]
    except Exception:
        info["dmarc"] = False

    if not info["spf"]:
        findings.append(
            Finding(
                title="SPF yozuvi yo'q",
                description="Email spoofing hujumlariga qarshi himoya yo'q.",
                severity=Severity.MEDIUM,
                category="Email xavfsizligi",
                recommendation="SPF DNS yozuvini qo'shing.",
            )
        )

    if not info["dmarc"]:
        findings.append(
            Finding(
                title="DMARC yozuvi yo'q",
                description="Email firibgarligi va phishing hujumlariga qarshi himoya zaif.",
                severity=Severity.MEDIUM,
                category="Email xavfsizligi",
                recommendation="DMARC DNS yozuvini sozlang.",
            )
        )

    return info, findings
