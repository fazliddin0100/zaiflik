import re
import ssl
import socket
from datetime import datetime, timezone

import httpx

from app.models import Finding, Severity
from app.target import normalize_domain, normalize_url, parse_target

__all__ = ["normalize_domain", "normalize_url", "parse_target"]


async def check_https_redirect(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    http_url = f"http://{domain}"

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            resp = await client.get(http_url)

        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                findings.append(
                    Finding(
                        title="HTTP dan HTTPS ga yo'naltirish mavjud",
                        description="Sayt HTTP so'rovlarni HTTPS ga yo'naltiradi.",
                        severity=Severity.INFO,
                        category="Shifrlash",
                        recommendation="Yaxshi amaliyot — davom eting.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Noto'g'ri HTTPS yo'naltirish",
                        description=f"HTTP so'rov {location} manziliga yo'naltiriladi, HTTPS emas.",
                        severity=Severity.HIGH,
                        category="Shifrlash",
                        recommendation="Barcha HTTP so'rovlarni HTTPS ga yo'naltiring.",
                    )
                )
        else:
            findings.append(
                Finding(
                    title="HTTP dan HTTPS ga yo'naltirish yo'q",
                    description="Sayt HTTP orqali ochiq holda ishlaydi, HTTPS ga yo'naltirmaydi.",
                    severity=Severity.HIGH,
                    category="Shifrlash",
                    recommendation="HTTP dan HTTPS ga 301/302 yo'naltirishni sozlang.",
                )
            )
    except httpx.RequestError:
        findings.append(
            Finding(
                title="HTTP ulanish tekshirilmadi",
                description="HTTP protokoli orqali ulanish amalga oshmadi.",
                severity=Severity.INFO,
                category="Shifrlash",
            )
        )

    return findings


async def check_ssl_certificate(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry - datetime.now(timezone.utc)).days

            if days_left < 0:
                findings.append(
                    Finding(
                        title="SSL sertifikat muddati tugagan",
                        description=f"Sertifikat {abs(days_left)} kun oldin tugagan.",
                        severity=Severity.CRITICAL,
                        category="Shifrlash",
                        recommendation="SSL sertifikatni darhol yangilang.",
                    )
                )
            elif days_left < 14:
                findings.append(
                    Finding(
                        title="SSL sertifikat tez orada tugaydi",
                        description=f"Sertifikat {days_left} kundan keyin tugaydi.",
                        severity=Severity.HIGH,
                        category="Shifrlash",
                        recommendation="Sertifikatni yangilashni rejalashtiring.",
                    )
                )
            elif days_left < 30:
                findings.append(
                    Finding(
                        title="SSL sertifikat muddati yaqinlashmoqda",
                        description=f"Sertifikat {days_left} kundan keyin tugaydi.",
                        severity=Severity.MEDIUM,
                        category="Shifrlash",
                        recommendation="Sertifikat yangilashni rejalashtiring.",
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="SSL sertifikat amal qilmoqda",
                        description=f"Sertifikat {days_left} kun qolgan.",
                        severity=Severity.INFO,
                        category="Shifrlash",
                    )
                )

        subject = dict(x[0] for x in cert.get("subject", ()))
        cn = subject.get("commonName", "")
        san = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]
        if domain not in san and cn != domain and f"*.{domain.split('.', 1)[-1]}" not in san:
            findings.append(
                Finding(
                    title="SSL sertifikat domeni mos kelmaydi",
                    description=f"Sertifikat {domain} domeni uchun emas.",
                    severity=Severity.HIGH,
                    category="Shifrlash",
                    recommendation="To'g'ri domen uchun sertifikat o'rnating.",
                )
            )

    except ssl.SSLCertVerificationError:
        findings.append(
            Finding(
                title="SSL sertifikat tasdiqlanmadi",
                description="Sertifikat ishonchli emas yoki noto'g'ri.",
                severity=Severity.CRITICAL,
                category="Shifrlash",
                recommendation="Ishonchli sertifikat provayderidan sertifikat o'rnating.",
            )
        )
    except (socket.timeout, OSError, ssl.SSLError):
        findings.append(
            Finding(
                title="HTTPS ulanish mavjud emas",
                description="443-port orqali HTTPS ulanish o'rnatilmadi.",
                severity=Severity.CRITICAL,
                category="Shifrlash",
                recommendation="HTTPS ni yoqing va SSL sertifikat o'rnating.",
            )
        )

    return findings


async def check_security_headers(url: str) -> list[Finding]:
    findings: list[Finding] = []

    header_checks = [
        (
            "strict-transport-security",
            "HSTS (Strict-Transport-Security) yo'q",
            "Brauzer HTTPS majburiy qilmaydi, MITM hujumlariga moyil.",
            Severity.MEDIUM,
            "max-age kamida 31536000 (1 yil) qilib sozlang.",
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options yo'q",
            "MIME-sniffing hujumlariga qarshi himoya yo'q.",
            Severity.MEDIUM,
            "X-Content-Type-Options: nosniff qo'shing.",
        ),
        (
            "x-frame-options",
            "X-Frame-Options yo'q",
            "Clickjacking hujumlariga qarshi himoya yo'q.",
            Severity.MEDIUM,
            "X-Frame-Options: DENY yoki SAMEORIGIN qo'shing.",
        ),
        (
            "content-security-policy",
            "Content-Security-Policy yo'q",
            "XSS va ma'lumot in'ektsiyasi hujumlariga qarshi himoya zaif.",
            Severity.HIGH,
            "Mos CSP siyosatini sozlang.",
        ),
        (
            "referrer-policy",
            "Referrer-Policy yo'q",
            "Referer ma'lumotlari ortiqcha uzatilishi mumkin.",
            Severity.LOW,
            "Referrer-Policy: strict-origin-when-cross-origin qo'shing.",
        ),
        (
            "permissions-policy",
            "Permissions-Policy yo'q",
            "Brauzer API'lari (kamera, mikrofon) cheklanmagan.",
            Severity.LOW,
            "Keraksiz ruxsatlarni Permissions-Policy bilan cheklang.",
        ),
    ]

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            resp = await client.get(url)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, title, desc, severity, rec in header_checks:
            if header not in headers:
                findings.append(
                    Finding(
                        title=title,
                        description=desc,
                        severity=severity,
                        category="Xavfsizlik sarlavhalari",
                        recommendation=rec,
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"{header.upper()} mavjud",
                        description=f"Qiymat: {headers[header][:120]}",
                        severity=Severity.INFO,
                        category="Xavfsizlik sarlavhalari",
                    )
                )

        server = headers.get("server", "")
        if server:
            findings.append(
                Finding(
                    title="Server ma'lumoti ochiq",
                    description=f"Server sarlavhasi: {server}",
                    severity=Severity.LOW,
                    category="Ma'lumot oshkor etish",
                    recommendation="Server versiyasini yashiring.",
                )
            )

        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(
                Finding(
                    title="X-Powered-By ma'lumoti ochiq",
                    description=f"Texnologiya: {powered}",
                    severity=Severity.LOW,
                    category="Ma'lumot oshkor etish",
                    recommendation="X-Powered-By sarlavhasini o'chiring.",
                )
            )

    except httpx.RequestError as e:
        findings.append(
            Finding(
                title="Saytga ulanishda xatolik",
                description=str(e),
                severity=Severity.CRITICAL,
                category="Ulanish",
            )
        )

    return findings


async def check_cookies(url: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            resp = await client.get(url)

        set_cookie_header = resp.headers.get("set-cookie", "")
        cookies = [set_cookie_header] if set_cookie_header else []
        if not cookies:
            return findings

        for cookie in cookies:
            name = cookie.split("=")[0].strip()
            lower = cookie.lower()

            issues = []
            if "secure" not in lower:
                issues.append("Secure flag yo'q")
            if "httponly" not in lower:
                issues.append("HttpOnly flag yo'q")
            if "samesite" not in lower:
                issues.append("SameSite atributi yo'q")

            if issues:
                findings.append(
                    Finding(
                        title=f"Cookie xavfsizligi: {name}",
                        description="; ".join(issues),
                        severity=Severity.MEDIUM,
                        category="Cookie",
                        recommendation="Secure, HttpOnly va SameSite=Strict qo'shing.",
                    )
                )

    except httpx.RequestError:
        pass

    return findings


async def check_sensitive_paths(base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    paths = [
        ("/.env", "CRITICAL", ".env fayli ochiq — maxfiy kalitlar oshkor bo'lishi mumkin."),
        ("/.git/HEAD", "CRITICAL", "Git repozitoriyasi ochiq — manba kodi oshkor bo'lishi mumkin."),
        ("/wp-config.php.bak", "HIGH", "WordPress zaxira fayli topildi."),
        ("/phpinfo.php", "HIGH", "phpinfo fayli ochiq — server ma'lumotlari oshkor."),
        ("/admin", "MEDIUM", "Admin panel manzili mavjud."),
        ("/backup", "MEDIUM", "Zaxira papkasi mavjud."),
        ("/robots.txt", "INFO", "robots.txt fayli mavjud."),
    ]

    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=8.0) as client:
            for path, sev, desc in paths:
                try:
                    resp = await client.head(f"{base_url}{path}")
                    if resp.status_code == 200:
                        findings.append(
                            Finding(
                                title=f"Ochiq manzil: {path}",
                                description=desc,
                                severity=severity_map[sev],
                                category="Ochiq manzillar",
                                recommendation=f"{path} manzilini yoping yoki himoyalang.",
                            )
                        )
                except httpx.RequestError:
                    continue
    except Exception:
        pass

    return findings
