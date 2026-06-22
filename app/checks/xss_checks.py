import re
from urllib.parse import quote

import httpx

from app.models import Finding, Severity

PROBE = "zaiflik7k2m9"
XSS_PAYLOAD = f'"><{PROBE}>'
COMMON_PARAMS = ["q", "search", "s", "query", "id", "page", "name", "keyword", "term", "redirect", "url", "next"]


def _extract_form_params(html: str) -> list[str]:
    params: list[str] = []
    for match in re.finditer(
        r'<form[^>]*method=["\']?get["\']?[^>]*>(.*?)</form>',
        html,
        re.IGNORECASE | re.DOTALL,
    ):
        form_html = match.group(1)
        for inp in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\']', form_html, re.IGNORECASE):
            params.append(inp.group(1))
    return params


def _is_reflected_unencoded(payload: str, html: str) -> bool:
    if payload not in html:
        return False
    idx = html.find(payload)
    snippet = html[max(0, idx - 10) : idx + len(payload) + 10]
    encoded_variants = ["&lt;", "&#60;", "&#x3c;", "%3C", "\\u003c"]
    return not any(v in snippet.lower() for v in encoded_variants)


async def check_xss_reflection(url: str) -> list[Finding]:
    findings: list[Finding] = []
    reflected: list[str] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=12.0) as client:
            resp = await client.get(url)
            form_params = _extract_form_params(resp.text)
            params_to_test = list(dict.fromkeys(COMMON_PARAMS + form_params))[:15]

            for param in params_to_test:
                for payload in (PROBE, XSS_PAYLOAD):
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(payload)}"
                    try:
                        r = await client.get(test_url)
                        if _is_reflected_unencoded(payload, r.text):
                            reflected.append(f"{param}={payload[:30]}")
                            break
                    except httpx.RequestError:
                        continue

            inline_scripts = len(re.findall(r"<script[^>]*>", resp.text, re.IGNORECASE))
            if inline_scripts > 3:
                findings.append(
                    Finding(
                        title="Ko'p inline scriptlar",
                        description=f"Sahifada {inline_scripts} ta inline <script> topildi — XSS xavfi yuqoriroq.",
                        severity=Severity.MEDIUM,
                        category="XSS",
                        recommendation="Inline scriptlarni kamaytiring va CSP siyosatini qo'llang.",
                    )
                )

    except httpx.RequestError as e:
        findings.append(
            Finding(
                title="XSS tekshiruvi bajarilmadi",
                description=str(e),
                severity=Severity.INFO,
                category="XSS",
            )
        )
        return findings

    if reflected:
        findings.append(
            Finding(
                title="Reflected XSS ehtimoli aniqlandi",
                description=f"Kiritilgan ma'lumot HTML da kodlanmagan holda qaytmoqda: {', '.join(reflected[:3])}",
                severity=Severity.HIGH,
                category="XSS",
                recommendation="Barcha foydalanuvchi kiritmalarini HTML encode qiling va CSP qo'llang.",
            )
        )
    else:
        findings.append(
            Finding(
                title="Reflected XSS topilmadi",
                description="Umumiy parametrlarda XSS aks ettirish aniqlanmadi.",
                severity=Severity.INFO,
                category="XSS",
            )
        )

    return findings
