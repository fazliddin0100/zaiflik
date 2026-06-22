import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ScanTarget:
    raw: str
    host: str
    base_url: str
    scan_url: str
    target_type: str
    base_domain: str
    path: str = ""
    scheme: str = "https"


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_base_domain(host: str) -> str:
    host = host.lower()
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def parse_target(raw: str) -> ScanTarget:
    raw = raw.strip()
    if not raw:
        raise ValueError("Manzil kiritilmagan")

    if not re.match(r"^https?://", raw, re.I):
        if "/" in raw or "?" in raw:
            raw = "https://" + raw
        else:
            raw = "https://" + raw.split("/")[0].split("?")[0]

    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Noto'g'ri manzil")

    scheme = parsed.scheme or "https"
    port = parsed.port
    path = parsed.path or ""
    query = parsed.query

    if port and port not in (80, 443):
        base_url = f"{scheme}://{host}:{port}"
    else:
        base_url = f"{scheme}://{host}"

    scan_url = base_url
    if path and path != "/":
        scan_url = base_url + path
    if query:
        scan_url += ("&" if "?" in scan_url else "?") + query

    if is_ip(host):
        target_type = "url" if (path and path != "/") or query else "ip"
    elif (path and path != "/") or query:
        target_type = "url"
    else:
        target_type = "domain"

    return ScanTarget(
        raw=raw.strip(),
        host=host,
        base_url=base_url,
        scan_url=scan_url,
        target_type=target_type,
        base_domain=extract_base_domain(host),
        path=path,
        scheme=scheme,
    )


def normalize_domain(raw: str) -> str:
    return parse_target(raw).host


def normalize_url(raw: str) -> str:
    target = parse_target(raw)
    return target.scan_url if target.target_type == "url" else target.base_url
