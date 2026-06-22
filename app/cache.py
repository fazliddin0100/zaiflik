import time

from app.models import ScanResult

_scan_cache: dict[str, tuple[ScanResult, float]] = {}
CACHE_TTL = 3600


def _key(raw: str) -> str:
    return raw.strip().lower()


def put_scan(raw: str, result: ScanResult) -> None:
    k = _key(raw)
    _scan_cache[k] = (result, time.time())
    if result.raw_input:
        _scan_cache[_key(result.raw_input)] = (result, time.time())


def get_scan(raw: str) -> ScanResult | None:
    k = _key(raw)
    entry = _scan_cache.get(k)
    if not entry:
        return None
    result, ts = entry
    if time.time() - ts > CACHE_TTL:
        _scan_cache.pop(k, None)
        return None
    return result
