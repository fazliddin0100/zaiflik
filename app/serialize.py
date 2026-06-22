from app.models import ScanResult


def result_to_dict(result: ScanResult) -> dict:
    summary: dict[str, int] = {}
    for f in result.findings:
        summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

    return {
        "domain": result.domain,
        "url": result.url,
        "target_type": result.target_type,
        "raw_input": result.raw_input,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "scan_duration_ms": result.scan_duration_ms,
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "category": f.category,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ],
        "summary": summary,
        "error": result.error,
    }
