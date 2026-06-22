from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.scanner import VulnerabilityScanner
from app.serialize import result_to_dict
from app.report import generate_pdf

app = FastAPI(title="Zaiflik Skaneri", version="2.0.0")
scanner = VulnerabilityScanner()

STATIC_DIR = Path(__file__).parent / "app" / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, examples=["example.com"])


class FindingResponse(BaseModel):
    title: str
    description: str
    severity: str
    category: str
    recommendation: str


class ScanResponse(BaseModel):
    domain: str
    url: str
    target_type: str = "domain"
    raw_input: str = ""
    infrastructure: dict = {}
    risk_score: float
    risk_level: str
    scan_duration_ms: int
    findings: list[FindingResponse]
    summary: dict[str, int]
    error: str | None = None


@app.get("/favicon.ico")
async def favicon():
    return Response(content=b"", media_type="image/x-icon")


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.post("/api/scan", response_model=ScanResponse)
async def scan_domain(req: ScanRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domen kiritilmagan")

    result = await scanner.scan(domain)
    data = result_to_dict(result)
    return ScanResponse(**data)


@app.post("/api/scan/pdf")
async def scan_domain_pdf(req: ScanRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domen kiritilmagan")

    result = await scanner.scan(domain)
    pdf_bytes = generate_pdf(result)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="zaiflik-{result.domain}.pdf"'
        },
    )
