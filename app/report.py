import os
from datetime import datetime
from io import BytesIO

from fpdf import FPDF

from app.models import ScanResult, SEVERITY_ORDER

SEVERITY_COLORS = {
    "kritik": (220, 53, 69),
    "yuqori": (253, 126, 20),
    "o'rta": (255, 193, 7),
    "past": (40, 167, 69),
    "ma'lumot": (0, 123, 255),
}

SEVERITY_LABELS = {
    "kritik": "Kritik",
    "yuqori": "Yuqori",
    "o'rta": "O'rta",
    "past": "Past",
    "ma'lumot": "Ma'lumot",
}


def _find_font() -> str | None:
    candidates = [
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "arial.ttf"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


class ZaiflikPDF(FPDF):
    def __init__(self):
        super().__init__()
        font_path = _find_font()
        if font_path:
            self.add_font("Custom", "", font_path)
            self._font = "Custom"
        else:
            self._font = "Helvetica"

    def _set_body_font(self, size: int = 10):
        self.set_font(self._font, size=size)

    def header(self):
        self._set_body_font(14)
        self.set_text_color(40, 40, 80)
        self.cell(0, 10, "Zaiflik Skaneri - Hisobot", new_x="LMARGIN", new_y="NEXT", align="C")
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self._set_body_font(8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Sahifa {self.page_no()}/{{nb}}", align="C")

    def write_line(self, text: str, size: int = 10, color: tuple[int, int, int] = (30, 30, 30)):
        self._set_body_font(size)
        self.set_text_color(*color)
        self.multi_cell(0, 5, text)
        self.ln(1)


def generate_pdf(result: ScanResult) -> bytes:
    pdf = ZaiflikPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.write_line(f"Domen: {result.domain}", size=12, color=(40, 40, 80))
    pdf.write_line(f"URL: {result.url}", size=10, color=(80, 80, 80))
    pdf.write_line(f"Sana: {datetime.now().strftime('%Y-%m-%d %H:%M')}", size=10, color=(80, 80, 80))
    pdf.write_line(f"Tekshiruv vaqti: {result.scan_duration_ms / 1000:.1f}s", size=10, color=(80, 80, 80))
    pdf.ln(3)

    pdf.write_line(f"Xavf darajasi: {result.risk_level} ({result.risk_score}%)", size=12, color=(40, 40, 80))
    pdf.ln(2)

    summary = result.by_severity()
    pdf.write_line("Xulosa:", size=11, color=(40, 40, 80))
    for sev in SEVERITY_ORDER:
        count = len(summary[sev.value])
        if count:
            color = SEVERITY_COLORS.get(sev.value, (0, 0, 0))
            pdf.write_line(f"  {SEVERITY_LABELS[sev.value]}: {count} ta", size=10, color=color)
    pdf.ln(3)

    if result.infrastructure:
        infra = result.infrastructure
        pdf.write_line("Tarmoq ma'lumotlari", size=12, color=(40, 40, 80))
        if infra.unique_ips:
            pdf.write_line(f"IP manzillar: {', '.join(infra.unique_ips)}", size=9)
        for sub in infra.subdomains:
            pdf.write_line(f"  {sub.name} -> {', '.join(sub.ips)}", size=9)
        if infra.ports:
            ports_txt = ", ".join(f"{p.port}/{p.service}" for p in infra.ports)
            pdf.write_line(f"Portlar ({infra.host}): {ports_txt}", size=9)
        dns = infra.dns
        if dns.get("mx"):
            pdf.write_line(f"MX: {', '.join(dns['mx'])}", size=9)
        if dns.get("ns"):
            pdf.write_line(f"NS: {', '.join(dns['ns'])}", size=9)
        pdf.ln(2)

    pdf.write_line("Topilgan zaifliklar", size=12, color=(40, 40, 80))
    pdf.ln(2)

    for f in result.findings:
        label = SEVERITY_LABELS.get(f.severity.value, f.severity.value)
        color = SEVERITY_COLORS.get(f.severity.value, (0, 0, 0))
        pdf.write_line(f"[{label}] {f.title}", size=10, color=color)
        pdf.write_line(f.description, size=9, color=(80, 80, 80))
        pdf.write_line(f"Kategoriya: {f.category}", size=8, color=(100, 100, 120))
        if f.recommendation:
            pdf.write_line(f"Tavsiya: {f.recommendation}", size=8, color=(60, 80, 160))
        pdf.ln(2)

    buffer = BytesIO()
    pdf.output(buffer)
    return buffer.getvalue()
