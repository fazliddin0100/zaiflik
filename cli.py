import argparse
import asyncio
import json
import sys
import webbrowser
from pathlib import Path
from urllib.parse import quote

from app.scanner import VulnerabilityScanner
from app.serialize import result_to_dict
from app.browser import open_browser
from app.html_report import generate_html

SEVERITY_LABELS = {
    "kritik": "KRITIK",
    "yuqori": "YUQORI",
    "o'rta": "O'RTA",
    "past": "PAST",
    "ma'lumot": "MA'LUMOT",
}


def print_text_report(data: dict) -> None:
    print()
    print("=" * 60)
    print(f"  ZAIFLIK SKANERI — {data['domain']}")
    print("=" * 60)
    print(f"  URL:           {data['url']}")
    print(f"  Xavf darajasi: {data['risk_level']} ({data['risk_score']}%)")
    print(f"  Vaqt:          {data['scan_duration_ms'] / 1000:.1f}s")
    print()

    if data["summary"]:
        print("  Xulosa:")
        for sev, count in data["summary"].items():
            label = SEVERITY_LABELS.get(sev, sev.upper())
            print(f"    {label:10} {count} ta")
        print()

    print(f"  Topilgan zaifliklar ({len(data['findings'])}):")
    print("-" * 60)

    for i, f in enumerate(data["findings"], 1):
        label = SEVERITY_LABELS.get(f["severity"], f["severity"].upper())
        print(f"\n  [{i}] [{label}] {f['title']}")
        print(f"      {f['description']}")
        print(f"      Kategoriya: {f['category']}")
        if f["recommendation"]:
            print(f"      Tavsiya: {f['recommendation']}")

    print()
    print("=" * 60)


def open_html_report(result, output_path: str | None) -> None:
    html_content = generate_html(result)
    if output_path:
        path = Path(output_path)
    else:
        path = Path(f"hisobot-{result.domain}.html")
    path.write_text(html_content, encoding="utf-8")
    webbrowser.open(path.resolve().as_uri())
    print(f"Brauzerda ochildi: {path}")


async def run_scan(args: argparse.Namespace) -> int:
    result = await VulnerabilityScanner().scan(args.domain)
    data = result_to_dict(result)

    if args.format == "json" or args.output:
        output = json.dumps(data, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"JSON saqlandi: {args.output}")
        else:
            print(output)

    if args.pdf:
        try:
            from app.report import generate_pdf
        except ImportError:
            print("PDF uchun fpdf2 kerak. O'rnating: pip install fpdf2", file=sys.stderr)
            return 1
        pdf_bytes = generate_pdf(result)
        with open(args.pdf, "wb") as f:
            f.write(pdf_bytes)
        print(f"PDF saqlandi: {args.pdf}")

    if args.open or args.html:
        open_html_report(result, args.html)

    if args.format == "text" and not args.output and not args.open:
        print_text_report(data)

    return 0


def run_serve(args: argparse.Namespace) -> int:
    import uvicorn

    url = f"http://localhost:{args.port}"
    if args.domain:
        url += f"?domain={quote(args.domain)}"

    print(f"Server ishga tushmoqda: {url}")
    print("To'xtatish uchun: Ctrl+C")
    open_browser(url)
    uvicorn.run("main:app", host="0.0.0.0", port=args.port, reload=False)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="zaiflik",
        description="Domen orqali sayt zaifliklarini aniqlash",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Domenni tekshirish")
    scan_parser.add_argument("domain", help="Tekshiriladigan domen (masalan: example.com)")
    scan_parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text", help="Chiqish formati"
    )
    scan_parser.add_argument("--pdf", metavar="FILE", help="PDF hisobot fayli")
    scan_parser.add_argument("--output", "-o", metavar="FILE", help="JSON natijani faylga saqlash")
    scan_parser.add_argument(
        "--open", "-b", action="store_true", help="Natijani brauzerda ochish (HTML)"
    )
    scan_parser.add_argument("--html", metavar="FILE", help="HTML hisobot fayli")

    serve_parser = sub.add_parser("serve", help="Web interfeysni ishga tushirish (brauzer ochiladi)")
    serve_parser.add_argument("--port", "-p", type=int, default=8000, help="Port (default: 8000)")
    serve_parser.add_argument(
        "--domain", "-d", help="Brauzerda avtomatik tekshiriladigan domen"
    )

    args = parser.parse_args()

    if args.command == "scan":
        return asyncio.run(run_scan(args))
    if args.command == "serve":
        return run_serve(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
