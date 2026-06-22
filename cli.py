import argparse
import asyncio
import json
import sys

from app.scanner import VulnerabilityScanner
from app.serialize import result_to_dict
from app.report import generate_pdf

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
        pdf_bytes = generate_pdf(result)
        with open(args.pdf, "wb") as f:
            f.write(pdf_bytes)
        print(f"PDF saqlandi: {args.pdf}")

    if args.format == "text" and not args.output:
        print_text_report(data)

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

    args = parser.parse_args()

    if args.command == "scan":
        return asyncio.run(run_scan(args))

    return 1


if __name__ == "__main__":
    sys.exit(main())
