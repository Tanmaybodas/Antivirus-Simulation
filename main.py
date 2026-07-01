import argparse
from pathlib import Path

from scanner import load_signatures, scan_folder, summarize, write_report


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SIGNATURES = BASE_DIR / "signatures.json"
DEFAULT_QUARANTINE = BASE_DIR / "quarantine"
DEFAULT_LOGS = BASE_DIR / "logs"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation - Signature Scanner"
    )
    parser.add_argument(
        "--scan",
        metavar="FOLDER",
        help="folder to scan recursively",
    )
    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="move detected files to the quarantine folder",
    )
    parser.add_argument(
        "--signatures",
        default=str(DEFAULT_SIGNATURES),
        help="path to signature JSON database",
    )
    parser.add_argument(
        "--list-quarantine",
        action="store_true",
        help="show files currently in quarantine",
    )
    return parser


def list_quarantine() -> None:
    DEFAULT_QUARANTINE.mkdir(exist_ok=True)
    files = [
        path
        for path in DEFAULT_QUARANTINE.iterdir()
        if path.is_file() and path.name != ".gitkeep"
    ]

    if not files:
        print("Quarantine is empty.")
        return

    print("Quarantined files:")
    for file_path in files:
        print(f"- {file_path.name}")


def run_scan(scan_path: str, signature_path: str, quarantine: bool) -> int:
    target_dir = Path(scan_path).resolve()
    signatures_file = Path(signature_path).resolve()

    if not target_dir.exists() or not target_dir.is_dir():
        print(f"Scan target is not a folder: {target_dir}")
        return 1

    signatures = load_signatures(signatures_file)
    results = scan_folder(target_dir, signatures, DEFAULT_QUARANTINE, quarantine)
    report_path = write_report(results, DEFAULT_LOGS)
    summary = summarize(results)

    print("\nScan Summary")
    print("------------")
    print(f"Target:        {target_dir}")
    print(f"Files scanned: {summary['files_scanned']}")
    print(f"Clean:         {summary['clean']}")
    print(f"Infected:      {summary['infected']}")
    print(f"Quarantined:   {summary['quarantined']}")
    print(f"Errors:        {summary['errors']}")
    print(f"Report:        {report_path}")

    infected = [result for result in results if result.status == "infected"]
    if infected:
        print("\nDetections")
        print("----------")
        for result in infected:
            action = f" -> quarantined to {result.quarantined_to}" if result.quarantined_to else ""
            print(f"- {result.malware_name}: {result.path}{action}")

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_quarantine:
        list_quarantine()
        return 0

    if not args.scan:
        parser.print_help()
        return 0

    return run_scan(args.scan, args.signatures, args.quarantine)


if __name__ == "__main__":
    raise SystemExit(main())
