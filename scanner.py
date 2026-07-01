import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


@dataclass
class ScanResult:
    path: str
    sha256: str
    status: str
    malware_name: str = ""
    quarantined_to: str = ""
    error: str = ""


def load_signatures(signature_file: Path) -> dict[str, str]:
    if not signature_file.exists():
        return {}

    with signature_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Signature database must be a JSON object.")

    return {key.lower(): str(value) for key, value in data.items()}


def calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()

    with file_path.open("rb") as file:
        while chunk := file.read(CHUNK_SIZE):
            digest.update(chunk)

    return digest.hexdigest()


def unique_quarantine_path(quarantine_dir: Path, source_path: Path) -> Path:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    candidate = quarantine_dir / source_path.name

    if not candidate.exists():
        return candidate

    stem = source_path.stem
    suffix = source_path.suffix
    counter = 1

    while True:
        candidate = quarantine_dir / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


def quarantine_file(source_path: Path, quarantine_dir: Path) -> Path:
    destination = unique_quarantine_path(quarantine_dir, source_path)
    shutil.move(str(source_path), str(destination))
    return destination


def scan_folder(
    target_dir: Path,
    signatures: dict[str, str],
    quarantine_dir: Path,
    quarantine: bool = False,
) -> list[ScanResult]:
    results: list[ScanResult] = []
    excluded_dirs = {quarantine_dir.resolve()}

    for file_path in target_dir.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            resolved_parent_dirs = set(file_path.resolve().parents)
            if excluded_dirs.intersection(resolved_parent_dirs):
                continue

            file_hash = calculate_sha256(file_path)
            malware_name = signatures.get(file_hash.lower(), "")

            if malware_name:
                quarantined_to = ""
                if quarantine:
                    quarantined_to = str(quarantine_file(file_path, quarantine_dir))

                results.append(
                    ScanResult(
                        path=str(file_path),
                        sha256=file_hash,
                        status="infected",
                        malware_name=malware_name,
                        quarantined_to=quarantined_to,
                    )
                )
            else:
                results.append(
                    ScanResult(path=str(file_path), sha256=file_hash, status="clean")
                )
        except OSError as exc:
            results.append(
                ScanResult(path=str(file_path), sha256="", status="error", error=str(exc))
            )

    return results


def write_report(results: list[ScanResult], logs_dir: Path) -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = logs_dir / f"scan_report_{timestamp}.json"

    report = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "files_scanned": len([result for result in results if result.status != "error"]),
        "threats_found": len([result for result in results if result.status == "infected"]),
        "errors": len([result for result in results if result.status == "error"]),
        "results": [result.__dict__ for result in results],
    }

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    return report_path


def summarize(results: list[ScanResult]) -> dict[str, int]:
    return {
        "files_scanned": len([result for result in results if result.status != "error"]),
        "clean": len([result for result in results if result.status == "clean"]),
        "infected": len([result for result in results if result.status == "infected"]),
        "errors": len([result for result in results if result.status == "error"]),
        "quarantined": len(
            [result for result in results if result.status == "infected" and result.quarantined_to]
        ),
    }
