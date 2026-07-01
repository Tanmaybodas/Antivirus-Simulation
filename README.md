# Basic Antivirus Simulation

This is an educational signature-based antivirus simulation. It scans files, calculates SHA-256 hashes, compares them with a local signature database, and optionally moves detected files to quarantine.

## Project Structure

```text
.
├── main.py
├── scanner.py
├── signatures.json
├── test_files/
├── quarantine/
├── logs/
└── README.md
```

## Usage

Scan the sample files:

```bash
python main.py --scan test_files
```

Scan and quarantine detected files:

```bash
python main.py --scan test_files --quarantine
```

View quarantined files:

```bash
python main.py --list-quarantine
```

## How It Works

1. The program loads known malicious SHA-256 hashes from `signatures.json`.
2. It recursively scans the target folder.
3. It hashes each file in chunks so large files can be handled efficiently.
4. If a hash exists in the signature database, the file is reported as infected.
5. With `--quarantine`, infected files are moved into `quarantine/`.
6. A JSON report is written to `logs/`.

## Disclaimer

This project is for educational use only. It is not a real antivirus and should not be used for actual malware protection.
