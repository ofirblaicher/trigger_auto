import os
import sys
import time
import json
import argparse
from pathlib import Path
import requests


VT_API_BASE = "https://www.virustotal.com/api/v3"

# Folder where THIS script is located
SCRIPT_DIR = Path(__file__).resolve().parent


def get_api_key():
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("[!] Please set the VT_API_KEY environment variable to your VirusTotal API key.")
        sys.exit(1)
    return api_key


def fetch_file_report(api_key: str, file_id: str) -> dict:
    headers = {"x-apikey": api_key}
    resp = requests.get(f"{VT_API_BASE}/files/{file_id}", headers=headers, timeout=30)

    if resp.status_code == 404:
        print(f"[!] File not found in VirusTotal: {file_id}")
        return {}

    resp.raise_for_status()
    return resp.json()


def extract_iocs(report: dict) -> dict:
    data = report.get("data", {})
    attrs = data.get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    detections = []
    for engine, res in results.items():
        if res.get("category") in ("malicious", "suspicious"):
            detections.append({
                "engine": engine,
                "category": res.get("category"),
                "result": res.get("result"),
            })

    return {
        "sha256": attrs.get("sha256"),
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
        "reputation": attrs.get("reputation"),
        "last_analysis_stats": stats,
        "detections": detections,
    }


def save_json(obj: dict, out_dir: Path, label: str):
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    safe_label = "".join(c if c.isalnum() else "_" for c in label)[:40]
    path = out_dir / f"vt_file_{safe_label}_{ts}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    print(f"[+] Full VT JSON saved to: {path}")


def load_hashes_from_file(path: Path):
    hashes = set()
    if not path.exists():
        print(f"[!] Hash file not found: {path}")
        return hashes

    with path.open(encoding="utf-8") as f:
        for line in f:
            h = line.strip()
            if h and not h.startswith("#"):
                hashes.add(h)
    return hashes


def main():
    print("=== VirusTotal File IoC Collector ===")
    print(f"[i] Script directory: {SCRIPT_DIR}")

    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", action="append")
    parser.add_argument("--hash-file")
    parser.add_argument("--out-dir", default=str(SCRIPT_DIR / "vt_file_iocs"))
    args = parser.parse_args()

    hashes = set()

    # 1. hashes from CLI
    if args.hash:
        hashes.update(args.hash)

    # 2. hash file provided
    if args.hash_file:
        hashes.update(load_hashes_from_file(Path(args.hash_file)))

    # 3. default: hashes.txt next to this script
    if not hashes:
        default_file = SCRIPT_DIR / "hashes.txt"
        print(f"[i] No hashes provided. Using default: {default_file}")
        hashes.update(load_hashes_from_file(default_file))

    if not hashes:
        print("[!] No hashes to process.")
        sys.exit(1)

    api_key = get_api_key()
    out_dir = Path(args.out_dir)
    all_results = []

    for h in sorted(hashes):
        print(f"\n=== Processing hash: {h} ===")
        try:
            report = fetch_file_report(api_key, h)
            if not report:
                continue

            iocs = extract_iocs(report)
            all_results.append(iocs)

            print(f"  sha256       : {iocs.get('sha256')}")
            print(f"  name         : {iocs.get('meaningful_name')}")
            print(f"  type         : {iocs.get('type_description')}")
            print(f"  reputation   : {iocs.get('reputation')}")
            print(f"  detections:")
            for d in iocs["detections"]:
                print(f"    - {d['engine']} -> {d['category']} ({d['result']})")

            save_json(report, out_dir, h)

        except Exception as e:
            print(f"[!] Error processing {h}: {e}")

    # Write summary
    summary_path = out_dir / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[+] Summary saved to: {summary_path}")
    print("=== Done ===")


if __name__ == "__main__":
    main()
