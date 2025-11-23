#!/usr/bin/env python3
"""
vt_file_iocs.py

VirusTotal file IoC collector.
Works when placed inside: trigger_auto/scripts/python/

Automatically loads hashes.txt from the SAME folder as this script.
"""

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
    parser.
