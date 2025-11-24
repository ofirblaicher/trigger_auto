import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Tuple

import requests
from tqdm import tqdm  # NEW

# =========================
# CONFIG CONSTANTS
# =========================

VT_DOWNLOAD_BASE_URL = "https://www.virustotal.com/api/v3/files"
VT_API_KEY_HEADER_NAME = "x-apikey"

SHA256_HEADER_CANDIDATES = [
    "x-vt-hash",
    "x-vt-file-sha256",
]

# Hard-coded default path for the hash file
hash_file_path = Path("trigger_auto/bin/hashes.txt")


# =========================
# HELPER FUNCTIONS
# =========================

def make_safe_filename(name: str) -> str:
    """
    Keep the provided name as-is (intended to be a hash from the txt file).
    Fallback to 'file' only if it's empty.
    """
    return name or "file"


def load_items(path: Path) -> List[str]:
    items: List[str] = []

    if not path.exists():
        print(f"[!] File not found: {path}")
        return items

    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                items.append(line)
    except Exception as e:
        print(f"[!] Error reading file '{path}': {e}")
        return []

    return items


def download_single_sample(
    api_key: str,
    file_hash: str,
    output_directory: Path,
    timeout_seconds: int = 60,
) -> Tuple[bool, str]:

    download_url = f"{VT_DOWNLOAD_BASE_URL}/{file_hash}/download"

    headers = {
        VT_API_KEY_HEADER_NAME: api_key,
    }

    try:
        response = requests.get(
            download_url,
            headers=headers,
            stream=True,
            timeout=timeout_seconds,
        )
    except requests.RequestException as e:
        return False, f"Network / request error: {e}"

    status = response.status_code

    if status == 404:
        return False, "Not found in VirusTotal (404)"
    elif status == 403:
        return False, "Forbidden (403)"
    elif status == 401:
        return False, "Unauthorized (401)"
    elif status == 429:
        return False, "Rate limited (429)"
    elif status != 200:
        try:
            short_body = response.text[:200]
        except Exception:
            short_body = "<unable to read body>"
        return False, f"Unexpected HTTP {status}: {short_body}"

    # Decide filename: ALWAYS use the hash from the txt file
    safe_name = make_safe_filename(file_hash)

    # Each sample gets its own directory under output_directory
    sample_dir = output_directory / safe_name
    sample_dir.mkdir(parents=True, exist_ok=True)

    # CHANGE → save as .exe instead of .bin
    output_path = sample_dir / f"{safe_name}.exe"

    # Optional per-file progress bar
    total_bytes = None
    content_length = response.headers.get("Content-Length")
    if content_length and content_length.isdigit():
        total_bytes = int(content_length)

    try:
        with output_path.open("wb") as f:
            # Only show per-file bar if we know total size
            with tqdm(
                total=total_bytes,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=safe_name,
                leave=False,
                disable=(total_bytes is None),
            ) as pbar:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    f.write(chunk)
                    if total_bytes is not None:
                        pbar.update(len(chunk))
    except Exception as e:
        return False, f"Failed writing file: {e}"

    return True, f"Saved to {output_path}"


# =========================
# MAIN PROGRAM
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VT Enterprise Sample Downloader")
    parser.add_argument(
        "--hash-file",
        "-f",
        help=(
            "Path to file containing hashes. "
            f"Default: {hash_file_path}"
        ),
    )
    parser.add_argument(
        "--delay",
        "-d",
        type=float,
        default=1.0,
        help="Delay in seconds between downloads (default: 1.0).",
    )
    return parser.parse_args()


def main() -> int:
    print("=== VT Enterprise Sample Downloader ===")

    # Save downloads into the project root /bin directory
    script_directory = Path(__file__).resolve().parent
    # scripts/python → scripts → trigger_auto (project root)
    project_root = script_directory.parent.parent
    output_directory = project_root / "bin"

    api_key = "c908c6627422663c4f0d9de954881dc6146388ed3ac61b6c6bf8b51872a5cbf8"
    if not api_key:
        print("[!] VT_API_KEY is not set. Aborting.")
        return 1

    args = parse_args()

    if args.hash_file:
        effective_hash_file = Path(args.hash_file).expanduser().resolve()
    else:
        effective_hash_file = hash_file_path

    print(f"[i] Using hash file: {effective_hash_file}")

    hashes = load_items(effective_hash_file)

    if not hashes:
        print("[!] No hashes found. Ensure file exists and is not empty.")
        return 1

    # Ensure base output directory exists (per-hash subdirs created in download_single_sample)
    output_directory.mkdir(parents=True, exist_ok=True)

    success = 0
    failure = 0

    # Overall progress bar over all hashes
    for h in tqdm(hashes, desc="Downloading samples", unit="file"):
        print(f"\n=== Downloading hash: {h} ===")

        ok, message = download_single_sample(
            api_key=api_key,
            file_hash=h,
            output_directory=output_directory,
        )

        if ok:
            print(f"[+] OK: {message}")
            success += 1
        else:
            print(f"[!] FAIL: {message}")
            failure += 1

        if args.delay > 0:
            time.sleep(args.delay)

    print("\n=== Download Summary ===")
    print(f"  Total : {success + failure}")
    print(f"  OK    : {success}")
    print(f"  Fail  : {failure}")
    print("=== Done ===")

    return 0


if __name__ == "__main__":
    sys.exit(main())
