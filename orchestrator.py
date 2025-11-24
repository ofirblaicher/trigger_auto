#!/usr/bin/env python3
"""
Generic orchestrator for the trigger_auto project.

Place this file in the root trigger_auto directory:
trigger_auto/
  bin/
  scripts/
    cmd/
    powershell/
    python/
  orchestrator.py  <-- here
"""

import os
import sys
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent
BIN_DIR = ROOT_DIR / "bin"
SCRIPTS_DIR = ROOT_DIR / "scripts"
POWERSHELL_DIR = SCRIPTS_DIR / "powershell"
PYTHON_DIR = SCRIPTS_DIR / "python"
CMD_DIR = SCRIPTS_DIR / "cmd"

ONE_LINERS_NAME = "one_liners.ps1"   # filename inside scripts/powershell

# Change this if your PowerShell executable is named differently (e.g. "pwsh")
POWERSHELL_EXE = "powershell.exe"

VT_PY_SCRIPT_NAME = "vt_file_iocs.py"  # special label for this script

# ---------------------------------------------------------------------------
# Job helpers
# ---------------------------------------------------------------------------

def add_job(jobs, name, cmd, cwd):
    """Add a job description to the list."""
    jobs.append({
        "name": name,
        "cmd": cmd,
        "cwd": cwd,
    })


def run_single_job(job):
    """Run one job and return a result dict."""
    name = job["name"]
    cmd = job["cmd"]
    cwd = job["cwd"]

    print(f"\n[+] Starting job: {name}")
    print(f"    Command: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=False,
            text=True
        )
        rc = result.returncode
        print(f"[+] Job finished: {name} (exit code {rc})")
        return {"name": name, "returncode": rc, "error": None}
    except FileNotFoundError:
        msg = f"Command not found: {cmd[0]}"
        print(f"[!] {msg}")
        return {"name": name, "returncode": None, "error": msg}
    except Exception as e:
        msg = f"Error running job: {e}"
        print(f"[!] {msg}")
        return {"name": name, "returncode": None, "error": msg}


def run_jobs_in_parallel(jobs, max_workers=None):
    """Run all jobs in parallel and return list of result dicts."""
    if not jobs:
        return []

    if max_workers is None:
        max_workers = min(8, max(1, len(jobs)))

    print(f"\n=== Running {len(jobs)} jobs in parallel "
          f"(max_workers={max_workers}) ===")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_job = {
            executor.submit(run_single_job, job): job for job in jobs
        }
        for future in as_completed(future_to_job):
            res = future.result()
            results.append(res)

    return results

# ---------------------------------------------------------------------------
# Job builders
# ---------------------------------------------------------------------------

def build_bin_jobs(jobs):
    """Create jobs for every executable file inside bin/."""
    if not BIN_DIR.exists():
        print(f"[!] BIN directory not found: {BIN_DIR}")
        return

    print(f"\n=== Preparing executables in {BIN_DIR} ===")
    for f in sorted(BIN_DIR.iterdir()):
        if f.is_file() and os.access(f, os.X_OK):
            add_job(jobs, f"bin/{f.name}", [str(f)], BIN_DIR)
        else:
            # On Windows, .exe/.bat may not always have +x bit set
            if f.suffix.lower() in (".exe", ".bat", ".cmd"):
                add_job(jobs, f"bin/{f.name}", [str(f)], BIN_DIR)


def build_python_jobs(jobs):
    """Create jobs for every .py file inside scripts/python/."""
    if not PYTHON_DIR.exists():
        print(f"[!] Python scripts directory not found: {PYTHON_DIR}")
        return

    print(f"\n=== Preparing Python scripts in {PYTHON_DIR} ===")
    for f in sorted(PYTHON_DIR.glob("*.py")):
        # Special label for the VT IoC script so it’s obvious in logs
        if f.name == VT_PY_SCRIPT_NAME:
            job_name = f"python/VT_IoCs({f.name})"
            print("\n=== Detected VirusTotal IoC script ===")
            print(f"    Script : {f}")
            # *** UPDATED NOTE ***
            print("    Note   : VT hash file is expected at bin/hashes.txt "
                  "under the project root. VT_API_KEY is expected from the environment.")
            print("=======================================")
        else:
            job_name = f"python/{f.name}"

        add_job(jobs, job_name, [sys.executable, str(f)], PYTHON_DIR)


def build_cmd_jobs(jobs):
    """Create jobs for every .bat/.cmd file inside scripts/cmd/."""
    if not CMD_DIR.exists():
        print(f"[!] CMD scripts directory not found: {CMD_DIR}")
        return

    print(f"\n=== Preparing CMD scripts in {CMD_DIR} ===")
    for f in sorted(CMD_DIR.iterdir()):
        if f.suffix.lower() in (".bat", ".cmd"):
            add_job(
                jobs,
                f"cmd/{f.name}",
                ["cmd.exe", "/c", str(f)],
                CMD_DIR
            )


def build_powershell_script_jobs(jobs):
    """Create jobs for every .ps1 inside scripts/powershell/ (except one_liners)."""
    if not POWERSHELL_DIR.exists():
        print(f"[!] PowerShell scripts directory not found: {POWERSHELL_DIR}")
        return

    print(f"\n=== Preparing PowerShell scripts in {POWERSHELL_DIR} ===")
    for f in sorted(POWERSHELL_DIR.glob("*.ps1")):
        if f.name == ONE_LINERS_NAME:
            continue  # handled separately
        add_job(
            jobs,
            f"ps1/{f.name}",
            [
                POWERSHELL_EXE,
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", str(f),
            ],
            POWERSHELL_DIR
        )


def build_powershell_module_jobs(jobs):
    """
    Create jobs for every .psm1 inside scripts/powershell/.
    For each module X.psm1 we:
      - Import-Module X.psm1
      - If a function named 'X' exists, call it.
    """
    if not POWERSHELL_DIR.exists():
        print(f"[!] PowerShell modules directory not found: {POWERSHELL_DIR}")
        return

    print(f"\n=== Preparing PowerShell modules in {POWERSHELL_DIR} ===")
    for f in sorted(POWERSHELL_DIR.glob("*.psm1")):
        module_path = str(f)
        escaped_path = module_path.replace("'", "''")
        entry_name = f.stem  # e.g. Mayhem.psm1 -> Mayhem

        ps_command = (
            f"$modulePath = '{escaped_path}';"
            "$ErrorActionPreference = 'Stop';"
            "Import-Module $modulePath;"
            f"$entry = '{entry_name}';"
            "if (Get-Command $entry -ErrorAction SilentlyContinue) "
            "{ & $entry } "
            "else "
            "{ Write-Host \"Module imported but no entry function named $entry was found.\" }"
        )

        add_job(
            jobs,
            f"psm1/{f.name}",
            [
                POWERSHELL_EXE,
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_command,
            ],
            POWERSHELL_DIR
        )

# ---------------------------------------------------------------------------
# one_liners.ps1 (sequential, line-by-line)
# ---------------------------------------------------------------------------

def run_one_liners():
    """
    Run one_liners.ps1 line-by-line in an elevated PowerShell window.

    Make sure you start your terminal or PowerShell AS ADMINISTRATOR before
    running this script so the commands execute with elevated permissions.
    """
    one_liners = POWERSHELL_DIR / ONE_LINERS_NAME
    results = []

    if not one_liners.exists():
        print(f"[!] One-liners file not found: {one_liners}")
        return results

    print(f"\n=== Running one-liners from {one_liners} (sequential) ===")
    with one_liners.open(encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue  # skip blank lines and comments

            name = f"one_liner line {idx}"
            print(f"\n[Line {idx}] {stripped}")

            job = {
                "name": name,
                "cmd": [
                    POWERSHELL_EXE,
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", stripped,
                ],
                "cwd": POWERSHELL_DIR,
            }
            res = run_single_job(job)
            results.append(res)

    return results

# ---------------------------------------------------------------------------
# Summary reporting
# ---------------------------------------------------------------------------

def print_summary(results, title="Summary"):
    print(f"\n=== {title} ===")
    if not results:
        print("No jobs were run.")
        return

    successes = [r for r in results if r["returncode"] == 0]
    failures = [r for r in results if r["returncode"] not in (0, None)]
    errors   = [r for r in results if r["returncode"] is None and r["error"]]

    for r in results:
        status = "OK" if r["returncode"] == 0 else "FAIL"
        if r["returncode"] is None and r["error"]:
            status = "ERROR"
        print(f"- {r['name']}: {status} "
              f"(code={r['returncode']}, error={r['error']})")

    print(f"\nTotal jobs   : {len(results)}")
    print(f"Successes    : {len(successes)}")
    print(f"Failures     : {len(failures)}")
    print(f"Errors       : {len(errors)}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== Trigger Auto Orchestrator (Python) ===")
    print(f"Root directory: {ROOT_DIR}")

    # Build all jobs that can be parallelized
    jobs = []
    build_bin_jobs(jobs)
    build_python_jobs(jobs)
    build_cmd_jobs(jobs)
    build_powershell_script_jobs(jobs)
    build_powershell_module_jobs(jobs)

    # Run those jobs in parallel
    parallel_results = run_jobs_in_parallel(jobs)

    # Run one_liners.ps1 sequentially, line-by-line
    one_liner_results = run_one_liners()

    # Combined summary
    all_results = parallel_results + one_liner_results
    print_summary(all_results, title="Per-script Success/Failure Summary")

    print("\n=== Orchestration complete ===")

if __name__ == "__main__":
    main()
