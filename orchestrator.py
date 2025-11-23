import os
import sys
import subprocess
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run_process(cmd, cwd=None):
    """Run a subprocess and stream output."""
    print(f"\n[+] Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=False,
            text=True
        )
        print(f"[+] Process exited with code {result.returncode}")
    except FileNotFoundError:
        print(f"[!] Command not found: {cmd[0]}")
    except Exception as e:
        print(f"[!] Error running {cmd}: {e}")


def run_bin_folder():
    """Run every executable file inside bin/."""
    if not BIN_DIR.exists():
        print(f"[!] BIN directory not found: {BIN_DIR}")
        return

    print(f"\n=== Running executables in {BIN_DIR} ===")
    for f in sorted(BIN_DIR.iterdir()):
        if f.is_file() and os.access(f, os.X_OK):
            run_process([str(f)], cwd=BIN_DIR)
        else:
            # On Windows, .exe/.bat may not always have +x bit set
            if f.suffix.lower() in (".exe", ".bat", ".cmd"):
                run_process([str(f)], cwd=BIN_DIR)


def run_python_scripts():
    """Run every .py file inside scripts/python/."""
    if not PYTHON_DIR.exists():
        print(f"[!] Python scripts directory not found: {PYTHON_DIR}")
        return

    print(f"\n=== Running Python scripts in {PYTHON_DIR} ===")
    for f in sorted(PYTHON_DIR.glob("*.py")):
        run_process([sys.executable, str(f)], cwd=PYTHON_DIR)


def run_cmd_scripts():
    """Run every .bat/.cmd file inside scripts/cmd/."""
    if not CMD_DIR.exists():
        print(f"[!] CMD scripts directory not found: {CMD_DIR}")
        return

    print(f"\n=== Running CMD scripts in {CMD_DIR} ===")
    for f in sorted(CMD_DIR.iterdir()):
        if f.suffix.lower() in (".bat", ".cmd"):
            run_process(["cmd.exe", "/c", str(f)], cwd=CMD_DIR)


def run_powershell_scripts():
    """Run every .ps1 file inside scripts/powershell/ EXCEPT one_liners.ps1."""
    if not POWERSHELL_DIR.exists():
        print(f"[!] PowerShell scripts directory not found: {POWERSHELL_DIR}")
        return

    print(f"\n=== Running PowerShell scripts in {POWERSHELL_DIR} ===")
    for f in sorted(POWERSHELL_DIR.glob("*.ps1")):
        if f.name == ONE_LINERS_NAME:
            continue  # handled separately
        run_process([
            POWERSHELL_EXE,
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", str(f)
        ], cwd=POWERSHELL_DIR)


def run_one_liners():
    """
    Run one_liners.ps1 line-by-line in an elevated PowerShell window.

    Make sure you start your terminal or PowerShell AS ADMINISTRATOR before
    running this script so the commands execute with elevated permissions.
    """
    one_liners = POWERSHELL_DIR / ONE_LINERS_NAME
    if not one_liners.exists():
        print(f"[!] One-liners file not found: {one_liners}")
        return

    print(f"\n=== Running one-liners from {one_liners} ===")
    with one_liners.open(encoding="utf-8", errors="ignore") as fh:
        for idx, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue  # skip blank lines and comments

            print(f"\n[Line {idx}] {stripped}")
            # Optionally pause between lines:
            # input("Press Enter to run this line, or Ctrl+C to stop...")

            run_process([
                POWERSHELL_EXE,
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", stripped
            ], cwd=POWERSHELL_DIR)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== Trigger Auto Orchestrator (Python) ===")
    print(f"Root directory: {ROOT_DIR}")

    # Order of execution – adjust to whatever sequence you want:
    ##run_bin_folder()
    run_python_scripts()
    ##run_cmd_scripts()
    run_powershell_scripts()
    run_one_liners()

    print("\n=== Orchestration complete ===")

if __name__ == "__main__":
    main()
