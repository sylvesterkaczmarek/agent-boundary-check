from __future__ import annotations

import subprocess
import sys


def main() -> int:
    # Deliberately simple deterministic runner used only by `agent-boundary demo`.
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        capture_output=True,
        text=True,
        check=False,
    )
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
