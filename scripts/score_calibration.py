"""Score a complete calibration bundle offline against the predeclared design."""
import argparse
from pathlib import Path

from agent_boundary_check.calibration import replay, score as score
from agent_boundary_check.render import safe_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--summary", action="store_true", help="print case outcomes and counts for quick review")
    args = parser.parse_args()
    try:
        replay(args.bundle, summary=args.summary)
    except (OSError, ValueError) as exc:
        parser.error(safe_text(exc))


if __name__ == "__main__":
    main()
