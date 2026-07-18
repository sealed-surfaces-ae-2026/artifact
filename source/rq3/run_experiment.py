"""Build, execute, oracle-check, and render the REAL-L RQ3 experiment."""

from __future__ import annotations

import argparse
from pathlib import Path

from real_rq3.engines import build_required, required_paths
from real_rq3.experiment import SEED, generate_artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--build", action="store_true", help="build E1/E2/E3 and the canonical-Core helper")
    parser.add_argument("--self-check", action="store_true", help="enable explicit matrix/oracle assertions (always fail closed)")
    parser.add_argument("--determinism-check", action="store_true", help="run every clean engine/program observation twice in fresh processes")
    args = parser.parse_args()

    if args.build:
        build_required()
    missing = [path for path in required_paths() if not path.is_file()]
    if missing:
        parser.error("missing engine artifacts (rerun with --build): " + ", ".join(map(str, missing)))

    artifacts = generate_artifacts(args.seed, args.determinism_check)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, payload in artifacts.items():
        (args.output / name).write_bytes(payload)
    print(
        f"PASS: matrix oracle complete; {len(artifacts)} artifacts; "
        f"clean canonical determinism={'checked' if args.determinism_check else 'single-run'}; "
        f"self-check={'requested' if args.self_check else 'built-in'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
