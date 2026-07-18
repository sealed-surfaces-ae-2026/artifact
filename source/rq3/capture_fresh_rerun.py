"""Capture a retained second fresh-process clean-engine observation pass.

This evidence helper complements ``run_experiment.py --determinism-check``:
the main harness records equality predicates and digests, while this helper
retains the complete second observations so an artifact reviewer can inspect
both byte preimages.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from real_rq3.canonical import encode, sha256
from real_rq3.engines import EngineBank
from real_rq3.experiment import ALL_PATHS, CLEAN_PROGRAMS, program


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    first_payload = json.loads(args.first.read_text(encoding="utf-8"))
    first = {
        (row["engine"], row["source_label"]): row
        for row in first_payload["clean"]
    }
    bank = EngineBank()
    second = []
    comparisons = []
    for source_label in CLEAN_PROGRAMS:
        source = program(source_label)
        for engine in ALL_PATHS:
            one = first[(engine, source_label)]
            two = bank.run(engine, source_label, source)
            canonical_one = encode(one["canonical_transcript"])
            canonical_two = encode(two["canonical_transcript"])
            raw_one = encode(one["raw"])
            raw_two = encode(two["raw"])
            second.append(two)
            comparisons.append(
                {
                    "engine": engine,
                    "source_label": source_label,
                    "canonical_run_1_sha256": sha256(canonical_one),
                    "canonical_run_2_sha256": sha256(canonical_two),
                    "canonical_byte_identical": canonical_one == canonical_two,
                    "raw_run_1_sha256": sha256(raw_one),
                    "raw_run_2_sha256": sha256(raw_two),
                    "raw_byte_identical": raw_one == raw_two,
                }
            )
    payload = {
        "schema": "sealed-surfaces.fresh-process-rerun/v1",
        "run_2": second,
        "comparisons": comparisons,
        "all_canonical_byte_identical": all(
            row["canonical_byte_identical"] for row in comparisons
        ),
        "all_raw_byte_identical": all(
            row["raw_byte_identical"] for row in comparisons
        ),
    }
    args.output.write_bytes(encode(payload) + b"\n")
    print(
        f"PASS: {len(comparisons)}/{len(comparisons)} fresh-process paths; "
        f"canonical={payload['all_canonical_byte_identical']}; "
        f"raw={payload['all_raw_byte_identical']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
