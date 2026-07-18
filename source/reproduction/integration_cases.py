"""Seven raw-observation-to-authorization integration cases.

The RQ3 mechanism corpus stops at VerificationStatus.  This module connects
representative genuine rows to the finite model's immutable report store,
aggregate, verified projection guard phi(J), and AuthorizationBasis.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
from typing import Any


ARTIFACT = Path(__file__).resolve().parents[2]
MODEL_DIR = ARTIFACT / "source" / "model"
sys.path.insert(0, str(MODEL_DIR))

import non_laundering_model as model  # noqa: E402


AXES = model.INDEPENDENCE_AXES


def load_rows() -> dict[tuple[str, str, str], dict[str, str]]:
    with (ARTIFACT / "raw" / "oracle-observations.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        rows = list(csv.DictReader(stream))
    return {
        (row["scope"], row["independence"], row["injection"]): row
        for row in rows
    }


def load_registry() -> dict[str, Any]:
    return json.loads(
        (ARTIFACT / "inputs" / "profile-registry" / "profile-registry.json").read_text(
            encoding="utf-8"
        )
    )


def profile_for(registry: dict[str, Any], name: str) -> tuple[model.IndependenceProfile, list[str]]:
    axes = []
    refs = []
    for axis in AXES:
        evidence = registry["profiles"][name]["axes"][axis]
        ref = evidence["evidence_ref"]
        axes.append(
            model.AxisEvidence(
                next(item for item in model.Relation if item.value == evidence["relation"]),
                next(item for item in model.Provenance if item.value == evidence["provenance"]),
                ref,
            )
        )
        refs.append(ref)
    return model.IndependenceProfile(tuple(axes)), refs


def evidence_digest(profile: model.IndependenceProfile, refs: list[str]) -> str:
    return model.digest_text("concrete-profile-and-evidence-refs", profile, tuple(refs))


def one_report(
    status: model.VerificationStatus,
    report_id: int,
    *,
    key: model.ReportKey = model.MODEL_KEY,
    digest: str = "sha256:integration-no-profile",
    created_epoch: int = 1,
) -> model.VerificationReport:
    return model.VerificationReport(
        key,
        report_id,
        status,
        supporting_evidence_digest=digest,
        created_epoch=created_epoch,
    )


def aggregate_store(
    reports: tuple[model.VerificationReport, ...],
    *,
    key: model.ReportKey = model.MODEL_KEY,
    epoch: int = 2,
) -> model.VerifierAggregate:
    return model.aggregate(
        key.envelope_id,
        key.context_id,
        key.verifier_scope,
        model.VerifierStore(reports),
        aggregation_epoch=epoch,
    )


def run_cases() -> list[dict[str, Any]]:
    rows = load_rows()
    registry = load_registry()
    results: list[dict[str, Any]] = []

    # 1. A1 stale-3 authenticates a claim but records skipped re-execution.
    row = rows[("A1", "I3", "stale-3")]
    assert row["pipeline_outcome"] == "not_reexecuted"
    skipped = model.not_reexecuted(model.NotReexecutedReason.SKIPPED_BY_POLICY)
    aggregate = aggregate_store((one_report(skipped, 101),))
    decision = model.authorize(aggregate, model.PromotionPolicy(True, True, 0))
    assert decision.state.status == skipped
    assert decision.basis is not None and decision.basis.tag is model.BasisTag.ORIGIN_ONLY
    results.append(
        {
            "case": "A1 stale-3 -> origin-only/nonpromotion",
            "status": skipped.tag.value,
            "basis": decision.basis.tag.value,
            "execution_promotion": False,
            "result": "PASS",
        }
    )

    # 2. B stale-3 becomes disagreement; no promotion transition exists.
    row = rows[("B", "I3", "stale-3")]
    assert row["pipeline_outcome"] == "execution_disagreed"
    aggregate = aggregate_store((one_report(model.EXECUTION_DISAGREED, 102),))
    decision = model.authorize(aggregate, model.PromotionPolicy(True, True, 0))
    assert decision.state.status is model.EXECUTION_DISAGREED
    assert decision.basis is None
    results.append(
        {
            "case": "B stale-3 -> disagreement/no grant",
            "status": decision.state.status.tag.value,
            "basis": None,
            "result": "PASS",
        }
    )

    # 3. Clean B agreement carries only I(P); phi receives aggregate J.
    row = rows[("B", "I3", "clean")]
    assert row["pipeline_outcome"] == "execution_agreed"
    profile_i3, refs_i3 = profile_for(registry, "I3")
    mask_i3 = profile_i3.verified_projection()
    report = one_report(
        model.agreed(profile_i3),
        103,
        digest=evidence_digest(profile_i3, refs_i3),
    )
    aggregate = aggregate_store((report,))
    assert aggregate.status.profile is not None
    assert aggregate.status.profile.mask == mask_i3
    decision = model.authorize(
        aggregate,
        model.PromotionPolicy(False, True, mask_i3),
    )
    assert decision.basis is not None
    assert decision.basis.tag is model.BasisTag.EXECUTION_AGREEMENT
    results.append(
        {
            "case": "B clean -> projection/execution agreement",
            "J": mask_i3,
            "basis": decision.basis.tag.value,
            "result": "PASS",
        }
    )

    # 4. Adding a current disagreement dominates an older origin-only report.
    old = one_report(skipped, 104, created_epoch=1)
    old_aggregate = aggregate_store((old,), epoch=1)
    old_decision = model.authorize(old_aggregate, model.PromotionPolicy(True, True, 0))
    assert old_decision.basis is not None
    later = one_report(model.EXECUTION_DISAGREED, 105, created_epoch=2)
    combined = aggregate_store((old, later), epoch=2)
    combined_decision = model.authorize(combined, model.PromotionPolicy(True, True, 0))
    assert combined.status is model.EXECUTION_DISAGREED
    assert combined_decision.basis is None
    assert old.status is skipped  # frozen report was not rewritten
    results.append(
        {
            "case": "old origin-only + later disagreement -> dominance",
            "old_basis": old_decision.basis.tag.value,
            "aggregate_status": combined.status.tag.value,
            "basis": None,
            "result": "PASS",
        }
    )

    # 5. Two agreement reports intersect their verified projections.
    profile_i2, refs_i2 = profile_for(registry, "I2")
    mask_i2 = profile_i2.verified_projection()
    reports = (
        one_report(model.agreed(profile_i2), 106, digest=evidence_digest(profile_i2, refs_i2)),
        one_report(model.agreed(profile_i3), 107, digest=evidence_digest(profile_i3, refs_i3)),
    )
    intersected = aggregate_store(reports)
    assert intersected.status.profile is not None
    expected_j = mask_i2 & mask_i3
    assert intersected.status.profile.mask == expected_j
    runtime_bit = 1 << AXES.index("runtime_backend")
    decision = model.authorize(
        intersected,
        model.PromotionPolicy(False, True, runtime_bit),
    )
    assert decision.basis is None
    results.append(
        {
            "case": "two agreements -> projection intersection",
            "left_projection": mask_i2,
            "right_projection": mask_i3,
            "J": expected_j,
            "basis": None,
            "result": "PASS",
        }
    )

    # 6. A valid agreement from a different verifier scope cannot grant.
    other_key = model.ReportKey("envelope", "context", "different-scope")
    report = one_report(
        model.agreed(profile_i3),
        108,
        key=other_key,
        digest=evidence_digest(profile_i3, refs_i3),
    )
    aggregate = aggregate_store((report,), key=other_key)
    decision = model.authorize(
        aggregate,
        model.PromotionPolicy(False, True, mask_i3),
    )
    assert decision.basis is None
    results.append(
        {
            "case": "mismatched verifier scope -> no grant",
            "status": decision.state.status.tag.value,
            "basis": None,
            "result": "PASS",
        }
    )

    # 7. A required high-authority evidence reference fails before I(P).
    invalid = registry["profiles"]["I3"]["axes"]["runtime_backend"].copy()
    assert invalid["relation"] == "Distinct"
    assert invalid["provenance"] == "VerifierEstablished"
    invalid["evidence_ref"] = None
    try:
        model.AxisEvidence(
            model.Relation.DISTINCT,
            model.Provenance.VERIFIER_ESTABLISHED,
            invalid["evidence_ref"],
        )
    except ValueError as exc:
        error = str(exc)
    else:
        raise AssertionError("invalid required evidence_ref reached projection")
    results.append(
        {
            "case": "invalid evidence_ref -> ill-formed before projection",
            "report_created": False,
            "error": error,
            "result": "PASS",
        }
    )

    assert len(results) == 7 and all(row["result"] == "PASS" for row in results)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = run_cases()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {"schema": "sealed-surfaces.integration-results/v1", "cases": results},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n",
            encoding="ascii",
            newline="\n",
        )
    for index, result in enumerate(results, 1):
        print(f"INTEGRATION_CASE_{index}: PASS - {result['case']}")
    print("INTEGRATION: 7/7 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
