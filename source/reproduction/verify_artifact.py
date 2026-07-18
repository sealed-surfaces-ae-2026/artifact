"""Offline verification and raw-to-derived regeneration for the artifact."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

sys.dont_write_bytecode = True


ARTIFACT = Path(__file__).resolve().parents[2]
RAW = ARTIFACT / "raw"
DERIVED = ARTIFACT / "derived"
INPUTS = ARTIFACT / "inputs"
MODEL = ARTIFACT / "source" / "model" / "non_laundering_model.py"
MODEL_DIR = MODEL.parent
sys.path.insert(0, str(MODEL_DIR))

import non_laundering_model as model  # noqa: E402
from integration_cases import run_cases  # noqa: E402


SCOPES = ("A0", "A1", "B", "C")
PAIRS = ("I0", "I1", "I2", "I3")
INJECTIONS = (
    "clean",
    "stale-1",
    "stale-2",
    "stale-3",
    "semantics-version-drift",
    "single-operation-backend-fault",
    "final-result-equal-trace-differs",
    "outcome-confusion",
    "diagnostics-promoted-as-success",
    "shared-rust-lineage-fault",
)
AXES = model.INDEPENDENCE_AXES


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value) + b"\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_registry() -> dict[str, Any]:
    return json.loads(
        (INPUTS / "profile-registry" / "profile-registry.json").read_text(
            encoding="ascii"
        )
    )


def read_matrix() -> tuple[list[str], list[dict[str, str]]]:
    with (RAW / "oracle-observations.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        fields = reader.fieldnames
    assert fields is not None
    return fields, rows


def expected_cell(scope: str, pair: str, injection: str) -> str:
    if injection == "clean":
        return "PASS"
    if scope == "A0" and injection not in {"clean", "stale-2"}:
        return "N/A"
    if injection == "stale-1":
        return "SIG"
    if injection == "stale-2":
        return "FRESH"
    if scope == "A1":
        return "MISS"
    if injection == "stale-3":
        return "REEXEC"
    if injection in {"semantics-version-drift", "single-operation-backend-fault"}:
        return "MISS" if pair == "I0" else "REEXEC"
    if injection == "final-result-equal-trace-differs":
        return "REEXEC" if scope == "C" else "MISS"
    if injection in {"outcome-confusion", "diagnostics-promoted-as-success"}:
        return "REEXEC"
    if injection == "shared-rust-lineage-fault":
        return "REEXEC" if pair == "I3" else "MISS"
    raise AssertionError((scope, pair, injection))


def observed_cell(row: dict[str, str]) -> str:
    if row["applicable"] == "no":
        return "N/A"
    if row["injection"] == "clean":
        return "PASS" if row["detected"] == "no" else "FALSE+"
    if row["detected"] == "no":
        return "MISS"
    return {
        "signature": "SIG",
        "nonce+freshness": "FRESH",
        "re-execution agreement": "REEXEC",
    }[row["detection_layer"]]


def validate_registry(registry: dict[str, Any], rows: list[dict[str, str]]) -> dict[str, int]:
    records = registry["evidence_records"]
    assert len(records) == 32
    verified_masks: dict[str, int] = {}
    for pair in PAIRS:
        mask = 0
        axes = registry["profiles"][pair]["axes"]
        assert set(axes) == set(AXES)
        for index, axis in enumerate(AXES):
            evidence = axes[axis]
            ref = evidence["evidence_ref"]
            assert ref in records
            record = records[ref]
            assert record["pair"] == pair and record["axis"] == axis
            assert record["relation"] == evidence["relation"]
            assert record["provenance"] == evidence["provenance"]
            computed = "sha256:" + sha256_bytes(
                canonical_json(record["canonical_derivation_preimage"])
            )
            assert computed == ref
            for required in (
                "source_digest",
                "executable_or_module_digest",
                "build_profile_digest",
                "dependency_lock_digest",
                "relation_rule",
            ):
                assert required in record
            rule = record["relation_rule"]
            assert rule["classification"] == evidence["relation"]
            assert rule["projection_bit"] == (
                1 if evidence["relation"] == "Distinct" else 0
            )
            if (
                evidence["relation"] == "Distinct"
                and evidence["provenance"]
                in {"RegistryVerified", "ExternallyAttested", "VerifierEstablished"}
                and ref
            ):
                mask |= 1 << index
        verified_masks[pair] = mask

    for row in rows:
        pair = row["independence"]
        for axis in AXES:
            expected = registry["profiles"][pair]["axes"][axis]
            assert row[f"{axis}_relation"] == expected["relation"]
            assert row[f"{axis}_provenance"] == expected["provenance"]
            assert row[f"{axis}_evidence_ref"] == expected["evidence_ref"]
    return verified_masks


def validate_and_derive_matrix(full: bool) -> tuple[list[dict[str, str]], dict[str, int]]:
    fields, rows = read_matrix()
    keys = {(row["scope"], row["independence"], row["injection"]) for row in rows}
    expected_keys = {
        (scope, pair, injection)
        for scope in SCOPES
        for pair in PAIRS
        for injection in INJECTIONS
    }
    assert len(rows) == 160 and keys == expected_keys
    registry = load_registry()
    masks = validate_registry(registry, rows)
    for row in rows:
        key = (row["scope"], row["independence"], row["injection"])
        assert observed_cell(row) == expected_cell(*key), key
        assert row["oracle_match"] == "yes"
    lookup = {
        (row["scope"], row["independence"], row["injection"]): row
        for row in rows
    }
    representative = (
        ("A0", "I0", "stale-3", "N/A"),
        ("A1", "I0", "stale-3", "MISS"),
        ("B", "I0", "stale-3", "REEXEC"),
        ("C", "I3", "stale-3", "REEXEC"),
        ("B", "I1", "shared-rust-lineage-fault", "MISS"),
        ("C", "I2", "shared-rust-lineage-fault", "MISS"),
        ("B", "I3", "shared-rust-lineage-fault", "REEXEC"),
    )
    for scope, pair, injection, expected in representative:
        assert observed_cell(lookup[(scope, pair, injection)]) == expected

    order = {
        (scope, pair, injection): (SCOPES.index(scope), PAIRS.index(pair), INJECTIONS.index(injection))
        for scope in SCOPES
        for pair in PAIRS
        for injection in INJECTIONS
    }
    rows.sort(key=lambda row: order[(row["scope"], row["independence"], row["injection"])])
    DERIVED.mkdir(parents=True, exist_ok=True)
    with (DERIVED / "matrix.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    if full:
        assert (DERIVED / "matrix.csv").read_bytes() == (
            RAW / "oracle-observations.csv"
        ).read_bytes()
    return rows, masks


def load_observation_run(name: str) -> dict[tuple[str, str], dict[str, Any]]:
    payload = json.loads(
        (RAW / "per-engine-observations" / f"{name}.json").read_text(
            encoding="ascii"
        )
    )
    observations = payload["observations"]
    assert len(observations) == 20
    result = {(row["engine"], row["source_label"]): row for row in observations}
    assert len(result) == 20
    return result


def validate_determinism() -> dict[str, Any]:
    first = load_observation_run("run-1")
    second = load_observation_run("run-2")
    assert first.keys() == second.keys()
    comparisons = []
    by_program: dict[str, set[bytes]] = {}
    transcript_one: dict[str, Any] = {}
    transcript_two: dict[str, Any] = {}
    for engine, program in sorted(first):
        one = first[(engine, program)]
        two = second[(engine, program)]
        canonical_one = canonical_json(one["canonical_transcript"])
        canonical_two = canonical_json(two["canonical_transcript"])
        raw_one = canonical_json(one["raw"])
        raw_two = canonical_json(two["raw"])
        assert canonical_one == canonical_two
        assert raw_one == raw_two
        by_program.setdefault(program, set()).add(canonical_one)
        key = f"{engine}/{program}"
        transcript_one[key] = one["canonical_transcript"]
        transcript_two[key] = two["canonical_transcript"]
        comparisons.append(
            {
                "engine": engine,
                "program": program,
                "canonical_run_1_sha256": sha256_bytes(canonical_one),
                "canonical_run_2_sha256": sha256_bytes(canonical_two),
                "canonical_byte_identical": True,
                "raw_run_1_sha256": sha256_bytes(raw_one),
                "raw_run_2_sha256": sha256_bytes(raw_two),
                "raw_byte_identical": True,
            }
        )
    assert all(len(values) == 1 for values in by_program.values())
    canonical_dir = DERIVED / "canonical-transcripts"
    write_json(canonical_dir / "run-1.json", transcript_one)
    write_json(canonical_dir / "run-2.json", transcript_two)
    payload = {
        "schema": "sealed-surfaces.determinism/v1",
        "fresh_process_paths": len(comparisons),
        "all_per_path_canonical_byte_identical": True,
        "all_per_path_raw_byte_identical": True,
        "all_cross_engine_canonical_byte_identical": True,
        "comparisons": comparisons,
    }
    write_json(DERIVED / "determinism.json", payload)
    return payload


def derive_independence(registry: dict[str, Any], masks: dict[str, int]) -> dict[str, Any]:
    payload = {
        "schema": "sealed-surfaces.independence-profiles/v1",
        "relation_rules": registry["relation_rules"],
        "profiles": {},
        "evidence_records": registry["evidence_records"],
    }
    for pair in PAIRS:
        profile = registry["profiles"][pair].copy()
        profile["verified_projection"] = masks[pair]
        payload["profiles"][pair] = profile
    write_json(DERIVED / "independence-profiles.json", payload)
    return payload


def derive_carrier() -> list[dict[str, Any]]:
    with (RAW / "carrier" / "raw-trials.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    selected = [
        row
        for row in rows
        if row["payload_regime"] == "large"
        and row["channel_family"] == "photo_recompress"
        and row["experiment"] in {"equal_area", "equal_module"}
        and row["arm"] in {"custom_grid", "mosaic_outer_rs"}
    ]
    assert len(selected) == 108

    def summarize(experiment: str, arm: str, subset: list[dict[str, str]]) -> dict[str, Any]:
        assert subset
        diagnostics = [
            float(row["diagnostic_accuracy"])
            for row in subset
            if row["diagnostic_accuracy"]
            and math.isfinite(float(row["diagnostic_accuracy"]))
        ]
        return {
            "experiment": experiment,
            "arm": arm,
            "trials": len(subset),
            "robust_recover_rate": sum(float(row["robust_recover"]) for row in subset) / len(subset),
            "decoder_wrong_output_rate": sum(float(row["decoder_wrong_output"]) for row in subset) / len(subset),
            "authenticated_false_acceptance_rate": sum(float(row["authenticated_false_acceptance"]) for row in subset) / len(subset),
            "diagnostic_accuracy_mean": sum(diagnostics) / len(diagnostics),
        }

    summaries = []
    for experiment in ("equal_area", "equal_module"):
        for arm in ("custom_grid", "mosaic_outer_rs"):
            subset = [
                row for row in selected if row["experiment"] == experiment and row["arm"] == arm
            ]
            summaries.append(summarize(experiment, arm, subset))
    for arm in ("custom_grid", "mosaic_outer_rs"):
        summaries.append(summarize("pooled", arm, [row for row in selected if row["arm"] == arm]))

    fields = (
        "experiment",
        "arm",
        "trials",
        "robust_recover_rate",
        "decoder_wrong_output_rate",
        "authenticated_false_acceptance_rate",
        "diagnostic_accuracy_mean",
    )
    with (DERIVED / "carrier-decision-subset.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(summaries)

    with (INPUTS / "carrier-baselines" / "decision-subset.csv").open(
        newline="", encoding="utf-8"
    ) as stream:
        baseline = list(csv.DictReader(stream))
    baseline_index = {(row["experiment"], row["arm"]): row for row in baseline}
    assert len(baseline_index) == 6
    for row in summaries:
        expected = baseline_index[(row["experiment"], row["arm"])]
        assert row["trials"] == int(expected["trials"])
        for field in fields[3:]:
            assert math.isclose(row[field], float(expected[field]), rel_tol=0.0, abs_tol=1e-15)
    return summaries


AXIS_TEX = {
    "source_lineage": r"\code{source\_\allowbreak{}lineage}",
    "parser_lineage": r"\code{parser\_\allowbreak{}lineage}",
    "semantics_core_lineage": r"\code{sema\allowbreak{}ntics\_\allowbreak{}core\_\allowbreak{}lineage}",
    "build_toolchain": r"\code{build\_\allowbreak{}tool\allowbreak{}chain}",
    "runtime_backend": r"\code{runtime\_\allowbreak{}backend}",
    "dependency_set": r"\code{depen\allowbreak{}dency\_\allowbreak{}set}",
    "hardware_architecture": r"\code{hardware\_\allowbreak{}archit\allowbreak{}ecture}",
    "operator_or_organization": r"\code{operator\_\allowbreak{}or\_\allowbreak{}organi\allowbreak{}zation}",
}

DISPLAY_INJECTION = {
    "clean": "clean",
    "stale-1": "stale-1",
    "stale-2": "stale-2",
    "stale-3": "stale-3",
    "semantics-version-drift": "semantics-version-drift",
    "single-operation-backend-fault": "single-op backend fault",
    "final-result-equal-trace-differs": "equal-result trace divergence",
    "outcome-confusion": "outcome confusion",
    "diagnostics-promoted-as-success": "diagnostics as success",
    "shared-rust-lineage-fault": "Rust-backend common-mode",
}


def render_table2(registry: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    semantics = []
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Recorded eight-axis RQ3 independence vectors.}",
        r"\label{tab:rq3-profiles}",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{2.2pt}",
        r"\renewcommand{\arraystretch}{1.08}",
        r"\begin{tabular}{p{0.14\textwidth}p{0.19\textwidth}p{0.19\textwidth}p{0.19\textwidth}p{0.19\textwidth}}",
        r"\toprule",
        r"\textbf{Axis} & \textbf{I0: E3 $\rightarrow$ E3} & \textbf{I1: E3 $\rightarrow$ E1} & \textbf{I2: E3 $\rightarrow$ E2} & \textbf{I3: E1 $\rightarrow$ E4} \\",
        r"\midrule",
    ]
    for axis in AXES:
        cells = [registry["profiles"][pair]["axes"][axis]["paper_summary"] for pair in PAIRS]
        semantics.append({"axis": axis, "cells": cells})
        lines.append(AXIS_TEX[axis] + " & " + " & ".join(cells) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""])
    return "\n".join(lines), semantics


def render_table3(rows: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]]:
    lookup = {
        (row["scope"], row["independence"], row["injection"]): observed_cell(row)
        for row in rows
    }
    semantics = []
    lines = [
        r"\begin{table*}[t]",
        r"\caption{RQ3 detecting layer and harness ground-truth injection class.}",
        r"\label{tab:rq3-matrix}",
        r"\centering",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{0.8pt}",
        r"\renewcommand{\arraystretch}{1.08}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{lcccccccccccccccc}",
        r"\toprule",
        r"\textbf{Injection} & "
        + " & ".join(
            rf"\textbf{{{scope}/{pair}}}" for scope in SCOPES for pair in PAIRS
        )
        + r" \\",
        r"\midrule",
    ]
    for injection in INJECTIONS:
        cells = [lookup[(scope, pair, injection)] for scope in SCOPES for pair in PAIRS]
        display = DISPLAY_INJECTION[injection]
        semantics.append({"injection": display, "cells": cells})
        lines.append(display + " & " + " & ".join(cells) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", "}", r"\end{table*}", ""])
    return "\n".join(lines), semantics


def render_table4(summaries: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    fairness = {"equal_area": "equal area", "equal_module": "equal module", "pooled": "pooled"}
    arms = {"custom_grid": "custom grid", "mosaic_outer_rs": "mosaic + outer RS"}
    order = [
        (experiment, arm)
        for experiment in ("equal_area", "equal_module", "pooled")
        for arm in ("custom_grid", "mosaic_outer_rs")
    ]
    index = {(row["experiment"], row["arm"]): row for row in summaries}
    semantics = []
    lines = [
        r"\begin{table*}[t]",
        r"\caption{Pre-registered carrier decision subset.}",
        r"\label{tab:carrier-result}",
        r"\centering",
        r"\scriptsize",
        r"\setlength{\tabcolsep}{2.2pt}",
        r"\renewcommand{\arraystretch}{1.08}",
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{llrrrrr}",
        r"\toprule",
        r"\textbf{Fairness mode} & \textbf{Arm} & \textbf{Trials} & \textbf{\code{robust\allowbreak{}Recover}} & \textbf{Decoder wrong-output} & \textbf{Authenticated false acceptance} & \textbf{Diagnostic F1} \\",
        r"\midrule",
    ]
    for experiment, arm in order:
        row = index[(experiment, arm)]
        semantic = {
            "fairness_mode": fairness[experiment],
            "arm": arms[arm],
            "trials": row["trials"],
            "robust_recover": f"{row['robust_recover_rate']:.3f}",
            "decoder_wrong_output": f"{row['decoder_wrong_output_rate']:.3f}",
            "authenticated_false_acceptance": f"{row['authenticated_false_acceptance_rate']:.3f}",
            "diagnostic_f1": f"{row['diagnostic_accuracy_mean']:.3f}",
        }
        semantics.append(semantic)
        lines.append(
            " & ".join(
                (
                    semantic["fairness_mode"],
                    semantic["arm"],
                    str(semantic["trials"]),
                    semantic["robust_recover"],
                    semantic["decoder_wrong_output"],
                    semantic["authenticated_false_acceptance"],
                    semantic["diagnostic_f1"],
                )
            )
            + r" \\" 
        )
    lines.extend([r"\bottomrule", r"\end{tabular}", "}", r"\end{table*}", ""])
    return "\n".join(lines), semantics


def derive_tables(
    rows: list[dict[str, str]], registry: dict[str, Any], carrier: list[dict[str, Any]]
) -> None:
    table2, semantic2 = render_table2(registry)
    table3, semantic3 = render_table3(rows)
    table4, semantic4 = render_table4(carrier)
    (DERIVED / "table2.tex").write_text(table2, encoding="ascii", newline="\n")
    (DERIVED / "table3.tex").write_text(table3, encoding="ascii", newline="\n")
    (DERIVED / "table4.tex").write_text(table4, encoding="ascii", newline="\n")
    semantics = {"table2": semantic2, "table3": semantic3, "table4": semantic4}
    write_json(DERIVED / "table-semantics.json", semantics)

    baseline = json.loads(
        (INPUTS / "preregistration" / "paper-tables.json").read_text(encoding="ascii")
    )
    review = ARTIFACT / "paper" / "sealed-surfaces-scored-review.pdf"
    assert sha256_file(review) == baseline["review_pdf_sha256"]
    assert semantics == baseline["semantics"]


def quick_model_checks() -> None:
    skipped = model.not_reexecuted(model.NotReexecutedReason.SKIPPED_BY_POLICY)
    state = model.State(skipped)
    policy = model.PromotionPolicy(False, True, 1)
    laundering = model.policy_successors(state, policy, broken_laundering=True)
    assert laundering and laundering[0].target.status != laundering[0].source.status

    raw_profile = model.IndependenceProfile(
        tuple(
            model.AxisEvidence(model.Relation.DISTINCT, model.Provenance.PUBLISHER_ASSERTED)
            for _ in AXES
        )
    )
    assert raw_profile.verified_projection() == 0
    assert raw_profile.relation_only_mask() == (1 << len(AXES)) - 1
    assert not policy.accepts_projection(raw_profile.verified_projection())
    assert policy.accepts_projection(raw_profile.relation_only_mask())
    assert policy.unsafely_accepts_raw_profile(raw_profile)


def full_model_checks() -> None:
    result = subprocess.run(
        [sys.executable, str(MODEL), "--self-check"],
        cwd=ARTIFACT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "NON-LAUNDERING MODEL: PASS" in output
    assert "BROKEN VARIANT CAUGHT:" in output
    assert "PUBLISHER-ASSERTED MUTATION CAUGHT:" in output
    assert "RAW-P POLICY MUTATION CAUGHT:" in output
    (DERIVED / "model-self-check.txt").write_text(output, encoding="utf-8", newline="\n")


def write_integration(results: list[dict[str, Any]]) -> None:
    write_json(
        DERIVED / "integration-results.json",
        {"schema": "sealed-surfaces.integration-results/v1", "cases": results},
    )


def validate_blinding() -> None:
    joined = ["lis", "pex"]
    host = ["top", "az"]
    bundle = ["j", "57"]
    banned_tokens = ("".join(joined), "".join(host), "".join(bundle))
    legacy_labels = ("".join(("l", "il")), "".join(("l", "it")))
    word_labels = re.compile(
        r"\b(?:" + "|".join(map(re.escape, legacy_labels)) + r")\b",
        re.IGNORECASE,
    )
    drive_path = re.compile(r"\b[A-Za-z]:[\\/]")
    home_path = re.compile(r"/(?:home|Users)/[^/\s]+", re.IGNORECASE)
    remote_tokens = (
        "".join(("ht", "tp", "://")),
        "".join(("ht", "tps", "://")),
        "".join(("g", "it", "@")),
        "".join(("git", "hub", ".")),
    )
    mail = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
    text_suffixes = {
        ".md", ".txt", ".json", ".csv", ".py", ".sh", ".ps1", ".toml",
        ".lock", ".rs", ".mjs", ".l", ".tex", ".bbl",
    }
    failures = []
    for path in sorted(ARTIFACT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ARTIFACT).as_posix()
        lowered_path = relative.lower()
        if any(token in lowered_path for token in banned_tokens):
            failures.append(f"path token: {relative}")
        if path.suffix.lower() not in text_suffixes and path.name != "MANIFEST.sha256":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = text.lower()
        if any(token in lowered for token in banned_tokens):
            failures.append(f"content token: {relative}")
        if word_labels.search(text) or drive_path.search(text) or home_path.search(text):
            failures.append(f"identity/path label: {relative}")
        remote_is_provenance = relative != "paper/review-extracted.txt"
        if (
            remote_is_provenance
            and any(token in lowered for token in remote_tokens)
        ) or mail.search(text):
            failures.append(f"remote/email label: {relative}")
    assert not failures, "\n".join(failures)
    extracted = (ARTIFACT / "paper" / "review-extracted.txt").read_text(encoding="utf-8")
    assert extracted.count("Anonymous Author(s)") >= 1


def validate_manifest() -> None:
    manifest = ARTIFACT / "MANIFEST.sha256"
    if not manifest.is_file():
        raise AssertionError("MANIFEST.sha256 is missing")
    entries = []
    for line in manifest.read_text(encoding="ascii").splitlines():
        digest, relative = line.split("  ", 1)
        path = ARTIFACT / Path(relative)
        assert path.is_file(), relative
        assert sha256_file(path) == digest, relative
        entries.append(relative)
    assert len(entries) == len(set(entries))
    assert entries == sorted(entries), "MANIFEST.sha256 is not in portable path order"
    actual = sorted(
        path.relative_to(ARTIFACT).as_posix()
        for path in ARTIFACT.rglob("*")
        if path.is_file() and path != manifest
    )
    assert entries == actual, "MANIFEST.sha256 is incomplete or contains extra paths"
    required = {
        "LIMITATIONS.md",
        "carrier/CARRIER-APPENDIX.md",
        "proofs/PROPERTIES.md",
        "source/model/non_laundering_model.py",
        "raw/oracle-observations.csv",
        "derived/matrix.csv",
        "derived/table2.tex",
        "derived/table3.tex",
        "derived/table4.tex",
        "inputs/preregistration/paper-tables.json",
        "paper/review-extracted.txt",
        "paper/sealed-surfaces-scored-review.pdf",
    }
    assert required.issubset(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--quick", action="store_true")
    mode.add_argument("--full", action="store_true")
    parser.add_argument(
        "--development-no-manifest",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"

    if args.full:
        full_model_checks()
    else:
        quick_model_checks()

    rows, masks = validate_and_derive_matrix(args.full)
    registry = load_registry()
    derive_independence(registry, masks)
    validate_determinism()
    carrier = derive_carrier()
    derive_tables(rows, registry, carrier)
    integration = run_cases()
    write_integration(integration)
    if args.full:
        validate_blinding()
    if not args.development_no_manifest:
        validate_manifest()

    print("MODEL: PASS")
    print("MUTATION_STATUS_LAUNDERING: CAUGHT")
    print("MUTATION_PUBLISHER_PROJECTION: CAUGHT")
    print("MUTATION_RAW_PROFILE_POLICY: CAUGHT")
    print("RQ3_ORACLE: 160/160 PASS")
    print("DETERMINISM_RERUN: BYTE_IDENTICAL")
    print("CARRIER_TABLE: REPRODUCED")
    print("INTEGRATION: 7/7 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
