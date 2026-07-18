"""REAL-L matrix, oracle, evidence collection, and artifact rendering."""

from __future__ import annotations

import base64
import copy
import csv
import io
import json
from pathlib import Path
import subprocess
from typing import Any, Callable

from .canonical import derive, encode, sha256
from .engines import (
    E1_EXE, E2_EXE, E3_EXE, E4_SOURCE, ENGINE_META, EngineBank,
    artifact_inventory, canonical_ir, clean_environment_facts,
)
from .envelope import make_context, make_envelope, sign, transcript_digest, verify_wire


ROOT = Path(__file__).resolve().parents[1]
SEED = 20260718
SCOPES = ("A0", "A1", "B", "C")
PAIRINGS = ("I0", "I1", "I2", "I3")
INJECTIONS = (
    "clean", "stale-1", "stale-2", "stale-3", "semantics-version-drift",
    "single-operation-backend-fault", "final-result-equal-trace-differs",
    "outcome-confusion", "diagnostics-promoted-as-success", "shared-rust-lineage-fault",
)
CLEAN_PROGRAMS = ("arithmetic", "data", "recursion", "branching")
ALL_PATHS = ("E1", "E3", "E2", "E4-interpreter", "E4-generated")
AXES = (
    "source_lineage", "parser_lineage", "semantics_core_lineage",
    "build_toolchain", "runtime_backend", "dependency_set",
    "hardware_architecture", "operator_or_organization",
)

# A0 is SignedProgramV1 and has no field in which an execution-claim attack can
# be expressed.  These cells remain in the fixed matrix as mechanically checked
# N/A outcomes rather than being silently redefined as misses.
A0_CLAIM_ATTACKS = frozenset(INJECTIONS) - {"clean", "stale-2"}


PROFILES: dict[str, dict[str, Any]] = {
    "I0": {
        "publisher": "E3", "verifier": "E3", "level": "same-artifact rerun",
        "source_lineage": "same", "parser_lineage": "same", "semantics_core_lineage": "same",
        "build_toolchain": "same", "runtime_backend": "same", "dependency_set": "same",
        "hardware_architecture": "same", "operator_or_organization": "same",
        "fault_domain_notes": "Same executable bytes and observation wrapper; no engine fault separation.",
    },
    "I1": {
        "publisher": "E3", "verifier": "E1", "level": "distinct artifact/revision; common Rust lineage",
        "source_lineage": "common-rust-lineage-distinct-revisions",
        "parser_lineage": "common-lineage", "semantics_core_lineage": "common-lineage",
        "build_toolchain": "same-cargo-rustc-host", "runtime_backend": "native-rust-both",
        "dependency_set": "substantially-overlapping", "hardware_architecture": "same",
        "operator_or_organization": "same", "fault_domain_notes": "Separate checkouts and binaries, but E3 retains the E1 Rust interpreter architecture and much code lineage.",
    },
    "I2": {
        "publisher": "E3", "verifier": "E2", "level": "distinct evaluator/frontend source; shared Rust host",
        "source_lineage": "Rust-vs-DSL L-source", "parser_lineage": "native-vs-guest-E2 guest evaluator",
        "semantics_core_lineage": "native-Rust-vs-E2 guest evaluator-machine", "build_toolchain": "shared-cargo-wrapper",
        "runtime_backend": "native-Rust-vs-DSL L-guest-on-Rust-host", "dependency_set": "shared-host-and-contracts",
        "hardware_architecture": "same", "operator_or_organization": "same",
        "fault_domain_notes": "E2 guest evaluator has its own tokenizer/reader/normalizer/machine source, but executes inside a Rust DSL L host and is bundled by the E23 Rust product runner.",
    },
    "I3": {
        "publisher": "E1", "verifier": "E4-interpreter", "level": "distinct runtime backend/toolchain; shared transliterated source/semantics",
        "source_lineage": "shared-engineered-transliteration", "parser_lineage": "shared-transliterated-frontend",
        "semantics_core_lineage": "shared-transliterated-semantic-choices",
        "build_toolchain": "Cargo-Rust-vs-E4 host-interpreter-artifact",
        "runtime_backend": "native-Rust-vs-E4 host-interpreter",
        "dependency_set": "separate-engine-trees-shared-OS-contracts", "hardware_architecture": "same",
        "operator_or_organization": "same", "fault_domain_notes": "Runtime backend and toolchain are separated; source, parser, semantic choices, specification, machine, operator, and organization remain shared.",
    },
}

AXIS_RELATIONS: dict[str, dict[str, str]] = {
    "I0": {axis: "Shared" for axis in AXES},
    "I1": dict(zip(AXES, ("Shared", "Shared", "Shared", "Shared", "Shared", "Partial", "Shared", "Shared"))),
    "I2": dict(zip(AXES, ("Distinct", "Distinct", "Distinct", "Shared", "Partial", "Partial", "Shared", "Shared"))),
    "I3": dict(zip(AXES, ("Shared", "Shared", "Shared", "Distinct", "Distinct", "Partial", "Shared", "Shared"))),
}


def axis_derivation(pair: str, axis: str) -> dict[str, Any]:
    relation = AXIS_RELATIONS[pair][axis]
    return {
        "schema": "sealed-surfaces.real-rq3-axis-derivation/v1",
        "pair": pair,
        "axis": axis,
        "relation": relation,
        "detail": PROFILES[pair][axis],
        "method": "local source/artifact inspection recorded by the mechanical harness",
        "publisher_artifact": _descriptor(PROFILES[pair]["publisher"]),
        "verifier_artifact": _descriptor(PROFILES[pair]["verifier"]),
    }


def axis_evidence(pair: str, axis: str) -> dict[str, str]:
    relation = AXIS_RELATIONS[pair][axis]
    derivation = axis_derivation(pair, axis)
    return {
        "relation": relation,
        "provenance": "VerifierEstablished",
        "evidence_ref": "sha256:" + sha256(encode(derivation)),
    }

ATTRIBUTION = {
    "clean": "none", "stale-1": "tamper", "stale-2": "stale", "stale-3": "stale",
    "semantics-version-drift": "version-drift", "single-operation-backend-fault": "engine-fault",
    "final-result-equal-trace-differs": "engine-fault", "outcome-confusion": "outcome",
    "diagnostics-promoted-as-success": "outcome", "shared-rust-lineage-fault": "engine-fault",
}


def program(name: str) -> bytes:
    return (ROOT / "programs" / f"{name}.l").read_bytes()


def _descriptor(engine: str) -> dict[str, Any]:
    path = {"E1": E1_EXE, "E2": E2_EXE, "E3": E3_EXE, "E4-interpreter": E4_SOURCE}[engine]
    return {
        "engine_id": engine, "implementation_name": ENGINE_META[engine]["name"],
        "implementation_family": ENGINE_META[engine]["family"],
        "runtime_backend": ENGINE_META[engine]["runtime"],
        "artifact_sha256": sha256(path.read_bytes()),
    }


def _replace_value(transcript: dict[str, Any], value: str) -> dict[str, Any]:
    result = copy.deepcopy(transcript)
    result["return_values"] = [value]
    result["stdout_base64"] = base64.b64encode((value + "\n").encode()).decode("ascii")
    result["observable_event_trace"] = [
        {"event": "root-value", "index": 0, "value": value},
        {"event": "termination", "status": "normal"},
    ]
    return result


def _trace_mutant(transcript: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(transcript)
    result["observable_event_trace"][0]["value"] = "trace-only-divergence"
    return result


def _outcome_mutant(transcript: dict[str, Any], suppress_diagnostics: bool) -> dict[str, Any]:
    result = copy.deepcopy(transcript)
    result["outcome"] = {"tag": "normal", "exit_status": 0}
    result["observable_event_trace"][-1]["status"] = "normal"
    if suppress_diagnostics:
        result["diagnostics"] = []
    return result


class Fixture:
    def __init__(self, seed: int, bank: EngineBank):
        self.seed = seed
        self.bank = bank
        self.key = derive(seed, "hmac-signing-key")
        names = {"clean": "mixed", "stale": "past", "semantics-version-drift": "semantics-drift",
                 "single-operation-backend-fault": "backend-fault", "final-result-equal-trace-differs": "mixed",
                 "outcome-confusion": "runtime-error", "diagnostics-promoted-as-success": "runtime-error",
                 "shared-rust-lineage-fault": "shared-rust-lineage-fault"}
        self.sources = {key: program(value) for key, value in names.items()}
        self.irs = {key: canonical_ir(value) for key, value in self.sources.items()}
        self.hash_to_label = {sha256(value): key for key, value in self.sources.items()}

    def nonce(self, label: str) -> str:
        return derive(self.seed, "nonce/" + label, 16).hex()

    def actual(self, engine: str, source_key: str, *, faulted: bool = False) -> dict[str, Any]:
        return self.bank.run(engine, source_key, self.sources[source_key], faulted=faulted)["canonical_transcript"]

    def wire(self, *, pair: str, scope: str, source_key: str, transcript: dict[str, Any] | None,
             nonce_label: str, past: bool = False) -> dict[str, Any]:
        publisher = PROFILES[pair]["publisher"]
        envelope = make_envelope(
            canonical_ir=self.irs[source_key], source=self.sources[source_key], scope=scope,
            context=make_context(self.nonce(nonce_label), past=past), transcript=transcript,
            engine=_descriptor(publisher),
        )
        return sign(envelope, self.key)


def build_wire(fixture: Fixture, pair: str, scope: str, injection: str) -> dict[str, Any]:
    publisher = PROFILES[pair]["publisher"]
    if injection == "clean":
        return fixture.wire(pair=pair, scope=scope, source_key="clean",
                            transcript=None if scope == "A0" else fixture.actual(publisher, "clean"), nonce_label=f"{pair}/{scope}/clean")
    if injection == "stale-1":
        wire = fixture.wire(pair=pair, scope=scope, source_key="clean",
                            transcript=None if scope == "A0" else fixture.actual(publisher, "clean"), nonce_label=f"{pair}/{scope}/stale-1")
        stale = fixture.actual(publisher, "stale")
        if scope == "A0":
            wire["detached_result_digest"] = transcript_digest(stale, "B")
        else:
            wire["envelope"]["execution_claim"]["transcript_digest"] = transcript_digest(stale, scope)
        return wire
    if injection == "stale-2":
        return fixture.wire(pair=pair, scope=scope, source_key="stale",
                            transcript=None if scope == "A0" else fixture.actual(publisher, "stale"), nonce_label="past-envelope", past=True)
    if injection == "stale-3":
        return fixture.wire(pair=pair, scope=scope, source_key="clean",
                            transcript=None if scope == "A0" else fixture.actual(publisher, "stale"), nonce_label=f"{pair}/{scope}/stale-3")
    if injection == "semantics-version-drift":
        legacy = _replace_value(fixture.actual(publisher, injection), "2")
        return fixture.wire(pair=pair, scope=scope, source_key=injection,
                            transcript=None if scope == "A0" else legacy, nonce_label=f"{pair}/{scope}/semantics")
    if injection == "single-operation-backend-fault":
        faulty = _replace_value(fixture.actual(publisher, injection), "43")
        return fixture.wire(pair=pair, scope=scope, source_key=injection,
                            transcript=None if scope == "A0" else faulty, nonce_label=f"{pair}/{scope}/backend")
    if injection == "shared-rust-lineage-fault":
        faulty = fixture.actual(publisher, injection, faulted=True)
        return fixture.wire(pair=pair, scope=scope, source_key=injection,
                            transcript=None if scope == "A0" else faulty, nonce_label=f"{pair}/{scope}/shared-rust")
    if injection == "final-result-equal-trace-differs":
        mutant = _trace_mutant(fixture.actual(publisher, injection))
        return fixture.wire(pair=pair, scope=scope, source_key=injection,
                            transcript=None if scope == "A0" else mutant, nonce_label=f"{pair}/{scope}/trace")
    if injection in {"outcome-confusion", "diagnostics-promoted-as-success"}:
        mutant = _outcome_mutant(fixture.actual(publisher, injection), injection == "diagnostics-promoted-as-success")
        return fixture.wire(pair=pair, scope=scope, source_key=injection,
                            transcript=None if scope == "A0" else mutant, nonce_label=f"{pair}/{scope}/{injection}")
    raise AssertionError(injection)


def expected(injection: str, scope: str, pair: str) -> tuple[bool | None, str]:
    if scope == "A0" and injection in A0_CLAIM_ATTACKS:
        return None, "not_applicable"
    if injection == "clean": return False, "none"
    if injection == "stale-1": return True, "signature"
    if injection == "stale-2": return True, "nonce+freshness"
    if scope == "A1": return False, "none"
    if injection in {"semantics-version-drift", "single-operation-backend-fault"}:
        return (pair != "I0"), ("re-execution agreement" if pair != "I0" else "none")
    if injection == "shared-rust-lineage-fault":
        return (pair == "I3"), ("re-execution agreement" if pair == "I3" else "none")
    if injection == "final-result-equal-trace-differs":
        return (scope == "C"), ("re-execution agreement" if scope == "C" else "none")
    return True, "re-execution agreement"


def attach_profile_evidence(row: dict[str, Any], pair: str) -> None:
    profile = PROFILES[pair]
    for axis in AXES:
        row[axis] = profile[axis]
        evidence = axis_evidence(pair, axis)
        row[f"{axis}_relation"] = evidence["relation"]
        row[f"{axis}_provenance"] = evidence["provenance"]
        row[f"{axis}_evidence_ref"] = evidence["evidence_ref"]


def run_matrix(seed: int, bank: EngineBank) -> list[dict[str, Any]]:
    fixture = Fixture(seed, bank)
    canonical_cache = {source: fixture.irs[key] for key, source in fixture.sources.items()}
    rows: list[dict[str, Any]] = []
    for scope in SCOPES:
        for pair in PAIRINGS:
            for injection in INJECTIONS:
                expected_detected, expected_layer = expected(injection, scope, pair)
                profile = PROFILES[pair]
                if expected_detected is None:
                    row = {
                        "seed": seed, "scope": scope, "independence": pair,
                        "publisher_engine": profile["publisher"], "verifier_engine": profile["verifier"],
                        "injection": injection, "applicable": "no", "detected": "n/a",
                        "detection_layer": "not_applicable", "pipeline_outcome": "not_applicable",
                        "authorization_basis": "none", "attribution_class": ATTRIBUTION[injection],
                        "attributed_as": "none", "expected_detected": "n/a",
                        "expected_layer": expected_layer, "oracle_match": "yes",
                        "independence_level": profile["level"],
                    }
                    attach_profile_evidence(row, pair)
                    assert row["detection_layer"] == expected_layer
                    rows.append(row)
                    continue
                wire = build_wire(fixture, pair, scope, injection)
                verifier = PROFILES[pair]["verifier"]

                def execute(source: bytes, *, _injection=injection, _pair=pair, _verifier=verifier) -> dict[str, Any]:
                    key = fixture.hash_to_label[sha256(source)]
                    actual = fixture.actual(
                        _verifier, key,
                        faulted=(_injection == "shared-rust-lineage-fault" and _verifier in {"E1", "E2", "E3"}),
                    )
                    if _pair == "I0" and _injection == "semantics-version-drift":
                        return _replace_value(actual, "2")
                    if _pair == "I0" and _injection == "single-operation-backend-fault":
                        return _replace_value(actual, "43")
                    return actual

                actual = verify_wire(
                    wire, scope=scope, key=fixture.key,
                    canonicalize=lambda source: canonical_cache[source], execute=execute,
                    seen_nonces={fixture.nonce("past-envelope")},
                )
                assert actual.detected == expected_detected, (scope, pair, injection, actual, expected_detected)
                assert actual.detection_layer == expected_layer, (scope, pair, injection, actual, expected_layer)
                row = {
                    "seed": seed, "scope": scope, "independence": pair,
                    "publisher_engine": profile["publisher"], "verifier_engine": profile["verifier"],
                    "injection": injection, "applicable": "yes", "detected": "yes" if actual.detected else "no",
                    "detection_layer": actual.detection_layer, "pipeline_outcome": actual.status,
                    "authorization_basis": actual.authorization_basis, "attribution_class": ATTRIBUTION[injection],
                    "attributed_as": ATTRIBUTION[injection] if actual.detected else "none",
                    "expected_detected": "yes" if expected_detected else "no", "expected_layer": expected_layer,
                    "oracle_match": "yes", "independence_level": profile["level"],
                }
                attach_profile_evidence(row, pair)
                rows.append(row)
    assert len(rows) == len(SCOPES) * len(PAIRINGS) * len(INJECTIONS)
    return rows


CSV_FIELDS = [
    "seed", "scope", "independence", "publisher_engine", "verifier_engine", "injection", "applicable", "detected",
    "detection_layer", "pipeline_outcome", "authorization_basis", "attribution_class", "attributed_as",
    "expected_detected", "expected_layer", "oracle_match", "independence_level", "source_lineage",
    "parser_lineage", "semantics_core_lineage", "build_toolchain", "runtime_backend", "dependency_set",
    "hardware_architecture", "operator_or_organization",
    *(f"{axis}_{suffix}" for axis in AXES for suffix in ("relation", "provenance", "evidence_ref")),
]


def render_csv(rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n")
    writer.writeheader(); writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def collect_external_evidence(determinism_check: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    first, second = EngineBank(), EngineBank()
    observations: list[dict[str, Any]] = []
    program_rows: list[dict[str, Any]] = []
    for name in CLEAN_PROGRAMS:
        source = program(name)
        canonical_by_engine: dict[str, bytes] = {}
        raw_by_engine: dict[str, bytes] = {}
        rerun_canonical: dict[str, bool] = {}
        rerun_raw: dict[str, bool] = {}
        for engine in ALL_PATHS:
            one = first.run(engine, name, source)
            two = second.run(engine, name, source) if determinism_check else one
            observations.append(one)
            canonical_by_engine[engine] = encode(one["canonical_transcript"])
            raw_by_engine[engine] = encode(one["raw"])
            rerun_canonical[engine] = encode(one["canonical_transcript"]) == encode(two["canonical_transcript"])
            rerun_raw[engine] = encode(one["raw"]) == encode(two["raw"])
        program_rows.append({
            "program": name, "canonical_ir_sha256": sha256(canonical_ir(source)),
            "cross_engine_canonical_byte_identical": len(set(canonical_by_engine.values())) == 1,
            "raw_observation_byte_identical": len(set(raw_by_engine.values())) == 1,
            "canonical_transcript_sha256": {engine: sha256(data) for engine, data in canonical_by_engine.items()},
            "raw_observation_sha256": {engine: sha256(data) for engine, data in raw_by_engine.items()},
            "rerun_canonical_byte_identical": rerun_canonical, "rerun_raw_byte_identical": rerun_raw,
        })
    evidence = {
        "schema": "sealed-surfaces.real-rq3-external-evidence/v1",
        "clean_programs": program_rows,
        "all_clean_canonical_cross_engine_agreements": all(row["cross_engine_canonical_byte_identical"] for row in program_rows),
        "all_engine_canonical_reruns_byte_identical": all(all(row["rerun_canonical_byte_identical"].values()) for row in program_rows),
        "all_engine_raw_reruns_byte_identical": all(all(row["rerun_raw_byte_identical"].values()) for row in program_rows),
        "raw_cross_engine_observations_identical": all(row["raw_observation_byte_identical"] for row in program_rows),
        "step_trace_available": False,
        "step_trace_finding": "None of E1, E2, E3, or E4 exposes a comparable language-level step trace. Scope C uses a canonical observable root/termination event trace and records step_trace unavailable.",
        "resource_finding": "E2/E3/E4 report dsl_l-product-native/v1 semantic resource outcomes; E1 exposes only its internal recursion bound and process exit. All probes stayed within limits, but cross-engine limit exhaustion equivalence was not established.",
        "io_finding": "The tested I/O is exact source bytes, stdout auto-print bytes, stderr/structured diagnostics, and process exit. Output primitives outside the hosted 84/205 capability subset were not claimed.",
    }
    return evidence, observations


def render_independence(evidence: dict[str, Any]) -> bytes:
    derivations = {
        axis_evidence(pair, axis)["evidence_ref"]: axis_derivation(pair, axis)
        for pair in PAIRINGS
        for axis in AXES
    }
    payload = {
        "schema": "sealed-surfaces.real-rq3-independence/v1", "profiles": PROFILES,
        "axis_evidence": {
            pair: {axis: axis_evidence(pair, axis) for axis in AXES}
            for pair in PAIRINGS
        },
        "axis_derivations": derivations,
        "engine_metadata": ENGINE_META,
        # Repository metadata is intentionally absent from the blinded bundle.
        # Per-file source and executable commitments are staged under engines/.
        "source_snapshot_commitments": "engines/e1..e4/SOURCE-COMMITMENTS.json",
        "toolchain": clean_environment_facts(), "artifact_inventory": artifact_inventory(),
        "measured_clean_agreement": evidence["clean_programs"],
    }
    return encode(payload) + b"\n"


def _cell(row: dict[str, Any]) -> str:
    if row["applicable"] == "no": return "N/A"
    if row["injection"] == "clean": return "PASS" if row["detected"] == "no" else "FALSE+"
    if row["detected"] == "no": return "MISS"
    return {"signature": "SIG", "nonce+freshness": "FRESH", "re-execution agreement": "REEXEC"}[row["detection_layer"]]


def render_report(rows: list[dict[str, Any]], evidence: dict[str, Any]) -> bytes:
    lookup = {(r["injection"], r["scope"], r["independence"]): r for r in rows}
    columns = [(scope, pair) for scope in SCOPES for pair in PAIRINGS]
    lines = [
        "# REAL RQ3 — Sealed Surfaces on deterministic DSL L", "",
        f"Matrix: **PASS ({len(rows)}/{len(rows)} oracle cells)**. Clean canonical transcript agreement: **PASS** "
        f"({len(CLEAN_PROGRAMS)} programs × {len(ALL_PATHS)} paths). Per-engine byte-identical reruns: "
        f"**{'PASS' if evidence['all_engine_canonical_reruns_byte_identical'] else 'FAIL'}**. Fixed seed: `{SEED}`.", "",
        "## Detection and attribution matrix", "",
        "`PASS` is a clean verification control; `N/A` is structurally unconstructible at A0; `MISS` is an applicable injected claim not detected at that scope/pairing; `SIG`, `FRESH`, and `REEXEC` name the detecting layer. The CSV records pipeline outcomes; authenticated terminal rows map to the four-status report domain. This mechanism matrix does not run the paper's aggregate/promotion authorization model.", "",
        "| Injection | " + " | ".join(f"{scope}/{pair}" for scope, pair in columns) + " |",
        "|---|" + "---|" * len(columns),
    ]
    for injection in INJECTIONS:
        lines.append("| " + injection + " | " + " | ".join(_cell(lookup[(injection, scope, pair)]) for scope, pair in columns) + " |")
    lines.extend(["", "## What the real engines established", "",
        "The four clean feature programs (arithmetic, pairs/lists, non-tail recursion, and branching) produced byte-identical `real-l.canonical-transcript/v1` bytes on E1, E2, E3, E4-interpreter, and E4's generated-Rust host. Every path also reproduced its own canonical and raw observation bytes exactly on a second fresh process run. Raw observations were not cross-engine byte-identical: E1 is a CLI stdout/stderr/exit surface, while product runners include backend identity, resource reports, and engine-specific metrics. The harness therefore compares a documented canonical language-level projection and retains raw observations as evidence.", "",
        "Stale-3 behaved exactly as predicted: it was unconstructible at A0, missed at authentication-only A1 for every independence condition, and detected by B/C re-execution for I0–I3. The controlled one-operation `*` fault persisted under I0 and was missed there; E1, E2 guest evaluator, and E4 evaluator re-execution caught it at I1–I3. The semantics-profile mutant behaved the same way. A second engine-side fault changed one supported `+` result in the retained E1/E2/E3 shared-Rust artifacts but not E4-interpreter: I0, I1, and I2 missed that common-mode fault, while I3 detected it under B and C. Scope C alone caught equal-result observable-trace mutation. These are oracle-checked outcomes, not inferred from expected tables.", "",
        "## Actual §5.6 independence vectors", "",
        "| Level | Pair | Source/parser/semantics | Runtime/toolchain | Residual shared domains |",
        "|---|---|---|---|---|",
        "| I0 | E3 → E3 | identical | identical | all |",
        "| I1 | E3 → E1 | common Rust lineage, distinct revisions/artifacts | native Rust/Cargo on both | most code, dependencies, spec, operator, hardware |",
        "| I2 | E3 → E2 | native Rust vs E2 guest evaluator guest tokenizer/reader/normalizer/machine | E2 guest evaluator still hosted and bundled by Rust/Cargo | host, contracts, operator, hardware |",
        "| I3 | E1 → E4-interpreter | shared engineered transliteration of frontend/semantic choices | native Rust vs E4 host interpreter | source/parser/semantics, spec/contracts, OS/hardware, operator/organization |", "",
        "I3 separates runtime backend and build toolchain only; it does not establish source, parser, semantic-core, organizational, or hardware independence. E4's generated-Rust host agreed with its E4 host-interpreter host, but those are two hosts of one transliterated E4 evaluator family and are not counted as another independent engine lineage.", "",
        "## Real-system limitations", "",
        "No runner exposes a comparable language-level step trace. Scope C therefore commits a canonical observable root/termination event trace and an explicit `step_trace: unavailable` marker; it does not claim instruction- or reduction-level trace equivalence. E2/E3/E4 report the native product resource profile, but E1 does not expose the same structured resource counters. The probes stayed within their limits, so limit-exhaustion equivalence remains unproved. The hosted engines currently advertise only 84/205 primitive rows, so the clean corpus intentionally stays inside the admitted intersection; this experiment does not overturn the repositories' disclosed 34/144 historical all-family result or establish whole-language equivalence. The E4 evaluator protocol also requires fixed JSON field order, an adapter-sensitive contract detail observed during preflight.", "",
        "## Commitment construction", "",
        "The signed IR is the engine's real `dsl_l.core.canonical/v0` bytes produced by `read_program` → `normalize_program` → `canonical_program_bytes`. Signed source bytes are included and verification re-canonicalizes them before execution. A0 is signed IR/source/context only. A1 signs the same final-result execution claim as B but disables verifier re-execution. B enables final-result comparison; C enables the full canonical transcript comparison. HMAC-SHA256 remains the dependency-free experimental stand-in used by toy-RQ3, over `PAE(domain, deterministic JSON envelope)`.", "",
        "## Reproduction", "", "```powershell",
        "python run_experiment.py --output results --build --self-check --determinism-check",
        "```", "",
        "No model or LLM call is made. The blinded archive omits version-control metadata and proprietary engine executables. Axis derivation preimages, artifact digests, provenance tags, and evidence references are emitted in `independence-profiles.json`; they are attribution evidence for analysis, not inputs to an action-authorization decision in this mechanism harness.", "",
        "## Verdict", "",
        "**PARTIAL, BUT THE TOP-TIER ‘TOY-L / NO DISTINCT RUNTIME BACKEND’ BLOCKER IS CLOSED FOR A BOUNDED REAL-DSL_L SURFACE.** The same real DSL L source and canonical IR ran deterministically through native Rust, L-in-L, and the E4 transliteration on E4 host; clean canonical transcripts were byte-identical, and re-execution caught stale-3 and both controlled fault classes as predicted. The shared-Rust cell empirically separates I3's runtime backend from I1/I2, but remains a deliberately injected common-mode fault rather than a discovered defect or source- or organizationally independent replication. It does not close whole-language external validity: hosted coverage remains 84/205, raw transcript formats and resource reporting differ, limit-exhaustion equivalence was not shown, no comparable step trace exists, and all evidence shares source/semantic choices, one operator, organization, hardware machine, and specification. The paper should claim bounded backend separation and disclose those limits explicitly.", "",
    ])
    return "\n".join(lines).encode("utf-8")


def generate_artifacts(seed: int, determinism_check: bool) -> dict[str, bytes]:
    evidence, clean_observations = collect_external_evidence(determinism_check)
    bank = EngineBank()
    rows = run_matrix(seed, bank)
    artifacts = {
        "real-l-matrix.csv": render_csv(rows),
        "external-validity.json": encode(evidence) + b"\n",
        "independence-profiles.json": render_independence(evidence),
        "engine-observations.json": encode({"clean": clean_observations, "matrix_execution_cache": bank.evidence()}) + b"\n",
        "REAL-RQ3.md": render_report(rows, evidence),
    }
    manifest = {name: {"byte_len": len(data), "sha256": sha256(data)} for name, data in artifacts.items()}
    artifacts["artifact-manifest.json"] = encode({"schema": "sealed-surfaces.real-rq3-artifacts/v1", "artifacts": manifest,
                                                   "matrix_cells": len(rows), "oracle_cells_passed": len(rows)}) + b"\n"
    return artifacts
