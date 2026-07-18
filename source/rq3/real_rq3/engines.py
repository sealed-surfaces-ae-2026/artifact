"""Adapters for the retained real DSL L execution paths."""

from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from .canonical import encode, sha256


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = Path(__file__).resolve().parents[3]
ENGINE_ROOT = ARTIFACT_ROOT / "engines"

E1_ROOT = ENGINE_ROOT / "e1"
E2_ROOT = ENGINE_ROOT / "e2"
E3_ROOT = ENGINE_ROOT / "e3"
E4_ROOT = ENGINE_ROOT / "e4"
E1_EXE = E1_ROOT / "bin/e1"
E2_EXE = E2_ROOT / "bin/e2"
E3_EXE = E3_ROOT / "bin/e3"
CANON_EXE = ROOT / "tools/canonicalize/target/debug/rq3-l-canonicalize"
E4_INTERPRETER = E4_ROOT / "bin/e4-interpreter"
E4_NATIVE = E4_ROOT / "bin/e4-generated"
E4_SOURCE = E4_ROOT / "source/e4-evaluator.source"
E4_ADAPTER = E4_ROOT / "source/host-adapter.mjs"
FAULT_BIN = ROOT / "tools/shared-rust-fault/bin"
FAULT_E1_EXE = FAULT_BIN / "e1-fault"
FAULT_E2_EXE = FAULT_BIN / "e2-fault"
FAULT_E3_EXE = FAULT_BIN / "e3-rust-product-fault.exe"

PRODUCT_LIMITS = [20_000_000, 2_000_000, 20_000_000, 100_000_000, 16_777_216]
DIAG = re.compile(r"^(\S+)\s+.*?:(\d+):(\d+)\s+(.*)$")


ENGINE_META: dict[str, dict[str, str]] = {
    "E1": {
        "name": "DSL L native reference CLI",
        "family": "native-rust-reference",
        "source": str(E1_ROOT / "implementation/src"),
        "runtime": "native Rust evaluator",
    },
    "E2": {
        "name": "E2 guest evaluator product runner",
        "family": "dsl_l-in-dsl_l",
        "source": str(E2_ROOT / "implementation/frontend/tokenizer.l") + " + bundled guest units",
        "runtime": "DSL L guest machine hosted by Rust DSL L",
    },
    "E3": {
        "name": "Rust product runner",
        "family": "native-rust-product",
        "source": str(E3_ROOT / "implementation/src"),
        "runtime": "native Rust evaluator through observation protocol",
    },
    "E4-interpreter": {
        "name": "E4 evaluator on E4 host interpreter host",
        "family": "dsl_l-in-e4_host",
        "source": str(E4_SOURCE),
        "runtime": "E4 host interpreter executing E4 evaluator",
    },
    "E4-generated": {
        "name": "E4 evaluator generated-Rust host",
        "family": "dsl_l-in-e4_host",
        "source": str(E4_SOURCE),
        "runtime": "E4 host-generated native Rust artifact executing E4 evaluator",
    },
}


def build_required() -> None:
    subprocess.run(
        ["cargo", "build", "--bin", "e1"], cwd=E1_ROOT / "implementation", check=True
    )
    subprocess.run(
        [
            "cargo", "build", "--bin", "e3", "--bin", "e2",
        ],
        cwd=E3_ROOT / "implementation", check=True,
    )
    subprocess.run(
        ["cargo", "build", "--manifest-path", str(ROOT / "tools/canonicalize/Cargo.toml")],
        cwd=ROOT, check=True,
    )


def required_paths() -> list[Path]:
    return [
        E1_EXE, E2_EXE, E3_EXE, FAULT_E1_EXE, FAULT_E2_EXE, FAULT_E3_EXE,
        CANON_EXE, E4_INTERPRETER, E4_NATIVE, E4_SOURCE, E4_ADAPTER,
    ]


def canonical_ir(source: bytes) -> bytes:
    result = subprocess.run([str(CANON_EXE)], input=source, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"canonicalizer failed: {result.stderr.decode(errors='replace')}")
    if not result.stdout.startswith(b"dsl_l.core.canonical/v0\n"):
        raise AssertionError("canonicalizer did not emit Canonical Core v0")
    return result.stdout


def _artifact(path: Path, kind: str, neutral_path: str | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "identity_kind": kind,
        "path": neutral_path or path.name,
        "byte_len": len(data),
        "sha256": sha256(data),
    }


def _request(engine: str, source: bytes, artifact: dict[str, Any]) -> bytes:
    backend = {"E2": "e2_guest", "E3": "rust", "E4-interpreter": "e4_eval", "E4-generated": "e4_eval"}[engine]
    value = {
        "schema": "dsl_l.backend-run-request/v1",
        "invocation_id": f"rq3-real/{engine}",
        "profile": "dsl_l-profile-1.5",
        "logical_source_id": "rq3-program.l",
        "source_bytes_base64": base64.b64encode(source).decode("ascii"),
        "source_sha256": sha256(source),
        "resource_profile": "dsl_l-product-native/v1",
        "limits": PRODUCT_LIMITS,
        "artifact_expectation": {
            "backend_id": backend,
            "profile": "dsl_l-profile-1.5",
            "capability_schema": "dsl_l.primitive-capabilities/v2",
            "observation_schema": "dsl_l.observation-result/v1",
            "artifact": artifact,
        },
        "cancellation": {"deadline_unix_millis": None, "abort_requested": False},
    }
    # The frozen E4 evaluator protocol deliberately validates declaration order as part of
    # its framing contract. Preserve the insertion order above; envelope encoding
    # remains separately canonical and key-sorted.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _diagnostic_projection(row: dict[str, Any]) -> dict[str, Any]:
    span = row.get("span", {})
    return {
        "code": row.get("code", "unknown"),
        "severity": row.get("severity", "error"),
        "message": row.get("message", ""),
        "irritants": row.get("irritants", []),
        "line": span.get("line", 1),
        "column": span.get("column", 1),
    }


def _events(values: list[str], status: str) -> list[dict[str, Any]]:
    events = [{"event": "root-value", "index": i, "value": value} for i, value in enumerate(values)]
    events.append({"event": "termination", "status": status})
    return events


def _canonical_transcript(
    *, stdout: bytes, values: list[str], diagnostics: list[dict[str, Any]],
    warnings: list[dict[str, Any]], status: str, exit_status: int,
) -> dict[str, Any]:
    outcome = "normal" if status == "ok" and exit_status == 0 else "error"
    return {
        "schema": "real-l.canonical-transcript/v1",
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "return_values": values,
        "diagnostics": diagnostics,
        "warnings": warnings,
        "outcome": {"tag": outcome, "exit_status": 0 if outcome == "normal" else 1},
        "observable_event_trace": _events(values, outcome),
        "step_trace": {"available": False, "reason": "no-runner-language-step-trace"},
    }


def _run_e1(source: bytes, *, faulted: bool = False) -> dict[str, Any]:
    executable = FAULT_E1_EXE if faulted else E1_EXE
    process = subprocess.run([str(executable), "-"], input=source, capture_output=True, timeout=30)
    diagnostics: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for line in process.stderr.decode("utf-8", errors="replace").splitlines():
        match = DIAG.match(line)
        row = {
            "code": match.group(1) if match else "unparsed-diagnostic",
            "severity": "warning" if match and match.group(1).startswith("W") else "error",
            "message": match.group(4) if match else line,
            "irritants": [],
            "line": int(match.group(2)) if match else 1,
            "column": int(match.group(3)) if match else 1,
        }
        (warnings if row["severity"] == "warning" else diagnostics).append(row)
    values = process.stdout.decode("utf-8", errors="strict").splitlines()
    transcript = _canonical_transcript(
        stdout=process.stdout, values=values, diagnostics=diagnostics, warnings=warnings,
        status="ok" if process.returncode == 0 else "runtime-error", exit_status=process.returncode,
    )
    return {
        "engine": "E1", "canonical_transcript": transcript,
        "raw": {
            "exit_status": process.returncode,
            "stdout_base64": base64.b64encode(process.stdout).decode("ascii"),
            "stderr_base64": base64.b64encode(process.stderr).decode("ascii"),
            "controlled_fault_artifact": faulted,
            "artifact": _artifact(executable, "executed-native-binary-bytes"),
        },
        "resource_reporting": "process-timeout-only",
    }


def _run_product(engine: str, source: bytes, *, faulted: bool = False) -> dict[str, Any]:
    if engine == "E3":
        executable = FAULT_E3_EXE if faulted else E3_EXE
        artifact = _artifact(executable, "executed-native-binary-bytes")
        command = [str(executable)]
    elif engine == "E2":
        executable = FAULT_E2_EXE if faulted else E2_EXE
        artifact = _artifact(executable, "dsl_l-e2_guest-product-runner-bytes")
        command = [str(executable)]
    elif engine == "E4-interpreter":
        artifact = _artifact(E4_SOURCE, "e4-interpreter-product-artifact-bytes", "e4/source/evaluator")
        command = [
            "node", str(E4_ADAPTER), "--host", "interpreter",
            "--artifact-path", "e4/source/evaluator", "--interpreter", str(E4_INTERPRETER),
            "--source", str(E4_SOURCE),
        ]
    elif engine == "E4-generated":
        artifact = _artifact(E4_NATIVE, "e4-generated-product-artifact-bytes", "e4/bin/generated")
        command = [
            "node", str(E4_ADAPTER), "--host", "generated-rust",
            "--artifact-path", "e4/bin/generated", "--native", str(E4_NATIVE),
        ]
    else:
        raise AssertionError(engine)
    if faulted and engine not in {"E2", "E3"}:
        raise AssertionError(f"no controlled shared-Rust fault artifact for {engine}")
    process = subprocess.run(command, input=_request(engine, source, artifact), capture_output=True, timeout=120)
    if process.returncode != 0:
        raise RuntimeError(f"{engine} runner failed: {process.stderr.decode(errors='replace')}")
    observation = json.loads(process.stdout)
    stdout = base64.b64decode(observation["stdout_bytes"]["base64"])
    if sha256(stdout) != observation["stdout_bytes"]["sha256"]:
        raise AssertionError(f"{engine} stdout digest mismatch")
    diagnostics = [_diagnostic_projection(row) for row in observation["diagnostics"]]
    warnings = [_diagnostic_projection(row) for row in observation["warnings"]]
    values = observation["value_projection"]["values"]
    transcript = _canonical_transcript(
        stdout=stdout, values=values, diagnostics=diagnostics, warnings=warnings,
        status=observation["status"], exit_status=observation["exit_status"],
    )
    return {
        "engine": engine, "canonical_transcript": transcript, "raw": observation,
        "resource_reporting": "semantic-resource-profile-and-counters",
    }


class EngineBank:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], dict[str, Any]] = {}

    def run(self, engine: str, label: str, source: bytes, *, faulted: bool = False) -> dict[str, Any]:
        key = (engine + ("/shared-rust-fault" if faulted else "/clean"), sha256(source))
        if key not in self._cache:
            result = _run_e1(source, faulted=faulted) if engine == "E1" else _run_product(engine, source, faulted=faulted)
            result["source_label"] = label
            result["controlled_fault_artifact"] = faulted
            self._cache[key] = result
        return copy.deepcopy(self._cache[key])

    def evidence(self) -> list[dict[str, Any]]:
        return [copy.deepcopy(self._cache[key]) for key in sorted(self._cache)]


def artifact_inventory() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path in required_paths():
        data = path.read_bytes()
        result[str(path)] = {"byte_len": len(data), "sha256": sha256(data)}
    return result


def clean_environment_facts() -> dict[str, str]:
    commands = {
        "rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"],
        "node": ["node", "--version"], "python": [os.sys.executable, "--version"],
    }
    facts: dict[str, str] = {}
    for name, command in commands.items():
        raw = subprocess.run(
            command, capture_output=True, text=True, check=True
        ).stdout.strip()
        words = raw.split()
        facts[name] = " ".join(words[:2]) if name != "node" else words[0]
    return facts
