"""SealedEnvelope construction and staged verification for REAL DSL L."""

from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
import hashlib
import hmac
from typing import Any, Callable

from .canonical import digest_value, encode, pae, sha256


DOMAIN = "sealed-surfaces/real-l/v1"
SCOPE_AXES = {
    "A1": ["stdout_base64", "return_values"],
    "B": ["stdout_base64", "return_values"],
    "C": [
        "stdout_base64", "return_values", "diagnostics", "warnings", "outcome",
        "observable_event_trace", "step_trace",
    ],
}
EXECUTION_CLAIM_FIELDS = frozenset({
    "attributed_engine", "claimed_outcome", "commitment_scope",
    "diagnostics_digest", "transcript_digest", "transcript_schema",
})


def commitment_scope(scope: str) -> dict[str, Any]:
    claim_scope = "B" if scope == "A1" else scope
    return {"scope_version": 1, "observation_axes": SCOPE_AXES[claim_scope]}


def transcript_project(transcript: dict[str, Any], scope: str) -> dict[str, Any]:
    claim_scope = "B" if scope == "A1" else scope
    return {key: transcript[key] for key in SCOPE_AXES[claim_scope]}


def transcript_digest(transcript: dict[str, Any], scope: str) -> dict[str, str]:
    claim_scope = "B" if scope == "A1" else scope
    return digest_value(f"sealed-surfaces/real-l/transcript/{claim_scope}/v1", transcript_project(transcript, claim_scope))


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"algorithm", "value"}
        and value.get("algorithm") == "sha256"
        and isinstance(value.get("value"), str)
        and len(value["value"]) == 64
        and all(character in "0123456789abcdef" for character in value["value"])
    )


def valid_execution_claim_shape(claim: object, scope: str) -> bool:
    """Validate the signed claim schema without performing re-execution."""

    if not isinstance(claim, dict) or set(claim) != EXECUTION_CLAIM_FIELDS:
        return False
    outcome = claim.get("claimed_outcome")
    return (
        isinstance(claim.get("attributed_engine"), dict)
        and isinstance(outcome, dict)
        and set(outcome) == {"tag", "exit_status"}
        and outcome.get("tag") in {"normal", "error"}
        and isinstance(outcome.get("exit_status"), int)
        and claim.get("commitment_scope") == commitment_scope(scope)
        and claim.get("transcript_schema") == "real-l.canonical-transcript/v1"
        and _is_digest(claim.get("diagnostics_digest"))
        and _is_digest(claim.get("transcript_digest"))
    )


def signed_message(envelope: dict[str, Any]) -> bytes:
    return pae(DOMAIN.encode(), encode(envelope))


def sign(envelope: dict[str, Any], key: bytes) -> dict[str, Any]:
    signature = hmac.new(key, signed_message(envelope), hashlib.sha256).hexdigest()
    return {"envelope": copy.deepcopy(envelope), "signature": {"algorithm": "HMAC-SHA256", "value": signature}}


def verify_signature(wire: dict[str, Any], key: bytes) -> bool:
    if wire.get("signature", {}).get("algorithm") != "HMAC-SHA256" or "envelope" not in wire:
        return False
    expected = hmac.new(key, signed_message(wire["envelope"]), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, wire["signature"].get("value", ""))


def make_context(nonce: str, *, past: bool = False) -> dict[str, str]:
    issued, expires = (("2029-12-31T23:00:00Z", "2029-12-31T23:10:00Z") if past else
                       ("2030-01-01T00:00:00Z", "2030-01-01T00:10:00Z"))
    return {
        "purpose": "rq3-real-failure-injection", "subject": "real-l-program",
        "issuer": "rq3-real-mechanical-harness", "nonce": nonce,
        "issued_at": issued, "expires_at": expires,
    }


def make_envelope(
    *, canonical_ir: bytes, source: bytes, scope: str, context: dict[str, str],
    transcript: dict[str, Any] | None, engine: dict[str, Any],
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "domain": DOMAIN,
        "envelope_version": 1,
        "payload_tag": "Program" if scope == "A0" else "Execution",
        "language_profile": "dsl_l-profile-1.5",
        "canonical_ir_format": "dsl_l.core.canonical/v0",
        "canonical_ir": canonical_ir.decode("utf-8"),
        "source_bytes_base64": base64.b64encode(source).decode("ascii"),
        "source_sha256": sha256(source),
        "semantics_digest": digest_value("sealed-surfaces/dsl_l-semantics/v1", {"profile": "dsl_l-profile-1.5"}),
        "context": context,
    }
    if scope == "A0":
        envelope["comparison_baseline"] = "signed-canonical-ir-only"
    else:
        assert transcript is not None
        envelope["execution_claim"] = {
            "attributed_engine": engine,
            "claimed_outcome": transcript["outcome"],
            "commitment_scope": commitment_scope(scope),
            "diagnostics_digest": digest_value("sealed-surfaces/real-l/diagnostics/v1", transcript["diagnostics"]),
            "transcript_digest": transcript_digest(transcript, scope),
            "transcript_schema": transcript["schema"],
        }
    return envelope


@dataclass(frozen=True)
class VerificationResult:
    detected: bool
    detection_layer: str
    status: str
    authorization_basis: str


def verify_wire(
    wire: dict[str, Any], *, scope: str, key: bytes,
    canonicalize: Callable[[bytes], bytes], execute: Callable[[bytes], dict[str, Any]],
    seen_nonces: set[str],
) -> VerificationResult:
    if not verify_signature(wire, key):
        return VerificationResult(True, "signature", "rejected", "none")
    envelope = wire["envelope"]
    context = envelope["context"]
    if (context["nonce"] in seen_nonces or context["issued_at"] > "2030-01-01T00:05:00Z" or
            context["expires_at"] < "2030-01-01T00:05:00Z"):
        return VerificationResult(True, "nonce+freshness", "rejected", "none")
    source = base64.b64decode(envelope["source_bytes_base64"])
    if sha256(source) != envelope["source_sha256"] or canonicalize(source).decode("utf-8") != envelope["canonical_ir"]:
        return VerificationResult(True, "canonical-ir-binding", "rejected", "none")
    if scope == "A0":
        if envelope.get("payload_tag") != "Program" or "execution_claim" in envelope:
            return VerificationResult(True, "payload-type", "rejected", "none")
        return VerificationResult(False, "none", "not_reexecuted", "none")
    if envelope.get("payload_tag") != "Execution":
        return VerificationResult(True, "payload-type", "rejected", "none")
    claim = envelope.get("execution_claim")
    if claim is None:
        return VerificationResult(True, "re-execution agreement", "not_comparable", "none")
    if not valid_execution_claim_shape(claim, scope):
        return VerificationResult(True, "claim-schema", "not_comparable", "none")
    if scope == "A1":
        return VerificationResult(False, "none", "not_reexecuted", "none")
    local = execute(source)
    agreement = (
        claim["transcript_schema"] == local["schema"]
        and claim["commitment_scope"] == commitment_scope(scope)
        and claim["transcript_digest"] == transcript_digest(local, scope)
        and claim["claimed_outcome"] == local["outcome"]
        and claim["diagnostics_digest"] == digest_value(
            "sealed-surfaces/real-l/diagnostics/v1", local["diagnostics"]
        )
    )
    if not agreement:
        return VerificationResult(True, "re-execution agreement", "execution_disagreed", "none")
    return VerificationResult(False, "none", "execution_agreed", "none")
