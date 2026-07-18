from __future__ import annotations

import unittest

from real_rq3.experiment import AXES, AXIS_RELATIONS, axis_evidence, expected
from real_rq3.envelope import commitment_scope, transcript_digest, valid_execution_claim_shape


class OracleTests(unittest.TestCase):
    def test_i3_discloses_transliteration_lineage(self) -> None:
        for axis in ("source_lineage", "parser_lineage", "semantics_core_lineage"):
            self.assertEqual(AXIS_RELATIONS["I3"][axis], "Shared")
        for axis in ("runtime_backend", "build_toolchain"):
            self.assertEqual(AXIS_RELATIONS["I3"][axis], "Distinct")

    def test_every_verifier_established_axis_has_evidence_ref(self) -> None:
        for pair in ("I0", "I1", "I2", "I3"):
            for axis in AXES:
                evidence = axis_evidence(pair, axis)
                self.assertEqual(evidence["provenance"], "VerifierEstablished")
                self.assertTrue(evidence["evidence_ref"].startswith("sha256:"))

    def test_a1_and_b_share_one_signed_final_result_claim_shape(self) -> None:
        transcript = {
            "stdout_base64": "",
            "return_values": [],
        }
        self.assertEqual(commitment_scope("A1"), commitment_scope("B"))
        self.assertEqual(
            transcript_digest(transcript, "A1"), transcript_digest(transcript, "B")
        )

    def test_a1_rejects_non_b_claim_shape_before_policy_skip(self) -> None:
        digest = {"algorithm": "sha256", "value": "0" * 64}
        claim = {
            "attributed_engine": {"engine_id": "E1"},
            "claimed_outcome": {"tag": "normal", "exit_status": 0},
            "commitment_scope": commitment_scope("B"),
            "diagnostics_digest": digest,
            "transcript_digest": digest,
            "transcript_schema": "real-l.canonical-transcript/v1",
        }
        self.assertTrue(valid_execution_claim_shape(claim, "A1"))
        self.assertTrue(valid_execution_claim_shape(claim, "B"))
        malformed = dict(claim)
        malformed["commitment_scope"] = commitment_scope("C")
        self.assertFalse(valid_execution_claim_shape(malformed, "A1"))

    def test_stale_three_requires_execution_scope(self) -> None:
        for pair in ("I0", "I1", "I2", "I3"):
            self.assertEqual(expected("stale-3", "A0", pair), (None, "not_applicable"))
            self.assertEqual(expected("stale-3", "A1", pair), (False, "none"))
            self.assertEqual(expected("stale-3", "B", pair), (True, "re-execution agreement"))

    def test_a0_claim_attacks_are_structurally_not_applicable(self) -> None:
        for injection in (
            "stale-1", "stale-3", "semantics-version-drift",
            "single-operation-backend-fault", "final-result-equal-trace-differs",
            "outcome-confusion", "diagnostics-promoted-as-success",
            "shared-rust-lineage-fault",
        ):
            self.assertEqual(expected(injection, "A0", "I0"), (None, "not_applicable"))

    def test_a1_authenticates_but_does_not_reexecute(self) -> None:
        for pair in ("I0", "I1", "I2", "I3"):
            self.assertEqual(expected("stale-1", "A1", pair), (True, "signature"))
            for injection in (
                "stale-3", "semantics-version-drift", "single-operation-backend-fault",
                "final-result-equal-trace-differs", "outcome-confusion",
                "diagnostics-promoted-as-success", "shared-rust-lineage-fault",
            ):
                self.assertEqual(expected(injection, "A1", pair), (False, "none"))

    def test_fault_separation_begins_above_i0(self) -> None:
        for injection in ("semantics-version-drift", "single-operation-backend-fault"):
            self.assertEqual(expected(injection, "B", "I0"), (False, "none"))
            for pair in ("I1", "I2", "I3"):
                self.assertEqual(expected(injection, "B", pair), (True, "re-execution agreement"))

    def test_trace_is_scope_c_only(self) -> None:
        for pair in ("I0", "I1", "I2", "I3"):
            self.assertEqual(expected("final-result-equal-trace-differs", "B", pair), (False, "none"))
            self.assertEqual(expected("final-result-equal-trace-differs", "C", pair), (True, "re-execution agreement"))

    def test_shared_rust_fault_requires_i3(self) -> None:
        for scope in ("B", "C"):
            for pair in ("I0", "I1", "I2"):
                self.assertEqual(expected("shared-rust-lineage-fault", scope, pair), (False, "none"))
            self.assertEqual(expected("shared-rust-lineage-fault", scope, "I3"), (True, "re-execution agreement"))


if __name__ == "__main__":
    unittest.main()
