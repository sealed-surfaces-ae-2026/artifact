"""Generated finite-domain properties for the non-laundering model."""

import unittest

import non_laundering_model as model


class NonLaunderingProperties(unittest.TestCase):
    def test_exhaustive_model_checker(self) -> None:
        stats = model.check_model()
        self.assertEqual(stats.concrete_relation_vectors, 4**len(model.INDEPENDENCE_AXES))
        self.assertEqual(stats.axis_evidence_cases, 32)
        self.assertEqual(
            stats.state_policy_pairs,
            len(model.ALL_STATES) * len(model.ALL_POLICIES),
        )
        self.assertEqual(
            stats.crown_paths_checked,
            (1 + len(model.ALL_NOT_REEXECUTED) + len(model.ALL_NOT_COMPARABLE))
            * len(model.ALL_POLICIES),
        )

    def test_partial_unknown_and_publisher_asserted_are_not_independent(self) -> None:
        for relation in model.Relation:
            for provenance in model.Provenance:
                evidence_ref = (
                    "sha256:test-evidence"
                    if provenance in model.HIGH_AUTHORITY_PROVENANCE
                    else None
                )
                evidence = model.AxisEvidence(relation, provenance, evidence_ref)
                expected = (
                    relation is model.Relation.DISTINCT
                    and provenance in model.HIGH_AUTHORITY_PROVENANCE
                )
                self.assertEqual(evidence.high_authority_independent(), expected)
                if provenance in model.HIGH_AUTHORITY_PROVENANCE:
                    with self.assertRaisesRegex(ValueError, "evidence_ref"):
                        model.AxisEvidence(relation, provenance)

    def test_aggregate_is_order_independent_and_disagreement_dominates(self) -> None:
        skipped = model.VerificationReport(
            model.MODEL_KEY,
            1,
            model.not_reexecuted(model.NotReexecutedReason.SKIPPED_BY_POLICY),
        )
        disagreed = model.VerificationReport(
            model.MODEL_KEY, 2, model.EXECUTION_DISAGREED
        )
        forward = model.aggregate(
            "envelope", "context", "scope", model.VerifierStore((skipped, disagreed))
        )
        reverse = model.aggregate(
            "envelope", "context", "scope", model.VerifierStore((disagreed, skipped))
        )
        self.assertIs(forward.status, model.EXECUTION_DISAGREED)
        self.assertEqual(forward, reverse)
        policy = model.PromotionPolicy(True, True, 0)
        self.assertIsNone(model.authorize(forward, policy).basis)

    def test_not_comparable_has_typed_origin_only_fallback(self) -> None:
        status = model.not_comparable(model.NotComparableReason.SCOPE_UNSUPPORTED)
        report = model.VerificationReport(model.MODEL_KEY, 1, status)
        aggregate = model.aggregate(
            "envelope", "context", "scope", model.VerifierStore((report,))
        )
        decision = model.authorize(aggregate, model.PromotionPolicy(True, False, 0))
        self.assertEqual(decision.state.status, status)
        self.assertEqual(decision.basis, model.origin_only_basis(status))

    def test_property_policy_never_relabels_status(self) -> None:
        checked = 0
        for state in model.ALL_STATES:
            for policy in model.ALL_POLICIES:
                for transition in model.policy_successors(state, policy):
                    checked += 1
                    self.assertEqual(transition.source.status, transition.target.status)
        self.assertGreater(checked, 0)

    def test_deliberately_broken_laundering_variant_is_caught(self) -> None:
        with self.assertRaisesRegex(
            model.InvariantViolation, "policy relabelled VerificationStatus"
        ):
            model.check_model(broken_laundering=True)

    def test_publisher_asserted_distinct_mutation_is_caught(self) -> None:
        with self.assertRaisesRegex(
            model.InvariantViolation, "provenance/policy guard"
        ):
            model.check_model(broken_provenance=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
