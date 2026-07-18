"""Exhaustive finite model for Sealed Surfaces non-laundering.

The model separates three operations:

* the verifier aggregates every current report for one
  (envelope_id, context_id, verifier_scope, aggregation_epoch) key with an
  explicit associative, commutative, idempotent binary join;
* the aggregate retains one of four report-level evidence-derived
  VerificationStatus variants; and
* policy may attach an AuthorizationBasis but may not rewrite that status.

Each independence axis has a quaternary relation, provenance, and evidence
reference.  High-authority independence requires Distinct plus registry
verification, external attestation, or verifier establishment, and the three
verified provenances require a nonempty evidence reference.  Policy receives
only the resulting Boolean 2^8 projection, never the raw profile.  Separate
exhaustive checks cover all 4^8 relation vectors and all 4 x 4 x 2 per-axis
relation/provenance/evidence-reference combinations.

No third-party packages are required.  Run:

    python non_laundering_model.py --self-check
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from functools import lru_cache
import hashlib
import json
from itertools import product
from typing import Iterable, Optional


INDEPENDENCE_AXES = (
    "source_lineage",
    "parser_lineage",
    "semantics_core_lineage",
    "build_toolchain",
    "runtime_backend",
    "dependency_set",
    "hardware_architecture",
    "operator_or_organization",
)
AXIS_COUNT = len(INDEPENDENCE_AXES)
PROFILE_QUOTIENT_COUNT = 1 << AXIS_COUNT


class Relation(Enum):
    SHARED = "Shared"
    PARTIAL = "Partial"
    DISTINCT = "Distinct"
    UNKNOWN = "Unknown"


class Provenance(Enum):
    PUBLISHER_ASSERTED = "PublisherAsserted"
    REGISTRY_VERIFIED = "RegistryVerified"
    EXTERNALLY_ATTESTED = "ExternallyAttested"
    VERIFIER_ESTABLISHED = "VerifierEstablished"


HIGH_AUTHORITY_PROVENANCE = frozenset(
    {
        Provenance.REGISTRY_VERIFIED,
        Provenance.EXTERNALLY_ATTESTED,
        Provenance.VERIFIER_ESTABLISHED,
    }
)


@dataclass(frozen=True)
class AxisEvidence:
    relation: Relation
    provenance: Provenance
    evidence_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if self.provenance in HIGH_AUTHORITY_PROVENANCE and not self.evidence_ref:
            raise ValueError("verified provenance requires a nonempty evidence_ref")

    def high_authority_independent(self) -> bool:
        return (
            self.relation is Relation.DISTINCT
            and self.provenance in HIGH_AUTHORITY_PROVENANCE
            and self.evidence_ref is not None
        )


@dataclass(frozen=True)
class IndependenceProfile:
    axes: tuple[AxisEvidence, ...]

    def __post_init__(self) -> None:
        if len(self.axes) != AXIS_COUNT:
            raise ValueError(f"expected {AXIS_COUNT} axis-evidence values")

    def verified_projection(self) -> int:
        """I(P): the only profile representation exposed to promotion policy."""

        mask = 0
        for index, evidence in enumerate(self.axes):
            if evidence.high_authority_independent():
                mask |= 1 << index
        return mask

    def high_authority_mask(self) -> int:
        """Backward-readable name for the verified Boolean projection."""

        return self.verified_projection()

    def relation_only_mask(self) -> int:
        """Unsafe projection used only by the deliberate provenance mutation."""

        mask = 0
        for index, evidence in enumerate(self.axes):
            if evidence.relation is Relation.DISTINCT:
                mask |= 1 << index
        return mask


def quotient_profile(mask: int) -> IndependenceProfile:
    """Canonical representative of one authorization-equivalence class.

    Every axis is Distinct.  Eligible axes carry verified provenance; ineligible
    axes are PublisherAsserted.  Consequently a relation-only implementation
    incorrectly accepts every ineligible axis, giving the provenance mutation
    a concrete counterexample in every non-full quotient class.
    """

    if not 0 <= mask < PROFILE_QUOTIENT_COUNT:
        raise ValueError("invalid profile quotient mask")
    axes = tuple(
        AxisEvidence(
            Relation.DISTINCT,
            Provenance.REGISTRY_VERIFIED
            if mask & (1 << index)
            else Provenance.PUBLISHER_ASSERTED,
            f"sha256:registry-axis-{index}" if mask & (1 << index) else None,
        )
        for index in range(AXIS_COUNT)
    )
    profile = IndependenceProfile(axes)
    assert profile.high_authority_mask() == mask
    return profile


ALL_PROFILES = tuple(
    quotient_profile(mask) for mask in range(PROFILE_QUOTIENT_COUNT)
)


class StatusTag(Enum):
    """Tags used by the finite reachability encoding.

    AUTHENTICATED is a pipeline-only intermediate sentinel.  It is excluded
    from ALL_REPORT_STATUSES, whose four tags are the report-level
    VerificationStatus domain consumed by aggregation and authorization.
    """

    AUTHENTICATED = "authenticated"
    EXECUTION_AGREED = "execution_agreed"
    EXECUTION_DISAGREED = "execution_disagreed"
    NOT_REEXECUTED = "not_reexecuted"
    NOT_COMPARABLE = "not_comparable"


class NotReexecutedReason(Enum):
    SKIPPED_BY_POLICY = "skipped_by_policy"
    ENGINE_UNAVAILABLE = "engine_unavailable"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    RESOURCE_BUDGET_DECLINED = "resource_budget_declined"


class NotComparableReason(Enum):
    PROFILE_MISMATCH = "profile_mismatch"
    SCOPE_UNSUPPORTED = "scope_unsupported"
    SCHEMA_MISMATCH = "schema_mismatch"
    EXECUTION_UNDEFINED = "execution_undefined"


Reason = NotReexecutedReason | NotComparableReason


def nonempty_reason_sets(enum_type: type[Enum]) -> tuple[frozenset[Enum], ...]:
    members = tuple(enum_type)
    return tuple(
        frozenset(member for index, member in enumerate(members) if mask & (1 << index))
        for mask in range(1, 1 << len(members))
    )


NOT_REEXECUTED_REASON_SETS = nonempty_reason_sets(NotReexecutedReason)
NOT_COMPARABLE_REASON_SETS = nonempty_reason_sets(NotComparableReason)


@dataclass(frozen=True)
class VerificationStatus:
    tag: StatusTag
    profile: Optional["VerifiedProjection"] = None
    reasons: frozenset[Reason] = frozenset()

    def __post_init__(self) -> None:
        if self.tag is StatusTag.EXECUTION_AGREED:
            if self.profile is None or self.reasons:
                raise ValueError("execution_agreed carries exactly a profile")
            return
        if self.profile is not None:
            raise ValueError("only execution_agreed carries a profile")
        if self.tag is StatusTag.NOT_REEXECUTED:
            if not self.reasons or not all(
                isinstance(reason, NotReexecutedReason) for reason in self.reasons
            ):
                raise ValueError("not_reexecuted carries typed non-execution reasons")
            return
        if self.tag is StatusTag.NOT_COMPARABLE:
            if not self.reasons or not all(
                isinstance(reason, NotComparableReason) for reason in self.reasons
            ):
                raise ValueError("not_comparable carries typed comparison reasons")
            return
        if self.reasons:
            raise ValueError("this status carries neither profile nor reason")


AUTHENTICATED = VerificationStatus(StatusTag.AUTHENTICATED)
EXECUTION_DISAGREED = VerificationStatus(StatusTag.EXECUTION_DISAGREED)


@dataclass(frozen=True)
class VerifiedProjection:
    """I(P), retained without inventing concrete provenance evidence."""

    mask: int

    def __post_init__(self) -> None:
        if not 0 <= self.mask < PROFILE_QUOTIENT_COUNT:
            raise ValueError("invalid verified-projection mask")


def agreed(profile: IndependenceProfile | VerifiedProjection | int) -> VerificationStatus:
    if isinstance(profile, IndependenceProfile):
        profile = VerifiedProjection(profile.verified_projection())
    elif isinstance(profile, int):
        profile = VerifiedProjection(profile)
    return VerificationStatus(StatusTag.EXECUTION_AGREED, profile=profile)


def not_reexecuted(
    reasons: NotReexecutedReason | frozenset[NotReexecutedReason],
) -> VerificationStatus:
    if isinstance(reasons, NotReexecutedReason):
        reasons = frozenset({reasons})
    return VerificationStatus(StatusTag.NOT_REEXECUTED, reasons=reasons)


def not_comparable(
    reasons: NotComparableReason | frozenset[NotComparableReason],
) -> VerificationStatus:
    if isinstance(reasons, NotComparableReason):
        reasons = frozenset({reasons})
    return VerificationStatus(StatusTag.NOT_COMPARABLE, reasons=reasons)


ALL_NOT_REEXECUTED = tuple(not_reexecuted(reasons) for reasons in NOT_REEXECUTED_REASON_SETS)
ALL_NOT_COMPARABLE = tuple(not_comparable(reasons) for reasons in NOT_COMPARABLE_REASON_SETS)
ALL_STATUSES = (
    AUTHENTICATED,
    *(agreed(mask) for mask in range(PROFILE_QUOTIENT_COUNT)),
    EXECUTION_DISAGREED,
    *ALL_NOT_REEXECUTED,
    *ALL_NOT_COMPARABLE,
)
ALL_REPORT_STATUSES = tuple(
    status for status in ALL_STATUSES if status.tag is not StatusTag.AUTHENTICATED
)


def join_status(
    left: Optional[VerificationStatus], right: Optional[VerificationStatus]
) -> Optional[VerificationStatus]:
    """Binary aggregate join; None is the identity element.

    Precedence is disagreement > agreement > not_comparable > not_reexecuted.
    Equal-kind reason sets are unioned, and agreeing verified projections are
    intersected.  The operation is intended to be associative, commutative, and
    idempotent; check_aggregation exhaustively asserts those laws.
    """

    if left is None:
        return right
    if right is None:
        return left
    precedence = {
        StatusTag.NOT_REEXECUTED: 0,
        StatusTag.NOT_COMPARABLE: 1,
        StatusTag.EXECUTION_AGREED: 2,
        StatusTag.EXECUTION_DISAGREED: 3,
    }
    if left.tag not in precedence or right.tag not in precedence:
        raise ValueError("join accepts only terminal report statuses")
    if left.tag is not right.tag:
        return left if precedence[left.tag] > precedence[right.tag] else right
    if left.tag is StatusTag.EXECUTION_DISAGREED:
        return EXECUTION_DISAGREED
    if left.tag is StatusTag.EXECUTION_AGREED:
        assert left.profile is not None and right.profile is not None
        return agreed(left.profile.mask & right.profile.mask)
    if left.tag is StatusTag.NOT_COMPARABLE:
        return not_comparable(
            frozenset(left.reasons | right.reasons)  # type: ignore[arg-type]
        )
    if left.tag is StatusTag.NOT_REEXECUTED:
        return not_reexecuted(
            frozenset(left.reasons | right.reasons)  # type: ignore[arg-type]
        )
    raise AssertionError("unreachable join case")


@dataclass(frozen=True)
class ReportKey:
    envelope_id: str
    context_id: str
    verifier_scope: str


@dataclass(frozen=True)
class VerificationReport:
    key: ReportKey
    report_id: int
    status: VerificationStatus
    supporting_evidence_digest: str = "sha256:model-evidence-none"
    created_epoch: int = 1
    superseded_at_epoch: Optional[int] = None


@dataclass(frozen=True)
class VerifierStore:
    """Verifier-owned report store; consumers cannot supply aggregate subsets."""

    reports: tuple[VerificationReport, ...]


MODEL_KEY = ReportKey("envelope", "context", "scope")
MODEL_EPOCH = 1


def canonical_model_value(value: object) -> object:
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if is_dataclass(value):
        return {
            "type": type(value).__name__,
            "fields": {
                field.name: canonical_model_value(getattr(value, field.name))
                for field in fields(value)
            },
        }
    if isinstance(value, (frozenset, set)):
        members = [canonical_model_value(member) for member in value]
        return {
            "set": sorted(
                members,
                key=lambda member: json.dumps(
                    member, sort_keys=True, separators=(",", ":")
                ),
            )
        }
    if isinstance(value, (tuple, list)):
        return [canonical_model_value(member) for member in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise TypeError(f"unsupported canonical model value: {type(value).__name__}")


def digest_text(*parts: object) -> str:
    encoded = json.dumps(
        canonical_model_value(parts),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class VerifierAggregate:
    """Opaque-in-the-spec result produced from the verifier's current store."""

    key: ReportKey
    report_ids: frozenset[int]
    status: VerificationStatus
    verifier_scope_digest: str
    aggregation_epoch: int
    report_set_digest: str


def aggregate(
    envelope_id: str,
    context_id: str,
    verifier_scope: str,
    verifier_store: VerifierStore,
    aggregation_epoch: int = MODEL_EPOCH,
) -> VerifierAggregate:
    """Compute the sole consumer-visible status from all current reports.

    Disagreement dominates every prior outcome.  Otherwise an agreement report
    dominates non-execution/incomparability; multiple agreeing profiles are
    conservatively intersected.  With no agreement, incomparability dominates
    non-execution and typed reasons are unioned.  Consumers never select a
    favorable member report.
    """

    key = ReportKey(envelope_id, context_id, verifier_scope)
    all_report_ids = tuple(report.report_id for report in verifier_store.reports)
    if len(set(all_report_ids)) != len(all_report_ids):
        raise ValueError("verifier-store report identifiers must be globally unique")
    current = tuple(
        report
        for report in verifier_store.reports
        if report.key == key
        and report.created_epoch <= aggregation_epoch
        and (
            report.superseded_at_epoch is None
            or report.superseded_at_epoch > aggregation_epoch
        )
    )
    if not current:
        raise ValueError("aggregate requires a nonempty current report set")
    report_ids = frozenset(report.report_id for report in current)
    if len(report_ids) != len(current):
        raise ValueError("current reports must have unique report identifiers")

    if aggregation_epoch < 0:
        raise ValueError("aggregation_epoch must be nonnegative")
    status: Optional[VerificationStatus] = None
    for report in current:
        status = join_status(status, report.status)
    if status is None:
        raise ValueError("reports must carry terminal verification statuses")
    verifier_scope_digest = digest_text("verifier-scope", verifier_scope)
    report_commitments = tuple(
        sorted(
            (
                report.report_id,
                report.created_epoch,
                report.status,
                report.supporting_evidence_digest,
            )
            for report in current
        )
    )
    report_set_digest = digest_text(
        "report-set", envelope_id, context_id, verifier_scope_digest,
        aggregation_epoch, *report_commitments,
    )
    return VerifierAggregate(
        key, report_ids, status, verifier_scope_digest, aggregation_epoch,
        report_set_digest,
    )


class BasisTag(Enum):
    ORIGIN_ONLY = "origin_only"
    EXECUTION_AGREEMENT = "execution_agreement"


@dataclass(frozen=True)
class AuthorizationBasis:
    tag: BasisTag
    fallback_status: Optional[VerificationStatus] = None

    def __post_init__(self) -> None:
        if self.tag is BasisTag.ORIGIN_ONLY:
            if self.fallback_status is None or self.fallback_status.tag not in {
                StatusTag.NOT_REEXECUTED,
                StatusTag.NOT_COMPARABLE,
            }:
                raise ValueError("origin_only requires an explicit typed fallback reason")
        elif self.fallback_status is not None:
            raise ValueError("execution_agreement carries no fallback reason")


EXECUTION_AGREEMENT_BASIS = AuthorizationBasis(BasisTag.EXECUTION_AGREEMENT)


def origin_only_basis(status: VerificationStatus) -> AuthorizationBasis:
    return AuthorizationBasis(BasisTag.ORIGIN_ONLY, fallback_status=status)


ALL_BASES: tuple[Optional[AuthorizationBasis], ...] = (
    None,
    *(origin_only_basis(status) for status in ALL_NOT_REEXECUTED),
    *(origin_only_basis(status) for status in ALL_NOT_COMPARABLE),
    EXECUTION_AGREEMENT_BASIS,
)


@dataclass(frozen=True)
class State:
    status: VerificationStatus
    basis: Optional[AuthorizationBasis] = None


@dataclass(frozen=True)
class PromotionPolicy:
    allow_origin_only: bool
    allow_execution_agreement: bool
    required_independence_mask: int
    allowed_verifier_scope_digest: str = digest_text(
        "verifier-scope", MODEL_KEY.verifier_scope
    )

    def __post_init__(self) -> None:
        if not 0 <= self.required_independence_mask < PROFILE_QUOTIENT_COUNT:
            raise ValueError("invalid required-independence mask")

    def accepts_projection(self, verified_projection: int) -> bool:
        """phi: {0,1}^8 -> {0,1}; raw profile evidence is not in-domain."""

        if not 0 <= verified_projection < PROFILE_QUOTIENT_COUNT:
            raise ValueError("projection escaped the eight-axis Boolean domain")
        required = self.required_independence_mask
        return (verified_projection & required) == required

    def unsafely_accepts_raw_profile(self, profile: IndependenceProfile) -> bool:
        """Deliberate mutation: phi illegally inspects raw Distinct relations."""

        required = self.required_independence_mask
        return (profile.relation_only_mask() & required) == required

    def digest(self) -> str:
        return digest_text(
            "promotion-policy", self.allow_origin_only,
            self.allow_execution_agreement, self.required_independence_mask,
            self.allowed_verifier_scope_digest,
        )


ALL_STATES = tuple(State(status, basis) for status, basis in product(ALL_STATUSES, ALL_BASES))
ALL_POLICIES = tuple(
    PromotionPolicy(origin, execution, required)
    for origin, execution, required in product(
        (False, True), (False, True), range(PROFILE_QUOTIENT_COUNT)
    )
)


class TransitionKind(Enum):
    EVIDENCE = "evidence"
    POLICY = "policy"


@dataclass(frozen=True)
class Transition:
    source: State
    target: State
    kind: TransitionKind


class InvariantViolation(AssertionError):
    pass


BAD_FOR_EXECUTION_AUTHORIZATION = frozenset(
    {
        StatusTag.EXECUTION_DISAGREED,
        StatusTag.NOT_REEXECUTED,
        StatusTag.NOT_COMPARABLE,
    }
)


def evidence_successors(state: State) -> tuple[Transition, ...]:
    if state != State(AUTHENTICATED):
        return ()
    return tuple(
        Transition(state, State(outcome), TransitionKind.EVIDENCE)
        for outcome in ALL_REPORT_STATUSES
    )


def policy_successors(
    state: State,
    policy: PromotionPolicy,
    *,
    broken_laundering: bool = False,
    broken_provenance: bool = False,
    broken_raw_policy: bool = False,
) -> tuple[Transition, ...]:
    if state.basis is not None:
        return ()

    if broken_laundering and state.status.tag is StatusTag.NOT_REEXECUTED:
        if policy.allow_execution_agreement:
            target = State(agreed(policy.required_independence_mask), EXECUTION_AGREEMENT_BASIS)
            return (Transition(state, target, TransitionKind.POLICY),)

    if state.status.tag in {StatusTag.NOT_REEXECUTED, StatusTag.NOT_COMPARABLE}:
        if policy.allow_origin_only:
            target = State(state.status, origin_only_basis(state.status))
            return (Transition(state, target, TransitionKind.POLICY),)

    if state.status.tag is StatusTag.EXECUTION_AGREED:
        profile = state.status.profile
        assert profile is not None
        raw_witness = quotient_profile(profile.mask)
        projection = (
            raw_witness.relation_only_mask()
            if broken_provenance
            else profile.mask
        )
        accepted = (
            policy.unsafely_accepts_raw_profile(raw_witness)
            if broken_raw_policy
            else policy.accepts_projection(projection)
        )
        if policy.allow_execution_agreement and accepted:
            target = State(state.status, EXECUTION_AGREEMENT_BASIS)
            return (Transition(state, target, TransitionKind.POLICY),)

    return ()


@dataclass(frozen=True)
class AuthorizationDecision:
    state: State
    verifier_scope_digest: str
    aggregation_epoch: int
    report_set_digest: str
    promotion_policy_digest: str

    @property
    def basis(self) -> Optional[AuthorizationBasis]:
        return self.state.basis


def authorize(
    verifier_aggregate: VerifierAggregate, policy: PromotionPolicy
) -> AuthorizationDecision:
    """Authorize an aggregate only when action policy pins its verifier scope."""

    aggregate_state = State(verifier_aggregate.status)
    if verifier_aggregate.verifier_scope_digest != policy.allowed_verifier_scope_digest:
        target = aggregate_state
    else:
        successors = policy_successors(aggregate_state, policy)
        target = successors[0].target if successors else aggregate_state
    return AuthorizationDecision(
        target,
        verifier_aggregate.verifier_scope_digest,
        verifier_aggregate.aggregation_epoch,
        verifier_aggregate.report_set_digest,
        policy.digest(),
    )


def structurally_well_formed(state: State) -> bool:
    if state.basis is None:
        return True
    if state.basis.tag is BasisTag.ORIGIN_ONLY:
        return (
            state.status.tag in {StatusTag.NOT_REEXECUTED, StatusTag.NOT_COMPARABLE}
            and state.basis.fallback_status == state.status
        )
    if state.basis.tag is BasisTag.EXECUTION_AGREEMENT:
        return state.status.tag is StatusTag.EXECUTION_AGREED
    return False


def authorized_under(state: State, policy: PromotionPolicy) -> bool:
    if state.basis is None:
        return True
    if state.basis.tag is BasisTag.ORIGIN_ONLY:
        return structurally_well_formed(state) and policy.allow_origin_only
    if state.basis.tag is BasisTag.EXECUTION_AGREEMENT:
        profile = state.status.profile
        return (
            state.status.tag is StatusTag.EXECUTION_AGREED
            and profile is not None
            and policy.allow_execution_agreement
            and policy.accepts_projection(profile.mask)
        )
    return False


def assert_transition_invariants(transition: Transition, policy: PromotionPolicy) -> None:
    source, target = transition.source, transition.target
    if not structurally_well_formed(target):
        raise InvariantViolation(f"ill-typed target state: {transition}")
    if transition.kind is TransitionKind.POLICY:
        if target.status != source.status:
            raise InvariantViolation(
                "policy relabelled VerificationStatus: "
                f"{source.status.tag.value} -> {target.status.tag.value}"
            )
        if not authorized_under(target, policy):
            source_mask = (
                source.status.profile.mask
                if source.status.profile is not None
                else None
            )
            raise InvariantViolation(
                "authorization lacks its required evidence/provenance/policy guard: "
                f"status={source.status.tag.value}, high_authority_mask={source_mask}, "
                f"required_mask={policy.required_independence_mask}"
            )
    if (
        target.status.tag in BAD_FOR_EXECUTION_AUTHORIZATION
        and target.basis is not None
        and target.basis.tag is BasisTag.EXECUTION_AGREEMENT
    ):
        raise InvariantViolation(
            "terminal non-agreement status received execution_agreement authority"
        )


def reachable_states(
    roots: Iterable[State],
    policy: PromotionPolicy,
    *,
    include_evidence: bool,
    broken_laundering: bool = False,
    broken_provenance: bool = False,
    broken_raw_policy: bool = False,
) -> tuple[set[State], int]:
    seen = set(roots)
    queue = deque(roots)
    edge_count = 0
    while queue:
        source = queue.popleft()
        transitions = list(
            policy_successors(
                source,
                policy,
                broken_laundering=broken_laundering,
                broken_provenance=broken_provenance,
                broken_raw_policy=broken_raw_policy,
            )
        )
        if include_evidence:
            transitions.extend(evidence_successors(source))
        for transition in transitions:
            edge_count += 1
            assert_transition_invariants(transition, policy)
            if transition.target not in seen:
                seen.add(transition.target)
                queue.append(transition.target)
    return seen, edge_count


@dataclass(frozen=True)
class CheckStats:
    concrete_relation_vectors: int
    axis_evidence_cases: int
    aggregate_singletons: int
    aggregate_ordered_pairs: int
    aggregate_ordered_triples: int
    aggregate_supersession_cases: int
    scope_pin_cases: int
    verifier_store_cases: int
    raw_states: int
    policies: int
    state_policy_pairs: int
    generated_policy_edges: int
    reachable_state_policy_pairs: int
    reachable_edges: int
    crown_paths_checked: int


@lru_cache(maxsize=1)
def check_relation_and_provenance_domain() -> tuple[int, int]:
    axis_evidence_cases = 0
    for relation, provenance, has_ref in product(Relation, Provenance, (False, True)):
        evidence_ref = "sha256:evidence" if has_ref else None
        expected_well_formed = (
            provenance is Provenance.PUBLISHER_ASSERTED or has_ref
        )
        try:
            evidence = AxisEvidence(relation, provenance, evidence_ref)
        except ValueError:
            if expected_well_formed:
                raise InvariantViolation("well-formed axis evidence was rejected")
        else:
            if not expected_well_formed:
                raise InvariantViolation("verified provenance without evidence_ref was accepted")
            expected = (
                relation is Relation.DISTINCT
                and provenance in HIGH_AUTHORITY_PROVENANCE
                and has_ref
            )
            if evidence.high_authority_independent() is not expected:
                raise InvariantViolation("axis provenance gate disagrees with its specification")
            if relation in {Relation.PARTIAL, Relation.UNKNOWN, Relation.SHARED} and expected:
                raise InvariantViolation("non-Distinct relation projected to independent")
        axis_evidence_cases += 1

    concrete_relation_vectors = 0
    for relations in product(Relation, repeat=AXIS_COUNT):
        raw_mask = sum(
            1 << index
            for index, relation in enumerate(relations)
            if relation is Relation.DISTINCT
        )
        if raw_mask >= PROFILE_QUOTIENT_COUNT:
            raise InvariantViolation("relation projection escaped the eight-axis domain")
        concrete_relation_vectors += 1
    return concrete_relation_vectors, axis_evidence_cases


@lru_cache(maxsize=1)
def check_aggregation() -> tuple[int, int, int, int, int, int]:
    singleton_count = 0
    pair_count = 0
    triple_count = 0
    supersession_count = 0
    status_indices = {status: index for index, status in enumerate(ALL_REPORT_STATUSES)}
    join_indices = [
        [0 for _ in ALL_REPORT_STATUSES] for _ in ALL_REPORT_STATUSES
    ]

    for index, status in enumerate(ALL_REPORT_STATUSES):
        report = VerificationReport(MODEL_KEY, index, status)
        result = aggregate(
            MODEL_KEY.envelope_id,
            MODEL_KEY.context_id,
            MODEL_KEY.verifier_scope,
            VerifierStore((report,)),
        )
        if result.status != status:
            raise InvariantViolation("singleton aggregate changed its status")
        if join_status(None, status) != status or join_status(status, None) != status:
            raise InvariantViolation("aggregate identity law failed")
        if join_status(status, status) != status:
            raise InvariantViolation("aggregate idempotence law failed")
        singleton_count += 1

    for left_index, left in enumerate(ALL_REPORT_STATUSES):
        for right_index, right in enumerate(ALL_REPORT_STATUSES):
            reports = (
                VerificationReport(MODEL_KEY, left_index, left),
                VerificationReport(MODEL_KEY, len(ALL_REPORT_STATUSES) + right_index, right),
            )
            forward = aggregate(
                MODEL_KEY.envelope_id,
                MODEL_KEY.context_id,
                MODEL_KEY.verifier_scope,
                VerifierStore(reports),
            )
            reverse = aggregate(
                MODEL_KEY.envelope_id,
                MODEL_KEY.context_id,
                MODEL_KEY.verifier_scope,
                VerifierStore(tuple(reversed(reports))),
            )
            if forward.status != reverse.status or forward.report_ids != reverse.report_ids:
                raise InvariantViolation("aggregate depends on report order")
            joined = join_status(left, right)
            if joined != join_status(right, left):
                raise InvariantViolation("binary join is not commutative")
            if forward.status != joined:
                raise InvariantViolation("aggregate fold disagrees with binary join")
            assert joined is not None
            join_indices[left_index][right_index] = status_indices[joined]
            if StatusTag.EXECUTION_DISAGREED in {left.tag, right.tag}:
                if forward.status is not EXECUTION_DISAGREED:
                    raise InvariantViolation("execution_disagreed failed to dominate")
            if {
                left.tag,
                right.tag,
            } == {StatusTag.NOT_REEXECUTED, StatusTag.EXECUTION_DISAGREED}:
                permissive = PromotionPolicy(True, True, 0)
                if authorize(forward, permissive).basis is not None:
                    raise InvariantViolation(
                        "prior not_reexecuted origin-only grant survived disagreement"
                    )
                supersession_count += 1
            pair_count += 1

    for left_index, left in enumerate(ALL_REPORT_STATUSES):
        for middle_index, middle in enumerate(ALL_REPORT_STATUSES):
            left_middle_index = join_indices[left_index][middle_index]
            for right_index, right in enumerate(ALL_REPORT_STATUSES):
                middle_right_index = join_indices[middle_index][right_index]
                if (
                    join_indices[left_middle_index][right_index]
                    != join_indices[left_index][middle_right_index]
                ):
                    raise InvariantViolation("three-report associativity failed")
                triple_count += 1

    favorable_key = ReportKey("envelope", "context", "unapproved-scope")
    favorable = aggregate(
        favorable_key.envelope_id,
        favorable_key.context_id,
        favorable_key.verifier_scope,
        VerifierStore(
            (VerificationReport(favorable_key, 0, agreed(PROFILE_QUOTIENT_COUNT - 1)),)
        ),
    )
    scope_pin_count = 0
    for policy in ALL_POLICIES:
        decision = authorize(favorable, policy)
        if decision.basis is not None:
            raise InvariantViolation("action policy accepted an unpinned verifier scope")
        if (
            decision.verifier_scope_digest != favorable.verifier_scope_digest
            or decision.aggregation_epoch != favorable.aggregation_epoch
            or decision.report_set_digest != favorable.report_set_digest
            or decision.promotion_policy_digest != policy.digest()
        ):
            raise InvariantViolation("authorization output omitted a required digest/epoch")
        scope_pin_count += 1

    old = VerificationReport(
        MODEL_KEY, 10, not_reexecuted(NotReexecutedReason.SKIPPED_BY_POLICY),
        created_epoch=1,
    )
    later_disagreement = VerificationReport(
        MODEL_KEY, 11, EXECUTION_DISAGREED, created_epoch=2,
    )
    store = VerifierStore((old, later_disagreement))
    if aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        store, aggregation_epoch=1,
    ).status != old.status:
        raise InvariantViolation("future report leaked into an earlier epoch")
    if aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        store, aggregation_epoch=2,
    ).status is not EXECUTION_DISAGREED:
        raise InvariantViolation("older unsuperseded report/store completeness failed")

    superseded_old = VerificationReport(
        MODEL_KEY, 12, old.status, created_epoch=1, superseded_at_epoch=2,
    )
    replacement = VerificationReport(MODEL_KEY, 13, agreed(0), created_epoch=2)
    replacement_store = VerifierStore((superseded_old, replacement))
    if aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        replacement_store, aggregation_epoch=1,
    ).status != old.status:
        raise InvariantViolation("report was superseded before its supersession epoch")
    if aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        replacement_store, aggregation_epoch=2,
    ).status != replacement.status:
        raise InvariantViolation("superseded report remained current")

    digest_store_a = VerifierStore((
        VerificationReport(MODEL_KEY, 20, old.status),
        VerificationReport(MODEL_KEY, 21, agreed(0)),
    ))
    digest_store_b = VerifierStore((
        VerificationReport(
            MODEL_KEY, 20,
            not_comparable(NotComparableReason.PROFILE_MISMATCH),
        ),
        VerificationReport(MODEL_KEY, 21, agreed(0)),
    ))
    digest_a = aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        digest_store_a,
    )
    digest_b = aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        digest_store_b,
    )
    if digest_a.status != digest_b.status or digest_a.report_ids != digest_b.report_ids:
        raise InvariantViolation("digest-content control did not preserve aggregate/id set")
    if digest_a.report_set_digest == digest_b.report_set_digest:
        raise InvariantViolation("report_set_digest omitted report contents")

    evidence_digest_a = VerifierStore((
        VerificationReport(
            MODEL_KEY, 22, agreed(1),
            supporting_evidence_digest="sha256:profile-and-refs-a",
        ),
    ))
    evidence_digest_b = VerifierStore((
        VerificationReport(
            MODEL_KEY, 22, agreed(1),
            supporting_evidence_digest="sha256:profile-and-refs-b",
        ),
    ))
    if aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        evidence_digest_a,
    ).report_set_digest == aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        evidence_digest_b,
    ).report_set_digest:
        raise InvariantViolation("report_set_digest omitted supporting profile/evidence")

    historical_base = VerificationReport(MODEL_KEY, 30, old.status, created_epoch=1)
    historical_future_supersession = VerificationReport(
        MODEL_KEY, 30, old.status, created_epoch=1, superseded_at_epoch=2,
    )
    historical_a = aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        VerifierStore((historical_base,)), aggregation_epoch=1,
    )
    historical_b = aggregate(
        MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
        VerifierStore((historical_future_supersession,)), aggregation_epoch=1,
    )
    if historical_a.report_set_digest != historical_b.report_set_digest:
        raise InvariantViolation("future supersession changed a historical epoch digest")

    duplicate_store = VerifierStore((
        VerificationReport(MODEL_KEY, 40, old.status),
        VerificationReport(ReportKey("other", "context", "scope"), 40, agreed(0)),
    ))
    try:
        aggregate(
            MODEL_KEY.envelope_id, MODEL_KEY.context_id, MODEL_KEY.verifier_scope,
            duplicate_store,
        )
    except ValueError:
        pass
    else:
        raise InvariantViolation("verifier store accepted a reused report identifier")

    verifier_store_cases = 7
    return (
        singleton_count, pair_count, triple_count, supersession_count,
        scope_pin_count, verifier_store_cases,
    )


def check_model(
    *,
    broken_laundering: bool = False,
    broken_provenance: bool = False,
    broken_raw_policy: bool = False,
) -> CheckStats:
    concrete_vectors, axis_cases = check_relation_and_provenance_domain()
    (
        aggregate_singletons,
        aggregate_pairs,
        aggregate_triples,
        supersession_cases,
        scope_pin_cases,
        verifier_store_cases,
    ) = check_aggregation()

    generated_policy_edges = 0
    for state in ALL_STATES:
        for policy in ALL_POLICIES:
            for transition in policy_successors(
                state,
                policy,
                broken_laundering=broken_laundering,
                broken_provenance=broken_provenance,
                broken_raw_policy=broken_raw_policy,
            ):
                generated_policy_edges += 1
                assert_transition_invariants(transition, policy)

    reachable_state_policy_pairs = 0
    reachable_edges = 0
    root = State(AUTHENTICATED)
    for policy in ALL_POLICIES:
        reachable, edges = reachable_states(
            (root,),
            policy,
            include_evidence=True,
            broken_laundering=broken_laundering,
            broken_provenance=broken_provenance,
            broken_raw_policy=broken_raw_policy,
        )
        reachable_state_policy_pairs += len(reachable)
        reachable_edges += edges

    crown_paths_checked = 0
    bad_statuses = (EXECUTION_DISAGREED, *ALL_NOT_REEXECUTED, *ALL_NOT_COMPARABLE)
    for bad_status in bad_statuses:
        for policy in ALL_POLICIES:
            reachable, _ = reachable_states(
                (State(bad_status),),
                policy,
                include_evidence=False,
                broken_laundering=broken_laundering,
                broken_provenance=broken_provenance,
                broken_raw_policy=broken_raw_policy,
            )
            crown_paths_checked += 1
            for state in reachable:
                if state.basis is not None and state.basis.tag is BasisTag.EXECUTION_AGREEMENT:
                    raise InvariantViolation(
                        "execution_agreement reachable from "
                        f"{bad_status.tag.value} under {policy}"
                    )

    return CheckStats(
        concrete_relation_vectors=concrete_vectors,
        axis_evidence_cases=axis_cases,
        aggregate_singletons=aggregate_singletons,
        aggregate_ordered_pairs=aggregate_pairs,
        aggregate_ordered_triples=aggregate_triples,
        aggregate_supersession_cases=supersession_cases,
        scope_pin_cases=scope_pin_cases,
        verifier_store_cases=verifier_store_cases,
        raw_states=len(ALL_STATES),
        policies=len(ALL_POLICIES),
        state_policy_pairs=len(ALL_STATES) * len(ALL_POLICIES),
        generated_policy_edges=generated_policy_edges,
        reachable_state_policy_pairs=reachable_state_policy_pairs,
        reachable_edges=reachable_edges,
        crown_paths_checked=crown_paths_checked,
    )


def _self_check() -> int:
    stats = check_model()
    print("NON-LAUNDERING MODEL: PASS")
    print(
        "exhausted "
        f"{stats.concrete_relation_vectors} quaternary relation vectors and "
        f"{stats.axis_evidence_cases} relation/provenance gate cases"
    )
    print(
        "checked aggregation over "
        f"{stats.aggregate_singletons} singleton and "
        f"{stats.aggregate_ordered_pairs} ordered status pairs and "
        f"{stats.aggregate_ordered_triples} ordered status triples, including "
        f"{stats.aggregate_supersession_cases} disagreement-supersession cases"
    )
    print(
        f"checked {stats.scope_pin_cases} action-policy verifier-scope pins and "
        "authorization digest/epoch outputs"
    )
    print(
        f"checked {stats.verifier_store_cases} verifier-store epoch, supersession, "
        "and report-content digest cases"
    )
    print(
        "exhausted "
        f"{stats.raw_states} raw states x {stats.policies} policies = "
        f"{stats.state_policy_pairs} state-policy pairs"
    )
    print(
        f"checked {stats.generated_policy_edges} generated policy edges, "
        f"{stats.reachable_edges} reachable edges, and "
        f"{stats.crown_paths_checked} forbidden-origin path families"
    )

    try:
        check_model(broken_laundering=True)
    except InvariantViolation as exc:
        print(f"BROKEN VARIANT CAUGHT: {exc}")
    else:
        print("ERROR: deliberately broken laundering variant was not caught")
        return 1

    try:
        check_model(broken_provenance=True)
    except InvariantViolation as exc:
        print(f"PUBLISHER-ASSERTED MUTATION CAUGHT: {exc}")
    else:
        print("ERROR: PublisherAsserted-only Distinct mutation was not caught")
        return 1

    try:
        check_model(broken_raw_policy=True)
    except InvariantViolation as exc:
        print(f"RAW-P POLICY MUTATION CAUGHT: {exc}")
    else:
        print("ERROR: raw-profile phi bypass mutation was not caught")
        return 1
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="run exhaustive checks and three deliberate mutation regressions",
    )
    args = parser.parse_args(argv)
    if args.self_check:
        return _self_check()
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
