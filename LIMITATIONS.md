# Detailed claim boundaries

The paper groups these boundaries into five categories to meet the venue's
total-page limit. This document preserves the full thirteen-item statement.

1. **No execution proof and no historical-execution proof.** The envelope contains a signed engine-attributed claim and supports verifier-side agreement. It does not prove that the attributed engine actually ran at publication time. No SNARK, STARK, TEE attestation, or equivalent proof mechanism is supplied.
2. **No defect exclusion.** Agreement increases differential detection sensitivity for fault domains separated by the recorded vector. It does not prove either implementation defect-free.
3. **No self-authenticating trust root.** An image cannot make its embedded key trustworthy. Trust anchors, allowed profiles, semantics, decoders, and policies are external verifier inputs.
4. **No replay prevention when freshness is a non-goal.** A copied valid envelope remains validly signed. Same-context replay is prevented only to the extent that external state and policy enforce the signed purpose, subject, nonce, issue time, and expiry.
5. **No source-language semantic equivalence.** If canonical L IR was translated from another language, the claims cover IR identity and its L execution, not equivalence to the source program. Visual round trip is carrier fidelity, not source semantics.
6. **Runtime/toolchain, not source or organizational, independence for E1 to E4.** Agreement strength depends on the actual `IndependenceProfile`. The profile labeled I3 separates E1 and E4 on runtime backend and build toolchain, but E4 is a transliteration that shares source, parser, and semantic-core lineage with E1. All tested paths also share one operator, organization, machine, and language specification. It is therefore not source-lineage, organizational, operator, hardware, or independent-specification replication. I0--I3 are profile labels, not a total order.
7. **No received-pixel integrity in robust mode.** Robust mode recovers and authenticates envelope bytes. Transformed pixels may differ.
8. **No proof of policy correctness, key management, or independent reproducibility.** The verifier assumes its trust, context, engine, promotion, format, resource, and freshness policies are supplied correctly. The work does not solve key custody or revocation or independently reproduce publisher environments.
9. **No conformance-suite, program-diversity, whole-language, or arbitrary-native-code claim.** Real-L evaluation contains a four-program clean feature corpus and six fixed injection fixtures within 84/205 hosted primitive rows. The 160 cells are condition combinations, not 160 diverse programs or samples. The broader repository ledger remains only 34/144 all-family agreeing cases. A systematic conformance suite is future work. Claims are confined to deterministic L, the modeled profiles and inputs, and the declared commitment scope. They establish neither whole-language equivalence nor whole-program safety.
10. **Canonical equality is not raw-observation equality.** Canonical transcripts were byte-identical, but raw observations differed across engines in identity, metrics, resource reports, and CLI/product structure. No completeness claim is made for axes projected away by canonicalization or absent from `commitment_scope`.
11. **No limit-exhaustion equivalence.** All probes stayed within configured limits. Differing resource interfaces mean equivalent behavior under recursion, memory, time, or other exhaustion was not established.
12. **No language-level step-trace equivalence.** None of the real engines exposes a comparable language-level step trace. Scope C commits only the canonical observable root/termination event trace and an explicit unavailable marker.
13. **No attack-prevalence claim.** Security games bound modeled acceptance events. They do not estimate real-world attack frequency.

The system also does not provide its own transparency log or trusted timestamp.
It can consume externally established trust and freshness state, but an
offline-verifiable carrier still relies on signature infrastructure. The
carried artifact needs no online manifest lookup or separate attestation
sidecar at verification time.
