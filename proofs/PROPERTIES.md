# Standard cryptographic properties

This document preserves the detailed games and proof sketches for Properties
1--3. They are DSSE-class carrier-transparency results, not new hardness
results. The paper retains the theorem statements and the common reduction.

## Common setting

The adversary may choose any received object and may query a sealing oracle.
Correct canonical parsing, injectivity of `DetEnc` and `PAE`, and conformance to
the transition relation define the modeled verifier. The reductions assume
collision resistance for every digest admitted by policy and existential
signature unforgeability under adaptive chosen-message attack for approved,
uncompromised keys.

Let sealing oracle \(\mathcal O_{\mathrm{seal}}(e)\) return a valid signature
on \(\mu(e)\) and record \(\mu(e)\) in query set \(Q\). Let
\(\operatorname{VfyPipeline}_\Pi(y)\) be the staged verifier. A negligible
function in security parameter \(\lambda\) is
\(\operatorname{negl}(\lambda)\).

## Property 1: authenticated-envelope unforgeability

**Game \(G_{\mathrm{auth}}\).** The challenger generates an approved key pair
and gives the adversary public parameters and adaptive access to
\(\mathcal O_{\mathrm{seal}}\). The adversary outputs \(y^*\). It wins iff the
pipeline reaches `authenticated` for \((e^*,\sigma^*)\) under the challenge key
and \(\mu(e^*)\notin Q\).

**Theorem 2.** Under signature unforgeability,

\[
\Pr[G_{\mathrm{auth}}^{\mathcal A}=1]
\leq \operatorname{Adv}^{\mathrm{euf\mbox{-}cma}}_{\mathrm{Sig}}(\mathcal B)
=\operatorname{negl}(\lambda).
\]

**Proof sketch.** The recovery output is parsed and canonically re-encoded
before signature verification. Acceptance therefore supplies a valid signature
on exact canonical bytes not queried from the sealing oracle, which is an
EUF-CMA forgery. The channel only influences the candidate bytes. An old
queried envelope is replay, not a win.

## Property 2: atomic binding of payload kind and fields

Define the protected vector

\[
\begin{aligned}
F(e):=(&\texttt{domain},\texttt{object\_version},\texttt{codec\_profile},\\
&\texttt{payload\_tag},\texttt{payload}).
\end{aligned}
\]

For the program tag, `payload` is the complete `SignedProgramV1`. For the
execution tag, it is the complete `SignedExecutionEnvelopeV1`, including its
nested program and claim. Canonical tagged encoding prevents the verifier from
parsing one variant as the other. Thus `execution_claim` is bound exactly when
the execution-bearing type is selected and is absent, rather than empty or
optional, in Scope A0.

**Game \(G_{\mathrm{bind}}\).** After sealing-oracle queries, the adversary
outputs accepted \((e^*,\sigma^*)\) and an alternative protected vector
\(F'\neq F(e^*)\). It wins if the verifier accepts \(F'\) as an opening of the
same signed message, or if two distinct resolved objects for a digest-bearing
field satisfy the same admitted digest.

**Theorem 3.** If `DetEnc` and `PAE` are injective and canonical, and assuming
signature unforgeability and collision resistance,

\[
\Pr[G_{\mathrm{bind}}^{\mathcal A}=1]
\leq \operatorname{Adv}^{\mathrm{euf\mbox{-}cma}}_{\mathrm{Sig}}(\mathcal B_1)
+q_H\operatorname{Adv}^{\mathrm{cr}}_H(\mathcal B_2)
=\operatorname{negl}(\lambda).
\]

**Proof sketch.** Changing an inline field changes `DetEnc(e)` and the signed
message, so acceptance without a matching sealing query is a forgery. If
message bytes do not change, injectivity gives the same typed vector.
Substituting the referent of a digest-bearing field while retaining its signed
digest yields a collision. This is why the entire envelope is signed.

## Property 3: resistance to authenticated region mixing

**Game \(G_{\mathrm{mix}}\).** The adversary obtains rendered, valid signed
objects \(y_1,\ldots,y_n\), constructs \(y^*\) from arbitrary regions of at
least two inputs plus arbitrary edits, and wins iff the pipeline authenticates
a new composite message \(\mu(e^*)\notin Q\).

**Theorem 4.** Under Theorems 2--3,

\[
\Pr[G_{\mathrm{mix}}^{\mathcal A}=1]
\leq \operatorname{Adv}^{\mathrm{euf\mbox{-}cma}}_{\mathrm{Sig}}(\mathcal B_1)
+q_H\operatorname{Adv}^{\mathrm{cr}}_H(\mathcal B_2)
=\operatorname{negl}(\lambda).
\]

**Proof sketch.** Physical provenance disappears at the authenticated pipeline
boundary because the verifier sees decoder output. If mixing creates new
canonical bytes that authenticate, it yields a forgery or alternative digest
opening. If it decodes to one old valid envelope, the event is substitution or
replay. Failure or unsigned output rejects. The theorem does not claim every
mixed image is undecodable.
