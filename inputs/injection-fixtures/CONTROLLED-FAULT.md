# Controlled common-lineage fault record

The three excluded experiment-only fault binaries for E1, E2, and E3 change
the shared native `+` primitive result from `585987` to `585988` only for the
exact operands `314159` and `271828`. E4 is unmodified and evaluates the same
supported primitive row to `585987`.

The mutation was temporarily inserted into the corresponding numeric primitive
module in the E1 and E2/E3 source trees. The isolated binaries were built and
the source modules were then restored byte-for-byte. The experiment record
retains these restored module SHA-256 values:

- E1 restored module: `e8f0fd2bc55509921436a7eced850c04f4cdf2da97f85daa92df4b82585f784d`
- E2/E3 restored module: `57e0fb38d2134198474eb23be0a9cdcc6a61d06eaddffb7319fe3d47e5c8d290`

The capability contract classifies `+` as supported across the native, E2
guest, and E4 evaluator paths. E2 delegates it to the pinned deterministic
native host primitive; E4 delegates it to the corresponding E4 host primitive.
This is therefore an engine-side common-mode mutation on the admitted 84/205
hosted primitive surface, not an observation-wrapper mutation and not a claim
of a naturally occurring defect.

The exact temporary patch preimage was not retained. This record describes the
experiment and its restored-source commitments; it is not presented as a
reconstructable patch. Exact excluded binary commitments are under `engines/`.
