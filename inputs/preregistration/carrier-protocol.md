# Appendix-A comparison spike: pre-registered protocol

Status: frozen before the first harness measurement run.

## Hypothesis and decision rule

H1 is the design document's Appendix A.1 hypothesis: in the practical payload
regime, a single-layer artifact with integrated ECC beats a strong standard
baseline (standard 2D-code mosaic plus outer erasure coding) on a lossy visual
channel.

The decision subset is fixed to:

- payload regime: `large` (4096 payload bytes, plus the identical signature envelope)
- channel family: `photo_recompress`
- comparison: `custom_grid` (arm 4) versus `mosaic_outer_rs` (arm 5)
- experiments: `equal_area` and `equal_module`, reported separately and pooled
- repetitions: three deterministic channel realizations per condition

H1 is `SUPPORTED` if arm 4 has a strictly higher pooled robust-recovery rate
than arm 5, or a strictly lower authenticated-false-acceptance rate, or a
strictly higher mean damage-location diagnostic accuracy, on that decision
subset. It is `REJECTED` if none of those three strict advantages occurs.
`MIXED` is reserved for conflicting experiment-specific directions that make
the pooled strict comparison sensitive to the fairness mode; it is not used to
turn a tie into support.

Authenticated-false-acceptance can decide H1 only if the empirical rates
differ. Equal zero counts do not constitute an advantage. Diagnostic accuracy
can decide H1 only when both arms have at least one non-null diagnostic result.

## Fixed comparison controls

- Payload bytes and the Ed25519-signed envelope are byte-identical across arms.
- Arm 5 uses six data plus three outer RS parity fragments. Its QR-M inner
  codeword redundancy and 50% outer redundancy are combined as
  `(1 + outer) * (1 + inner) - 1`. Arm 4's RS parity/data ratio is matched to
  that version-specific combined coding ratio (approximately 138%). Mandatory
  framing, finder, signed-manifest, and index bytes are protocol overhead rather
  than parity; they are reported through logical dimensions and physical area.
- `equal_area`: every artifact fills the same 1200 x 1200 pixel physical box
  inside a 1600 x 1600 capture frame. Nearest-neighbor scaling quantizes logical
  cells to adjacent integer widths; the minimum must be at least 2 capture pixels.
- `equal_module`: every logical module/cell is 4 capture pixels. Artifacts are
  centered in the same 1600 x 1600 capture frame; configurations that cannot
  fit are recorded as capacity/geometry failures.
- Nominal capture field: 200 x 200 mm at 1600 x 1600 pixels and fixed simulated
  distance. Thus 8 px/mm, a 150 x 150 mm equal-area box, and a 0.5 mm equal
  module/cell size.
- Every arm receives a 2000 ms end-to-end decode budget. A correct result after
  that budget is scored as a budget failure.
- All randomness is derived from the fixed seed 20260718 plus condition and
  repetition identifiers.

The equal-area experiment enforces the common physical box and a common
minimum-module lower bound; the equal-module experiment enforces exact module
size. Exact equality of both area and module size is generally impossible for
artifacts with different logical dimensions, which is why Appendix A.3 asks
for these as separate experiments.

Protocol audit note: an initial pilot matched only the configurable 50% RS
layer and omitted QR-M's native inner ECC from redundancy accounting; it is
preserved as `results_unmatched_pilot/`. A second pilot allocated equal boxes
but left unequal unused margins after integer module scaling; it is preserved
as `results_underfilled_equal_area_pilot/`. Both were invalidated. The H1
decision rule and channel matrix were unchanged. The corrected total-coding
ratio and full-box equal-area rules above were frozen before the final
`results/` run.

## Recovery and security predicates

- `exactRecover`: decoded envelope equals the original and the normalized
  received 1600 x 1600 RGB raster equals the canonical raster.
- `robustRecover`: decoded envelope bytes equal the original.
- `decoder_wrong_output`: the carrier returns a complete envelope different
  from the original.
- `authenticated_false_acceptance`: such a wrong output nevertheless passes
  Ed25519 verification and envelope parsing.
- `substitution_replay`: not exercised by this carrier-only channel matrix and
  reported as `n/a`, not folded into either wrong-output metric.

## Channels

- identity control
- JPEG qualities 95, 80, 65, 50, 30
- scales 100%, 75%, 50%, 25% (downsample then restore to the capture frame)
- simulated photo plus JPEG recompression: angles 0, 15, 30 degrees crossed
  with dark, normal, bright illumination
- grayscale
- color/gamma shifts: gamma 0.70, gamma 1.40, warm tint, cool tint

## Diagnostics

Damage location is scored at each carrier's native independently recoverable
unit: RS byte positions for the custom grid and fragment/tile positions for the
mosaic. The score is set-based F1 against byte/sample discrepancies or failed
original fragments. A true-negative no-damage case scores 1. Structure recovery
and data recovery are separate columns. Latency is staged into localization,
symbol/sample decode, ECC/erasure recovery, authentication, and total time.
