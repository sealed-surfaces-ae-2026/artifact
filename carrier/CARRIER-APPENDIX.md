# Lossy visual carrier definitions and design retreat

This document preserves the full carrier definitions, protocol, and results
that accompany the paper's short evaluation note. The carrier is a portability
mechanism, not the paper's security contribution.

## Definitions

Fix a supported codec profile \(v\). Let:

- \(m\in\mathbb{B}^*\) be the canonical bytes of a signed envelope;
- \(E_v\colon\mathbb{B}^*\rightarrow\mathcal{C}_v\) be the deterministic encoder, with logical visual codeword \(c=E_v(m)\);
- \(R_v\colon\mathcal{C}_v\rightarrow\mathcal{X}_v\) be the deterministic renderer, with canonical raster \(x_0=R_v(E_v(m))\);
- \(T\colon\mathcal{X}_v\rightarrow\mathcal{Y}\) be a channel transformation, with received object \(y=T(x_0)\); and
- \(D_v\colon\mathcal{Y}\rightarrow\mathbb{B}^*\cup\{\bot\}\) be the decoder.

The canonical raster function
\(N\colon\mathcal{Y}\rightarrow\mathcal{X}\cup\{\bot\}\) applies a fixed,
versioned interpretation of orientation, color space, alpha composition,
dimensions, channel order, bit depth, and sample quantization. Metadata not
named by that interpretation is discarded. An EXIF-like orientation is applied
rather than compared as an uninterpreted field. \(N(y)=\bot\) when the object
has no unique raster under the profile. The renderer's output is canonical, so
\(N(R_v(c))=R_v(c)\). Functional correctness of the codec requires

\[
D_v(R_v(E_v(m)))=m.
\]

This is a codec condition, not a cryptographic claim about arbitrary received
objects.

## Recovery predicates

For received object \(y\) and intended envelope bytes \(m\), define

\[
\operatorname{exactRecover}_v(y,m)
\Longleftrightarrow
D_v(y)=m \land N(y)=R_v(E_v(m))
\]

and

\[
\operatorname{robustRecover}_v(y,m)
\Longleftrightarrow
D_v(y)=m.
\]

Thus `exactRecover` implies `robustRecover`, but not conversely. Exact recovery
uses canonical-raster equality, not file-byte equality. Distinct metadata,
lossless compression choices, scan orders, or color-profile encodings can
denote the same canonical raster.

For the separate publication property fixing container bytes, let

\[
F_v(m):=\operatorname{CanonicalFileEncode}(R_v(E_v(m)))
\]

and define

\[
\begin{aligned}
\operatorname{fileExactAccept}_v(f,m)
\Longleftrightarrow{}&
\operatorname{ParseCanonicalFile}(f)\\
&\land \operatorname{Bytes}(f)=F_v(m).
\end{aligned}
\]

`fileExactAccept` concerns deterministic publication of a designated
container. It is not the exact-channel identity criterion.

## Hard binding after loss

`exactRecover` states both exact envelope recovery and canonical-raster
identity. `robustRecover` states exact recovery of \(m\) despite possible raster
change. Robust recovery therefore permits hard authentication of the recovered
envelope after signature verification. It does not authenticate the received
pixels. The claim is "exact recovery and authentication of a signed canonical
payload within the stated channel boundary," not "pixel integrity survives
lossy transformation."

No similarity score, watermark match, or decoder confidence is authentication.
Error correction yields a candidate \(m\). Only a valid signature over those
exact canonical bytes yields `authenticated`. A wrong decoder output
\(m'\neq m\) is a carrier error. It becomes an authenticated false acceptance
only if cryptographic and contextual checks also accept \(m'\).

## Pre-registered negative result

The carrier spike used a deterministic simulated photo and recompression
channel, not a physical-print/camera population study. Its observed zero
authenticated-false-acceptance counts are empirical only. Cryptographic
confidence comes from the assumed EUF-CMA security of the deployed signature
scheme, Ed25519 in that spike, not the sample size.

H1 asked whether the custom single-layer grid strictly improved the
large-payload simulated-photo-plus-JPEG decision subset over a strong mosaic
baseline. The baseline used six data and three parity fragments, QR-M inner
error correction, bound fragment indices and physical positions, a repeated
signed manifest, and outer Reed-Solomon erasure recovery of any six fragments.
Equal-area and equal-module controls used the same payload bytes, signed
envelope, decode budget, and arm-independent noise seeds. No pre-registered
metric showed a strict custom-grid advantage, so H1 was rejected.

### Carrier decision subset, formerly Table 4

| Fairness mode | Arm | Trials | `robustRecover` | Decoder wrong-output | Authenticated false acceptance | Diagnostic F1 |
|---|---|---:|---:|---:|---:|---:|
| equal area | custom grid | 27 | 0.704 | 0.000 | 0.000 | 0.957 |
| equal area | mosaic + outer RS | 27 | 1.000 | 0.000 | 0.000 | 1.000 |
| equal module | custom grid | 27 | 0.704 | 0.000 | 0.000 | 0.958 |
| equal module | mosaic + outer RS | 27 | 1.000 | 0.000 | 0.000 | 1.000 |
| pooled | custom grid | 54 | 0.704 | 0.000 | 0.000 | 0.957 |
| pooled | mosaic + outer RS | 54 | 1.000 | 0.000 | 0.000 | 1.000 |

The custom carrier recovered 70.4% versus the strong baseline's 100% under
both fairness modes. Both arms had 0% decoder wrong-output and 0%
authenticated false acceptance. Pooled diagnostic F1 was 0.957 versus 1.000.
Replay/substitution was not applicable to this carrier-only channel matrix and
was not counted as either decoder wrong-output or authenticated false
acceptance.

## Consequence

The carrier instantiation therefore uses `canonical signed envelope + standard
2D symbols + multi-symbol sharding + outer erasure correction`. The custom grid
is not part of the claimed system and showed no measurable advantage over the
strong baseline. The typed discipline, authoritative envelope, and real-engine
RQ3 matrix do not depend on the carrier. The visual layer is a UX and
portability choice, not a security differentiator.

## Executed comparison protocol

### Systems

The comparison included QR at multiple built-in error-correction levels, Data
Matrix, Aztec, the custom carrier, and the mandatory strong baseline:

```text
canonical signed envelope
+ best available standard 2D carrier
+ multi-symbol sharding
+ signed manifest and bound fragment indices/positions
+ outer Reed-Solomon erasure correction
```

### Fairness constraints

All systems received identical envelope bytes, matched total redundancy,
minimum module or cell size controls, capture resolution and physical
allocation, and decode-time/compute budgets. Equal physical area and equal
module/cell size were separate analyses. The mosaic reconstructed any six of
nine fragments and was not weakened by requiring every shard to survive.

### Payloads, channels, and metrics

Payload regimes were approximately 0.5 KB, 1.5 KB, and 4 KB. Simulated
channels included JPEG recompression, scaling, photo/recompression transforms,
grayscale conversion, and color-space or gamma transformation. Metrics included
physical area, effective capacity, `exactRecover`, `robustRecover`, decoder
wrong-output, authenticated false acceptance, damage-localization accuracy,
structural/data recovery, and staged latency. The large-payload
simulated-photo-plus-JPEG decision subset and H1 rule were fixed before the
verdict.
