# Sealed Surfaces reproduction artifact

This anonymous, network-free artifact checks the finite non-laundering model,
three deliberate mutations, seven end-to-end integration cases, the frozen
160-cell RQ3 oracle corpus, fresh-process determinism records, and the carrier
decision table. The implementation under study is named only as DSL L; its
execution paths are E1--E4.

## Start here

From a POSIX Bash shell at the artifact root:

```sh
./verify_all.sh --quick
./verify_all.sh --full
```

`--quick` checks the environment, model smoke cases, representative RQ3
fixtures, mutation sentinels, and all seven integration paths. Expected runtime is
under one minute. `--full` runs the exhaustive model, all three mutations, all
seven integration paths, validates every frozen raw observation, regenerates
the 160-cell matrix, paper Tables 2 and 3, and the artifact-side carrier table,
and checks byte or semantic equality against their pinned baselines. Expected runtime is two to five minutes on a
4-core CPU with 8 GiB RAM. Allow 2 GiB free disk space for the unpacked archive
and temporary derived files.

## Reproducibility checklist for the non-laundering model

- Runtime dependency: Python 3.11 or newer, standard library only.
- Normative invocation: run `./verify_all.sh --full` from the artifact root.
  The model-only command is
  `python source/model/non_laundering_model.py --self-check`.
- Expected model success marker: `NON-LAUNDERING MODEL: PASS` and process exit
  code 0. The wrapper's complete success markers are listed below.
- Relation/provenance: 65,536 quaternary eight-axis vectors and 32 one-axis
  gate cases. Only verified-provenance `Distinct` with its required reference
  projects to one.
- Aggregation: 287 singletons, 82,369 ordered pairs, and 23,639,903 ordered
  triples, including 30 disagreement-supersession orders. All four join laws
  are asserted.
- State/policy: 9,216 states times 1,024 policies equals 9,437,184 pairs,
  28,482 generated edges, 322,370 reachable edges, and 31,744 forbidden-origin
  path families.
- Scope/store: 1,024 scope-pin cases check all four output fields. Seven store
  cases check epoch selection, supersession timing, status/support-record
  digest separation, historical stability, and unique report identifiers.
- Mutations: the status relabel, corrupted `PublisherAsserted` projection, and
  raw-profile policy each print a `CAUGHT` marker.
- Covered: join and dominance, scope and output binding, status immutability,
  basis and axis provenance, required references, typed fallback reasons, and
  terminal failure. Stage monotonicity and signed-value authority are not
  modeled.
- Interpretation: exhaustive only for the finite conjunctive-monotone policy
  language. Arbitrary projected predicates rely on the structural argument.
  This is neither an implementation-conformance proof nor a claim beyond
  safety and mutation regression.

The full mode deliberately does **not** rebuild or freshly execute E1--E4.
Their private implementations and identity-bearing binaries cannot be included
in an absolutely blinded, license-clean review bundle. Full mode instead
validates the frozen genuine observation corpus, its executable/source/build
commitments, canonical and per-path raw rerun identities, and every derivation
from raw evidence to paper Tables 2 and 3 and the artifact-side carrier table.
See `ARTIFACT-SCOPE.md` before treating
this as fresh engine replication.

## Platform support

- Tested target: Windows 11 x86-64 through 64-bit Git Bash 5.2.37.
- Also supported by design: x86-64 Linux with Bash 5 and Python 3.11+.
- PowerShell may launch the optional wrapper when present; the normative entry
  point remains `verify_all.sh`.
- Network access is neither required nor used.

The archived experiment environment used Python 3.12.10, Rust/Cargo 1.96.0,
and Node 22.23.1. Replaying the frozen corpus requires only Bash, Python 3.11+
and common checksum utilities; Rust and Node are checked as provenance facts,
not invoked to rebuild the excluded engines.

## Successful output

Full verification ends with these markers (plus `INTEGRATION: 7/7 PASS`):

```text
MODEL: PASS
MUTATION_STATUS_LAUNDERING: CAUGHT
MUTATION_PUBLISHER_PROJECTION: CAUGHT
MUTATION_RAW_PROFILE_POLICY: CAUGHT
RQ3_ORACLE: 160/160 PASS
DETERMINISM_RERUN: BYTE_IDENTICAL
CARRIER_TABLE: REPRODUCED
```

Any missing marker is a failure.

## Failure diagnostics

- `python: command not found`: install Python 3.11 or newer and ensure `python` or
  `python3` is on `PATH`.
- `bad interpreter`, `unexpected EOF`, or heredoc errors: verify that
  `verify_all.sh` retained LF line endings and run it from Git Bash or Bash 5.
- Digest mismatch under `raw/`: do not edit the corpus; re-extract the archive
  and compare the file against `MANIFEST.sha256`.
- Matrix/table mismatch: inspect the named regenerated file under `derived/`
  and the corresponding assertion printed immediately before failure.
- Missing E1--E4 executable: expected in this blinded review bundle. Do not
  point the verifier at an external checkout; engine reruns are out of scope.
- Carrier dependency import errors apply only to the historical carrier source
  rerun, not to table reproduction from frozen raw trials. Exact package
  versions are in `toolchain/carrier-requirements.lock`.

Verification is fail-closed: the first failed assertion exits nonzero. For a
portable transcript use `./verify_all.sh --full 2>&1 | tee verify-full.log`.

## Layout

- `source/`: finite model, tests, blinded RQ3 harness, fixture generators, and
  carrier experiment source.
- `engines/e1` ... `engines/e4`: blinded commitments and explicit exclusion
  records for the exact artifacts used.
- `inputs/`: clean L programs, injected fixtures, profile/preregistration data,
  and carrier baselines.
- `raw/`: immutable observations, stdout/diagnostics/resource reports, and
  determinism reruns.
- `derived/`: regenerated canonical transcripts, matrix, evidence profiles,
  paper Tables 2 and 3, and the artifact-side carrier table.
- `toolchain/`: normalized locks, versions, build flags, and artifact digests.
- `carrier/CARRIER-APPENDIX.md`: full carrier definitions, protocol, design
  retreat, and the carrier decision table removed from the page-limited paper.
- `proofs/PROPERTIES.md`: detailed games and proof sketches for Properties
  1--3.
- `LIMITATIONS.md`: the detailed thirteen-item boundary list grouped into five
  categories in the paper.
