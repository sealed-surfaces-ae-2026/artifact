# Blinded source transformation record

The source under `source/rq3/` preserves the experiment logic but is a blinded
snapshot, not byte-identical to the private working copy. The following
mechanical transformations were applied before inclusion:

- the real DSL and implementation product names were replaced with `L` and
  internal identifier `dsl_l`;
- engine/product/host names were replaced with E1--E4 and the E4 path labels
  `interpreter` and `generated`;
- L source extensions were normalized to `.l`;
- absolute workspace paths were replaced with artifact-relative E1--E4 paths;
- repository-head discovery and source-control identifiers were removed and
  replaced by content commitments under `engines/`;
- compiler/interpreter version output was reduced to product and semantic
  version, omitting release dates and source-control revision tokens;
- the canonicalizer dependency lock's remote registry locator was replaced by
  the neutral `registry+blinded-offline-index` placeholder while preserving package names,
  versions, checksums, and dependency edges; the file is consequently named
  `Cargo.lock.blinded` and is provenance data, not a rebuild promise;
- all copied text was normalized to UTF-8 without BOM and LF line endings.

No oracle branch, expected outcome, comparison projection, fixture payload,
seed, policy rule, or table calculation was changed. The private engine source
and binaries were not rewritten into anonymous lookalikes; they were excluded
and committed by digest as described in `ARTIFACT-SCOPE.md`.
