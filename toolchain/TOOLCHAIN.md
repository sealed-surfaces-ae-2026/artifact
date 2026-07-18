# Toolchain and build record

## Frozen experiment environment

- Python: 3.12.10
- Rust compiler: 1.96.0, x86_64-pc-windows-gnu, LLVM 22.1.2
- Cargo: 1.96.0, x86_64-pc-windows-gnu
- Node.js: 22.23.1
- Carrier packages: exact versions in `carrier-requirements.lock`
- Artifact wrapper test shell: 64-bit Git Bash 5.2.37

Compiler revision hashes and release dates are intentionally omitted as
identity-bearing metadata; semantic version, target, and LLVM version are
retained.

## Recorded clean build commands

The historical harness requested default Cargo debug profiles:

```text
cargo build --bin E1
cargo build --bin E1 --bin E2 --bin E3
cargo build --manifest-path source/rq3/tools/canonicalize/Cargo.toml
```

The first command describes E1's earlier standalone crate layout. It must not be
reinterpreted against the current private workspace layout; the retained E1
binary is bound by its exact executable and historical source commitments. E2
and E3 were requested together by the harness, but the genuine run did not
capture a build-profile, lock, or dirty-source-tree digest before a concurrent
rebuild. Their exact executable identities are recorded; their implementation
preimages are `UNKNOWN`. No release flag, custom optimization flag, target
override, or environment-specific rust flag was recorded by the harness.

E4 used an already activated cross-language interpreter instance and a retained
generated-native host. The experiment did not rebuild either host. Exact E4
artifact commitments are under `engines/e4/`.

The reproduction wrapper does not invoke these build commands because the
corresponding private sources and identity-bearing binaries are excluded.
