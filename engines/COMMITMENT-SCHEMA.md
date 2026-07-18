# Blinded source commitment algorithm

`blinded-tree-sha256-v1` binds a private source closure without publishing its
identity-bearing paths.

1. Select the exact files that formed the recorded build or module closure.
2. Sort their private, source-relative UTF-8 paths by ordinal byte order.
3. Replace each path, in that order, with a one-based six-digit ordinal. No
   private path byte enters the public preimage.
4. Hash each file's exact bytes with SHA-256; preserve its byte length and line
   endings.
5. For each file append this ASCII line to the tree preimage:

   ```text
   NNNNNN BYTE_LENGTH LOWERCASE_FILE_SHA256\n
   ```

6. The tree commitment is SHA-256 over the complete UTF-8/ASCII preimage.

The JSON records file count, aggregate byte length, preimage byte length, and
tree digest so accidental changes in selection or serialization fail closed.
The private path order is not published because filenames themselves contain
the blinded implementation identities. Source-control revisions, timestamps,
authors, remotes, and tree identifiers are not part of this scheme.

`canonical-json-sha256-v1` hashes the exact compact JSON string shown in the
`preimage` field as UTF-8 without BOM or trailing newline. It is used for build
profiles whose executable names and temporary paths have already been replaced
by E1--E4 labels. The replacement changes no compiler option or build mode.

`status: UNKNOWN` is intentional, not a wildcard. It means the genuine run
captured the executable/module commitment but did not capture the stated
preimage before a concurrent private-worktree change. A later tree is never
substituted for the missing historical one.

