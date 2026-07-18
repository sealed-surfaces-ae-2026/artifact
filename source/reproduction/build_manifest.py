"""Build the artifact-wide SHA-256 manifest in stable path order."""

from __future__ import annotations

import hashlib
from pathlib import Path


ARTIFACT = Path(__file__).resolve().parents[2]
MANIFEST = ARTIFACT / "MANIFEST.sha256"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    files = sorted(
        (
            path
            for path in ARTIFACT.rglob("*")
            if path.is_file() and path != MANIFEST
        ),
        key=lambda path: path.relative_to(ARTIFACT).as_posix(),
    )
    lines = [
        f"{sha256_file(path)}  {path.relative_to(ARTIFACT).as_posix()}"
        for path in files
    ]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"MANIFEST: {len(lines)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
