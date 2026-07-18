#!/usr/bin/env bash
set -euo pipefail

artifact_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$artifact_root"

if [[ $# -ne 1 || ( "$1" != "--quick" && "$1" != "--full" ) ]]; then
    echo "usage: ./verify_all.sh --quick|--full" >&2
    exit 2
fi
mode=$1

if LC_ALL=C grep -q $'\r' "$0"; then
    echo "ERROR: verify_all.sh contains CR bytes; restore the LF-only artifact copy" >&2
    exit 1
fi

if [[ -z ${BASH_VERSION:-} ]]; then
    echo "ERROR: POSIX entry point requires Bash" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    python_cmd=(python3 -B)
elif command -v python >/dev/null 2>&1; then
    python_cmd=(python -B)
else
    echo "ERROR: Python 3.11 or newer was not found" >&2
    exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
"${python_cmd[@]}" -c 'import sys; assert sys.version_info >= (3, 11), sys.version'

echo "ENVIRONMENT: PASS (Bash ${BASH_VERSION%%(*}; $("${python_cmd[@]}" --version 2>&1))"
"${python_cmd[@]}" source/reproduction/verify_artifact.py "$mode"
