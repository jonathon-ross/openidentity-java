#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
echo "========================================================================"
echo "OPENIDENTITY JAVA SDK RELEASE GATE"
echo "========================================================================"
mvn clean verify
git diff --exit-code
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Release gate failed: git worktree is not clean." >&2
  git status --short
  exit 1
fi
echo "========================================================================"
echo "OPENIDENTITY JAVA SDK RELEASE GATE: PASS"
echo "========================================================================"
