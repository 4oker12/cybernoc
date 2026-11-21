#!/usr/bin/env bash
# Cybernova portable setup. Run only from a reviewed, private Git checkout.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT"
fail() { printf 'CYBERNOVA_SETUP_ERROR: %s\n' "$*" >&2; exit 2; }
for cmd in git python3 docker; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing dependency: $cmd"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
origin="$(git remote get-url origin 2>/dev/null)" || fail "Not a Git checkout"
case "$origin" in
  git@github.com:4oker12/cybernoc|git@github.com:4oker12/cybernoc.git|https://github.com/4oker12/cybernoc|https://github.com/4oker12/cybernoc.git) ;;
  *) fail "Unexpected Git remote; verify repository identity" ;;
esac
sha="$(git rev-parse --verify HEAD)" || fail "Cannot resolve source revision"
expected="$(printenv CYBERNOVA_EXPECTED_SHA 2>/dev/null || true)"
if [[ -n "$expected" && "$sha" != "$expected" ]]; then
  fail "Source revision does not match CYBERNOVA_EXPECTED_SHA"
fi
printf 'Cybernova source: %s\n' "$sha"
printf 'Nothing will be installed or downloaded without confirmation in the wizard.\n'
cd "$ROOT/cybernova/research-platform/portable"
exec python3 manage.py wizard
