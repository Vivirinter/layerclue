#!/usr/bin/env bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1
ci_python=${LAYERCLUE_CI_PYTHON:-/usr/bin/python3}
"$ci_python" -c 'import sys; sys.exit(0 if sys.version_info[:2] in {(3, 12), (3, 13)} else "CI tooling requires a supported Python 3.12 or 3.13 interpreter")'

# Run from the repository root. All generated files stay outside the checkout.
audit_tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/layerclue-audit.XXXXXXXX")
trap 'rm -rf -- "$audit_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$ci_python" -m venv "$audit_tmp/venv"
"$audit_tmp/venv/bin/python" -m pip --disable-pip-version-check --no-cache-dir install \
  --require-hashes --only-binary=:all: -r tools/requirements-ci-check.txt

shopt -s nullglob
workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
if ((${#workflows[@]} == 0)); then
  printf '%s\n' 'No workflow files found; run from the repository root.' >&2
  exit 1
fi

go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 \
  -shellcheck="$audit_tmp/venv/bin/shellcheck" -pyflakes= "${workflows[@]}"
"$audit_tmp/venv/bin/shellcheck" tools/ci/*.sh
# Explicit paths also audit untracked workflows during local release preparation.
# Offline mode performs no GitHub API requests and needs no repository token.
"$audit_tmp/venv/bin/zizmor" --offline "${workflows[@]}" .github/dependabot.yml
"$ci_python" -m unittest discover -s tools/ci -p '*_test.py'
