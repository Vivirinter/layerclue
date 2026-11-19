#!/usr/bin/env bash
set -euo pipefail
umask 077

# --require-clean binds CI packages to the checked-out commit. Local developer
# validation may omit it; this does not create a release or publisher identity.
clean=()
if [[ "${1:-}" == '--require-clean' ]]; then
  clean=(--require-clean)
  shift
fi
if (($# != 0)); then
  printf '%s\n' 'Usage: bash tools/ci/package.sh [--require-clean]' >&2
  exit 2
fi
ci_python=${LAYERCLUE_CI_PYTHON:-/usr/bin/python3}
"$ci_python" -c 'import sys; sys.exit(0 if sys.version_info[:2] in {(3, 12), (3, 13)} else "CI tooling requires a supported Python 3.12 or 3.13 interpreter")'

# Check ignored/untracked source too. No API verification or secret upload occurs.
go run github.com/zricethezav/gitleaks/v8@v8.30.1 dir --config tools/gitleaks.toml \
  --gitleaks-ignore-path /dev/null --ignore-gitleaks-allow --redact=100 \
  --no-banner --no-color --timeout=120 .

package_tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/layerclue-package.XXXXXXXX")
trap 'rm -rf -- "$package_tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export PYTHONDONTWRITEBYTECODE=1

go mod verify
CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -trimpath -o "$package_tmp/layerclue" ./cmd/layerclue
cli="$package_tmp/layerclue"
"$cli" explain /usr/bin/helper --case examples/demo --strict --json > "$package_tmp/report.json"
"$cli" verify "$package_tmp/report.json" --case examples/demo --strict

go run ./tools/mkexample --output "$package_tmp/provenance-example"
"$cli" explain /opt/tool --case "$package_tmp/provenance-example" --strict

# These disposable keys authenticate only synthetic test inventories/packages.
"$cli" keygen --private-key "$package_tmp/private.hex" --public-key "$package_tmp/public.hex"
"$cli" collect --case examples/demo --output "$package_tmp/bundle" \
  --method 'synthetic CI fixture' --sign-key "$package_tmp/private.hex"
"$cli" verify-case --case "$package_tmp/bundle/case" --inventory "$package_tmp/bundle/inventory.json" \
  --public-key "$package_tmp/public.hex"
"$cli" explain /usr/bin/helper --case "$package_tmp/bundle/case" --strict

go run ./tools/mkdockerexample --output "$package_tmp/docker-example"
"$cli" acquire-docker --source "$package_tmp/docker-example/source" --plan "$package_tmp/docker-example/plan.json" \
  --output "$package_tmp/docker-bundle" --sign-key "$package_tmp/private.hex"
"$cli" verify-case --case "$package_tmp/docker-bundle/case" --inventory "$package_tmp/docker-bundle/inventory.json" \
  --public-key "$package_tmp/public.hex"
"$cli" explain /usr/bin/helper --case "$package_tmp/docker-bundle/case" --strict
"$cli" explain /opt/deleted --case "$package_tmp/docker-bundle/case" --strict

go run ./tools/mkrelease --output "$package_tmp/candidate" "${clean[@]}" --sign-key "$package_tmp/private.hex"
go run ./tools/verifyrelease --dir "$package_tmp/candidate" --public-key "$package_tmp/public.hex" --require-signed
"$ci_python" -m venv "$package_tmp/validator"
"$package_tmp/validator/bin/python" -m pip --disable-pip-version-check --no-cache-dir install \
  --require-hashes --only-binary=:all: -r tools/requirements-release-check.txt
"$package_tmp/validator/bin/python" tools/validate_sbom.py --dir "$package_tmp/candidate"

LAYERCLUE_INSTALL_TEST=1 go test -v -count=1 -timeout 180s ./internal/lab -run '^TestBinaryInstallation$'
