#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$1" >&2
  printf '%s\n' 'Use a compatible disposable lab environment; this script never installs tools or changes host policy.' >&2
  exit 1
}

if (($# != 1)); then
  fail 'Usage: bash tools/ci/runtime-preflight.sh docker|containerd'
fi
case "$1" in
  docker)
    command -v docker >/dev/null || fail 'Docker is not preinstalled.'
    [[ -z "${DOCKER_HOST:-}" || "$DOCKER_HOST" == unix://* ]] || fail 'A local Docker Unix socket is required.'
    endpoint=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')
    [[ "$endpoint" == unix://* ]] || fail 'A local Docker context is required.'
    driver=$(docker info --format '{{.Driver}}')
    [[ "$driver" == 'overlay2' ]] || fail 'The lab requires classic Docker overlay2, not the containerd image store.'
    ;;
  containerd)
    for executable in /usr/bin/containerd /usr/bin/ctr /usr/bin/unshare; do
      [[ -x "$executable" ]] || fail "Missing required preinstalled executable: $executable"
    done
    version=$(/usr/bin/containerd --version)
    [[ "$version" == *' 1.7.'* ]] || fail 'The lab currently validates containerd 1.7 only.'
    if [[ "${REQUIRE_RUNC:-false}" == 'true' ]]; then
      [[ -x /usr/bin/runc ]] || fail 'The manual runc profile requires /usr/bin/runc.'
    fi
    ;;
  *) fail 'Unknown runtime lab profile.' ;;
esac

# Private namespace creation is the only stateful probe. No mount or policy in
# the caller's namespace is changed. The helper PID namespace dies on exit.
command -v unshare >/dev/null || fail 'unshare is not preinstalled.'
unshare --user --map-root-user --mount --propagation private --pid --fork \
  --kill-child=KILL --net --mount-proc /usr/bin/true || fail 'Required private user/mount/PID/network namespaces are unavailable.'
