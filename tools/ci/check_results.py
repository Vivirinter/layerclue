"""Fail closed unless every required CI job succeeded; no third-party imports."""
import json
import os
import sys

REQUIRED = frozenset({"workflow-audit", "quality", "security", "fuzz", "package"})
OPTIONAL = frozenset({"runtime-labs", "private-labs"})


def check(results, required_labs=frozenset()):
    if not set(required_labs) <= OPTIONAL:
        raise ValueError("unknown requested runtime lab")
    if not isinstance(results, dict) or set(results) != REQUIRED | OPTIONAL:
        raise ValueError("missing or unexpected CI job results")
    for name in sorted(results):
        job = results[name]
        if not isinstance(job, dict):
            raise ValueError(f"invalid result for {name}")
        allowed = {"success"} if name in REQUIRED | set(required_labs) else {"success", "skipped"}
        if job.get("result") not in allowed:
            raise ValueError(f"job {name} did not satisfy the CI gate")


def main():
    try:
        requested = set()
        for env, name in (("REQUIRE_RUNTIME_LAB", "runtime-labs"),
                          ("REQUIRE_PRIVATE_LAB", "private-labs")):
            value = os.environ.get(env, "false")
            if value not in {"true", "false"}:
                raise ValueError("invalid requested-lab flag")
            if value == "true":
                requested.add(name)
        check(json.loads(os.environ["NEEDS_RESULTS"]), requested)
    except (KeyError, ValueError, TypeError) as error:
        print(f"CI gate failed: {error}", file=sys.stderr)
        return 1
    print("All required jobs succeeded; any requested runtime jobs also succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
