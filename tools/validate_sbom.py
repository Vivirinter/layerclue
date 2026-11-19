#!/usr/bin/env python3
"""Validate generated SBOMs against hash-pinned, offline CycloneDX schemas.

This is a development/release check, not a LayerClue runtime dependency. The
registry refuses network retrieval; all referenced schemas come from this tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from referencing.jsonschema import DRAFT7


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def read_json(path: Path, maximum: int):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError(f"oversized JSON input: {path.name!r}")
    return raw, json.loads(raw, object_pairs_hook=unique_object)


def no_network(uri: str):
    raise NoSuchResource(ref=uri)


def validator(schema_dir: Path):
    _, manifest = read_json(schema_dir / "SOURCES.json", 16 << 10)
    if manifest.get("schema") != "layerclue.validation-schemas/v1":
        raise ValueError("unsupported schema manifest")
    expected = {"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"}
    if {item["path"] for item in manifest["files"]} != expected or len(manifest["files"]) != 3:
        raise ValueError("unexpected validation schema set")
    resources = []
    schemas = {}
    for item in manifest["files"]:
        name = item["path"]
        raw, document = read_json(schema_dir / name, 2 << 20)
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError(f"schema checksum mismatch: {name!r}")
        resource = Resource.from_contents(document, default_specification=DRAFT7)
        for uri in [document.get("$id"), f"http://cyclonedx.org/schema/{name}", f"https://cyclonedx.org/schema/{name}"]:
            if uri:
                resources.append((uri, resource))
        schemas[name] = document
    registry = Registry(retrieve=no_network).with_resources(resources)
    schema = schemas["bom-1.6.schema.json"]
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", type=Path, required=True, help="generated release directory")
    args = parser.parse_args(argv)
    try:
        check = validator(Path(__file__).resolve().parent / "schemas")
        for arch in ("amd64", "arm64"):
            path = args.dir / f"SBOM_linux_{arch}.cdx.json"
            _, data = read_json(path, 1 << 20)
            if data.get("bomFormat") != "CycloneDX" or data.get("specVersion") != "1.6":
                raise ValueError("expected a CycloneDX 1.6 SBOM")
            error = next(check.iter_errors(data), None)
            if error is not None:
                raise ValueError(f"{path.name!r}: {error.message!r}")
    except (OSError, ValueError, KeyError, NoSuchResource) as error:
        print(f"SBOM validation failed: {str(error)!r}", file=sys.stderr)
        return 1
    print("Both binary SBOMs conform to the pinned CycloneDX 1.6 schemas; no network schema retrieval was used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
