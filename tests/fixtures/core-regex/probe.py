"""Dependency-free Python and ECMAScript-u checks against fixed expected vectors.

Run from any directory with ``python tests/fixtures/core-regex/probe.py``.
Node must be explicitly available for this standalone conformance probe; failure
to start either engine is an error. This is not a full JSON Schema validator and
is not a prerequisite of the maintained Python test suite.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCHEMA = ROOT / "packages/fishhat-contracts/src/fishhat_contracts/contracts/common.schema.json"


def accepts(schema, value):
    return (
        schema["minLength"] <= len(value) <= schema["maxLength"]
        and re.search(schema["pattern"], value) is not None
        and ("not" not in schema or re.search(schema["not"]["pattern"], value) is None)
    )


def main():
    definitions = json.loads(SCHEMA.read_text())["$defs"]
    vectors = json.loads((HERE / "expected.json").read_text())
    for vector in vectors:
        actual = accepts(definitions[vector["definition"]], vector["value"])
        if actual != vector["valid"]:
            raise AssertionError(("Python", vector["id"], actual, vector["valid"]))
    print(f"Python: {len(vectors)} explicit expected vectors passed", flush=True)
    subprocess.run(["node", str(HERE / "probe.mjs")], check=True)


if __name__ == "__main__":
    main()
