"""Complete scaffold checksum verification with measured filename-work bounds."""

import json
import random
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import bundle_install
from tests.test_bundle_install import bundle_fixture, seal

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/bundle_install.py"],
    "scope": "standalone scaffold checksum ordering and complete synthetic bundle verification",
    "relationship": "no-product-claim",
    "reason": "Fixed semantic cases preserve checksum ordering; increasing real bundle extents count actual filename encoding/comparison work and reject a changed final artifact. No timing target or native installation claim.",
    "claims": [],
}


@pytest.mark.parametrize(
    "names",
    [
        pytest.param([], id="empty"),
        pytest.param(["b", "aa", "a", "ab"], id="prefix-terminals"),
        pytest.param(
            ["\uffff", "\U00010000", "β", "é", "e\u0301", "\udc80", "line\nx"],
            id="unicode-and-filesystem-surrogates",
        ),
        pytest.param(
            ["a" * 256 + "z", "a" * 256, "a" * 256 + "aa", "a" * 256 + "b"],
            id="shared-prefixes",
        ),
    ],
)
def test_standalone_filename_order_preserves_canonical_checksum_order(names):
    assert bundle_install._ordered_names(iter(names)) == sorted(names)


def test_complete_bundle_filename_work_is_linear(tmp_path, monkeypatch):
    work = [0]

    class MeasuredName(str):
        __hash__ = str.__hash__

        def _compare(self, other):
            if isinstance(other, str):
                work[0] += 1
                for left, right in zip(str.__iter__(self), str.__iter__(other), strict=False):
                    work[0] += 1
                    if left != right:
                        break

        def __eq__(self, other):
            self._compare(other)
            return str.__eq__(self, other)

        def __lt__(self, other):
            self._compare(other)
            return str.__lt__(self, other)

        def encode(self, encoding="utf-8", errors="strict"):
            result = str.encode(self, encoding, errors)
            work[0] += len(result)
            return result

    def measured_loads(data):
        result = json.loads(data)
        result["files"] = {MeasuredName(name): value for name, value in result["files"].items()}
        return result

    samples = []
    for count in (64, 256, 1024):
        with tempfile.TemporaryDirectory(dir=tmp_path) as directory:
            bundle = Path(directory)
            expected = bundle_fixture(bundle)
            manifest = bundle_install.verify(bundle, expected)
            indices = list(range(count))
            random.Random(17).shuffle(indices)
            for index in indices:
                name = "wheels/" + "shared-name-prefix-" * 4 + f"{index:08d}.whl"
                path = bundle / name
                path.write_bytes(b"public synthetic artifact")
                manifest["files"][name] = {
                    "size": path.stat().st_size,
                    "sha256": bundle_install.sha256(path),
                }
            final = bundle / "wheels/zz-final-artifact.whl"
            final.write_bytes(b"complete inventory canary")
            manifest["files"][final.relative_to(bundle).as_posix()] = {
                "size": final.stat().st_size,
                "sha256": bundle_install.sha256(final),
            }
            expected = seal(bundle, manifest)
            logical_bytes = sum(len(name.encode("utf-8")) for name in manifest["files"])
            work[0] = 0
            with monkeypatch.context() as patch:
                patch.setattr(bundle_install, "json", SimpleNamespace(loads=measured_loads))
                verified = bundle_install.verify(bundle, expected)
            observed = work[0]
            assert len(verified["files"]) == count + 3
            assert observed >= logical_bytes > 0
            samples.append({"files": count + 3, "filename_bytes": logical_bytes, "work": observed})
            final.write_bytes(b"changed final artifact")
            with pytest.raises(ValueError, match="artifact changed"):
                bundle_install.verify(bundle, expected)

    (tmp_path / "filename-work.json").write_text(json.dumps(samples, indent=2) + "\n")
    baseline = samples[0]
    for sample in samples[1:]:
        assert sample["work"] * baseline["filename_bytes"] <= (
            1.05 * baseline["work"] * sample["filename_bytes"]
        ), ("non-linear bundle filename work", samples)
