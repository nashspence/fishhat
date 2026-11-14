"""Validate mount observations for the retained disposable resource owner."""

from __future__ import annotations

import copy
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.native_smoke_loop import live, require, same_claim, token


def unescape(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    pattern = r"\\(040|011|012|134)"
    require("\\" not in re.sub(pattern, "", value), "mount-path-observation-unavailable")
    return re.sub(pattern, lambda match: escapes[match[1]], value)


def number(value: str, *, positive: bool = False) -> int:
    require(value.isascii() and value.isdecimal(), "mount-number-observation-unavailable")
    result = int(value)
    require(str(result) == value and (not positive or result > 0), "mount-number-unavailable")
    return result


@dataclass(frozen=True)
class Mount:
    identifier: int
    parent: int
    device: tuple[int, int]
    root: str
    target: str
    options: frozenset[str]
    propagation: tuple[str, ...]
    filesystem: str
    source: str
    super_options: frozenset[str]


def table(raw: str) -> dict[int, Mount]:
    """Read the complete kernel view without truncating or sorting its entries."""
    result: dict[int, Mount] = {}
    for line in raw.splitlines():
        sections = line.split(" - ")
        require(len(sections) == 2, "mount-record-unavailable")
        left, right = (section.split() for section in sections)
        require(len(left) >= 6 and len(right) == 3, "mount-record-unavailable")
        device = left[2].split(":")
        require(len(device) == 2, "mount-device-unavailable")
        identifier = number(left[0], positive=True)
        require(identifier not in result, "mount-inventory-ambiguous")
        options, super_options = left[5].split(","), right[2].split(",")
        require(
            all(options)
            and all(super_options)
            and len(set(options)) == len(options)
            and len(set(super_options)) == len(super_options),
            "mount-options-unavailable",
        )
        propagation = tuple(left[6:])
        seen: set[str] = set()
        for field in propagation:
            kind, separator, value = field.partition(":")
            require(kind not in seen, "mount-propagation-ambiguous")
            seen.add(kind)
            if kind == "unbindable":
                require(not separator, "mount-propagation-unavailable")
            else:
                require(
                    kind in {"shared", "master", "propagate_from"} and separator,
                    "mount-propagation-unavailable",
                )
                number(value, positive=True)
        root, target = unescape(left[3]), unescape(left[4])
        require(root.startswith("/") and target.startswith("/"), "mount-path-unavailable")
        result[identifier] = Mount(
            identifier,
            number(left[1]),
            (number(device[0]), number(device[1])),
            root,
            target,
            frozenset(options),
            propagation,
            right[0],
            unescape(right[1]),
            frozenset(super_options),
        )
    require(result and any(row.target == "/" for row in result.values()), "mount-view-unavailable")
    return result


def private(view: dict[int, Mount]) -> None:
    require(view and any(row.target == "/" for row in view.values()), "mount-view-unavailable")
    require(
        all(
            not field.startswith(("shared:", "master:", "propagate_from:"))
            for row in view.values()
            for field in row.propagation
        ),
        "mount-namespace-not-private",
    )


def namespace_record(value: dict[str, int]) -> dict[str, int]:
    require(set(value) == {"device", "inode"}, "mount-namespace-unavailable")
    require(
        all(type(item) is int and item >= 0 for item in value.values()) and value["inode"] > 0,
        "mount-namespace-unavailable",
    )
    return dict(value)


def directory_record(value: dict[str, int]) -> dict[str, int]:
    require(set(value) == {"device", "inode", "uid", "gid", "mode"}, "mount-root-unavailable")
    require(
        all(type(item) is int and item >= 0 for item in value.values())
        and value["inode"] > 0
        and value["uid"] == value["gid"] == 0
        and stat.S_ISDIR(value["mode"]),
        "mount-root-unavailable",
    )
    return dict(value)


def mounted(view: dict[int, Mount], target: Path, device: tuple[int, int]) -> Mount:
    private(view)
    selected = [row for row in view.values() if row.target == str(target)]
    require(len(selected) == 1, "mount-target-unavailable")
    row = selected[0]
    require(
        row.device == device
        and row.root == "/"
        and row.filesystem == "xfs"
        and {"rw", "nosuid", "nodev"} <= row.options
        and bool({"prjquota", "pquota"} & row.super_options),
        "mount-custody-mismatch",
    )
    return row


@dataclass(frozen=True)
class MountIdentity:
    """Observation identity only; its caller retains the actual resource handles."""

    enrollment: str
    namespace: dict[str, int]
    mount: Mount
    directory: dict[str, int]
    loop: dict[str, Any]
    target: Path

    @classmethod
    def capture(
        cls,
        enrollment: str,
        namespace: dict[str, int],
        view: dict[int, Mount],
        directory: dict[str, int],
        loop: dict[str, Any],
        target: Path,
        end: float,
    ) -> MountIdentity:
        live(end)
        token(enrollment)
        require(target.is_absolute(), "mount-target-unavailable")
        ns, root = namespace_record(namespace), directory_record(directory)
        rdevice = loop["association"]["node"]["rdevice"]
        require(
            type(rdevice) is int and rdevice >= 0 and os.major(rdevice) == 7,
            "mount-loop-unavailable",
        )
        device = (os.major(rdevice), os.minor(rdevice))
        require(root["device"] == os.makedev(*device), "mount-root-device-mismatch")
        require(loop["association"]["enrollment"] == enrollment, "mount-enrollment-mismatch")
        return cls(enrollment, ns, mounted(view, target, device), root, copy.deepcopy(loop), target)

    def claim(self) -> dict[str, Any]:
        return {
            "enrollment": self.enrollment,
            "namespace": dict(self.namespace),
            "mount": {
                "identifier": self.mount.identifier,
                "major": self.mount.device[0],
                "minor": self.mount.device[1],
                "target_sha256": hashlib.sha256(str(self.target).encode()).hexdigest(),
                "source_sha256": hashlib.sha256(self.mount.source.encode()).hexdigest(),
                "directory": dict(self.directory),
            },
            "loop": copy.deepcopy(self.loop),
        }

    def check(
        self,
        claim: Any,
        namespace: dict[str, int],
        view: dict[int, Mount],
        directory: dict[str, int],
        loop: dict[str, Any],
        end: float,
    ) -> None:
        live(end)
        require(same_claim(claim, self.claim()), "mount-foreign-claim-refused")
        require(same_claim(namespace_record(namespace), self.namespace), "mount-namespace-changed")
        require(same_claim(directory_record(directory), self.directory), "mount-root-changed")
        require(same_claim(loop, self.loop), "mount-loop-changed")
        require(
            mounted(view, self.target, self.mount.device) == self.mount, "mount-identity-changed"
        )

    def absent(self, namespace: dict[str, int], view: dict[int, Mount], end: float) -> bool:
        live(end)
        require(same_claim(namespace_record(namespace), self.namespace), "mount-namespace-changed")
        private(view)
        return all(
            row.identifier != self.mount.identifier
            and row.target != str(self.target)
            and row.device != self.mount.device
            for row in view.values()
        )
