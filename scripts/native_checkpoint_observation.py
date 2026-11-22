"""Validate original installed-checkpoint observations without executing payloads."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import re
from pathlib import PurePosixPath
from typing import Any

from scripts import native_linux_owner_entrypoint as execution
from scripts.native_linux_owner_checkpoint import CASES, SCOPE, require

_HEX = r'"(?:\\x[0-9a-f]{2})*"'
_OPEN = re.compile(
    rf"^openat\((AT_FDCWD|[0-9]+), ({_HEX}), ([A-Z0-9_|]+)(?:, ([0-7]+))?\)\s+=\s+([0-9]+)$"
)
_IO = re.compile(rf"^(read|write)\(([0-9]+), ({_HEX}), ([0-9]+)\)\s+=\s+([0-9]+)$")
_CHANGE = re.compile(
    rf"^(linkat|renameat)\(([0-9]+), ({_HEX}), ([0-9]+), ({_HEX})(?:, 0)?\)\s+=\s+0$"
)
_UNLINK = re.compile(rf"^unlinkat\(([0-9]+), ({_HEX}), 0\)\s+=\s+0$")


def _shape(value: Any, fields: str, reason: str) -> None:
    require(isinstance(value, dict) and set(value) == set(fields.split()), reason)


def _bytes(text: str) -> bytes:
    values = execution._literal_values(text)
    require(len(values) == 1, "ambiguous-byte-string")
    return values[0]


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode()


def _record(snapshot: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    require(
        set(snapshot) == {"directory", "entries", "original_files_base64"}, "record-snapshot-shape"
    )
    require(
        set(snapshot["entries"]) == set(snapshot["original_files_base64"]) == {"anchor", "current"},
        "record-namespace-changed",
    )
    execution._file_metadata(snapshot["directory"], {"kind": "directory", "mode": 0o700})
    require(snapshot["directory"].get("file_capability") is None, "record-directory-capability")
    value: dict[str, Any] = {}
    for name in ("anchor", "current"):
        row = snapshot["entries"][name]
        execution._file_metadata(row, {"kind": "regular", "mode": 0o600})
        raw = base64.b64decode(snapshot["original_files_base64"][name], validate=True)
        require(
            len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
            "record-original-changed",
        )
        if name == "anchor":
            require(raw == b"", "anchor-not-empty")
        else:
            decoded = json.loads(raw)
            require(isinstance(decoded, dict), "record-not-object")
            assert isinstance(decoded, dict)
            value = decoded
            require(raw == _canonical(value), "record-not-canonical")
    anchor = snapshot["entries"]["anchor"]
    require(
        set(value) == {"format", "owner", "journal_id", "anchor", "previous", "current"},
        "record-format-changed",
    )
    require(
        value["format"] == "fishhat.checkpoint-store/v1"
        and value["owner"] == context["owner"]
        and value["journal_id"] == context["journal_id"],
        "record-binding-changed",
    )
    require(
        value["anchor"] == {"device": anchor["device"], "inode": anchor["inode"]}
        and all(type(v) is int for v in value["anchor"].values()),
        "record-anchor-changed",
    )
    for name in ("previous", "current"):
        require(
            value[name] is None
            or (
                isinstance(value[name], str)
                and re.fullmatch(r"[0-9a-f]{64}", value[name]) is not None
            ),
            "record-head-changed",
        )
    require(value["current"] is not None or value["previous"] is None, "record-history-changed")
    return value


def _inventory(actual: dict[str, Any], expected: dict[str, Any]) -> None:
    require(set(actual) == set(expected), "installed-extent-changed")
    identities = set()
    for name, wanted in expected.items():
        require(
            name == "."
            or (not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts),
            "installed-path-escape",
        )
        identity = execution._file_metadata(actual[name], wanted)
        require(identity not in identities, "installed-hardlink-alias")
        identities.add(identity)


def _origin(value: dict[str, Any], c: dict[str, Any], role: str) -> None:
    _shape(
        value,
        "pid parent_pid uids gids groups executable proc_executable cwd capabilities start_ticks version isolated no_site no_bytecode sys_path module context_sha256 enrollment boot_id",
        "process-origin-shape",
    )
    context = c["inputs"]["context"]
    prefix = str(PurePosixPath(context["library"]).parent.parent)
    runtime = prefix + "/runtime/python"
    uid, gid = (
        (0, 0) if role == "root" else (c["accounts"][role]["uid"], c["accounts"][role]["gid"])
    )
    require(
        type(value["pid"]) is int
        and value["pid"] > 1
        and type(value["parent_pid"]) is int
        and value["parent_pid"] > 0,
        "invalid-process-origin",
    )
    require(
        value["uids"] == [uid] * 3 and value["gids"] == [gid] * 3, "execution-principal-changed"
    )
    require(
        value["groups"] == sorted(set(value["groups"])) and gid in value["groups"],
        "execution-groups-changed",
    )
    require(
        value["executable"] == value["proc_executable"] == runtime + "/bin/python3.12",
        "execution-runtime-changed",
    )
    require(
        value["cwd"] == "/" and (uid == 0 or int(value["capabilities"], 16) == 0),
        "execution-context-changed",
    )
    require(
        value["isolated"] == value["no_site"] == value["no_bytecode"] == 1
        and value["version"][:2] == [3, 12]
        and len(value["version"]) == 3,
        "execution-isolation-changed",
    )
    require(
        value["sys_path"]
        == [
            context["library"],
            runtime + "/lib/python312.zip",
            runtime + "/lib/python3.12",
            runtime + "/lib/python3.12/lib-dynload",
        ],
        "execution-search-path-changed",
    )
    expected_module = c["inputs"]["expected_wheels"]["lib/fishhat_owner/checkpoint_store.py"]
    require(
        value["module"]
        == {
            "path": context["library"] + "/fishhat_owner/checkpoint_store.py",
            "sha256": expected_module["sha256"],
        },
        "backend-payload-changed",
    )
    require(
        value["context_sha256"] == c["inputs"]["programs"]["context.json"]["sha256"]
        and value["enrollment"] == c["enrollment"]
        and value["boot_id"] == c["boot_id"],
        "execution-custody-changed",
    )
    require(
        isinstance(value["start_ticks"], str) and value["start_ticks"].isdigit(),
        "process-start-missing",
    )


def _owned_path(path: str | None, authority: str) -> bool:
    return path is not None and (path == authority or path.startswith(authority + "/"))


def _descriptor_change(line: str, descriptors: dict[int, str]) -> bool:
    match = re.fullmatch(r"close\(([0-9]+)\)\s+=\s+0", line)
    if match:
        descriptors.pop(int(match[1]), None)
        return True
    match = re.fullmatch(
        r"(?:dup\(([0-9]+)\)|fcntl\(([0-9]+), F_DUPFD_CLOEXEC, [0-9]+\))\s+=\s+([0-9]+)", line
    )
    if match:
        old = int(match[1] or match[2])
        if old in descriptors:
            descriptors[int(match[3])] = descriptors[old]
        return True
    return False


def trace_events(raw: str, authority: str) -> dict[str, Any]:
    """Decode complete checkpoint file operations from one original trace."""
    descriptors: dict[int, str] = {0: "<stdin>", 1: "<stdout>", 2: "<stderr>"}
    events: list[dict[str, Any]] = []
    opened: list[str] = []
    stdout = bytearray()

    def relative(directory: str, name: str) -> str:
        if name.startswith("/"):
            return posixpath.normpath(name)
        parent = "/" if directory == "AT_FDCWD" else descriptors.get(int(directory))
        require(parent is not None, "unknown-relative-directory")
        assert parent is not None
        return posixpath.normpath(str(PurePosixPath(parent) / name))

    path: str | None
    for number, line in enumerate(raw.splitlines()):
        match = _OPEN.fullmatch(line)
        if match:
            directory, name, flags, mode, result = match.groups()
            path = relative(directory, os.fsdecode(_bytes(name)))
            descriptors[int(result)] = path
            opened.append(path)
            if _owned_path(path, authority):
                require(
                    "O_NOFOLLOW" in flags and "O_CLOEXEC" in flags, "unprotected-checkpoint-open"
                )
                events.append(
                    {
                        "kind": "open",
                        "path": path,
                        "flags": flags,
                        "mode": mode,
                        "index": number,
                        "fd": int(result),
                    }
                )
            continue
        if _descriptor_change(line, descriptors):
            continue
        match = _IO.fullmatch(line)
        if match:
            kind, descriptor, data, requested, count = match.groups()
            path = descriptors.get(int(descriptor))
            if path == "<stdout>" or _owned_path(path, authority):
                payload = _bytes(data)
                require(
                    (len(payload) == int(requested) and int(count) <= len(payload))
                    if kind == "write"
                    else (len(payload) == int(count) and int(count) <= int(requested)),
                    "truncated-checkpoint-io",
                )
                payload = payload[: int(count)]
                if kind == "write" and path == "<stdout>":
                    stdout.extend(payload)
                    events.append({"kind": "reply", "path": path, "data": payload, "index": number})
                elif path != "<stdout>":
                    events.append({"kind": kind, "path": path, "data": payload, "index": number})
            continue
        match = re.fullmatch(
            r"fsync\(([0-9]+)\)\s+=\s+(0|-1 EIO \(Input/output error\) \(INJECTED\))", line
        )
        if match:
            path = descriptors.get(int(match[1]))
            if _owned_path(path, authority):
                events.append(
                    {"kind": "sync", "path": path, "success": match[2] == "0", "index": number}
                )
            continue
        match = _CHANGE.fullmatch(line)
        if match:
            kind, source_fd, source, target_fd, target = match.groups()
            source_path = relative(source_fd, os.fsdecode(_bytes(source)))
            target_path = relative(target_fd, os.fsdecode(_bytes(target)))
            if source_path.startswith(authority + "/") or target_path.startswith(authority + "/"):
                events.append(
                    {"kind": kind, "source": source_path, "target": target_path, "index": number}
                )
            continue
        match = _UNLINK.fullmatch(line)
        if match:
            path = relative(match[1], os.fsdecode(_bytes(match[2])))
            if path.startswith(authority + "/"):
                events.append({"kind": "unlink", "path": path, "index": number})
            continue
        match = re.fullmatch(
            r"flock\(([0-9]+), (LOCK_(?:SH|EX)\|LOCK_NB|LOCK_UN)\)\s+=\s+(0|-1 EAGAIN \(Resource temporarily unavailable\))",
            line,
        )
        if match:
            path = descriptors.get(int(match[1]))
            if path == authority + "/anchor":
                events.append(
                    {
                        "kind": "lock",
                        "path": path,
                        "flags": match[2],
                        "success": match[3] == "0",
                        "index": number,
                    }
                )
    return {"events": events, "opened": opened, "stdout": bytes(stdout)}


def _current_reads(events: list[dict[str, Any]], authority: str) -> list[bytes]:
    values: list[bytes] = []
    current = bytearray()
    for row in events:
        if row["kind"] != "read" or row["path"] != authority + "/current":
            continue
        if row["data"]:
            current.extend(row["data"])
        else:
            values.append(bytes(current))
            current.clear()
    require(not current, "current-read-not-complete")
    return values


def _publication(
    events: list[dict[str, Any]],
    authority: str,
    value: dict[str, Any],
    *,
    initialize: bool = False,
    uncertain: bool = False,
    interrupted: bool = False,
    unacknowledged: bool = False,
) -> None:
    pending, current = authority + "/.pending", authority + "/current"
    writes = [row for row in events if row["kind"] == "write" and row["path"] == pending]
    require(
        bool(writes) and b"".join(row["data"] for row in writes) == _canonical(value),
        "incomplete-authoritative-write",
    )
    synced = [
        row for row in events if row["kind"] == "sync" and row["path"] == pending and row["success"]
    ]
    require(len(synced) == 1 and writes[-1]["index"] < synced[0]["index"], "pending-sync-missing")
    changes = [row for row in events if row["kind"] in ("linkat", "renameat")]
    locks = [
        row
        for row in events
        if row["kind"] == "lock" and row["flags"] == "LOCK_EX|LOCK_NB" and row["success"]
    ]
    require(
        len(locks) == 1 and locks[0]["index"] < writes[0]["index"], "publication-not-serialized"
    )
    if interrupted:
        require(
            not changes and not any(row["kind"] == "reply" for row in events),
            "interruption-after-replacement",
        )
        require(
            not any(
                row["kind"] == "lock"
                and row["flags"] == "LOCK_UN"
                and locks[0]["index"] < row["index"] < synced[0]["index"]
                for row in events
            ),
            "lock-released-before-pending-sync",
        )
        return
    require(
        len(changes) == 1
        and changes[0]["kind"] == ("linkat" if initialize else "renameat")
        and changes[0]["source"] == pending
        and changes[0]["target"] == current
        and synced[0]["index"] < changes[0]["index"],
        "publication-order-changed",
    )
    directory_syncs = [row for row in events if row["kind"] == "sync" and row["path"] == authority]
    require(
        len(directory_syncs) == 1
        and directory_syncs[0]["success"] is not uncertain
        and changes[0]["index"] < directory_syncs[0]["index"],
        "directory-publication-unconfirmed",
    )
    require(
        not any(
            row["kind"] == "lock"
            and row["flags"] == "LOCK_UN"
            and locks[0]["index"] < row["index"] < directory_syncs[0]["index"]
            for row in events
        ),
        "lock-released-before-publication",
    )
    replies = [row for row in events if row["kind"] == "reply"]
    require(
        not replies
        if unacknowledged
        else bool(replies) and directory_syncs[0]["index"] < replies[0]["index"],
        "reply-before-publication",
    )
    if initialize:
        anchor_syncs = [
            row
            for row in events
            if row["kind"] == "sync" and row["path"] == authority + "/anchor" and row["success"]
        ]
        removed = [row for row in events if row["kind"] == "unlink" and row["path"] == pending]
        require(
            len(anchor_syncs) == len(removed) == 1
            and anchor_syncs[0]["index"] < writes[0]["index"]
            and changes[0]["index"] < removed[0]["index"] < directory_syncs[0]["index"],
            "genesis-publication-order-changed",
        )


def _live(value: dict[str, Any], c: dict[str, Any], label: str) -> dict[str, Any]:
    if "marker_original_base64" in value:
        raw = base64.b64decode(value["marker_original_base64"], validate=True)
        marker = json.loads(raw)
        _shape(marker, "origin action case label descriptors", "live-marker-shape")
        assert isinstance(marker, dict)
        row = value["marker_metadata"]
        require(
            len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
            "live-marker-changed",
        )
        execution._file_metadata(row, {"kind": "regular", "mode": 0o600})
        require(
            marker["label"] == label
            and value["marker_path"] == c["inputs"]["context"]["control"] + "/" + label,
            "live-marker-context-changed",
        )
        _origin(marker["origin"], c, "root")
        observed = value["process"]
        require(
            marker["origin"]["pid"] == observed["pid"]
            and marker["origin"]["start_ticks"] == observed["start_ticks"],
            "live-process-substituted",
        )
        return marker
    require(
        "SIGSTOP" in value["trace_before_original"] and value["process"]["state"] in ("T", "t"),
        "live-stop-not-observed",
    )
    return {}


def selection(c: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The closed workload, including each original success/refusal selection."""
    rows: dict[str, dict[str, Any]] = {}

    def add(
        action: str,
        case: str,
        label: str,
        *,
        role: str = "root",
        outcome: str = "success",
        inject: str | None = None,
        **options: Any,
    ) -> None:
        require(label not in rows, "duplicate-workload-label")
        rows[label] = {
            "request": {"action": action, "case": case, "label": label, **options},
            "role": role,
            "outcome": outcome,
            "inject": inject,
        }

    def deny(action: str, case: str, label: str, **options: Any) -> None:
        add(action, case, label, outcome="refusal", **options)

    a, b = c["heads"]
    add("initialize", "valid", "initialize-valid")
    add("inspect", "valid", "inspect-valid")
    add("deny-modification", "valid", "peer-modification-denied", role=c["peer_account"])
    deny("initialize", "valid", "refuse-existing")
    deny("inspect", "missing", "refuse-missing")
    for binding in ("owner", "epoch", "journal"):
        deny("inspect", "valid", "refuse-" + binding, binding=binding)
    deny("inspect", "valid", "refuse-same-domain", capture="same-domain")
    for role in (c["admin_account"], c["peer_account"]):
        deny("inspect", "valid", "refuse-" + role + "-inspect", role=role)
        deny("initialize", "valid", "refuse-" + role + "-initialize", role=role)
    add("publish", "valid", "publish-first", expected=None, current=a)
    deny("publish", "valid", "refuse-stale", expected=None, current=b)
    add("publish", "valid", "publish-second", expected=a, current=b)
    add("publish", "valid", "publish-idempotent", expected=b, current=b)
    add("initialize", "contested", "initialize-contested")
    add("held-publish", "contested", "holder", expected=None, current=a)
    deny("inspect", "contested", "copy-lock-refused", journal_index=1)
    deny("publish", "contested", "copy-stale-refused", journal_index=1, expected=None, current=b)
    add("inspect", "contested", "copy-inspect", journal_index=1)
    add("initialize", "aliases", "initialize-aliases")
    add("alias-parent", "aliases", "alias-holder")
    deny("inspect", "aliases", "inherited-lock-refused")
    deny("inspect", "aliases", "duplicate-lock-refused")
    add("inspect", "aliases", "aliases-final")
    for case in ("replaced", "unlinked"):
        add("initialize", case, "initialize-" + case)
        add("held-publish", case, "hold-" + case, outcome="refusal", expected=None, current=a)
        deny("inspect", case, case + "-new-holder-refused")
        deny("inspect", case, case + "-after-holder-refused")
    add(
        "initialize",
        "initializing",
        "incomplete-initialize",
        outcome="killed",
        inject="--inject=fsync:signal=SIGSTOP:when=1",
    )
    deny("inspect", "initializing", "incomplete-open-refused")
    deny("initialize", "initializing", "incomplete-reset-refused")
    add("initialize", "fresh", "fresh-initialize")
    add("initialize", "interrupted", "initialize-interrupted")
    add("publish", "interrupted", "interrupted-baseline", expected=None, current=a)
    add(
        "publish",
        "interrupted",
        "pending-publication",
        outcome="killed",
        inject="--inject=renameat:signal=SIGSTOP:when=1",
        expected=a,
        current=b,
    )
    deny("inspect", "interrupted", "pending-open-refused")
    deny("initialize", "interrupted", "pending-reset-refused")
    add("initialize", "lost", "initialize-lost")
    add("lost-reply", "lost", "lost-before-reply", outcome="killed", expected=None, current=a)
    add("inspect", "lost", "lost-reply-inspect")
    deny("publish", "lost", "lost-reply-stale", expected=None, current=a)
    add("initialize", "uncertain", "initialize-uncertain")
    add(
        "uncertain-publish",
        "uncertain",
        "uncertain-publication",
        outcome="uncertain",
        inject="--inject=fsync:error=EIO:when=2",
        expected=None,
        current=a,
    )
    add("inspect", "uncertain", "uncertain-inspect")
    deny("publish", "uncertain", "uncertain-stale", expected=None, current=a)
    for case in (
        "malformed",
        "file-mode",
        "directory-mode",
        "file-owner",
        "directory-owner",
        "hardlink",
        "capability",
        "pending",
    ):
        add("initialize", case, "initialize-" + case)
        deny("inspect", case, "foreign-" + case)
    return rows


def _live_invocation(live: dict[str, Any], row: dict[str, Any], c: dict[str, Any]) -> None:
    observed = live["process"]
    pid = observed["pid"]
    original = [item for item in row["trace_originals"] if item["pid"] == pid]
    require(len(original) == 1, "live-process-not-traced")
    starts = [line for line in original[0]["original"].splitlines() if line.startswith("execve(")]
    require(len(starts) == 1, "live-execution-missing")
    executable, arguments, environment = execution._execution(starts[0])
    require(
        observed["executable"] == os.fsdecode(executable)
        and observed["executable_sha256"] == c["inputs"]["runtime_executable_sha256"],
        "live-runtime-changed",
    )
    require(
        bytes.fromhex(observed["cmdline_hex"]) == b"\0".join(arguments) + b"\0",
        "live-arguments-changed",
    )
    wanted_environment = (
        b"\0".join(key + b"=" + value for key, value in environment.items()) + b"\0"
    )
    require(
        observed["environment_sha256"] == hashlib.sha256(wanted_environment).hexdigest(),
        "live-environment-changed",
    )
    require(
        observed["process_group"] == observed["session"] == row["tracer_pid"],
        "live-session-unbound",
    )
    require(
        observed["parent_pid"]
        in {1, row["tracer_pid"], *(item["pid"] for item in row["trace_originals"])},
        "live-parent-unbound",
    )
    status = observed["status"]
    require(
        [int(item) for item in status["Uid"].split()] == [0] * 4
        and [int(item) for item in status["Gid"].split()] == [0] * 4,
        "live-principal-changed",
    )
    require(
        re.fullmatch(r"[0-9a-f]{16}", status["CapEff"]) is not None, "live-capabilities-missing"
    )
    if "marker_original_base64" in live:
        marker = json.loads(base64.b64decode(live["marker_original_base64"], validate=True))
        require(
            int(status["CapEff"], 16) == int(marker["origin"]["capabilities"], 16)
            and [int(item) for item in status["Groups"].split()] == marker["origin"]["groups"],
            "live-marker-principal-changed",
        )
    else:
        require(
            original[0]["original"].startswith(live["trace_before_original"])
            and "SIGSTOP" in live["trace_before_original"]
            and observed["state"] in ("T", "t"),
            "live-stopped-trace-unbound",
        )


def _live_processes(value: dict[str, Any], records: dict[str, Any], c: dict[str, Any]) -> None:
    for live, label in (
        (value["competition"]["live"], "holder"),
        (value["aliases"]["parent_live"], "alias-holder"),
        (value["aliases"]["inherited_live"], "alias-holder"),
        (value["aliases"]["single_alias_live"], "alias-holder"),
        (value["incomplete_genesis"]["live"], "incomplete-initialize"),
        (value["interruption"]["live"], "pending-publication"),
        (value["lost_reply"]["live"], "lost-before-reply"),
        *((item["live"], "hold-" + item["case"]) for item in value["anchor_substitutions"]),
    ):
        _live_invocation(live, records[label][0], c)


def _modification_refusals(
    row: dict[str, Any], reply: dict[str, Any], context: dict[str, Any]
) -> None:
    prefix = str(PurePosixPath(context["library"]).parent.parent)
    paths = [
        context["library"] + "/fishhat_owner/checkpoint_store.py",
        prefix + "/runtime/python/bin/python3.12",
        prefix + "/probe.py",
        prefix + "/context.json",
        context["cases"]["valid"] + "/anchor",
        context["cases"]["valid"] + "/current",
        context["journals"][0] + "/HEAD",
    ]
    expected = {(path, operation) for path in paths for operation in ("open-write", "chmod")}
    denials = reply["details"]["denied_modifications"]
    require(
        len(denials) == len(expected)
        and {(item["path"], item["operation"]) for item in denials} == expected
        and all(item["errno"] in (1, 13) for item in denials),
        "modification-refusals-incomplete",
    )
    require(reply["record"] is reply["error"] is None, "modification-refusal-reply-changed")
    actual = set()
    for line in row["trace_originals"][0]["original"].splitlines():
        match = re.fullmatch(
            rf"openat\(AT_FDCWD, ({_HEX}), O_WRONLY\|O_NOFOLLOW\|O_CLOEXEC\)\s+=\s+-1 (?:EACCES \(Permission denied\)|EPERM \(Operation not permitted\))",
            line,
        )
        if match:
            actual.add((os.fsdecode(_bytes(match[1])), "open-write"))
        match = re.fullmatch(
            rf"chmod\(({_HEX}), 0600\)\s+=\s+-1 (?:EACCES \(Permission denied\)|EPERM \(Operation not permitted\))",
            line,
        )
        if match:
            actual.add((os.fsdecode(_bytes(match[1])), "chmod"))
    require(actual == expected, "modification-refusal-not-observed")


def verify_observation(value: dict[str, Any], c: dict[str, Any]) -> None:
    _shape(
        value,
        "scope status enrollment boot_id observer_pid observer_uid input_sha256 bootstrap_sha256 primary_error cleanup_errors invocations owned_children cleanup native_product_qualified writer_authority_qualified storage_before transfer observer_packages journals_before capture_domains installed_before program_before refusals initializations genesis_before genesis_after normal_publication competition aliases anchor_substitutions incomplete_genesis interruption lost_reply uncertainty journals_after installed_after program_after storage_after",
        "observation-shape",
    )
    context = c["inputs"]["context"]
    require(
        value["scope"] == SCOPE
        and value["status"] == "passed"
        and value["native_product_qualified"] is value["writer_authority_qualified"] is False,
        "scope-changed",
    )
    require(
        value["enrollment"] == c["enrollment"]
        and value["boot_id"] == c["boot_id"]
        and type(value["observer_pid"]) is int
        and value["observer_pid"] > 1
        and value["observer_uid"] == 0,
        "observer-context-changed",
    )
    require(
        value["primary_error"] is None and value["cleanup_errors"] == [], "incomplete-observation"
    )
    require(
        value["input_sha256"] == c["input_sha256"]
        and value["bootstrap_sha256"] == c["bootstrap_sha256"],
        "changed-source-inputs",
    )
    for key, expected in (
        ("runtime", c["inputs"]["expected_runtime"]),
        ("packages", c["inputs"]["expected_wheels"]),
        ("observer", c["inputs"]["expected_observer"]),
    ):
        _inventory(value["installed_before"][key], expected)
    require(
        value["installed_before"] == value["installed_after"]
        and set(value["installed_before"]) == {"runtime", "packages", "observer"},
        "installed-custody-changed",
    )
    _inventory(value["program_before"], c["inputs"]["programs"])
    require(value["program_before"] == value["program_after"], "program-custody-changed")
    require(
        value["storage_before"] == value["storage_after"]
        and value["storage_before"]["directory"] == c["storage"]["control"]["directory"],
        "storage-custody-changed",
    )
    require(
        value["journals_before"] == value["journals_after"] and len(value["journals_before"]) == 2,
        "journal-copy-custody-changed",
    )
    copies = value["journals_before"]
    require(
        copies[0]["original_files_base64"] == copies[1]["original_files_base64"]
        and set(copies[0]["entries"]) == set(copies[1]["entries"]) == {"HEAD"},
        "journal-copy-bytes-changed",
    )
    require(
        copies[0]["entries"]["HEAD"]["inode"] != copies[1]["entries"]["HEAD"]["inode"],
        "journal-copy-inode-reused",
    )
    domains = value["capture_domains"]
    authority_device = domains["authority"]["directory"]["device"]
    journal_device = domains["journal"]["directory"]["device"]
    require(
        authority_device == domains["guest_root"]["device"]
        and authority_device != journal_device == c["storage"]["control"]["directory"]["device"],
        "capture-domain-not-independent",
    )
    for name in ("authority", "journal"):
        mounts = domains[name]["mount"]["filesystems"]
        require(
            len(mounts) == 1
            and json.loads(domains[name]["mount"]["stdout"])["filesystems"] == mounts,
            "mount-original-changed",
        )
        major, minor = (int(part) for part in mounts[0]["maj:min"].split(":"))
        require(
            os.makedev(major, minor) == domains[name]["directory"]["device"],
            "mount-device-mismatch",
        )
    require(
        domains["authority"]["mount"]["filesystems"][0]["target"] == "/"
        and domains["journal"]["mount"]["filesystems"][0]["uuid"]
        == c["storage"]["control"]["uuid"],
        "mount-capture-context-changed",
    )
    require(
        domains["authority"]["mount"]["filesystems"][0]["uuid"]
        != domains["journal"]["mount"]["filesystems"][0]["uuid"],
        "filesystem-identity-reused",
    )
    initial = {row["case"]: row for row in value["initializations"]}
    require(
        len(initial) == len(value["initializations"])
        and set(initial) == set(CASES) - {"missing", "initializing"},
        "genesis-extent-missing",
    )
    anchors = {}
    for case, row in initial.items():
        require(
            row["before"]["entries"] == row["before"]["original_files_base64"] == {},
            "genesis-adopted-existing-custody",
        )
        record = _record(row["after"], context)
        require(record["previous"] is record["current"] is None, "genesis-head-not-empty")
        anchors[case] = record["anchor"]
    selected = selection(c)
    records = {}
    all_pids: set[int] = set()
    traces = {}
    for row in value["invocations"]:
        _shape(
            row,
            "label request arguments observer_argv observer_environment environment role tracer_pid tracer_joined trace_originals returncode stdout stderr elapsed_seconds",
            "invocation-shape",
        )
        label = row["label"]
        require(
            label not in records and row["role"] in ("root", c["admin_account"], c["peer_account"]),
            "invocation-identity-reused",
        )
        require(
            row["tracer_joined"] is True
            and type(row["tracer_pid"]) is int
            and row["tracer_pid"] > 1
            and row["stderr"] == ""
            and type(row["elapsed_seconds"]) in (int, float)
            and row["elapsed_seconds"] >= 0,
            "invocation-not-settled",
        )
        wanted = selected[label]
        request = row["request"]
        require(
            request == wanted["request"] and row["role"] == wanted["role"],
            "workload-selection-changed",
        )
        context_prefix = str(PurePosixPath(context["library"]).parent.parent)
        expected_arguments = [
            context_prefix + "/runtime/python/bin/python3.12",
            "-I",
            "-S",
            "-B",
            context_prefix + "/probe.py",
            json.dumps(request, sort_keys=True),
        ]
        expected_observer = [
            context_prefix + "/observer/usr/bin/strace",
            "-ff",
            "--kill-on-exit",
            "-s",
            str(c["string_limit"]),
            "-xx",
            "-v",
            "-q",
            "-e",
            c["trace_filter"],
            "-o",
            context_prefix + "/traces/" + label,
            "-u",
            wanted["role"],
            "-E",
            "LD_LIBRARY_PATH",
        ]
        if wanted["inject"] is not None:
            expected_observer.append(wanted["inject"])
        require(
            row["arguments"] == expected_arguments
            and row["observer_argv"] == expected_observer + expected_arguments,
            "observer-command-changed",
        )
        clean = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        require(
            row["environment"] == clean
            and row["observer_environment"]
            == clean | {"LD_LIBRARY_PATH": context_prefix + "/observer/usr/lib/x86_64-linux-gnu"},
            "observer-environment-changed",
        )
        require(request["case"] in CASES and request["label"] == label, "request-context-changed")
        decoded = []
        output = bytearray()
        for original in row["trace_originals"]:
            _shape(original, "pid metadata original process_absent", "trace-original-shape")
            pid = original["pid"]
            require(
                type(pid) is int
                and pid > 1
                and pid not in all_pids
                and original["process_absent"] is True,
                "trace-process-reused",
            )
            all_pids.add(pid)
            raw = original["original"]
            execution._file_metadata(original["metadata"], {"kind": "regular", "mode": 0o600})
            require(
                hashlib.sha256(raw.encode()).hexdigest() == original["metadata"]["sha256"]
                and len(raw.encode()) == original["metadata"]["bytes"],
                "trace-original-changed",
            )
            starts = [line for line in raw.splitlines() if line.startswith("execve(")]
            require(len(starts) == 1, "selected-execution-missing")
            binary, arguments, environment = execution._execution(starts[0])
            require(
                binary == os.fsencode(row["arguments"][0])
                and arguments[:5] == [os.fsencode(x) for x in row["arguments"][:5]],
                "trace-command-changed",
            )
            require(
                environment
                == {b"PATH": b"/usr/bin:/bin", b"LANG": b"C.UTF-8", b"LC_ALL": b"C.UTF-8"},
                "trace-environment-changed",
            )
            actual_request = json.loads(arguments[5])
            if actual_request.get("action") == "alias-holder":
                require(
                    request["action"] == "alias-parent"
                    and actual_request
                    == request
                    | {"action": "alias-holder", "descriptor": actual_request["descriptor"]}
                    and type(actual_request["descriptor"]) is int,
                    "unbound-inherited-descriptor",
                )
            else:
                require(
                    actual_request == request
                    and arguments == [os.fsencode(x) for x in row["arguments"]],
                    "trace-request-changed",
                )
            parsed = trace_events(raw, context["cases"][request["case"]])
            require(
                context["library"] + "/fishhat_owner/checkpoint_store.py" in parsed["opened"],
                "installed-backend-not-opened",
            )
            output.extend(parsed["stdout"])
            decoded.extend(parsed["events"])
        require(bytes(output) == row["stdout"].encode(), "reply-not-bound-to-trace")
        require(
            len(row["trace_originals"]) == (2 if request["action"] == "alias-parent" else 1),
            "untracked-descendant",
        )
        if row["stdout"]:
            require(row["returncode"] == 0, "successful-reply-exit-changed")
            reply = json.loads(row["stdout"])
            _shape(
                reply,
                "origin action label case journal_index capture binding record error details",
                "reply-shape",
            )
            _origin(reply["origin"], c, row["role"])
            require(
                reply["origin"]["pid"] in {item["pid"] for item in row["trace_originals"]},
                "reply-process-unbound",
            )
            require(
                reply["case"] == request["case"]
                and reply["label"] == label
                and reply["action"]
                == ("alias-holder" if request["action"] == "alias-parent" else request["action"]),
                "reply-context-changed",
            )
            require(
                reply["binding"] == request.get("binding", "correct")
                and reply["capture"] == request.get("capture", "control")
                and reply["journal_index"] == request.get("journal_index", 0),
                "reply-binding-changed",
            )
            require(
                (reply["error"] is None) == (wanted["outcome"] == "success")
                and wanted["outcome"] != "killed",
                "reply-outcome-changed",
            )
        else:
            require(
                wanted["outcome"] == "killed" and row["returncode"] == -9,
                "unexplained-missing-reply",
            )
            reply = None
        records[label] = (row, reply)
        traces[label] = decoded
    require(set(records) == set(selected), "invocation-extent-changed")
    _live_processes(value, records, c)
    denied_row, denied_reply = records["peer-modification-denied"]
    _modification_refusals(denied_row, denied_reply, context)
    for case, initialization in initial.items():
        label = initialization["label"]
        record = _record(initialization["after"], context)
        require(
            records[label][1]["record"] == record and records[label][1]["error"] is None,
            "genesis-reply-changed",
        )
        _publication(traces[label], context["cases"][case], record, initialize=True)
    refused = {
        label
        for label, wanted in selected.items()
        if wanted["outcome"] == "refusal" and not label.startswith("hold-")
    }
    require(
        len(value["refusals"]) == len(refused)
        and {row["label"] for row in value["refusals"]} == refused,
        "refusal-extent-missing",
    )
    for refusal in value["refusals"]:
        label = refusal["label"]
        require(
            refusal["before"] == refusal["after"]
            and records[label][1] == refusal["reply"]
            and refusal["reply"]["error"] is not None
            and refusal["reply"]["record"] is None,
            "refusal-changed-custody",
        )
        require(
            not any(
                row["kind"] in ("write", "sync", "linkat", "renameat", "unlink")
                for row in traces[label]
            ),
            "refusal-wrote-custody",
        )
        original_current = refusal["before"]["original_files_base64"].get("current")
        observed_reads = _current_reads(traces[label], context["cases"][refusal["reply"]["case"]])
        require(
            not observed_reads
            or (
                original_current is not None
                and all(
                    raw == base64.b64decode(original_current, validate=True)
                    for raw in observed_reads
                )
            ),
            "refusal-read-not-original-current",
        )
    for label in ("copy-lock-refused", "inherited-lock-refused", "duplicate-lock-refused"):
        require(
            any(row["kind"] == "lock" and not row["success"] for row in traces[label]),
            "competing-lock-not-refused",
        )
    a, b = c["heads"]
    for label, case, previous, current in (
        ("publish-first", "valid", None, a),
        ("publish-second", "valid", a, b),
        ("holder", "contested", None, a),
        ("interrupted-baseline", "interrupted", None, a),
        ("lost-before-reply", "lost", None, a),
        ("uncertain-publication", "uncertain", None, a),
        ("pending-publication", "interrupted", a, b),
    ):
        expected = {
            "format": "fishhat.checkpoint-store/v1",
            "owner": context["owner"],
            "journal_id": context["journal_id"],
            "anchor": anchors[case],
            "previous": previous,
            "current": current,
        }
        _publication(
            traces[label],
            context["cases"][case],
            expected,
            uncertain=label == "uncertain-publication",
            interrupted=label == "pending-publication",
            unacknowledged=label == "lost-before-reply",
        )
        if label not in ("lost-before-reply", "pending-publication", "uncertain-publication"):
            require(
                records[label][1]["record"] == expected and records[label][1]["error"] is None,
                "published-reply-changed",
            )
    inspection_heads = {
        "inspect-valid": ("valid", None, None),
        "publish-idempotent": ("valid", a, b),
        "copy-inspect": ("contested", None, a),
        "aliases-final": ("aliases", None, None),
        "lost-reply-inspect": ("lost", None, a),
        "uncertain-inspect": ("uncertain", None, a),
    }
    for label, (case, previous, current) in inspection_heads.items():
        expected_record = {
            "format": "fishhat.checkpoint-store/v1",
            "owner": context["owner"],
            "journal_id": context["journal_id"],
            "anchor": anchors[case],
            "previous": previous,
            "current": current,
        }
        originals = _current_reads(traces[label], context["cases"][case])
        require(
            bool(originals)
            and all(raw == _canonical(expected_record) for raw in originals)
            and records[label][1]["record"] == expected_record,
            "inspection-reply-not-original-current",
        )
        require(
            records[label][1]["error"] is None
            and not any(
                row["kind"] in ("write", "sync", "linkat", "renameat", "unlink")
                for row in traces[label]
            ),
            "inspection-mutated-custody",
        )
    require(
        _record(value["normal_publication"], context)["current"] == b
        and _record(value["competition"]["published"], context)["current"] == a,
        "current-publication-changed",
    )
    holder = _live(value["competition"]["live"], c, "holder")
    aliases = value["aliases"]
    parent = _live(aliases["parent_live"], c, "alias-holder-parent")
    inherited = _live(aliases["inherited_live"], c, "alias-holder")
    single = _live(aliases["single_alias_live"], c, "alias-holder-one")
    for marker, case, count in (
        (holder, "contested", 1),
        (parent, "aliases", 2),
        (inherited, "aliases", 2),
        (single, "aliases", 1),
    ):
        require(len(marker["descriptors"]) == count, "descriptor-alias-extent-changed")
        for held in marker["descriptors"].values():
            require(
                {key: held["metadata"][key] for key in ("device", "inode")} == anchors[case]
                and held["target"] == context["cases"][case] + "/anchor"
                and re.search(r"^lock:.*FLOCK\s+ADVISORY\s+WRITE\s+", held["fdinfo"], re.MULTILINE)
                is not None,
                "held-description-not-locked",
            )
    require(
        aliases["parent_absent_before_competition"] is True
        and parent["origin"]["pid"] != inherited["origin"]["pid"],
        "parent-not-excluded-from-alias-witness",
    )
    require(
        len(value["anchor_substitutions"]) == 2
        and {row["case"] for row in value["anchor_substitutions"]} == {"replaced", "unlinked"},
        "anchor-substitution-extent-missing",
    )
    for row in value["anchor_substitutions"]:
        _live(row["live"], c, "hold-" + row["case"])
        require(
            row["after"] == row["substituted"] and row["held_reply"]["error"] is not None,
            "anchor-substitution-adopted",
        )
        require(
            row["before"]["original_files_base64"]["current"]
            == row["after"]["original_files_base64"]["current"],
            "substituted-anchor-overwrote-current",
        )
    for key in ("incomplete_genesis", "interruption"):
        _live(value[key]["live"], c, "")
        require(
            value[key]["after"] == value[key]["live"]["authority"]
            and value[key]["killed"]["stdout"] == "",
            "interruption-custody-changed",
        )
    interrupted = value["interruption"]
    require(
        interrupted["before"]["original_files_base64"]["current"]
        == interrupted["after"]["original_files_base64"]["current"]
        and set(interrupted["after"]["entries"]) == {"anchor", "current", ".pending"},
        "pending-publication-not-retained",
    )
    lost = value["lost_reply"]
    _live(lost["live"], c, "lost-before-reply")
    require(
        lost["published"] == lost["after"]
        and _record(lost["after"], context)["current"] == a
        and lost["inspected"] == records["lost-reply-inspect"][1],
        "lost-reply-not-reconciled",
    )
    uncertain = value["uncertainty"]
    require(
        uncertain["scope"] == "controlled-syscall-error-after-replace-not-device-fault"
        and uncertain["published"] == uncertain["after"]
        and _record(uncertain["after"], context)["current"] == a,
        "uncertainty-custody-changed",
    )
    require(
        uncertain["failed"] == records["uncertain-publication"][1]
        and uncertain["failed"]["error"]["errno"] == 5
        and uncertain["failed"]["details"]["same_handle_refusal"]["type"] == "ContractError",
        "uncertain-handle-not-fenced",
    )
    require(
        len(value["owned_children"]) == len(records)
        and {row["label"] for row in value["owned_children"]} == set(records),
        "owned-child-extent-missing",
    )
    for row in value["owned_children"]:
        original = records[row["label"]][0]
        require(
            row["tracer_pid"] == original["tracer_pid"]
            and row["returncode"] == original["returncode"]
            and row["tracer_joined"] is row["tracees_absent"] is True
            and set(row["tracee_pids"]) == {item["pid"] for item in original["trace_originals"]},
            "owned-child-not-settled",
        )
    expected_paths = {
        str(PurePosixPath(context["journals"][0]).parent),
        "/var/lib/fishhat-checkpoint-fixture-" + c["enrollment"],
    }
    require(
        len(value["cleanup"]) == 2
        and {row["path"] for row in value["cleanup"]} == expected_paths
        and all(
            row["removed"] is True and type(row["inode"]) is int and row["inode"] > 0
            for row in value["cleanup"]
        ),
        "owned-namespace-not-removed",
    )
