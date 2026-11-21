"""Inert launcher build data and ELF admission; command execution is replaced."""

import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from scripts import bundle_install as installer
from scripts import owner_launcher as launcher

CHECK_PURPOSE = {
    "purpose": "validation-tooling",
    "authority": ["scripts/owner_launcher.py", "scripts/bundle_install.py"],
    "scope": "fixed build/configuration custody, static ELF permissions and complete file admission with compiler execution replaced",
    "relationship": "no-product-claim",
    "reason": "Synthetic ELF bytes are never executed; native launch credentials, environment, argv and effects need an independently observed enrolled guest.",
    "claims": [],
}


def elf(*, flags=5, stack=6, stack_kind=0x6474E551, file_extent=1024, entry=0x400100):
    raw = bytearray(1024)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 2, 62, 1, entry, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, flags, 0, 0x400000, 0, file_extent, 1024, 4096)
    struct.pack_into("<IIQQQQQQ", raw, 120, stack_kind, stack, 0, 0, 0, 0, 0, 16)
    return bytes(raw)


@pytest.mark.parametrize(
    "value",
    ["/var/lib/approved/python", '/var/lib/a";\\q\n/π', "/var/lib/raw-\udcff"],
    ids=["ascii", "literal-control-text", "filesystem-bytes"],
)
def test_target_paths_roundtrip_as_literal_bytes_without_compiler_tokens(value):
    raw = launcher.target_header(value, "/var/lib/approved/program.py").decode()
    lines = raw.splitlines()
    assert len(lines) == 2
    literal = lines[0].split('"')[1]
    assert bytes(int(chunk, 16) for chunk in literal.split("\\x")[1:]) == os.fsencode(value)
    assert '";' not in literal and "\n" not in literal


@pytest.mark.parametrize(
    "value", ["relative", "/safe/../unsafe", "/safe\0/unsafe"], ids=["relative", "parent", "nul"]
)
def test_unsafe_targets_refused_before_build(value):
    with pytest.raises(ValueError, match="unsafe"):
        launcher.target_header(value, "/fixed/program.py")


def test_static_elf_entry_and_non_executable_stack_are_read_without_loading(tmp_path):
    path = tmp_path / "inert"
    path.write_bytes(elf())
    installer._verify_owner_launcher_elf(path)
    assert path.read_bytes() == elf()


@pytest.mark.parametrize(
    "change",
    [
        {"flags": 7},
        {"stack": 7},
        {"stack": 4},
        {"stack_kind": 0},
        {"file_extent": 128},
        {"entry": 0x401000},
    ],
)
def test_executable_write_stack_and_zero_backed_entry_refused(tmp_path, change):
    path = tmp_path / "inert"
    path.write_bytes(elf(**change))
    with pytest.raises(ValueError):
        installer._verify_owner_launcher_elf(path)


def test_build_retains_exact_source_configuration_invocation_and_output(tmp_path):
    calls = []

    def command(argv, name, nominal):
        calls.append((argv, name, nominal))
        assert name == "owner-launcher-build"
        assert "-nostdlib" in argv and "-nostdinc" in argv and "-static" in argv
        (tmp_path / "build/launch").write_bytes(elf())
        return ""

    interpreter = {"path": "/protected/python/bin/python3.12", "sha256": "a" * 64}
    program = {"path": "/protected/program.py", "sha256": "b" * 64}
    result = launcher.build(
        command,
        tmp_path / "build",
        interpreter=interpreter,
        program=program,
        tools={"observed": "synthetic"},
    )
    manifest = result["manifest"]
    assert (tmp_path / "build/launch.c").read_bytes() == launcher.SOURCE.read_bytes()
    assert (tmp_path / "build/targets.h").read_bytes() == launcher.target_header(
        interpreter["path"], program["path"]
    )
    assert manifest["build"]["argv"] == calls[0][0]
    assert manifest["build"]["output_executed"] is False
    assert manifest["interpreter"] == interpreter and manifest["program"] == program
    raw = (tmp_path / "build/launcher.json").read_bytes()
    assert (
        json.loads(raw) == manifest and hashlib.sha256(raw).hexdigest() == result["manifest_sha256"]
    )
    for name, item in manifest["files"].items():
        value = (tmp_path / "build" / name).read_bytes()
        assert item == {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    before = {p.name: p.read_bytes() for p in (tmp_path / "build").iterdir()}
    with pytest.raises(FileExistsError):
        launcher.build(
            command, tmp_path / "build", interpreter=interpreter, program=program, tools={}
        )
    assert len(calls) == 1 and before == {
        p.name: p.read_bytes() for p in (tmp_path / "build").iterdir()
    }


def test_failed_build_preserves_partial_inputs_without_success_manifest(tmp_path):
    def command(*args):
        (tmp_path / "build/launch").write_bytes(b"incomplete output")
        raise RuntimeError("synthetic compiler interruption")

    target = {"path": "/protected/program", "sha256": "a" * 64}
    with pytest.raises(RuntimeError, match="interruption"):
        launcher.build(command, tmp_path / "build", interpreter=target, program=target, tools={})
    assert {p.name for p in (tmp_path / "build").iterdir()} == {"launch", "launch.c", "targets.h"}
    assert (tmp_path / "build/launch").read_bytes() == b"incomplete output"


@pytest.mark.parametrize(
    "case",
    [
        "matching",
        "version",
        "architecture",
        "missing",
        "duplicate",
        "driver",
        "frontend",
        "assembler",
        "linker",
    ],
)
def test_build_tool_package_gate_uses_fixed_hosted_pins_and_retains_actual_hashes(
    tmp_path, monkeypatch, case
):
    from contextlib import nullcontext

    from scripts.native_linux_guest import GuestBootError

    # Model the files supplied by the selected Ubuntu packages. Keep this
    # independent of the configured paths so an unsupported layout fails here.
    layout = {
        "driver": "/usr/bin/x86_64-linux-gnu-gcc-13",
        "frontend": "/usr/libexec/gcc/x86_64-linux-gnu/13/cc1",
        "assembler": "/usr/bin/x86_64-linux-gnu-as",
        "linker": "/usr/bin/x86_64-linux-gnu-ld.bfd",
    }
    paths = {name: tmp_path / name for name in layout}
    for name, path in paths.items():
        if name != case:
            path.write_bytes(("inert tool identity: " + name).encode())
    selected = {path: paths[name] for name, path in layout.items()}
    original_open = Path.open

    def open_tool(path, *args, **kwargs):
        if str(path).startswith("/usr/"):
            if str(path) not in selected:
                raise FileNotFoundError("unsupported fixture tool layout")
            path = selected[str(path)]
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_tool)
    rows = [[name, *values] for name, values in launcher.PACKAGES.items()]
    if case == "version":
        rows[0][1] = "unapproved"
    elif case == "architecture":
        rows[0][2] = "unapproved"
    elif case == "missing":
        rows.pop()
    elif case == "duplicate":
        rows[1] = list(rows[0])
    calls = []

    def root(argv, name, nominal):
        assert name == "owner-launcher-build-tools" and nominal == 300
        calls.append(argv)

    def command(argv, name, nominal, *, capture):
        assert (
            argv[0] == "/usr/bin/dpkg-query"
            and name == "owner-launcher-build-tools"
            and nominal == 10
            and capture
        )
        return "\n".join("\t".join(row) for row in rows) + "\n"

    if case == "matching":
        report = launcher.provision_tools(command, root, lambda name: nullcontext())
        assert report["sha256"] == {
            name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()
        }
        assert report["packages"] == {
            name: list(value) for name, value in launcher.PACKAGES.items()
        }
    elif case in layout:
        with pytest.raises(GuestBootError, match=f"build-tool-unavailable-{case}"):
            launcher.provision_tools(command, root, lambda name: nullcontext())
    else:
        with pytest.raises(GuestBootError, match="build-tool-mismatch"):
            launcher.provision_tools(command, root, lambda name: nullcontext())
    assert len(calls) == 1
    assert set(calls[0][-len(launcher.PACKAGES) :]) == {
        name + "=" + value[0] for name, value in launcher.PACKAGES.items()
    }
