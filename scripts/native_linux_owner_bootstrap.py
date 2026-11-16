"""Observe fixed static environment clearing only in an enrolled disposable guest."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, TypedDict

from scripts.bundle_install import (
    OWNER_BOOTSTRAP_INPUTS,
    OWNER_PYTHON_BYTES,
    OWNER_PYTHON_SHA256,
    OWNER_PYTHON_URL,
    sha256,
)
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation import source_identity
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-fixed-static-bootstrap-only"
ARCHIVE = "https://archive.ubuntu.com/ubuntu/pool/main/b/busybox/"


class ArtifactPin(TypedDict):
    bytes: int
    sha256: str


PINS: dict[str, ArtifactPin] = {
    name: {"bytes": size, "sha256": digest} for name, size, digest in OWNER_BOOTSTRAP_INPUTS
}
TRANSFER_NAMES = tuple(name for name in PINS if name not in ("busybox", "copyright", "LICENSE"))
ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
DENIALS = (
    ("static", "write"),
    ("static", "unlink"),
    ("package", "write"),
    ("package", "unlink"),
    ("interrupted", "write"),
    ("interrupted", "unlink"),
    ("static", "replace"),
    ("namespace", "create"),
)
REJECTIONS = (
    "interrupted",
    "existing",
    "source-alias",
    "parent-alias",
    "foreign-parent",
    "writable-parent",
    "changed-input",
)

OBSERVE = r"""
import base64, errno, hashlib, json, os, pathlib, sys, types
c=json.loads(sys.argv[1])
def digest(path):
    with pathlib.Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
result={'pid':os.getpid(),'parent_pid':os.getppid(),'uids':list(os.getresuid()),
        'gids':list(os.getresgid()),'groups':os.getgroups(),
        'capabilities':next(line.split(':',1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),
        'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'enrollment':pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip(),
        'probe':c['probe'],'environment':dict(os.environ),'cwd':os.getcwd(),
        'executable':sys.executable,'executable_sha256':digest(sys.executable),
        'flags':{name:getattr(sys.flags,name) for name in ('isolated','ignore_environment','no_site','no_user_site','safe_path','dont_write_bytecode')},
        'denied':[],'administrative_refusal':False}
if c['peer']:
    for role,path in [('static',c['static']),('package',c['package']),('interrupted',c['interrupted'])]:
        for operation in ('write','unlink'):
            try:
                if operation=='write':
                    descriptor=os.open(path,os.O_WRONLY|os.O_NONBLOCK);os.close(descriptor)
                else:pathlib.Path(path).unlink()
            except OSError as error:
                assert error.errno in (errno.EACCES,errno.EPERM)
                result['denied'].append({'role':role,'operation':operation,'errno':error.errno})
            else:raise AssertionError('peer modified protected bootstrap')
    for role,operation in [('static','replace'),('namespace','create')]:
        try:
            if operation=='replace':os.replace(c['substitute'],c['static'])
            else:
                descriptor=os.open(c['unavailable'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(descriptor)
        except OSError as error:
            assert error.errno in (errno.EACCES,errno.EPERM)
            result['denied'].append({'role':role,'operation':operation,'errno':error.errno})
        else:raise AssertionError('peer replaced protected namespace')
    module=types.ModuleType('approved_static_installer')
    exec(compile(base64.b64decode(c['bootstrap']),'<approved-bootstrap>','exec'),module.__dict__)
    try:module._install_owner_bootstrap(pathlib.Path(c['poison']),pathlib.Path(c['poison'])/'unavailable')
    except ValueError as error:
        assert 'administrative custody' in str(error);result['administrative_refusal']=True
    else:raise AssertionError('peer provisioned administrative bootstrap')
print(json.dumps(result,sort_keys=True))
"""

INTERRUPTED = r"""
import base64, json, os, pathlib, sys, types
c=json.loads(sys.argv[1]);module=types.ModuleType('approved_static_installer')
exec(compile(base64.b64decode(c['bootstrap']),'<approved-bootstrap>','exec'),module.__dict__)
def pause(*args):
    ready=pathlib.Path(c['ready']);pending=ready.with_suffix('.pending')
    with pending.open('x') as stream:
        os.chmod(pending,0o600)
        json.dump({'pid':os.getpid(),'parent_pid':os.getppid(),'uid':os.geteuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()},stream)
        stream.flush();os.fsync(stream.fileno())
    os.replace(pending,ready)
    assert sys.stdin.buffer.read(1)==b'never release'
    raise AssertionError('interrupted installer resumed')
module._verify_owner_bootstrap_elf=pause
module._install_owner_bootstrap(pathlib.Path(c['inputs']),pathlib.Path(c['interrupted']))
"""

REMOTE = r"""
import base64, hashlib, io, json, os, pathlib, shutil, signal, stat, subprocess, sys, tarfile, time, types, uuid, zipfile
c=json.loads(sys.argv[1]);owned=[];child=None;stage='admission'
result={'scope':c['scope'],'status':'failed','native_product_qualified':False,
        'enrollment':c['enrollment'],'boot_id':c['boot_id'],'bootstrap_sha256':c['bootstrap_sha256'],
        'observer_pid':os.getpid(),'observer_uid':os.geteuid(),'primary_error':None,'cleanup_errors':[],'cleanup':[]}
def metadata(path):
    value=path.lstat()
    return {'device':value.st_dev,'inode':value.st_ino,'uid':value.st_uid,'gid':value.st_gid,
            'mode':stat.S_IMODE(value.st_mode),'kind':'directory' if stat.S_ISDIR(value.st_mode) else 'regular' if stat.S_ISREG(value.st_mode) else 'link' if stat.S_ISLNK(value.st_mode) else 'other'}
def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def inventory(root):
    return {'.':metadata(root),**{path.name:{**metadata(path),'bytes':path.stat().st_size,'sha256':digest(path)} for path in root.iterdir()}}
def command(argv,**kwargs):
    global child
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,**kwargs)
    output,errors=child.communicate(timeout=c['child_timeout'])
    assert child.returncode==0,'fixed child command failed'
    pid=child.pid;child=None;return pid,output,errors
try:
    assert os.geteuid()==os.getegid()==0
    assert pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip()==c['enrollment']
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['boot_id']
    raw=base64.b64decode(c['bootstrap']);assert hashlib.sha256(raw).hexdigest()==c['bootstrap_sha256']
    module=types.ModuleType('approved_static_installer');exec(compile(raw,'<approved-bootstrap>','exec'),module.__dict__)
    prefix=pathlib.Path('/var/lib')/('fishhat-bootstrap-fixture-'+c['enrollment'])
    poison=pathlib.Path('/tmp')/('fishhat-bootstrap-fixture-'+c['enrollment'])
    for path,mode in [(prefix,0o755),(poison,0o700)]:
        path.mkdir(mode=mode);os.chmod(path,mode);owned.append((path,metadata(path)))
    result['namespaces']=[{'path':str(path),**before} for path,before in owned]
    inputs=prefix/'inputs';inputs.mkdir(mode=0o700)
    transfer=prefix/'inputs.zip';stage='input-transfer';count=0;checksum=hashlib.sha256()
    with transfer.open('xb') as output:
        os.chmod(transfer,0o600)
        while chunk:=sys.stdin.buffer.read(1048576):
            count+=len(chunk);assert count<=c['input_bytes'];checksum.update(chunk);output.write(chunk)
        output.flush();os.fsync(output.fileno())
    assert count==c['input_bytes'] and checksum.hexdigest()==c['input_sha256']
    result['input']={**metadata(transfer),'bytes':count,'sha256':checksum.hexdigest()}
    stage='fixed-package-byte-preparation'
    with zipfile.ZipFile(transfer) as archive:
        assert set(archive.namelist())==set(c['input_members']) and len(archive.infolist())==len(c['input_members'])
        for name,expected in c['input_members'].items():
            path=inputs/name
            with archive.open(name) as source,path.open('xb') as output:
                os.chmod(path,0o600);shutil.copyfileobj(source,output,1048576);output.flush();os.fsync(output.fileno())
            assert digest(path)==expected
    clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    package=inputs/'busybox-static_1.36.1-6ubuntu3.1_amd64.deb'
    assert package.stat().st_size==c['pins'][package.name]['bytes']
    _,package_tar,_=command(['/usr/bin/dpkg-deb','--fsys-tarfile',str(package)],cwd='/',env=clean)
    result['preparation_tool']={'path':'/usr/bin/dpkg-deb','sha256':digest(pathlib.Path('/usr/bin/dpkg-deb')),'mode':'read-package-filesystem-only','maintainer_scripts_executed':False}
    with tarfile.open(fileobj=io.BytesIO(package_tar),mode='r:') as archive:
        for member_name,name in [('./usr/bin/busybox','busybox'),('./usr/share/doc/busybox-static/copyright','copyright')]:
            member=archive.getmember(member_name);assert member.isfile();source=archive.extractfile(member);assert source is not None
            with source,(inputs/name).open('xb') as output:shutil.copyfileobj(source,output,1048576)
            os.chmod(inputs/name,0o600)
    with tarfile.open(inputs/'busybox_1.36.1.orig.tar.bz2','r:bz2') as archive:
        member=archive.getmember('busybox-1.36.1/LICENSE');assert member.isfile();source=archive.extractfile(member);assert source is not None
        with source,(inputs/'LICENSE').open('xb') as output:shutil.copyfileobj(source,output,1048576)
        os.chmod(inputs/'LICENSE',0o600)
    for name,pin in c['pins'].items():
        assert (inputs/name).stat().st_size==pin['bytes'] and digest(inputs/name)==pin['sha256']
    result['prepared']=inventory(inputs)
    runtime=module._install_owner_python(inputs/'runtime.tar.gz',prefix/'runtime')
    assert digest(runtime)==c['runtime_executable_sha256']
    interrupted=prefix/'interrupted';ready=prefix/'ready.json';stage='interrupted-private-installation'
    configuration={**c,'inputs':str(inputs),'interrupted':str(interrupted),'ready':str(ready)}
    child=subprocess.Popen(['/usr/bin/python3','-I','-S','-B','-c',c['interrupt_program'],json.dumps(configuration)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=clean,close_fds=True)
    deadline=time.monotonic()+c['child_timeout']
    while not ready.exists():
        assert child.poll() is None and time.monotonic()<deadline,'installer gate unavailable';time.sleep(0.05)
    observed=json.loads(ready.read_text());assert observed=={'pid':child.pid,'parent_pid':os.getpid(),'uid':0,'boot_id':c['boot_id']}
    child.kill();child.communicate(timeout=c['child_timeout']);assert child.returncode==-signal.SIGKILL
    result['interruption']={**observed,'returncode':child.returncode,'joined':True,'candidate':inventory(interrupted)};child=None
    stage='fresh-installation';installed=prefix/'installed';static=module._install_owner_bootstrap(inputs,installed)
    result['before']=inventory(installed);result['rejections']=[]
    def reject(name,source,target):
        try:module._install_owner_bootstrap(source,target)
        except (OSError,ValueError) as error:result['rejections'].append({'case':name,'type':type(error).__name__,'errno':getattr(error,'errno',None)})
        else:raise AssertionError('static refusal missing')
    reject('interrupted',inputs,interrupted);reject('existing',inputs,installed)
    alias=prefix/'source-alias';alias.symlink_to(inputs,target_is_directory=True);reject('source-alias',alias,prefix/'bad-source')
    alias=prefix/'parent-alias';alias.symlink_to(prefix,target_is_directory=True);reject('parent-alias',inputs,alias/'bad-parent')
    foreign=prefix/'foreign';foreign.mkdir();os.chown(foreign,c['peer_uid'],c['peer_gid']);reject('foreign-parent',inputs,foreign/'unavailable')
    writable=prefix/'writable';writable.mkdir();os.chmod(writable,0o777);reject('writable-parent',inputs,writable/'unavailable')
    changed=prefix/'changed';changed.mkdir(mode=0o700)
    for name in c['pins']:shutil.copyfile(inputs/name,changed/name)
    with (changed/'busybox').open('r+b') as output:output.write(b'changed')
    reject('changed-input',changed,prefix/'bad-digest')
    stage='independent-root-and-peer-invocations';os.chown(poison,c['peer_uid'],c['peer_gid'])
    for name in ['sitecustomize.py','usercustomize.py','startup.py','shell-startup']:
        path=poison/name;path.write_text("raise SystemExit('poisoned startup')\n");os.chmod(path,0o600);os.chown(path,c['peer_uid'],c['peer_gid'])
    substitute=poison/'substitute';substitute.write_bytes(b'untrusted substitution');os.chmod(substitute,0o600);os.chown(substitute,c['peer_uid'],c['peer_gid'])
    result['invocations']={}
    for role,peer in [('administrative',False),('peer',True)]:
        debug=poison/('loader-'+role)
        poison_environment={**clean,'PATH':str(poison),'HOME':str(poison),'PYTHONHOME':str(poison),'PYTHONPATH':str(poison),'PYTHONUSERBASE':str(poison),'PYTHONSTARTUP':str(poison/'startup.py'),'ENV':str(poison/'shell-startup'),'BASH_ENV':str(poison/'shell-startup'),'LD_LIBRARY_PATH':str(poison),'LD_PRELOAD':str(poison/'missing-preload.so'),'LD_DEBUG':'libs,files','LD_DEBUG_OUTPUT':str(debug)}
        credentials={'user':c['peer_uid'],'group':c['peer_gid'],'extra_groups':[]} if peer else {}
        observed_config={'peer':peer,'probe':str(uuid.uuid4()),'static':str(static),'package':str(installed/package.name),'interrupted':str(interrupted/'busybox'),'substitute':str(substitute),'unavailable':str(installed/'unavailable'),'bootstrap':c['bootstrap'],'poison':str(poison)}
        action=[str(runtime),'-I','-S','-B','-c',c['observe_program'],json.dumps(observed_config)]
        pid,output,errors=command(action,cwd=str(poison),env=poison_environment,**credentials)
        negative=json.loads(output);assert negative['pid']==pid and negative['parent_pid']==os.getpid()
        loader=pathlib.Path(str(debug)+'.'+str(pid));assert loader.is_file() and loader.stat().st_size>0
        negative_loader={**metadata(loader),'path':str(loader),'bytes':loader.stat().st_size,'sha256':digest(loader)}
        observed_config['probe']=str(uuid.uuid4());action=[str(runtime),'-I','-S','-B','-c',c['observe_program'],json.dumps(observed_config)]
        pid,output,errors=command([str(static),'env','-i','LANG=C.UTF-8','LC_ALL=C.UTF-8',*action],cwd=str(poison),env=poison_environment,**credentials)
        sanitized=json.loads(output);assert sanitized['pid']==pid and sanitized['parent_pid']==os.getpid() and sanitized['environment']=={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'} and errors==b''
        absent=pathlib.Path(str(debug)+'.'+str(pid));assert not absent.exists() and not absent.is_symlink()
        result['invocations'][role]={'negative':negative,'negative_loader':negative_loader,'sanitized':sanitized,'sanitized_loader_path':str(absent),'sanitized_loader_absent':True}
    result['after']=inventory(installed);result['interrupted_after']=inventory(interrupted);result['prepared_after']=inventory(inputs)
    assert result['before']==result['after'] and result['interruption']['candidate']==result['interrupted_after'] and result['prepared']==result['prepared_after']
    result['status']='passed'
except BaseException as error:result['primary_error']={'stage':stage,'type':type(error).__name__}
finally:
    if child is not None:
        try:
            if child.poll() is None:child.kill()
            child.communicate(timeout=c['child_timeout'])
        except BaseException as error:result['cleanup_errors'].append({'stage':'child','type':type(error).__name__})
    for path,before in reversed(owned):
        try:
            after=metadata(path);assert all(after[key]==before[key] for key in ('device','inode','kind')) and after['uid'] in (0,c['peer_uid'])
            assert shutil.rmtree.avoids_symlink_attacks;shutil.rmtree(path);assert not path.exists() and not path.is_symlink()
            result['cleanup'].append({'path':str(path),'device':before['device'],'inode':before['inode'],'absent':True})
        except BaseException as error:result['cleanup_errors'].append({'stage':'namespace','type':type(error).__name__})
    if result['cleanup_errors']:result['status']='failed'
print(json.dumps(result,sort_keys=True))
"""


def _prepare_inputs(guest: Guest, temporary: Path) -> tuple[Path, dict[str, Any]]:
    """Download fixed inert inputs; package byte preparation happens in the guest."""
    source = source_identity()
    if not source["clean"]:
        raise GuestBootError("owner-bootstrap-source-not-clean")
    members = {name: PINS[name]["sha256"] for name in TRANSFER_NAMES}
    members["runtime.tar.gz"] = OWNER_PYTHON_SHA256
    for name, digest in members.items():
        runtime = name == "runtime.tar.gz"
        guest.command(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(Path(__file__).with_name("native_owner_python_download.py")),
                str(temporary / name),
                OWNER_PYTHON_URL if runtime else ARCHIVE + name,
                str(OWNER_PYTHON_BYTES if runtime else PINS[name]["bytes"]),
                digest,
                str(watchdog(30)),
            ],
            "owner-bootstrap-fixed-input-download",
            180,
        )
    with tarfile.open(temporary / "runtime.tar.gz", "r:gz") as archive:
        executable = archive.extractfile("python/bin/python3.12")
        if executable is None:
            raise GuestBootError("owner-bootstrap-runtime-executable-unavailable")
        with executable:
            checksum = hashlib.sha256()
            while chunk := executable.read(1_048_576):
                checksum.update(chunk)
            executable_hash = checksum.hexdigest()
    path = temporary / "inputs.zip"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as output:
            for name in members:
                output.write(temporary / name, name)
        stream.flush()
        os.fsync(stream.fileno())
    return path, {
        "input_sha256": sha256(path),
        "input_bytes": path.stat().st_size,
        "input_members": members,
        "pins": PINS,
        "runtime_executable_sha256": executable_hash,
        "source": source,
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
    }


def _require(value: bool, reason: str) -> None:
    if not value:
        raise GuestBootError("owner-bootstrap-" + reason)


def _metadata(value: dict[str, Any], *, uid: int, gid: int, mode: int, kind: str) -> None:
    _require(
        set(value) == {"device", "inode", "uid", "gid", "mode", "kind"}
        and all(
            type(value[k]) is int and value[k] >= 0
            for k in ("device", "inode", "uid", "gid", "mode")
        )
        and (value["uid"], value["gid"], value["mode"], value["kind"]) == (uid, gid, mode, kind),
        "metadata-mismatch",
    )


def _tree(value: dict[str, Any], *, sealed: bool, prepared: bool = False) -> set[tuple[int, int]]:
    expected = dict(PINS)
    if prepared:
        expected["runtime.tar.gz"] = {"bytes": OWNER_PYTHON_BYTES, "sha256": OWNER_PYTHON_SHA256}
    _require(set(value) == {".", *expected}, "namespace-extent-mismatch")
    _metadata(value["."], uid=0, gid=0, mode=0o555 if sealed else 0o700, kind="directory")
    identifiers = {(value["."]["device"], value["."]["inode"])}
    for name, pin in expected.items():
        row = value[name]
        _require(
            set(row) == {"device", "inode", "uid", "gid", "mode", "kind", "bytes", "sha256"},
            "file-shape-mismatch",
        )
        _metadata(
            {k: row[k] for k in ("device", "inode", "uid", "gid", "mode", "kind")},
            uid=0,
            gid=0,
            mode=(0o555 if name == "busybox" else 0o444) if sealed else 0o600,
            kind="regular",
        )
        _require(
            type(row["bytes"]) is int
            and row["bytes"] == pin["bytes"]
            and row["sha256"] == pin["sha256"],
            "file-identity-mismatch",
        )
        identifier = (row["device"], row["inode"])
        _require(identifier not in identifiers, "namespace-alias")
        identifiers.add(identifier)
    return identifiers


def verify_observation(value: dict[str, Any], c: dict[str, Any]) -> None:
    _require(
        set(value)
        == {
            "scope",
            "status",
            "native_product_qualified",
            "enrollment",
            "boot_id",
            "bootstrap_sha256",
            "observer_pid",
            "observer_uid",
            "primary_error",
            "cleanup_errors",
            "cleanup",
            "input",
            "preparation_tool",
            "prepared",
            "interruption",
            "before",
            "rejections",
            "invocations",
            "after",
            "interrupted_after",
            "prepared_after",
            "namespaces",
        },
        "observation-shape-mismatch",
    )
    _require(
        value["scope"] == SCOPE
        and value["status"] == "passed"
        and value["native_product_qualified"] is False
        and value["enrollment"] == c["enrollment"]
        and value["boot_id"] == c["boot_id"]
        and value["bootstrap_sha256"] == c["bootstrap_sha256"]
        and type(value["observer_uid"]) is int
        and value["observer_uid"] == 0
        and type(value["observer_pid"]) is int
        and value["observer_pid"] > 1
        and value["primary_error"] is None
        and value["cleanup_errors"] == [],
        "original-observation-mismatch",
    )
    transfer = value["input"]
    _metadata(
        {k: transfer[k] for k in ("device", "inode", "uid", "gid", "mode", "kind")},
        uid=0,
        gid=0,
        mode=0o600,
        kind="regular",
    )
    _require(
        transfer["bytes"] == c["input_bytes"] and transfer["sha256"] == c["input_sha256"],
        "transfer-mismatch",
    )
    prepared = _tree(value["prepared"], sealed=False, prepared=True)
    complete = _tree(value["before"], sealed=True)
    partial = _tree(value["interruption"]["candidate"], sealed=False)
    _require(
        prepared.isdisjoint(complete | partial) and complete.isdisjoint(partial),
        "installation-identity-reused",
    )
    _require(
        value["before"] == value["after"]
        and value["prepared"] == value["prepared_after"]
        and value["interruption"]["candidate"] == value["interrupted_after"],
        "retained-input-changed",
    )
    interrupted = value["interruption"]
    _require(
        interrupted["parent_pid"] == value["observer_pid"]
        and interrupted["uid"] == 0
        and interrupted["boot_id"] == c["boot_id"]
        and interrupted["returncode"] == -9
        and interrupted["joined"] is True,
        "interruption-mismatch",
    )
    pids = {value["observer_pid"]}
    _require(
        type(interrupted["pid"]) is int
        and interrupted["pid"] > 1
        and interrupted["pid"] not in pids,
        "interrupted-process-reused",
    )
    pids.add(interrupted["pid"])
    _require(
        [row["case"] for row in value["rejections"]] == list(REJECTIONS),
        "rejection-extent-mismatch",
    )
    for row in value["rejections"]:
        expected = (
            ("FileExistsError", 17)
            if row["case"] in ("interrupted", "existing")
            else ("NotADirectoryError", 20)
            if row["case"] in ("source-alias", "parent-alias")
            else ("ValueError", None)
        )
        _require((row["type"], row["errno"]) == expected, "rejection-mismatch")
    tool = value["preparation_tool"]
    _require(
        tool["path"] == "/usr/bin/dpkg-deb"
        and tool["mode"] == "read-package-filesystem-only"
        and tool["maintainer_scripts_executed"] is False
        and isinstance(tool["sha256"], str)
        and len(tool["sha256"]) == 64,
        "package-preparation-mismatch",
    )
    prefix = "/var/lib/fishhat-bootstrap-fixture-" + c["enrollment"]
    poison = "/tmp/fishhat-bootstrap-fixture-" + c["enrollment"]
    probes: set[str] = set()
    _require(set(value["invocations"]) == {"administrative", "peer"}, "invocation-extent-mismatch")
    for role, uid in (("administrative", 0), ("peer", c["peer_uid"])):
        invocation = value["invocations"][role]
        _require(
            set(invocation)
            == {
                "negative",
                "negative_loader",
                "sanitized",
                "sanitized_loader_path",
                "sanitized_loader_absent",
            },
            "invocation-record-shape-mismatch",
        )
        negative, sanitized = invocation["negative"], invocation["sanitized"]
        for observed in (negative, sanitized):
            _require(
                set(observed)
                == {
                    "pid",
                    "parent_pid",
                    "uids",
                    "gids",
                    "groups",
                    "capabilities",
                    "boot_id",
                    "enrollment",
                    "probe",
                    "environment",
                    "cwd",
                    "executable",
                    "executable_sha256",
                    "flags",
                    "denied",
                    "administrative_refusal",
                },
                "invocation-shape-mismatch",
            )
            _require(
                all(
                    type(v) is int
                    for v in [*observed["uids"], *observed["gids"], *observed["groups"]]
                ),
                "invocation-numeric-identity-mismatch",
            )
            _require(
                type(observed["pid"]) is int
                and observed["pid"] > 1
                and observed["pid"] not in pids
                and observed["parent_pid"] == value["observer_pid"],
                "actual-process-mismatch",
            )
            pids.add(observed["pid"])
            _require(
                observed["uids"] == [uid] * 3
                and observed["gids"] == [c["peer_gid"] if role == "peer" else 0] * 3
                and observed["boot_id"] == c["boot_id"]
                and observed["enrollment"] == c["enrollment"],
                "invocation-identity-mismatch",
            )
            _require(
                observed["cwd"] == poison
                and observed["executable"] == prefix + "/runtime/python/bin/python3.12"
                and observed["executable_sha256"] == c["runtime_executable_sha256"],
                "selected-executable-mismatch",
            )
            _require(
                set(observed["flags"])
                == {
                    "isolated",
                    "ignore_environment",
                    "no_site",
                    "no_user_site",
                    "safe_path",
                    "dont_write_bytecode",
                }
                and all(type(v) in (int, bool) and v == 1 for v in observed["flags"].values()),
                "python-isolation-mismatch",
            )
            import uuid

            _require(
                str(uuid.UUID(observed["probe"])) == observed["probe"]
                and observed["probe"] not in probes,
                "probe-reused",
            )
            probes.add(observed["probe"])
            expected_denials = list(DENIALS) if role == "peer" else []
            _require(
                [(r["role"], r["operation"]) for r in observed["denied"]] == expected_denials
                and all(r["errno"] in (1, 13) for r in observed["denied"]),
                "kernel-denial-mismatch",
            )
            _require(
                observed["administrative_refusal"] is (role == "peer"),
                "administrative-refusal-mismatch",
            )
            if role == "peer":
                _require(
                    observed["groups"] == [] and observed["capabilities"] == "0" * 16,
                    "peer-privilege-mismatch",
                )
        _require(sanitized["environment"] == ENVIRONMENT, "environment-not-cleared")
        environment = negative["environment"]
        _require(
            all(
                environment.get(k) == poison
                for k in (
                    "PATH",
                    "HOME",
                    "PYTHONHOME",
                    "PYTHONPATH",
                    "PYTHONUSERBASE",
                    "LD_LIBRARY_PATH",
                )
            )
            and environment.get("LD_DEBUG") == "libs,files"
            and environment.get("LD_PRELOAD") == poison + "/missing-preload.so"
            and environment.get("LD_DEBUG_OUTPUT") == poison + "/loader-" + role
            and environment.get("ENV") == environment.get("BASH_ENV") == poison + "/shell-startup"
            and environment.get("PYTHONSTARTUP") == poison + "/startup.py",
            "negative-environment-ineffective",
        )
        loader = invocation["negative_loader"]
        _require(
            loader["path"] == poison + "/loader-" + role + "." + str(negative["pid"])
            and loader["kind"] == "regular"
            and loader["uid"] == uid
            and type(loader["bytes"]) is int
            and loader["bytes"] > 0
            and isinstance(loader["sha256"], str)
            and len(loader["sha256"]) == 64,
            "negative-loader-observation-mismatch",
        )
        _require(
            invocation["sanitized_loader_path"]
            == poison + "/loader-" + role + "." + str(sanitized["pid"])
            and invocation["sanitized_loader_absent"] is True,
            "sanitized-loader-output-present",
        )
    namespaces = value["namespaces"]
    _require(
        len(namespaces) == 2 and [row["path"] for row in namespaces] == [prefix, poison],
        "namespace-enrollment-mismatch",
    )
    for row in namespaces:
        _require(
            set(row) == {"path", "device", "inode", "uid", "gid", "mode", "kind"},
            "namespace-enrollment-shape-mismatch",
        )
        _metadata(
            {k: row[k] for k in ("device", "inode", "uid", "gid", "mode", "kind")},
            uid=0,
            gid=0,
            mode=0o755 if row["path"] == prefix else 0o700,
            kind="directory",
        )
    cleanup = value["cleanup"]
    for row in cleanup:
        (original,) = [item for item in namespaces if item["path"] == row["path"]]
        _require(
            set(row) == {"path", "device", "inode", "absent"}
            and row["device"] == original["device"]
            and row["inode"] == original["inode"],
            "cleanup-identity-mismatch",
        )
    _require(
        len(cleanup) == 2
        and {row["path"] for row in cleanup} == {prefix, poison}
        and all(row["absent"] is True for row in cleanup)
        and len({(row["device"], row["inode"]) for row in cleanup}) == 2,
        "owned-cleanup-mismatch",
    )


def qualify_bootstrap(
    guest: Guest,
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
) -> None:
    if guest.observed is None:
        raise GuestBootError("guest-not-verified")
    metrics = RunStats()
    report.update(scope=SCOPE, status="failed", native_product_qualified=False)
    try:
        with tempfile.TemporaryDirectory(prefix="fh-bootstrap-", dir=temporary) as directory:
            with progress("guest-owner-bootstrap-inputs"):
                path, inputs = _prepare_inputs(guest, Path(directory))
            report["inputs"] = inputs
            bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
            peer = guest.observed["accounts"][guest.accounts[1]]
            configuration = {
                **inputs,
                "scope": SCOPE,
                "enrollment": guest.enrollment,
                "boot_id": guest.observed["boot_id"],
                "bootstrap": base64.b64encode(bootstrap).decode(),
                "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
                "peer_uid": peer["uid"],
                "peer_gid": peer["gid"],
                "child_timeout": watchdog(180),
                "observe_program": OBSERVE,
                "interrupt_program": INTERRUPTED,
            }
            with progress("guest-owner-static-bootstrap"):
                raw = guest.guarded(
                    ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(configuration)],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    nominal=600,
                    input_path=path,
                )
            report["original_reply_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                report["unparsed_original_reply"] = raw
                raise GuestBootError("owner-bootstrap-invalid-original-reply") from None
            report["original_observation"] = value
            try:
                verify_observation(value, configuration)
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GuestBootError("owner-bootstrap-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-bootstrap-invalid-statistics")
