"""Observe the real fixed host command only in the enrolled disposable Linux guest."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path, PurePosixPath
from typing import Any

from scripts import native_linux_owner_identity, native_linux_owner_wheels, owner_launcher
from scripts.bundle_install import (
    OWNER_PYTHON_BYTES,
    OWNER_PYTHON_SHA256,
    _owner_entrypoint_program,
)
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-protected-host-entrypoint-only"
OBSERVER_PACKAGE = ("strace", "6.8-0ubuntu2", "amd64")
OBSERVER_PINS = {
    "strace_6.8-0ubuntu2_amd64.deb": {
        "package": "strace",
        "version": "6.8-0ubuntu2",
        "architecture": "amd64",
        "url": "https://archive.ubuntu.com/ubuntu/pool/main/s/strace/strace_6.8-0ubuntu2_amd64.deb",
        "bytes": 584172,
        "sha256": "d588810ae26b06fee6678dc81e5b54f6efcde8e718e4589adb4d11d254b9820b",
    },
    "libunwind8_1.6.2-3build1_amd64.deb": {
        "package": "libunwind8",
        "version": "1.6.2-3build1",
        "architecture": "amd64",
        "url": "https://archive.ubuntu.com/ubuntu/pool/main/libu/libunwind/libunwind8_1.6.2-3build1_amd64.deb",
        "bytes": 55198,
        "sha256": "658977d18976149b75391850ba0ccacaf7bde3201f0284189da50cd634334d17",
    },
}
PROFILES = ("complete", "interrupted", "retry")
LAUNCHER_ROLES = ("launch", "launch.c", "targets.h", "launcher.json")

CLEANUP = r"""
import json,os,pathlib,sys
paths=json.loads(sys.argv[1])
print(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'enrollment':pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip(),
                  'paths':[{'path':path,'absent':not pathlib.Path(path).exists() and not pathlib.Path(path).is_symlink()} for path in paths]},sort_keys=True))
"""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise GuestBootError("owner-entrypoint-" + reason)


def _checksum(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _parents(expected: dict[str, dict[str, Any]], name: str, mode: int) -> None:
    parent = PurePosixPath(name).parent
    while str(parent) != "." and str(parent) not in expected:
        expected[str(parent)] = {"kind": "directory", "mode": mode}
        parent = parent.parent


def _runtime_payloads(archive: Path) -> dict[str, dict[str, Any]]:
    """Derive the full pinned runtime closure as inert data, without importing it."""
    expected: dict[str, dict[str, Any]] = {
        "runtime": {"kind": "directory", "mode": 0o555},
        "runtime/runtime.tar.gz": {
            "kind": "regular",
            "mode": 0o400,
            "bytes": OWNER_PYTHON_BYTES,
            "sha256": OWNER_PYTHON_SHA256,
        },
    }
    with archive.open("rb") as stream:
        _require(
            hashlib.file_digest(stream, "sha256").hexdigest() == OWNER_PYTHON_SHA256,
            "runtime-changed",
        )
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            name = "runtime/" + member.name.rstrip("/")
            _require(name not in expected, "duplicate-runtime-member")
            if member.isfile():
                content = source.extractfile(member)
                _require(content is not None, "missing-runtime-member")
                assert content is not None
                with content:
                    hasher = hashlib.sha256()
                    while chunk := content.read(1_048_576):
                        hasher.update(chunk)
                    checksum = hasher.hexdigest()
                row: dict[str, Any] = {
                    "kind": "regular",
                    "mode": 0o555 if member.mode & 0o111 else 0o444,
                    "bytes": member.size,
                    "sha256": checksum,
                }
            elif member.issym():
                row = {"kind": "symlink", "mode": 0o777, "target": member.linkname}
            elif member.isdir():
                row = {"kind": "directory", "mode": 0o555}
            else:
                raise GuestBootError("owner-entrypoint-unsupported-runtime-member")
            expected[name] = row
            _parents(expected, name, 0o555)
    return expected


def _observer_payloads(
    guest: Guest, temporary: Path
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]]]:
    """Read fixed package data on the enrolled controller; execute no package code."""
    members: dict[str, bytes] = {}
    destination = temporary / "observer-expected"
    destination.mkdir(mode=0o700)
    for name, pin in OBSERVER_PINS.items():
        path = temporary / name
        guest.command(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(Path(__file__).with_name("native_owner_python_download.py")),
                str(path),
                str(pin["url"]),
                str(pin["bytes"]),
                str(pin["sha256"]),
                str(watchdog(30)),
            ],
            "owner-entrypoint-fixed-observer-download",
            180,
        )
        raw = path.read_bytes()
        _require(
            len(raw) == pin["bytes"] and _checksum(raw) == pin["sha256"], "changed-observer-package"
        )
        members[name] = raw
        guest.command(
            ["/usr/bin/dpkg-deb", "--extract", str(path), str(destination)],
            "owner-entrypoint-read-package-data",
            60,
        )
    expected: dict[str, dict[str, Any]] = {".": {"kind": "directory", "mode": 0o555}}
    for directory, names, files in os.walk(destination, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            key = path.relative_to(destination).as_posix()
            if path.is_symlink():
                _require(
                    path.resolve(strict=True).is_relative_to(destination), "observer-alias-escape"
                )
                row = {"kind": "symlink", "mode": 0o777, "target": os.readlink(path)}
            elif path.is_dir():
                row = {"kind": "directory", "mode": 0o555}
            else:
                _require(path.is_file() and path.stat().st_nlink == 1, "special-observer-member")
                with path.open("rb") as stream:
                    checksum = hashlib.file_digest(stream, "sha256").hexdigest()
                row = {
                    "kind": "regular",
                    "mode": 0o555 if path.stat().st_mode & 0o111 else 0o444,
                    "bytes": path.stat().st_size,
                    "sha256": checksum,
                }
            expected[key] = row
    return members, expected


def _prepare_inputs(
    guest: Guest, temporary: Path, tools: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    """Prepare three destination-bound builds on the enrolled hosted facility only."""
    base = temporary / "wheel-inputs"
    base.mkdir(mode=0o700)
    existing, wheel_inputs = native_linux_owner_wheels._prepare_inputs(guest, base)
    with zipfile.ZipFile(existing) as source:
        _require(
            set(source.namelist()) == {"runtime.tar.gz", "bundle.zip"}, "unexpected-shared-inputs"
        )
        candidate = source.read("bundle.zip")
    prefix = PurePosixPath("/var/lib/fishhat-entrypoint-fixture-" + guest.enrollment)
    builds: dict[str, Any] = {}
    bindings: dict[str, Any] = {}
    members, expected_observer = _observer_payloads(guest, temporary)
    for name in PROFILES:
        destination = prefix / name
        interpreter = {
            "path": str(destination / "runtime/python/bin/python3.12"),
            "sha256": wheel_inputs["runtime_executable_sha256"],
        }
        program_raw = _owner_entrypoint_program(Path(str(destination / "packages/lib")))
        program = {"path": str(destination / "host-ops.py"), "sha256": _checksum(program_raw)}
        directory = temporary / ("build-" + name)
        built = owner_launcher.build(
            guest.command, directory, interpreter=interpreter, program=program, tools=tools
        )
        originals = {}
        for role in LAUNCHER_ROLES:
            raw = (directory / role).read_bytes()
            members["launchers/" + name + "/" + role] = raw
            originals[role] = {
                "bytes": len(raw),
                "sha256": _checksum(raw),
                "base64": base64.b64encode(raw).decode(),
            }
        bindings[name] = {
            "interpreter": interpreter,
            "program": program,
            "manifest_sha256": built["manifest_sha256"],
        }
        builds[name] = built | {
            "files_original": originals,
            "program_original_base64": base64.b64encode(program_raw).decode(),
        }
    _require(guest.observed is not None, "guest-unverified")
    assert guest.observed is not None
    configuration = {
        "enrollment": guest.enrollment,
        "boot_id": guest.observed["boot_id"],
        "manifest_sha256": wheel_inputs["manifest_sha256"],
        "bindings": bindings,
    }
    bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
    readiness = Path("tests/fixtures/readiness.json").read_bytes()
    members.update(
        {
            "bundle.zip": candidate,
            "install.py": bootstrap,
            "interrupt.py": INTERRUPTED.encode(),
            "configuration.json": owner_launcher.canonical(configuration),
            "valid-readiness.json": readiness,
        }
    )
    expected_inputs: dict[str, dict[str, Any]] = {".": {"kind": "directory", "mode": 0o700}}
    with zipfile.ZipFile(io.BytesIO(candidate)) as source:
        seen = set()
        for member in source.infolist():
            _require(member.filename not in seen, "duplicate-candidate-member")
            seen.add(member.filename)
            relative = "bundle/" + member.filename.rstrip("/")
            row = (
                {"kind": "directory", "mode": 0o700}
                if member.is_dir()
                else {
                    "kind": "regular",
                    "mode": 0o600,
                    "bytes": member.file_size,
                    "sha256": _checksum(source.read(member)),
                }
            )
            _require(
                relative not in expected_inputs or row == expected_inputs[relative],
                "conflicting-candidate-member",
            )
            expected_inputs[relative] = row
            _parents(expected_inputs, relative, 0o700)
    output = temporary / "inputs.zip"
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.write(base / "runtime.tar.gz", "runtime.tar.gz")
            for name, raw in members.items():
                archive.writestr(name, raw)
                expected_inputs[name] = {
                    "kind": "regular",
                    "mode": 0o600,
                    "bytes": len(raw),
                    "sha256": _checksum(raw),
                }
                _parents(expected_inputs, name, 0o700)
        stream.flush()
        os.fsync(stream.fileno())
    expected_inputs["runtime.tar.gz"] = {
        "kind": "regular",
        "mode": 0o600,
        "bytes": OWNER_PYTHON_BYTES,
        "sha256": OWNER_PYTHON_SHA256,
    }
    with output.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    return output, {
        "source": wheel_inputs["candidate_source"],
        "candidate_provenance": wheel_inputs["candidate_provenance"],
        "candidate_sha256": wheel_inputs["candidate_sha256"],
        "candidate_bytes": wheel_inputs["candidate_bytes"],
        "manifest_sha256": wheel_inputs["manifest_sha256"],
        "configuration": configuration,
        "builds": builds,
        "input_sha256": checksum,
        "input_bytes": output.stat().st_size,
        "bootstrap_sha256": _checksum(bootstrap),
        "interrupt_sha256": _checksum(INTERRUPTED.encode()),
        "expected_inputs": expected_inputs,
        "expected_observer": expected_observer,
        "expected_wheels": wheel_inputs["expected_payloads"],
        "expected_runtime": _runtime_payloads(base / "runtime.tar.gz"),
        "valid_readiness_sha256": _checksum(readiness),
    }


INTERRUPTED = r"""
import importlib.util,json,os,pathlib,sys
c=json.loads(pathlib.Path(sys.argv[1]).read_text());spec=importlib.util.spec_from_file_location('approved_installer',c['bootstrap'])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def pause(descriptor):
    ready=pathlib.Path(c['ready']);pending=ready.with_name(ready.name+'.pending')
    with pending.open('x') as stream:
        os.chmod(pending,0o600);json.dump({'pid':os.getpid(),'uid':os.geteuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()},stream)
        stream.flush();os.fsync(stream.fileno())
    os.replace(pending,ready)
    assert sys.stdin.buffer.read(1)==b'never release'
    raise AssertionError('interrupted installation resumed')
module._seal_owner_entrypoint=pause
module._install_owner_entrypoint(pathlib.Path(c['bundle']),pathlib.Path(c['runtime']),pathlib.Path(c['launcher']),pathlib.Path(c['destination']),manifest_sha256=c['manifest'],launcher_manifest_sha256=c['launcher_manifest'])
"""

REMOTE = (
    native_linux_owner_identity.REMOTE_HELPERS
    + r"""
import ctypes,errno,hashlib,importlib.util,io,json,os,pathlib,re,select,shutil,signal,stat,struct,subprocess,sys,tarfile,time,zipfile
c=json.loads(sys.argv[1]);os.umask(0o077);owned=[];child=None;stage='admission';trace_pids=set()
clean={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
result={'scope':c['scope'],'status':'failed','native_product_qualified':False,'enrollment':c['enrollment'],'boot_id':c['boot_id'],
        'observer_pid':os.getpid(),'observer_uid':os.geteuid(),'primary_error':None,'cleanup_errors':[],'cleanup':[]}
def digest(path):
    with pathlib.Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def metadata(path):
    value=path.lstat();row={'device':value.st_dev,'inode':value.st_ino,'uid':value.st_uid,'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),'links':value.st_nlink}
    if stat.S_ISREG(value.st_mode):row.update(kind='regular',bytes=value.st_size,sha256=digest(path),file_capability=os.getxattr(path,'security.capability').hex() if 'security.capability' in os.listxattr(path) else None)
    elif stat.S_ISDIR(value.st_mode):row['kind']='directory'
    elif stat.S_ISLNK(value.st_mode):row.update(kind='symlink',target=os.readlink(path))
    else:row['kind']='other'
    return row
def inventory(root):
    rows={'.':metadata(root)}
    for directory,names,files in os.walk(root,followlinks=False):
        for name in names+files:
            path=pathlib.Path(directory)/name;rows[path.relative_to(root).as_posix()]=metadata(path)
    return rows
def status(pid):
    values={}
    for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in ('Pid','PPid','Uid','Gid','Groups','CapEff','CapPrm','CapInh','CapAmb'):values[key]=value.strip()
    return values
def credentials(mode,packet):
    os.setgroups([])
    if mode in ('peer','ambient'):
        os.setresgid(c['peer_gid'],c['peer_gid'],c['peer_gid'])
        if mode=='ambient':
            library=ctypes.CDLL(None,use_errno=True);assert library.prctl(8,1,0,0,0)==0
        os.setresuid(c['peer_uid'],c['peer_uid'],c['peer_uid'])
        if mode=='ambient':
            class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
            class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
            values=(Data*2)();values[0]=Data(1<<10,1<<10,1<<10)
            assert library.capset(ctypes.byref(Header(0x20080522,0)),values)==0 and library.prctl(47,2,10,0,0)==0
    elif mode=='uid-mismatch':os.setresuid(c['peer_uid'],0,0)
    elif mode=='gid-mismatch':os.setresgid(c['peer_gid'],0,0)
    else:os.setresgid(0,0,0);os.setresuid(0,0,0)
    raw=json.dumps({'pid':os.getpid(),'uids':list(os.getresuid()),'gids':list(os.getresgid()),'groups':os.getgroups(),'status':status(os.getpid())}).encode()
    assert os.write(packet,raw)==len(raw)
def direct(argv,role,environment,input_data=None):
    global child
    read_end,write_end=os.pipe2(os.O_CLOEXEC)
    try:
        child=subprocess.Popen(argv,stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,cwd=poison,close_fds=True,
                               preexec_fn=lambda:credentials(role,write_end),pass_fds=(write_end,),start_new_session=True)
        pid=child.pid;os.close(write_end);write_end=None;output,error=child.communicate(input=input_data,timeout=c['child_timeout'])
        packet=b''
        while chunk:=os.read(read_end,4096):packet+=chunk
        before=json.loads(packet);assert before['pid']==pid
        record={'pid':pid,'before':before,'returncode':child.returncode,'stdout':output.decode(),'stderr':error.decode(),'joined':child.poll() is not None,'argv':argv}
        child=None;return record
    finally:
        for fd in (read_end,write_end):
            if fd is not None:os.close(fd)
def install(name):
    binding=configuration['bindings'][name]
    return module._install_owner_entrypoint(bundle,inputs/'runtime.tar.gz',inputs/'launchers'/name,prefix/name,
               manifest_sha256=configuration['manifest_sha256'],launcher_manifest_sha256=binding['manifest_sha256'])
def refuse(name):
    try:install(name)
    except (ValueError,OSError) as error:return {'type':type(error).__name__,'errno':getattr(error,'errno',None)}
    raise AssertionError('existing installation was adopted')
def trace(command,arguments,role,label,hold=False):
    global child
    account='root' if role=='root' else c['peer_account'];directory=poison/role
    environment=poisoned|{'LD_DEBUG_OUTPUT':str(directory/('positive-loader-'+label))}
    tracebase=traces/label;fifo=directory/(label+'.json');writer=None;pidfd=None
    if hold:os.mkfifo(fifo,0o600);os.chown(fifo,0 if role=='root' else c['peer_uid'],0 if role=='root' else c['peer_gid'])
    args=[str(fifo) if value=='@fifo' else value for value in arguments]
    binding=configuration['bindings'][command.parent.name]
    strings=[str(command),binding['interpreter']['path'],binding['program']['path'],*args,*[key+'='+value for key,value in environment.items()]]
    string_limit=max(len(os.fsencode(value)) for value in strings)+1
    group_selection=os.getgrouplist(account,0 if role=='root' else c['peer_gid'])
    argv=[str(observer/'usr/bin/strace'),'-ff','--kill-on-exit','-s',str(string_limit),'-xx','-v','-q','-e','trace=%file,%process,%creds,%network,umask,close_range','-o',str(tracebase),'-u',account]
    argv += [value for key,item in environment.items() for value in ('-E',key+'='+item)]
    argv += [str(command),*args]
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=observer_env,cwd=poison,close_fds=True,start_new_session=True)
        tracer=child.pid;observed=None
        if hold:
            deadline=time.monotonic()+c['child_timeout']
            while writer is None:
                assert child.poll() is None and time.monotonic()<deadline
                try:writer=os.open(fifo,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                except OSError as error:
                    assert error.errno==errno.ENXIO;time.sleep(0.02)
            files=list(traces.glob(label+'.*'));assert len(files)==1
            pid=int(files[0].name.rsplit('.',1)[1]);pidfd=os.pidfd_open(pid);trace_pids.add(pid)
            proc=pathlib.Path('/proc')/str(pid);before_stat=(proc/'stat').read_text();facts=status(pid)
            assert int(facts['PPid'])==tracer
            observed={'pid':pid,'tracer_pid':tracer,'status':facts,'start_ticks':before_stat.rsplit(')',1)[1].split()[19],
                      'executable':os.readlink(proc/'exe'),'cmdline_hex':(proc/'cmdline').read_bytes().hex(),'environment_hex':(proc/'environ').read_bytes().hex(),
                      'process_group':os.getpgid(pid),'session':os.getsid(pid),'pidfd_open':True}
            assert observed['start_ticks']==(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
            raw=(inputs/'valid-readiness.json').read_bytes();offset=0
            while offset<len(raw):offset+=os.write(writer,raw[offset:])
            os.close(writer);writer=None
        output,error=child.communicate(timeout=c['child_timeout']);returncode=child.returncode;assert child.poll() is not None
        files=list(traces.glob(label+'.*'));assert len(files)==1
        pid=int(files[0].name.rsplit('.',1)[1]);trace_pids.add(pid)
        if pidfd is None:pidfd=os.pidfd_open(pid) if pathlib.Path('/proc/'+str(pid)).exists() else None
        if pidfd is not None:
            poll=select.poll();poll.register(pidfd,select.POLLIN);assert poll.poll(c['child_timeout']*1000)
        assert not pathlib.Path('/proc/'+str(pid)).exists()
        code_opens={}
        for line in files[0].read_text().splitlines():
            if line.startswith('openat(') and re.search(r'\)\s+=\s+[0-9]+$',line):
                raw_path=line[len('openat('):].partition(', ')[2].partition(', ')[0]
                match=re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"',raw_path);assert match is not None
                path=os.fsdecode(bytes.fromhex(match[1].replace('\\x','')))
                if path.endswith(('.py','.pyc')) or '.so' in pathlib.PurePosixPath(path).name:
                    resolved=(pathlib.Path(path) if pathlib.Path(path).is_absolute() else poison/path).resolve(strict=True)
                    code_opens[path]={'resolved':str(resolved),'metadata':metadata(resolved)}
        record={'role':role,'label':label,'command':str(command),'arguments':args,'environment':environment,'tracer_pid':tracer,'tracee_pid':pid,
                'code_opens':code_opens,
                'returncode':returncode,'stdout':output.decode(),'stderr':error.decode(),'tracer_joined':True,'tracee_absent':True,'observation':observed,
                'initial_group_selection':group_selection,'observer_argv':argv,'observer_environment':observer_env,'string_limit':string_limit,
                'trace_original':files[0].read_text(),'trace_metadata':metadata(files[0]),'positive_loader_files':[p.name for p in directory.glob('positive-loader-'+label+'.*')]}
        assert returncode==0 and error==b'' and not record['positive_loader_files'];child=None;return record
    finally:
        for fd in (writer,pidfd):
            if fd is not None:os.close(fd)
try:
    assert os.geteuid()==0 and pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip()==c['enrollment']
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['boot_id']
    prefix=pathlib.Path('/var/lib/fishhat-entrypoint-fixture-'+c['enrollment']);poison=pathlib.Path('/tmp/fishhat-entrypoint-fixture-'+c['enrollment'])
    for path in (prefix,poison):
        path.mkdir(mode=0o755);path.chmod(0o755);owned.append((path,path.stat().st_dev,path.stat().st_ino))
    inputs=prefix/'inputs';inputs.mkdir(mode=0o700);traces=prefix/'traces';traces.mkdir(mode=0o700)
    stage='transfer';payload=sys.stdin.buffer.read();assert len(payload)==c['input_bytes'] and hashlib.sha256(payload).hexdigest()==c['input_sha256']
    expected={'runtime.tar.gz','bundle.zip','install.py','interrupt.py','configuration.json','valid-readiness.json'}|{'launchers/'+role+'/'+name for role in ('complete','interrupted','retry') for name in ('launch','launch.c','targets.h','launcher.json')}|set(c['observer_pins'])
    members={}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert len(archive.namelist())==len(expected) and set(archive.namelist())==expected
        for name in archive.namelist():
            path=inputs/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=archive.read(name)
            with path.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            members[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    result['transfer']={'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'members':members};del payload
    configuration=json.loads((inputs/'configuration.json').read_text());assert configuration['enrollment']==c['enrollment'] and configuration['boot_id']==c['boot_id']
    assert digest(inputs/'install.py')==c['bootstrap_sha256'] and digest(inputs/'interrupt.py')==c['interrupt_sha256']
    spec=importlib.util.spec_from_file_location('approved_entrypoint_installer',inputs/'install.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    bundle=inputs/'bundle';bundle.mkdir(mode=0o700)
    with zipfile.ZipFile(inputs/'bundle.zip') as archive:archive.extractall(bundle)
    stage='observer-tool'
    observer=prefix/'observer';observer.mkdir(mode=0o700);packages={}
    for name,pin in c['observer_pins'].items():
        path=inputs/name;assert path.stat().st_size==pin['bytes'] and digest(path)==pin['sha256']
        fields={}
        for field in ('Package','Version','Architecture'):
            action=subprocess.run(['/usr/bin/dpkg-deb','--field',str(path),field],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=clean,timeout=c['child_timeout'])
            assert action.stderr==b'';fields[field]=action.stdout.decode().strip()
        assert fields=={'Package':pin['package'],'Version':pin['version'],'Architecture':pin['architecture']}
        action=subprocess.run(['/usr/bin/dpkg-deb','--fsys-tarfile',str(path)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=clean,timeout=c['child_timeout']);assert action.stderr==b''
        with tarfile.open(fileobj=io.BytesIO(action.stdout),mode='r:') as archive:archive.extractall(observer,filter='data')
        packages[name]={'bytes':path.stat().st_size,'sha256':digest(path),'fields':fields,'data_tar_sha256':hashlib.sha256(action.stdout).hexdigest()}
    module._seal_python(observer)
    observer_env=clean|{'LD_LIBRARY_PATH':str(observer/'usr/lib/x86_64-linux-gnu')}
    result['observer_before']=inventory(observer)
    result['observer_tool']={'package_original':'\t'.join(c['observer_package'])+'\n','packages':packages,
        'executable_path':str(observer/'usr/bin/strace'),'executable':metadata(observer/'usr/bin/strace'),
        'preparation_tool':{'path':'/usr/bin/dpkg-deb','sha256':digest(pathlib.Path('/usr/bin/dpkg-deb')),'mode':'read-package-filesystem-only','maintainer_scripts_executed':False},
        'product_runtime_dependency':False,'offline':True}
    stage='complete-install';result['inputs_before']=inventory(inputs);command=install('complete')
    result['complete_before']=inventory(prefix/'complete');result['existing_refusal']=refuse('complete')
    stage='symlink-refusals';result['symlink_refusals']=[]
    for name,ancestry in (('destination-link',False),('parent-link',True)):
        link=prefix/name;link.symlink_to(prefix/'complete',target_is_directory=True);before=metadata(link)
        destination=link/'unapproved-child' if ancestry else link
        try:module._install_owner_entrypoint(bundle,inputs/'runtime.tar.gz',inputs/'launchers/complete',destination,manifest_sha256=configuration['manifest_sha256'],launcher_manifest_sha256=configuration['bindings']['complete']['manifest_sha256'])
        except (ValueError,OSError) as error:
            result['symlink_refusals'].append({'name':name,'before':before,'after':metadata(link),'error':{'type':type(error).__name__,'errno':getattr(error,'errno',None)},'target_child_absent':not (prefix/'complete/unapproved-child').exists()})
        else:raise AssertionError('symlink installation accepted')
        assert metadata(link)==before
    stage='interrupted-install';ready=prefix/'ready.json';binding=configuration['bindings']['interrupted']
    interrupted={'bootstrap':str(inputs/'install.py'),'bundle':str(bundle),'runtime':str(inputs/'runtime.tar.gz'),'launcher':str(inputs/'launchers/interrupted'),
                 'destination':str(prefix/'interrupted'),'manifest':configuration['manifest_sha256'],'launcher_manifest':binding['manifest_sha256'],'ready':str(ready)}
    config=prefix/'interrupted.json';config.write_text(json.dumps(interrupted))
    child=subprocess.Popen([sys.executable,'-I','-S','-B',str(inputs/'interrupt.py'),str(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=clean,close_fds=True,start_new_session=True)
    deadline=time.monotonic()+c['child_timeout']
    while not ready.exists():
        assert child.poll() is None and time.monotonic()<deadline;time.sleep(0.02)
    announced=json.loads(ready.read_text());assert announced=={'pid':child.pid,'uid':0,'boot_id':c['boot_id']}
    killed=child.pid;child.kill();child.communicate(timeout=c['child_timeout']);assert child.returncode==-signal.SIGKILL
    result['interruption']={'pid':killed,'announced':announced,'returncode':child.returncode,'joined':True};child=None
    result['interrupted_before']=inventory(prefix/'interrupted');result['interrupted_refusal']=refuse('interrupted')
    retry=install('retry');result['retry_before']=inventory(prefix/'retry')
    stage='poison-context';hook="raise RuntimeError('unapproved caller code executed')\n"
    for name in ('sitecustomize.py','usercustomize.py','json.py','python','sh'):(poison/name).write_text(hook)
    (poison/'fishhat_host').mkdir();(poison/'fishhat_host/__init__.py').write_text(hook)
    (poison/'gitconfig').write_text('[core]\nsshCommand = unapproved-program\n[alias]\nhost-ops = !unapproved-program\n')
    for name in ('sitecustomize.py','usercustomize.py','json.py','gitconfig','fishhat_host/__init__.py'):(poison/name).chmod(0o444)
    (poison/'fishhat_host').chmod(0o555)
    for name in ('python','sh'):
        (poison/name).write_text('#!/bin/sh\nexit 91\n');(poison/name).chmod(0o555)
    for role in ('root','peer'):
        directory=poison/role;directory.mkdir(mode=0o700)
        if role=='peer':os.chown(directory,c['peer_uid'],c['peer_gid'])
    poisoned={'LANG':'invalid_fixture_locale','LC_ALL':'invalid_fixture_locale','HOME':str(poison),'PATH':str(poison),'PYTHONHOME':str(poison),'PYTHONPATH':str(poison),
              'PYTHONUSERBASE':str(poison),'PYTHONSTARTUP':str(poison/'sitecustomize.py'),'ENV':str(poison/'sh'),'BASH_ENV':str(poison/'sh'),
              'LD_PRELOAD':str(poison/'missing-preload.so'),'LD_AUDIT':str(poison/'missing-audit.so'),'LD_LIBRARY_PATH':str(poison),'LD_DEBUG':'libs,files'}
    poisoned.update({'GIT_CONFIG_SYSTEM':str(poison/'gitconfig'),'GIT_CONFIG_GLOBAL':str(poison/'gitconfig'),'GIT_EXEC_PATH':str(poison),'GIT_SSH_COMMAND':'unapproved-program'})
    result['negative_controls']=[];result['direct_invocations']=[];result['traced_invocations']=[]
    for role in ('root','peer'):
        directory=poison/role;control_env=poisoned|{'LD_DEBUG_OUTPUT':str(directory/'negative-loader')}
        selected=configuration['bindings']['complete'];interpreter=selected['interpreter']['path'];program=selected['program']['path']
        control=direct([interpreter,'-I','-S','-B',program,'info','--json'],role,control_env)
        loader=directory/('negative-loader.'+str(control['pid']));assert control['returncode']==0 and loader.is_file()
        control.update(role=role,environment=control_env,loader={'path':str(loader),**metadata(loader)});result['negative_controls'].append(control)
        record=direct([str(command),'info','--json'],role,poisoned);assert record['returncode']==0 and record['stderr']==''
        record.update(role=role,environment=poisoned);result['direct_invocations'].append(record)
        for label,args,hold in [('help',['--help'],False),('info',['info','--json'],False),('validate',['validate','@fifo','--schema','readiness.schema.json','--json'],True)]:
            result['traced_invocations'].append(trace(retry if label=='validate' else command,args,role,role+'-'+label,hold))
    stage='unsupported-contexts';result['refusals']=[]
    for mode in ('uid-mismatch','gid-mismatch','ambient','setuid','filecap'):
        target=command
        if mode in ('setuid','filecap'):
            target=prefix/('unsafe-'+mode);shutil.copyfile(command,target);target.chmod(0o4555 if mode=='setuid' else 0o555)
            if mode=='filecap':os.setxattr(target,'security.capability',struct.pack('<IIIII',0x02000001,1<<10,0,0,0))
        record=direct([str(target),'info','--json'],mode if mode not in ('setuid','filecap') else 'peer',clean)
        assert record['returncode']==126 and record['stdout']=='' and record['stderr']=='Unsupported invocation context\n'
        record.update(mode=mode,target=metadata(target),traced=False);result['refusals'].append(record)
    stage='mutation-refusal';result['dispatch_refusals']=[]
    for args in (['run','/unapproved/program'],['-c','unapproved'],['commission'],['--interpreter=/unapproved/python']):
        record=direct([str(command),*args],'peer',poisoned);assert record['returncode']==2 and record['stdout']==''
        result['dispatch_refusals'].append(record)
    stage='peer-denials';denials={}
    actions={'command-write':('write',str(command)),'program-write':('write',str(prefix/'complete/host-ops.py')),'runtime-write':('write',configuration['bindings']['complete']['interpreter']['path']),
             'library-write':('write',str(prefix/'complete/packages/lib/fishhat_host/cli.py')),'command-unlink':('unlink',str(command)),'create':('create',str(prefix/'complete/peer-created')),
             'chmod':('chmod',str(prefix/'complete')),'rename':('rename',str(prefix/'complete'))}
    probe="import json,os,pathlib,sys; c=json.loads(sys.argv[1]); p=pathlib.Path(c['path']); a=c['action']; (p.write_bytes(b'peer mutation') if a in ('write','create') else p.unlink() if a=='unlink' else p.chmod(0o777) if a=='chmod' else p.rename(p.with_name('peer-replaced')))"
    for name,(action,path) in actions.items():
        record=direct(['/usr/bin/python3','-I','-S','-B','-c',probe,json.dumps({'path':path,'action':action})],'peer',clean)
        assert record['returncode']!=0 and ('PermissionError' in record['stderr']);denials[name]=record
    result['peer_denials']=denials
    stage='administrative-refusal'
    import base64
    receiver="import base64,json,pathlib,sys,types; c=json.loads(sys.stdin.buffer.read()); m=types.ModuleType('approved_entrypoint_receiver'); exec(compile(base64.b64decode(c['bootstrap']),'<approved-bootstrap>','exec'),m.__dict__); m._install_owner_entrypoint(pathlib.Path(c['bundle']),pathlib.Path(c['runtime']),pathlib.Path(c['launcher']),pathlib.Path(c['destination']),manifest_sha256=c['manifest'],launcher_manifest_sha256=c['launcher_manifest'])"
    attempted=poison/'peer/unapproved-install'
    reply=direct(['/usr/bin/python3','-I','-S','-B','-c',receiver],'peer',clean,json.dumps({'bootstrap':base64.b64encode((inputs/'install.py').read_bytes()).decode(),'bundle':str(bundle),'runtime':str(inputs/'runtime.tar.gz'),'launcher':str(inputs/'launchers/complete'),'destination':str(attempted),'manifest':configuration['manifest_sha256'],'launcher_manifest':configuration['bindings']['complete']['manifest_sha256']}).encode())
    assert reply['returncode']!=0 and 'protected staging requires Linux administrative custody' in reply['stderr'] and not attempted.exists()
    result['administrative_refusal']=reply|{'candidate_absent':True}
    stage='owner-identity';result['owner_identity']=owner_identity_probe(command)
    for name in ('complete','interrupted','retry'):result[name+'_after']=inventory(prefix/name)
    result['inputs_after']=inventory(inputs);result['observer_after']=inventory(observer)
    assert result['observer_before']==result['observer_after']
    assert result['inputs_before']==result['inputs_after']
    for name in ('complete','interrupted','retry'):assert result[name+'_before']==result[name+'_after']
    result['status']='passed'
except BaseException as error:result['primary_error']={'stage':stage,'type':type(error).__name__,'message':str(error)}
finally:
    result['identity_children'],identity_errors=identity_cleanup();result['cleanup_errors'].extend(identity_errors)
    if child is not None:
        try:
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            child.communicate(timeout=c['child_timeout']);assert child.poll() is not None;child=None
        except BaseException as error:result['cleanup_errors'].append({'stage':'child-join','type':type(error).__name__})
    if 'traces' in locals() and traces.exists():
        for path in traces.iterdir():
            if path.name.rsplit('.',1)[-1].isdigit():trace_pids.add(int(path.name.rsplit('.',1)[-1]))
    for pid in trace_pids:
        try:
            deadline=time.monotonic()+c['child_timeout']
            while pathlib.Path('/proc/'+str(pid)).exists():
                assert time.monotonic()<deadline;time.sleep(0.02)
        except BaseException as error:result['cleanup_errors'].append({'stage':'tracee-absence','type':type(error).__name__})
    if child is None and not result['cleanup_errors']:
        for path,device,inode in reversed(owned):
            try:
                value=path.lstat();assert stat.S_ISDIR(value.st_mode) and (value.st_dev,value.st_ino)==(device,inode)
                shutil.rmtree(path);assert not path.exists() and not path.is_symlink();result['cleanup'].append({'path':str(path),'device':device,'inode':inode,'removed':True})
            except BaseException as error:result['cleanup_errors'].append({'path':str(path),'type':type(error).__name__})
    if result['cleanup_errors']:result['status']='failed'
print(json.dumps(result,sort_keys=True))
"""
)


def _file_metadata(row: dict[str, Any], expected: dict[str, Any]) -> tuple[int, int]:
    for name in ("device", "inode", "uid", "gid", "mode", "links"):
        _require(type(row[name]) is int and row[name] >= 0, "invalid-file-metadata")
    _require(row["device"] > 0 and row["inode"] > 0 and row["links"] > 0, "invalid-file-identity")
    _require(row["uid"] == row["gid"] == 0, "foreign-installed-file")
    for name, value in expected.items():
        _require(type(row[name]) is type(value) and row[name] == value, "changed-installed-file")
    if row["kind"] == "regular":
        _require(
            row["links"] == 1 and row["file_capability"] == expected.get("file_capability"),
            "unsafe-installed-file",
        )
        _require(type(row["bytes"]) is int and row["bytes"] >= 0, "invalid-file-size")
        _require(
            type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"]) is not None,
            "invalid-file-hash",
        )
    return row["device"], row["inode"]


def _expected_installation(inputs: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    sealed = name != "interrupted"
    expected = {".": {"kind": "directory", "mode": 0o555 if sealed else 0o700}}
    expected.update(inputs["expected_runtime"])
    for relative, row in inputs["expected_wheels"].items():
        key = "packages" if relative == "." else "packages/" + relative
        expected[key] = row | {"mode": 0o555 if row["kind"] == "directory" else 0o444}
    expected["launcher"] = {"kind": "directory", "mode": 0o555}
    for role, row in inputs["builds"][name]["files_original"].items():
        expected["launcher/" + role] = {
            "kind": "regular",
            "mode": 0o555 if role == "launch" else 0o444,
            "bytes": row["bytes"],
            "sha256": row["sha256"],
        }
    raw = base64.b64decode(inputs["builds"][name]["program_original_base64"], validate=True)
    expected["host-ops.py"] = {
        "kind": "regular",
        "mode": 0o444,
        "bytes": len(raw),
        "sha256": _checksum(raw),
    }
    launch = inputs["builds"][name]["files_original"]["launch"]
    expected["host-ops"] = {
        "kind": "regular",
        "mode": 0o555 if sealed else 0o600,
        "bytes": launch["bytes"],
        "sha256": launch["sha256"],
    }
    return expected


def _tree(value: dict[str, Any], expected: dict[str, dict[str, Any]]) -> set[tuple[int, int]]:
    _require(type(value) is dict and set(value) == set(expected), "incomplete-file-closure")
    nodes = [_file_metadata(value[name], row) for name, row in expected.items()]
    _require(len(set(nodes)) == len(nodes), "aliased-file-custody")
    return set(nodes)


def _principal(row: dict[str, Any], uid: int, gid: int) -> None:
    _require(type(row["pid"]) is int and row["pid"] > 1, "invalid-process-identity")
    for key, value in (("uids", uid), ("gids", gid)):
        _require(
            type(row[key]) is list
            and len(row[key]) == 3
            and all(type(item) is int and item == value for item in row[key]),
            "wrong-original-principal",
        )
    _require(row["groups"] == [], "wrong-original-groups")
    _require(int(row["status"]["Pid"]) == row["pid"], "foreign-process-status")
    _require(
        [int(value) for value in row["status"]["Uid"].split()] == [uid] * 4
        and [int(value) for value in row["status"]["Gid"].split()] == [gid] * 4
        and row["status"]["Groups"].split() == [],
        "inconsistent-original-status",
    )
    for key in ("CapEff", "CapPrm", "CapInh", "CapAmb"):
        _require(
            type(row["status"][key]) is str
            and re.fullmatch("[0-9a-f]{16}", row["status"][key]) is not None,
            "invalid-original-capabilities",
        )
    if uid:
        _require(
            all(
                int(row["status"][key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")
            ),
            "unexpected-original-capabilities",
        )


def _poison_environment(enrollment: str) -> dict[str, str]:
    prefix = "/tmp/fishhat-entrypoint-fixture-" + enrollment
    return {
        "LANG": "invalid_fixture_locale",
        "LC_ALL": "invalid_fixture_locale",
        "HOME": prefix,
        "PATH": prefix,
        "PYTHONHOME": prefix,
        "PYTHONPATH": prefix,
        "PYTHONUSERBASE": prefix,
        "PYTHONSTARTUP": prefix + "/sitecustomize.py",
        "ENV": prefix + "/sh",
        "BASH_ENV": prefix + "/sh",
        "LD_PRELOAD": prefix + "/missing-preload.so",
        "LD_AUDIT": prefix + "/missing-audit.so",
        "LD_LIBRARY_PATH": prefix,
        "LD_DEBUG": "libs,files",
        "GIT_CONFIG_SYSTEM": prefix + "/gitconfig",
        "GIT_CONFIG_GLOBAL": prefix + "/gitconfig",
        "GIT_EXEC_PATH": prefix,
        "GIT_SSH_COMMAND": "unapproved-program",
    }


def _literal_values(raw: str) -> list[bytes]:
    matches = list(re.finditer(r'"((?:\\x[0-9a-f]{2})*)"', raw))
    _require(raw.count('"') == 2 * len(matches), "malformed-trace-strings")
    rest = re.sub(r'"(?:\\x[0-9a-f]{2})*"', "", raw)
    _require(not rest.strip(" ,"), "abbreviated-or-malformed-trace-array")
    return [bytes.fromhex(match[1].replace("\\x", "")) for match in matches]


def _execution(line: str) -> tuple[bytes, list[bytes], dict[bytes, bytes]]:
    _require(line.startswith("execve("), "unexpected-exec-operation")
    path, separator, rest = line[len("execve(") :].partition(", [")
    _require(bool(separator), "missing-exec-argv")
    argv, separator, rest = rest.partition("], [")
    _require(bool(separator), "missing-exec-environment")
    environment, separator, ending = rest.partition("])")
    _require(bool(separator) and ending.strip() == "= 0", "unsuccessful-exec")
    executable = _literal_values(path)
    _require(len(executable) == 1, "ambiguous-exec-path")
    values: dict[bytes, bytes] = {}
    for item in _literal_values(environment):
        key, separator_bytes, value = item.partition(b"=")
        _require(
            bool(separator_bytes) and bool(key) and key not in values, "malformed-exec-environment"
        )
        values[key] = value
    return executable[0], _literal_values(argv), values


def _trace(row: dict[str, Any], inputs: dict[str, Any], c: dict[str, Any]) -> None:
    role, label = row["role"], row["label"]
    profile = "retry" if label.endswith("-validate") else "complete"
    binding = inputs["configuration"]["bindings"][profile]
    prefix = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/" + profile
    command = prefix + "/host-ops"
    _require(row["command"] == command, "wrong-installed-command")
    _require(
        row["environment"]
        == _poison_environment(c["enrollment"])
        | {
            "LD_DEBUG_OUTPUT": "/tmp/fishhat-entrypoint-fixture-"
            + c["enrollment"]
            + "/"
            + role
            + "/positive-loader-"
            + label
        },
        "ineffective-trace-poison",
    )
    complete_strings = [
        command,
        binding["interpreter"]["path"],
        binding["program"]["path"],
        *row["arguments"],
        *[key + "=" + value for key, value in row["environment"].items()],
    ]
    string_limit = max(len(os.fsencode(value)) for value in complete_strings) + 1
    _require(
        type(row["string_limit"]) is int
        and row["string_limit"] == string_limit
        and row["observer_argv"][:5]
        == [
            "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/observer/usr/bin/strace",
            "-ff",
            "--kill-on-exit",
            "-s",
            str(string_limit),
        ],
        "incomplete-observer-string-budget",
    )
    expected_environment = _poison_environment(c["enrollment"]) | {
        "LD_DEBUG_OUTPUT": "/tmp/fishhat-entrypoint-fixture-"
        + c["enrollment"]
        + "/"
        + role
        + "/positive-loader-"
        + label
    }
    observer_prefix = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/observer"
    _require(
        row["observer_environment"]
        == {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": observer_prefix + "/usr/lib/x86_64-linux-gnu",
        },
        "changed-observer-environment",
    )
    expected_observer = [
        observer_prefix + "/usr/bin/strace",
        "-ff",
        "--kill-on-exit",
        "-s",
        str(string_limit),
        "-xx",
        "-v",
        "-q",
        "-e",
        "trace=%file,%process,%creds,%network,umask,close_range",
        "-o",
        "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/traces/" + label,
        "-u",
        "root" if role == "root" else c["peer_account"],
    ]
    expected_observer += [
        item for key, value in expected_environment.items() for item in ("-E", key + "=" + value)
    ]
    expected_observer += [command, *row["arguments"]]
    _require(row["observer_argv"] == expected_observer, "changed-observer-invocation")
    _require(
        type(row["tracer_pid"]) is int
        and type(row["tracee_pid"]) is int
        and row["tracer_pid"] > 1
        and row["tracee_pid"] > 1
        and row["tracer_pid"] != row["tracee_pid"],
        "invalid-trace-pids",
    )
    _require(row["tracer_joined"] is row["tracee_absent"] is True, "unjoined-trace-process")
    _require(
        type(row["returncode"]) is int
        and row["returncode"] == 0
        and row["stderr"] == ""
        and row["positive_loader_files"] == [],
        "failed-traced-invocation",
    )
    log = row["trace_original"]
    _require(
        type(log) is str and log.endswith("+++ exited with 0 +++\n"), "incomplete-original-trace"
    )
    _file_metadata(
        row["trace_metadata"],
        {
            "kind": "regular",
            "mode": 0o600,
            "bytes": len(log.encode()),
            "sha256": _checksum(log.encode()),
        },
    )
    lines = log.splitlines()
    executions = [line for line in lines if line.startswith(("execve(", "execveat("))]
    _require(len(executions) == 2, "unexpected-program-dispatch")
    first, second = map(_execution, executions)
    encoded_args = [os.fsencode(value) for value in row["arguments"]]
    _require(
        first
        == (
            os.fsencode(command),
            [os.fsencode(command), *encoded_args],
            {os.fsencode(k): os.fsencode(v) for k, v in row["environment"].items()},
        ),
        "changed-original-exec-context",
    )
    interpreter, program = binding["interpreter"]["path"], binding["program"]["path"]
    _require(
        second
        == (
            os.fsencode(interpreter),
            [os.fsencode(interpreter), b"-I", b"-S", b"-B", os.fsencode(program), *encoded_args],
            {b"LANG": b"C.UTF-8", b"LC_ALL": b"C.UTF-8"},
        ),
        "changed-selected-exec-context",
    )
    mutation = (
        "setuid(",
        "setgid(",
        "setresuid(",
        "setresgid(",
        "setreuid(",
        "setregid(",
        "setfsuid(",
        "setfsgid(",
        "setgroups(",
        "capset(",
        "mkdir(",
        "mkdirat(",
        "unlink(",
        "unlinkat(",
        "rename(",
        "renameat(",
        "renameat2(",
        "chmod(",
        "fchmodat(",
    )
    network = (
        "socket(",
        "socketpair(",
        "connect(",
        "bind(",
        "listen(",
        "accept(",
        "accept4(",
        "sendto(",
        "sendmsg(",
        "recvfrom(",
        "recvmsg(",
    )
    start = lines.index(executions[0])
    _require(
        not any(line.startswith(mutation + network) for line in lines[start + 1 :]),
        "unexpected-mutation-or-network",
    )
    opened = set()
    for line in lines:
        if line.startswith("openat(") and re.search(r"\)\s+=\s+[0-9]+$", line):
            path, _, flags = line[len("openat(") :].partition(", ")[2].partition(", ")
            values = _literal_values(path)
            _require(len(values) == 1, "ambiguous-open-path")
            opened.add(os.fsdecode(values[0]))
            _require(
                "O_WRONLY" not in flags and "O_RDWR" not in flags and "O_CREAT" not in flags,
                "unexpected-file-write",
            )
    library = prefix + "/packages/lib/"
    required = {
        library + name
        for name in (
            "fishhat_host/__init__.py",
            "fishhat_host/cli.py",
            "fishhat_cli/validation.py",
            "fishhat_contracts/validation.py",
        )
    }
    _require(required | {program} <= opened, "missing-actual-owner-module-opens")
    installed_files = _expected_installation(inputs, profile)
    code_paths = {
        path
        for path in opened
        if path.endswith((".py", ".pyc")) or ".so" in PurePosixPath(path).name
    }
    _require(set(row["code_opens"]) == code_paths, "incomplete-code-origin-observations")
    for path in opened:
        _require(PurePosixPath(path).is_absolute(), "unsafe-open-origin")
        if path in code_paths:
            origin = row["code_opens"][path]
            resolved = origin["resolved"]
            _require(
                PurePosixPath(resolved).is_absolute() and ".." not in PurePosixPath(resolved).parts,
                "unsafe-resolved-origin",
            )
            if resolved.startswith(prefix + "/"):
                relative = resolved.removeprefix(prefix + "/")
                _require(
                    relative in installed_files and installed_files[relative]["kind"] == "regular",
                    "unclassified-installed-code",
                )
                _require(
                    origin["metadata"] == inputs["observed_installation"][relative],
                    "changed-observed-code",
                )
            else:
                # The dynamic loader reads its protected cache before selecting libraries.
                loader_cache = path == resolved == "/etc/ld.so.cache"
                platform = loader_cache or (
                    path != "/etc/ld.so.cache"
                    and ".so" in PurePosixPath(resolved).name
                    and PurePosixPath(resolved).name.startswith("lib")
                    and str(PurePosixPath(resolved).parent)
                    in ("/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu")
                )
                _require(platform and not path.startswith(prefix + "/"), "unapproved-code-origin")
                _file_metadata(origin["metadata"], {"kind": "regular"})
                _require(origin["metadata"]["mode"] & 0o6022 == 0, "unprotected-platform-code")
        request_input = row["arguments"][1] if label.endswith("-validate") else None
        _require(
            not path.startswith("/tmp/fishhat-entrypoint-fixture-") or path == request_input,
            "caller-file-opened",
        )
    if label.endswith("-validate"):
        # The request FIFO is the only caller-owned data opened by this read-only command.
        fifo = row["arguments"][1]
        _require(
            fifo.startswith(
                "/tmp/fishhat-entrypoint-fixture-" + c["enrollment"] + "/" + role + "/"
            ),
            "wrong-validation-input",
        )
        observation = row["observation"]
        uid, gid = (0, 0) if role == "root" else (c["peer_uid"], c["peer_gid"])
        _require(
            observation["pid"] == row["tracee_pid"]
            and observation["tracer_pid"] == row["tracer_pid"]
            and observation["pidfd_open"] is True,
            "foreign-proc-observer",
        )
        _require(
            observation["executable"] == interpreter
            and observation["process_group"] == observation["session"] == row["tracer_pid"],
            "wrong-live-executable",
        )
        _require(
            bytes.fromhex(observation["cmdline_hex"]) == b"\0".join(second[1]) + b"\0",
            "wrong-live-command-line",
        )
        _require(
            bytes.fromhex(observation["environment_hex"]) == b"LANG=C.UTF-8\0LC_ALL=C.UTF-8\0",
            "wrong-live-environment",
        )
        facts = observation["status"]
        _require(
            [int(value) for value in facts["Uid"].split()] == [uid] * 4
            and [int(value) for value in facts["Gid"].split()] == [gid] * 4,
            "wrong-live-principal",
        )
        groups = row["initial_group_selection"]
        _require(
            type(groups) is list
            and all(type(group) is int and group >= 0 for group in groups)
            and gid in groups
            and sorted(int(value) for value in facts["Groups"].split()) == sorted(groups),
            "changed-live-groups",
        )
        _require(
            int(facts["Pid"]) == row["tracee_pid"]
            and int(facts["PPid"]) == row["tracer_pid"]
            and observation["start_ticks"].isdigit(),
            "wrong-live-process-custody",
        )
        if uid:
            _require(
                all(int(facts[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")),
                "unexpected-live-capabilities",
            )
        _require(
            json.loads(row["stdout"])
            == {
                "tool": "host-ops",
                "status": "valid",
                "scope": "local-contracts-only",
                "production_qualified": False,
            },
            "failed-offline-validation",
        )
    else:
        _require(row["observation"] is None, "unexpected-proc-observation")
        if label.endswith("-help"):
            _require(
                "host-ops" in row["stdout"] and "validate" in row["stdout"], "missing-offline-help"
            )
        else:
            _info(row["stdout"])


def _info(raw: str) -> None:
    value = json.loads(raw)
    _require(
        value["tool"] == "host-ops"
        and value["implementation"] == "scaffold"
        and value["capabilities"] == ["local-contract-validation", "owner-state-identity"]
        and value["native_mutations"] is value["production_qualified"] is False,
        "wrong-installed-capabilities",
    )


def verify_observation(value: dict[str, Any], c: dict[str, Any]) -> None:
    inputs = c["inputs"]
    _require(
        value["scope"] == SCOPE
        and value["status"] == "passed"
        and value["native_product_qualified"] is False,
        "probe-not-passed",
    )
    _require(
        value["enrollment"] == c["enrollment"]
        and value["boot_id"] == c["boot_id"]
        and type(value["observer_pid"]) is int
        and value["observer_pid"] > 1
        and type(value["observer_uid"]) is int
        and value["observer_uid"] == 0,
        "foreign-observer",
    )
    _require(value["primary_error"] is None and value["cleanup_errors"] == [], "probe-error")
    _require(
        value["transfer"]["bytes"] == inputs["input_bytes"]
        and value["transfer"]["sha256"] == inputs["input_sha256"],
        "changed-transfer",
    )
    transfer = {
        name: {key: row[key] for key in ("bytes", "sha256")}
        for name, row in inputs["expected_inputs"].items()
        if row["kind"] == "regular" and not name.startswith("bundle/")
    }
    _require(value["transfer"]["members"] == transfer, "incomplete-transfer-custody")
    _require(value["inputs_before"] == value["inputs_after"], "changed-protected-inputs")
    nodes = _tree(value["inputs_before"], inputs["expected_inputs"])
    for name in PROFILES:
        _require(value[name + "_before"] == value[name + "_after"], "changed-installation")
        selected = _tree(value[name + "_before"], _expected_installation(inputs, name))
        _require(nodes.isdisjoint(selected), "reused-installation-custody")
        nodes |= selected
    _require(
        value["existing_refusal"]
        == value["interrupted_refusal"]
        == {"type": "FileExistsError", "errno": 17},
        "candidate-adopted",
    )
    interruption = value["interruption"]
    _require(
        type(interruption["pid"]) is int
        and interruption["pid"] > 1
        and interruption["returncode"] == -9
        and interruption["joined"] is True
        and interruption["announced"]
        == {"pid": interruption["pid"], "uid": 0, "boot_id": c["boot_id"]},
        "interruption-not-joined",
    )
    _require(
        [row["name"] for row in value["symlink_refusals"]] == ["destination-link", "parent-link"],
        "missing-symlink-refusals",
    )
    for row in value["symlink_refusals"]:
        _require(
            row["before"] == row["after"]
            and row["before"]["kind"] == "symlink"
            and row["target_child_absent"] is True
            and row["error"]["type"]
            in ("FileExistsError", "NotADirectoryError", "OSError", "ValueError"),
            "ineffective-symlink-refusal",
        )
    _require(value["observer_before"] == value["observer_after"], "changed-observer-closure")
    observed_nodes = _tree(value["observer_before"], inputs["expected_observer"])
    _require(nodes.isdisjoint(observed_nodes), "reused-observer-custody")
    tool = value["observer_tool"]
    _require(
        tool["package_original"] == "\t".join(OBSERVER_PACKAGE) + "\n"
        and tool["product_runtime_dependency"] is False
        and tool["offline"] is True,
        "wrong-observer-package",
    )
    _require(set(tool["packages"]) == set(OBSERVER_PINS), "incomplete-observer-packages")
    for name, pin in OBSERVER_PINS.items():
        package = tool["packages"][name]
        _require(
            type(package["bytes"]) is int
            and package["bytes"] == pin["bytes"]
            and package["sha256"] == pin["sha256"]
            and package["fields"]
            == {
                "Package": pin["package"],
                "Version": pin["version"],
                "Architecture": pin["architecture"],
            }
            and re.fullmatch("[0-9a-f]{64}", package["data_tar_sha256"]) is not None,
            "changed-observer-package",
        )
    preparation = tool["preparation_tool"]
    _require(
        preparation["path"] == "/usr/bin/dpkg-deb"
        and preparation["mode"] == "read-package-filesystem-only"
        and preparation["maintainer_scripts_executed"] is False
        and re.fullmatch("[0-9a-f]{64}", preparation["sha256"]) is not None,
        "unsafe-observer-preparation",
    )
    _require(
        tool["executable"] == value["observer_before"]["usr/bin/strace"]
        and tool["executable_path"]
        == "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/observer/usr/bin/strace",
        "wrong-observer-executable",
    )
    _require(
        [row["role"] for row in value["negative_controls"]] == ["root", "peer"],
        "missing-loader-controls",
    )
    for row in value["negative_controls"]:
        uid, gid = (0, 0) if row["role"] == "root" else (c["peer_uid"], c["peer_gid"])
        _principal(row["before"], uid, gid)
        _require(
            row["pid"] == row["before"]["pid"]
            and row["joined"] is True
            and type(row["returncode"]) is int
            and row["returncode"] == 0,
            "failed-loader-control",
        )
        _require(
            row["loader"]["path"]
            == "/tmp/fishhat-entrypoint-fixture-"
            + c["enrollment"]
            + "/"
            + row["role"]
            + "/negative-loader."
            + str(row["pid"])
            and row["loader"]["kind"] == "regular"
            and row["loader"]["uid"] == uid
            and row["loader"]["bytes"] > 0,
            "ineffective-loader-control",
        )
        _require(
            row["environment"]
            == _poison_environment(c["enrollment"])
            | {
                "LD_DEBUG_OUTPUT": "/tmp/fishhat-entrypoint-fixture-"
                + c["enrollment"]
                + "/"
                + row["role"]
                + "/negative-loader"
            },
            "ineffective-negative-poison",
        )
        binding = inputs["configuration"]["bindings"]["complete"]
        _require(
            row["argv"]
            == [
                binding["interpreter"]["path"],
                "-I",
                "-S",
                "-B",
                binding["program"]["path"],
                "info",
                "--json",
            ],
            "wrong-loader-control-program",
        )
        _info(row["stdout"])
    _require(
        [row["role"] for row in value["direct_invocations"]] == ["root", "peer"],
        "missing-direct-invocations",
    )
    for row in value["direct_invocations"]:
        uid, gid = (0, 0) if row["role"] == "root" else (c["peer_uid"], c["peer_gid"])
        _principal(row["before"], uid, gid)
        _require(
            row["pid"] == row["before"]["pid"]
            and row["joined"] is True
            and type(row["returncode"]) is int
            and row["returncode"] == 0
            and row["stderr"] == "",
            "failed-direct-invocation",
        )
        _require(
            row["environment"] == _poison_environment(c["enrollment"])
            and row["argv"]
            == [
                "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/complete/host-ops",
                "info",
                "--json",
            ],
            "changed-direct-context",
        )
        _info(row["stdout"])
    _require(
        [(row["role"], row["label"]) for row in value["traced_invocations"]]
        == [
            (role, role + "-" + label)
            for role in ("root", "peer")
            for label in ("help", "info", "validate")
        ],
        "incomplete-traced-invocations",
    )
    for row in value["traced_invocations"]:
        profile = "retry" if row["label"].endswith("-validate") else "complete"
        _trace(row, inputs | {"observed_installation": value[profile + "_before"]}, c)
    _require(
        [row["mode"] for row in value["refusals"]]
        == ["uid-mismatch", "gid-mismatch", "ambient", "setuid", "filecap"],
        "missing-credential-refusals",
    )
    for row in value["refusals"]:
        _require(
            row["traced"] is False
            and row["joined"] is True
            and row["returncode"] == 126
            and row["stdout"] == ""
            and row["stderr"] == "Unsupported invocation context\n",
            "ineffective-credential-refusal",
        )
        mode = row["mode"]
        source = inputs["builds"]["complete"]["files_original"]["launch"]
        _file_metadata(
            row["target"],
            {
                "kind": "regular",
                "mode": 0o4555 if mode == "setuid" else 0o555,
                "bytes": source["bytes"],
                "sha256": source["sha256"],
                "file_capability": "0100000200040000000000000000000000000000"
                if mode == "filecap"
                else None,
            },
        )
        before = row["before"]
        for key in ("uids", "gids"):
            _require(
                type(before[key]) is list
                and len(before[key]) == 3
                and all(type(item) is int and item >= 0 for item in before[key]),
                "invalid-original-refusal-credentials",
            )
        _require(
            type(before["pid"]) is int and before["pid"] == row["pid"] and before["groups"] == [],
            "ineffective-original-context",
        )
        if mode == "uid-mismatch":
            _require(
                before["uids"] == [c["peer_uid"], 0, 0] and before["gids"] == [0] * 3,
                "ineffective-uid-transition",
            )
        elif mode == "gid-mismatch":
            _require(
                before["gids"] == [c["peer_gid"], 0, 0] and before["uids"] == [0] * 3,
                "ineffective-gid-transition",
            )
        else:
            _require(
                before["uids"] == [c["peer_uid"]] * 3 and before["gids"] == [c["peer_gid"]] * 3,
                "wrong-refused-principal",
            )
            _require(
                all(
                    int(before["status"][key], 16) == (1 << 10 if mode == "ambient" else 0)
                    for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")
                ),
                "ineffective-capability-context",
            )
    _require(
        len(value["dispatch_refusals"]) == 4
        and all(
            row["joined"] is True and row["returncode"] == 2 and row["stdout"] == ""
            for row in value["dispatch_refusals"]
        ),
        "unexpected-mutation-dispatch",
    )
    denials = value["peer_denials"]
    _require(
        set(denials)
        == {
            "command-write",
            "program-write",
            "runtime-write",
            "library-write",
            "command-unlink",
            "create",
            "chmod",
            "rename",
        },
        "missing-peer-denials",
    )
    for row in denials.values():
        _principal(row["before"], c["peer_uid"], c["peer_gid"])
        _require(
            row["joined"] is True
            and type(row["returncode"]) is int
            and row["returncode"] != 0
            and "PermissionError" in row["stderr"],
            "ineffective-peer-denial",
        )
    administrative = value["administrative_refusal"]
    _principal(administrative["before"], c["peer_uid"], c["peer_gid"])
    _require(
        administrative["joined"] is administrative["candidate_absent"] is True
        and type(administrative["returncode"]) is int
        and administrative["returncode"] != 0
        and "protected staging requires Linux administrative custody" in administrative["stderr"],
        "ineffective-administrative-refusal",
    )
    expected = [
        "/tmp/fishhat-entrypoint-fixture-" + c["enrollment"],
        "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"],
    ]
    _require(
        [row["path"] for row in value["cleanup"]] == expected
        and all(row["removed"] is True for row in value["cleanup"]),
        "incomplete-owned-cleanup",
    )


def qualify_entrypoint(
    guest: Guest,
    temporary: Path,
    progress: Callable[[str], AbstractContextManager[None]],
    report: dict[str, Any],
    *,
    root_command: Callable[[list[str], str, float], None],
) -> None:
    if guest.observed is None:
        raise GuestBootError("guest-not-verified")
    metrics = RunStats()
    report.update(scope=SCOPE, status="failed", native_product_qualified=False)
    try:
        tools = owner_launcher.provision_tools(guest.command, root_command, progress)
        report["build_tools"] = tools
        with tempfile.TemporaryDirectory(prefix="fh-entrypoint-", dir=temporary) as directory:
            with progress("guest-owner-entrypoint-inputs"):
                path, inputs = _prepare_inputs(guest, Path(directory), tools)
            report["inputs"] = inputs
            peer = guest.observed["accounts"][guest.accounts[1]]
            c = {
                "scope": SCOPE,
                "identity_owner": native_linux_owner_identity.fixture_owner(guest.enrollment),
                "identity_trace_filter": native_linux_owner_identity.TRACE_FILTER,
                "enrollment": guest.enrollment,
                "boot_id": guest.observed["boot_id"],
                "peer_account": guest.accounts[1],
                "peer_uid": peer["uid"],
                "peer_gid": peer["gid"],
                "observer_package": list(OBSERVER_PACKAGE),
                "child_timeout": watchdog(180),
                "observer_pins": OBSERVER_PINS,
                **{
                    key: inputs[key]
                    for key in (
                        "input_sha256",
                        "input_bytes",
                        "bootstrap_sha256",
                        "interrupt_sha256",
                    )
                },
            }
            with progress("guest-protected-owner-entrypoint"):
                raw = guest.guarded(
                    ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(c)],
                    guest.enrollment,
                    guest.observed["boot_id"],
                    nominal=1200,
                    input_path=path,
                )
            report["original_reply_sha256"] = _checksum(raw.encode())
            try:
                value = json.loads(raw)
            except (ValueError, RecursionError):
                report["unparsed_original_reply"] = raw
                raise GuestBootError("owner-entrypoint-invalid-original-reply") from None
            report["original_observation"] = value
            paths = [
                "/var/lib/fishhat-entrypoint-fixture-" + guest.enrollment,
                "/tmp/fishhat-entrypoint-fixture-" + guest.enrollment,
            ]
            cleanup = guest.guarded(
                ["/usr/bin/python3", "-I", "-S", "-B", "-c", CLEANUP, json.dumps(paths)],
                guest.enrollment,
                guest.observed["boot_id"],
                nominal=30,
            )
            report["cleanup_observer_original_reply"] = cleanup
            checked = json.loads(cleanup)
            _require(
                type(checked["pid"]) is int
                and checked["pid"] > 1
                and checked["pid"] != value["observer_pid"]
                and type(checked["uid"]) is int
                and checked["uid"] == 0
                and checked["boot_id"] == c["boot_id"]
                and checked["enrollment"] == c["enrollment"]
                and checked["paths"] == [{"path": name, "absent": True} for name in paths],
                "independent-cleanup-unconfirmed",
            )
            try:
                verify_observation(value, c | {"inputs": inputs})
                native_linux_owner_identity.verify_observation(value, c | {"inputs": inputs})
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GuestBootError("owner-entrypoint-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-entrypoint-invalid-statistics")
