"""Observe the fixed launch primitive only in the enrolled disposable guest."""

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
from typing import Any

from scripts import owner_launcher
from scripts.bundle_install import OWNER_PYTHON_BYTES, OWNER_PYTHON_SHA256, OWNER_PYTHON_URL, sha256
from scripts.native_linux_guest import Guest, GuestBootError
from scripts.run_stats import RunStats, valid_stats
from scripts.validation import source_identity
from scripts.validation_timeouts import watchdog

SCOPE = "disposable-guest-fixed-static-launch-primitive-only"
SCALES = (0, 16, 64, 256)
ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
DENIALS = (
    "binary-write",
    "source-write",
    "program-write",
    "runtime-write",
    "manifest-unlink",
    "parent-create",
    "installed-chmod",
    "installed-replace",
)
REFUSALS = ("uid-mismatch", "gid-mismatch", "ambient", "setuid", "filecap")

OBSERVE = r"""
import errno,hashlib,json,os,pathlib,sys
c=json.loads(sys.argv[1])
def digest(path):
    with pathlib.Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
try:os.fstat(c['extra_fd'])
except OSError as error:assert error.errno==errno.EBADF
else:raise AssertionError('inherited descriptor available')
denied=[]
for name,path,operation in c['denials']:
    try:
        if operation=='write':descriptor=os.open(path,os.O_WRONLY|os.O_NONBLOCK);os.close(descriptor)
        elif operation=='unlink':pathlib.Path(path).unlink()
        elif operation=='create':descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(descriptor)
        elif operation=='chmod':pathlib.Path(path).chmod(0o777)
        else:pathlib.Path(path).rename(pathlib.Path(path).with_name('peer-replacement'))
    except OSError as error:
        assert error.errno in (errno.EACCES,errno.EPERM);denied.append({'name':name,'errno':error.errno})
    else:raise AssertionError('protected bytes changed')
with pathlib.Path(c['marker']).open('x') as stream:stream.write(c['nonce'])
result={'pid':os.getpid(),'parent_pid':os.getppid(),'uids':list(os.getresuid()),'gids':list(os.getresgid()),'groups':os.getgroups(),
        'capabilities':{key:line.split(':',1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() for key in ('CapEff','CapPrm','CapInh','CapAmb') if line.startswith(key+':')},
        'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'enrollment':pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip(),
        'environment':dict(os.environ),'cwd':os.getcwd(),'executable':sys.executable,'executable_sha256':digest(sys.executable),
        'program':__file__,'program_sha256':digest(__file__),'flags':{name:getattr(sys.flags,name) for name in ('isolated','ignore_environment','no_site','no_user_site','safe_path','dont_write_bytecode')},
        'sys_path':sys.path,'argv':sys.argv[2:],'nonce':c['nonce'],'extra_fd_closed':True,'denied':denied}
print(json.dumps(result,sort_keys=True))
"""

INTERRUPT = r"""
import hashlib,json,os,pathlib,sys,types
c=json.loads(sys.argv[1]);module=types.ModuleType('approved_launch_installer')
source=pathlib.Path(c['bootstrap_path']).read_bytes();assert hashlib.sha256(source).hexdigest()==c['bootstrap_sha256']
exec(compile(source,'<approved-bootstrap>','exec'),module.__dict__)
def pause(path):
    pending=pathlib.Path(c['ready']+'.pending')
    with pending.open('x') as stream:
        os.chmod(pending,0o600);json.dump({'pid':os.getpid(),'uid':os.geteuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()},stream);stream.flush();os.fsync(stream.fileno())
    os.replace(pending,c['ready'])
    assert sys.stdin.buffer.read(1)==b'never release'
    raise AssertionError('interrupted installer resumed')
module._verify_owner_launcher_elf=pause
module._install_owner_launcher(pathlib.Path(c['inputs']),pathlib.Path(c['interrupted']),c['manifest_sha256'])
"""

REMOTE = r"""
import base64,ctypes,errno,hashlib,json,os,pathlib,shutil,signal,stat,struct,subprocess,sys,time,types,uuid,zipfile
c=json.loads(sys.argv[1]);owned=[];child=None;stage='admission'
result={'scope':c['scope'],'status':'failed','native_product_qualified':False,'enrollment':c['enrollment'],'boot_id':c['boot_id'],
        'observer_pid':os.getpid(),'observer_uid':os.geteuid(),'primary_error':None,'cleanup_errors':[],'cleanup':[]}
def digest(path):
    with pathlib.Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def metadata(path):
    value=path.lstat();regular=stat.S_ISREG(value.st_mode)
    return {'device':value.st_dev,'inode':value.st_ino,'uid':value.st_uid,'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),'links':value.st_nlink,
            'kind':'regular' if regular else 'directory' if stat.S_ISDIR(value.st_mode) else 'other',
            **({'bytes':value.st_size,'sha256':digest(path),'file_capability':os.getxattr(path,'security.capability').hex() if 'security.capability' in os.listxattr(path) else None} if regular else {})}
def inventory(path):return {'.':metadata(path),**{p.name:metadata(p) for p in path.iterdir()}}
def principal():
    lines=pathlib.Path('/proc/self/status').read_text().splitlines()
    return {'pid':os.getpid(),'uids':list(os.getresuid()),'gids':list(os.getresgid()),'groups':os.getgroups(),
            'capabilities':{key:line.split(':',1)[1].strip() for line in lines for key in ('CapEff','CapPrm','CapInh','CapAmb') if line.startswith(key+':')}}
def invoke(argv,mode,poison=True):
    global child
    read_end,write_end=os.pipe2(os.O_CLOEXEC)
    extra=os.open(prefix/'inherited-input',os.O_RDONLY|os.O_NOFOLLOW)
    def credentials():
        os.setgroups([])
        if mode in ('peer','ambient'):
            os.setresgid(c['peer_gid'],c['peer_gid'],c['peer_gid'])
            if mode=='ambient':
                library=ctypes.CDLL(None,use_errno=True)
                assert library.prctl(8,1,0,0,0)==0
            os.setresuid(c['peer_uid'],c['peer_uid'],c['peer_uid'])
            if mode=='ambient':
                class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
                class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
                values=(Data*2)();values[0]=Data(1<<10,1<<10,1<<10)
                assert library.capset(ctypes.byref(Header(0x20080522,0)),values)==0
                assert library.prctl(47,2,10,0,0)==0
        elif mode=='uid-mismatch':os.setresuid(c['peer_uid'],0,0)
        elif mode=='gid-mismatch':os.setresgid(c['peer_gid'],0,0)
        else:os.setresgid(0,0,0);os.setresuid(0,0,0)
        os.set_inheritable(extra,True)
        before=principal();before['inherited_descriptor_open']=stat.S_ISREG(os.fstat(extra).st_mode);before['inherited_descriptor_inheritable']=os.get_inheritable(extra)
        packet=json.dumps(before).encode();assert os.write(write_end,packet)==len(packet)
    configuration=json.loads(argv[1]);configuration['extra_fd']=extra
    argv=[argv[0],json.dumps(configuration),*argv[2:]]
    environment=poison_environment if poison else {'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment,cwd=poison_root,
                               preexec_fn=credentials,pass_fds=(write_end,extra),start_new_session=True)
        pid=child.pid;os.close(write_end);write_end=None
        output,error=child.communicate(timeout=c['child_timeout'])
        packet=os.read(read_end,4096);assert os.read(read_end,1)==b''
        before=json.loads(packet);assert before['pid']==pid
        record={'pid':pid,'returncode':child.returncode,'before':before,'stdout':output.decode(),'stderr':error.decode(),'joined':child.poll() is not None,'extra_fd':extra}
        child=None;return record
    finally:
        for descriptor in (read_end,write_end,extra):
            if descriptor is not None:os.close(descriptor)
def rejection(inputs,destination,expected):
    try:module._install_owner_launcher(inputs,destination,expected)
    except (ValueError,OSError) as error:return {'type':type(error).__name__,'errno':getattr(error,'errno',None)}
    raise AssertionError('unsafe launch installation accepted')
try:
    assert os.geteuid()==0 and pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip()==c['enrollment']
    assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['boot_id']
    prefix=pathlib.Path('/var/lib/fishhat-launcher-fixture-'+c['enrollment'])
    poison_root=pathlib.Path('/tmp/fishhat-launcher-fixture-'+c['enrollment'])
    assert c['interpreter']['path']==str(prefix/'runtime/python/bin/python3.12') and c['program']['path']==str(prefix/'observe.py')
    for path,mode in ((prefix,0o755),(poison_root,0o700)):
        path.mkdir(mode=mode);owned.append((path,path.stat().st_dev,path.stat().st_ino))
    os.chown(poison_root,c['peer_uid'],c['peer_gid'])
    stage='prepare-inputs';inputs=prefix/'inputs';inputs.mkdir(mode=0o700)
    payload=sys.stdin.buffer.read();assert hashlib.sha256(payload).hexdigest()==c['input_sha256'] and len(payload)==c['input_bytes']
    import io
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert set(archive.namelist())=={'runtime.tar.gz','launch','launch.c','targets.h','launcher.json','install.py','observe.py','interrupt.py'}
        for name in archive.namelist():
            path=inputs/name if name in ('launch','launch.c','targets.h','launcher.json') else prefix/name
            with path.open('xb') as stream:os.chmod(path,0o600);stream.write(archive.read(name));stream.flush();os.fsync(stream.fileno())
    bootstrap=(prefix/'install.py').read_bytes();assert hashlib.sha256(bootstrap).hexdigest()==c['bootstrap_sha256']
    module=types.ModuleType('approved_launch_installer');exec(compile(bootstrap,'<approved-bootstrap>','exec'),module.__dict__)
    interpreter=module._install_owner_python(prefix/'runtime.tar.gz',prefix/'runtime')
    program=prefix/'observe.py'
    assert digest(program)==c['program']['sha256'] and digest(prefix/'interrupt.py')==c['interrupt_program_sha256']
    program.chmod(0o444)
    (prefix/'inherited-input').write_bytes(b'owned inherited descriptor canary\n');(prefix/'inherited-input').chmod(0o444)
    hook=poison_root/'hook'
    hook.write_text("raise RuntimeError('poison hook executed')\n");hook.chmod(0o755)
    for name in ('sitecustomize.py','usercustomize.py','python','sh'):
        (poison_root/name).write_text("raise RuntimeError('poison import executed')\n");(poison_root/name).chmod(0o755)
    poison_environment={'LANG':'invalid_fixture_locale','LC_ALL':'invalid_fixture_locale','HOME':str(poison_root),'PATH':str(poison_root),
                        'PYTHONHOME':str(poison_root),'PYTHONPATH':str(poison_root),'PYTHONSTARTUP':str(hook),'ENV':str(hook),'BASH_ENV':str(hook),'LD_PRELOAD':str(poison_root/'unapproved-loader.so'),'LD_LIBRARY_PATH':str(poison_root)}
    stage='complete-install';complete=prefix/'complete';interrupted=prefix/'interrupted';retry=prefix/'retry'
    executable=module._install_owner_launcher(inputs,complete,c['manifest_sha256'])
    result['targets_before']={'interpreter':metadata(interpreter),'program':metadata(program)};result['inputs_before']=inventory(inputs);result['complete_before']=inventory(complete)
    result['existing_refusal']=rejection(inputs,complete,c['manifest_sha256'])
    ready=prefix/'interruption-ready.json';stage='interrupted-install'
    interrupted_configuration={**c,'inputs':str(inputs),'interrupted':str(interrupted),'ready':str(ready),'bootstrap_path':str(prefix/'install.py')}
    child=subprocess.Popen([sys.executable,'-I','-S','-B',str(prefix/'interrupt.py'),json.dumps(interrupted_configuration)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
    deadline=time.monotonic()+c['child_timeout']
    while not ready.exists():
        assert child.poll() is None and time.monotonic()<deadline
        time.sleep(0.02)
    announced=json.loads(ready.read_text());assert announced['pid']==child.pid and announced['uid']==0 and announced['boot_id']==c['boot_id'] and child.poll() is None
    killed_pid=child.pid;child.kill();child.communicate(timeout=c['child_timeout']);assert child.returncode==-signal.SIGKILL
    result['interruption']={'pid':killed_pid,'announced':announced,'returncode':child.returncode,'joined':child.poll() is not None};child=None
    result['interrupted_before']=inventory(interrupted);result['interrupted_refusal']=rejection(inputs,interrupted,c['manifest_sha256'])
    retry_executable=module._install_owner_launcher(inputs,retry,c['manifest_sha256']);result['retry_before']=inventory(retry)
    stage='actual-launch';result['invocations']=[]
    denials=[('binary-write',str(executable),'write'),('source-write',str(complete/'launch.c'),'write'),('program-write',str(program),'write'),('runtime-write',str(interpreter),'write'),
             ('manifest-unlink',str(complete/'launcher.json'),'unlink'),('parent-create',str(prefix/'peer-created'),'create'),('installed-chmod',str(complete),'chmod'),('installed-replace',str(complete),'rename')]
    literals=['','-I','-c','--interpreter=/unapproved/python','$(unapproved-command); literal','unicode-π','line\ntext','non-utf8-\udcff']
    for role in ('root','peer'):
        for scale in c['scales']:
            nonce=uuid.uuid4().hex;marker=poison_root/('marker-'+nonce)
            arguments=literals+[str(index)+':literal' for index in range(scale)]
            configuration={'marker':str(marker),'nonce':nonce,'denials':denials if role=='peer' and scale==0 else [],'extra_fd':None}
            selected=retry_executable if scale==c['scales'][-1] else executable
            record=invoke([str(selected),json.dumps(configuration),*arguments],role)
            record['launcher_path']=str(selected);record['launcher']=metadata(selected)
            assert record['returncode']==0 and record['stderr']=='' and marker.read_text()==nonce
            observation=json.loads(record.pop('stdout'));record.update(role=role,scale=scale,nonce=nonce,arguments=arguments,observation=observation,marker=metadata(marker))
            assert observation['extra_fd_closed']
            result['invocations'].append(record)
    stage='unsupported-contexts';result['refusals']=[]
    for mode in ('uid-mismatch','gid-mismatch','ambient','setuid','filecap'):
        target=executable
        if mode in ('setuid','filecap'):
            target=prefix/('unsafe-'+mode);shutil.copyfile(executable,target);target.chmod(0o4555 if mode=='setuid' else 0o555)
            if mode=='filecap':os.setxattr(target,'security.capability',struct.pack('<IIIII',0x02000001,1<<10,0,0,0))
        nonce=uuid.uuid4().hex;marker=poison_root/('refused-'+nonce)
        configuration={'marker':str(marker),'nonce':nonce,'denials':[],'extra_fd':-1}
        record=invoke([str(target),json.dumps(configuration),'literal'],mode if mode not in ('setuid','filecap') else 'peer')
        assert record['returncode']==126 and record['stdout']=='' and record['stderr']=='Unsupported invocation context\n' and not marker.exists()
        record.update(mode=mode,marker_absent=True,target=metadata(target));result['refusals'].append(record)
    result['targets_after']={'interpreter':metadata(interpreter),'program':metadata(program)};result['inputs_after']=inventory(inputs)
    result['complete_after']=inventory(complete);result['interrupted_after']=inventory(interrupted);result['retry_after']=inventory(retry)
    result['retry_executable_sha256']=digest(retry_executable)
    result['status']='passed'
except BaseException as error:result['primary_error']={'stage':stage,'type':type(error).__name__,'message':str(error)}
finally:
    if child is not None:
        try:
            if child.poll() is None:child.kill()
            child.communicate(timeout=c['child_timeout']);assert child.poll() is not None
            child=None
        except BaseException as error:result['cleanup_errors'].append({'stage':'child-join','type':type(error).__name__})
    if child is None:
        for path,device,inode in reversed(owned):
            try:
                value=path.lstat();assert stat.S_ISDIR(value.st_mode) and (value.st_dev,value.st_ino)==(device,inode)
                shutil.rmtree(path);assert not path.exists() and not path.is_symlink()
                result['cleanup'].append({'path':str(path),'device':device,'inode':inode,'removed':True})
            except BaseException as error:result['cleanup_errors'].append({'path':str(path),'type':type(error).__name__})
    if result['cleanup_errors']:result['status']='failed'
print(json.dumps(result,sort_keys=True))
"""

CLEANUP = r"""
import json,os,pathlib,sys
paths=json.loads(sys.argv[1])
print(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  'enrollment':pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip(),
                  'paths':[{'path':path,'absent':not pathlib.Path(path).exists() and not pathlib.Path(path).is_symlink()} for path in paths]},sort_keys=True))
"""


def _prepare_inputs(
    guest: Guest, directory: Path, tools: dict[str, Any]
) -> tuple[Path, dict[str, Any]]:
    """Compile only on the already enrolled hosted worker, never execute output."""
    source = source_identity()
    if not source["clean"]:
        raise GuestBootError("owner-launcher-source-not-clean")
    guest.command(
        [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(Path(__file__).with_name("native_owner_python_download.py")),
            str(directory / "runtime.tar.gz"),
            OWNER_PYTHON_URL,
            str(OWNER_PYTHON_BYTES),
            OWNER_PYTHON_SHA256,
            str(watchdog(30)),
        ],
        "owner-launcher-runtime-download",
        180,
    )
    with tarfile.open(directory / "runtime.tar.gz", "r:gz") as distribution:
        executable = distribution.extractfile("python/bin/python3.12")
        if executable is None:
            raise GuestBootError("owner-launcher-runtime-executable-unavailable")
        with executable:
            checksum = hashlib.sha256()
            while chunk := executable.read(1_048_576):
                checksum.update(chunk)
            executable_hash = checksum.hexdigest()
    prefix = "/var/lib/fishhat-launcher-fixture-" + guest.enrollment
    interpreter = {"path": prefix + "/runtime/python/bin/python3.12", "sha256": executable_hash}
    program = {
        "path": prefix + "/observe.py",
        "sha256": hashlib.sha256(OBSERVE.encode()).hexdigest(),
    }
    built = owner_launcher.build(
        guest.command, directory / "build", interpreter=interpreter, program=program, tools=tools
    )
    files = {}
    for name in ("launch", "launch.c", "targets.h", "launcher.json"):
        raw = (directory / "build" / name).read_bytes()
        files[name] = {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "base64": base64.b64encode(raw).decode(),
        }
    bootstrap = Path(__file__).with_name("bundle_install.py").read_bytes()
    path = directory / "inputs.zip"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.write(directory / "runtime.tar.gz", "runtime.tar.gz")
            for name in files:
                archive.write(directory / "build" / name, name)
            for name, raw in (
                ("install.py", bootstrap),
                ("observe.py", OBSERVE.encode()),
                ("interrupt.py", INTERRUPT.encode()),
            ):
                archive.writestr(name, raw)
        stream.flush()
        os.fsync(stream.fileno())
    return path, {
        "source": source,
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "input_sha256": sha256(path),
        "input_bytes": path.stat().st_size,
        "runtime_archive_sha256": OWNER_PYTHON_SHA256,
        "runtime_archive_bytes": OWNER_PYTHON_BYTES,
        "interpreter": interpreter,
        "program": program,
        "manifest_sha256": built["manifest_sha256"],
        "bootstrap_sha256": hashlib.sha256(bootstrap).hexdigest(),
        "interrupt_program_sha256": hashlib.sha256(INTERRUPT.encode()).hexdigest(),
        "launcher_files_original": files,
        "observe_program_original_base64": base64.b64encode(OBSERVE.encode()).decode(),
        "interrupt_program_original_base64": base64.b64encode(INTERRUPT.encode()).decode(),
        "build": built["manifest"]["build"],
    }


def _require(value: bool, reason: str) -> None:
    if not value:
        raise GuestBootError("owner-launcher-" + reason)


def _metadata(row: dict[str, Any], *, regular: bool) -> None:
    for name in ("device", "inode", "uid", "gid", "mode", "links"):
        _require(type(row[name]) is int and row[name] >= 0, "invalid-file-metadata")
    _require(
        row["inode"] > 0 and row["kind"] == ("regular" if regular else "directory"),
        "invalid-file-kind",
    )
    if regular:
        _require(
            type(row["bytes"]) is int
            and row["bytes"] >= 0
            and isinstance(row["sha256"], str)
            and len(row["sha256"]) == 64
            and set(row["sha256"]) <= set("0123456789abcdef"),
            "invalid-file-identity",
        )


def _principal(row: dict[str, Any]) -> None:
    _require(type(row["pid"]) is int and row["pid"] > 1, "invalid-process-identity")
    for name in ("uids", "gids"):
        _require(
            isinstance(row[name], list)
            and len(row[name]) == 3
            and all(type(value) is int and value >= 0 for value in row[name]),
            "invalid-credentials",
        )
    _require(
        isinstance(row["groups"], list)
        and all(type(value) is int and value >= 0 for value in row["groups"]),
        "invalid-groups",
    )
    _require(
        set(row["capabilities"]) == {"CapEff", "CapPrm", "CapInh", "CapAmb"}
        and all(
            isinstance(value, str) and len(value) == 16 and set(value) <= set("0123456789abcdef")
            for value in row["capabilities"].values()
        ),
        "invalid-capabilities",
    )


def _tree(value: dict[str, Any], files: dict[str, Any], *, sealed: bool) -> set[tuple[int, int]]:
    _require(set(value) == {".", *files}, "incomplete-file-closure")
    root = value["."]
    _metadata(root, regular=False)
    _require(
        root["kind"] == "directory"
        and root["uid"] == root["gid"] == 0
        and root["mode"] == (0o555 if sealed else 0o700),
        "unprotected-installation",
    )
    identities = {(root["device"], root["inode"])}
    for name, expected in files.items():
        row = value[name]
        _metadata(row, regular=True)
        _require(
            row["kind"] == "regular"
            and row["uid"] == row["gid"] == 0
            and row["links"] == 1
            and row["file_capability"] is None,
            "unprotected-input-file",
        )
        _require(
            row["mode"] == ((0o555 if name == "launch" else 0o444) if sealed else 0o600),
            "unsafe-file-mode",
        )
        _require(
            row["bytes"] == expected["bytes"] and row["sha256"] == expected["sha256"],
            "changed-input-file",
        )
        identities.add((row["device"], row["inode"]))
    _require(len(identities) == len(files) + 1, "aliased-input-files")
    return identities


def verify_observation(value: dict[str, Any], c: dict[str, Any]) -> None:
    _require(
        value["scope"] == SCOPE
        and value["status"] == "passed"
        and value["native_product_qualified"] is False,
        "probe-not-passed",
    )
    _require(
        value["enrollment"] == c["enrollment"]
        and value["boot_id"] == c["boot_id"]
        and value["observer_uid"] == 0
        and value["observer_pid"] > 1,
        "foreign-observer",
    )
    _require(value["primary_error"] is None and value["cleanup_errors"] == [], "probe-error")
    originals = c["launcher_files_original"]
    complete = _tree(value["complete_before"], originals, sealed=True)
    retry = _tree(value["retry_before"], originals, sealed=True)
    interrupted = _tree(value["interrupted_before"], originals, sealed=False)
    _require(
        complete.isdisjoint(retry | interrupted) and retry.isdisjoint(interrupted),
        "reused-candidate-identity",
    )
    for name in ("complete", "interrupted", "retry", "inputs", "targets"):
        _require(value[name + "_before"] == value[name + "_after"], "protected-bytes-changed")
    _tree(value["inputs_before"], originals, sealed=False)
    for name, mode in (("interpreter", 0o555), ("program", 0o444)):
        row = value["targets_before"][name]
        _metadata(row, regular=True)
        _require(
            row["kind"] == "regular"
            and row["uid"] == row["gid"] == 0
            and row["mode"] == mode
            and row["links"] == 1
            and row["file_capability"] is None
            and row["sha256"] == c[name]["sha256"],
            "unprotected-target",
        )
    _require(
        value["existing_refusal"]["type"]
        == value["interrupted_refusal"]["type"]
        == "FileExistsError",
        "candidate-reused",
    )
    interrupted_process = value["interruption"]
    _require(
        type(interrupted_process["pid"]) is int and interrupted_process["pid"] > 1,
        "invalid-interruption-identity",
    )
    _require(
        interrupted_process["joined"] is True
        and interrupted_process["returncode"] == -9
        and interrupted_process["announced"]
        == {"pid": interrupted_process["pid"], "uid": 0, "boot_id": c["boot_id"]},
        "interruption-not-joined",
    )
    expected = {(role, scale) for role in ("root", "peer") for scale in SCALES}
    invocations = value["invocations"]
    _require(
        len(invocations) == len(expected)
        and {(row["role"], row["scale"]) for row in invocations} == expected,
        "incomplete-invocations",
    )
    pids = {interrupted_process["pid"]}
    nonces = set()
    for row in invocations:
        observation = row["observation"]
        _principal(row["before"])
        _principal(observation)
        _metadata(row["launcher"], regular=True)
        _metadata(row["marker"], regular=True)
        _require(
            type(row["scale"]) is int
            and row["scale"] in SCALES
            and isinstance(row["nonce"], str)
            and len(row["nonce"]) == 32
            and set(row["nonce"]) <= set("0123456789abcdef"),
            "invalid-invocation-extent",
        )
        uid, gid = (0, 0) if row["role"] == "root" else (c["peer_uid"], c["peer_gid"])
        _require(
            row["joined"] is True
            and row["returncode"] == 0
            and row["stderr"] == ""
            and observation["pid"] == row["pid"] == row["before"]["pid"]
            and observation["parent_pid"] == value["observer_pid"],
            "foreign-invocation",
        )
        _require(
            observation["uids"] == row["before"]["uids"] == [uid] * 3
            and observation["gids"] == row["before"]["gids"] == [gid] * 3
            and observation["groups"] == row["before"]["groups"] == [],
            "changed-principal",
        )
        _require(
            observation["capabilities"] == row["before"]["capabilities"]
            and (
                uid == 0 or all(int(raw, 16) == 0 for raw in observation["capabilities"].values())
            ),
            "changed-capabilities",
        )
        _require(
            observation["boot_id"] == c["boot_id"]
            and observation["enrollment"] == c["enrollment"]
            and observation["environment"] == ENVIRONMENT
            and all(
                observation["flags"].get(name) == 1
                for name in (
                    "isolated",
                    "ignore_environment",
                    "no_site",
                    "no_user_site",
                    "safe_path",
                    "dont_write_bytecode",
                )
            ),
            "unsafe-process-context",
        )
        _require(
            observation["executable"] == c["interpreter"]["path"]
            and observation["executable_sha256"] == c["interpreter"]["sha256"]
            and observation["program"] == c["program"]["path"]
            and observation["program_sha256"] == c["program"]["sha256"]
            and observation["extra_fd_closed"] is True,
            "substituted-target",
        )
        prefix = "/var/lib/fishhat-launcher-fixture-" + c["enrollment"]
        selected = "retry" if row["scale"] == SCALES[-1] else "complete"
        _require(
            row["launcher_path"] == prefix + "/" + selected + "/launch"
            and row["launcher"] == value[selected + "_before"]["launch"]
            and row["before"]["inherited_descriptor_open"] is True
            and row["before"]["inherited_descriptor_inheritable"] is True,
            "unproved-original-launch-input",
        )
        runtime = str(Path(c["interpreter"]["path"]).parent.parent)
        _require(
            observation["cwd"] == "/tmp/fishhat-launcher-fixture-" + c["enrollment"]
            and isinstance(observation["sys_path"], list)
            and bool(observation["sys_path"])
            and all(
                isinstance(path, str)
                and path.startswith(runtime + "/")
                and ".." not in Path(path).parts
                for path in observation["sys_path"]
            ),
            "unsafe-import-path",
        )
        literals = [
            "",
            "-I",
            "-c",
            "--interpreter=/unapproved/python",
            "$(unapproved-command); literal",
            "unicode-π",
            "line\ntext",
            "non-utf8-\udcff",
        ]
        arguments = literals + [str(index) + ":literal" for index in range(row["scale"])]
        _require(row["arguments"] == observation["argv"] == arguments, "incomplete-arguments")
        _require(
            observation["nonce"] == row["nonce"]
            and row["marker"]["uid"] == uid
            and row["marker"]["gid"] == gid
            and row["marker"]["mode"] == 0o600
            and row["marker"]["bytes"] == len(row["nonce"]),
            "foreign-execution-marker",
        )
        _require(
            row["marker"]["sha256"] == hashlib.sha256(row["nonce"].encode()).hexdigest()
            and row["marker"]["links"] == 1
            and row["marker"]["file_capability"] is None,
            "changed-execution-marker",
        )
        names = [item["name"] for item in observation["denied"]]
        _require(
            names == (list(DENIALS) if row["role"] == "peer" and row["scale"] == 0 else [])
            and all(item["errno"] in (1, 13) for item in observation["denied"]),
            "missing-peer-denial",
        )
        _require(row["pid"] not in pids and row["nonce"] not in nonces, "replayed-process")
        pids.add(row["pid"])
        nonces.add(row["nonce"])
    refusals = value["refusals"]
    _require([row["mode"] for row in refusals] == list(REFUSALS), "missing-context-refusal")
    for row in refusals:
        _principal(row["before"])
        _metadata(row["target"], regular=True)
        _require(
            row["target"]["sha256"] == originals["launch"]["sha256"]
            and row["target"]["uid"] == row["target"]["gid"] == 0
            and row["target"]["links"] == 1,
            "substituted-refusal-binary",
        )
        _require(
            row["returncode"] == 126
            and row["stdout"] == ""
            and row["stderr"] == "Unsupported invocation context\n"
            and row["joined"] is True
            and row["marker_absent"] is True
            and row["pid"] == row["before"]["pid"]
            and row["pid"] not in pids,
            "unsupported-context-entered-program",
        )
        pids.add(row["pid"])
        if row["mode"] == "uid-mismatch":
            _require(row["before"]["uids"] == [c["peer_uid"], 0, 0], "ineffective-uid-control")
        elif row["mode"] == "gid-mismatch":
            _require(row["before"]["gids"] == [c["peer_gid"], 0, 0], "ineffective-gid-control")
        elif row["mode"] == "ambient":
            _require(
                row["before"]["uids"] == [c["peer_uid"]] * 3
                and all(int(raw, 16) == 1 << 10 for raw in row["before"]["capabilities"].values()),
                "ineffective-capability-control",
            )
        elif row["mode"] == "setuid":
            _require(
                row["target"]["mode"] == 0o4555 and row["target"]["uid"] == 0,
                "ineffective-setuid-control",
            )
        else:
            _require(
                row["target"]["file_capability"] == "0100000200040000000000000000000000000000",
                "ineffective-filecap-control",
            )
    prefix = "/var/lib/fishhat-launcher-fixture-" + c["enrollment"]
    _require(
        {row["path"] for row in value["cleanup"]}
        == {prefix, "/tmp/fishhat-launcher-fixture-" + c["enrollment"]}
        and len(value["cleanup"]) == 2
        and all(row["removed"] is True for row in value["cleanup"]),
        "missing-owned-cleanup",
    )
    _require(
        value["retry_executable_sha256"] == originals["launch"]["sha256"],
        "changed-retry-executable",
    )


def qualify_launcher(
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
        with tempfile.TemporaryDirectory(prefix="fh-launcher-", dir=temporary) as directory:
            with progress("guest-owner-launcher-inputs"):
                path, inputs = _prepare_inputs(guest, Path(directory), tools)
            report["inputs"] = inputs
            peer = guest.observed["accounts"][guest.accounts[1]]
            c = {
                name: inputs[name]
                for name in (
                    "input_sha256",
                    "input_bytes",
                    "manifest_sha256",
                    "interpreter",
                    "program",
                    "bootstrap_sha256",
                    "interrupt_program_sha256",
                )
            }
            c.update(
                scope=SCOPE,
                enrollment=guest.enrollment,
                boot_id=guest.observed["boot_id"],
                peer_uid=peer["uid"],
                peer_gid=peer["gid"],
                child_timeout=watchdog(180),
                scales=list(SCALES),
            )
            with progress("guest-owner-static-launcher"):
                raw = guest.guarded(
                    ["/usr/bin/python3", "-I", "-S", "-B", "-c", REMOTE, json.dumps(c)],
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
                raise GuestBootError("owner-launcher-invalid-original-reply") from None
            report["original_observation"] = value
            paths = [
                "/var/lib/fishhat-launcher-fixture-" + guest.enrollment,
                "/tmp/fishhat-launcher-fixture-" + guest.enrollment,
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
                checked["uid"] == 0
                and checked["pid"] > 1
                and checked["pid"] != value["observer_pid"]
                and checked["boot_id"] == c["boot_id"]
                and checked["enrollment"] == c["enrollment"]
                and checked["paths"] == [{"path": name, "absent": True} for name in paths],
                "independent-cleanup-unconfirmed",
            )
            try:
                verify_observation(
                    value, c | {"launcher_files_original": inputs["launcher_files_original"]}
                )
            except (KeyError, TypeError, ValueError, AttributeError):
                raise GuestBootError("owner-launcher-invalid-observation-shape") from None
            report["status"] = "passed"
    finally:
        report["qualification_statistics"] = metrics.finish()
        if not valid_stats(report["qualification_statistics"]):
            raise GuestBootError("owner-launcher-invalid-statistics")
