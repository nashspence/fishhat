"""Installed identity observations inside the enrolled entrypoint fixture only."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

SCOPE = "disposable-guest-protected-owner-identity-only"
TRACE_FILTER = "trace=%file,%process,%creds,%network,umask,close_range,close,fsync,fdatasync,flock,fchmod,write,pwrite64,writev,pwritev,pwritev2,ftruncate,fallocate"


def fixture_owner(enrollment: str) -> dict[str, str]:
    namespace = uuid.UUID(enrollment)
    return {
        "tool": "host-ops",
        "id": str(uuid.uuid5(namespace, "protected-owner-identity")),
        "epoch": str(uuid.uuid5(namespace, "protected-owner-identity-epoch")),
    }


REMOTE_HELPERS = r"""
identity_children=[]
def identity_arguments(action,path,owner=None):
    owner=c['identity_owner'] if owner is None else owner
    return ['state',action,str(path),'--owner-id',owner['id'],'--owner-epoch',owner['epoch'],'--json']
def identity_snapshot(path):
    import base64
    entries={};originals={}
    for entry in path.iterdir():
        entries[entry.name]=metadata(entry)|{'mtime_ns':entry.lstat().st_mtime_ns,'ctime_ns':entry.lstat().st_ctime_ns}
        if entry.is_file() and not entry.is_symlink():originals[entry.name]=base64.b64encode(entry.read_bytes()).decode()
    return {'directory':metadata(path)|{'mtime_ns':path.lstat().st_mtime_ns,'ctime_ns':path.lstat().st_ctime_ns},'entries':entries,'original_files_base64':originals}
def identity_direct(command,action,path,role='root',owner=None):
    record=direct([str(command),*identity_arguments(action,path,owner)],role,poisoned)
    record.update(role=role,environment=poisoned)
    return record
def identity_reply(record,action,success=True):
    assert record['joined'] is True
    if success:
        assert record['returncode']==0 and record['stderr']==''
        value=json.loads(record['stdout']);assert value=={'tool':'host-ops','status':'initialized' if action=='initialize' else 'verified',
              'owner':c['identity_owner'],'schema_revision':'v1_0003','generation':0,'native_mutations':False,'production_qualified':False}
    else:
        assert record['returncode']==2 and record['stdout']==''
        expected={'tool':'host-ops','status':'unconfirmed' if action=='initialize' else 'invalid',
                  'error':'OWNER_INITIALIZATION_UNCONFIRMED' if action=='initialize' else 'OWNER_STATE_REJECTED'}
        assert json.loads(record['stderr'])==expected

def identity_spawn(command,action,path,label,inject=None):
    account='root';environment=poisoned|{'LD_DEBUG_OUTPUT':str(poison/'root'/('positive-loader-'+label))}
    binding=configuration['bindings']['complete'];arguments=identity_arguments(action,path)
    strings=[str(command),binding['interpreter']['path'],binding['program']['path'],*arguments,*[key+'='+value for key,value in environment.items()]]
    strings.append(json.dumps({'tool':'host-ops','status':'initialized','owner':c['identity_owner'],'schema_revision':'v1_0003','generation':0,'native_mutations':False,'production_qualified':False},sort_keys=True)+'\n')
    longest=max(len(os.fsencode(str(prefix/'complete'/name))) for name in result['complete_before'])
    limit=max(longest,max(len(os.fsencode(value)) for value in strings))+1
    tracebase=traces/label
    argv=[str(observer/'usr/bin/strace'),'-ff','--kill-on-exit','-s',str(limit),'-xx','-v','-q','-e',c['identity_trace_filter'],'-o',str(tracebase),'-u',account]
    if inject is not None:argv.append(inject)
    argv += [value for key,item in environment.items() for value in ('-E',key+'='+item)]
    argv += [str(command),*arguments]
    process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=observer_env,cwd=poison,close_fds=True,start_new_session=True)
    entry={'process':process,'pid':process.pid,'label':label,'arguments':arguments,'command':str(command),'environment':environment,
           'observer_argv':argv,'observer_environment':observer_env,'string_limit':limit,'initial_group_selection':os.getgrouplist('root',0)}
    identity_children.append(entry);return entry

def identity_finish(entry):
    process=entry['process'];output,error=process.communicate(timeout=c['child_timeout']);assert process.poll() is not None
    files=list(traces.glob(entry['label']+'.*'));assert len(files)==1
    pid=int(files[0].name.rsplit('.',1)[1]);trace_pids.add(pid)
    deadline=time.monotonic()+c['child_timeout']
    while pathlib.Path('/proc/'+str(pid)).exists():
        assert time.monotonic()<deadline;time.sleep(0.02)
    raw=files[0].read_text();origins={}
    for line in raw.splitlines():
        if line.startswith('openat(') and re.search(r'\)\s+=\s+[0-9]+$',line):
            raw_path=line[len('openat('):].partition(', ')[2].partition(', ')[0]
            match=re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"',raw_path);assert match is not None
            path=os.fsdecode(bytes.fromhex(match[1].replace('\\x','')))
            if path.endswith(('.py','.pyc')) or '.so' in pathlib.PurePosixPath(path).name:
                resolved=(pathlib.Path(path) if pathlib.Path(path).is_absolute() else poison/path).resolve(strict=True)
                origins[path]={'resolved':str(resolved),'metadata':metadata(resolved)}
    record={key:value for key,value in entry.items() if key not in ('process','pid')}
    record.update(role='root',tracer_pid=entry['pid'],tracee_pid=pid,code_opens=origins,returncode=process.returncode,
                  stdout=output.decode(),stderr=error.decode(),tracer_joined=True,tracee_absent=True,joined=True,
                  trace_original=raw,trace_metadata=metadata(files[0]),positive_loader_files=[p.name for p in (poison/'root').glob('positive-loader-'+entry['label']+'.*')])
    assert not record['positive_loader_files'];return record

def identity_stopped(entry,path):
    deadline=time.monotonic()+c['child_timeout'];pid=None
    while True:
        assert entry['process'].poll() is None and time.monotonic()<deadline
        files=list(traces.glob(entry['label']+'.*'))
        if len(files)==1:
            pid=int(files[0].name.rsplit('.',1)[1]);trace_pids.add(pid);proc=pathlib.Path('/proc')/str(pid)
            try:
                state=next(line.split()[1] for line in (proc/'status').read_text().splitlines() if line.startswith('State:'))
                if state in ('T','t') and 'SIGSTOP' in files[0].read_text() and (path/'.initializing').is_file() and not (path/'owner.sqlite3').exists():break
            except FileNotFoundError:pass
        time.sleep(0.02)
    descriptor=os.pidfd_open(pid);proc=pathlib.Path('/proc')/str(pid);first=(proc/'stat').read_text()
    facts={'pid':pid,'tracer_pid':entry['pid'],'start_ticks':first.rsplit(')',1)[1].split()[19],'status':status(pid),
           'state':state,'executable':os.readlink(proc/'exe'),'cmdline_hex':(proc/'cmdline').read_bytes().hex(),
           'environment_hex':(proc/'environ').read_bytes().hex(),'process_group':os.getpgid(pid),'session':os.getsid(pid),'pidfd_open':True}
    assert facts['start_ticks']==(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    return descriptor,facts

def identity_cleanup():
    errors=[];records=[]
    for entry in identity_children:
        process=entry['process']
        try:
            if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
            process.communicate(timeout=c['child_timeout']);assert process.poll() is not None
            records.append({'label':entry['label'],'pid':entry['pid'],'joined':True,'returncode':process.returncode})
        except BaseException as error:errors.append({'stage':'identity-child-join','type':type(error).__name__})
    return records,errors

def owner_identity_probe(command):
    import base64,sqlite3,uuid
    started=time.monotonic();root=prefix/'identity';root.mkdir(mode=0o700)
    proof={'scope':'disposable-guest-protected-owner-identity-only','status':'failed','native_owner_qualified':False,
           'owner':c['identity_owner'],'root':str(root),'traced_invocations':[],'refusals':[]}
    def fresh(name):
        path=root/name;path.mkdir(mode=0o700);return path
    valid=fresh('valid');before=identity_snapshot(valid)
    initialized=identity_finish(identity_spawn(command,'initialize',valid,'root-identity-initialize'));identity_reply(initialized,'initialize')
    proof['traced_invocations'].append(initialized);valid_after=identity_snapshot(valid)
    inspected=identity_finish(identity_spawn(command,'inspect',valid,'root-identity-inspect'));identity_reply(inspected,'inspect')
    proof['traced_invocations'].append(inspected);assert identity_snapshot(valid)==valid_after
    proof['genesis']={'before':before,'after':valid_after,'inspection_after':identity_snapshot(valid)}
    def refuse(label,path,action='inspect',role='root',owner=None):
        first=identity_snapshot(path);reply=identity_direct(command,action,path,role,owner);identity_reply(reply,action,False)
        last=identity_snapshot(path);assert first==last
        proof['refusals'].append({'label':label,'path':str(path),'action':action,'role':role,'expected_owner':c['identity_owner'] if owner is None else owner,'before':first,'after':last,'invocation':reply})
    refuse('existing-identity',valid,'initialize');refuse('peer-initialize',valid,'initialize','peer');refuse('peer-inspect',valid,'inspect','peer')
    other_id=dict(c['identity_owner']);other_id['id']=str(uuid.uuid5(uuid.UUID(c['enrollment']),'foreign-owner'))
    other_epoch=dict(c['identity_owner']);other_epoch['epoch']=str(uuid.uuid5(uuid.UUID(c['enrollment']),'foreign-owner-epoch'))
    refuse('wrong-owner',valid,owner=other_id);refuse('wrong-epoch',valid,owner=other_epoch)
    missing=fresh('missing');refuse('missing',missing)
    mutations=[('foreign-role',"UPDATE meta SET owner=?",(json.dumps(['app-ops',c['identity_owner']['id']],separators=(',',':')),)),
               ('foreign-revision',"UPDATE alembic_version SET version_num='foreign'",()),
               ('missing-index','DROP INDEX requests_active',()),('extra-table','CREATE TABLE unapproved(value TEXT)',()),
               ('foreign-wide','CREATE TABLE unapproved_wide('+','.join('c'+str(i)+' TEXT' for i in range(64))+')',()),
               ('wrong-version','PRAGMA user_version=2',()),('multiple-owners',"INSERT INTO meta VALUES('foreign','foreign',0)",())]
    for label,sql,parameters in mutations:
        path=fresh(label);database=path/'owner.sqlite3';shutil.copyfile(valid/'owner.sqlite3',database);database.chmod(0o600)
        with sqlite3.connect(database) as connection:connection.execute(sql,parameters)
        refuse(label,path)
    for label in ('malformed','symlink','hardlink','file-mode','directory-mode','file-owner','capability','sidecar','pending'):
        path=fresh(label);database=path/'owner.sqlite3';shutil.copyfile(valid/'owner.sqlite3',database);database.chmod(0o600)
        if label=='malformed':database.write_bytes(b'not an owner database')
        elif label=='symlink':database.rename(path/'retained');database.symlink_to(path/'retained')
        elif label=='hardlink':os.link(database,path/'alias')
        elif label=='file-mode':database.chmod(0o640)
        elif label=='directory-mode':path.chmod(0o750)
        elif label=='file-owner':os.chown(database,c['peer_uid'],c['peer_gid'])
        elif label=='capability':os.setxattr(database,'security.capability',struct.pack('<IIIII',0x02000001,1<<10,0,0,0))
        elif label=='sidecar':(path/'owner.sqlite3-wal').write_bytes(b'retained uncertain bytes')
        else:(path/'.initializing').write_bytes(b'retained initialization attempt')
        refuse(label,path)
    retained=fresh('retained');database=retained/'owner.sqlite3';shutil.copyfile(valid/'owner.sqlite3',database);database.chmod(0o600)
    with sqlite3.connect(database) as connection:
        connection.executemany('INSERT INTO requests VALUES(?,?,?,?,?)',[(str(i),'a'*64,'fixture-canary','accepted','none') for i in range(256)])
    first=identity_snapshot(retained);reply=identity_direct(command,'inspect',retained);identity_reply(reply,'inspect');assert identity_snapshot(retained)==first
    proof['retained_rows']={'rows':256,'before':first,'after':identity_snapshot(retained),'invocation':reply}
    concurrent=fresh('concurrent');entry=identity_spawn(command,'initialize',concurrent,'root-identity-concurrent','--inject=fsync:signal=SIGSTOP:when=1')
    descriptor,live=identity_stopped(entry,concurrent)
    try:
        first=identity_snapshot(concurrent)
        competing=identity_direct(command,'initialize',concurrent);identity_reply(competing,'initialize',False)
        inspecting=identity_direct(command,'inspect',concurrent);identity_reply(inspecting,'inspect',False)
        held_after=identity_snapshot(concurrent);assert held_after==first;signal.pidfd_send_signal(descriptor,signal.SIGCONT)
        completed=identity_finish(entry);identity_reply(completed,'initialize')
    finally:os.close(descriptor)
    proof['concurrency']={'live':live,'private_before':first,'private_after':held_after,'competing':competing,'inspecting':inspecting,'completed':completed,'published':identity_snapshot(concurrent)}
    interrupted=fresh('interrupted');entry=identity_spawn(command,'initialize',interrupted,'root-identity-interrupted','--inject=fsync:signal=SIGSTOP:when=1')
    descriptor,live=identity_stopped(entry,interrupted)
    try:
        first=identity_snapshot(interrupted);os.killpg(entry['pid'],signal.SIGKILL);killed=identity_finish(entry)
        assert killed['returncode']==-signal.SIGKILL and killed['stdout']=='' and identity_snapshot(interrupted)==first
    finally:os.close(descriptor)
    rejected=identity_direct(command,'inspect',interrupted);identity_reply(rejected,'inspect',False)
    repeated=identity_direct(command,'initialize',interrupted);identity_reply(repeated,'initialize',False)
    assert identity_snapshot(interrupted)==first
    retry=fresh('retry');reply=identity_direct(command,'initialize',retry);identity_reply(reply,'initialize')
    proof['interruption']={'live':live,'private_before':first,'private_after':identity_snapshot(interrupted),'killed':killed,'rejected':rejected,'repeated':repeated,'fresh_retry':identity_snapshot(retry),'retry_invocation':reply}
    unknown=fresh('unconfirmed');syncs=len(re.findall(r'^fsync\([0-9]+\)\s+=\s+0$',initialized['trace_original'],re.M));assert syncs>=2
    uncertain=identity_finish(identity_spawn(command,'initialize',unknown,'root-identity-unconfirmed','--inject=fsync:error=EIO:when='+str(syncs)));identity_reply(uncertain,'initialize',False)
    first=identity_snapshot(unknown);assert set(first['entries'])=={'owner.sqlite3'}
    recovered=identity_direct(command,'inspect',unknown);identity_reply(recovered,'inspect');assert identity_snapshot(unknown)==first
    repeated=identity_direct(command,'initialize',unknown);identity_reply(repeated,'initialize',False);assert identity_snapshot(unknown)==first
    proof['unconfirmed_publication']={'sync_ordinal':syncs,'failed':uncertain,'published':first,'reconciled':recovered,'repeated':repeated,'after':identity_snapshot(unknown)}
    proof['elapsed_seconds']=time.monotonic()-started;proof['status']='passed';return proof
"""


def _require(condition: bool, reason: str) -> None:
    from scripts.native_linux_guest import GuestBootError

    if not condition:
        raise GuestBootError("owner-identity-" + reason)


def _arguments(action: str, path: str, owner: dict[str, str]) -> list[str]:
    return [
        "state",
        action,
        path,
        "--owner-id",
        owner["id"],
        "--owner-epoch",
        owner["epoch"],
        "--json",
    ]


def _reply(record: dict[str, Any], action: str, owner: dict[str, str], *, success: bool) -> None:
    import json

    _require(record["joined"] is True, "unjoined-command")
    if success:
        _require(
            type(record["returncode"]) is int
            and record["returncode"] == 0
            and record["stderr"] == "",
            "failed-command",
        )
        expected = {
            "tool": "host-ops",
            "status": "initialized" if action == "initialize" else "verified",
            "owner": owner,
            "schema_revision": "v1_0003",
            "generation": 0,
            "native_mutations": False,
            "production_qualified": False,
        }
        value = json.loads(record["stdout"])
        _require(
            value == expected
            and type(value["generation"]) is int
            and value["native_mutations"] is value["production_qualified"] is False,
            "changed-command-result",
        )
    else:
        _require(
            type(record["returncode"]) is int
            and record["returncode"] == 2
            and record["stdout"] == "",
            "failed-refusal",
        )
        _require(
            json.loads(record["stderr"])
            == {
                "tool": "host-ops",
                "status": "unconfirmed" if action == "initialize" else "invalid",
                "error": "OWNER_INITIALIZATION_UNCONFIRMED"
                if action == "initialize"
                else "OWNER_STATE_REJECTED",
            },
            "changed-refusal",
        )


def _snapshot(value: dict[str, Any], *, protected: bool = True) -> dict[str, bytes]:
    import base64
    import hashlib

    from scripts.native_linux_owner_entrypoint import _file_metadata

    _require(
        type(value) is dict and set(value) == {"directory", "entries", "original_files_base64"},
        "snapshot-shape",
    )
    if protected:
        _file_metadata(value["directory"], {"kind": "directory", "mode": 0o700})
    entries = value["entries"]
    _require(
        type(entries) is dict
        and all(
            type(name) is str and name not in ("", ".", "..") and "/" not in name
            for name in entries
        ),
        "snapshot-entry-name",
    )
    originals = value["original_files_base64"]
    _require(
        type(originals) is dict
        and set(originals) == {name for name, row in entries.items() if row["kind"] == "regular"},
        "snapshot-original-extent",
    )
    raw = {}
    for name, encoded in originals.items():
        content = base64.b64decode(encoded, validate=True)
        row = entries[name]
        _require(
            type(row["bytes"]) is int
            and row["bytes"] == len(content)
            and row["sha256"] == hashlib.sha256(content).hexdigest(),
            "snapshot-original-mismatch",
        )
        raw[name] = content
    return raw


def _installed_catalogue() -> dict[tuple[str, str, str], str | None]:
    """Read immutable migration SQL as data; do not call the storage implementation."""
    import ast
    import sqlite3
    from contextlib import closing
    from pathlib import Path

    root = (
        Path(__file__).resolve().parents[1]
        / "fishhat/owner-support/src/fishhat_owner/migrations/versions"
    )
    with closing(sqlite3.connect(":memory:")) as database:
        database.execute(
            "CREATE TABLE alembic_version (\n\tversion_num VARCHAR(32) NOT NULL, \n\tCONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)\n)"
        )
        for name in ("v1_0001", "v1_0002", "v1_0003"):
            tree = ast.parse((root / (name + ".py")).read_text())
            upgrade = next(
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "upgrade"
            )
            for node in upgrade.body:
                _require(
                    isinstance(node, ast.Expr) and isinstance(node.value, ast.Call),
                    "migration-authority-shape",
                )
                assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                call = node.value
                _require(
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "op"
                    and call.func.attr == "execute"
                    and len(call.args) == 1
                    and not call.keywords,
                    "migration-authority-call",
                )
                sql = ast.literal_eval(call.args[0])
                _require(type(sql) is str, "migration-authority-sql")
                database.execute(sql)
        return {
            (kind, name, table): sql
            for kind, name, table, sql in database.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema"
            )
        }


@contextmanager
def _original_database(raw: bytes) -> Iterator[sqlite3.Connection]:
    """Inspect captured data read-only with the controller's supported SQLite API."""
    import os
    import tempfile
    from contextlib import closing
    from pathlib import Path

    with tempfile.TemporaryDirectory(prefix="fh-identity-original-") as directory:
        path = Path(directory) / "original.sqlite3"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as database:
            yield database


def _database(value: dict[str, Any], owner: dict[str, str], *, rows: int = 0) -> None:
    import json
    import sqlite3

    from scripts.native_linux_owner_entrypoint import _file_metadata

    originals = _snapshot(value)
    _require(set(value["entries"]) == set(originals) == {"owner.sqlite3"}, "published-extent")
    _file_metadata(
        value["entries"]["owner.sqlite3"],
        {"kind": "regular", "mode": 0o600, "file_capability": None},
    )
    with _original_database(originals["owner.sqlite3"]) as database:
        database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 5)
        database.execute("PRAGMA trusted_schema=OFF")
        database.execute("PRAGMA query_only=ON")
        catalogue = {
            (kind, name, table): sql
            for kind, name, table, sql in database.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema"
            )
        }
        _require(catalogue == _installed_catalogue(), "published-schema")
        _require(database.execute("PRAGMA user_version").fetchone() == (1,), "published-version")
        _require(
            database.execute("SELECT version_num FROM alembic_version").fetchall()
            == [("v1_0003",)],
            "published-revision",
        )
        _require(
            database.execute("SELECT owner,epoch,generation FROM meta").fetchall()
            == [
                (json.dumps([owner["tool"], owner["id"]], separators=(",", ":")), owner["epoch"], 0)
            ],
            "published-owner",
        )
        for table in ("request_effects", "effect_resolutions"):
            _require(
                database.execute("SELECT count(*) FROM " + table).fetchone() == (0,),
                "unexpected-owner-effects",
            )
        retained = database.execute(
            "SELECT request_id,payload_digest,principal,state,effect FROM requests"
        ).fetchall()
        _require(
            len(retained) == rows
            and set(retained)
            == {
                (str(index), "a" * 64, "fixture-canary", "accepted", "none")
                for index in range(rows)
            },
            "retained-request-extent",
        )


def _direct(
    record: dict[str, Any],
    c: dict[str, Any],
    action: str,
    path: str,
    *,
    owner: dict[str, str] | None = None,
    role: str = "root",
    success: bool = False,
) -> None:
    from scripts.native_linux_owner_entrypoint import _poison_environment, _principal

    selected = c["identity_owner"] if owner is None else owner
    command = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/complete/host-ops"
    _require(
        record["argv"] == [command, *_arguments(action, path, selected)]
        and record["environment"] == _poison_environment(c["enrollment"])
        and record["role"] == role,
        "direct-command-context",
    )
    uid, gid = (0, 0) if role == "root" else (c["peer_uid"], c["peer_gid"])
    _principal(record["before"], uid, gid)
    _require(
        type(record["pid"]) is int and record["pid"] == record["before"]["pid"],
        "direct-process-custody",
    )
    _reply(record, action, selected, success=success)


def _trace(
    record: dict[str, Any],
    value: dict[str, Any],
    c: dict[str, Any],
    action: str,
    path: str,
    label: str,
    *,
    inject: str | None = None,
    success: bool = True,
    killed: bool = False,
) -> dict[str, Any]:
    import hashlib
    import os

    from scripts.native_linux_owner_entrypoint import (
        _execution,
        _file_metadata,
        _poison_environment,
    )

    prefix = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"]
    command = prefix + "/complete/host-ops"
    poison = "/tmp/fishhat-entrypoint-fixture-" + c["enrollment"]
    binding = c["inputs"]["configuration"]["bindings"]["complete"]
    arguments = _arguments(action, path, c["identity_owner"])
    environment = _poison_environment(c["enrollment"]) | {
        "LD_DEBUG_OUTPUT": poison + "/root/positive-loader-" + label
    }
    strings = [
        command,
        binding["interpreter"]["path"],
        binding["program"]["path"],
        *arguments,
        *[key + "=" + item for key, item in environment.items()],
    ]
    strings.append(_success_output(c["identity_owner"]))
    limit = (
        max(
            max(
                len(os.fsencode(prefix + "/complete/" + name)) for name in value["complete_before"]
            ),
            max(len(os.fsencode(item)) for item in strings),
        )
        + 1
    )
    expected_argv = [
        prefix + "/observer/usr/bin/strace",
        "-ff",
        "--kill-on-exit",
        "-s",
        str(limit),
        "-xx",
        "-v",
        "-q",
        "-e",
        TRACE_FILTER,
        "-o",
        prefix + "/traces/" + label,
        "-u",
        "root",
    ]
    if inject is not None:
        expected_argv.append(inject)
    expected_argv += [item for key, val in environment.items() for item in ("-E", key + "=" + val)]
    expected_argv += [command, *arguments]
    _require(
        record["label"] == label
        and record["role"] == "root"
        and record["command"] == command
        and record["arguments"] == arguments
        and record["environment"] == environment
        and record["observer_argv"] == expected_argv
        and record["string_limit"] == limit
        and record["observer_environment"]
        == {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": prefix + "/observer/usr/lib/x86_64-linux-gnu",
        },
        "trace-command-context",
    )
    _require(
        type(record["tracer_pid"]) is int
        and type(record["tracee_pid"]) is int
        and record["tracer_pid"] > 1
        and record["tracee_pid"] > 1
        and record["tracer_pid"] != record["tracee_pid"]
        and record["tracer_joined"] is record["tracee_absent"] is record["joined"] is True
        and record["positive_loader_files"] == [],
        "trace-process-custody",
    )
    if killed:
        _require(
            type(record["returncode"]) is int
            and record["returncode"] == -9
            and record["stdout"] == "",
            "interrupted-child-not-killed",
        )
    else:
        _reply(record, action, c["identity_owner"], success=success)
    raw = record["trace_original"]
    _require(
        type(raw) is str
        and raw.endswith("\n")
        and (
            "--- SIGSTOP " in raw
            if killed
            else raw.endswith("+++ exited with " + ("0" if success else "2") + " +++\n")
        ),
        "incomplete-trace",
    )
    _file_metadata(
        record["trace_metadata"],
        {
            "kind": "regular",
            "mode": 0o600,
            "bytes": len(raw.encode()),
            "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        },
    )
    lines = raw.splitlines()
    _stream_output(lines, record)
    executions = [line for line in lines if line.startswith(("execve(", "execveat("))]
    _require(len(executions) == 2, "extra-executable-dispatch")
    first, second = map(_execution, executions)
    encoded = [os.fsencode(item) for item in arguments]
    _require(
        first
        == (
            os.fsencode(command),
            [os.fsencode(command), *encoded],
            {os.fsencode(key): os.fsencode(val) for key, val in environment.items()},
        ),
        "trace-first-exec",
    )
    _require(
        second
        == (
            os.fsencode(binding["interpreter"]["path"]),
            [
                os.fsencode(binding["interpreter"]["path"]),
                b"-I",
                b"-S",
                b"-B",
                os.fsencode(binding["program"]["path"]),
                *encoded,
            ],
            {b"LANG": b"C.UTF-8", b"LC_ALL": b"C.UTF-8"},
        ),
        "trace-runtime-exec",
    )
    start = lines.index(executions[0])
    banned = (
        "open",
        "openat2",
        "creat",
        "utime",
        "utimes",
        "futimesat",
        "utimensat",
        "fchmodat2",
        "socket",
        "socketpair",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "sendmsg",
        "sendmmsg",
        "recvfrom",
        "recvmsg",
        "recvmmsg",
        "shutdown",
        "setuid",
        "setgid",
        "setresuid",
        "setresgid",
        "setreuid",
        "setregid",
        "setfsuid",
        "setfsgid",
        "setgroups",
        "capset",
        "clone",
        "clone3",
        "fork",
        "vfork",
        "mkdir",
        "mkdirat",
        "rmdir",
        "rename",
        "renameat",
        "renameat2",
        "chmod",
        "fchmodat",
        "chown",
        "fchown",
        "lchown",
        "fchownat",
        "symlink",
        "symlinkat",
        "mknod",
        "mknodat",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "removexattr",
        "lremovexattr",
        "fremovexattr",
        "truncate",
    )
    _require(
        not any(
            line.startswith(tuple(name + "(" for name in banned)) for line in lines[start + 1 :]
        ),
        "extra-effect-or-network",
    )
    events, opened = _file_events(lines, path, poison, action)
    _origins(record, value, c, opened, binding, prefix, poison)
    _publication(events, lines, path, action, success=success, killed=killed)
    return {
        "events": events,
        "executions": second,
        "fsyncs": len([event for event in events if event[1] == "fsync"]),
    }


def _success_output(owner: dict[str, str]) -> str:
    import json

    return (
        json.dumps(
            {
                "tool": "host-ops",
                "status": "initialized",
                "owner": owner,
                "schema_revision": "v1_0003",
                "generation": 0,
                "native_mutations": False,
                "production_qualified": False,
            },
            sort_keys=True,
        )
        + "\n"
    )


def _stream_output(lines: list[str], record: dict[str, Any]) -> None:
    import re

    from scripts.native_linux_owner_entrypoint import _literal_values

    streams = {1: bytearray(), 2: bytearray()}
    for line in lines:
        if not re.match(r"write\([12],", line):
            continue
        match = re.fullmatch(
            r'write\(([12]), ("(?:\\x[0-9a-f]{2})*"), ([0-9]+)\)\s+=\s+([0-9]+)', line
        )
        _require(match is not None, "incomplete-original-output")
        assert match is not None
        (raw,) = _literal_values(match[2])
        _require(len(raw) == int(match[3]) == int(match[4]), "partial-original-output")
        streams[int(match[1])].extend(raw)
    _require(
        bytes(streams[1]) == record["stdout"].encode()
        and bytes(streams[2]) == record["stderr"].encode(),
        "original-output-mismatch",
    )


def _file_events(
    lines: list[str], path: str, poison: str, action: str
) -> tuple[list[tuple[int, str, str, bool]], set[str]]:
    import os
    import posixpath
    import re
    from pathlib import PurePosixPath

    from scripts.native_linux_owner_entrypoint import _literal_values

    descriptors: dict[int, tuple[str, bool]] = {}
    opened: set[str] = set()
    pending = path + "/.initializing"
    database = path + "/owner.sqlite3"
    allowed = {pending, pending + "-journal", database}
    events: list[tuple[int, str, str, bool]] = []

    def pathname(token: str, directory: str = "AT_FDCWD") -> str:
        literals = _literal_values(token)
        _require(len(literals) == 1, "ambiguous-path")
        item = os.fsdecode(literals[0])
        if not item.startswith("/"):
            base = poison if directory == "AT_FDCWD" else descriptors[int(directory)][0]
            item = str(PurePosixPath(base) / item)
        match = re.fullmatch(r"/proc/self/fd/([0-9]+)(/.*)?", item)
        if match:
            _require(int(match[1]) in descriptors, "unbound-directory-descriptor")
            item = descriptors[int(match[1])][0] + (match[2] or "")
        return posixpath.normpath(item)

    for index, line in enumerate(lines):
        if line.startswith("openat("):
            match = re.fullmatch(
                r'openat\((AT_FDCWD|[0-9]+), ("(?:\\x[0-9a-f]{2})*"), (.*?)\)\s+=\s+([0-9]+)', line
            )
            if match is None:
                _require(not re.search(r"\)\s+=\s+[0-9]+$", line), "unparsed-successful-open")
                continue
            directory, token, flags, fd = match.groups()
            literal = os.fsdecode(_literal_values(token)[0])
            resolved = pathname(token, directory)
            opened.add(literal)
            write = any(
                flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
            )
            _require(
                not write or (action == "initialize" and resolved in allowed),
                "out-of-store-write-open",
            )
            if resolved == pending and "O_CREAT" in flags:
                _require(
                    "O_EXCL" in flags
                    and "O_NOFOLLOW" in flags
                    and "O_CLOEXEC" in flags
                    and flags.endswith(", 0600"),
                    "unsafe-private-reservation",
                )
                events.append((index, "reserve", resolved, True))
            descriptors[int(fd)] = (resolved, write)
        elif line.startswith("close("):
            match = re.fullmatch(r"close\(([0-9]+)\)\s+=\s+0", line)
            if match:
                descriptors.pop(int(match[1]), None)
        elif line.startswith(
            (
                "write(",
                "pwrite64(",
                "writev(",
                "pwritev(",
                "pwritev2(",
                "ftruncate(",
                "fallocate(",
                "fchmod(",
                "fsync(",
                "fdatasync(",
                "flock(",
            )
        ):
            match = re.match(r"([a-z0-9]+)\(([0-9]+),?", line)
            _require(match is not None, "unparsed-descriptor-operation")
            assert match is not None
            operation, number = match.groups()
            fd = int(number)
            if operation == "write" and fd in (1, 2):
                events.append((index, "ack" if fd == 1 else "error", "", True))
                continue
            _require(fd in descriptors, "unbound-file-descriptor")
            target, writable = descriptors[fd]
            if operation == "flock":
                _require(
                    target == path
                    and (
                        "LOCK_EX|LOCK_NB" in line
                        if action == "initialize"
                        else "LOCK_SH|LOCK_NB" in line
                    ),
                    "unsafe-initialization-lock",
                )
            elif operation in ("fsync", "fdatasync"):
                _require(action == "initialize" and target in allowed | {path}, "out-of-store-sync")
                events.append((index, operation, target, line.endswith("= 0")))
            else:
                _require(
                    action == "initialize" and writable and target in allowed,
                    "out-of-store-descriptor-write",
                )
                if operation == "fchmod":
                    _require(
                        re.fullmatch(r"fchmod\([0-9]+, 0600\)\s+=\s+0", line) is not None,
                        "unsafe-private-mode",
                    )
        elif line.startswith(("linkat(", "unlinkat(", "unlink(", "link(")):
            if line.startswith("linkat("):
                match = re.fullmatch(
                    r'linkat\(([0-9]+), ("(?:\\x[0-9a-f]{2})*"), ([0-9]+), ("(?:\\x[0-9a-f]{2})*"), 0\)\s+=\s+0',
                    line,
                )
                _require(match is not None and action == "initialize", "unsafe-publication")
                assert match is not None
                source = pathname(match[2], match[1])
                destination = pathname(match[4], match[3])
                _require(source == pending and destination == database, "wrong-publication-path")
                events.append((index, "publish", destination, True))
            elif line.startswith("unlinkat("):
                match = re.fullmatch(
                    r'unlinkat\(([0-9]+), ("(?:\\x[0-9a-f]{2})*"), 0\)\s+=\s+0', line
                )
                _require(match is not None, "unsafe-private-unlink")
                assert match is not None
                target = pathname(match[2], match[1])
                _require(action == "initialize" and target == pending, "wrong-private-unlink")
                events.append((index, "unpublish-private", target, True))
            else:
                match = re.fullmatch(r'unlink\(("(?:\\x[0-9a-f]{2})*")\)\s+=\s+0', line)
                _require(match is not None, "unexpected-file-link-mutation")
                assert match is not None
                _require(
                    action == "initialize" and pathname(match[1]) == pending + "-journal",
                    "out-of-store-unlink",
                )
    return events, opened


def _origins(
    record: dict[str, Any],
    value: dict[str, Any],
    c: dict[str, Any],
    opened: set[str],
    binding: dict[str, Any],
    prefix: str,
    poison: str,
) -> None:
    from pathlib import PurePosixPath

    from scripts.native_linux_owner_entrypoint import _expected_installation, _file_metadata

    required = {binding["program"]["path"]} | {
        prefix + "/complete/packages/lib/" + name
        for name in (
            "fishhat_host/cli.py",
            "fishhat_cli/validation.py",
            "fishhat_owner/identity_store.py",
            "fishhat_owner/migrations/__init__.py",
            "fishhat_contracts/validation.py",
        )
    }
    _require(required <= opened, "missing-actual-storage-code")
    code = {
        item
        for item in opened
        if item.endswith((".py", ".pyc")) or ".so" in PurePosixPath(item).name
    }
    _require(set(record["code_opens"]) == code, "incomplete-code-origins")
    installed = _expected_installation(c["inputs"], "complete")
    for item in opened:
        _require(not item.startswith(poison + "/"), "caller-code-or-data-opened")
        if item not in code:
            continue
        origin = record["code_opens"][item]
        resolved = origin["resolved"]
        _require(
            PurePosixPath(resolved).is_absolute() and ".." not in PurePosixPath(resolved).parts,
            "unsafe-code-origin",
        )
        if resolved.startswith(prefix + "/complete/"):
            relative = resolved.removeprefix(prefix + "/complete/")
            _require(relative in installed, "uninstalled-code-origin")
            _file_metadata(origin["metadata"], installed[relative])
            _require(
                origin["metadata"] == value["complete_before"][relative], "changed-code-origin"
            )
        else:
            loader_cache = item == resolved == "/etc/ld.so.cache"
            platform = loader_cache or (
                item != "/etc/ld.so.cache"
                and PurePosixPath(resolved).name.startswith("lib")
                and ".so" in PurePosixPath(resolved).name
                and str(PurePosixPath(resolved).parent)
                in ("/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu")
            )
            _require(
                platform and not item.startswith(prefix + "/complete/"), "unapproved-code-origin"
            )
            _file_metadata(origin["metadata"], {"kind": "regular"})
            _require(origin["metadata"]["mode"] & 0o6022 == 0, "unprotected-platform-code")


def _publication(
    events: list[tuple[int, str, str, bool]],
    lines: list[str],
    path: str,
    action: str,
    *,
    success: bool,
    killed: bool,
) -> None:
    import re

    pending = path + "/.initializing"
    raw = "\n".join(lines) + "\n"
    reserves = [event for event in events if event[1] == "reserve"]
    locks = [line for line in lines if line.startswith("flock(")]
    _require(len(locks) == 1 and locks[0].endswith("= 0"), "missing-initialization-mutex")
    if action == "initialize":
        _require(len(reserves) == 1, "missing-exclusive-reservation")
        publications = [event for event in events if event[1] == "publish"]
        if killed:
            _require(
                not publications and not any(event[1] == "ack" for event in events),
                "interrupted-publication",
            )
        else:
            _require(len(publications) == 1, "missing-publication")
            published = publications[0][0]
            file_sync = [
                event[0]
                for event in events
                if event[1] == "fsync" and event[2] == pending and event[3]
            ]
            removed = [event[0] for event in events if event[1] == "unpublish-private"]
            # SQLite may synchronize its new rollback-journal directory before
            # the private database commitment. Publication still needs its own
            # successful directory sync after the private name is removed.
            directory_sync = [
                event
                for event in events
                if event[1] == "fsync" and event[2] == path and event[0] > published
            ]
            earlier_directory_sync = [
                event
                for event in events
                if event[1] == "fsync" and event[2] == path and event[0] < published
            ]
            preparation_sync = [
                event
                for event in events
                if event[1] in ("fsync", "fdatasync") and event[0] < published
            ]
            _require(
                bool(file_sync)
                and reserves[0][0] < file_sync[-1] < published
                and all(event[3] and reserves[0][0] < event[0] for event in preparation_sync)
                and all(event[0] < file_sync[-1] for event in earlier_directory_sync)
                and len(removed) == 1
                and published < removed[0]
                and len(directory_sync) == 1
                and removed[0] < directory_sync[0][0]
                and directory_sync[0][3] is success,
                "uncommitted-publication-order",
            )
            acknowledgements = [
                event[0] for event in events if event[1] == ("ack" if success else "error")
            ]
            _require(
                bool(acknowledgements)
                and directory_sync[0][0] < acknowledgements[0]
                and not any(event[1] == ("error" if success else "ack") for event in events),
                "premature-or-contradictory-acknowledgement",
            )
            if not success:
                _require(
                    re.search(r"^fsync\([0-9]+\)\s+=\s+-1 EIO .*\(INJECTED\)$", raw, re.M)
                    is not None,
                    "missing-injected-sync-failure",
                )
    else:
        _require(
            not reserves
            and not any(
                event[1] in ("publish", "unpublish-private", "fsync", "fdatasync")
                for event in events
            ),
            "inspection-mutated-state",
        )


def _live(
    row: dict[str, Any], trace: dict[str, Any], parsed: dict[str, Any], c: dict[str, Any]
) -> None:
    _require(
        row["pid"] == trace["tracee_pid"]
        and row["tracer_pid"] == trace["tracer_pid"]
        and row["pidfd_open"] is True
        and row["state"] in ("T", "t")
        and row["process_group"] == row["session"] == trace["tracer_pid"],
        "unheld-process-custody",
    )
    execution = parsed["executions"]
    _require(
        row["executable"].encode() == execution[0]
        and bytes.fromhex(row["cmdline_hex"]) == b"\0".join(execution[1]) + b"\0"
        and bytes.fromhex(row["environment_hex"]) == b"LANG=C.UTF-8\0LC_ALL=C.UTF-8\0",
        "changed-live-runtime",
    )
    facts = row["status"]
    _require(
        type(row["start_ticks"]) is str
        and row["start_ticks"].isdigit()
        and int(row["start_ticks"]) > 0
        and int(facts["Pid"]) == row["pid"]
        and int(facts["PPid"]) == row["tracer_pid"],
        "changed-live-process-identity",
    )
    _require(
        [int(item) for item in facts["Uid"].split()] == [0] * 4
        and [int(item) for item in facts["Gid"].split()] == [0] * 4
        and sorted(int(item) for item in facts["Groups"].split())
        == sorted(trace["initial_group_selection"])
        and 0 in trace["initial_group_selection"],
        "changed-live-root-principal",
    )
    _require("--- SIGSTOP " in trace["trace_original"], "missing-original-stop")


def _refusal_input(row: dict[str, Any], genesis: dict[str, Any], c: dict[str, Any]) -> None:
    import json
    import sqlite3

    label = row["label"]
    value = row["before"]
    entries = value["entries"]
    originals = _snapshot(value, protected=label != "directory-mode")
    original = _snapshot(genesis)["owner.sqlite3"]
    file = entries["owner.sqlite3"]
    if label == "symlink":
        _require(
            set(entries) == {"owner.sqlite3", "retained"}
            and file["kind"] == "symlink"
            and file["target"] == row["path"] + "/retained"
            and originals == {"retained": original},
            "missing-symlink-control",
        )
    elif label == "hardlink":
        _require(
            set(entries) == {"owner.sqlite3", "alias"}
            and file == entries["alias"]
            and file["links"] == 2
            and originals == {"owner.sqlite3": original, "alias": original},
            "missing-hardlink-control",
        )
    elif label in ("file-mode", "directory-mode", "file-owner", "capability", "sidecar", "pending"):
        _require(originals["owner.sqlite3"] == original, "changed-metadata-control-data")
        if label == "file-mode":
            _require(file["mode"] == 0o640, "missing-file-mode-control")
        elif label == "directory-mode":
            _require(value["directory"]["mode"] == 0o750, "missing-directory-mode-control")
        elif label == "file-owner":
            _require(
                (file["uid"], file["gid"]) == (c["peer_uid"], c["peer_gid"]),
                "missing-file-owner-control",
            )
        elif label == "capability":
            _require(
                file["file_capability"] == "0100000200040000000000000000000000000000",
                "missing-file-capability-control",
            )
        else:
            name = "owner.sqlite3-wal" if label == "sidecar" else ".initializing"
            _require(
                set(entries) == {"owner.sqlite3", name}
                and originals[name]
                == (
                    b"retained uncertain bytes"
                    if label == "sidecar"
                    else b"retained initialization attempt"
                ),
                "missing-incomplete-control",
            )
    elif label == "malformed":
        _require(
            originals == {"owner.sqlite3": b"not an owner database"}, "missing-malformed-control"
        )
    else:
        _require(
            set(entries) == set(originals) == {"owner.sqlite3"}
            and originals["owner.sqlite3"] != original,
            "unchanged-schema-control",
        )
        with _original_database(originals["owner.sqlite3"]) as database:
            database.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("PRAGMA query_only=ON")
            catalogue = {
                (kind, name, table): sql
                for kind, name, table, sql in database.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_schema"
                )
            }
            if label == "foreign-role":
                _require(
                    database.execute("SELECT owner FROM meta").fetchall()
                    == [
                        (json.dumps(["app-ops", c["identity_owner"]["id"]], separators=(",", ":")),)
                    ],
                    "missing-role-control",
                )
            elif label == "foreign-revision":
                _require(
                    database.execute("SELECT version_num FROM alembic_version").fetchall()
                    == [("foreign",)],
                    "missing-revision-control",
                )
            elif label == "wrong-version":
                _require(
                    database.execute("PRAGMA user_version").fetchone() == (2,),
                    "missing-version-control",
                )
            elif label == "multiple-owners":
                _require(
                    database.execute("SELECT count(*) FROM meta").fetchone() == (2,),
                    "missing-multiple-owner-control",
                )
            elif label == "missing-index":
                _require(
                    catalogue
                    == {
                        key: sql
                        for key, sql in _installed_catalogue().items()
                        if key != ("index", "requests_active", "requests")
                    },
                    "missing-index-control",
                )
            else:
                table = "unapproved_wide" if label == "foreign-wide" else "unapproved"
                _require(
                    ("table", table, table) in catalogue
                    and len(
                        database.execute("SELECT * FROM pragma_table_info(?)", (table,)).fetchall()
                    )
                    == (64 if label == "foreign-wide" else 1),
                    "missing-foreign-table-control",
                )


def verify_observation(value: dict[str, Any], c: dict[str, Any]) -> None:
    """Validate the full owned identity witness before accepting its outer fixture."""
    import math
    import uuid

    owner = fixture_owner(c["enrollment"])
    _require(
        c["identity_owner"] == owner and c["identity_trace_filter"] == TRACE_FILTER,
        "changed-fixture-selection",
    )
    proof = value["owner_identity"]
    root = "/var/lib/fishhat-entrypoint-fixture-" + c["enrollment"] + "/identity"
    _require(
        set(proof)
        == {
            "scope",
            "status",
            "native_owner_qualified",
            "owner",
            "root",
            "traced_invocations",
            "refusals",
            "genesis",
            "retained_rows",
            "concurrency",
            "interruption",
            "unconfirmed_publication",
            "elapsed_seconds",
        },
        "proof-shape",
    )
    _require(
        proof["scope"] == SCOPE
        and proof["status"] == "passed"
        and proof["native_owner_qualified"] is False
        and proof["owner"] == owner
        and proof["root"] == root
        and type(proof["elapsed_seconds"]) in (int, float)
        and math.isfinite(proof["elapsed_seconds"])
        and proof["elapsed_seconds"] > 0,
        "proof-scope",
    )
    genesis = proof["genesis"]
    _require(
        _snapshot(genesis["before"]) == {} and genesis["before"]["entries"] == {},
        "adopted-existing-genesis",
    )
    _database(genesis["after"], owner)
    _require(genesis["after"] == genesis["inspection_after"], "inspection-changed-genesis")
    traces = proof["traced_invocations"]
    _require(type(traces) is list and len(traces) == 2, "trace-extent")
    initial = _trace(traces[0], value, c, "initialize", root + "/valid", "root-identity-initialize")
    _trace(traces[1], value, c, "inspect", root + "/valid", "root-identity-inspect")
    expected_labels = (
        "existing-identity",
        "peer-initialize",
        "peer-inspect",
        "wrong-owner",
        "wrong-epoch",
        "missing",
        "foreign-role",
        "foreign-revision",
        "missing-index",
        "extra-table",
        "foreign-wide",
        "wrong-version",
        "multiple-owners",
        "malformed",
        "symlink",
        "hardlink",
        "file-mode",
        "directory-mode",
        "file-owner",
        "capability",
        "sidecar",
        "pending",
    )
    refusals = proof["refusals"]
    _require(
        type(refusals) is list and [row["label"] for row in refusals] == list(expected_labels),
        "refusal-extent",
    )
    for row in refusals:
        label = row["label"]
        action = "initialize" if label in ("existing-identity", "peer-initialize") else "inspect"
        path = root + ("/valid" if label in expected_labels[:5] else "/" + label)
        role = "peer" if label.startswith("peer-") else "root"
        selected = dict(owner)
        if label in ("wrong-owner", "wrong-epoch"):
            selected["id" if label == "wrong-owner" else "epoch"] = str(
                uuid.uuid5(
                    uuid.UUID(c["enrollment"]),
                    "foreign-owner" if label == "wrong-owner" else "foreign-owner-epoch",
                )
            )
        _require(
            row["path"] == path
            and row["action"] == action
            and row["role"] == role
            and row["expected_owner"] == selected
            and row["before"] == row["after"],
            "changed-refused-custody",
        )
        _snapshot(row["before"], protected=label != "directory-mode")
        _direct(row["invocation"], c, action, path, owner=selected, role=role)
        if label in expected_labels[:5]:
            _require(row["before"] == genesis["after"], "refusal-did-not-use-published-identity")
        elif label == "missing":
            _require(row["before"]["entries"] == {}, "missing-control-not-empty")
        else:
            _require("owner.sqlite3" in row["before"]["entries"], "missing-refusal-input")
            _refusal_input(row, genesis["after"], c)
    retained = proof["retained_rows"]
    _require(
        type(retained["rows"]) is int
        and retained["rows"] == 256
        and retained["before"] == retained["after"],
        "retained-custody",
    )
    _database(retained["before"], owner, rows=256)
    _direct(retained["invocation"], c, "inspect", root + "/retained", success=True)
    for name in ("concurrency", "interruption"):
        row = proof[name]
        first = _snapshot(row["private_before"])
        _require(
            ".initializing" in first
            and "owner.sqlite3" not in row["private_before"]["entries"]
            and row["private_before"] == row["private_after"],
            "interrupted-private-custody",
        )
        path = root + ("/concurrent" if name == "concurrency" else "/interrupted")
        trace = row["completed" if name == "concurrency" else "killed"]
        parsed = _trace(
            trace,
            value,
            c,
            "initialize",
            path,
            "root-identity-concurrent" if name == "concurrency" else "root-identity-interrupted",
            inject="--inject=fsync:signal=SIGSTOP:when=1",
            killed=name == "interruption",
        )
        _live(row["live"], trace, parsed, c)
        _direct(row["competing" if name == "concurrency" else "repeated"], c, "initialize", path)
        _direct(row["inspecting" if name == "concurrency" else "rejected"], c, "inspect", path)
        if name == "concurrency":
            _database(row["published"], owner)
        else:
            _database(row["fresh_retry"], owner)
            _direct(row["retry_invocation"], c, "initialize", root + "/retry", success=True)
    uncertain = proof["unconfirmed_publication"]
    _require(
        type(uncertain["sync_ordinal"]) is int
        and uncertain["sync_ordinal"] == initial["fsyncs"]
        and initial["fsyncs"] >= 2,
        "changed-sync-fault-position",
    )
    _trace(
        uncertain["failed"],
        value,
        c,
        "initialize",
        root + "/unconfirmed",
        "root-identity-unconfirmed",
        inject="--inject=fsync:error=EIO:when=" + str(initial["fsyncs"]),
        success=False,
    )
    _database(uncertain["published"], owner)
    _require(uncertain["published"] == uncertain["after"], "unconfirmed-state-changed")
    _direct(uncertain["reconciled"], c, "inspect", root + "/unconfirmed", success=True)
    _direct(uncertain["repeated"], c, "initialize", root + "/unconfirmed")
    all_traces = [
        *traces,
        proof["concurrency"]["completed"],
        proof["interruption"]["killed"],
        uncertain["failed"],
    ]
    joined = value["identity_children"]
    _require(
        type(joined) is list
        and len(joined) == len(all_traces)
        and all(
            entry
            == {
                "label": record["label"],
                "pid": record["tracer_pid"],
                "joined": True,
                "returncode": record["returncode"],
            }
            for entry, record in zip(joined, all_traces, strict=True)
        ),
        "identity-cleanup-extent",
    )
    pids = [record[key] for record in all_traces for key in ("tracer_pid", "tracee_pid")]
    _require(
        len(set(pids)) == len(pids) and value["cleanup_errors"] == [], "identity-child-custody"
    )
