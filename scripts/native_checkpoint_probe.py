"""Fixed installed-package probe data for the enrolled disposable guest."""

PROGRAM = r"""
import hashlib,json,os,pathlib,stat,subprocess,sys,uuid
context_path=pathlib.Path(__file__).with_name('context.json')
context_raw=context_path.read_bytes();c=json.loads(context_raw)
assert c['scope']=='disposable-guest-protected-checkpoint-storage-only'
assert hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()==c['probe_sha256']
assert pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip()==c['enrollment']
assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['boot_id']
assert sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
sys.path.insert(0,c['library'])
from fishhat_owner import checkpoint_store
from fishhat_contracts.validation import ContractError
request=json.loads(sys.argv[1]);action=request['action'];label=request['label']
assert isinstance(label,str) and label and all(ch.isascii() and (ch.isalnum() or ch in '_-') for ch in label)
authority=pathlib.Path(c['cases'][request['case']]);index=request.get('journal_index',0)
assert type(index) is int and index in (0,1)
capture=request.get('capture','control');assert capture in ('control','same-domain')
journal=pathlib.Path(c['journals'][index] if capture=='control' else c['local_journal']);owner=dict(c['owner']);journal_id=c['journal_id']
foreign=request.get('binding','correct');assert foreign in ('correct','owner','epoch','journal')
if foreign=='owner':owner['id']=str(uuid.uuid5(uuid.UUID(c['enrollment']),'foreign-checkpoint-owner'))
elif foreign=='epoch':owner['epoch']=str(uuid.uuid5(uuid.UUID(c['enrollment']),'foreign-checkpoint-epoch'))
elif foreign=='journal':journal_id=str(uuid.uuid5(uuid.UUID(c['enrollment']),'foreign-checkpoint-journal'))
def file_metadata(descriptor):
 row=os.fstat(descriptor)
 return {'device':row.st_dev,'inode':row.st_ino,'uid':row.st_uid,'gid':row.st_gid,
         'mode':stat.S_IMODE(row.st_mode),'links':row.st_nlink,'bytes':row.st_size}
def origin():
 module=pathlib.Path(checkpoint_store.__file__)
 return {'pid':os.getpid(),'parent_pid':os.getppid(),'uids':list(os.getresuid()),'gids':list(os.getresgid()),
         'groups':os.getgroups(),'executable':sys.executable,'proc_executable':os.readlink('/proc/self/exe'),
         'cwd':os.getcwd(),'capabilities':next(line.split(':',1)[1].strip() for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:')),
         'start_ticks':pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19],
         'version':list(sys.version_info[:3]),
         'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,'no_bytecode':sys.flags.dont_write_bytecode,
         'sys_path':sys.path,'module':{'path':str(module),'sha256':hashlib.sha256(module.read_bytes()).hexdigest()},
         'context_sha256':hashlib.sha256(context_raw).hexdigest(),'enrollment':c['enrollment'],'boot_id':c['boot_id']}
def ready(name,descriptors=(),**extra):
 path=pathlib.Path(c['control'])/name
 value={'origin':origin(),'action':action,'case':request['case'],'label':name,
        'descriptors':{str(fd):{'metadata':file_metadata(fd),'target':os.readlink('/proc/self/fd/'+str(fd)),
                      'fdinfo':pathlib.Path('/proc/self/fdinfo/'+str(fd)).read_text()} for fd in descriptors},**extra}
 descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(descriptor,'w') as stream:json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush()
 return value
def release(expected):
 assert sys.stdin.readline()==expected+'\n','fixture control interrupted'
def failed(error):
 return {'type':type(error).__name__,'errno':error.errno if isinstance(error,OSError) else None,'message':str(error)}
value=None;error=None;details={}
try:
 if action=='deny-modification':
  paths=[str(pathlib.Path(c['library'])/'fishhat_owner/checkpoint_store.py'),sys.executable,
         str(pathlib.Path(__file__)),str(context_path),str(authority/'anchor'),str(authority/'current'),str(journal/'HEAD')]
  denied=[]
  for path in paths:
   for operation in ('open-write','chmod'):
    try:
     if operation=='open-write':
      descriptor=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC);os.close(descriptor)
     else:os.chmod(path,0o600)
    except PermissionError as refusal:denied.append({'path':path,'operation':operation,'errno':refusal.errno})
    else:raise AssertionError('unprivileged custody modification was available')
  details={'denied_modifications':denied}
 elif action=='initialize':
  value=checkpoint_store.CheckpointStore.initialize(authority,journal,owner=owner,journal_id=journal_id)
 elif action=='alias-holder':
  descriptor=request['descriptor'];assert type(descriptor) is int and descriptor>2
  assert os.readlink('/proc/self/fd/'+str(descriptor))==str(authority/'anchor')
  held=file_metadata(descriptor);linked=(authority/'anchor').stat()
  assert (held['device'],held['inode'])==(linked.st_dev,linked.st_ino)
  alias=os.dup(descriptor)
  try:
   ready(label,(descriptor,alias));release('close-first');os.close(descriptor);descriptor=-1
   ready(label+'-one',(alias,));release('close-last')
  finally:
   if descriptor>=0:os.close(descriptor)
   os.close(alias)
  details={'inherited_anchor':held,'duplicate_closed':True}
 elif action in ('inspect','publish','held-publish','lost-reply','uncertain-publish','alias-parent'):
  with checkpoint_store.CheckpointStore.open(authority,journal,owner=owner,journal_id=journal_id) as store:
   if action=='inspect':value=store.read()
   elif action=='alias-parent':
    with store.locked():
     descriptor=os.dup(store._anchor)
     ready(label+'-parent',(store._anchor,descriptor));release('spawn-child')
     child_request={**request,'action':'alias-holder','descriptor':descriptor}
     child=subprocess.Popen([sys.executable,'-I','-S','-B',__file__,json.dumps(child_request,sort_keys=True)],
        stdin=sys.stdin,stdout=sys.stdout,stderr=sys.stderr,pass_fds=(descriptor,),cwd='/',env=dict(os.environ))
     os._exit(0)
   else:
    try:
     with store.locked():
      if action=='held-publish':ready(label,(store._anchor,));release('publish')
      value=store.compare_and_swap(request['expected'],request['current'])
    except OSError as failure:
     if action!='uncertain-publish':raise
     error=failed(failure)
     try:store.read()
     except ContractError as fenced:details['same_handle_refusal']=failed(fenced)
     else:raise AssertionError('uncertain checkpoint handle remained usable')
    else:
     if action=='uncertain-publish':raise AssertionError('expected controlled observer error absent')
    if action=='lost-reply':ready(label,(store._anchor,));release('acknowledge')
 else:raise AssertionError('unknown installed checkpoint probe action')
except (ContractError,OSError) as failure:error=failed(failure)
print(json.dumps({'origin':origin(),'action':action,'label':label,'case':request['case'],
                  'journal_index':index,'capture':capture,'binding':foreign,'record':value,'error':error,'details':details},sort_keys=True),flush=True)
"""
