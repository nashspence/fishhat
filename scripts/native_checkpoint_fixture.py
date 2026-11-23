"""Guest observer data for installed checkpoint storage qualification."""

REMOTE = r"""
import base64,hashlib,importlib.util,io,json,os,pathlib,pwd,re,shutil,signal,stat,struct,subprocess,sys,tarfile,time,uuid,zipfile
c=json.loads(sys.argv[1]);clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
os.umask(0o077)
result={'scope':c['scope'],'status':'failed','enrollment':c['enrollment'],'boot_id':c['boot_id'],
        'observer_pid':os.getpid(),'observer_uid':os.geteuid(),'input_sha256':c['input_sha256'],
        'bootstrap_sha256':c['bootstrap_sha256'],'primary_error':None,'cleanup_errors':[],
        'invocations':[],'owned_children':[],'cleanup':[],'native_product_qualified':False,'writer_authority_qualified':False}
owned=[];children=[];stage='admission'
prefix=pathlib.Path('/var/lib/fishhat-checkpoint-fixture-'+c['enrollment'])
storage_root=pathlib.Path('/run/fhs-'+uuid.UUID(c['enrollment']).hex)
control_mount=storage_root/'control';journal_root=control_mount/('checkpoint-'+uuid.UUID(c['enrollment']).hex)
def progress(value):
 global stage
 stage=value
 try:print('fishhat-checkpoint-progress '+stage+' '+str(len(result['invocations'])),file=sys.stderr,flush=True)
 except OSError:pass
def failure(error):
 reason='observation-error'
 if isinstance(error,subprocess.TimeoutExpired):reason='child-timeout'
 elif isinstance(error,AssertionError):
  reason={'native stop unavailable':'stop-unavailable','fixture marker unavailable':'marker-unavailable'}.get(str(error),'assertion')
 elif isinstance(error,OSError):reason='os-error'
 try:print('fishhat-checkpoint-failure '+stage+' '+reason,file=sys.stderr,flush=True)
 except OSError:pass
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def metadata(path):
 row=path.lstat();kind='symlink' if stat.S_ISLNK(row.st_mode) else 'directory' if stat.S_ISDIR(row.st_mode) else 'regular' if stat.S_ISREG(row.st_mode) else 'other'
 value={'device':row.st_dev,'inode':row.st_ino,'uid':row.st_uid,'gid':row.st_gid,'mode':stat.S_IMODE(row.st_mode),
        'links':row.st_nlink,'kind':kind,'mtime_ns':row.st_mtime_ns,'ctime_ns':row.st_ctime_ns}
 if kind=='symlink':value['target']=os.readlink(path)
 else:
  value['file_capability']=base64.b64encode(os.getxattr(path,'security.capability',follow_symlinks=False)).decode() if 'security.capability' in os.listxattr(path,follow_symlinks=False) else None
  if kind=='regular':value.update(bytes=row.st_size,sha256=digest(path))
 return value
def inventory(root):
 value={'.':metadata(root)}
 for directory,names,files in os.walk(root,followlinks=False):
  for name in names+files:
   path=pathlib.Path(directory)/name;row=metadata(path);assert row['kind'] in ('directory','regular','symlink')
   if row['kind']=='symlink':assert path.resolve(strict=True).is_relative_to(root)
   value[path.relative_to(root).as_posix()]=row
 return value
def snapshot(path):
 row=metadata(path);entries={};originals={}
 if row['kind']=='directory':
  for entry in path.iterdir():
   entries[entry.name]=metadata(entry)
   if entries[entry.name]['kind']=='regular':originals[entry.name]=base64.b64encode(entry.read_bytes()).decode()
 return {'directory':row,'entries':entries,'original_files_base64':originals}
def directory_identity(path):
 row=path.lstat();assert stat.S_ISDIR(row.st_mode) and row.st_uid==row.st_gid==0
 return row.st_dev,row.st_ino
def control_snapshot():
 row=metadata(control_mount)
 return {'directory':{key:row[key] for key in ('device','inode','uid','gid','mode')},'canary':metadata(control_mount/'canary')}
def proc(pid):
 path=pathlib.Path('/proc')/str(pid);first=(path/'stat').read_text();fields=first.rsplit(')',1)[1].split()
 status={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (path/'status').read_text().splitlines() if ':' in line}
 value={'pid':pid,'start_ticks':fields[19],'state':fields[0],'parent_pid':int(fields[1]),
        'status':{key:status[key] for key in ('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb')},
        'executable':os.readlink(path/'exe'),'executable_sha256':digest(path/'exe'),
        'cmdline_hex':(path/'cmdline').read_bytes().hex(),'environment_sha256':hashlib.sha256((path/'environ').read_bytes()).hexdigest(),
        'process_group':os.getpgid(pid),'session':os.getsid(pid)}
 assert fields[19]==(path/'stat').read_text().rsplit(')',1)[1].split()[19]
 return value
def spawn(action,case,label,*,role='root',inject=None,**options):
 request={'action':action,'case':case,'label':label,**options}
 arguments=[str(executable),'-I','-S','-B',str(prefix/'probe.py'),json.dumps(request,sort_keys=True)]
 argv=[str(observer/'usr/bin/strace'),'-ff','--kill-on-exit','-s',str(c['string_limit']),'-xx','-v','-q',
       '-e',c['trace_filter'],'-o',str(traces/label),'-u',role,'-E','LD_LIBRARY_PATH']
 if inject is not None:argv.append(inject)
 argv+=arguments;started=time.monotonic()
 process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=observer_env,close_fds=True,start_new_session=True)
 entry={'process':process,'label':label,'request':request,'arguments':arguments,'observer_argv':argv,
        'observer_environment':observer_env,'environment':clean,'role':role,'started':started,'finished':False}
 children.append(entry);progress(stage);return entry
def trace_files(entry):return sorted(traces.glob(entry['label']+'.*'))
def wait_marker(entry,label=None):
 path=control/(entry['label'] if label is None else label);end=time.monotonic()+c['child_timeout']
 while True:
  assert entry['process'].poll() is None and time.monotonic()<end,'fixture marker unavailable'
  try:
   raw=path.read_bytes();value=json.loads(raw)
  except (FileNotFoundError,ValueError):time.sleep(0.02);continue
  descriptor=os.pidfd_open(value['origin']['pid'])
  try:
   observed=proc(value['origin']['pid']);assert observed['start_ticks']==value['origin']['start_ticks']
  except BaseException:os.close(descriptor);raise
  return descriptor,{'marker_path':str(path),'marker_original_base64':base64.b64encode(raw).decode(),'marker_metadata':metadata(path),'process':observed}
def wait_stopped(entry,authority,*,initializing=False):
 end=time.monotonic()+c['child_timeout']
 while True:
  assert entry['process'].poll() is None and time.monotonic()<end,'native stop unavailable'
  files=trace_files(entry)
  if len(files)==1:
   pid=int(files[0].name.rsplit('.',1)[1]);path=pathlib.Path('/proc')/str(pid)
   try:
    stopped=next(line.split()[1] for line in (path/'status').read_text().splitlines() if line.startswith('State:')) in ('T','t')
    pending=(authority/'anchor').is_file() and not (authority/'current').exists() if initializing else (authority/'.pending').is_file()
    if stopped and pending and 'SIGSTOP' in files[0].read_text():
     descriptor=os.pidfd_open(pid)
     try:observed=proc(pid)
     except BaseException:os.close(descriptor);raise
     return descriptor,{'process':observed,'trace_before_original':files[0].read_text(),'authority':snapshot(authority)}
   except FileNotFoundError:pass
  time.sleep(0.02)
def send(entry,value):
 assert entry['process'].stdin is not None;entry['process'].stdin.write((value+'\n').encode());entry['process'].stdin.flush()
def finish(entry):
 process=entry['process'];output,error=process.communicate(timeout=c['child_timeout']);files=trace_files(entry);assert files
 originals=[]
 for path in files:
  pid=int(path.name.rsplit('.',1)[1]);end=time.monotonic()+c['child_timeout']
  while pathlib.Path('/proc',str(pid)).exists():assert time.monotonic()<end;time.sleep(0.02)
  originals.append({'pid':pid,'metadata':metadata(path),'original':path.read_text(),'process_absent':True})
 record={key:value for key,value in entry.items() if key not in ('process','started','finished')}
 record.update(tracer_pid=process.pid,tracer_joined=process.poll() is not None,trace_originals=originals,
               returncode=process.returncode,stdout=output.decode(),stderr=error.decode(),elapsed_seconds=time.monotonic()-entry['started'])
 assert len(output)<c['string_limit'] and error==b''
 entry['finished']=True;entry['record']=record;result['invocations'].append(record);progress(stage);return record
def reply(record,*,success=True):
 assert record['returncode']==0 and record['stderr']=='' and record['tracer_joined']
 value=json.loads(record['stdout']);assert (value['error'] is None)==success
 return value
def call(action,case,label,*,success=True,**options):
 before=snapshot(cases[case]) if action=='initialize' and success else None
 value=reply(finish(spawn(action,case,label,**options)),success=success)
 if action=='initialize' and success:result['initializations'].append({'case':case,'label':label,'before':before,'after':snapshot(cases[case])})
 return value
def refuse(action,case,label,**options):
 before=snapshot(cases[case]);value=call(action,case,label,success=False,**options);after=snapshot(cases[case]);assert before==after
 result['refusals'].append({'label':label,'before':before,'after':after,'reply':value});return value
try:
 progress('admission')
 assert os.geteuid()==os.getegid()==0
 assert pathlib.Path('/etc/fishhat-fixture-enrollment').read_text().strip()==c['enrollment']
 assert pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==c['boot_id']
 assert metadata(control_mount)['device']==c['storage']['control']['directory']['device']
 result['storage_before']=control_snapshot()
 assert result['storage_before']['directory']==c['storage']['control']['directory']
 for path,mode in ((prefix,0o755),(journal_root,0o700)):
  path.mkdir(mode=mode);path.chmod(mode);owned.append((path,directory_identity(path)))
 inputs=prefix/'inputs';inputs.mkdir(mode=0o700);traces=prefix/'traces';traces.mkdir(mode=0o700);control=prefix/'control';control.mkdir(mode=0o700)
 payload=sys.stdin.buffer.read();assert len(payload)==c['input_bytes'] and hashlib.sha256(payload).hexdigest()==c['input_sha256']
 with zipfile.ZipFile(io.BytesIO(payload)) as archive:
  assert len(archive.namelist())==len(c['input_members']) and set(archive.namelist())==set(c['input_members'])
  for member in archive.infolist():
   assert member.filename in c['input_members'] and not member.is_dir() and pathlib.PurePosixPath(member.filename).name==member.filename
   assert stat.S_IFMT(member.external_attr>>16) in (0,stat.S_IFREG)
   raw=archive.read(member);assert hashlib.sha256(raw).hexdigest()==c['input_members'][member.filename]
   with (inputs/member.filename).open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 result['transfer']={'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'members':{name:metadata(inputs/name) for name in c['input_members']}};del payload
 assert digest(inputs/'install.py')==c['bootstrap_sha256']
 spec=importlib.util.spec_from_file_location('approved_checkpoint_installer',inputs/'install.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 bundle=inputs/'bundle';bundle.mkdir(mode=0o700)
 with zipfile.ZipFile(inputs/'bundle.zip') as archive:
  seen=set()
  for member in archive.infolist():
   parts=module._member_parts(member.filename)
   assert '/'.join(parts)==member.filename and not member.is_dir() and member.filename not in seen
   assert stat.S_IFMT(member.external_attr>>16) in (0,stat.S_IFREG);seen.add(member.filename)
   target=bundle/member.filename;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   with archive.open(member) as source,target.open('xb') as output:shutil.copyfileobj(source,output,1048576)
 progress('observer');observer=prefix/'observer';observer.mkdir(mode=0o700);packages={}
 for name,pin in c['observer_pins'].items():
  path=inputs/name;assert path.stat().st_size==pin['bytes'] and digest(path)==pin['sha256'];fields={}
  for field in ('Package','Version','Architecture'):
   ran=subprocess.run(['/usr/bin/dpkg-deb','--field',str(path),field],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,env=clean,timeout=c['child_timeout']);assert ran.stderr==b'';fields[field]=ran.stdout.decode().strip()
  assert fields=={'Package':pin['package'],'Version':pin['version'],'Architecture':pin['architecture']}
  ran=subprocess.run(['/usr/bin/dpkg-deb','--fsys-tarfile',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,env=clean,timeout=c['child_timeout']);assert ran.stderr==b''
  with tarfile.open(fileobj=io.BytesIO(ran.stdout),mode='r:') as archive:archive.extractall(observer,filter='data')
  packages[name]={'bytes':path.stat().st_size,'sha256':digest(path),'fields':fields,'data_tar_sha256':hashlib.sha256(ran.stdout).hexdigest()}
 module._seal_python(observer);observer_env=clean|{'LD_LIBRARY_PATH':str(observer/'usr/lib/x86_64-linux-gnu')}
 result['observer_packages']=packages
 progress('installed-payload');executable=module._install_owner_python(inputs/'runtime.tar.gz',prefix/'runtime')
 module._install_owner_wheels(bundle,prefix/'packages',c['manifest_sha256'])
 for name in ('probe.py','context.json'):
  source=inputs/name;target=prefix/name
  with target.open('xb') as output:output.write(source.read_bytes());output.flush();os.fsync(output.fileno())
  target.chmod(0o444)
 configuration=json.loads((prefix/'context.json').read_text())
 assert configuration['enrollment']==c['enrollment'] and configuration['boot_id']==c['boot_id'] and configuration['probe_sha256']==digest(prefix/'probe.py')
 assert configuration['library']==str(prefix/'packages/lib') and configuration['control']==str(control)
 authority_root=prefix/'authority';authority_root.mkdir(mode=0o700)
 cases={name:pathlib.Path(value) for name,value in configuration['cases'].items()}
 assert set(cases)==set(c['cases']) and all(path==authority_root/name for name,path in cases.items())
 for path in cases.values():path.mkdir(mode=0o700)
 local_journal=prefix/'same-domain-journal';local_journal.mkdir(mode=0o700)
 journals=[journal_root/'original',journal_root/'copy']
 assert configuration['journals']==[str(path) for path in journals] and configuration['local_journal']==str(local_journal)
 for path in journals:path.mkdir(mode=0o700)
 head=(c['heads'][0]+'\n').encode();(journals[0]/'HEAD').write_bytes(head);(journals[0]/'HEAD').chmod(0o600)
 shutil.copyfile(journals[0]/'HEAD',journals[1]/'HEAD');(journals[1]/'HEAD').chmod(0o600)
 result['journals_before']=[snapshot(path) for path in journals]
 assert result['journals_before'][0]['entries']['HEAD']['inode']!=result['journals_before'][1]['entries']['HEAD']['inode']
 def mount(path):
  ran=subprocess.run(['/usr/bin/findmnt','--json','--target',str(path),'--output','TARGET,SOURCE,FSTYPE,UUID,MAJ:MIN,OPTIONS'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,env=clean,timeout=c['child_timeout']);assert ran.stderr==b''
  return {'arguments':ran.args,'stdout':ran.stdout.decode(),'filesystems':json.loads(ran.stdout)['filesystems']}
 result['capture_domains']={'guest_root':metadata(pathlib.Path('/')),'authority':{'directory':metadata(authority_root),'mount':mount(authority_root)},'journal':{'directory':metadata(journal_root),'mount':mount(journal_root)}}
 assert result['capture_domains']['authority']['directory']['device']!=result['capture_domains']['journal']['directory']['device']
 assert result['capture_domains']['authority']['directory']['device']==pathlib.Path('/').stat().st_dev
 installed={'runtime':prefix/'runtime','packages':prefix/'packages','observer':observer}
 result['installed_before']={name:inventory(path) for name,path in installed.items()};result['program_before']={name:metadata(prefix/name) for name in ('probe.py','context.json')}
 result['refusals']=[];result['initializations']=[]
 progress('genesis');result['genesis_before']=snapshot(cases['valid']);genesis=call('initialize','valid','initialize-valid');result['genesis_after']=snapshot(cases['valid'])
 first=snapshot(cases['valid']);call('inspect','valid','inspect-valid');assert snapshot(cases['valid'])==first
 call('deny-modification','valid','peer-modification-denied',role=c['peer_account'])
 refuse('initialize','valid','refuse-existing');refuse('inspect','missing','refuse-missing')
 for binding in ('owner','epoch','journal'):refuse('inspect','valid','refuse-'+binding,binding=binding)
 refuse('inspect','valid','refuse-same-domain',capture='same-domain')
 for role in (c['admin_account'],c['peer_account']):
  refuse('inspect','valid','refuse-'+role+'-inspect',role=role);refuse('initialize','valid','refuse-'+role+'-initialize',role=role)
 progress('cas');a,b=c['heads']
 call('publish','valid','publish-first',expected=None,current=a)
 refuse('publish','valid','refuse-stale',expected=None,current=b)
 call('publish','valid','publish-second',expected=a,current=b)
 first=snapshot(cases['valid']);call('publish','valid','publish-idempotent',expected=b,current=b);assert snapshot(cases['valid'])==first
 result['normal_publication']=snapshot(cases['valid'])
 progress('copies');call('initialize','contested','initialize-contested')
 entry=spawn('held-publish','contested','holder',expected=None,current=a);descriptor,live=wait_marker(entry)
 try:
  first=snapshot(cases['contested']);refuse('inspect','contested','copy-lock-refused',journal_index=1)
  send(entry,'publish');completed=reply(finish(entry));after=snapshot(cases['contested'])
 finally:os.close(descriptor)
 refuse('publish','contested','copy-stale-refused',journal_index=1,expected=None,current=b)
 inspected=call('inspect','contested','copy-inspect',journal_index=1)
 result['competition']={'live':live,'held':first,'published':after,'completed':completed,'inspected':inspected}
 progress('aliases');call('initialize','aliases','initialize-aliases');entry=spawn('alias-parent','aliases','alias-holder')
 parent_descriptor,parent_live=wait_marker(entry,'alias-holder-parent')
 try:send(entry,'spawn-child')
 finally:os.close(parent_descriptor)
 descriptor,live=wait_marker(entry)
 try:
  parent_pid=parent_live['process']['pid'];end=time.monotonic()+c['child_timeout']
  while pathlib.Path('/proc',str(parent_pid)).exists():assert time.monotonic()<end;time.sleep(0.02)
  refuse('inspect','aliases','inherited-lock-refused');send(entry,'close-first')
  second_descriptor,second_live=wait_marker(entry,'alias-holder-one')
  try:refuse('inspect','aliases','duplicate-lock-refused');send(entry,'close-last');completed=reply(finish(entry))
  finally:os.close(second_descriptor)
 finally:os.close(descriptor)
 inspected=call('inspect','aliases','aliases-final')
 result['aliases']={'parent_live':parent_live,'parent_absent_before_competition':True,'inherited_live':live,'single_alias_live':second_live,'completed':completed,'inspected':inspected}
 progress('anchor-substitution');result['anchor_substitutions']=[]
 for case,replace in (('replaced',True),('unlinked',False)):
  call('initialize',case,'initialize-'+case);entry=spawn('held-publish',case,'hold-'+case,expected=None,current=a);descriptor,live=wait_marker(entry)
  try:
   before=snapshot(cases[case]);anchor=cases[case]/'anchor'
   if replace:
    anchor.rename(control/(case+'-retained-anchor'));anchor.touch(mode=0o600,exist_ok=False)
   else:anchor.unlink()
   substituted=snapshot(cases[case]);refuse('inspect',case,case+'-new-holder-refused');send(entry,'publish');completed=reply(finish(entry),success=False)
   assert snapshot(cases[case])==substituted
  finally:os.close(descriptor)
  refuse('inspect',case,case+'-after-holder-refused')
  result['anchor_substitutions'].append({'case':case,'live':live,'before':before,'substituted':substituted,'held_reply':completed,'after':snapshot(cases[case])})
 progress('incomplete-genesis');entry=spawn('initialize','initializing','incomplete-initialize',inject='--inject=fsync:signal=SIGSTOP:when=1')
 descriptor,live=wait_stopped(entry,cases['initializing'],initializing=True)
 try:signal.pidfd_send_signal(descriptor,signal.SIGKILL);killed=finish(entry)
 finally:os.close(descriptor)
 first=snapshot(cases['initializing']);assert first==live['authority'];refuse('inspect','initializing','incomplete-open-refused');refuse('initialize','initializing','incomplete-reset-refused')
 call('initialize','fresh','fresh-initialize');result['incomplete_genesis']={'live':live,'killed':killed,'after':snapshot(cases['initializing']),'fresh':snapshot(cases['fresh'])}
 progress('interrupted-publication');call('initialize','interrupted','initialize-interrupted');call('publish','interrupted','interrupted-baseline',expected=None,current=a)
 before=snapshot(cases['interrupted']);entry=spawn('publish','interrupted','pending-publication',expected=a,current=b,inject='--inject=renameat:signal=SIGSTOP:when=1')
 descriptor,live=wait_stopped(entry,cases['interrupted'])
 try:signal.pidfd_send_signal(descriptor,signal.SIGKILL);killed=finish(entry)
 finally:os.close(descriptor)
 assert snapshot(cases['interrupted'])==live['authority'];refuse('inspect','interrupted','pending-open-refused');refuse('initialize','interrupted','pending-reset-refused')
 result['interruption']={'before':before,'live':live,'killed':killed,'after':snapshot(cases['interrupted'])}
 progress('lost-reply');call('initialize','lost','initialize-lost');entry=spawn('lost-reply','lost','lost-before-reply',expected=None,current=a)
 descriptor,live=wait_marker(entry)
 try:published=snapshot(cases['lost']);signal.pidfd_send_signal(descriptor,signal.SIGKILL);killed=finish(entry)
 finally:os.close(descriptor)
 assert killed['stdout']=='' and snapshot(cases['lost'])==published
 inspected=call('inspect','lost','lost-reply-inspect');refuse('publish','lost','lost-reply-stale',expected=None,current=a)
 result['lost_reply']={'live':live,'published':published,'killed':killed,'inspected':inspected,'after':snapshot(cases['lost'])}
 progress('controlled-publication-error');call('initialize','uncertain','initialize-uncertain')
 entry=spawn('uncertain-publish','uncertain','uncertain-publication',expected=None,current=a,inject='--inject=fsync:error=EIO:when=2');failed=reply(finish(entry),success=False)
 published=snapshot(cases['uncertain']);inspected=call('inspect','uncertain','uncertain-inspect');refuse('publish','uncertain','uncertain-stale',expected=None,current=a)
 result['uncertainty']={'scope':'controlled-syscall-error-after-replace-not-device-fault','failed':failed,'published':published,'inspected':inspected,'after':snapshot(cases['uncertain'])}
 progress('foreign-custody')
 for case in ('malformed','file-mode','directory-mode','file-owner','directory-owner','hardlink','capability','pending'):
  call('initialize',case,'initialize-'+case)
  if case=='malformed':(cases[case]/'current').write_bytes(b'not canonical checkpoint custody\n')
  elif case=='file-mode':(cases[case]/'current').chmod(0o640)
  elif case=='directory-mode':cases[case].chmod(0o750)
  elif case=='file-owner':os.chown(cases[case]/'current',c['peer_uid'],c['peer_gid'])
  elif case=='directory-owner':os.chown(cases[case],c['peer_uid'],c['peer_gid'])
  elif case=='hardlink':os.link(cases[case]/'current',control/'retained-current-alias')
  elif case=='capability':os.setxattr(cases[case]/'current','security.capability',struct.pack('<IIIII',0x02000001,1<<10,0,0,0))
  else:(cases[case]/'.pending').write_bytes(b'retained unknown publication\n')
  refuse('inspect',case,'foreign-'+case)
 result['journals_after']=[snapshot(path) for path in journals];assert result['journals_after']==result['journals_before']
 result['installed_after']={name:inventory(path) for name,path in installed.items()};assert result['installed_after']==result['installed_before']
 result['program_after']={name:metadata(prefix/name) for name in ('probe.py','context.json')};assert result['program_after']==result['program_before']
 result['storage_after']=control_snapshot();assert result['storage_after']==result['storage_before']
 result['status']='passed'
except BaseException as error:result['primary_error']={'stage':stage,'type':type(error).__name__,'message':str(error)};failure(error)
finally:
 progress('child-settlement')
 for entry in children:
  process=entry['process']
  try:
   if not entry['finished']:
    if process.poll() is None:os.killpg(process.pid,signal.SIGKILL)
    process.communicate(timeout=c['child_timeout'])
   assert process.poll() is not None
   pids=[int(path.name.rsplit('.',1)[1]) for path in trace_files(entry)]
   assert all(not pathlib.Path('/proc',str(pid)).exists() for pid in pids)
   result['owned_children'].append({'label':entry['label'],'tracer_pid':process.pid,'returncode':process.returncode,'tracer_joined':True,'tracee_pids':pids,'tracees_absent':True})
  except BaseException as error:result['cleanup_errors'].append({'stage':'child-settlement','label':entry['label'],'type':type(error).__name__})
 progress('owned-namespace')
 for path,identity in reversed(owned):
  try:
   assert directory_identity(path)==identity and shutil.rmtree.avoids_symlink_attacks
   shutil.rmtree(path);assert not path.exists();result['cleanup'].append({'path':str(path),'device':identity[0],'inode':identity[1],'removed':True})
  except BaseException as error:result['cleanup_errors'].append({'stage':'owned-namespace','type':type(error).__name__})
 if result['primary_error'] is not None or result['cleanup_errors']:result['status']='failed'
json.dump(result,sys.stdout,sort_keys=True);sys.stdout.write('\n');sys.stdout.flush()
"""
