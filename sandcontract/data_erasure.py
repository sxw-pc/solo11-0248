"""Customer-verifiable data erasure across physical media and wrapping keys.

The deletion scope is traced from sandbox write logs, archive pages, snapshots
and object copies down to physical blocks (including controller remap areas)
and every copy of the wrapping keys (datacenter, cache, offline disaster
recovery). Two contract strategies are supported on the same site:

* ``physical``  - rewrite shared blocks for the other tenant, seal the legally
  held pages, erase every remaining tenant block per media with controller
  receipts covering the remap area, then destroy every key copy.
* ``crypto``    - isolate the tenant's pages behind the tenant's own wrapping
  key and destroy every copy of that key (including offline copies); the
  retained ciphertext is released later through normal media reclamation.

No completion certificate is issued while a single receipt or evidence item is
missing or unverified. All evidence lives in a filesystem vault so state spans
the database and the filesystem; every stage is transactional and resumable and
can only advance to an evidenced state.
"""
import hashlib,json,os
from .store import one,rows

PHYSICAL='physical';CRYPTO='crypto'
STAGES={PHYSICAL:['intake','isolate','seal','erase','destroy_keys','certify'],
        CRYPTO:['intake','isolate','seal','shred_keys','certify']}

def _fh(*parts):
 return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()

def page_fingerprint(archive,page_no):
 """Stable plaintext identity of a logical page, independent of its block."""
 return _fh('page',archive,page_no)

def _canon(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'))

def _vault_write(root,rel,payload):
 path=os.path.join(root,rel)
 os.makedirs(os.path.dirname(path),exist_ok=True)
 data=payload.encode() if isinstance(payload,str) else payload
 with open(path,'wb') as f:f.write(data)
 return path,hashlib.sha256(data).hexdigest()

def _vault_digest(root,rel):
 with open(os.path.join(root,rel),'rb') as f:return hashlib.sha256(f.read()).hexdigest()

# ---------------------------------------------------------------- receipt API
def receipt_token(job,kind,target,extra=''):
 return _fh('receipt',job,kind,target,extra)

def receipt_payload(job,kind,target,extra=''):
 """The statement a controller / offline custodian returns for one target."""
 return _canon({'job':job,'kind':kind,'target':target,'extra':extra,'token':receipt_token(job,kind,target,extra)})

def _expected_extra(db,kind,target):
 if kind=='erase':
  b=one(db,'SELECT * FROM blocks WHERE id=?',(target,))
  if not b:return None
  return f"{b['media']}|{b['extent']}|{b['remap_extent']}"
 if kind=='destroy':
  c=one(db,'SELECT * FROM key_copies WHERE id=?',(target,))
  return c['key_id'] if c else None
 return ''

# ----------------------------------------------------------------- registries
def _register_media(db,x):
 if one(db,'SELECT id FROM media WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO media VALUES(?,?,?)',(x['id'],x['kind'],'active'))
 return {'decision':'media_registered'}

def _register_block(db,x):
 if one(db,'SELECT id FROM blocks WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 if not one(db,'SELECT id FROM media WHERE id=?',(x['media'],)):return {'decision':'invalid_reference'}
 db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?)',(x['id'],x['media'],x['extent'],x.get('remap_extent'),x['bytes_hash'],x.get('state','dedicated')))
 return {'decision':'block_registered'}

def _register_archive(db,x):
 if one(db,'SELECT id FROM archives WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO archives VALUES(?,?,?)',(x['id'],x['tenant'],'active'))
 return {'decision':'archive_registered'}

def _register_page(db,x):
 if one(db,'SELECT 1 FROM archive_pages WHERE archive=? AND page_no=?',(x['archive'],x['page_no'])):return {'decision':'already_registered'}
 if not one(db,'SELECT id FROM blocks WHERE id=?',(x['block_id'],)) or not one(db,'SELECT id FROM wrapping_keys WHERE id=?',(x['key_id'],)):return {'decision':'invalid_reference'}
 db.execute('INSERT INTO archive_pages VALUES(?,?,?,?,?,?)',(x['archive'],x['page_no'],x['tenant'],x['block_id'],x['key_id'],'active'))
 db.execute('INSERT OR IGNORE INTO block_refs VALUES(?,?,?,?)',(x['block_id'],x['archive'],x['page_no'],x['tenant']))
 return {'decision':'page_registered'}

def _register_snapshot(db,x):
 if one(db,'SELECT id FROM snapshots WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)',(x['id'],x['archive'],x['tenant'],x['block_id'],x['key_id'],'active'))
 return {'decision':'snapshot_registered'}

def _register_copy(db,x):
 if one(db,'SELECT id FROM object_copies WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO object_copies VALUES(?,?,?,?,?,?,?)',(x['id'],x['archive'],x['tenant'],x['location'],x['block_id'],x['key_id'],'active'))
 return {'decision':'copy_registered'}

def _register_write(db,x):
 if one(db,'SELECT id FROM sandbox_writes WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO sandbox_writes VALUES(?,?,?,?,?,?,?,?)',(x['id'],x['start_id'],x['tenant'],x['archive'],x['page_no'],x['block_id'],x['key_id'],'active'))
 return {'decision':'write_registered'}

def _register_key(db,x):
 if one(db,'SELECT id FROM wrapping_keys WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 db.execute('INSERT INTO wrapping_keys VALUES(?,?,?)',(x['id'],x['tenant'],'active'))
 return {'decision':'key_registered'}

def _register_key_copy(db,x):
 if one(db,'SELECT id FROM key_copies WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 if not one(db,'SELECT id FROM wrapping_keys WHERE id=?',(x['key_id'],)):return {'decision':'invalid_reference'}
 db.execute('INSERT INTO key_copies VALUES(?,?,?,?,?)',(x['id'],x['key_id'],x['location'],x.get('kind',x['location']),'active'))
 return {'decision':'key_copy_registered'}

def _register_hold(db,x):
 if one(db,'SELECT id FROM holds WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 if x.get('incident') and not one(db,'SELECT id FROM incidents WHERE id=?',(x['incident'],)):return {'decision':'invalid_reference'}
 if not one(db,'SELECT id FROM wrapping_keys WHERE id=? AND state=?',(x['seal_key_id'],'active')):return {'decision':'invalid_reference'}
 db.execute('INSERT INTO holds VALUES(?,?,?,?,?,?,?,?,?)',(x['id'],x['tenant'],x['archive'],x['page_from'],x['page_to'],x['until_ts'],x['seal_key_id'],x.get('incident'),'active'))
 return {'decision':'hold_registered'}

def _seal_evidence(db,x):
 """Custodian-sealed incident evidence that an erasure request must not touch."""
 if one(db,'SELECT id FROM sealed_evidence WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 hold=one(db,'SELECT * FROM holds WHERE id=?',(x['id_hold'],))
 if not hold:return {'decision':'invalid_reference'}
 root=x['vault_root']
 path,digest=_vault_write(root,f"incidents/{x['id']}.bin",_canon({'hold':hold['id'],'archive':x['archive'],'page_no':x['page_no'],'fingerprint':page_fingerprint(x['archive'],x['page_no'])}))
 db.execute('INSERT INTO sealed_evidence VALUES(?,?,?,?,?,?,?,?,?,?)',(x['id'],hold['id'],x['archive'],x['page_no'],hold['tenant'],path,digest,hold['seal_key_id'],hold['incident'],'sealed'))
 return {'decision':'evidence_sealed','digest':digest}

def _register_receipt(db,x):
 if one(db,'SELECT id FROM external_receipts WHERE id=?',(x['id'],)):return {'decision':'already_registered'}
 job=one(db,'SELECT * FROM erasure_jobs WHERE id=?',(x['job'],))
 if not job:return {'decision':'invalid_reference'}
 if x['kind'] not in ('erase','destroy'):return {'decision':'invalid_receipt'}
 extra=_expected_extra(db,x['kind'],x['target'])
 if extra is None:return {'decision':'invalid_reference'}
 try:stmt=json.loads(x['payload'])
 except (TypeError,ValueError):return {'decision':'receipt_rejected'}
 if stmt.get('job')!=x['job'] or stmt.get('kind')!=x['kind'] or stmt.get('target')!=x['target'] or stmt.get('extra')!=extra or stmt.get('token')!=receipt_token(x['job'],x['kind'],x['target'],extra):
  return {'decision':'receipt_rejected'}
 root=job['vault_root']
 path,digest=_vault_write(root,f"receipts/{x['id']}.json",x['payload'])
 db.execute('INSERT INTO external_receipts VALUES(?,?,?,?,?,?,?)',(x['id'],x['job'],x['kind'],x['target'],path,digest,'verified'))
 return {'decision':'receipt_registered','digest':digest}

# ------------------------------------------------------------- erasure intake
def _manifest_add(db,job,kind,ref_id,detail,state='pending'):
 db.execute('INSERT OR IGNORE INTO erasure_manifests VALUES(?,?,?,?,?)',(job,kind,ref_id,_canon(detail),state))

def _start_erasure(db,x):
 if x['strategy'] not in STAGES:return {'decision':'invalid_strategy'}
 arch=one(db,'SELECT * FROM archives WHERE id=?',(x['archive'],))
 if not arch:return {'decision':'invalid_reference'}
 if arch['tenant']!=x['tenant']:return {'decision':'tenant_mismatch'}
 prior=rows(db,'SELECT * FROM erasure_jobs WHERE archive=? ORDER BY id',(x['archive'],))
 live=[j for j in prior if not one(db,"SELECT 1 FROM certificates WHERE job=? AND state='revoked'",(j['id'],)) and one(db,"SELECT 1 FROM certificates WHERE job=? AND state='issued'",(j['id'],))]
 if live:return {'decision':'already_erased','job':live[-1]['id']}
 if prior:return {'decision':'resume_required','job':prior[-1]['id']}
 db.execute('CREATE TABLE IF NOT EXISTS retention_records(id TEXT PRIMARY KEY,start_id TEXT,archive_id TEXT,state TEXT)')
 rec=one(db,'SELECT * FROM retention_records WHERE start_id=? AND archive_id=?',(x['start_id'],x['archive']))
 if not rec or rec['state'] not in ('provisional','erasing'):return {'decision':'retention_record_missing'}
 if not one(db,'SELECT id FROM starts WHERE id=?',(x['start_id'],)):return {'decision':'start_missing'}
 tenant=x['tenant'];job=x['id']
 pages=rows(db,'SELECT * FROM archive_pages WHERE archive=? AND tenant=?',(x['archive'],tenant))
 if not pages:return {'decision':'empty_archive'}
 page_nos={p['page_no'] for p in pages}
 active_holds=rows(db,'SELECT * FROM holds WHERE tenant=? AND archive=? AND state=?',(tenant,x['archive'],'active'))
 for h in active_holds:
  if h['page_from']>h['page_to'] or any(no not in page_nos for no in range(h['page_from'],h['page_to']+1)):return {'decision':'hold_outside_archive','hold':h['id']}
 db.execute("INSERT INTO erasure_jobs VALUES(?,?,?,?,?,?,?)",(x['id'],x['tenant'],x['archive'],x['start_id'],x['strategy'],'running',x['vault_root']))
 db.execute("UPDATE retention_records SET state='erasing' WHERE start_id=? AND archive_id=?",(x['start_id'],x['archive']))
 block_ids=set()
 for p in pages:
  _manifest_add(db,job,'page',f"{p['archive']}:{p['page_no']}",p)
  block_ids.add(p['block_id'])
 for tbl,kind in (('snapshots','snapshot'),('object_copies','copy'),('sandbox_writes','write')):
  for r in rows(db,f'SELECT * FROM {tbl} WHERE archive=? AND tenant=?',(x['archive'],tenant)):
   _manifest_add(db,job,kind,r['id'],r);block_ids.add(r['block_id'])
 for bid in sorted(block_ids):
  b=one(db,'SELECT * FROM blocks WHERE id=?',(bid,))
  _manifest_add(db,job,'block',bid,b)
 for k in rows(db,'SELECT * FROM wrapping_keys WHERE tenant=?',(tenant,)):
  _manifest_add(db,job,'key',k['id'],k)
  for c in rows(db,'SELECT * FROM key_copies WHERE key_id=?',(k['id'],)):_manifest_add(db,job,'key_copy',c['id'],c)
 for h in active_holds:_manifest_add(db,job,'hold',h['id'],h)
 for stage in STAGES[x['strategy']]:db.execute('INSERT INTO erasure_stages VALUES(?,?,?,?)',(job,stage,'complete' if stage=='intake' else 'pending',None))
 _vault_write(x['vault_root'],f"jobs/{job}/manifest.json",_canon(rows(db,'SELECT * FROM erasure_manifests WHERE job=? ORDER BY kind,ref_id',(job,))))
 return {'decision':'erasure_started','job':job,'stages':STAGES[x['strategy']]}

# -------------------------------------------------------------------- stages
def _stage(db,job,name):return one(db,'SELECT * FROM erasure_stages WHERE job=? AND stage=?',(job,name))
def _done(db,job,name):
 s=_stage(db,job,name);return bool(s and s['state']=='complete')
def _complete(db,job,name,detail):
 db.execute('UPDATE erasure_stages SET state=?,detail=? WHERE job=? AND stage=?',('complete',_canon(detail),job,name))

def _held_ranges(db,job):
 out=[]
 for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='hold'",(job,)):
  h=one(db,"SELECT * FROM holds WHERE id=? AND state='active'",(m['ref_id'],))
  if h:out.append(h)
 return out

def _isolate(db,job,fault):
 if _done(db,job,'isolate'):return {'decision':'stage_already_complete','stage':'isolate'}
 tenant=one(db,'SELECT * FROM erasure_jobs WHERE id=?',(job,))['tenant']
 migrations=[]
 for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='block'",(job,)):
  bid=m['ref_id'];b=one(db,'SELECT * FROM blocks WHERE id=?',(bid,))
  others=[r for r in rows(db,'SELECT * FROM block_refs WHERE block_id=?',(bid,)) if r['tenant']!=tenant]
  if not others:continue
  by_tenant={}
  for r in others:by_tenant.setdefault(r['tenant'],[]).append(r)
  for ot,refs in sorted(by_tenant.items()):
   nbid=f"{bid}--dedicated--{ot}"
   if not one(db,'SELECT id FROM blocks WHERE id=?',(nbid,)):
    db.execute('INSERT INTO blocks VALUES(?,?,?,?,?,?)',(nbid,b['media'],f"{b['extent']}--d-{ot}",b['remap_extent'],_fh(b['bytes_hash'],ot),'dedicated'))
   nb=one(db,'SELECT * FROM blocks WHERE id=?',(nbid,))
   _manifest_add(db,job,'block',nbid,nb,'migrated')
   for r in refs:
    db.execute('INSERT OR IGNORE INTO block_refs VALUES(?,?,?,?)',(nbid,r['archive'],r['page_no'],ot))
    for tbl in ('archive_pages','snapshots','object_copies','sandbox_writes'):
     ids=rows(db,f'SELECT * FROM {tbl} WHERE block_id=? AND tenant=?',(bid,ot))
     for row in ids:
      key_col='page_no' if tbl in ('archive_pages','sandbox_writes') else 'id'
      db.execute(f'UPDATE {tbl} SET block_id=? WHERE {key_col}=? AND tenant=?',(nbid,row[key_col],ot))
    db.execute('DELETE FROM block_refs WHERE block_id=? AND archive=? AND page_no=? AND tenant=?',(bid,r['archive'],r['page_no'],ot))
   migrations.append({'from':bid,'to':nbid,'tenant':ot,'pages':[r['page_no'] for r in refs]})
  db.execute("UPDATE blocks SET state='a_only' WHERE id=?",(bid,))
  db.execute("UPDATE erasure_manifests SET state='a_only' WHERE job=? AND kind='block' AND ref_id=?",(job,bid))
 root=one(db,'SELECT vault_root FROM erasure_jobs WHERE id=?',(job,))['vault_root']
 path,digest=_vault_write(root,f"jobs/{job}/isolate.json",_canon({'migrations':migrations}))
 _complete(db,job,'isolate',{'migrations':migrations,'evidence':digest})
 return {'decision':'isolated','migrations':len(migrations),'evidence':path}

def _seal(db,job,fault):
 if _done(db,job,'seal'):return {'decision':'stage_already_complete','stage':'seal'}
 root=one(db,'SELECT vault_root FROM erasure_jobs WHERE id=?',(job,))['vault_root']
 sealed=[]
 for h in _held_ranges(db,job):
  for page_no in range(h['page_from'],h['page_to']+1):
   ev=one(db,'SELECT * FROM sealed_evidence WHERE hold=? AND archive=? AND page_no=? AND state=?',(h['id'],h['archive'],page_no,'sealed'))
   if ev:
    if _vault_digest(root,os.path.relpath(ev['vault_path'],root))!=ev['digest']:return {'decision':'evidence_tampered'}
    sealed.append({'page':page_no,'reused':ev['id']});continue
   if fault=='seal':return {'decision':'seal_failed'}
   eid=f"seal-{h['id']}-{page_no}"
   payload=_canon({'hold':h['id'],'archive':h['archive'],'page_no':page_no,'tenant':h['tenant'],'fingerprint':page_fingerprint(h['archive'],page_no),'incident':h['incident']})
   path,digest=_vault_write(root,f"seals/{eid}.bin",payload)
   db.execute('INSERT INTO sealed_evidence VALUES(?,?,?,?,?,?,?,?,?,?)',(eid,h['id'],h['archive'],page_no,h['tenant'],path,digest,h['seal_key_id'],h['incident'],'sealed'))
   db.execute("UPDATE archive_pages SET state='held' WHERE archive=? AND page_no=? AND tenant=?",(h['archive'],page_no,h['tenant']))
   db.execute("UPDATE sandbox_writes SET state='held' WHERE archive=? AND tenant=? AND page_no=?",(h['archive'],h['tenant'],page_no))
   sealed.append({'page':page_no,'evidence':eid})
 held_block_ids=_held_block_ids(db,job)
 if held_block_ids:
  marks=','.join('?'*len(held_block_ids))
  db.execute(f"UPDATE snapshots SET state='held' WHERE block_id IN ({marks})",tuple(held_block_ids))
  db.execute(f"UPDATE object_copies SET state='held' WHERE block_id IN ({marks})",tuple(held_block_ids))
 _complete(db,job,'seal',{'sealed':sealed})
 return {'decision':'sealed','pages':sealed}

def _job_blocks(db,job):
 return [one(db,'SELECT * FROM blocks WHERE id=?',(m['ref_id'],)) for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='block' AND state!='migrated'",(job,))]

def _held_block_ids(db,job):
 ids=set()
 for h in _held_ranges(db,job):
  for p in rows(db,'SELECT block_id FROM archive_pages WHERE archive=? AND tenant=? AND page_no BETWEEN ? AND ?',(h['archive'],h['tenant'],h['page_from'],h['page_to'])):ids.add(p['block_id'])
 return ids

def _verified_receipt(db,job,kind,target):
 r=one(db,"SELECT * FROM external_receipts WHERE job=? AND kind=? AND target=? AND state='verified'",(job,kind,target))
 if not r:return None
 extra=_expected_extra(db,kind,target)
 with open(r['vault_path'],encoding='utf8') as f:token=json.loads(f.read())['token']
 if receipt_token(job,kind,target,extra)!=token:return None
 return r

def _erase_blocks(db,job,fault):
 if _done(db,job,'erase'):return {'decision':'stage_already_complete','stage':'erase'}
 root=one(db,'SELECT vault_root FROM erasure_jobs WHERE id=?',(job,))['vault_root']
 protected=_held_block_ids(db,job);targets=[];missing=[]
 for b in _job_blocks(db,job):
  if b['id'] in protected:continue
  if b['state']=='erased':continue
  if not b['remap_extent']:return {'decision':'remap_unverified','block':b['id']}
  if fault=='erase':return {'decision':'erase_receipt_missing','block':b['id']}
  r=_verified_receipt(db,job,'erase',b['id'])
  if not r:missing.append(b['id'])
  else:targets.append((b,r))
 if missing:return {'decision':'erase_receipt_missing','blocks':missing}
 # Every controller receipt is verified first; only now does the stage commit.
 erased=[]
 for b,r in targets:
  db.execute("UPDATE blocks SET state='erased' WHERE id=?",(b['id'],))
  for tbl in ('archive_pages','snapshots','object_copies','sandbox_writes'):
   db.execute(f"UPDATE {tbl} SET state='erased' WHERE block_id=? AND state!='held'",(b['id'],))
  erased.append({'block':b['id'],'media':b['media'],'receipt':r['id'],'digest':r['digest']})
 for bid in protected:db.execute("UPDATE blocks SET state='retained' WHERE id=?",(bid,))
 path,digest=_vault_write(root,f"jobs/{job}/erase.json",_canon({'erased':erased,'retained':sorted(protected)}))
 _complete(db,job,'erase',{'erased':erased,'retained':sorted(protected),'evidence':digest})
 return {'decision':'erased','blocks':len(erased),'retained':sorted(protected),'evidence':path}

def _seal_key_ids(db,job):
 ids=set()
 for h in _held_ranges(db,job):
  for ev in rows(db,"SELECT seal_key_id FROM sealed_evidence WHERE hold=? AND state='sealed'",(h['id'],)):ids.add(ev['seal_key_id'])
 return ids

def _destroy_keys(db,job,stage,fault):
 if _done(db,job,stage):return {'decision':'stage_already_complete','stage':stage}
 root=one(db,'SELECT vault_root FROM erasure_jobs WHERE id=?',(job,))['vault_root']
 protected=_seal_key_ids(db,job);targets=[];missing=[]
 for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='key'",(job,)):
  kid=m['ref_id']
  if kid in protected:continue
  for c in rows(db,'SELECT * FROM key_copies WHERE key_id=?',(kid,)):
   if c['state']=='destroyed':continue
   if fault=='destroy':return {'decision':'key_destruction_unverified','copy':c['id']}
   r=_verified_receipt(db,job,'destroy',c['id'])
   if not r:missing.append({'copy':c['id'],'location':c['location']})
   else:targets.append((kid,c,r))
 if missing:return {'decision':'key_destruction_unverified','copies':missing}
 destroyed=[]
 for kid,c,r in targets:
  db.execute("UPDATE key_copies SET state='destroyed' WHERE id=?",(c['id'],))
  destroyed.append({'copy':c['id'],'key':kid,'location':c['location'],'receipt':r['id']})
 for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='key'",(job,)):
  kid=m['ref_id']
  if not rows(db,"SELECT id FROM key_copies WHERE key_id=? AND state!='destroyed'",(kid,)):
   db.execute("UPDATE wrapping_keys SET state='destroyed' WHERE id=?",(kid,))
 path,digest=_vault_write(root,f"jobs/{job}/{stage}.json",_canon({'destroyed':destroyed,'protected_seal_keys':sorted(protected)}))
 _complete(db,job,stage,{'destroyed':destroyed,'evidence':digest})
 return {'decision':'keys_destroyed','copies':len(destroyed),'evidence':path}

def _retained_a_blocks(db,job,tenant):
 out=[]
 for b in _job_blocks(db,job):
  if b['state'] in ('erased',):continue
  tenants={r['tenant'] for r in rows(db,'SELECT tenant FROM block_refs WHERE block_id=?',(b['id'],))}
  page_tenants=set()
  for p in rows(db,'SELECT tenant FROM archive_pages WHERE block_id=?',(b['id'],)):page_tenants.add(p['tenant'])
  if tenants|page_tenants:
   if (tenants|page_tenants)-{tenant}:return None,b['id']
  out.append(b['id'])
 return out,None

def _certify(db,job,fault):
 if _done(db,job,'certify'):
  c=one(db,"SELECT * FROM certificates WHERE job=? AND state='issued'",(job,))
  return {'decision':'already_certified','certificate':c['id'] if c else None}
 j=one(db,'SELECT * FROM erasure_jobs WHERE id=?',(job,));tenant=j['tenant'];strategy=j['strategy']
 held=_held_ranges(db,job)
 protected_blocks=_held_block_ids(db,job)
 retained,foreign=_retained_a_blocks(db,job,tenant)
 if foreign:return {'decision':'foreign_tenant_on_retained_block','block':foreign}
 if strategy==PHYSICAL:
  for b in _job_blocks(db,job):
   if b['id'] in protected_blocks:
    if b['state']!='retained':return {'decision':'held_block_not_isolated','block':b['id']}
   elif b['state']!='erased':return {'decision':'physical_erase_incomplete','block':b['id']}
  if not _done(db,job,'erase') or not _done(db,job,'destroy_keys'):return {'decision':'prerequisite_stage_open'}
 else:
  if not _done(db,job,'shred_keys'):return {'decision':'prerequisite_stage_open'}
  for bid in retained:
   db.execute("UPDATE blocks SET state=? WHERE id=?",('retained' if bid in protected_blocks else 'retained_cipher',bid))
  for k in rows(db,'SELECT * FROM wrapping_keys WHERE tenant=?',(tenant,)):
   if k['id'] not in _seal_key_ids(db,job) and k['state']!='destroyed':return {'decision':'key_copy_survives','key':k['id']}
 for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='key_copy'",(job,)):
  c=one(db,'SELECT * FROM key_copies WHERE id=?',(m['ref_id'],))
  if c and c['key_id'] not in _seal_key_ids(db,job) and c['state']!='destroyed':return {'decision':'key_copy_survives','copy':c['id']}
 for ev in rows(db,"SELECT * FROM sealed_evidence WHERE state='sealed' AND tenant=?",(tenant,)):
  root=j['vault_root']
  if not os.path.exists(ev['vault_path']) or _vault_digest(root,os.path.relpath(ev['vault_path'],root))!=ev['digest']:return {'decision':'evidence_tampered'}
 scope={'erased_pages':[],'retained_holds':[{'hold':h['id'],'pages':[h['page_from'],h['page_to']],'until_ts':h['until_ts']} for h in held],
        'erased_blocks':[b['id'] for b in _job_blocks(db,job) if b['state']=='erased'],
        'retained_blocks':[b['id'] for b in _job_blocks(db,job) if b['state'] in ('retained','retained_cipher')],
        'destroyed_keys':[m['ref_id'] for m in rows(db,"SELECT * FROM erasure_manifests WHERE job=? AND kind='key'",(job,)) if one(db,"SELECT state FROM wrapping_keys WHERE id=?",(m['ref_id'],))['state']=='destroyed'],
        'strategy':strategy}
 for p in rows(db,'SELECT * FROM archive_pages WHERE archive=? AND tenant=?',(j['archive'],tenant)):
  if p['state'] in ('erased','held') or (strategy==CRYPTO and one(db,"SELECT state FROM wrapping_keys WHERE id=?",(p['key_id'],))['state']=='destroyed'):scope['erased_pages'].append(p['page_no'])
 kind='partial' if held else 'full'
 root=j['vault_root']
 cert_id=_pending_cert(db,job)
 payload=_canon({'job':job,'kind':kind,'tenant':tenant,'archive':j['archive'],'scope':scope})
 path,digest=_vault_write(root,f"certs/{cert_id}.json",payload)
 db.execute('INSERT INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?)',(cert_id,job,kind,tenant,j['archive'],_canon(scope),'unrecoverable' if kind=='full' else 'partial_retained','issued',path,None))
 if held:
  db.execute("UPDATE erasure_jobs SET state='certified_hold' WHERE id=?",(job,))
  db.execute("UPDATE archives SET state='retained_hold' WHERE id=?",(j['archive'],))
  db.execute("UPDATE retention_records SET state='retained_hold' WHERE start_id=? AND archive_id=?",(j['start_id'],j['archive']))
  decision='partial_certified'
 else:
  db.execute("UPDATE erasure_jobs SET state='certified' WHERE id=?",(job,))
  db.execute("UPDATE archives SET state='erased' WHERE id=?",(j['archive'],))
  db.execute("UPDATE retention_records SET state='erased' WHERE start_id=? AND archive_id=?",(j['start_id'],j['archive']))
  decision='certified'
 _complete(db,job,'certify',{'certificate':cert_id,'digest':digest})
 return {'decision':decision,'certificate':cert_id,'digest':digest,'scope':scope}

def _pending_cert(db,job):
 n=rows(db,"SELECT id FROM certificates WHERE id LIKE ?",(f'cert-{job}-%',))
 return f'cert-{job}-{len(n)+1}'

def _proceed(db,x):
 j=one(db,'SELECT * FROM erasure_jobs WHERE id=?',(x['job'],))
 if not j:return {'decision':'invalid_reference'}
 if j['state'] in ('certified','certified_hold'):return {'decision':'already_certified','job':x['job'],'state':j['state']}
 fault=x.get('fault')
 for stage in STAGES[j['strategy']]:
  s=_stage(db,x['job'],stage)
  if s and s['state']=='complete':continue
  if stage=='isolate':return _isolate(db,x['job'],fault)
  if stage=='seal':return _seal(db,x['job'],fault)
  if stage=='erase':return _erase_blocks(db,x['job'],fault)
  if stage in ('destroy_keys','shred_keys'):return _destroy_keys(db,x['job'],stage,fault)
  if stage=='certify':return _certify(db,x['job'],fault)
 return {'decision':'nothing_pending'}

# ------------------------------------------------------------- hold release
def _release_hold(db,x):
 h=one(db,"SELECT * FROM holds WHERE id=? AND state='active'",(x['hold'],))
 if not h:return {'decision':'hold_not_active'}
 if x['at']<h['until_ts']:return {'decision':'hold_not_expired'}
 job=one(db,"SELECT * FROM erasure_jobs WHERE archive=? AND tenant=? AND state='certified_hold'",(h['archive'],h['tenant']))
 if not job:return {'decision':'no_certified_job'}
 root=job['vault_root'];job=job['id'];fault=x.get('fault')
 block_ids={p['block_id'] for p in rows(db,'SELECT block_id FROM archive_pages WHERE archive=? AND tenant=? AND page_no BETWEEN ? AND ?',(h['archive'],h['tenant'],h['page_from'],h['page_to']))}
 seal_copies=[c for c in rows(db,'SELECT * FROM key_copies WHERE key_id=?',(h['seal_key_id'],)) if c['state']!='destroyed']
 # Verify every controller and seal-key receipt before any state changes.
 for bid in sorted(block_ids):
  b=one(db,'SELECT * FROM blocks WHERE id=?',(bid,))
  if b['state']=='erased':continue
  if not b['remap_extent']:return {'decision':'remap_unverified','block':bid}
  if fault=='erase':return {'decision':'erase_receipt_missing','block':bid}
  if not _verified_receipt(db,job,'erase',bid):return {'decision':'erase_receipt_missing','block':bid}
 for c in seal_copies:
  if fault=='destroy':return {'decision':'key_destruction_unverified','copy':c['id']}
  if not _verified_receipt(db,job,'destroy',c['id']):return {'decision':'key_destruction_unverified','copy':c['id']}
 erased=[]
 for bid in sorted(block_ids):
  b=one(db,'SELECT * FROM blocks WHERE id=?',(bid,))
  if b['state']=='erased':continue
  db.execute("UPDATE blocks SET state='erased' WHERE id=?",(bid,))
  db.execute("UPDATE archive_pages SET state='erased' WHERE archive=? AND page_no BETWEEN ? AND ? AND tenant=?",(h['archive'],h['page_from'],h['page_to'],h['tenant']))
  erased.append(bid)
 destroyed=[]
 for c in seal_copies:
  db.execute("UPDATE key_copies SET state='destroyed' WHERE id=?",(c['id'],));destroyed.append(c['id'])
 db.execute("UPDATE wrapping_keys SET state='destroyed' WHERE id=?",(h['seal_key_id'],))
 if h['incident']:
  db.execute("UPDATE sealed_evidence SET state='retained_evidence' WHERE hold=? AND incident IS NOT NULL",(h['id'],))
 else:
  db.execute("UPDATE sealed_evidence SET state='destroyed' WHERE hold=?",(h['id'],))
 db.execute("UPDATE holds SET state='released' WHERE id=?",(h['id'],))
 partial=one(db,"SELECT * FROM certificates WHERE job=? AND state='issued' AND kind='partial'",(job,))
 new_id=f'cert-{job}-release'
 path,digest=_vault_write(root,f"certs/{new_id}.json",_canon({'job':job,'kind':'full','released_hold':h['id'],'erased_blocks':erased,'destroyed_seal_copies':destroyed}))
 if partial:
  db.execute("UPDATE certificates SET state='revoked' WHERE id=?",(partial['id'],))
  _vault_write(root,f"revocations/{partial['id']}.json",_canon({'revoked':partial['id'],'replacement':new_id,'reason':'hold_expired'}))
  db.execute('INSERT INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?)',(new_id,job,'full',h['tenant'],h['archive'],_canon({'released_hold':h['id']}),'unrecoverable','issued',path,partial['id']))
 else:
  db.execute('INSERT INTO certificates VALUES(?,?,?,?,?,?,?,?,?,?)',(new_id,job,'full',h['tenant'],h['archive'],_canon({'released_hold':h['id']}),'unrecoverable','issued',path,None))
 db.execute("UPDATE erasure_jobs SET state='certified' WHERE id=?",(job,))
 db.execute("UPDATE archives SET state='erased' WHERE id=?",(h['archive'],))
 db.execute("UPDATE retention_records SET state='erased' WHERE archive_id=?",(h['archive'],))
 return {'decision':'hold_released','erased_blocks':erased,'certificate':new_id,'revoked':partial['id'] if partial else None}

def _reclaim(db,x):
 j=one(db,"SELECT * FROM erasure_jobs WHERE id=? AND strategy=?",(x['job'],CRYPTO))
 if not j:return {'decision':'invalid_reference'}
 if j['state'] not in ('certified','certified_hold'):return {'decision':'job_not_certified'}
 root=j['vault_root'];reclaimed=[]
 for b in _job_blocks(db,x['job']):
  if b['state']!='retained_cipher':continue
  if not b['remap_extent']:return {'decision':'remap_unverified','block':b['id']}
  r=_verified_receipt(db,x['job'],'erase',b['id'])
  if not r:return {'decision':'erase_receipt_missing','block':b['id']}
  db.execute("UPDATE blocks SET state='erased' WHERE id=?",(b['id'],));reclaimed.append(b['id'])
 path,digest=_vault_write(root,f"jobs/{x['job']}/reclaim.json",_canon({'reclaimed':reclaimed}))
 return {'decision':'reclaimed','blocks':reclaimed,'evidence':path}

def _revoke_certificate(db,x):
 c=one(db,"SELECT * FROM certificates WHERE id=? AND state='issued'",(x['certificate'],))
 if not c:return {'decision':'certificate_not_active'}
 root=one(db,'SELECT vault_root FROM erasure_jobs WHERE id=?',(c['job'],))['vault_root']
 path,digest=_vault_write(root,f"revocations/{c['id']}.json",_canon({'revoked':c['id'],'reason':x['reason']}))
 db.execute("UPDATE certificates SET state='revoked' WHERE id=?",(c['id'],))
 return {'decision':'certificate_revoked','certificate':c['id'],'evidence':path}

# -------------------------------------------------------------- readability
def read_page(db,archive,page_no):
 """Customer-verifiable read probe: who can still reconstruct this page."""
 p=one(db,'SELECT * FROM archive_pages WHERE archive=? AND page_no=?',(archive,page_no))
 if not p:return {'readable':False,'reason':'unknown_page'}
 b=one(db,'SELECT * FROM blocks WHERE id=?',(p['block_id'],))
 k=one(db,'SELECT * FROM wrapping_keys WHERE id=?',(p['key_id'],))
 if p['state']=='erased' or (b and b['state']=='erased'):return {'readable':False,'reason':'physical_erased','fingerprint':page_fingerprint(archive,page_no)}
 ev=one(db,"SELECT * FROM sealed_evidence WHERE archive=? AND page_no=? AND state='sealed' ORDER BY id",(archive,page_no))
 if ev:
  return {'readable':True,'via':'sealed_evidence','fingerprint':page_fingerprint(archive,page_no),'evidence':ev['id'],'seal_key':ev['seal_key_id']}
 if k and k['state']=='destroyed':return {'readable':False,'reason':'key_destroyed','fingerprint':page_fingerprint(archive,page_no)}
 return {'readable':True,'via':'live','fingerprint':page_fingerprint(archive,page_no),'block':p['block_id'],'key':p['key_id']}

def run(db,x):
 op=x['op']
 if op=='register_media':return _register_media(db,x)
 if op=='register_block':return _register_block(db,x)
 if op=='register_archive':return _register_archive(db,x)
 if op=='register_page':return _register_page(db,x)
 if op=='register_snapshot':return _register_snapshot(db,x)
 if op=='register_copy':return _register_copy(db,x)
 if op=='register_write':return _register_write(db,x)
 if op=='register_key':return _register_key(db,x)
 if op=='register_key_copy':return _register_key_copy(db,x)
 if op=='register_hold':return _register_hold(db,x)
 if op=='seal_evidence':return _seal_evidence(db,x)
 if op=='register_receipt':return _register_receipt(db,x)
 if op=='erase':return _start_erasure(db,x)
 if op=='proceed':return _proceed(db,x)
 if op=='release_hold':return _release_hold(db,x)
 if op=='reclaim':return _reclaim(db,x)
 if op=='revoke_certificate':return _revoke_certificate(db,x)
 raise ValueError(op)
