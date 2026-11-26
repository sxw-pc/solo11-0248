"""Revoke stolen dataset keys, re-encrypt confirmed data, hand service over.

A lease row marked revoked, or a newer key version admitted by latest row,
never proves the old key is dead: only rejection receipts from the database
endpoint and every online holder, or attested destruction of offline copies,
close the old-key window. Re-encryption is staged inside a hardware boundary
and cut over atomically, so an interrupted run never leaves a
customer-confirmed page readable only by the stolen key. Pre-incident read
facts and delivered fence receipts are append-only evidence.
"""
from .store import one,rows

def _compromise(db,key,version):
 return one(db,'SELECT * FROM key_compromises WHERE key_id=? AND version=?',(key,version))
def _recovery(db,key,version):
 return one(db,'SELECT * FROM recoveries WHERE key_id=? AND version=?',(key,version))
def _fenced(db,key,version):
 return {r['holder'] for r in rows(db,'SELECT holder FROM key_fences WHERE key_id=? AND version=?',(key,version))}
def _key_known(db,key,version):
 return one(db,'SELECT 1 FROM key_leases WHERE key_id=? AND version=?',(key,version)) or one(db,'SELECT 1 FROM key_copies WHERE key_id=? AND version=?',(key,version))
def _holders(db,key,version):
 fenced=_fenced(db,key,version)
 leases=rows(db,'SELECT * FROM key_leases WHERE key_id=? AND version=? ORDER BY id',(key,version))
 copies=rows(db,'SELECT * FROM key_copies WHERE key_id=? AND version=? ORDER BY id',(key,version))
 out=[]
 if leases or copies or _compromise(db,key,version):out.append({'holder':'db','kind':'database','fenced':'db' in fenced})
 for l in leases:
  out.append({'holder':l['id'],'kind':'lease','workload':l['workload'],'purpose':l['purpose'],'lease_state':l['state'],'fenced':l['id'] in fenced})
 for c in copies:
  out.append({'holder':c['holder'],'kind':c['kind'],'online':bool(c['online']),'fenced':c['holder'] in fenced})
 return out
def _open(db,key,version):return [h['holder'] for h in _holders(db,key,version) if not h['fenced']]
def _required(db,dataset):
 a=one(db,'SELECT MAX(record) m FROM customer_acks WHERE dataset=?',(dataset,))['m'] or 0
 r=one(db,'SELECT MAX(record) m FROM read_facts WHERE dataset=?',(dataset,))['m'] or 0
 return max(a,r)
def _notify(db,nid,kind,detail,at):
 db.execute('INSERT INTO notifications VALUES(?,?,?,?)',(nid,kind,detail,at))
def _sources(db,dataset,fk,fv,need,live_ok):
 snap=one(db,'SELECT * FROM snapshots WHERE dataset=?',(dataset,))
 plan=[]
 for r in range(1,need+1):
  page=one(db,'SELECT * FROM dataset_pages WHERE dataset=? AND record=?',(dataset,r))
  if live_ok and page and page['key_id']==fk and page['version']==fv:src='live'
  elif snap and snap['key_id']==fk and snap['version']==fv and r<=snap['up_to']:src='snapshot'
  elif one(db,'SELECT 1 FROM customer_logs WHERE dataset=? AND record=?',(dataset,r)):src='customer-log'
  else:return None,r
  plan.append((r,src))
 return plan,None

def run(db,x):
 op=x['op']
 if op=='dataset':
  if one(db,'SELECT id FROM datasets WHERE id=?',(x['id'],)):return {'decision':'dataset_conflict'}
  db.execute('INSERT INTO datasets VALUES(?,?,?,NULL,NULL,NULL)',(x['id'],x['key_id'],x['version']))
  return {'decision':'dataset_recorded'}
 if op=='lease':
  old=one(db,'SELECT * FROM key_leases WHERE id=?',(x['id'],))
  if old:
   same=all(old[k]==x[k] for k in ('workload','start_id','dataset','key_id','version','purpose','expires_at'))
   return {'decision':'reused' if same else 'conflict'}
  start=one(db,'SELECT * FROM starts WHERE id=?',(x['start_id'],))
  if not start:return {'decision':'unavailable'}
  b=one(db,'SELECT * FROM bindings WHERE id=?',(start['binding'],))
  if not b or b['workload']!=x['workload']:return {'decision':'lease_binding_mismatch'}
  if not one(db,'SELECT id FROM datasets WHERE id=?',(x['dataset'],)):return {'decision':'unknown_dataset'}
  if x['purpose'] not in ('read','write','sign'):return {'decision':'invalid_purpose'}
  if x['expires_at']<=x['at']:return {'decision':'expired_lease'}
  if _compromise(db,x['key_id'],x['version']):return {'decision':'key_compromised'}
  if b['status']=='quarantined':return {'decision':'binding_quarantined'}
  if x['purpose']=='write' and one(db,"SELECT id FROM key_leases WHERE dataset=? AND purpose='write' AND state='issued'",(x['dataset'],)):return {'decision':'writer_conflict'}
  g=one(db,'SELECT COUNT(*) n FROM starts WHERE binding=?',(start['binding'],))['n']
  db.execute('INSERT INTO key_leases VALUES(?,?,?,?,?,?,?,?,?,?,NULL)',(x['id'],x['workload'],x['start_id'],g,x['dataset'],x['key_id'],x['version'],x['purpose'],x['expires_at'],'issued'))
  if x['purpose']=='write':db.execute('UPDATE datasets SET writer=? WHERE id=?',(x['workload'],x['dataset']))
  return {'decision':'issued','generation':g}
 if op=='copy':
  if one(db,'SELECT id FROM key_copies WHERE id=?',(x['id'],)):return {'decision':'duplicate_copy'}
  if not _key_known(db,x['key_id'],x['version']):return {'decision':'unknown_key'}
  db.execute('INSERT INTO key_copies VALUES(?,?,?,?,?,?,?)',(x['id'],x['key_id'],x['version'],x['holder'],x['kind'],1 if x['online'] else 0,x['at']))
  if _compromise(db,x['key_id'],x['version']):
   _notify(db,x['id']+':notify','affected_scope_extended',x['holder'],x['at'])
   return {'decision':'late_copy_recorded','holder':x['holder']}
  return {'decision':'copy_recorded','holder':x['holder']}
 if op=='snapshot':
  if not one(db,'SELECT id FROM datasets WHERE id=?',(x['dataset'],)):return {'decision':'unknown_dataset'}
  if one(db,'SELECT id FROM snapshots WHERE dataset=?',(x['dataset'],)):return {'decision':'snapshot_conflict'}
  db.execute('INSERT INTO snapshots VALUES(?,?,?,?,?,?)',(x['id'],x['dataset'],x['up_to'],x['key_id'],x['version'],x['at']))
  return {'decision':'snapshot_recorded'}
 if op=='customer_ack':
  d=one(db,'SELECT * FROM datasets WHERE id=?',(x['dataset'],))
  if not d:return {'decision':'unknown_dataset'}
  if one(db,'SELECT 1 FROM customer_acks WHERE dataset=? AND record=?',(x['dataset'],x['record'])):return {'decision':'duplicate_ack'}
  db.execute('INSERT INTO customer_acks VALUES(?,?,?)',(x['dataset'],x['record'],x['at']))
  db.execute('INSERT OR IGNORE INTO dataset_pages VALUES(?,?,?,?,?)',(x['dataset'],x['record'],d['serving_key'],d['serving_version'],'workload-write'))
  return {'decision':'ack_recorded'}
 if op=='read':
  if one(db,'SELECT id FROM read_facts WHERE id=?',(x['id'],)):return {'decision':'duplicate_read'}
  if not one(db,'SELECT id FROM datasets WHERE id=?',(x['dataset'],)):return {'decision':'unknown_dataset'}
  c=_compromise(db,x['key_id'],x['version'])
  cls='exposed_window' if c and x['at']>=c['at'] else 'legitimate'
  db.execute('INSERT INTO read_facts VALUES(?,?,?,?,?,?,?)',(x['id'],x['dataset'],x['record'],x['key_id'],x['version'],x['at'],cls))
  return {'decision':'read_recorded','classification':cls}
 if op=='customer_log':
  if not one(db,'SELECT id FROM datasets WHERE id=?',(x['dataset'],)):return {'decision':'unknown_dataset'}
  missing=[r for r in x['records'] if not one(db,'SELECT 1 FROM customer_acks WHERE dataset=? AND record=?',(x['dataset'],r))]
  if missing:return {'decision':'unacked_record','records':missing}
  for r in x['records']:db.execute('INSERT OR IGNORE INTO customer_logs VALUES(?,?,?)',(x['dataset'],r,x['at']))
  return {'decision':'log_recorded','records':len(x['records'])}
 if op=='compromise':
  if one(db,'SELECT id FROM key_compromises WHERE id=?',(x['id'],)):return {'decision':'duplicate_report'}
  if not _key_known(db,x['key_id'],x['version']):return {'decision':'unknown_key'}
  if _compromise(db,x['key_id'],x['version']):return {'decision':'already_compromised'}
  db.execute('INSERT INTO key_compromises VALUES(?,?,?,?,?)',(x['id'],x['key_id'],x['version'],x['evidence'],x['at']))
  rid='recovery:'+x['id']
  db.execute('INSERT INTO recoveries VALUES(?,?,?,NULL,?,?,NULL)',(rid,x['key_id'],x['version'],'open',x['at']))
  for s in rows(db,'SELECT DISTINCT s.binding b FROM starts s JOIN key_leases l ON l.start_id=s.id WHERE l.key_id=? AND l.version=?',(x['key_id'],x['version'])):
   db.execute('INSERT INTO violations VALUES(?,?,?,?,?,?)',(x['id']+':signal:'+s['b'],s['b'],'secret-compromise','custody-log',x['at'],100))
  _notify(db,x['id']+':notify','compromise_detected',x['evidence'],x['at'])
  return {'decision':'compromise_recorded','recovery':rid,'open_holders':_open(db,x['key_id'],x['version'])}
 if op=='strategy':
  rec=_recovery(db,x['key_id'],x['version'])
  if not rec:return {'decision':'no_compromise'}
  if x['mode'] not in ('halt_rebuild','managed_transition'):return {'decision':'invalid_strategy'}
  if rec['strategy']:return {'decision':'strategy_conflict'}
  db.execute('UPDATE recoveries SET strategy=? WHERE id=?',(x['mode'],rec['id']))
  return {'decision':'strategy_recorded','mode':x['mode']}
 if op=='halt':
  leases=rows(db,"SELECT * FROM key_leases WHERE workload=? AND dataset=? AND state='issued'",(x['workload'],x['dataset']))
  if not leases:return {'decision':'no_lease'}
  db.executemany("UPDATE key_leases SET state='revoked',revoked_at=? WHERE id=?",[(x['at'],l['id']) for l in leases])
  d=one(db,'SELECT * FROM datasets WHERE id=?',(x['dataset'],))
  if d and d['writer']==x['workload']:db.execute('UPDATE datasets SET writer=NULL,halted_at=COALESCE(halted_at,?) WHERE id=?',(x['at'],x['dataset']))
  return {'decision':'halted','revoked':len(leases)}
 if op=='fence':
  if not _compromise(db,x['key_id'],x['version']):return {'decision':'no_compromise'}
  h=x['holder']
  if h!='db':
   lease=one(db,'SELECT * FROM key_leases WHERE id=? AND key_id=? AND version=?',(h,x['key_id'],x['version']))
   copy=one(db,'SELECT * FROM key_copies WHERE holder=? AND key_id=? AND version=?',(h,x['key_id'],x['version']))
   if not lease and not copy:return {'decision':'unknown_holder'}
   if copy and not copy['online']:return {'decision':'holder_offline'}
  if one(db,'SELECT 1 FROM key_fences WHERE key_id=? AND version=? AND holder=?',(x['key_id'],x['version'],h)):return {'decision':'duplicate_fence'}
  db.execute('INSERT INTO key_fences VALUES(?,?,?,?,?,?)',(x['id'],x['key_id'],x['version'],h,'receipt',x['at']))
  return {'decision':'fence_recorded','open_holders':_open(db,x['key_id'],x['version'])}
 if op=='destroy':
  if not _compromise(db,x['key_id'],x['version']):return {'decision':'no_compromise'}
  copy=one(db,'SELECT * FROM key_copies WHERE holder=? AND key_id=? AND version=?',(x['holder'],x['key_id'],x['version']))
  if not copy:return {'decision':'unknown_holder'}
  if copy['online']:return {'decision':'holder_online'}
  if not x.get('attestation'):return {'decision':'attestation_missing'}
  if one(db,'SELECT 1 FROM key_fences WHERE key_id=? AND version=? AND holder=?',(x['key_id'],x['version'],x['holder'])):return {'decision':'duplicate_fence'}
  db.execute('INSERT INTO key_fences VALUES(?,?,?,?,?,?)',(x['id'],x['key_id'],x['version'],x['holder'],'destroyed',x['at']))
  return {'decision':'copy_destroyed','open_holders':_open(db,x['key_id'],x['version'])}
 if op=='convert':
  d=one(db,'SELECT * FROM datasets WHERE id=?',(x['dataset'],))
  if not d:return {'decision':'unknown_dataset'}
  fk,fv=d['serving_key'],d['serving_version']
  if not _compromise(db,fk,fv):return {'decision':'no_compromise'}
  rec=_recovery(db,fk,fv)
  if rec['strategy']!='managed_transition':return {'decision':'strategy_mismatch'}
  if not x.get('boundary'):return {'decision':'boundary_required'}
  if (x['to_key'],x['to_version'])==(fk,fv):return {'decision':'same_key'}
  if _compromise(db,x['to_key'],x['to_version']):return {'decision':'key_compromised'}
  need=_required(db,x['dataset'])
  if not need:return {'decision':'nothing_confirmed'}
  plan,missing=_sources(db,x['dataset'],fk,fv,need,'db' not in _fenced(db,fk,fv))
  if plan is None:return {'decision':'missing_source','record':missing}
  db.execute('DELETE FROM staged_pages WHERE dataset=?',(x['dataset'],))
  db.executemany('INSERT INTO staged_pages VALUES(?,?,?,?,?)',[(x['dataset'],r,x['to_key'],x['to_version'],src) for r,src in plan])
  sources={}
  for _,src in plan:sources[src]=sources.get(src,0)+1
  return {'decision':'staged','records':need,'sources':sources}
 if op=='takeover':
  d=one(db,'SELECT * FROM datasets WHERE id=?',(x['dataset'],))
  if not d:return {'decision':'unknown_dataset'}
  need=_required(db,x['dataset'])
  staged=rows(db,'SELECT * FROM staged_pages WHERE dataset=? ORDER BY record',(x['dataset'],))
  if not need or len(staged)<need or [s['record'] for s in staged]!=list(range(1,len(staged)+1)):return {'decision':'no_staged_conversion'}
  keys={(s['key_id'],s['version']) for s in staged}
  if len(keys)!=1:return {'decision':'inconsistent_stage'}
  (tk,tv),=keys
  if _compromise(db,tk,tv):return {'decision':'key_compromised'}
  start=one(db,'SELECT * FROM starts WHERE id=?',(x['start_id'],))
  if not start:return {'decision':'unavailable'}
  b=one(db,'SELECT * FROM bindings WHERE id=?',(start['binding'],))
  if not b or b['workload']!=x['workload']:return {'decision':'lease_binding_mismatch'}
  if b['status']=='quarantined':return {'decision':'binding_quarantined'}
  if x['expires_at']<=x['at']:return {'decision':'expired_lease'}
  others=rows(db,"SELECT * FROM key_leases WHERE dataset=? AND state='issued' AND workload!=?",(x['dataset'],x['workload']))
  db.executemany("UPDATE key_leases SET state='revoked',revoked_at=? WHERE id=?",[(x['at'],l['id']) for l in others])
  db.execute('DELETE FROM dataset_pages WHERE dataset=?',(x['dataset'],))
  db.executemany('INSERT INTO dataset_pages VALUES(?,?,?,?,?)',[(x['dataset'],s['record'],tk,tv,s['source']) for s in staged])
  db.execute('DELETE FROM staged_pages WHERE dataset=?',(x['dataset'],))
  g=one(db,'SELECT COUNT(*) n FROM starts WHERE binding=?',(start['binding'],))['n']
  lid=x['id']+':lease'
  db.execute('INSERT INTO key_leases VALUES(?,?,?,?,?,?,?,?,?,?,NULL)',(lid,x['workload'],x['start_id'],g,x['dataset'],tk,tv,'write',x['expires_at'],'issued'))
  db.execute('UPDATE datasets SET serving_key=?,serving_version=?,writer=? WHERE id=?',(tk,tv,x['workload'],x['dataset']))
  if d['halted_at'] is not None:db.execute('UPDATE datasets SET restored_at=COALESCE(restored_at,?) WHERE id=?',(x['at'],x['dataset']))
  return {'decision':'took_over','serving_key':tk,'serving_version':tv,'writer':x['workload'],'lease':lid,'retired':len(others),'downtime':(x['at']-d['halted_at']) if d['halted_at'] is not None else 0}
 if op=='rebuild':
  d=one(db,'SELECT * FROM datasets WHERE id=?',(x['dataset'],))
  if not d:return {'decision':'unknown_dataset'}
  fk,fv=d['serving_key'],d['serving_version']
  if not _compromise(db,fk,fv):return {'decision':'no_compromise'}
  rec=_recovery(db,fk,fv)
  if rec['strategy']!='halt_rebuild':return {'decision':'strategy_mismatch'}
  if 'db' not in _fenced(db,fk,fv):return {'decision':'db_not_fenced'}
  if one(db,"SELECT id FROM key_leases WHERE dataset=? AND purpose='write' AND state='issued'",(x['dataset'],)):return {'decision':'writer_active'}
  if (x['to_key'],x['to_version'])==(fk,fv):return {'decision':'same_key'}
  if _compromise(db,x['to_key'],x['to_version']):return {'decision':'key_compromised'}
  need=_required(db,x['dataset'])
  if not need:return {'decision':'nothing_confirmed'}
  plan,missing=_sources(db,x['dataset'],fk,fv,need,False)
  if plan is None:return {'decision':'missing_source','record':missing}
  db.execute('DELETE FROM dataset_pages WHERE dataset=?',(x['dataset'],))
  db.executemany('INSERT INTO dataset_pages VALUES(?,?,?,?,?)',[(x['dataset'],r,x['to_key'],x['to_version'],src) for r,src in plan])
  db.execute('UPDATE datasets SET serving_key=?,serving_version=? WHERE id=?',(x['to_key'],x['to_version'],x['dataset']))
  if d['halted_at'] is not None:db.execute('UPDATE datasets SET restored_at=COALESCE(restored_at,?) WHERE id=?',(x['at'],x['dataset']))
  sources={}
  for _,src in plan:sources[src]=sources.get(src,0)+1
  return {'decision':'rebuilt','records':need,'sources':sources,'downtime':(x['at']-d['halted_at']) if d['halted_at'] is not None else 0}
 if op=='status':
  c=_compromise(db,x['key_id'],x['version'])
  hs=_holders(db,x['key_id'],x['version'])
  rec=_recovery(db,x['key_id'],x['version'])
  ds=rows(db,'SELECT * FROM datasets WHERE serving_key=? AND serving_version=? OR id IN (SELECT dataset FROM key_leases WHERE key_id=? AND version=?) ORDER BY id',(x['key_id'],x['version'],x['key_id'],x['version']))
  return {'decision':'status','compromised':bool(c),'evidence':c['evidence'] if c else None,'holders':hs,'open_holders':[h['holder'] for h in hs if not h['fenced']],'old_key_live':any(not h['fenced'] for h in hs),'recovery':{'strategy':rec['strategy'],'state':rec['state'],'opened_at':rec['opened_at'],'closed_at':rec['closed_at']} if rec else None,'datasets':[{'id':d['id'],'serving_key':d['serving_key'],'serving_version':d['serving_version'],'writer':d['writer'],'halted_at':d['halted_at'],'restored_at':d['restored_at']} for d in ds]}
 if op=='complete':
  if not _compromise(db,x['key_id'],x['version']):return {'decision':'no_compromise'}
  rec=_recovery(db,x['key_id'],x['version'])
  open_h=_open(db,x['key_id'],x['version'])
  if open_h:return {'decision':'holders_open','open_holders':open_h}
  serving=rows(db,'SELECT id FROM datasets WHERE serving_key=? AND serving_version=?',(x['key_id'],x['version']))
  if serving:return {'decision':'still_serving_compromised_key','datasets':[s['id'] for s in serving]}
  for a in rows(db,'SELECT DISTINCT dataset FROM key_leases WHERE key_id=? AND version=?',(x['key_id'],x['version'])):
   d=one(db,'SELECT * FROM datasets WHERE id=?',(a['dataset'],))
   unreadable=[]
   for t in ('customer_acks','read_facts'):
    for r in rows(db,f'SELECT record FROM {t} WHERE dataset=?',(a['dataset'],)):
     if not one(db,'SELECT 1 FROM dataset_pages WHERE dataset=? AND record=? AND key_id=? AND version=?',(a['dataset'],r['record'],d['serving_key'],d['serving_version'])):unreadable.append(r['record'])
   if unreadable:return {'decision':'unreadable_confirmed_records','dataset':a['dataset'],'records':sorted(set(unreadable))}
  db.execute("UPDATE recoveries SET state='complete',closed_at=? WHERE id=?",(x['at'],rec['id']))
  _notify(db,x['id']+':notify','recovery_complete',x['key_id']+':'+str(x['version']),x['at'])
  return {'decision':'recovery_complete','closed_at':x['at']}
 if op=='reads':
  return {'decision':'read_facts','reads':rows(db,'SELECT * FROM read_facts WHERE dataset=? ORDER BY record,at',(x['dataset'],))}
 if op=='notifications':
  return {'decision':'notifications','notifications':rows(db,'SELECT * FROM notifications ORDER BY rowid')}
 raise ValueError(op)
