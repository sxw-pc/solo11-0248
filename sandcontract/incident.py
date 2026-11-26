import json
from .store import one,rows
from . import policy_compile as pc

def run(db,x):
 op=x['op']
 if op=='observe':
  b=one(db,'SELECT * FROM bindings WHERE id=?',(x['binding'],))
  if not b or x['confidence']<0 or x['confidence']>100:return {'decision':'invalid_signal'}
  if one(db,'SELECT id FROM violations WHERE id=?',(x['id'],)):return {'decision':'duplicate_signal'}
  db.execute('INSERT INTO violations VALUES(?,?,?,?,?,?)',(x['id'],x['binding'],x['kind'],x['source'],x['at'],x['confidence']))
  return {'decision':'credible' if x['confidence']>=80 else 'noise'}
 if op=='quarantine':
  b=one(db,'SELECT * FROM bindings WHERE id=?',(x['binding'],))
  w=one(db,'SELECT * FROM workloads WHERE id=?',(b['workload'],)) if b else None
  signals=rows(db,'SELECT * FROM violations WHERE binding=? AND confidence>=80',(x['binding'],))
  if not b or not signals:return {'decision':'insufficient_evidence'}
  if x['scope']=='tenant' and len({s['source'] for s in signals})<2:return {'decision':'tenant_scope_denied'}
  if x['scope'] not in ('binding','tenant') or one(db,'SELECT id FROM incidents WHERE id=?',(x['id'],)):return {'decision':'incident_conflict'}
  db.execute('INSERT INTO incidents VALUES(?,?,?,?,?)',(x['id'],x['binding'],x['scope'],'open',x['reason']))
  members=rows(db,"SELECT b.id FROM bindings b JOIN workloads w ON w.id=b.workload WHERE w.tenant=? AND b.status IN ('active','at_risk','quarantined')",(w['tenant'],)) if x['scope']=='tenant' else [{'id':b['id']}]
  db.executemany('INSERT INTO incident_members VALUES(?,?)',[(x['id'],m['id']) for m in members])
  db.executemany("UPDATE bindings SET status='quarantined' WHERE id=?",[(m['id'],) for m in members])
  if x['scope']=='tenant':db.execute('UPDATE tenant_limits SET freeze=1 WHERE tenant=?',(w['tenant'],))
  return {'decision':'tenant_frozen' if x['scope']=='tenant' else 'binding_quarantined','affected':len(members)}
 if op=='reset':
  b=one(db,'SELECT * FROM bindings WHERE id=?',(x['binding'],))
  if not b or b['status']!='quarantined' or one(db,'SELECT id FROM resets WHERE id=?',(x['id'],)):return {'decision':'reset_denied'}
  db.execute('INSERT INTO resets VALUES(?,?,?,?,?)',(x['id'],b['id'],x['node_uid'],x['new_digest'],x['at']))
  return {'decision':'reset_recorded'}
 if op=='release':
  case=one(db,"SELECT * FROM incidents WHERE id=? AND status='open'",(x['incident'],))
  if not case:return {'decision':'release_unverified'}
  members=rows(db,'SELECT binding FROM incident_members WHERE incident=? ORDER BY binding',(case['id'],))
  verified=[]
  for member in members:
   b=one(db,'SELECT * FROM bindings WHERE id=?',(member['binding'],))
   w=one(db,'SELECT * FROM workloads WHERE id=?',(b['workload'],)) if b else None
   n=one(db,'SELECT * FROM nodes WHERE id=?',(w['node'],)) if w else None
   profile_id=x.get('new_profiles',{}).get(b['id'],x.get('new_profile')) if b else None
   p=one(db,"SELECT * FROM profiles WHERE id=? AND status='active'",(profile_id,))
   reset=one(db,'SELECT * FROM resets WHERE binding=? ORDER BY at DESC LIMIT 1',(b['id'],)) if b else None
   other=one(db,"SELECT 1 FROM incident_members m JOIN incidents i ON i.id=m.incident WHERE m.binding=? AND i.id!=? AND i.status='open'",(b['id'],case['id'])) if b else None
   if not b or b['status']!='quarantined' or not n or not p or not reset or other or p['digest']==b['profile_digest'] or b['node_uid']!=n['uid'] or b['node_generation']!=n['generation'] or reset['node_uid']!=n['uid'] or reset['new_digest']!=p['digest'] or reset['at']>x['at'] or p['required_feature'] not in json.loads(n['features']) or (p['policy'] and not pc.loaded_contract(db,n['uid'],n['generation'],p['digest'])):
    return {'decision':'release_unverified','pending':member['binding']}
   verified.append((b,w,p))
  db.execute("UPDATE incidents SET status='closed' WHERE id=?",(case['id'],))
  for b,w,p in verified:
   db.execute("UPDATE bindings SET profile_digest=?,status='active' WHERE id=?",(p['digest'],b['id']))
   db.execute("UPDATE workloads SET profile=?,status='assigned' WHERE id=?",(p['id'],w['id']))
  if case['scope']=='tenant':
   tenant=verified[0][1]['tenant'] if verified else None
   open_tenant=one(db,"SELECT 1 FROM incidents i JOIN bindings b ON b.id=i.binding JOIN workloads w ON w.id=b.workload WHERE w.tenant=? AND i.scope='tenant' AND i.status='open'",(tenant,))
   if not open_tenant:db.execute('UPDATE tenant_limits SET freeze=0 WHERE tenant=?',(tenant,))
  return {'decision':'released','bindings':len(verified)}
 raise ValueError(op)
