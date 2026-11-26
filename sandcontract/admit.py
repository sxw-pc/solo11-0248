import json
from .store import one,rows
from . import node_handoff

def run(db,x):
 op=x['op']
 if op=='limit':
  if x['max_risk']<0:return {'decision':'invalid_limit'}
  db.execute('INSERT INTO tenant_limits VALUES(?,?,0) ON CONFLICT(tenant) DO UPDATE SET max_risk=excluded.max_risk',(x['tenant'],x['max_risk']))
  return {'decision':'limit_recorded'}
 if op=='request':
  p=one(db,"SELECT * FROM profiles WHERE id=? AND status='active'",(x['profile'],))
  limit=one(db,'SELECT * FROM tenant_limits WHERE tenant=?',(x['tenant'],))
  if not p or not limit or limit['freeze'] or x['risk']>limit['max_risk'] or x['risk']<0:return {'decision':'request_denied'}
  if one(db,'SELECT id FROM workloads WHERE id=?',(x['id'],)):return {'decision':'workload_conflict'}
  db.execute('INSERT INTO workloads VALUES(?,?,?,?,?,?,?,?)',(x['id'],x['tenant'],x['profile'],None,1,x['risk'],x.get('capability'),'requested'))
  return {'decision':'requested'}
 if op=='exception':
  w=one(db,'SELECT * FROM workloads WHERE id=?',(x['workload'],))
  if not w or x['capability']!=w['capability'] or x['until_ts']<=x['at'] or one(db,'SELECT id FROM exceptions WHERE id=?',(x['id'],)):return {'decision':'invalid_exception'}
  db.execute('INSERT INTO exceptions VALUES(?,?,?,?,?)',(x['id'],x['workload'],x['capability'],x['until_ts'],'pending'))
  return {'decision':'pending'}
 if op=='approve':
  e=one(db,'SELECT * FROM exceptions WHERE id=?',(x['exception'],))
  if not e or e['until_ts']<x['at'] or x['role'] not in ('security','owner'):return {'decision':'approval_denied'}
  if one(db,'SELECT id FROM approvals WHERE id=?',(x['id'],)):return {'decision':'approval_conflict'}
  if one(db,'SELECT id FROM approvals WHERE exception_id=? AND actor=? AND role!=?',(x['exception'],x['actor'],x['role'])):return {'decision':'actor_role_conflict'}
  db.execute('INSERT INTO approvals VALUES(?,?,?,?,?)',(x['id'],x['exception'],x['role'],x['actor'],x['until_ts']))
  approvals=rows(db,'SELECT * FROM approvals WHERE exception_id=? AND until_ts>=?',(x['exception'],x['at']))
  if len({r['role'] for r in approvals})==2 and len({r['actor'] for r in approvals})>=2:
   db.execute("UPDATE exceptions SET status='approved' WHERE id=?",(x['exception'],))
   return {'decision':'approved'}
  return {'decision':'pending_second_role'}
 if op=='assign':
  w=one(db,'SELECT * FROM workloads WHERE id=?',(x['workload'],))
  p=one(db,'SELECT * FROM profiles WHERE id=?',(w['profile'],)) if w else None
  n=one(db,'SELECT * FROM nodes WHERE id=?',(x['node'],))
  limit=one(db,'SELECT * FROM tenant_limits WHERE tenant=?',(w['tenant'],)) if w else None
  if not w or w['status']!='requested' or not p or p['status']!='active' or not n or p['required_feature'] not in json.loads(n['features']) or limit['freeze'] or x.get('capability')!=w['capability']:
   return {'decision':'assignment_denied'}
  e=None
  if x.get('capability'):
   e=one(db,"SELECT * FROM exceptions WHERE workload=? AND capability=? AND status='approved' AND until_ts>=?",(w['id'],x['capability'],x['at']))
   if not e:return {'decision':'exception_missing'}
  node_handoff.ensure_chassis(db,n['uid'],n['capacity'],n['id'],n['generation'],x.get('at'))
  # Physical capacity belongs to the chassis UID and is shared by every boot
  # generation.  Filtering by the current generation made an old, still
  # running generation look empty after a node page replacement.
  used=node_handoff.physical_used(db,n['uid'])
  if used>=n['capacity']:return {'decision':node_handoff.dec('node_full')}
  db.execute('INSERT INTO bindings VALUES(?,?,?,?,?,?,?)',(x['id'],w['id'],p['digest'],n['uid'],n['generation'],e['id'] if e else None,'active'))
  node_handoff.after_assignment(db,x,n)
  db.execute("UPDATE workloads SET node=?,status='assigned' WHERE id=?",(n['id'],w['id']))
  return {'decision':'assigned','digest':p['digest']}
 if op=='start':
  b=one(db,'SELECT * FROM bindings WHERE id=?',(x['binding'],))
  w=one(db,'SELECT * FROM workloads WHERE id=?',(b['workload'],)) if b else None
  n=one(db,'SELECT * FROM nodes WHERE id=?',(w['node'],)) if w else None
  p=one(db,'SELECT * FROM profiles WHERE id=?',(w['profile'],)) if w else None
  limit=one(db,'SELECT * FROM tenant_limits WHERE tenant=?',(w['tenant'],)) if w else None
  exception=one(db,"SELECT * FROM exceptions WHERE id=? AND status='approved' AND until_ts>=?",(b['exception_id'],x['at'])) if b and b['exception_id'] else True
  if not b or b['status']!='active' or not n or not p or p['status']!='active' or limit['freeze'] or not exception or b['node_uid']!=n['uid'] or b['node_generation']!=n['generation'] or x['node_uid']!=n['uid'] or x['profile_digest']!=p['digest']:
   # Still preserve an authentic old-agent start receipt as physical occupancy
   # evidence; it simply cannot confirm a start under the current generation.
   node_handoff.capture_start_receipt(db,x,b)
   return {'decision':'stale_start_receipt'}
  if one(db,'SELECT id FROM starts WHERE id=?',(x['id'],)):return {'decision':'start_receipt_conflict'}
  db.execute('INSERT INTO starts VALUES(?,?,?,?,?)',(x['id'],b['id'],p['digest'],n['uid'],x['at']))
  node_handoff.after_start(db,x,b)
  db.execute("UPDATE workloads SET status='running' WHERE id=?",(w['id'],))
  return {'decision':'started'}
 return node_handoff.run(db,x)
