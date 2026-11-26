import hashlib,json
from .store import one,rows
from . import policy_compile as pc

def digest(x):
 data={k:x[k] for k in ('syscalls','devices','network','required_feature')}
 if x.get('policy') is not None:data['policy']=x['policy']
 return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
def run(db,x):
 op=x['op']
 if op=='node':
  old=one(db,'SELECT * FROM nodes WHERE id=?',(x['id'],))
  if x['capacity']<1 or (old and x['generation']<=old['generation']):return {'decision':'stale_or_invalid_node'}
  att=pc.validate_attestation(x['attestation']) if x.get('attestation') else None
  if x.get('attestation') and not att:return {'decision':'invalid_attestation'}
  db.execute('INSERT INTO nodes VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET uid=excluded.uid,generation=excluded.generation,features=excluded.features,capacity=excluded.capacity',(x['id'],x['uid'],x['generation'],json.dumps(x['features']),x['capacity']))
  if att:
   ad=pc.attestation_digest(att)
   db.execute('INSERT INTO node_attestations VALUES(?,?,?,?,?,?) ON CONFLICT(node_uid,node_generation) DO UPDATE SET kernel_build=excluded.kernel_build,filter_version=excluded.filter_version,attestation=excluded.attestation,attestation_digest=excluded.attestation_digest',(x['uid'],x['generation'],att['kernel_build'],att['filter_version'],json.dumps(att,sort_keys=True),ad))
  return {'decision':'node_recorded'}
 if op=='publish':
  if not x['syscalls'] or len(x['syscalls'])!=len(set(x['syscalls'])) or x['revision']<1:return {'decision':'invalid_profile'}
  pol=pc.canonical_policy(x['policy']) if x.get('policy') is not None else None
  if x.get('policy') is not None and not pol:return {'decision':'invalid_policy'}
  old=one(db,'SELECT * FROM profiles WHERE id=?',(x['id'],))
  if old and x['revision']<=old['revision']:return {'decision':'stale_revision'}
  pj=json.dumps(pol,sort_keys=True) if pol else None
  d=digest(dict(x,policy=pol) if pol else x)
  db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,syscalls=excluded.syscalls,devices=excluded.devices,network=excluded.network,required_feature=excluded.required_feature,status=excluded.status,policy=excluded.policy',(x['id'],x['revision'],d,json.dumps(x['syscalls']),json.dumps(x['devices']),json.dumps(x['network']),x['required_feature'],'draft',pj))
  if old:db.execute("UPDATE bindings SET status='at_risk' WHERE profile_digest=? AND status='active'",(old['digest'],))
  return {'decision':'published','digest':d}
 if op=='activate':
  p=one(db,'SELECT * FROM profiles WHERE id=?',(x['id'],))
  if not p or p['status']!='draft':return {'decision':'not_draft'}
  pol=json.loads(p['policy']) if p['policy'] else None
  compatible=[]
  for n in rows(db,'SELECT * FROM nodes'):
   if p['required_feature'] not in json.loads(n['features']):continue
   if pol is None:compatible.append(n['id']);continue
   att=one(db,'SELECT * FROM node_attestations WHERE node_uid=? AND node_generation=?',(n['uid'],n['generation']))
   if not att:continue
   table=json.loads(att['attestation'])['syscall_table']
   if all(call in table for call in {r['call'] for r in pol['syscall_rules']}):compatible.append(n['id'])
  if not compatible:return {'decision':'no_compatible_node'}
  db.execute("UPDATE profiles SET status='active' WHERE id=?",(x['id'],))
  return {'decision':'active','nodes':compatible}
 if op=='revoke':
  p=one(db,'SELECT * FROM profiles WHERE id=?',(x['id'],))
  if not p or x['revision']!=p['revision']:return {'decision':'stale_revocation'}
  db.execute("UPDATE profiles SET status='revoked' WHERE id=?",(x['id'],))
  db.execute("UPDATE bindings SET status='at_risk' WHERE profile_digest=? AND status='active'",(p['digest'],))
  return {'decision':'revoked'}
 raise ValueError(op)
