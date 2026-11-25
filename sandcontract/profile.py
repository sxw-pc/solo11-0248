import hashlib,json
from .store import one,rows

def digest(x):
 data={k:x[k] for k in ('syscalls','devices','network','required_feature')}
 return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
def run(db,x):
 op=x['op']
 if op=='node':
  old=one(db,'SELECT * FROM nodes WHERE id=?',(x['id'],))
  if x['capacity']<1 or (old and x['generation']<=old['generation']):return {'decision':'stale_or_invalid_node'}
  db.execute('INSERT INTO nodes VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET uid=excluded.uid,generation=excluded.generation,features=excluded.features,capacity=excluded.capacity',(x['id'],x['uid'],x['generation'],json.dumps(x['features']),x['capacity']))
  return {'decision':'node_recorded'}
 if op=='publish':
  if not x['syscalls'] or len(x['syscalls'])!=len(set(x['syscalls'])) or x['revision']<1:return {'decision':'invalid_profile'}
  old=one(db,'SELECT * FROM profiles WHERE id=?',(x['id'],))
  if old and x['revision']<=old['revision']:return {'decision':'stale_revision'}
  d=digest(x)
  db.execute('INSERT INTO profiles VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest,syscalls=excluded.syscalls,devices=excluded.devices,network=excluded.network,required_feature=excluded.required_feature,status=excluded.status',(x['id'],x['revision'],d,json.dumps(x['syscalls']),json.dumps(x['devices']),json.dumps(x['network']),x['required_feature'],'draft'))
  if old:db.execute("UPDATE bindings SET status='at_risk' WHERE profile_digest=? AND status='active'",(old['digest'],))
  return {'decision':'published','digest':d}
 if op=='activate':
  p=one(db,'SELECT * FROM profiles WHERE id=?',(x['id'],))
  if not p or p['status']!='draft':return {'decision':'not_draft'}
  compatible=[n['id'] for n in rows(db,'SELECT * FROM nodes') if p['required_feature'] in json.loads(n['features'])]
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
