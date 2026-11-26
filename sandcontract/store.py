import json,sqlite3
from contextlib import contextmanager

SCHEMA="""
CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY,revision INTEGER,digest TEXT,syscalls TEXT,devices TEXT,network TEXT,required_feature TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,uid TEXT,generation INTEGER,features TEXT,capacity INTEGER);
CREATE TABLE IF NOT EXISTS tenant_limits(tenant TEXT PRIMARY KEY,max_risk INTEGER,freeze INTEGER);
CREATE TABLE IF NOT EXISTS workloads(id TEXT PRIMARY KEY,tenant TEXT,profile TEXT,node TEXT,epoch INTEGER,risk INTEGER,capability TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS exceptions(id TEXT PRIMARY KEY,workload TEXT,capability TEXT,until_ts INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,exception_id TEXT,role TEXT,actor TEXT,until_ts INTEGER);
CREATE TABLE IF NOT EXISTS bindings(id TEXT PRIMARY KEY,workload TEXT,profile_digest TEXT,node_uid TEXT,node_generation INTEGER,exception_id TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS starts(id TEXT PRIMARY KEY,binding TEXT,profile_digest TEXT,node_uid TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS violations(id TEXT PRIMARY KEY,binding TEXT,kind TEXT,source TEXT,at INTEGER,confidence INTEGER);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,binding TEXT,scope TEXT,status TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS incident_members(incident TEXT,binding TEXT,PRIMARY KEY(incident,binding));
CREATE TABLE IF NOT EXISTS resets(id TEXT PRIMARY KEY,binding TEXT,node_uid TEXT,new_digest TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS media(id TEXT PRIMARY KEY,kind TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS blocks(id TEXT PRIMARY KEY,media TEXT,extent TEXT,remap_extent TEXT,bytes_hash TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS archives(id TEXT PRIMARY KEY,tenant TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS archive_pages(archive TEXT,page_no INTEGER,tenant TEXT,block_id TEXT,key_id TEXT,state TEXT,PRIMARY KEY(archive,page_no));
CREATE TABLE IF NOT EXISTS block_refs(block_id TEXT,archive TEXT,page_no INTEGER,tenant TEXT,PRIMARY KEY(block_id,archive,page_no));
CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY,archive TEXT,tenant TEXT,block_id TEXT,key_id TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS object_copies(id TEXT PRIMARY KEY,archive TEXT,tenant TEXT,location TEXT,block_id TEXT,key_id TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS sandbox_writes(id TEXT PRIMARY KEY,start_id TEXT,tenant TEXT,archive TEXT,page_no INTEGER,block_id TEXT,key_id TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS wrapping_keys(id TEXT PRIMARY KEY,tenant TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS key_copies(id TEXT PRIMARY KEY,key_id TEXT,location TEXT,kind TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS holds(id TEXT PRIMARY KEY,tenant TEXT,archive TEXT,page_from INTEGER,page_to INTEGER,until_ts INTEGER,seal_key_id TEXT,incident TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS sealed_evidence(id TEXT PRIMARY KEY,hold TEXT,archive TEXT,page_no INTEGER,tenant TEXT,vault_path TEXT,digest TEXT,seal_key_id TEXT,incident TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS erasure_jobs(id TEXT PRIMARY KEY,tenant TEXT,archive TEXT,start_id TEXT,strategy TEXT,state TEXT,vault_root TEXT);
CREATE TABLE IF NOT EXISTS erasure_stages(job TEXT,stage TEXT,state TEXT,detail TEXT,PRIMARY KEY(job,stage));
CREATE TABLE IF NOT EXISTS erasure_manifests(job TEXT,kind TEXT,ref_id TEXT,detail TEXT,state TEXT,PRIMARY KEY(job,kind,ref_id));
CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,job TEXT,kind TEXT,tenant TEXT,archive TEXT,scope TEXT,result TEXT,state TEXT,vault_path TEXT,revokes_cert TEXT);
CREATE TABLE IF NOT EXISTS external_receipts(id TEXT PRIMARY KEY,job TEXT,kind TEXT,target TEXT,vault_path TEXT,digest TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,subsystem TEXT,request_id TEXT UNIQUE,input TEXT,result TEXT);
"""
def connect(path):
 db=sqlite3.connect(path,isolation_level=None);db.row_factory=sqlite3.Row;db.execute('PRAGMA busy_timeout=3000');db.executescript(SCHEMA);return db
@contextmanager
def tx(db):
 db.execute('BEGIN IMMEDIATE')
 try:yield;db.execute('COMMIT')
 except BaseException:db.execute('ROLLBACK');raise
def one(db,q,a=()):
 r=db.execute(q,a).fetchone();return dict(r) if r else None
def rows(db,q,a=()):return [dict(r) for r in db.execute(q,a)]
def execute(db,sub,step):
 from . import profile,admit,incident,data_retention,data_erasure
 module={'profile':profile,'admit':admit,'incident':incident,'retention':data_retention,'erasure':data_erasure}[sub]
 with tx(db):
  old=one(db,'SELECT * FROM events WHERE request_id=?',(step['request_id'],))
  if old:return json.loads(old['result']) if old['subsystem']==sub and json.loads(old['input'])==step else {'decision':'request_conflict'}
  result=module.run(db,step)
  db.execute('INSERT INTO events(subsystem,request_id,input,result) VALUES(?,?,?,?)',(sub,step['request_id'],json.dumps(step,sort_keys=True),json.dumps(result,sort_keys=True)))
  return result
def replay(path):
 source=connect(path);target=connect(':memory:');events=rows(source,'SELECT subsystem,input,result FROM events ORDER BY seq');diff=[]
 for i,e in enumerate(events,1):
  if execute(target,e['subsystem'],json.loads(e['input']))!=json.loads(e['result']):diff.append({'event':i})
 for t in [r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('events','sqlite_sequence') ORDER BY name")]:
  if [tuple(r) for r in source.execute(f'SELECT * FROM {t} ORDER BY rowid')]!=[tuple(r) for r in target.execute(f'SELECT * FROM {t} ORDER BY rowid')]:diff.append({'table':t})
 source.close();target.close();return {'verified':not diff,'events':len(events),'divergence':diff}
