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
CREATE TABLE IF NOT EXISTS datasets(id TEXT PRIMARY KEY,serving_key TEXT,serving_version INTEGER,writer TEXT,halted_at INTEGER,restored_at INTEGER);
CREATE TABLE IF NOT EXISTS key_leases(id TEXT PRIMARY KEY,workload TEXT,start_id TEXT,generation INTEGER,dataset TEXT,key_id TEXT,version INTEGER,purpose TEXT,expires_at INTEGER,state TEXT,revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS key_copies(id TEXT PRIMARY KEY,key_id TEXT,version INTEGER,holder TEXT,kind TEXT,online INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS key_compromises(id TEXT PRIMARY KEY,key_id TEXT,version INTEGER,evidence TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS key_fences(id TEXT PRIMARY KEY,key_id TEXT,version INTEGER,holder TEXT,kind TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS recoveries(id TEXT PRIMARY KEY,key_id TEXT,version INTEGER,strategy TEXT,state TEXT,opened_at INTEGER,closed_at INTEGER);
CREATE TABLE IF NOT EXISTS dataset_pages(dataset TEXT,record INTEGER,key_id TEXT,version INTEGER,source TEXT,PRIMARY KEY(dataset,record));
CREATE TABLE IF NOT EXISTS staged_pages(dataset TEXT,record INTEGER,key_id TEXT,version INTEGER,source TEXT,PRIMARY KEY(dataset,record));
CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY,dataset TEXT,up_to INTEGER,key_id TEXT,version INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS customer_acks(dataset TEXT,record INTEGER,at INTEGER,PRIMARY KEY(dataset,record));
CREATE TABLE IF NOT EXISTS customer_logs(dataset TEXT,record INTEGER,at INTEGER,PRIMARY KEY(dataset,record));
CREATE TABLE IF NOT EXISTS read_facts(id TEXT PRIMARY KEY,dataset TEXT,record INTEGER,key_id TEXT,version INTEGER,at INTEGER,classification TEXT);
CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,kind TEXT,detail TEXT,at INTEGER);
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
 from . import profile,admit,incident,secret_recovery
 module={'profile':profile,'admit':admit,'incident':incident,'secret':secret_recovery}[sub]
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
