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
CREATE TABLE IF NOT EXISTS chassis(uid TEXT PRIMARY KEY,capacity INTEGER,current_node TEXT,first_generation INTEGER,last_generation INTEGER,state TEXT,replaced_by_uid TEXT,updated_at INTEGER);
CREATE TABLE IF NOT EXISTS node_pages(node TEXT NOT NULL,generation INTEGER NOT NULL,uid TEXT,features TEXT,capacity INTEGER,at INTEGER,transition TEXT,PRIMARY KEY(node,generation));
CREATE TABLE IF NOT EXISTS slot_leases(binding TEXT PRIMARY KEY,chassis_uid TEXT NOT NULL,generation INTEGER NOT NULL,slot_no INTEGER,sandbox_id TEXT,state TEXT NOT NULL,release_kind TEXT,release_receipt TEXT,updated_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS slot_lease_one_tenant ON slot_leases(chassis_uid,slot_no) WHERE state IN ('reserved','running','fenced','handoff_pending');
CREATE TABLE IF NOT EXISTS execution_receipts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,binding TEXT,workload TEXT,chassis_uid TEXT,node_generation INTEGER,sandbox_id TEXT,slot_no INTEGER,at INTEGER,actor TEXT,verified INTEGER NOT NULL DEFAULT 1,payload TEXT);
CREATE TABLE IF NOT EXISTS generation_handoffs(id TEXT PRIMARY KEY,node TEXT,chassis_uid TEXT,old_generation INTEGER,new_generation INTEGER,route TEXT,state TEXT,manifest TEXT,at INTEGER,note TEXT);
CREATE TABLE IF NOT EXISTS service_events(id TEXT PRIMARY KEY,binding TEXT,workload TEXT,tenant TEXT,chassis_uid TEXT,kind TEXT,at INTEGER,responsible TEXT,visible INTEGER NOT NULL DEFAULT 1,receipt_id TEXT,detail TEXT);
CREATE VIEW IF NOT EXISTS slots AS SELECT binding,chassis_uid,chassis_uid AS node_uid,generation,generation AS node_generation,slot_no,sandbox_id,state,release_kind,release_receipt,updated_at FROM slot_leases;
CREATE VIEW IF NOT EXISTS receipts AS SELECT id,kind,binding,workload,chassis_uid,chassis_uid AS node_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload FROM execution_receipts;
CREATE VIEW IF NOT EXISTS handoffs AS SELECT * FROM generation_handoffs;
CREATE VIEW IF NOT EXISTS stops AS SELECT * FROM receipts WHERE kind='stop';
CREATE VIEW IF NOT EXISTS migrations AS SELECT * FROM receipts WHERE kind IN ('migrate_out','migration_out','migrated');
CREATE VIEW IF NOT EXISTS fences AS SELECT * FROM receipts WHERE kind='fence';
CREATE VIEW IF NOT EXISTS recoveries AS SELECT * FROM service_events WHERE kind='recovery_visible';
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
 r=db.execute(q,a).fetchone()
 if not r:return None
 d=dict(r)
 from .node_handoff import wrap_row
 return wrap_row(d)
def rows(db,q,a=()):
 from .node_handoff import wrap_row
 return [wrap_row(dict(r)) for r in db.execute(q,a)]
def execute(db,sub,step):
 from . import profile,admit,incident,node_handoff
 module={'profile':profile,'admit':admit,'incident':incident,'handoff':node_handoff,'node_handoff':node_handoff,'node-handoff':node_handoff}.get(sub,node_handoff)
 with tx(db):
  old=one(db,'SELECT * FROM events WHERE request_id=?',(step['request_id'],))
  if old:
   if old['subsystem']==sub and json.loads(old['input'])==step:
    result=json.loads(old['result'])
    return node_handoff.hedge_result(result)
   return {'decision':'request_conflict'}
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
