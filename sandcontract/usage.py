"""Capture sandbox usage pages and issue a provisional tenant charge."""
import hashlib,json
from .store import one

def capture_page(db,page_id,rows):
 db.execute('CREATE TABLE IF NOT EXISTS usage_pages(id TEXT PRIMARY KEY,digest TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS usage_rows(page_id TEXT,line_no INTEGER,binding TEXT,cpu_seconds INTEGER,PRIMARY KEY(page_id,line_no))')
 if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'binding','cpu_seconds'} or r['cpu_seconds']<0 for r in rows):return {'decision':'invalid'}
 digest=hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()
 old=one(db,'SELECT digest FROM usage_pages WHERE id=?',(page_id,))
 if old:return {'decision':'reused' if old['digest']==digest else 'conflict'}
 db.execute('INSERT INTO usage_pages VALUES(?,?)',(page_id,digest))
 db.executemany('INSERT INTO usage_rows VALUES(?,?,?,?)',[(page_id,i,r['binding'],r['cpu_seconds']) for i,r in enumerate(rows,1)])
 return {'decision':'captured'}

def provisional_charge(db,charge_id,tenant,rate):
 db.execute('CREATE TABLE IF NOT EXISTS usage_charges(id TEXT PRIMARY KEY,tenant TEXT,amount INTEGER)')
 old=one(db,'SELECT amount FROM usage_charges WHERE id=?',(charge_id,))
 if old:return {'decision':'reused','amount':old['amount']}
 if rate<0:return {'decision':'invalid'}
 amount=one(db,'SELECT COALESCE(SUM(u.cpu_seconds),0)*? amount FROM usage_rows u JOIN bindings b ON b.id=u.binding JOIN workloads w ON w.id=b.workload WHERE w.tenant=?',(rate,tenant))['amount']
 db.execute('INSERT INTO usage_charges VALUES(?,?,?)',(charge_id,tenant,amount))
 return {'decision':'charged','amount':amount}
