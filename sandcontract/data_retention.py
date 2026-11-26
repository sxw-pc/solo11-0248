"""Draft a sandbox data-retention record after a confirmed start."""
from .store import one

def provisional_record(db,record_id,start_id,archive_id):
 db.execute('CREATE TABLE IF NOT EXISTS retention_records(id TEXT PRIMARY KEY,start_id TEXT,archive_id TEXT,state TEXT)')
 old=one(db,'SELECT archive_id FROM retention_records WHERE id=?',(record_id,))
 if old:return {'decision':'reused' if old['archive_id']==archive_id else 'conflict'}
 if not one(db,'SELECT id FROM starts WHERE id=?',(start_id,)) or not archive_id:return {'decision':'unavailable'}
 db.execute('INSERT INTO retention_records VALUES(?,?,?,?)',(record_id,start_id,archive_id,'provisional'))
 return {'decision':'recorded','archive':archive_id}

def run(db,x):
 op=x['op']
 if op=='provisional':
  return provisional_record(db,x['id'],x['start_id'],x['archive_id'])
 raise ValueError(op)
