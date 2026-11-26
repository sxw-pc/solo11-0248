"""Issue a provisional secret lease to a started sandbox."""
from .store import one

def provisional_lease(db,lease_id,start_id,secret_id):
 db.execute('CREATE TABLE IF NOT EXISTS secret_leases(id TEXT PRIMARY KEY,start_id TEXT,secret_id TEXT,state TEXT)')
 old=one(db,'SELECT secret_id FROM secret_leases WHERE id=?',(lease_id,))
 if old:return {'decision':'reused' if old['secret_id']==secret_id else 'conflict'}
 start=one(db,'SELECT id FROM starts WHERE id=?',(start_id,))
 if not start or not secret_id:return {'decision':'unavailable'}
 db.execute('INSERT INTO secret_leases VALUES(?,?,?,?)',(lease_id,start_id,secret_id,'issued'))
 return {'decision':'issued','secret':secret_id}
