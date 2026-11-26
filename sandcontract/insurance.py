"""Draft a provisional insurer notice from a quarantined binding."""
from .store import one

def provisional_notice(db,notice_id,incident_id,policy_id):
 db.execute('CREATE TABLE IF NOT EXISTS insurer_notices(id TEXT PRIMARY KEY,incident TEXT,policy TEXT,state TEXT)')
 old=one(db,'SELECT policy FROM insurer_notices WHERE id=?',(notice_id,))
 if old:return {'decision':'reused' if old['policy']==policy_id else 'conflict'}
 if not one(db,'SELECT id FROM incidents WHERE id=?',(incident_id,)) or not policy_id:return {'decision':'unavailable'}
 db.execute('INSERT INTO insurer_notices VALUES(?,?,?,?)',(notice_id,incident_id,policy_id,'draft'))
 return {'decision':'drafted','policy':policy_id}
