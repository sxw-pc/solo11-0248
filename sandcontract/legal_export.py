"""Draft an incident evidence manifest for a legal request."""
import json
from .store import one,rows

def provisional_manifest(db,manifest_id,incident_id):
 db.execute('CREATE TABLE IF NOT EXISTS legal_manifests(id TEXT PRIMARY KEY,incident TEXT,members TEXT)')
 old=one(db,'SELECT members FROM legal_manifests WHERE id=?',(manifest_id,))
 if old:return {'decision':'reused','members':json.loads(old['members'])}
 case=one(db,'SELECT id FROM incidents WHERE id=?',(incident_id,))
 if not case:return {'decision':'unavailable'}
 members=[r['binding'] for r in rows(db,'SELECT binding FROM incident_members WHERE incident=? ORDER BY binding',(incident_id,))]
 db.execute('INSERT INTO legal_manifests VALUES(?,?,?)',(manifest_id,incident_id,json.dumps(members)))
 return {'decision':'drafted','members':members}
