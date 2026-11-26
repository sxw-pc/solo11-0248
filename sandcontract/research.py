"""Capture an independent security finding about a sandbox profile."""
from .store import one

def submit(db,report_id,researcher,profile_id,trace_digest):
 db.execute('CREATE TABLE IF NOT EXISTS research_reports(id TEXT PRIMARY KEY,researcher TEXT,profile TEXT,trace_digest TEXT)')
 old=one(db,'SELECT trace_digest FROM research_reports WHERE id=?',(report_id,))
 if old:return {'decision':'reused' if old['trace_digest']==trace_digest else 'conflict'}
 if not researcher or not trace_digest:return {'decision':'invalid'}
 db.execute('INSERT INTO research_reports VALUES(?,?,?,?)',(report_id,researcher,profile_id,trace_digest))
 return {'decision':'submitted'}
