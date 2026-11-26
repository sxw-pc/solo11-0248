"""Draft a provisional research reward for an active profile."""
from .store import one

def provisional_offer(db,offer_id,report_id,amount):
 db.execute('CREATE TABLE IF NOT EXISTS research_reports(id TEXT PRIMARY KEY,researcher TEXT,profile TEXT,trace_digest TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS bounty_offers(id TEXT PRIMARY KEY,report TEXT,amount INTEGER)')
 old=one(db,'SELECT amount FROM bounty_offers WHERE id=?',(offer_id,))
 if old:return {'decision':'reused','amount':old['amount']}
 report=one(db,'SELECT profile FROM research_reports WHERE id=?',(report_id,))
 active=one(db,"SELECT id FROM profiles WHERE id=? AND status='active'",(report['profile'],)) if report else None
 if not active or amount<0:return {'decision':'unavailable'}
 db.execute('INSERT INTO bounty_offers VALUES(?,?,?)',(offer_id,report_id,amount))
 return {'decision':'offered','amount':amount}
