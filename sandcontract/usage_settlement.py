"""双边结算：物理供应商应付 与 客户可收取用量 各自立据，差额挂平台待核。

This module is an event-sourced settlement ledger layered on the existing
profile/admit/incident tables and the ``usage.py`` capture pages.

Invariants enforced here:

* Physical increments are derived **per chassis + node generation over
  monotonic counter intervals**.  Resent intervals are de-duplicated by their
  natural digest, counter wrap / stale generations are rejected, and a meter
  second can be allocated to at most one effective provider bill/payment.
* Customer invoices are built only from **independently proven execution
  receipts** that are contractually chargeable.  Merely having an active
  binding, or an agent page label, never creates a charge.  Post-isolation
  kernel burn and migration double-run are parked in a separately listed
  responsibility bucket instead of being billed.
* The provider is paid for proven physical time even when tenant attribution
  is unknown.  The customer/provider gap stays in a suspense record carrying
  the original window and the candidate tenants; it is never split 50/50.
* Invoices, provider payments, credit notes and late attribution proof are
  append-only credentials.  Bounces are appended lifecycle events and
  corrections are new documents; old rows are never edited.

Every mutating entry point accepts either ``fn(db, **fields)`` or
``fn(db, payload_dict)`` and is also dispatched through :func:`run` so that
``store.execute(db, 'settlement', step)`` records and replays it.
"""
import hashlib
import json

from .store import one, rows
from .usage import capture_page as _capture_page

# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------

_TABLES = [
    """CREATE TABLE IF NOT EXISTS us_chassis_state(
         chassis TEXT PRIMARY KEY, max_generation INTEGER)""",
    """CREATE TABLE IF NOT EXISTS us_meter_intervals(
         id TEXT PRIMARY KEY, chassis TEXT, generation INTEGER,
         start_ts INTEGER, end_ts INTEGER,
         counter_from INTEGER, counter_to INTEGER, seconds INTEGER,
         source TEXT, digest TEXT UNIQUE)""",
    """CREATE TABLE IF NOT EXISTS us_receipts(
         id TEXT PRIMARY KEY, workload TEXT, binding TEXT, tenant TEXT,
         chassis TEXT, generation INTEGER, start_ts INTEGER, end_ts INTEGER,
         seconds INTEGER, source TEXT, digest TEXT UNIQUE)""",
    """CREATE TABLE IF NOT EXISTS us_unavailable(
         id TEXT PRIMARY KEY, workload TEXT, binding TEXT, tenant TEXT,
         chassis TEXT, generation INTEGER, start_ts INTEGER, end_ts INTEGER,
         seconds INTEGER, reason TEXT, responsible TEXT,
         within_claims INTEGER DEFAULT 0, incident_id TEXT, digest TEXT UNIQUE)""",
    """CREATE TABLE IF NOT EXISTS us_handoffs(
         id TEXT PRIMARY KEY, workload TEXT,
         old_binding TEXT, new_binding TEXT,
         old_chassis TEXT, old_generation INTEGER,
         new_chassis TEXT, new_generation INTEGER,
         cutover_ts INTEGER, overlap_seconds INTEGER, at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS us_evidence(
         id TEXT PRIMARY KEY, kind TEXT, meter_interval_id TEXT,
         workload TEXT, seconds INTEGER, candidates TEXT,
         basis TEXT, source TEXT, at INTEGER, digest TEXT UNIQUE)""",
    """CREATE TABLE IF NOT EXISTS us_contracts(
         id TEXT PRIMARY KEY, tenant TEXT, customer_rate INTEGER,
         cpu_billable INTEGER, terms TEXT, at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS us_deposit_facilities(
         id TEXT PRIMARY KEY, party TEXT, limit_amount INTEGER, at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS us_settlements(
         id TEXT PRIMARY KEY, at INTEGER, snapshot TEXT)""",
    """CREATE TABLE IF NOT EXISTS us_actions(
         id TEXT PRIMARY KEY, settlement TEXT, kind TEXT,
         at INTEGER, payload TEXT, UNIQUE(settlement, kind))""",
    """CREATE TABLE IF NOT EXISTS us_suspense(
         id TEXT PRIMARY KEY, settlement TEXT UNIQUE, at INTEGER,
         chassis TEXT, generation INTEGER, start_ts INTEGER, end_ts INTEGER,
         window_json TEXT, seconds INTEGER, disputed_seconds INTEGER,
         unexplained_seconds INTEGER, amount INTEGER,
         candidates TEXT, blocks TEXT, bridge TEXT)""",
    """CREATE TABLE IF NOT EXISTS us_docs(
         id TEXT PRIMARY KEY, doc_type TEXT, at INTEGER,
         tenant TEXT, provider TEXT, facility TEXT, settlement TEXT,
         ref_id TEXT, corrects_id TEXT, meter_interval_id TEXT,
         seconds INTEGER, unit_rate INTEGER, amount INTEGER,
         funding TEXT, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS us_doc_events(
         id TEXT PRIMARY KEY, doc_id TEXT, kind TEXT, at INTEGER, reason TEXT)""",
    """CREATE TABLE IF NOT EXISTS us_acknowledgements(
         id TEXT PRIMARY KEY, settlement TEXT, tenant TEXT, doc_id TEXT,
         at INTEGER, actor TEXT, basis TEXT)""",
]

_DOC_COLS = ['id', 'doc_type', 'at', 'tenant', 'provider', 'facility',
             'settlement', 'ref_id', 'corrects_id', 'meter_interval_id',
             'seconds', 'unit_rate', 'amount', 'funding', 'detail']


def ensure(db):
    for stmt in _TABLES:
        db.execute(stmt)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _params(x, kw):
    p = dict(x) if isinstance(x, dict) else {}
    p.update(kw)
    return p


def _digest(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode('utf8')
    ).hexdigest()


def _j(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _parse(text, default):
    if not text:
        return default
    return json.loads(text)


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def table_exists(db, name):
    return one(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
               (name,)) is not None


def _id_exists(db, table, doc_id):
    return one(db, f"SELECT * FROM {table} WHERE id=?", (doc_id,))


def _workload(db, workload_id):
    return one(db, 'SELECT * FROM workloads WHERE id=?', (workload_id,))


def _binding(db, binding_id):
    return one(db, 'SELECT * FROM bindings WHERE id=?', (binding_id,))


def _belongs(row, iv):
    """Evidence belongs to a meter interval when chassis/gen match and its
    timestamps are contained in the interval window."""
    if row['chassis'] != iv['chassis'] or row['generation'] != iv['generation']:
        return False
    rs, re_ = row['start_ts'], row['end_ts']
    if rs is None or re_ is None or iv['start_ts'] is None or iv['end_ts'] is None:
        return True
    return rs >= iv['start_ts'] and re_ <= iv['end_ts']


def _add_doc(db, **d):
    for c in _DOC_COLS:
        d.setdefault(c, None)
    for c in ('funding', 'detail'):
        if not isinstance(d[c], str) and d[c] is not None:
            d[c] = _j(d[c])
    db.execute(
        f"INSERT INTO us_docs ({','.join(_DOC_COLS)}) "
        f"VALUES ({','.join('?' * len(_DOC_COLS))})",
        [d.get(c) for c in _DOC_COLS],
    )
    return d


def _doc_by_id(db, doc_id):
    return one(db, 'SELECT * FROM us_docs WHERE id=?', (doc_id,))


def _bounce_event(db, doc_id):
    return one(db, "SELECT * FROM us_doc_events WHERE doc_id=? AND kind='bounced' "
                   "ORDER BY rowid LIMIT 1", (doc_id,))


def _payment_effective(db, pay_id):
    return _bounce_event(db, pay_id) is None


def _doc_brief(db, d):
    bounced = _bounce_event(db, d['id'])
    return {
        'id': d['id'],
        'type': d['doc_type'],
        'at': d['at'],
        'tenant': d['tenant'],
        'provider': d['provider'],
        'facility': d['facility'],
        'settlement': d['settlement'],
        'ref_id': d['ref_id'],
        'corrects_id': d['corrects_id'],
        'meter_interval_id': d['meter_interval_id'],
        'seconds': d['seconds'],
        'unit_rate': d['unit_rate'],
        'amount': d['amount'],
        'funding': _parse(d['funding'], None),
        'detail': _parse(d['detail'], None),
        'bounced': bounced is not None,
        'effective': bounced is None and d['doc_type'] in (
            'cust_pay', 'provider_pay'),
        'bounce_reason': bounced['reason'] if bounced else None,
    }


# ---------------------------------------------------------------------------
# evidence ingestion: device counters, execution receipts, unavailability
# ---------------------------------------------------------------------------

def record_meter(db, x=None, **kw):
    """Record one monotonic device counter interval for a chassis/generation."""
    p = _params(x, kw)
    ensure(db)
    mid = p.get('id')
    chassis, gen = p.get('chassis'), p.get('generation')
    cf, ct = p.get('counter_from'), p.get('counter_to')
    if not mid or not chassis or not _is_int(gen) or not _is_int(cf) \
            or not _is_int(ct) or gen < 0 or cf < 0:
        return {'decision': 'invalid_meter_reading'}
    if _id_exists(db, 'us_meter_intervals', mid):
        return {'decision': 'reused', 'id': mid}
    digest = _digest({'chassis': chassis, 'generation': gen,
                      'start_ts': p.get('start_ts'), 'end_ts': p.get('end_ts'),
                      'counter_from': cf, 'counter_to': ct})
    dup = one(db, 'SELECT id FROM us_meter_intervals WHERE digest=?', (digest,))
    if dup:
        return {'decision': 'meter_duplicate', 'id': dup['id'],
                'seconds': max(0, ct - cf)}
    if ct < cf:
        return {'decision': 'counter_rollback', 'chassis': chassis,
                'generation': gen, 'counter_from': cf, 'counter_to': ct}
    state = one(db, 'SELECT * FROM us_chassis_state WHERE chassis=?', (chassis,))
    if state and gen < state['max_generation']:
        return {'decision': 'stale_generation', 'chassis': chassis,
                'reported_generation': gen,
                'max_generation': state['max_generation']}
    prior = one(
        db,
        'SELECT MAX(counter_to) top_to, MAX(end_ts) top_end '
        'FROM us_meter_intervals WHERE chassis=? AND generation=?',
        (chassis, gen),
    )
    seconds = ct - cf
    if prior and prior['top_to'] is not None:
        top = prior['top_to']
        if ct <= top and cf < top:
            return {'decision': 'counter_wrap', 'chassis': chassis,
                    'generation': gen, 'prior_counter_top': top,
                    'counter_from': cf, 'counter_to': ct}
        if cf < top:
            return {'decision': 'interval_overlap', 'chassis': chassis,
                    'generation': gen, 'prior_counter_top': top,
                    'counter_from': cf, 'counter_to': ct}
        st, en = p.get('start_ts'), p.get('end_ts')
        if prior['top_end'] is not None and st is not None and st < prior['top_end']:
            return {'decision': 'window_overlap', 'chassis': chassis,
                    'generation': gen, 'start_ts': st,
                    'prior_end': prior['top_end']}
    # A generation change must not recycle the same wall window into new
    # meter seconds that could be billed twice.  Epochs are disjoint in time.
    win_s, win_e = p.get('start_ts'), p.get('end_ts')
    if _is_int(win_s) and _is_int(win_e):
        clash = one(
            db,
            'SELECT id, generation FROM us_meter_intervals '
            'WHERE chassis=? AND generation!=? AND start_ts IS NOT NULL '
            'AND end_ts IS NOT NULL AND start_ts < ? AND ? < end_ts LIMIT 1',
            (chassis, gen, win_e, win_s),
        )
        if clash:
            return {'decision': 'generation_window_overlap',
                    'chassis': chassis, 'generation': gen,
                    'conflicting_interval': clash['id'],
                    'conflicting_generation': clash['generation']}
    db.execute(
        'INSERT INTO us_meter_intervals VALUES(?,?,?,?,?,?,?,?,?,?)',
        (mid, chassis, gen, p.get('start_ts'), p.get('end_ts'),
         cf, ct, seconds, p.get('source', 'agent'), digest),
    )
    db.execute(
        'INSERT INTO us_chassis_state(chassis,max_generation) VALUES(?,?) '
        'ON CONFLICT(chassis) DO UPDATE SET '
        'max_generation=MAX(us_chassis_state.max_generation,excluded.max_generation)',
        (chassis, gen),
    )
    return {'decision': 'meter_recorded', 'id': mid, 'seconds': seconds}


def record_receipt(db, x=None, **kw):
    """Independent execution receipt proving a workload really ran N seconds."""
    p = _params(x, kw)
    ensure(db)
    rid, wid = p.get('id'), p.get('workload')
    secs = p.get('seconds')
    if not rid or not wid or not _is_int(secs) or secs <= 0:
        return {'decision': 'invalid_receipt'}
    if _id_exists(db, 'us_receipts', rid):
        return {'decision': 'reused', 'id': rid}
    w = _workload(db, wid)
    if not w:
        return {'decision': 'unknown_workload', 'workload': wid}
    bid = p.get('binding')
    if bid:
        b = _binding(db, bid)
        if not b:
            return {'decision': 'unknown_binding', 'binding': bid}
        if b['workload'] != wid:
            return {'decision': 'binding_workload_mismatch',
                    'binding': bid, 'workload': wid}
    digest = _digest({'workload': wid, 'binding': bid,
                      'chassis': p.get('chassis'),
                      'generation': p.get('generation'),
                      'start_ts': p.get('start_ts'), 'end_ts': p.get('end_ts'),
                      'seconds': secs})
    dup = one(db, 'SELECT id FROM us_receipts WHERE digest=?', (digest,))
    if dup:
        return {'decision': 'receipt_duplicate', 'id': dup['id']}
    db.execute(
        'INSERT INTO us_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (rid, wid, bid, w['tenant'], p.get('chassis'), p.get('generation'),
         p.get('start_ts'), p.get('end_ts'), secs,
         p.get('source', 'independent-execution-receipt'), digest),
    )
    return {'decision': 'receipt_recorded', 'id': rid,
            'tenant': w['tenant'], 'seconds': secs}


def record_unavailable(db, x=None, **kw):
    """Seconds the machine burned but the customer could not use.

    ``within_claims=1`` means these seconds are already inside gross execution
    receipts and must be deducted before charging (migration double-run).
    ``within_claims=0`` means extra physical-only burn such as post-isolation
    kernel execution.  Either way they are listed as a responsible party's
    cost and never invoiced to the tenant by default.
    """
    p = _params(x, kw)
    ensure(db)
    uid = p.get('id')
    secs = p.get('seconds')
    if not uid or not _is_int(secs) or secs <= 0:
        return {'decision': 'invalid_unavailable_period'}
    if _id_exists(db, 'us_unavailable', uid):
        return {'decision': 'reused', 'id': uid}
    wid, tid = p.get('workload'), None
    bid = p.get('binding')
    if bid:
        b = _binding(db, bid)
        if not b:
            return {'decision': 'unknown_binding', 'binding': bid}
        wid = wid or b['workload']
    if wid:
        w = _workload(db, wid)
        if not w:
            return {'decision': 'unknown_workload', 'workload': wid}
        tid = w['tenant']
    if not wid:
        return {'decision': 'workload_or_binding_required'}
    digest = _digest({'workload': wid, 'binding': bid,
                      'chassis': p.get('chassis'),
                      'generation': p.get('generation'),
                      'start_ts': p.get('start_ts'), 'end_ts': p.get('end_ts'),
                      'seconds': secs, 'reason': p.get('reason')})
    db.execute(
        'INSERT INTO us_unavailable VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (uid, wid, bid, tid, p.get('chassis'), p.get('generation'),
         p.get('start_ts'), p.get('end_ts'), secs,
         p.get('reason', 'unavailable'), p.get('responsible', 'platform'),
         1 if p.get('within_claims') else 0, p.get('incident_id'), digest),
    )
    return {'decision': 'period_recorded', 'id': uid,
            'tenant': tid, 'seconds': secs,
            'reason': p.get('reason', 'unavailable')}


def record_migration(db, x=None, **kw):
    """Record a workload handoff to another chassis and its overlap cost."""
    p = _params(x, kw)
    ensure(db)
    hid, wid = p.get('id'), p.get('workload')
    old_bid, new_bid = p.get('old_binding'), p.get('new_binding')
    if not hid or not wid or not old_bid or not new_bid:
        return {'decision': 'invalid_migration'}
    if _id_exists(db, 'us_handoffs', hid):
        return {'decision': 'reused', 'id': hid}
    w = _workload(db, wid)
    old = _binding(db, old_bid)
    if not w:
        return {'decision': 'unknown_workload', 'workload': wid}
    if not old or old['workload'] != wid:
        return {'decision': 'unknown_binding', 'binding': old_bid}
    if _id_exists(db, 'bindings', new_bid):
        return {'decision': 'binding_conflict', 'binding': new_bid}
    new_chassis = p.get('new_chassis') or p.get('new_node_uid')
    new_gen = p.get('new_generation', 1)
    if not new_chassis:
        return {'decision': 'invalid_migration', 'reason': 'new_chassis required'}
    db.execute(
        'INSERT INTO bindings VALUES(?,?,?,?,?,?,?)',
        (new_bid, wid, old['profile_digest'], new_chassis, new_gen,
         old['exception_id'], 'active'),
    )
    overlap = p.get('overlap_seconds', 0) or 0
    db.execute('INSERT INTO us_handoffs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (hid, wid, old_bid, new_bid, old['node_uid'],
                old['node_generation'], new_chassis, new_gen,
                p.get('cutover_ts'), overlap, p.get('at')))
    if _is_int(overlap) and overlap > 0:
        op_id = f'{hid}:overlap'
        db.execute(
            'INSERT INTO us_unavailable VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (op_id, wid, old_bid, w['tenant'], old['node_uid'],
             old['node_generation'], p.get('overlap_start'),
             p.get('overlap_end'), overlap, 'migration_overlap', 'platform',
             1, None, _digest({'handoff': hid, 'overlap': overlap})),
        )
    return {'decision': 'migration_recorded', 'id': hid,
            'new_binding': new_bid, 'overlap_seconds': overlap}


# ---------------------------------------------------------------------------
# attribution evidence: disjunction (A-or-B) and late conclusive proof
# ---------------------------------------------------------------------------

def record_disjunction(db, x=None, **kw):
    """Record that N seconds are provably used by one of ``candidates`` only."""
    p = _params(x, kw)
    ensure(db)
    eid, mid = p.get('id'), p.get('meter_interval_id')
    secs, candidates = p.get('seconds'), p.get('candidates')
    if not eid or not mid or not _is_int(secs) or secs <= 0 \
            or not isinstance(candidates, (list, tuple)) or not candidates:
        return {'decision': 'invalid_disjunction'}
    if _id_exists(db, 'us_evidence', eid):
        return {'decision': 'reused', 'id': eid}
    if not _id_exists(db, 'us_meter_intervals', mid):
        return {'decision': 'unknown_meter_interval', 'meter_interval_id': mid}
    for c in candidates:
        if not _workload(db, c):
            return {'decision': 'unknown_workload', 'workload': c}
    digest = _digest({'kind': 'disjunction', 'meter_interval_id': mid,
                     'seconds': secs, 'candidates': list(candidates)})
    db.execute('INSERT INTO us_evidence VALUES(?,?,?,?,?,?,?,?,?,?)',
               (eid, 'disjunction', mid, None, secs, _j(list(candidates)),
                p.get('basis', 'shared_generation_slot'),
                p.get('source', 'site-evidence'), p.get('at'), digest))
    return {'decision': 'disjunction_recorded', 'id': eid,
            'seconds': secs, 'candidates': list(candidates)}


def submit_proof(db, x=None, **kw):
    """Append late conclusive attribution proof (never edits old evidence)."""
    p = _params(x, kw)
    ensure(db)
    eid, mid, wid = p.get('id'), p.get('meter_interval_id'), p.get('workload')
    secs = p.get('seconds')
    if not eid or not mid or not wid or not _is_int(secs) or secs <= 0:
        return {'decision': 'invalid_proof'}
    if _id_exists(db, 'us_evidence', eid):
        return {'decision': 'reused', 'id': eid}
    if not _id_exists(db, 'us_meter_intervals', mid):
        return {'decision': 'unknown_meter_interval', 'meter_interval_id': mid}
    if not _workload(db, wid):
        return {'decision': 'unknown_workload', 'workload': wid}
    digest = _digest({'kind': 'conclusive', 'meter_interval_id': mid,
                      'workload': wid, 'seconds': secs,
                      'source': p.get('source')})
    dup = one(db, 'SELECT id FROM us_evidence WHERE digest=?', (digest,))
    if dup:
        return {'decision': 'proof_duplicate', 'id': dup['id']}
    db.execute('INSERT INTO us_evidence VALUES(?,?,?,?,?,?,?,?,?,?)',
               (eid, 'conclusive', mid, wid, secs, None,
                p.get('basis', 'device_independent_receipt'),
                p.get('source', 'device-independent-receipt'),
                p.get('at'), digest))
    return {'decision': 'proof_recorded', 'id': eid,
            'workload': wid, 'seconds': secs}


# ---------------------------------------------------------------------------
# contracts and the pre-signed shared risk deposit facility
# ---------------------------------------------------------------------------

def record_contract(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    cid, tenant = p.get('id'), p.get('tenant')
    if not cid or not tenant:
        return {'decision': 'invalid_contract'}
    if _id_exists(db, 'us_contracts', cid):
        return {'decision': 'reused', 'id': cid}
    rate = p.get('customer_rate', 1)
    if not _is_int(rate) or rate < 0:
        return {'decision': 'invalid_contract', 'reason': 'bad rate'}
    db.execute('INSERT INTO us_contracts VALUES(?,?,?,?,?,?)',
               (cid, tenant, rate, 1 if p.get('cpu_billable', True) else 0,
                _j(p.get('terms') or {}), p.get('at')))
    return {'decision': 'contract_recorded', 'id': cid, 'tenant': tenant}


def _current_contract(db, tenant):
    return one(db, 'SELECT * FROM us_contracts WHERE tenant=? '
                   'ORDER BY rowid DESC LIMIT 1', (tenant,))


def record_deposit_facility(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    fid = p.get('id')
    limit = p.get('limit_amount')
    if not fid or not _is_int(limit) or limit < 0:
        return {'decision': 'invalid_deposit_facility'}
    if _id_exists(db, 'us_deposit_facilities', fid):
        return {'decision': 'reused', 'id': fid}
    db.execute('INSERT INTO us_deposit_facilities VALUES(?,?,?,?)',
               (fid, p.get('party', 'shared-compute-risk-pool'),
                limit, p.get('at')))
    return {'decision': 'deposit_facility_recorded', 'id': fid,
            'limit_amount': limit}


def deposit_state(db, facility_id):
    ensure(db)
    f = _id_exists(db, 'us_deposit_facilities', facility_id)
    if not f:
        return None
    occupied = one(
        db,
        "SELECT COALESCE(SUM(CASE doc_type WHEN 'deposit_advance' THEN amount "
        "WHEN 'deposit_refund' THEN -amount ELSE 0 END),0) occupied "
        "FROM us_docs WHERE facility=? AND doc_type IN "
        "('deposit_advance','deposit_refund')",
        (facility_id,),
    )['occupied']
    return {'id': facility_id, 'party': f['party'],
            'limit_amount': f['limit_amount'], 'occupied': occupied,
            'available': f['limit_amount'] - occupied}


# ---------------------------------------------------------------------------
# provider bills and payments (exactly once per physical meter second)
# ---------------------------------------------------------------------------

def _bill_reversal(db, bill_id):
    return one(db, "SELECT * FROM us_docs WHERE doc_type='provider_bill_reversal' "
                   "AND corrects_id=? ORDER BY rowid LIMIT 1", (bill_id,))


def register_provider_bill(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    bid, mid = p.get('id'), p.get('meter_interval_id')
    secs, amount = p.get('seconds'), p.get('amount')
    if not bid or not mid or not _is_int(secs) or secs <= 0 \
            or not _is_int(amount) or amount < 0:
        return {'decision': 'invalid_provider_bill'}
    if _id_exists(db, 'us_docs', bid):
        return {'decision': 'reused', 'id': bid}
    iv = _id_exists(db, 'us_meter_intervals', mid)
    if not iv:
        return {'decision': 'unknown_meter_interval', 'meter_interval_id': mid}
    if secs > iv['seconds']:
        return {'decision': 'bill_exceeds_meter', 'billed_seconds': secs,
                'meter_seconds': iv['seconds']}
    allocated = one(
        db,
        "SELECT COALESCE(SUM(b.seconds),0) s FROM us_docs b "
        "WHERE b.doc_type='provider_bill' AND b.meter_interval_id=? "
        "AND NOT EXISTS (SELECT 1 FROM us_docs r "
        "  WHERE r.doc_type='provider_bill_reversal' AND r.corrects_id=b.id)",
        (mid,),
    )['s']
    if allocated + secs > iv['seconds']:
        return {'decision': 'meter_seconds_already_billed',
                'meter_interval_id': mid, 'already_billed_seconds': allocated,
                'requested_seconds': secs, 'meter_seconds': iv['seconds']}
    _add_doc(db, id=bid, doc_type='provider_bill', at=p.get('at'),
             provider=p.get('provider'), meter_interval_id=mid,
             seconds=secs, amount=amount,
             detail={'counter_window': [iv['counter_from'], iv['counter_to']]})
    return {'decision': 'provider_bill_recorded', 'id': bid,
            'meter_interval_id': mid, 'seconds': secs, 'amount': amount}


def reverse_provider_bill(db, x=None, **kw):
    """Append an unpaid-bill correction so a provider can be switched."""
    p = _params(x, kw)
    ensure(db)
    rid, bill_id = p.get('id'), p.get('bill_id')
    if not rid or not bill_id:
        return {'decision': 'invalid_reversal'}
    if _id_exists(db, 'us_docs', rid):
        return {'decision': 'reused', 'id': rid}
    bill = _doc_by_id(db, bill_id)
    if not bill or bill['doc_type'] != 'provider_bill':
        return {'decision': 'unknown_bill', 'bill_id': bill_id}
    if _bill_reversal(db, bill_id):
        return {'decision': 'bill_already_reversed', 'bill_id': bill_id}
    paid = one(db, "SELECT id FROM us_docs pay WHERE pay.doc_type='provider_pay' "
                   "AND pay.ref_id=? AND NOT EXISTS ("
                   " SELECT 1 FROM us_doc_events e WHERE e.doc_id=pay.id "
                   " AND e.kind='bounced') LIMIT 1", (bill_id,))
    if paid:
        return {'decision': 'bill_paid_reversal_denied', 'bill_id': bill_id}
    _add_doc(db, id=rid, doc_type='provider_bill_reversal', at=p.get('at'),
             provider=bill['provider'], corrects_id=bill_id,
             meter_interval_id=bill['meter_interval_id'],
             seconds=bill['seconds'], amount=bill['amount'],
             detail={'reason': p.get('reason', 'provider switch correction')})
    return {'decision': 'provider_bill_reversed', 'id': rid, 'bill_id': bill_id}


def pay_provider(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    pid, bill_id = p.get('id'), p.get('bill_id')
    if not pid or not bill_id:
        return {'decision': 'invalid_provider_payment'}
    existing = _doc_by_id(db, pid)
    if existing:
        if existing['doc_type'] == 'provider_pay' and existing['ref_id'] == bill_id:
            return {'decision': 'reused', 'id': pid}
        return {'decision': 'id_conflict', 'id': pid}
    bill = _doc_by_id(db, bill_id)
    if not bill or bill['doc_type'] != 'provider_bill':
        return {'decision': 'unknown_bill', 'bill_id': bill_id}
    if _bill_reversal(db, bill_id):
        return {'decision': 'bill_reversed', 'bill_id': bill_id}
    amount = p.get('amount', bill['amount'])
    if not _is_int(amount) or amount != bill['amount']:
        return {'decision': 'invalid_payment_amount',
                'expected': bill['amount'], 'amount': amount}
    settled = one(
        db,
        "SELECT pay.id FROM us_docs pay WHERE pay.doc_type='provider_pay' "
        "AND pay.ref_id=? AND NOT EXISTS ("
        " SELECT 1 FROM us_doc_events e WHERE e.doc_id=pay.id "
        " AND e.kind='bounced') LIMIT 1",
        (bill_id,),
    )
    if settled:
        return {'decision': 'bill_already_paid', 'bill_id': bill_id,
                'payment_id': settled['id']}
    funding = p.get('funding') or {'platform': amount}
    _add_doc(db, id=pid, doc_type='provider_pay', at=p.get('at'),
             provider=bill['provider'], settlement=p.get('settlement'),
             ref_id=bill_id, meter_interval_id=bill['meter_interval_id'],
             amount=amount, funding=funding)
    return {'decision': 'provider_payment_recorded', 'id': pid,
            'bill_id': bill_id, 'amount': amount, 'funding': funding}


def bounce_provider_payment(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    eid, pid = p.get('id'), p.get('payment_id')
    if not eid or not pid:
        return {'decision': 'invalid_bounce'}
    if _id_exists(db, 'us_doc_events', eid):
        return {'decision': 'reused', 'id': eid}
    pay = _doc_by_id(db, pid)
    if not pay or pay['doc_type'] != 'provider_pay':
        return {'decision': 'unknown_payment', 'payment_id': pid}
    if _bounce_event(db, pid):
        return {'decision': 'payment_already_bounced', 'payment_id': pid}
    db.execute('INSERT INTO us_doc_events VALUES(?,?,?,?,?)',
               (eid, pid, 'bounced', p.get('at'), p.get('reason', 'bank return')))
    return {'decision': 'provider_payment_bounced', 'payment_id': pid}


# ---------------------------------------------------------------------------
# customer credentials: formal invoices, credit notes, payments, bounces
# ---------------------------------------------------------------------------

def issue_invoice(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    iid, tenant = p.get('id'), p.get('tenant')
    if not iid or not tenant:
        return {'decision': 'invalid_invoice'}
    if _id_exists(db, 'us_docs', iid):
        return {'decision': 'reused', 'id': iid}
    amount = p.get('amount')
    secs, rate = p.get('seconds'), p.get('unit_rate', 1)
    if amount is None:
        if not _is_int(secs) or not _is_int(rate):
            return {'decision': 'invalid_invoice',
                    'reason': 'amount or seconds+unit_rate required'}
        amount = secs * rate
    if not _is_int(amount) or amount < 0:
        return {'decision': 'invalid_invoice', 'reason': 'bad amount'}
    _add_doc(db, id=iid, doc_type='invoice', at=p.get('at'), tenant=tenant,
             settlement=p.get('settlement'), seconds=secs, unit_rate=rate,
             amount=amount, detail={'kind': p.get('kind', 'standard'),
                                    **(p.get('detail') or {})})
    return {'decision': 'invoice_issued', 'id': iid,
            'tenant': tenant, 'amount': amount}


def issue_credit_note(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    cid, tenant, amount = p.get('id'), p.get('tenant'), p.get('amount')
    corrects = p.get('corrects_id')
    if not cid or not tenant or not _is_int(amount) or amount <= 0:
        return {'decision': 'invalid_credit_note'}
    if _id_exists(db, 'us_docs', cid):
        return {'decision': 'reused', 'id': cid}
    inv = None
    settlement = p.get('settlement')
    if corrects:
        inv = _doc_by_id(db, corrects)
        if not inv or inv['doc_type'] != 'invoice':
            return {'decision': 'unknown_invoice', 'corrects_id': corrects}
        if inv['tenant'] != tenant:
            return {'decision': 'credit_tenant_mismatch'}
        if amount > inv['amount']:
            return {'decision': 'credit_exceeds_invoice'}
        settlement = settlement or inv['settlement']
    _add_doc(db, id=cid, doc_type='credit', at=p.get('at'), tenant=tenant,
             settlement=settlement, corrects_id=corrects, amount=amount,
             detail={'reason': p.get('reason', 'correction')})
    return {'decision': 'credit_note_issued', 'id': cid,
            'tenant': tenant, 'amount': amount, 'corrects_id': corrects}


def _invoice_outstanding(db, inv):
    credited = one(db, "SELECT COALESCE(SUM(amount),0) s FROM us_docs "
                       "WHERE doc_type='credit' AND corrects_id=?",
                   (inv['id'],))['s']
    paid = one(db, "SELECT COALESCE(SUM(p.amount),0) s FROM us_docs p "
                   "WHERE p.doc_type='cust_pay' AND p.ref_id=? AND NOT EXISTS("
                   " SELECT 1 FROM us_doc_events e WHERE e.doc_id=p.id "
                   " AND e.kind='bounced')", (inv['id'],))['s']
    return inv['amount'] - credited - paid


def pay_customer(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    pid, inv_id = p.get('id'), p.get('invoice_id')
    if not pid or not inv_id:
        return {'decision': 'invalid_customer_payment'}
    if _id_exists(db, 'us_docs', pid):
        return {'decision': 'reused', 'id': pid}
    inv = _doc_by_id(db, inv_id)
    if not inv or inv['doc_type'] != 'invoice':
        return {'decision': 'unknown_invoice', 'invoice_id': inv_id}
    outstanding = _invoice_outstanding(db, inv)
    amount = p.get('amount', outstanding)
    if not _is_int(amount) or amount <= 0 or amount > outstanding:
        return {'decision': 'payment_exceeds_balance',
                'invoice_id': inv_id, 'outstanding': outstanding,
                'requested': amount}
    _add_doc(db, id=pid, doc_type='cust_pay', at=p.get('at'),
             tenant=inv['tenant'], settlement=inv['settlement'],
             ref_id=inv_id, amount=amount,
             funding=p.get('funding') or {'bank': amount})
    left = _invoice_outstanding(db, inv)
    return {'decision': 'customer_payment_recorded', 'id': pid,
            'invoice_id': inv_id, 'amount': amount,
            'outstanding': left}


def bounce_customer_payment(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    eid, pid = p.get('id'), p.get('payment_id')
    if not eid or not pid:
        return {'decision': 'invalid_bounce'}
    if _id_exists(db, 'us_doc_events', eid):
        return {'decision': 'reused', 'id': eid}
    pay = _doc_by_id(db, pid)
    if not pay or pay['doc_type'] != 'cust_pay':
        return {'decision': 'unknown_payment', 'payment_id': pid}
    if _bounce_event(db, pid):
        return {'decision': 'payment_already_bounced', 'payment_id': pid}
    db.execute('INSERT INTO us_doc_events VALUES(?,?,?,?,?)',
               (eid, pid, 'bounced', p.get('at'), p.get('reason', 'bank return')))
    inv = _doc_by_id(db, pay['ref_id']) if pay['ref_id'] else None
    return {'decision': 'customer_payment_bounced', 'payment_id': pid,
            'invoice_id': pay['ref_id'],
            'outstanding': _invoice_outstanding(db, inv) if inv else None}


def acknowledge(db, x=None, **kw):
    """Append-only customer sign-off of a notice/invoice/settlement.

    A sign-off is evidence of receipt/acceptance; it never creates an invoice
    by itself (important for plan B verifiable usage notices).
    """
    p = _params(x, kw)
    ensure(db)
    aid = p.get('id')
    sid, tenant = p.get('settlement'), p.get('tenant')
    doc_id = p.get('doc_id')
    if not aid or not sid or not tenant:
        return {'decision': 'invalid_acknowledgement'}
    if _id_exists(db, 'us_acknowledgements', aid):
        return {'decision': 'reused', 'id': aid}
    if not _id_exists(db, 'us_settlements', sid):
        return {'decision': 'unknown_settlement', 'settlement': sid}
    if doc_id:
        d = _doc_by_id(db, doc_id)
        if not d or d['settlement'] != sid or d['tenant'] != tenant:
            return {'decision': 'unknown_document_for_ack', 'doc_id': doc_id}
    prior = one(db, 'SELECT id FROM us_acknowledgements WHERE settlement=? '
                   'AND tenant=? AND COALESCE(doc_id,\'\')=COALESCE(?, \'\')',
                (sid, tenant, doc_id))
    if prior:
        return {'decision': 'already_acknowledged', 'id': prior['id']}
    db.execute('INSERT INTO us_acknowledgements VALUES(?,?,?,?,?,?,?)',
               (aid, sid, tenant, doc_id, p.get('at'), p.get('actor'),
                p.get('basis', 'customer_sign_off')))
    return {'decision': 'acknowledged', 'id': aid,
            'settlement': sid, 'tenant': tenant, 'doc_id': doc_id}


def tenant_statement(db, tenant):
    ensure(db)
    docs = rows(db, 'SELECT * FROM us_docs WHERE tenant=? ORDER BY rowid',
                (tenant,))
    invoices = [_doc_brief(db, d) for d in docs if d['doc_type'] == 'invoice']
    credits = [_doc_brief(db, d) for d in docs if d['doc_type'] == 'credit']
    payments = [_doc_brief(db, d) for d in docs if d['doc_type'] == 'cust_pay']
    invoiced = sum(d['amount'] for d in invoices)
    credited = sum(d['amount'] for d in credits)
    paid = sum(d['amount'] for d in payments if d['effective'])
    return {'tenant': tenant, 'invoiced': invoiced, 'credited': credited,
            'paid_effective': paid,
            'balance_due': invoiced - credited - paid,
            'invoices': invoices, 'credits': credits, 'payments': payments}


def provider_statement(db, provider=None, bill_id=None):
    ensure(db)
    if bill_id:
        bill = _doc_by_id(db, bill_id)
        if not bill:
            return None
        pays = rows(db, "SELECT * FROM us_docs WHERE doc_type='provider_pay' "
                       "AND ref_id=? ORDER BY rowid", (bill_id,))
        pay_briefs = [_doc_brief(db, d) for d in pays]
        effective = sum(d['amount'] for d in pay_briefs if d['effective'])
        return {'bill': _doc_brief(db, bill), 'payments': pay_briefs,
                'paid_effective': effective,
                'outstanding': bill['amount'] - effective,
                'reversed': _bill_reversal(db, bill_id) is not None}
    bills = rows(db, "SELECT * FROM us_docs WHERE doc_type='provider_bill' "
                     "AND (? IS NULL OR provider=?) ORDER BY rowid",
                 (provider, provider))
    return {'provider': provider,
            'bills': [provider_statement(db, bill_id=b['id']) for b in bills]}


# ---------------------------------------------------------------------------
# reconciliation: physical vs chargeable, gap stays in platform suspense
# ---------------------------------------------------------------------------

def _capture_usage_page(db, **p):
    page_id, page_rows = p.get('page_id'), p.get('rows')
    return _capture_page(db, page_id, page_rows)


def capture_usage_page(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    return _capture_usage_page(db, **p)


def _page_claims(db, page_id):
    if not page_id or not table_exists(db, 'usage_rows'):
        return {}
    if not one(db, 'SELECT id FROM usage_pages WHERE id=?', (page_id,)):
        return {}
    out = {}
    for r in rows(
            db,
            'SELECT w.tenant tenant, COALESCE(SUM(r.cpu_seconds),0) s '
            'FROM usage_rows r JOIN bindings b ON b.id=r.binding '
            'JOIN workloads w ON w.id=b.workload '
            'WHERE r.page_id=? GROUP BY w.tenant ORDER BY w.tenant',
            (page_id,)):
        out[r['tenant']] = r['s']
    return out


def _normalize_interval_ids(p):
    ids = p.get('meter_interval_ids')
    if ids is None:
        single = p.get('meter_interval_id')
        ids = [single] if single else []
    return [i for i in ids if i]


def _build_snapshot(db, p):
    interval_ids = _normalize_interval_ids(p)
    if not interval_ids:
        return {'decision': 'invalid_settlement',
                'reason': 'meter_interval_id(s) required'}
    intervals = []
    for mid in interval_ids:
        iv = _id_exists(db, 'us_meter_intervals', mid)
        if not iv:
            return {'decision': 'unknown_meter_interval',
                    'meter_interval_id': mid}
        intervals.append(iv)
    P = sum(iv['seconds'] for iv in intervals)

    # gross independent execution receipts in these windows
    gross = {}
    receipt_rows = []
    for r in rows(db, 'SELECT * FROM us_receipts ORDER BY rowid'):
        if any(_belongs(r, iv) for iv in intervals):
            gross[r['tenant']] = gross.get(r['tenant'], 0) + r['seconds']
            receipt_rows.append(r['id'])

    # unavailable / responsibility periods in these windows
    deduct = {}
    responsibility = []
    extra_unavailable = 0
    for u in rows(db, 'SELECT * FROM us_unavailable ORDER BY rowid'):
        if any(_belongs(u, iv) for iv in intervals):
            responsibility.append({
                'id': u['id'], 'tenant': u['tenant'],
                'binding': u['binding'], 'seconds': u['seconds'],
                'reason': u['reason'], 'responsible': u['responsible'],
                'within_claims': bool(u['within_claims']),
                'incident_id': u['incident_id']})
            if u['within_claims']:
                deduct[u['tenant']] = deduct.get(u['tenant'], 0) + u['seconds']
            else:
                extra_unavailable += u['seconds']

    net = {}
    for t, g in gross.items():
        net[t] = g - deduct.get(t, 0)
        if net[t] < 0:
            return {'decision': 'evidence_exceeds_meter',
                    'reason': 'overlap deduction exceeds proven receipts',
                    'tenant': t}

    # contract chargeability
    tenant_seconds = {}
    blocked = 0
    for t, s in net.items():
        c = _current_contract(db, t)
        if c and not c['cpu_billable']:
            blocked += s
            responsibility.append({'id': f'contract:{c["id"]}:{t}',
                                   'tenant': t, 'seconds': s,
                                   'reason': 'contract_not_cpu_billable',
                                   'responsible': 'customer_contract',
                                   'within_claims': False})
        else:
            tenant_seconds[t] = s

    C = sum(tenant_seconds.values())
    R = sum(item['seconds'] for item in responsibility)

    # disjunctive attribution evidence (A-or-B), never split
    D = 0
    blocks = []
    iv_ids = {iv['id'] for iv in intervals}
    for e in rows(db, "SELECT * FROM us_evidence WHERE kind='disjunction' "
                      "ORDER BY rowid"):
        if e['meter_interval_id'] in iv_ids:
            D += e['seconds']
            blocks.append({'evidence_id': e['id'],
                           'meter_interval_id': e['meter_interval_id'],
                           'seconds': e['seconds'],
                           'candidates': _parse(e['candidates'], []),
                           'basis': e['basis']})

    used = C + R + D
    if used > P:
        return {'decision': 'evidence_exceeds_meter',
                'physical_seconds': P, 'certain_seconds': C,
                'responsibility_seconds': R, 'disputed_seconds': D,
                'overflow_seconds': used - P}
    X = P - used
    cr = p.get('customer_rate', 1)
    pr = p.get('provider_rate', 1)
    snap = {
        'interval_ids': interval_ids,
        'intervals': [{'id': iv['id'], 'chassis': iv['chassis'],
                       'generation': iv['generation'],
                       'start_ts': iv['start_ts'], 'end_ts': iv['end_ts'],
                       'counter_from': iv['counter_from'],
                       'counter_to': iv['counter_to'],
                       'seconds': iv['seconds']} for iv in intervals],
        'physical_seconds': P,
        'gross_receipt_seconds': sum(gross.values()),
        'deduct_within_claims_seconds': sum(deduct.values()),
        'certain_seconds': C,
        'tenant_seconds': tenant_seconds,
        'responsibility_seconds': R,
        'responsibility': responsibility,
        'blocked_contract_seconds': blocked,
        'disputed_seconds': D,
        'unexplained_seconds': X,
        'gap_seconds': D + X,
        'dispute_blocks': blocks,
        'page_id': p.get('page_id'),
        'page_claims': _page_claims(db, p.get('page_id')),
        'customer_rate': cr,
        'provider_rate': pr,
        'receipt_ids': receipt_rows,
    }
    return {'decision': 'ok', 'snapshot': snap}


def _insert_settlement(db, sid, p, built):
    db.execute('INSERT INTO us_settlements VALUES(?,?,?)',
               (sid, p.get('at'), _j(built['snapshot'])))


def reconcile(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    sid = p.get('id')
    if not sid:
        return {'decision': 'invalid_settlement', 'reason': 'id required'}
    if _id_exists(db, 'us_settlements', sid):
        return overview(db, sid, decision='settlement_exists')
    built = _build_snapshot(db, p)
    if built['decision'] != 'ok':
        return built
    _insert_settlement(db, sid, p, built)
    return overview(db, sid, decision='reconciled')


def settle(db, x=None, **kw):
    """Reconcile and, when ``plan`` is A/B, execute the chosen current period."""
    p = _params(x, kw)
    ensure(db)
    sid = p.get('id')
    if not sid:
        return {'decision': 'invalid_settlement', 'reason': 'id required'}
    existing = _id_exists(db, 'us_settlements', sid)
    if existing:
        ov = overview(db, sid, decision='settlement_exists')
        plan = _norm_plan(p.get('plan'))
        pa = _plan_action(db, sid)
        if plan and (not pa or _plan_name(pa) == plan):
            err = _apply_plan(db, sid, _snapshot(existing), p)
            if err:
                return err
        return overview(db, sid,
                        decision='settled' if plan and not pa else 'settlement_exists')
    built = _build_snapshot(db, p)
    if built['decision'] != 'ok':
        return built
    _insert_settlement(db, sid, p, built)
    snap = built['snapshot']
    plan = _norm_plan(p.get('plan'))
    if plan:
        err = _apply_plan(db, sid, snap, p)
        if err:
            return err
        return overview(db, sid, decision='settled')
    return overview(db, sid, decision='reconciled')


def _snapshot(st):
    return _parse(st['snapshot'], {})


def _norm_plan(plan):
    if plan in ('A', 'a', 'reserve', 'plan_a', 'jia'):
        return 'A'
    if plan in ('B', 'b', 'deposit', 'plan_b', 'yi'):
        return 'B'
    return None


def _plan_action(db, sid):
    return one(db, "SELECT * FROM us_actions WHERE settlement=? "
                   "AND kind='plan_selected'", (sid,))


def _plan_name(pa):
    return _parse(pa['payload'], {}).get('plan') if pa else None


def _settlement_bill_ids(db, sid, p, snap):
    ids = p.get('bill_ids')
    if ids is None:
        bid = p.get('bill_id')
        ids = [bid] if bid else []
    return [i for i in ids if i]


def _apply_plan(db, sid, snap, p):
    pa = _plan_action(db, sid)
    plan = _norm_plan(p.get('plan'))
    if pa:
        chosen = _plan_name(pa)
        if plan and chosen != plan:
            return {'decision': 'plan_conflict', 'settlement': sid,
                    'selected_plan': chosen, 'requested_plan': plan}
        return None  # already applied; idempotent no-op
    if not plan:
        return {'decision': 'invalid_plan', 'plan': p.get('plan')}

    cr = snap['customer_rate']
    pr = snap['provider_rate']
    gap = snap['gap_seconds']
    disputed = snap['disputed_seconds']

    # validate bills up front so we never half-post a plan
    bill_ids = _settlement_bill_ids(db, sid, p, snap)
    bills = []
    for bid in bill_ids:
        bill = _doc_by_id(db, bid)
        if not bill or bill['doc_type'] != 'provider_bill':
            return {'decision': 'unknown_bill', 'bill_id': bid}
        if bill['meter_interval_id'] not in snap['interval_ids']:
            return {'decision': 'bill_window_mismatch', 'bill_id': bid}
        if _bill_reversal(db, bid):
            return {'decision': 'bill_reversed', 'bill_id': bid}
        already = one(
            db,
            "SELECT id FROM us_docs pay WHERE pay.doc_type='provider_pay' "
            "AND pay.ref_id=? AND NOT EXISTS ("
            " SELECT 1 FROM us_doc_events e WHERE e.doc_id=pay.id "
            " AND e.kind='bounced') LIMIT 1", (bid,))
        if already:
            return {'decision': 'bill_already_paid', 'bill_id': bid}
        bills.append(bill)

    facility_id = p.get('deposit_facility') or p.get('facility_id')
    dep_state = deposit_state(db, facility_id) if facility_id else None
    deposit_need = disputed * pr
    if plan == 'B':
        if deposit_need > 0:
            if not dep_state:
                return {'decision': 'deposit_facility_required',
                        'needed_amount': deposit_need}
            if dep_state['available'] < deposit_need:
                return {'decision': 'deposit_unavailable',
                        'needed_amount': deposit_need,
                        'available': dep_state['available']}

    at = p.get('at')

    if plan == 'A':
        # undisputed formal invoices only
        for t, secs in sorted(snap['tenant_seconds'].items()):
            _add_doc(db, id=f'{sid}:inv:{t}', doc_type='invoice', at=at,
                     tenant=t, settlement=sid, seconds=secs, unit_rate=cr,
                     amount=secs * cr, detail={'kind': 'certain', 'plan': 'A'})
        # platform own reserve pays every provider bill in full
        for bill in bills:
            _add_doc(db, id=f'{sid}:ppay:{bill["id"]}', doc_type='provider_pay',
                     at=at, provider=bill['provider'], settlement=sid,
                     ref_id=bill['id'],
                     meter_interval_id=bill['meter_interval_id'],
                     amount=bill['amount'],
                     funding={'platform_reserve': bill['amount']})
    else:
        # verifiable usage notices only - deliberately no formal invoices
        for t, secs in sorted(snap['tenant_seconds'].items()):
            _add_doc(db, id=f'{sid}:notice:{t}', doc_type='notice', at=at,
                     tenant=t, settlement=sid, seconds=secs, unit_rate=cr,
                     amount=secs * cr,
                     detail={'verifiable_seconds': secs,
                             'pending_evidence_seconds': gap,
                             'formal_invoice': False, 'plan': 'B'})
        remaining_dep = deposit_need
        for bill in bills:
            dep_part = max(0, min(remaining_dep, bill['amount']))
            plat_part = bill['amount'] - dep_part
            funding = {'platform': plat_part}
            if dep_part:
                funding['shared_risk_deposit'] = dep_part
            _add_doc(db, id=f'{sid}:ppay:{bill["id"]}', doc_type='provider_pay',
                     at=at, provider=bill['provider'], settlement=sid,
                     ref_id=bill['id'],
                     meter_interval_id=bill['meter_interval_id'],
                     amount=bill['amount'], funding=funding)
            remaining_dep -= dep_part
        if deposit_need > 0:
            _add_doc(db, id=f'{sid}:dep-adv', doc_type='deposit_advance', at=at,
                     facility=facility_id, settlement=sid,
                     seconds=disputed, unit_rate=pr, amount=deposit_need,
                     detail={'bridge': 'shared_risk_deposit'})

    # known responsibility postings (never customer receivables)
    for i, item in enumerate(snap['responsibility']):
        suffix = item.get('id') or f'item-{i}'
        _add_doc(db, id=f'{sid}:cost:{suffix}', doc_type='cost_allocation',
                 at=at, tenant=item.get('tenant'), settlement=sid,
                 seconds=item['seconds'],
                 amount=item['seconds'] * pr,
                 detail={'reason': item['reason'],
                         'responsible': item['responsible'],
                         'binding': item.get('binding'),
                         'incident_id': item.get('incident_id')})

    # the gap keeps the original window and candidates in platform suspense
    primary = snap['intervals'][0]
    candidates = sorted({c for b in snap['dispute_blocks']
                         for c in b['candidates']})
    db.execute('INSERT INTO us_suspense VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (f'{sid}:suspense', sid, at, primary['chassis'],
                primary['generation'], primary['start_ts'], primary['end_ts'],
                _j(snap['intervals']), gap, disputed,
                snap['unexplained_seconds'], gap * cr,
                _j(candidates), _j(snap['dispute_blocks']),
                'platform_reserve' if plan == 'A' else 'shared_risk_deposit'))

    db.execute('INSERT INTO us_actions VALUES(?,?,?,?,?)',
               (p.get('action_id') or f'{sid}:plan', sid, 'plan_selected', at,
                _j({'plan': plan, 'bill_ids': [b['id'] for b in bills],
                    'deposit_facility': facility_id})))
    return None


def execute_plan(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    sid = p.get('settlement') or p.get('settlement_id') or p.get('id')
    st = _id_exists(db, 'us_settlements', sid) if sid else None
    if not st:
        return {'decision': 'unknown_settlement', 'settlement': sid}
    if _plan_action(db, sid):
        pa = _plan_action(db, sid)
        chosen = _plan_name(pa)
        if _norm_plan(p.get('plan')) not in (None, chosen):
            return {'decision': 'plan_conflict', 'selected_plan': chosen}
        return overview(db, sid, decision='plan_already_executed')
    err = _apply_plan(db, sid, _snapshot(st), p)
    if err:
        return err
    return overview(db, sid, decision='plan_executed')


# ---------------------------------------------------------------------------
# late proof resolution and deposit return
# ---------------------------------------------------------------------------

def resolve_dispute(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    action_id = p.get('id')
    sid = p.get('settlement') or p.get('settlement_id')
    proof_id = p.get('proof_id')
    if not action_id or not sid or not proof_id:
        return {'decision': 'invalid_resolution'}
    if _id_exists(db, 'us_actions', action_id):
        return {'decision': 'reused', 'id': action_id}
    st = _id_exists(db, 'us_settlements', sid)
    if not st:
        return {'decision': 'unknown_settlement', 'settlement': sid}
    if one(db, "SELECT id FROM us_actions WHERE settlement=? "
               "AND kind='dispute_resolved'", (sid,)):
        return overview(db, sid, decision='already_resolved')
    pa = _plan_action(db, sid)
    if not pa:
        return {'decision': 'no_plan_selected', 'settlement': sid}
    plan = _plan_name(pa)
    proof = _id_exists(db, 'us_evidence', proof_id)
    if not proof or proof['kind'] != 'conclusive':
        return {'decision': 'no_conclusive_proof', 'proof_id': proof_id}
    sus = one(db, 'SELECT * FROM us_suspense WHERE settlement=?', (sid,))
    snap = _snapshot(st)
    blocks = snap['dispute_blocks']
    target = None
    if blocks:
        for b in blocks:
            if b['evidence_id'] and proof['meter_interval_id'] == b['meter_interval_id'] \
                    and proof['seconds'] == b['seconds']:
                target = b
                break
        if target is None:
            return {'decision': 'proof_quantity_or_window_mismatch'}
        if proof['workload'] not in target['candidates']:
            return {'decision': 'proof_outside_candidates',
                    'workload': proof['workload'],
                    'candidates': target['candidates']}
    w = _workload(db, proof['workload'])
    tenant = w['tenant']
    cr = snap['customer_rate']
    secs = proof['seconds']
    at = p.get('at')

    if plan == 'A':
        _add_doc(db, id=f'{sid}:inv-late:{proof_id}', doc_type='invoice', at=at,
                 tenant=tenant, settlement=sid, seconds=secs, unit_rate=cr,
                 amount=secs * cr,
                 detail={'kind': 'supplementary_late_attribution',
                         'proof_id': proof_id})
    else:
        tenants = set(snap['tenant_seconds']) | {tenant}
        for t in sorted(tenants):
            final_secs = snap['tenant_seconds'].get(t, 0)
            if t == tenant:
                final_secs += secs
            if final_secs <= 0:
                continue
            _add_doc(db, id=f'{sid}:inv-final:{t}', doc_type='invoice', at=at,
                     tenant=t, settlement=sid, seconds=final_secs, unit_rate=cr,
                     amount=final_secs * cr,
                     detail={'kind': 'final_after_late_proof',
                             'proof_id': proof_id})

    db.execute('INSERT INTO us_actions VALUES(?,?,?,?,?)',
               (action_id, sid, 'dispute_resolved', at,
                _j({'proof_id': proof_id, 'workload': proof['workload'],
                    'tenant': tenant, 'seconds': secs, 'plan': plan})))
    return overview(db, sid, decision='dispute_resolved')


def refund_deposit(db, x=None, **kw):
    p = _params(x, kw)
    ensure(db)
    rid = p.get('id')
    sid = p.get('settlement') or p.get('settlement_id')
    if not rid or not sid:
        return {'decision': 'invalid_refund'}
    if _id_exists(db, 'us_docs', rid):
        return {'decision': 'reused', 'id': rid}
    pa = _plan_action(db, sid)
    if not pa or _plan_name(pa) != 'B':
        return {'decision': 'not_deposit_plan', 'settlement': sid}
    if one(db, "SELECT id FROM us_actions WHERE settlement=? "
               "AND kind='deposit_refunded'", (sid,)):
        return {'decision': 'deposit_already_refunded'}
    advance = _doc_by_id(db, f'{sid}:dep-adv')
    if not advance:
        return {'decision': 'no_deposit_advance'}
    res = one(db, "SELECT * FROM us_actions WHERE settlement=? "
                  "AND kind='dispute_resolved'", (sid,))
    if not res:
        return {'decision': 'collection_outstanding',
                'reason': 'dispute not yet resolved by proof'}
    payload = _parse(res['payload'], {})
    tenant = payload.get('tenant')
    final_inv = _doc_by_id(db, f'{sid}:inv-final:{tenant}')
    if not final_inv:
        return {'decision': 'collection_outstanding',
                'reason': 'final invoice missing'}
    outstanding = _invoice_outstanding(db, final_inv)
    if outstanding > 0:
        return {'decision': 'collection_outstanding',
                'invoice_id': final_inv['id'], 'outstanding': outstanding}
    _add_doc(db, id=rid, doc_type='deposit_refund', at=p.get('at'),
             facility=advance['facility'], settlement=sid,
             seconds=advance['seconds'], amount=advance['amount'],
             detail={'returned_after_collection': True})
    db.execute('INSERT INTO us_actions VALUES(?,?,?,?,?)',
               (p.get('action_id') or f'{sid}:dep-refund-action', sid,
                'deposit_refunded', p.get('at'),
                _j({'refund_doc': rid, 'amount': advance['amount']})))
    ov = overview(db, sid, decision='deposit_refunded')
    return ov


# ---------------------------------------------------------------------------
# read model
# ---------------------------------------------------------------------------

def suspense_state(db, sid):
    ensure(db)
    sus = one(db, 'SELECT * FROM us_suspense WHERE settlement=?', (sid,))
    if not sus:
        return None
    snap = None
    st = _id_exists(db, 'us_settlements', sid)
    if st:
        snap = _snapshot(st)
    resolved = one(db, "SELECT * FROM us_actions WHERE settlement=? "
                       "AND kind='dispute_resolved'", (sid,))
    refunded = one(db, "SELECT id FROM us_actions WHERE settlement=? "
                       "AND kind='deposit_refunded'", (sid,))
    state = 'open'
    recovery_invoice_id = None
    outstanding = None
    if sus['bridge'] == 'platform_reserve':
        if resolved:
            payload = _parse(resolved['payload'], {})
            proof_id = payload.get('proof_id')
            recovery_invoice_id = f'{sid}:inv-late:{proof_id}'
            inv = _doc_by_id(db, recovery_invoice_id)
            if inv:
                outstanding = _invoice_outstanding(db, inv)
                state = 'recovered' if outstanding == 0 else 'recovery_invoiced'
        else:
            state = 'open_pending_proof'
    else:
        if refunded:
            state = 'closed_deposit_returned'
        elif resolved:
            payload = _parse(resolved['payload'], {})
            inv = _doc_by_id(db, f'{sid}:inv-final:{payload.get("tenant")}')
            outstanding = _invoice_outstanding(db, inv) if inv else None
            state = 'paid_pending_deposit_return' if outstanding == 0 \
                else 'invoiced_pending_collection'
        else:
            state = 'secured_by_deposit_pending_proof'
    return {'id': sus['id'], 'settlement': sid, 'state': state,
            'bridge': sus['bridge'], 'seconds': sus['seconds'],
            'disputed_seconds': sus['disputed_seconds'],
            'unexplained_seconds': sus['unexplained_seconds'],
            'amount': sus['amount'], 'candidates': _parse(sus['candidates'], []),
            'blocks': _parse(sus['blocks'], []),
            'window': _parse(sus['window_json'], []),
            'chassis': sus['chassis'], 'generation': sus['generation'],
            'start_ts': sus['start_ts'], 'end_ts': sus['end_ts'],
            'recovery_invoice_id': recovery_invoice_id,
            'recovery_outstanding': outstanding}


def overview(db, sid, decision='overview'):
    ensure(db)
    st = _id_exists(db, 'us_settlements', sid)
    if not st:
        return {'decision': 'unknown_settlement', 'settlement': sid}
    snap = _snapshot(st)
    actions = rows(db, 'SELECT id,kind,at,payload FROM us_actions '
                       'WHERE settlement=? ORDER BY rowid', (sid,))
    docs = rows(db, 'SELECT * FROM us_docs WHERE settlement=? ORDER BY rowid',
                (sid,))
    briefs = [_doc_brief(db, d) for d in docs]
    plan_action = _plan_action(db, sid)
    tenants = sorted(set(snap.get('tenant_seconds', {}))
                     | {d['tenant'] for d in briefs if d['tenant']})
    balances = {}
    for t in tenants:
        ts = tenant_statement(db, t)
        balances[t] = {'invoiced': ts['invoiced'], 'credited': ts['credited'],
                       'paid_effective': ts['paid_effective'],
                       'balance_due': ts['balance_due']}
    facility_id = _parse(plan_action['payload'], {}).get('deposit_facility') \
        if plan_action else None
    deposit = deposit_state(db, facility_id) if facility_id else None
    provider_payments = [b for b in briefs if b['type'] == 'provider_pay']
    # bills are registered before the settlement, so recover them from the
    # plan payload and the payment -> bill reference
    bill_refs = set(_parse(plan_action['payload'], {}).get('bill_ids', [])) \
        if plan_action else set()
    bill_refs |= {p['ref_id'] for p in provider_payments if p.get('ref_id')}
    provider_bills = [_doc_brief(db, _doc_by_id(db, bid))
                      for bid in sorted(bill_refs) if _doc_by_id(db, bid)]
    invoices = [b for b in briefs if b['type'] == 'invoice']
    credits = [b for b in briefs if b['type'] == 'credit']
    customer_payments = [b for b in briefs if b['type'] == 'cust_pay']
    provider_paid_effective = sum(p['amount'] for p in provider_payments
                                  if p['effective'])
    provider_billed_amount = sum(b['amount'] for b in provider_bills
                                 if not _bill_reversal(db, b['id']))
    customer_invoiced = sum(i['amount'] for i in invoices)
    customer_credited = sum(c['amount'] for c in credits)
    customer_paid = sum(p['amount'] for p in customer_payments if p['effective'])
    two_sided = {
        'physical_seconds': snap['physical_seconds'],
        'customer_chargeable_seconds': snap['certain_seconds'],
        'responsibility_seconds': snap['responsibility_seconds'],
        'disputed_seconds': snap['disputed_seconds'],
        'unexplained_seconds': snap['unexplained_seconds'],
        'suspense_gap_seconds': snap['gap_seconds'],
        'provider_billed_amount': provider_billed_amount,
        'provider_paid_effective_amount': provider_paid_effective,
        'customer_invoiced_amount': customer_invoiced,
        'customer_credited_amount': customer_credited,
        'customer_paid_effective_amount': customer_paid,
        'customer_balance_due_amount': customer_invoiced - customer_credited
        - customer_paid,
        'seconds_equation_holds': (
            snap['certain_seconds'] + snap['responsibility_seconds']
            + snap['disputed_seconds'] + snap['unexplained_seconds']
            == snap['physical_seconds']),
    }
    out = {
        'decision': decision,
        'id': sid,
        'at': st['at'],
        'physical_seconds': snap['physical_seconds'],
        'certain_seconds': snap['certain_seconds'],
        'tenant_seconds': snap['tenant_seconds'],
        'responsibility_seconds': snap['responsibility_seconds'],
        'responsibility': snap['responsibility'],
        'disputed_seconds': snap['disputed_seconds'],
        'unexplained_seconds': snap['unexplained_seconds'],
        'gap_seconds': snap['gap_seconds'],
        'page_claims': snap['page_claims'],
        'customer_rate': snap['customer_rate'],
        'provider_rate': snap['provider_rate'],
        'two_sided': two_sided,
        'state': {
            'plan': _plan_name(plan_action),
            'actions': [{'id': a['id'], 'kind': a['kind'], 'at': a['at'],
                         'payload': _parse(a['payload'], {})} for a in actions],
            'resolved': one(db, "SELECT 1 FROM us_actions WHERE settlement=? "
                                 "AND kind='dispute_resolved'", (sid,)) is not None,
            'deposit_refunded': one(
                db, "SELECT 1 FROM us_actions WHERE settlement=? "
                    "AND kind='deposit_refunded'", (sid,)) is not None,
        },
        'invoices': invoices,
        'notices': [b for b in briefs if b['type'] == 'notice'],
        'credits': credits,
        'customer_payments': customer_payments,
        'provider_bills': provider_bills,
        'provider_payments': provider_payments,
        'deposit_movements': [b for b in briefs
                              if b['type'] in ('deposit_advance', 'deposit_refund')],
        'cost_allocations': [b for b in briefs
                             if b['type'] == 'cost_allocation'],
        'suspense': suspense_state(db, sid),
        'acknowledgements': rows(
            db, 'SELECT id,tenant,doc_id,at,actor,basis '
                'FROM us_acknowledgements WHERE settlement=? ORDER BY rowid',
            (sid,)),
        'deposit': deposit,
        'balances': balances,
        'snapshot': snap,
    }
    return out


# ---------------------------------------------------------------------------
# event subsystem dispatch
# ---------------------------------------------------------------------------

OPS = {
    'contract': record_contract,
    'record_contract': record_contract,
    'deposit_facility': record_deposit_facility,
    'record_deposit_facility': record_deposit_facility,
    'meter': record_meter,
    'meter_reading': record_meter,
    'record_meter_reading': record_meter,
    'counter_reading': record_meter,
    'reading': record_meter,
    'receipt': record_receipt,
    'execution_receipt': record_receipt,
    'record_execution_receipt': record_receipt,
    'unavailable': record_unavailable,
    'isolation': record_unavailable,
    'unavailable_period': record_unavailable,
    'migrate': record_migration,
    'migration': record_migration,
    'disjunction': record_disjunction,
    'either_of': record_disjunction,
    'proof': submit_proof,
    'late_proof': submit_proof,
    'submit_late_proof': submit_proof,
    'attribution_proof': submit_proof,
    'capture_page': capture_usage_page,
    'usage_page': capture_usage_page,
    'provider_bill': register_provider_bill,
    'register_provider_bill': register_provider_bill,
    'bill': register_provider_bill,
    'reverse_provider_bill': reverse_provider_bill,
    'provider_bill_reversal': reverse_provider_bill,
    'pay_provider': pay_provider,
    'provider_payment': pay_provider,
    'bounce_provider': bounce_provider_payment,
    'bounce_provider_payment': bounce_provider_payment,
    'invoice': issue_invoice,
    'issue_invoice': issue_invoice,
    'create_invoice': issue_invoice,
    'credit': issue_credit_note,
    'credit_note': issue_credit_note,
    'issue_credit_note': issue_credit_note,
    'pay_customer': pay_customer,
    'customer_payment': pay_customer,
    'bounce_customer': bounce_customer_payment,
    'bounce_customer_payment': bounce_customer_payment,
    'reconcile': reconcile,
    'settle': settle,
    'settlement': settle,
    'execute_plan': execute_plan,
    'plan': execute_plan,
    'resolve': resolve_dispute,
    'resolve_dispute': resolve_dispute,
    'refund_deposit': refund_deposit,
    'acknowledge': acknowledge,
    'sign_off': acknowledge,
    'signoff': acknowledge,
    'customer_sign_off': acknowledge,
    'accept_usage': acknowledge,
}


def run(db, x):
    p = dict(x)
    op = p.pop('op', None)
    p.pop('request_id', None)
    fn = OPS.get(op)
    if fn is None:
        raise ValueError(op)
    ensure(db)
    return fn(db, **p)


# friendly aliases for direct callers
record_meter_reading = record_meter
add_meter_reading = record_meter
submit_execution_receipt = record_receipt
add_execution_receipt = record_receipt
issue_provider_bill = register_provider_bill
create_invoice = issue_invoice
add_credit_note = issue_credit_note
settle_period = settle
