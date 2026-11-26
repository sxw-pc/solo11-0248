"""Settle sandbox incident indemnity from execution facts, not database clocks.

Loss intervals are reconstructed from four pieces of evidence:
  * the workload's run window (the minutes the customer's job could run),
  * the moment physical isolation actually took effect,
  * the re-admission receipt proving the node is usable again,
  * the customer's own recovery confirmation.

The incident ``open`` row and the control-plane ``release`` time are only
workflow states: release at minute 32 does not mean the node is usable until a
receipt exists (minute 36), and downtime does not end until the customer
confirms (minute 37).

Every unavailability minute and every fee voucher is settled through one
shared ledger fragment.  Two policies, the platform service-credit programme
and the customer contract may touch the same loss, but a fragment can only be
paid once -- duplicate notices and late re-reports are recorded as denied
lines rather than creating a second benefit.  Booked insurer obligations and
bank receipts are kept apart so a bounced transfer leaves the receivable
intact while the cash side shows the reversal.
"""
import json

from .store import one, rows

UNAVAILABILITY = 'unavailability'
FEE_KINDS = ('investigation', 'extra_compute', 'forensics')
ROUTES = ('insurer_direct', 'platform_topup')

DDL = """
CREATE TABLE IF NOT EXISTS run_windows(id TEXT PRIMARY KEY,workload TEXT,start_min INTEGER,end_min INTEGER);
CREATE TABLE IF NOT EXISTS timeline_facts(id TEXT PRIMARY KEY,incident TEXT,kind TEXT,at_min INTEGER,epoch INTEGER,note TEXT);
CREATE TABLE IF NOT EXISTS policies(id TEXT, revision INTEGER, effective_at INTEGER, covers TEXT, waiting_min INTEGER, cap INTEGER, coinsurance REAL, exclusions TEXT, PRIMARY KEY(id,revision));
CREATE TABLE IF NOT EXISTS indemnity_notices(id TEXT PRIMARY KEY,incident TEXT,policy TEXT,policy_revision INTEGER,state TEXT,created_at INTEGER);
CREATE TABLE IF NOT EXISTS notice_lines(id TEXT PRIMARY KEY,notice TEXT,line_type TEXT,voucher_id TEXT,amount INTEGER);
CREATE TABLE IF NOT EXISTS fee_vouchers(id TEXT PRIMARY KEY,incident TEXT,kind TEXT,amount INTEGER,verified_amount INTEGER,status TEXT,epoch INTEGER);
CREATE TABLE IF NOT EXISTS credit_vouchers(id TEXT PRIMARY KEY,incident TEXT,minutes INTEGER,amount INTEGER,status TEXT,epoch INTEGER,revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS settlements(id TEXT PRIMARY KEY,incident TEXT,epoch INTEGER,route TEXT,total_loss INTEGER,downtime_min INTEGER);
CREATE TABLE IF NOT EXISTS settlement_lines(id TEXT PRIMARY KEY,settlement TEXT,fragment TEXT,line_type TEXT,policy TEXT,claim_notice TEXT,payee TEXT,amount INTEGER,status TEXT,denied_reason TEXT,epoch INTEGER);
CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,settlement TEXT,policy TEXT,payee TEXT,amount INTEGER,status TEXT,at_min INTEGER,bank_reference TEXT);
CREATE TABLE IF NOT EXISTS incident_reopens(incident TEXT,epoch INTEGER,reason TEXT,at_min INTEGER,PRIMARY KEY(incident,epoch));
"""


def init(db):
    # Individual CREATE statements keep an open BEGIN IMMEDIATE alive;
    # executescript would implicitly commit the event-sourcing transaction.
    for stmt in DDL.split(';'):
        stmt = stmt.strip()
        if stmt:
            db.execute(stmt)


def _epoch(db, incident_id):
    r = one(db, 'SELECT COALESCE(MAX(epoch),0) e FROM incident_reopens WHERE incident=?', (incident_id,))
    return r['e'] if r else 0


def _workload_for_incident(db, incident_id):
    case = one(db, 'SELECT * FROM incidents WHERE id=?', (incident_id,))
    if not case:
        return None
    b = one(db, 'SELECT * FROM bindings WHERE id=?', (case['binding'],))
    w = one(db, 'SELECT * FROM workloads WHERE id=?', (b['workload'],)) if b else None
    return w


def _window(db, incident_id):
    w = _workload_for_incident(db, incident_id)
    if not w:
        return None
    return one(db, 'SELECT * FROM run_windows WHERE workload=?', (w['id'],))


def _fact(db, incident_id, kind, epoch=None):
    if epoch is None:
        epoch = _epoch(db, incident_id)
    return one(db, 'SELECT * FROM timeline_facts WHERE incident=? AND kind=? AND epoch=?',
               (incident_id, kind, epoch))


def downtime_minutes(db, incident_id, epoch=None):
    """Verified downtime for one incident epoch.

    Returns a dict with the resolved interval so callers can see which
    evidence fixed each boundary.  ``start``/``end`` are None until the
    physical isolation fact and the customer recovery confirmation exist;
    the node-ready receipt is required as intermediate evidence and may
    extend (never shorten) the end relative to control-plane release.
    """
    if epoch is None:
        epoch = _epoch(db, incident_id)
    iso = _fact(db, incident_id, 'isolation', epoch)
    ready = _fact(db, incident_id, 'node_ready', epoch)
    rec = _fact(db, incident_id, 'recovery', epoch)
    win = _window(db, incident_id)
    out = {'incident': incident_id, 'epoch': epoch, 'start': None, 'end': None,
           'minutes': 0, 'window_start': win['start_min'] if win else None,
           'window_end': win['end_min'] if win else None,
           'isolation_at': iso['at_min'] if iso else None,
           'node_ready_at': ready['at_min'] if ready else None,
           'recovery_at': rec['at_min'] if rec else None, 'complete': False}
    if not (iso and rec and win):
        return out
    if ready and ready['at_min'] < iso['at_min']:
        return dict(out, reason='ready_before_isolation')
    if rec['at_min'] < iso['at_min']:
        return dict(out, reason='recovery_before_isolation')
    start = max(iso['at_min'], win['start_min'])
    end = min(rec['at_min'], win['end_min'])
    if end <= start:
        return dict(out, reason='outside_run_window')
    out.update(start=start, end=end, minutes=end - start, complete=True)
    return out


def _record_timeline(db, x, kind):
    incident_id = x['incident']
    if not one(db, 'SELECT id FROM incidents WHERE id=?', (incident_id,)):
        return {'decision': 'incident_unknown'}
    epoch = _epoch(db, incident_id)
    if one(db, 'SELECT id FROM timeline_facts WHERE id=?', (x['id'],)):
        return {'decision': 'duplicate_fact'}
    at = x['at']
    iso = _fact(db, incident_id, 'isolation', epoch)
    ready = _fact(db, incident_id, 'node_ready', epoch)
    rec = _fact(db, incident_id, 'recovery', epoch)
    if kind == 'isolation':
        pass
    elif kind == 'node_ready':
        if not iso or at < iso['at_min']:
            return {'decision': 'timeline_order_violation'}
    elif kind == 'recovery':
        if not iso or at < iso['at_min']:
            return {'decision': 'timeline_order_violation'}
        if ready and at < ready['at_min']:
            return {'decision': 'timeline_order_violation'}
    if one(db, 'SELECT id FROM timeline_facts WHERE incident=? AND kind=? AND epoch=?',
           (incident_id, kind, epoch)):
        return {'decision': 'fact_conflict'}
    db.execute('INSERT INTO timeline_facts VALUES(?,?,?,?,?,?)',
               (x['id'], incident_id, kind, at, epoch, x.get('note')))
    return {'decision': 'fact_recorded', 'kind': kind, 'at': at, 'epoch': epoch}


def _policy_terms(db, policy_id, revision=None):
    if revision is None:
        return one(db, 'SELECT * FROM policies WHERE id=? ORDER BY revision DESC LIMIT 1', (policy_id,))
    return one(db, 'SELECT * FROM policies WHERE id=? AND revision=?', (policy_id, revision))


def _loads(value):
    return json.loads(value) if isinstance(value, str) else list(value or ())


def _unavail_fragment(incident_id, epoch, minute):
    return f'{incident_id}:e{epoch}:unavail:{minute}'


def _fee_fragment(incident_id, epoch, voucher_id):
    return f'{incident_id}:e{epoch}:fee:{voucher_id}'


def _settled_fragments(db, incident_id, epoch):
    return {r['fragment'] for r in rows(
        db, "SELECT DISTINCT fragment FROM settlement_lines l JOIN settlements s ON s.id=l.settlement "
            "WHERE s.incident=? AND l.epoch=? AND l.status='payable'", (incident_id, epoch))}


def _effective_credits(db, incident_id, epoch):
    return rows(db, "SELECT * FROM credit_vouchers WHERE incident=? AND epoch=? AND status='active'",
                (incident_id, epoch))


def run(db, x):
    op = x['op']
    if op == 'run_window':
        w = one(db, 'SELECT * FROM workloads WHERE id=?', (x['workload'],))
        if not w:
            return {'decision': 'workload_unknown'}
        if not one(db, 'SELECT 1 FROM starts st JOIN bindings b ON b.id=st.binding WHERE b.workload=?',
                   (w['id'],)):
            return {'decision': 'start_receipt_missing'}
        if x['end_min'] <= x['start_min']:
            return {'decision': 'invalid_window'}
        if one(db, 'SELECT id FROM run_windows WHERE workload=?', (w['id'],)):
            return {'decision': 'window_conflict'}
        db.execute('INSERT INTO run_windows VALUES(?,?,?,?)',
                   (f'win:{w["id"]}', w['id'], x['start_min'], x['end_min']))
        return {'decision': 'window_recorded', 'workload': w['id'],
                'start_min': x['start_min'], 'end_min': x['end_min']}
    if op == 'isolation':
        return _record_timeline(db, x, 'isolation')
    if op == 'node_ready':
        return _record_timeline(db, x, 'node_ready')
    if op == 'recovery':
        return _record_timeline(db, x, 'recovery')
    if op == 'policy':
        if x['revision'] < 1:
            return {'decision': 'invalid_policy_revision'}
        old = _policy_terms(db, x['id'], x['revision'])
        if old:
            return {'decision': 'policy_revision_conflict'}
        latest = _policy_terms(db, x['id'])
        if latest and x['revision'] <= latest['revision']:
            return {'decision': 'stale_policy_revision'}
        coins = x.get('coinsurance', 1.0)
        if coins <= 0 or coins > 1:
            return {'decision': 'invalid_coinsurance'}
        covers = x.get('covers', [])
        exclusions = x.get('exclusions', [])
        unknown = set(covers) | set(exclusions)
        if unknown - {UNAVAILABILITY, *FEE_KINDS}:
            return {'decision': 'unknown_coverage_category'}
        db.execute('INSERT INTO policies VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['revision'], x['effective_at'], json.dumps(sorted(covers)),
                    x.get('waiting_min', 0), x.get('cap'), coins, json.dumps(sorted(exclusions))))
        return {'decision': 'policy_recorded', 'policy': x['id'], 'revision': x['revision']}
    if op == 'notice':
        incident_id = x['incident']
        if not one(db, 'SELECT id FROM incidents WHERE id=?', (incident_id,)):
            return {'decision': 'unavailable'}
        old = one(db, 'SELECT * FROM indemnity_notices WHERE id=?', (x['notice'],))
        if old:
            return {'decision': 'reused' if old['policy'] == x['policy'] else 'notice_conflict'}
        terms = _policy_terms(db, x['policy'])
        if not terms:
            return {'decision': 'policy_unknown'}
        # validate every line before writing anything, so a bad line cannot
        # leave an orphaned notice header behind
        seen_line_ids = set()
        for n, line in enumerate(x.get('lines', []), 1):
            lid = line.get('id', f'{x["notice"]}:line:{n}')
            if line['line_type'] not in (UNAVAILABILITY, *FEE_KINDS):
                return {'decision': 'unknown_coverage_category'}
            if lid in seen_line_ids:
                return {'decision': 'notice_line_conflict'}
            seen_line_ids.add(lid)
            if one(db, 'SELECT id FROM notice_lines WHERE id=?', (lid,)):
                return {'decision': 'notice_line_conflict'}
        db.execute('INSERT INTO indemnity_notices VALUES(?,?,?,?,?,?)',
                   (x['notice'], incident_id, x['policy'], terms['revision'], 'draft', x['at']))
        n = 0
        for line in x.get('lines', []):
            n += 1
            lid = line.get('id', f'{x["notice"]}:line:{n}')
            db.execute('INSERT INTO notice_lines VALUES(?,?,?,?,?)',
                       (lid, x['notice'], line['line_type'], line.get('voucher_id'),
                        line.get('amount', 0)))
        return {'decision': 'drafted', 'notice': x['notice'], 'policy': x['policy'],
                'policy_revision': terms['revision']}
    if op == 'fee':
        incident_id = x['incident']
        if not one(db, 'SELECT id FROM incidents WHERE id=?', (incident_id,)):
            return {'decision': 'incident_unknown'}
        if x['kind'] not in FEE_KINDS or x['amount'] < 0:
            return {'decision': 'invalid_fee'}
        if one(db, 'SELECT id FROM fee_vouchers WHERE id=?', (x['id'],)):
            return {'decision': 'duplicate_fee'}
        epoch = _epoch(db, incident_id)
        verified = 0 if x['kind'] == 'forensics' else x['amount']
        db.execute('INSERT INTO fee_vouchers VALUES(?,?,?,?,?,?,?)',
                   (x['id'], incident_id, x['kind'], x['amount'], verified,
                    'disputed' if x['kind'] == 'forensics' else 'verified', epoch))
        return {'decision': 'fee_recorded', 'voucher': x['id'], 'kind': x['kind'],
                'verified_amount': verified}
    if op == 'verify_forensics':
        v = one(db, "SELECT * FROM fee_vouchers WHERE id=? AND kind='forensics'", (x['voucher'],))
        if not v:
            return {'decision': 'voucher_unknown'}
        if v['status'] == 'verified':
            return {'decision': 'already_verified'}
        if x['verified_amount'] < 0 or x['verified_amount'] > v['amount']:
            return {'decision': 'invalid_verified_amount'}
        db.execute('UPDATE fee_vouchers SET verified_amount=?, status=? WHERE id=?',
                   (x['verified_amount'], 'verified', v['id']))
        return {'decision': 'forensics_verified', 'voucher': v['id'],
                'verified_amount': x['verified_amount']}
    if op == 'dispute_forensics':
        v = one(db, "SELECT * FROM fee_vouchers WHERE id=? AND kind='forensics'", (x['voucher'],))
        if not v:
            return {'decision': 'voucher_unknown'}
        if one(db, 'SELECT l.id FROM settlement_lines l JOIN settlements s ON s.id=l.settlement '
                  "WHERE l.fragment=? AND l.status='payable'",
               (_fee_fragment(v['incident'], v['epoch'], v['id']),)):
            return {'decision': 'settled_locked'}
        db.execute("UPDATE fee_vouchers SET status='disputed', verified_amount=0 WHERE id=?", (v['id'],))
        return {'decision': 'forensics_disputed', 'voucher': v['id']}
    if op == 'credit':
        incident_id = x['incident']
        if not one(db, 'SELECT id FROM incidents WHERE id=?', (incident_id,)):
            return {'decision': 'incident_unknown'}
        if x['minutes'] < 0 or x['amount'] < 0:
            return {'decision': 'invalid_credit'}
        if one(db, 'SELECT id FROM credit_vouchers WHERE id=?', (x['id'],)):
            return {'decision': 'duplicate_credit'}
        epoch = _epoch(db, incident_id)
        db.execute('INSERT INTO credit_vouchers VALUES(?,?,?,?,?,?,?)',
                   (x['id'], incident_id, x['minutes'], x['amount'], 'active', epoch, None))
        return {'decision': 'credit_recorded', 'voucher': x['id'], 'minutes': x['minutes']}
    if op == 'revoke_credit':
        v = one(db, 'SELECT * FROM credit_vouchers WHERE id=?', (x['voucher'],))
        if not v:
            return {'decision': 'voucher_unknown'}
        if v['status'] == 'revoked':
            return {'decision': 'already_revoked'}
        if one(db, 'SELECT 1 FROM settlements WHERE incident=? AND epoch=?',
               (v['incident'], v['epoch'])):
            return {'decision': 'settled_locked'}
        db.execute("UPDATE credit_vouchers SET status='revoked', revoked_at=? WHERE id=?",
                   (x['at'], v['id']))
        return {'decision': 'credit_revoked', 'voucher': v['id']}
    if op == 'payment':
        if x['status'] not in ('presented', 'bounced', 're_presented'):
            return {'decision': 'invalid_payment_status'}
        if one(db, 'SELECT id FROM payments WHERE id=?', (x['id'],)):
            return {'decision': 'duplicate_payment'}
        s = one(db, 'SELECT * FROM settlements WHERE id=?', (x['settlement'],))
        if not s:
            return {'decision': 'settlement_unknown'}
        if not one(db, 'SELECT id FROM policies WHERE id=?', (x['policy'],)):
            return {'decision': 'policy_unknown'}
        if x['amount'] <= 0:
            return {'decision': 'invalid_payment'}
        db.execute('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], s['id'], x['policy'], x['payee'], x['amount'], x['status'],
                    x['at'], x.get('bank_reference')))
        return {'decision': 'payment_recorded', 'voucher': x['id'], 'status': x['status']}
    if op == 'reopen':
        case = one(db, "SELECT * FROM incidents WHERE id=?", (x['incident'],))
        if not case:
            return {'decision': 'incident_unknown'}
        if case['status'] != 'closed':
            return {'decision': 'incident_not_closed'}
        next_epoch = _epoch(db, x['incident']) + 1
        if one(db, 'SELECT 1 FROM incident_reopens WHERE incident=? AND epoch=?',
               (x['incident'], next_epoch)):
            return {'decision': 'reopen_conflict'}
        db.execute("UPDATE incidents SET status='open' WHERE id=?", (x['incident'],))
        db.execute('INSERT INTO incident_reopens VALUES(?,?,?,?)',
                   (x['incident'], next_epoch, x.get('reason'), x['at']))
        return {'decision': 'reopened', 'incident': x['incident'], 'epoch': next_epoch}
    if op == 'settle':
        return _settle(db, x)
    raise ValueError(op)


def _notice_map(db, incident_id):
    out = {}
    for n in rows(db, 'SELECT * FROM indemnity_notices WHERE incident=?', (incident_id,)):
        out[n['id']] = n
    return out


def _settle(db, x):
    incident_id = x['incident']
    route = x['route']
    if route not in ROUTES:
        return {'decision': 'invalid_route'}
    case = one(db, 'SELECT * FROM incidents WHERE id=?', (incident_id,))
    if not case:
        return {'decision': 'incident_unknown'}
    epoch = x.get('epoch', _epoch(db, incident_id))
    if one(db, 'SELECT id FROM settlements WHERE id=?', (x['settlement'],)):
        return {'decision': 'settlement_conflict'}
    dt = downtime_minutes(db, incident_id, epoch)
    if not dt['complete']:
        return {'decision': 'downtime_incomplete', **dt}
    minutes = dt['minutes']
    rate = x['minute_rate']
    if rate <= 0:
        return {'decision': 'invalid_rate'}
    total_loss = minutes * rate
    notices = _notice_map(db, incident_id)
    if not notices:
        return {'decision': 'no_notice'}
    terms_by_notice = {nid: _policy_terms(db, n['policy'], n['policy_revision'])
                       for nid, n in notices.items()}
    if any(t is None for t in terms_by_notice.values()):
        return {'decision': 'policy_version_missing'}
    settled_fragments = _settled_fragments(db, incident_id, epoch)

    # --- platform service credits already in the customer's hands ----------
    credits = _effective_credits(db, incident_id, epoch)
    credited_min = sum(c['minutes'] for c in credits)
    credited_amt = sum(c['amount'] for c in credits)
    # credits cannot exceed the verified downtime loss
    applied_credit_min = min(credited_min, minutes)
    applied_credit_amt = min(credited_amt, total_loss)
    if route == 'platform_topup':
        topup_min = minutes - applied_credit_min
        topup_amt = total_loss - applied_credit_amt
        if topup_min > 0:
            cid = f'credit:topup:{incident_id}:e{epoch}'
            if not one(db, 'SELECT id FROM credit_vouchers WHERE id=?', (cid,)):
                db.execute('INSERT INTO credit_vouchers VALUES(?,?,?,?,?,?,?)',
                           (cid, incident_id, topup_min, topup_amt, 'active', epoch, None))
            credits = rows(db, "SELECT * FROM credit_vouchers WHERE incident=? AND epoch=? AND status='active'",
                           (incident_id, epoch))
            applied_credit_min = min(sum(c['minutes'] for c in credits), minutes)
            applied_credit_amt = min(sum(c['amount'] for c in credits), total_loss)

    # --- catalog of claim lines ---------------------------------------------
    all_lines = []
    for nid, n in notices.items():
        for ln in rows(db, 'SELECT * FROM notice_lines WHERE notice=?', (nid,)):
            all_lines.append((nid, n, ln))

    fee_vouchers = {v['id']: v for v in rows(db, 'SELECT * FROM fee_vouchers WHERE incident=? AND epoch=?',
                                             (incident_id, epoch))}
    fee_claimed = {}
    for nid, n, ln in all_lines:
        if ln['line_type'] in FEE_KINDS:
            fee_claimed.setdefault(ln['voucher_id'], []).append((nid, n, ln))

    lines_out = []
    obligations = []   # (policy, payee, amount, fragment, notice)
    seq = 0

    def add_line(fragment, line_type, notice, payee, amount, status, reason=None):
        nonlocal seq
        seq += 1
        lid = f"{x['settlement']}:line:{seq}"
        db.execute('INSERT INTO settlement_lines VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (lid, x['settlement'], fragment, line_type,
                    notices[notice]['policy'] if notice else None, notice, payee, amount, status, reason, epoch))
        lines_out.append({'fragment': fragment, 'line_type': line_type, 'policy':
                          notices[notice]['policy'] if notice else None, 'notice': notice,
                          'payee': payee, 'amount': amount, 'status': status, 'denied_reason': reason})

    # --- unavailability: one ledger fragment per verified minute ------------
    # waiting period minutes belong to nobody (policy deductible).
    # insurer_direct: minutes already in the customer's hands as platform
    #   credit cannot draw insurer cash again (single recovery for the minute).
    # platform_topup: the platform funded the whole loss as credits, so the
    #   business-interruption insurer indemnifies the platform instead of the
    #   customer; the credit is the funding instrument, not a second claimant.
    waiting = {}
    for nid, terms in terms_by_notice.items():
        waiting[nid] = terms['waiting_min']
    credit_min_remaining = applied_credit_min
    for minute in range(dt['start'], dt['end']):
        fragment = _unavail_fragment(incident_id, epoch, minute)
        if fragment in settled_fragments:
            for nid, n, ln in all_lines:
                if ln['line_type'] == UNAVAILABILITY:
                    add_line(fragment, UNAVAILABILITY, nid, None, 0, 'denied', 'fragment_already_settled')
            continue
        claimants = [(nid, n, ln) for nid, n, ln in all_lines if ln['line_type'] == UNAVAILABILITY]
        eligible = []
        for nid, n, ln in claimants:
            terms = terms_by_notice[nid]
            if UNAVAILABILITY not in _loads(terms['covers']):
                add_line(fragment, UNAVAILABILITY, nid, None, 0, 'denied', 'coverage_excluded')
            elif UNAVAILABILITY in _loads(terms['exclusions']):
                add_line(fragment, UNAVAILABILITY, nid, None, 0, 'denied', 'policy_exclusion')
            else:
                eligible.append((nid, n, terms))
        if not eligible:
            add_line(fragment, UNAVAILABILITY, None, None, 0, 'denied', 'no_eligible_coverage')
            continue
        # deterministic winner: earliest notice id, then policy id
        eligible.sort(key=lambda t: (notices[t[0]]['created_at'], t[0]))
        winner_nid, winner_n, terms = eligible[0]
        for nid, n, terms2 in eligible[1:]:
            add_line(fragment, UNAVAILABILITY, nid, None, 0, 'denied', 'duplicate_fragment_other_winner')
        # the waiting-period deductible is measured from the first covered
        # minute, independently of platform credits granted in parallel
        if waiting[winner_nid] > 0:
            waiting[winner_nid] -= 1
            add_line(fragment, UNAVAILABILITY, winner_nid, None, 0, 'denied', 'waiting_period')
            continue
        if route == 'insurer_direct' and credit_min_remaining > 0:
            credit_min_remaining -= 1
            add_line(fragment, UNAVAILABILITY, winner_nid, None, 0, 'denied', 'platform_credit_offset')
            continue
        gross = rate
        net = int(round(gross * terms['coinsurance']))
        cap = terms['cap']
        paid_so_far = sum(o[2] for o in obligations if o[0] == terms['id'] and o[4] == winner_nid)
        if cap is not None:
            net = min(net, max(0, cap - paid_so_far))
        residual = gross - net
        if route == 'insurer_direct':
            if net > 0:
                add_line(fragment, UNAVAILABILITY, winner_nid, x['customer'], net, 'payable')
                obligations.append((terms['id'], x['customer'], net, fragment, winner_nid))
            if residual > 0:
                add_line(fragment, UNAVAILABILITY, None, x['customer'], residual, 'payable',
                         'platform_residual')
        else:  # platform_topup: insurer indemnifies the platform for funded credits
            if net > 0:
                add_line(fragment, UNAVAILABILITY, winner_nid, x['platform'], net, 'payable')
                obligations.append((terms['id'], x['platform'], net, fragment, winner_nid))
            if residual > 0:
                add_line(fragment, UNAVAILABILITY, None, x['platform'], residual, 'payable',
                         'platform_retained')

    # --- fee fragments: investigation / extra compute / forensics -----------
    for vid, vouchers in sorted(fee_vouchers.items()):
        v = vouchers
        fragment = _fee_fragment(incident_id, epoch, vid)
        claimants = fee_claimed.get(vid, [])
        if not claimants:
            continue
        if fragment in settled_fragments:
            for nid, n, ln in claimants:
                add_line(fragment, v['kind'], nid, None, 0, 'denied', 'fragment_already_settled')
            continue
        if v['status'] != 'verified' or v['verified_amount'] <= 0:
            for nid, n, ln in claimants:
                add_line(fragment, v['kind'], nid, None, 0, 'denied', 'fee_not_verified')
            continue
        eligible = []
        for nid, n, ln in claimants:
            terms = terms_by_notice[nid]
            if v['kind'] not in _loads(terms['covers']) or v['kind'] in _loads(terms['exclusions']):
                add_line(fragment, v['kind'], nid, None, 0, 'denied', 'coverage_excluded')
            else:
                eligible.append((nid, n, terms))
        if not eligible:
            continue
        eligible.sort(key=lambda t: (notices[t[0]]['created_at'], t[0]))
        winner_nid, winner_n, terms = eligible[0]
        for nid, n, terms2 in eligible[1:]:
            add_line(fragment, v['kind'], nid, None, 0, 'denied', 'duplicate_fragment_other_winner')
        amount = int(round(v['verified_amount'] * terms['coinsurance']))
        cap = terms['cap']
        if cap is not None:
            paid_so_far = sum(o[2] for o in obligations if o[0] == terms['id'] and o[4] == winner_nid)
            amount = min(amount, max(0, cap - paid_so_far))
        if amount > 0:
            add_line(fragment, v['kind'], winner_nid, x['platform'], amount, 'payable')
            obligations.append((terms['id'], x['platform'], amount, fragment, winner_nid))

    # --- persist settlement header and expected payment obligations ---------
    db.execute('INSERT INTO settlements VALUES(?,?,?,?,?,?)',
               (x['settlement'], incident_id, epoch, route, total_loss, minutes))
    n = 0
    for policy_id, payee, amount, fragment, nid in obligations:
        n += 1
        db.execute('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?)',
                   (f'{x["settlement"]}:due:{n}', x['settlement'], policy_id, payee, amount,
                    'booked', x.get('at', 0), None))

    customer_credit = min(applied_credit_amt, total_loss)
    customer_cash = sum(o[2] for o in obligations if o[1] == x['customer'])
    platform_receivable = sum(o[2] for o in obligations if o[1] == x['platform'])
    return {'decision': 'settled', 'settlement': x['settlement'], 'incident': incident_id,
            'epoch': epoch, 'route': route, 'downtime_minutes': minutes,
            'interval': {'start': dt['start'], 'end': dt['end']},
            'total_loss': total_loss, 'rate': rate,
            'platform_credit_minutes': applied_credit_min,
            'platform_credit_amount': customer_credit,
            'customer_cash': customer_cash,
            'customer_total': customer_credit + customer_cash,
            'platform_receivable': platform_receivable,
            'lines': lines_out,
            'obligations': [{'policy': p, 'payee': payee, 'amount': amt}
                            for p, payee, amt, _, _ in obligations]}


def bank_position(db, settlement_id):
    """Booked rights vs money actually received, kept separately."""
    out = {}
    for r in rows(db, 'SELECT policy,status,amount FROM payments WHERE settlement=? ORDER BY id',
                  (settlement_id,)):
        slot = out.setdefault(r['policy'], {'booked': 0, 'presented': 0, 'bounced': 0,
                                            're_presented': 0, 'received': 0})
        slot[r['status']] = slot.get(r['status'], 0) + r['amount']
        if r['status'] in ('presented', 're_presented'):
            slot['received'] += r['amount']
        if r['status'] == 'bounced':
            slot['received'] -= r['amount']
    return out
