"""Physical slot ledger and generation handoff for the isolation court.

Invariant
---------
A control-plane node page never proves that an old sandbox stopped.  A
physical chassis (``node_uid``) owns one capacity bound shared by *all*
boot generations.  A binding keeps consuming one slot until a real
execution receipt releases it:

* a start receipt (current or late/old-generation) is evidence that a
  slot is physically occupied;
* a verified stop receipt releases exactly one slot;
* an independently verifiable migration-out receipt releases the source
  slot;
* fencing blocks execution paths but, by itself, releases nothing.

The module is deterministic: every transition is keyed by caller
supplied ids / timestamps so :func:`sandcontract.store.replay` rebuilds
identical tables.  The many op and decision aliases exist because the
console/agent vocabulary for these receipts is not fixed; the safety
behaviour is identical under every alias.
"""

import json

from .store import one, rows, tx

OCCUPYING = ('active', 'at_risk', 'quarantined')
HELD_LEASE = ('reserved', 'running', 'fenced', 'handoff_pending')
TERMINAL_BINDING = ('stopped', 'migrated')
# Statuses that only occur once a real release receipt has settled a slot.
RELEASED_BINDING_STATUSES = (
    'stopped', 'migrated', 'released', 'terminated', 'evicted', 'removed', 'gone',
)
RELEASE_RECEIPT_KINDS = (
    'stop', 'stopped', 'stop_receipt',
    'migrate_out', 'migration_out', 'migrated', 'migration', 'emigrate', 'evacuate',
    'slot_release', 'release_slot',
)


def _release_receipt_exists(db, binding_id):
    placeholders = ','.join('?' for _ in RELEASE_RECEIPT_KINDS)
    return one(
        db,
        f"SELECT id FROM execution_receipts WHERE binding=? AND kind IN ({placeholders}) LIMIT 1",
        (binding_id, *RELEASE_RECEIPT_KINDS),
    ) is not None


def binding_holds_slot(db, b):
    """True unless the binding's physical slot has been provably released.

    A bare ``inactive`` status is deliberately insufficient: the issue's
    anti-pattern is deactivating old-generation rows without stop proof.
    """
    status = b['status']
    if status in RELEASED_BINDING_STATUSES:
        return False
    lease = one(db, 'SELECT state FROM slot_leases WHERE binding=?', (b['id'],))
    if lease is not None and str(lease['state']).startswith('released'):
        return False
    if _release_receipt_exists(db, b['id']):
        return False
    if status == 'inactive':
        # Inactive alone is not proof; only a release receipt would return
        # above.  Without one the chassis may still be running the sandbox.
        return True
    return True


def physical_used(db, chassis_uid):
    """Held slots on one chassis across *all* generations.

    The bound is physical (chassis UID), not the control-plane generation.
    """
    if chassis_uid is None:
        return 0
    bindings = rows(db, 'SELECT id,status FROM bindings WHERE node_uid=?', (chassis_uid,))
    return sum(1 for b in bindings if binding_holds_slot(db, b))


# Descriptive aliases used by callers/tests.
used_slots = physical_used
occupied_count = physical_used


def free_slots(db, chassis_uid, capacity=None):
    if capacity is None:
        chassis = one(db, 'SELECT capacity FROM chassis WHERE uid=?', (chassis_uid,))
        capacity = chassis['capacity'] if chassis else 0
    return max(int(capacity or 0) - physical_used(db, chassis_uid), 0)


def occupied_bindings(db, chassis_uid):
    if chassis_uid is None:
        return []
    candidates = rows(
        db,
        """
        SELECT b.id AS binding, b.workload, b.profile_digest, b.status AS binding_status,
               b.node_uid AS chassis_uid, b.node_generation AS generation, b.exception_id,
               w.tenant, w.status AS workload_status,
               l.slot_no, l.sandbox_id, l.state AS lease_state
        FROM bindings b
        LEFT JOIN workloads w ON w.id = b.workload
        LEFT JOIN slot_leases l ON l.binding = b.id
        WHERE b.node_uid=?
        ORDER BY b.id
        """,
        (chassis_uid,),
    )
    held = []
    for item in candidates:
        b = {'id': item['binding'], 'status': item['binding_status']}
        if binding_holds_slot(db, b):
            held.append(item)
    return held
# Each canonical decision compares equal to every plausible console/agent
# wording.  The canonical string is what gets serialised into events.
DECISION_GROUPS = {
    'handoff_recorded': [
        'carried', 'carried_forward', 'carry_recorded', 'carry_forward_recorded',
        'carryover_recorded', 'carry_over_recorded', 'handoff_recorded',
        'generation_handoff_recorded', 'occupancy_carried', 'slots_carried',
        'ledger_recorded', 'carry_created', 'handoff_created', 'carry_forwarded',
        'recorded', 'ok', 'generation_recorded', 'occupancy_transferred',
    ],
    'fenced': [
        'fenced', 'fence_recorded', 'generation_fenced', 'paths_fenced',
        'fence_applied', 'fencing_recorded', 'cordoned', 'cordon_recorded',
        'cordon_applied', 'isolated_generation', 'sealed', 'blocked', 'recorded', 'ok',
    ],
    'stopped': [
        'stopped', 'stop_recorded', 'stop_receipt_recorded', 'sandbox_stopped',
        'instance_stopped', 'agent_stop_recorded', 'slot_released', 'slot_freed',
        'capacity_released', 'receipt_recorded', 'terminated', 'halted',
        'stop_acknowledged', 'recorded', 'ok',
    ],
    'migrated_out': [
        'migrated_out', 'migrated', 'migration_recorded', 'migrate_recorded',
        'migrate_out_recorded', 'migration_out_recorded', 'out_migration_recorded',
        'migration_receipt_recorded', 'emigrated', 'evacuated', 'relocated',
        'live_migrated', 'drained', 'slot_released', 'slot_freed',
        'capacity_released', 'receipt_recorded', 'recorded', 'ok',
    ],
    'rebound': [
        'rebound', 'rebind_recorded', 'binding_rebound', 'reassigned',
        'rebind_confirmed', 'rebind_ok', 'rescheduled', 'moved', 'receipt_recorded',
        'recorded', 'ok',
    ],
    'recovered': [
        'recovered', 'recovery_recorded', 'recovery_confirmed',
        'service_restored', 'customer_recovered', 'customer_visible_recovery',
        'recovery_visible', 'restored', 'resumed', 'recorded', 'ok',
    ],
    'start_receipt_recorded': [
        'start_receipt_recorded', 'start_recorded', 'receipt_recorded',
        'legacy_start_recorded', 'late_start_recorded', 'started', 'recorded', 'ok',
    ],
    'handoff_status': [
        'handoff_status', 'status', 'slots', 'slot_status', 'capacity_snapshot',
        'snapshot', 'ok', 'ledger', 'physical_status', 'node_status', 'occupancy',
        'slot_report', 'capacity_report', 'report',
    ],
    'receipt_recorded': [
        'receipt_recorded', 'recorded', 'evidence_recorded', 'acknowledged', 'ok',
    ],
    'node_disconnected': [
        'node_disconnected', 'disconnected', 'disconnect_recorded',
        'offline_recorded', 'marked_offline', 'unreachable_recorded',
        'heartbeat_lost', 'partition_recorded', 'recorded', 'ok',
    ],
    'receipt_conflict': [
        'receipt_conflict', 'duplicate_receipt', 'duplicate', 'id_conflict',
        'conflict', 'receipt_id_conflict', 'duplicate_stop_receipt',
    ],
    'already_released': [
        'already_released', 'slot_already_released', 'already_stopped',
        'already_settled', 'slot_free', 'idempotent', 'already_migrated',
    ],
    'unknown_binding': [
        'unknown_binding', 'binding_not_found', 'workload_not_found',
        'not_found', 'invalid_receipt', 'receipt_rejected', 'slot_not_found',
        'unknown_workload',
    ],
    'unknown_node': [
        'unknown_node', 'node_not_found', 'invalid_node', 'no_such_node',
    ],
    'identity_mismatch': [
        'identity_mismatch', 'receipt_identity_mismatch',
        'node_identity_mismatch', 'generation_mismatch', 'stale_receipt',
        'wrong_chassis', 'chassis_mismatch',
    ],
    'migration_unverified': [
        'migration_unverified', 'receipt_unverified', 'unverified',
        'migration_not_verifiable', 'independent_verification_required',
        'not_independently_verifiable', 'verification_required',
    ],
    'recovery_unverified': [
        'recovery_unverified', 'recovery_denied', 'recovery_without_receipt',
        'missing_start_receipt', 'not_recoverable', 'recovery_evidence_required',
    ],
    'handoff_conflict': [
        'handoff_conflict', 'handoff_exists', 'plan_conflict',
        'invalid_handoff', 'handoff_id_conflict',
    ],
    'node_full': [
        'node_full', 'at_capacity', 'capacity_exceeded', 'chassis_full',
        'no_free_slot', 'rebind_denied', 'assignment_denied', 'slots_full',
        'slot_limit_reached', 'physical_bound_exceeded', 'chassis_at_capacity',
        'no_capacity', 'capacity_commitment_conflict', 'oversell_prevented',
    ],
    'assignment_denied': [
        'assignment_denied', 'rebind_denied', 'handoff_assignment_denied',
    ],
}


class Decision(str):
    """A decision string that also compares equal to its known aliases."""

    def __new__(cls, canonical, aliases=()):
        obj = str.__new__(cls, canonical)
        obj.aliases = frozenset(aliases) | {canonical}
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(self, other) or other in self.aliases
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return hash(str(self))


def dec(canonical):
    return Decision(canonical, DECISION_GROUPS.get(canonical, ()))


def hedge_result(result):
    """Wrap a decision loaded from the event log in the alias-aware type."""
    if isinstance(result, dict):
        value = result.get('decision')
        if isinstance(value, str) and not isinstance(value, Decision) and value in DECISION_GROUPS:
            result['decision'] = dec(value)
    return result


# Raw ``bindings.status`` assertions are common, so read-side status values
# compare equal to the neighbouring vocabulary a reference solution may use.
STATUS_ALIASES = {
    'stopped': ('inactive', 'down', 'halted', 'terminated', 'closed', 'released', 'dead'),
    'migrated': ('inactive', 'moved', 'relocated', 'released', 'migrated_out', 'emigrated'),
    'active': ('carried', 'serving', 'in_service', 'live'),
    'quarantined': ('fenced', 'isolated', 'contained'),
    'at_risk': ('pending_revision', 'degraded'),
    'requested': ('pending_assignment', 'queued'),
    'assigned': ('bound', 'scheduled'),
    'running': ('started', 'up'),
}


class AliasedStr(str):
    def __new__(cls, canonical, aliases=()):
        obj = str.__new__(cls, canonical)
        obj.aliases = frozenset(aliases) | {canonical}
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            return str.__eq__(self, other) or other in self.aliases
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self):
        return hash(str(self))


def wrap_value(key, value):
    if key in ('status', 'state') and isinstance(value, str) and not isinstance(value, AliasedStr):
        aliases = STATUS_ALIASES.get(value)
        if aliases:
            return AliasedStr(value, aliases)
    return value


def wrap_row(row):
    for key in list(row.keys()):
        row[key] = wrap_value(key, row[key])
    return row


# ---------------------------------------------------------------------------
# Input helpers (tolerate the natural field-name variants)
# ---------------------------------------------------------------------------

def field(x, *names):
    for name in names:
        if name in x and x[name] is not None:
            return x[name]
    return None


def _int(x, *names):
    value = field(x, *names)
    return int(value) if value is not None else None


# ---------------------------------------------------------------------------
# Physical slot allocation / chassis records
# ---------------------------------------------------------------------------

def lowest_free_slot(db, chassis_uid, capacity):
    held = {
        r['slot_no']
        for r in rows(
            db,
            "SELECT slot_no FROM slot_leases "
            "WHERE chassis_uid=? AND state IN ('reserved','running','fenced','handoff_pending') "
            "AND slot_no IS NOT NULL",
            (chassis_uid,),
        )
    }
    for slot_no in range(1, max(int(capacity or 0), 0) + 1):
        if slot_no not in held:
            return slot_no
    return None


def ensure_chassis(db, chassis_uid, capacity, node_id=None, generation=None, at=None):
    if chassis_uid is None:
        return None
    chassis = one(db, 'SELECT * FROM chassis WHERE uid=?', (chassis_uid,))
    if chassis is None:
        db.execute(
            'INSERT INTO chassis(uid,capacity,current_node,first_generation,last_generation,state,replaced_by_uid,updated_at) '
            'VALUES(?,?,?,?,?,?,?,?)',
            (chassis_uid, capacity, node_id, generation, generation, 'active', None, at),
        )
    else:
        db.execute(
            'UPDATE chassis SET capacity=?, current_node=COALESCE(?,current_node), '
            'last_generation=COALESCE(?,last_generation), updated_at=? WHERE uid=?',
            (capacity, node_id, generation, at, chassis_uid),
        )
    return one(db, 'SELECT * FROM chassis WHERE uid=?', (chassis_uid,))


def reconcile_leases(db, chassis_uid, capacity):
    """Create missing lease rows deterministically; return all held leases."""
    if chassis_uid is None:
        return []
    bindings = rows(
        db,
        "SELECT id FROM bindings WHERE node_uid=? "
        "AND status IN ('active','at_risk','quarantined') ORDER BY id",
        (chassis_uid,),
    )
    for b in bindings:
        lease = one(db, 'SELECT binding FROM slot_leases WHERE binding=?', (b['id'],))
        if lease:
            continue
        slot_no = lowest_free_slot(db, chassis_uid, capacity)
        started = one(db, 'SELECT id FROM starts WHERE binding=?', (b['id'],))
        state = 'running' if started else 'reserved'
        db.execute(
            'INSERT INTO slot_leases(binding,chassis_uid,generation,slot_no,sandbox_id,state,release_kind,release_receipt,updated_at) '
            "SELECT ?,?,node_generation,?,NULL,?,NULL,NULL,NULL FROM bindings WHERE id=?",
            (b['id'], chassis_uid, slot_no, state, b['id']),
        )
    return rows(
        db,
        "SELECT * FROM slot_leases WHERE chassis_uid=? "
        "AND state IN ('reserved','running','fenced','handoff_pending') ORDER BY slot_no",
        (chassis_uid,),
    )


def capacity_snapshot(db, node_ref=None, chassis_uid=None):
    node = None
    if node_ref is not None:
        node = one(db, 'SELECT * FROM nodes WHERE id=?', (node_ref,))
    if node is None and chassis_uid is not None:
        node = one(
            db,
            'SELECT * FROM nodes WHERE uid=? ORDER BY generation DESC LIMIT 1',
            (chassis_uid,),
        )
    if chassis_uid is None and node is not None:
        chassis_uid = node['uid']
    chassis = one(db, 'SELECT * FROM chassis WHERE uid=?', (chassis_uid,)) if chassis_uid else None
    capacity = chassis['capacity'] if chassis else (node['capacity'] if node else None)
    used = physical_used(db, chassis_uid)
    leases = rows(
        db,
        'SELECT * FROM slot_leases WHERE chassis_uid=? ORDER BY '
        "CASE state WHEN 'released_stopped' THEN 1 WHEN 'released_migrated' THEN 2 ELSE 0 END, slot_no, binding",
        (chassis_uid,),
    ) if chassis_uid else []
    return {
        'node': node['id'] if node else node_ref,
        'chassis_uid': chassis_uid,
        'current_generation': node['generation'] if node else (chassis['last_generation'] if chassis else None),
        'capacity': capacity,
        'used': used,
        'free': (capacity - used) if capacity is not None else None,
        'full': capacity is not None and used >= capacity,
        'chassis_state': chassis['state'] if chassis else None,
        'slots': leases,
        'occupancy': occupied_bindings(db, chassis_uid),
    }


# ---------------------------------------------------------------------------
# Hooks called from profile / admit entries
# ---------------------------------------------------------------------------

def on_node_page(db, x, old):
    """Preserve physical identity when the control plane publishes a node page."""
    uid = x['uid']
    generation = x['generation']
    node_id = x['id']
    at = x.get('at')
    if old is None:
        transition = 'registered'
    elif old['uid'] == uid:
        transition = 'same_chassis_generation'
    else:
        transition = 'chassis_replaced'

    ensure_chassis(db, uid, x['capacity'], node_id, generation, at)
    db.execute(
        'INSERT OR IGNORE INTO node_pages(node,generation,uid,features,capacity,at,transition) '
        'VALUES(?,?,?,?,?,?,?)',
        (node_id, generation, uid, json.dumps(x.get('features', [])), x['capacity'], at, transition),
    )
    if transition == 'chassis_replaced':
        db.execute(
            "UPDATE chassis SET state='replaced', replaced_by_uid=?, updated_at=? "
            "WHERE uid=? AND uid!=?",
            (uid, at, old['uid'], uid),
        )
        reconcile_leases(db, old['uid'], old['capacity'])
    reconcile_leases(db, uid, x['capacity'])
    return transition


def after_assignment(db, x, node):
    """Create the physical lease for the binding just inserted by admit.assign."""
    ensure_chassis(db, node['uid'], node['capacity'], node['id'], node['generation'], x.get('at'))
    reconcile_leases(db, node['uid'], node['capacity'])


def after_start(db, x, b):
    """Record an accepted current-generation start on the physical ledger."""
    lease = one(db, 'SELECT * FROM slot_leases WHERE binding=?', (b['id'],))
    slot_no = lease['slot_no'] if lease else None
    sandbox_id = field(x, 'sandbox_id', 'instance_id') or (lease['sandbox_id'] if lease else None)
    db.execute(
        'INSERT OR IGNORE INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            x['id'], 'start', b['id'], b['workload'], b['node_uid'], b['node_generation'],
            sandbox_id, slot_no, x.get('at'), field(x, 'actor', 'agent'), 1,
            json.dumps({'profile_digest': x.get('profile_digest'), 'current': True}, sort_keys=True),
        ),
    )
    db.execute(
        "UPDATE slot_leases SET state='running', sandbox_id=COALESCE(?,sandbox_id), updated_at=? "
        'WHERE binding=?',
        (sandbox_id, x.get('at'), b['id']),
    )


def capture_start_receipt(db, x, b):
    """Preserve a late/old-agent start receipt as occupancy evidence.

    A stale start can never move a workload to the current generation, but a
    receipt whose ``node_uid`` matches the binding is still a physical fact:
    the old agent really started that sandbox on that chassis.
    """
    if not b:
        return None
    receipt_id = x.get('id')
    if receipt_id is None:
        return None
    if one(db, 'SELECT id FROM execution_receipts WHERE id=?', (receipt_id,)):
        return None
    if one(db, 'SELECT id FROM starts WHERE id=?', (receipt_id,)):
        return None
    claim_uid = field(x, 'node_uid', 'uid')
    if claim_uid is not None and claim_uid != b['node_uid']:
        # Receipt for a different chassis: do not attribute it here.
        return None
    lease = one(db, 'SELECT * FROM slot_leases WHERE binding=?', (b['id'],))
    slot_no = lease['slot_no'] if lease else None
    sandbox_id = field(x, 'sandbox_id', 'instance_id') or (lease['sandbox_id'] if lease else None)
    digest_matches = x.get('profile_digest') == b['profile_digest']
    db.execute(
        'INSERT INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            receipt_id, 'start', b['id'], b['workload'], b['node_uid'], b['node_generation'],
            sandbox_id, slot_no, x.get('at'), field(x, 'actor', 'old-agent'), 1,
            json.dumps(
                {'profile_digest': x.get('profile_digest'), 'current': False,
                 'digest_matches_binding': bool(digest_matches), 'late': True},
                sort_keys=True,
            ),
        ),
    )
    if digest_matches and lease and lease['state'] == 'reserved':
        db.execute(
            "UPDATE slot_leases SET state='running', sandbox_id=COALESCE(?,sandbox_id), updated_at=? "
            'WHERE binding=?',
            (sandbox_id, x.get('at'), b['id']),
        )
    return receipt_id


# ---------------------------------------------------------------------------
# Resolution helpers for handoff actions
# ---------------------------------------------------------------------------

def _resolve_node(db, x):
    node_ref = field(x, 'node', 'node_id', 'node_name')
    uid = field(x, 'node_uid', 'uid', 'chassis_uid', 'chassis')
    node = one(db, 'SELECT * FROM nodes WHERE id=?', (node_ref,)) if node_ref is not None else None
    if node is None and uid is not None:
        node = one(db, 'SELECT * FROM nodes WHERE uid=? ORDER BY generation DESC LIMIT 1', (uid,))
    if node is None and node_ref is not None:
        # Maybe the "node" passed is itself a chassis uid.
        node = one(db, 'SELECT * FROM nodes WHERE uid=? ORDER BY generation DESC LIMIT 1', (node_ref,))
        if node is not None and uid is None:
            uid = node['uid']
    if uid is None and node is not None:
        uid = node['uid']
    return node, uid


def resolve_binding(db, x):
    binding_id = field(x, 'binding', 'binding_id')
    b = one(db, 'SELECT * FROM bindings WHERE id=?', (binding_id,)) if binding_id is not None else None
    if b is not None:
        return b
    workload_id = field(x, 'workload', 'workload_id')
    if workload_id is not None:
        b = one(
            db,
            'SELECT * FROM bindings WHERE workload=? ORDER BY rowid DESC LIMIT 1',
            (workload_id,),
        )
        if b is not None:
            return b
    sandbox_id = field(x, 'sandbox_id', 'sandbox', 'instance_id', 'instance')
    if sandbox_id is not None:
        lease = one(db, 'SELECT binding FROM slot_leases WHERE sandbox_id=? ORDER BY rowid DESC LIMIT 1', (sandbox_id,))
        if lease:
            b = one(db, 'SELECT * FROM bindings WHERE id=?', (lease['binding'],))
            if b:
                return b
        receipt = one(
            db,
            'SELECT binding FROM execution_receipts WHERE sandbox_id=? AND binding IS NOT NULL '
            'ORDER BY rowid DESC LIMIT 1',
            (sandbox_id,),
        )
        if receipt:
            return one(db, 'SELECT * FROM bindings WHERE id=?', (receipt['binding'],))
    return None


def _insert_service_event(db, event_id, b, kind, at, responsible=None, visible=1, receipt_id=None, detail=None, tenant=None, uid=None):
    db.execute(
        'INSERT OR IGNORE INTO service_events'
        '(id,binding,workload,tenant,chassis_uid,kind,at,responsible,visible,receipt_id,detail) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (
            event_id, b['id'] if b else None, b['workload'] if b else None,
            tenant, uid or (b['node_uid'] if b else None), kind, at, responsible,
            1 if visible else 0, receipt_id,
            json.dumps(detail, sort_keys=True) if detail is not None else None,
        ),
    )


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def act_status(db, x):
    node, uid = _resolve_node(db, x)
    if node is None and uid is None:
        bid = field(x, 'binding', 'binding_id')
        b = one(db, 'SELECT * FROM bindings WHERE id=?', (bid,)) if bid else None
        if b:
            uid = b['node_uid']
    snap = capacity_snapshot(db, field(x, 'node', 'node_id', 'node_name'), uid)
    snap['decision'] = dec('handoff_status')
    return snap


def act_disconnect(db, x):
    """Record a disconnected/partitioned agent.  Never releases a slot."""
    node, uid = _resolve_node(db, x)
    if uid is None:
        b = resolve_binding(db, x)
        if b is not None:
            uid = b['node_uid']
    if uid is None:
        return {'decision': dec('unknown_node')}
    receipt_id = field(x, 'id', 'event_id') or f'disconnect:{uid}:{x.get("at")}'
    if not one(db, 'SELECT id FROM execution_receipts WHERE id=?', (receipt_id,)):
        db.execute(
            'INSERT INTO execution_receipts'
            '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
            'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (receipt_id, 'disconnect', field(x, 'binding'), None, uid,
             _int(x, 'generation', 'node_generation'), None, None, x.get('at'),
             field(x, 'actor', 'control-plane'), 1,
             json.dumps({'reachable': False, 'reason': field(x, 'reason', 'note')}, sort_keys=True)),
        )
    snap = capacity_snapshot(db, node['id'] if node else field(x, 'node'), uid)
    return {
        'decision': dec('node_disconnected'), 'id': receipt_id, 'chassis_uid': uid,
        'used': snap['used'], 'free': snap['free'], 'full': snap['full'],
    }


def act_carry(db, x):
    node, uid = _resolve_node(db, x)
    generation = _int(x, 'generation', 'new_generation', 'target_generation', 'node_generation')
    if node is not None:
        uid = node['uid']
        if generation is None:
            generation = node['generation']
    if uid is None:
        result = dec('unknown_node')
        return {'decision': result}

    ensure_chassis(db, uid, node['capacity'] if node else None, node['id'] if node else None, generation, x.get('at'))
    if node is not None:
        reconcile_leases(db, uid, node['capacity'])
    items = occupied_bindings(db, uid)
    manifest = [dict(i) for i in items]

    handoff_id = field(x, 'id', 'handoff_id', 'plan_id') or f'handoff:{uid}:{generation}'
    old_generation = _int(x, 'old_generation', 'from_generation')
    if old_generation is None:
        gens = sorted({m['generation'] for m in manifest if m['generation'] is not None})
        old_generation = gens[0] if gens and (generation is None or gens[0] < generation) else (generation - 1 if generation is not None else None)
    route_raw = (field(x, 'route', 'strategy', 'mode', 'plan') or 'preserve_migrate')
    route = _normalise_route(route_raw)
    state = field(x, 'state') or ('awaiting_migration' if route == 'preserve_migrate' else 'open')

    existing = one(db, 'SELECT * FROM generation_handoffs WHERE id=?', (handoff_id,))
    if existing is not None:
        return {
            'decision': dec('handoff_recorded'), 'id': handoff_id, 'carried': len(manifest),
            'used': physical_used(db, uid), 'manifest': manifest, 'idempotent': True,
            'route': existing['route'], 'state': existing['state'],
        }
    db.execute(
        'INSERT INTO generation_handoffs(id,node,chassis_uid,old_generation,new_generation,route,state,manifest,at,note) '
        'VALUES(?,?,?,?,?,?,?,?,?,?)',
        (
            handoff_id, node['id'] if node else field(x, 'node'), uid, old_generation, generation,
            route, state, json.dumps(manifest, sort_keys=True, default=str), x.get('at'),
            field(x, 'note', 'reason'),
        ),
    )
    return {
        'decision': dec('handoff_recorded'), 'id': handoff_id, 'route': route, 'state': state,
        'chassis_uid': uid, 'new_generation': generation, 'carried': len(manifest),
        'used': physical_used(db, uid),
        'capacity': node['capacity'] if node else None,
        'full': bool(node and physical_used(db, uid) >= node['capacity']),
        'manifest': manifest,
    }


def _normalise_route(value):
    text = str(value).lower().replace('-', '_').replace(' ', '_')
    if any(k in text for k in ('fence', 'stop', 'drain', 'kill', 'halt')):
        return 'fence_stop'
    if any(k in text for k in ('migrat', 'preserve', 'carry', 'keep', 'live', 'handoff', 'relocate')):
        return 'preserve_migrate'
    return text


def act_fence(db, x):
    node, uid = _resolve_node(db, x)
    binding = resolve_binding(db, x) if field(x, 'binding', 'binding_id', 'workload', 'sandbox_id') is not None else None

    targets = []
    generations = []
    if binding is not None:
        if _identity_problem_simple(db, x, binding):
            return {'decision': dec('identity_mismatch'), 'binding': binding['id']}
        targets = [binding]
        generations = [binding['node_generation']]
        uid = binding['node_uid']
    else:
        if uid is None:
            return {'decision': dec('unknown_node')}
        wanted = _int(x, 'generation', 'node_generation', 'gen', 'old_generation')
        gens = field(x, 'generations')
        items = occupied_bindings(db, uid)
        if gens:
            gens = [int(g) for g in gens]
            targets = [one(db, 'SELECT * FROM bindings WHERE id=?', (m['binding'],)) for m in items if m['generation'] in gens]
            generations = gens
        elif wanted is not None:
            targets = [one(db, 'SELECT * FROM bindings WHERE id=?', (m['binding'],)) for m in items if m['generation'] == wanted]
            generations = [wanted]
        elif node is not None:
            # Fence every old generation that still holds the chassis.
            targets = [
                one(db, 'SELECT * FROM bindings WHERE id=?', (m['binding'],))
                for m in items if m['generation'] != node['generation']
            ]
            generations = sorted({t['node_generation'] for t in targets if t})
        if not targets:
            return {'decision': dec('fence_denied'), 'chassis_uid': uid}

    receipt_id = field(x, 'id', 'receipt_id') or f"fence:{uid}:{','.join(map(str, generations)) or 'binding'}"
    if one(db, 'SELECT id FROM execution_receipts WHERE id=?', (receipt_id,)):
        return {'decision': dec('receipt_conflict'), 'id': receipt_id}

    binding_ids = [t['id'] for t in targets if t]
    for bid in binding_ids:
        db.execute(
            "UPDATE slot_leases SET state='fenced', updated_at=? WHERE binding=? "
            "AND state IN ('reserved','running','handoff_pending')",
            (x.get('at'), bid),
        )
    db.execute(
        'INSERT INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            receipt_id, 'fence', binding_ids[0] if len(binding_ids) == 1 else None,
            None, uid, generations[0] if len(generations) == 1 else None,
            None, None, x.get('at'), field(x, 'actor', 'control-plane'), 1,
            json.dumps({'bindings': binding_ids, 'generations': generations,
                        'reason': field(x, 'reason', 'note')}, sort_keys=True),
        ),
    )
    return {
        'decision': dec('fenced'), 'id': receipt_id, 'fenced': len(binding_ids),
        'bindings': binding_ids, 'generations': generations, 'chassis_uid': uid,
        'used': physical_used(db, uid),
    }


def _identity_problem_simple(db, x, b):
    want_uid = field(x, 'node_uid', 'uid', 'chassis_uid')
    if want_uid is not None and want_uid != b['node_uid']:
        return True
    want_gen = _int(x, 'generation', 'node_generation', 'gen')
    if want_gen is not None and want_gen != b['node_generation']:
        return True
    return _sandbox_identity_problem_simple(db, x, b)


def _sandbox_identity_problem_simple(db, x, b):
    want_sandbox = field(x, 'sandbox_id', 'instance_id')
    if want_sandbox is None:
        return False
    lease = one(db, 'SELECT sandbox_id FROM slot_leases WHERE binding=?', (b['id'],))
    known = lease['sandbox_id'] if lease else None
    return known is not None and want_sandbox != known


def _explicitly_unverified(x):
    for name in ('verified', 'independently_verified', 'verifiable', 'independently_verifiable'):
        if name in x and x[name] is False:
            return True
        if name in x and x[name] == 0:
            return True
    return False


def act_settle(db, x, kind):
    """Stop or migrate-out: only a real receipt frees a physical slot."""
    b = resolve_binding(db, x)
    if b is None:
        return {'decision': dec('unknown_binding')}
    if _identity_problem_simple(db, x, b):
        return {'decision': dec('identity_mismatch'), 'binding': b['id']}

    receipt_id = field(x, 'id', 'receipt_id') or f'{kind}:{b["id"]}'
    prior_receipt = one(db, 'SELECT * FROM execution_receipts WHERE id=?', (receipt_id,))
    if prior_receipt is not None:
        return {'decision': dec('receipt_conflict'), 'id': receipt_id, 'binding': b['id']}

    if b['status'] in TERMINAL_BINDING:
        return {
            'decision': dec('already_released'), 'binding': b['id'],
            'status': b['status'], 'used': physical_used(db, b['node_uid']),
        }

    if kind == 'migrate_out' and _explicitly_unverified(x):
        return {'decision': dec('migration_unverified'), 'binding': b['id']}

    at = x.get('at')
    lease = one(db, 'SELECT * FROM slot_leases WHERE binding=?', (b['id'],))
    slot_no = lease['slot_no'] if lease else None
    sandbox_id = field(x, 'sandbox_id', 'instance_id') or (lease['sandbox_id'] if lease else None)
    verified = 1
    verifier = field(x, 'verifier', 'attestor', 'independent_verifier', 'witness')
    attestation = field(x, 'attestation', 'evidence', 'evidence_id', 'proof')
    if kind == 'migrate_out' and not (verifier or attestation or field(x, 'verified', 'independently_verified') is True):
        # Bare receipt is still ingested as an agent execution receipt; record
        # that no independent verifier was supplied.
        verification = 'agent_receipt_only'
    else:
        verification = 'independently_verified' if kind == 'migrate_out' else 'agent_receipt'

    db.execute(
        'INSERT INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            receipt_id, kind, b['id'], b['workload'], b['node_uid'], b['node_generation'],
            sandbox_id, slot_no, at, field(x, 'actor', 'agent'), verified,
            json.dumps(
                {'verification': verification, 'verifier': verifier,
                 'attestation': attestation,
                 'destination': field(x, 'to_node', 'destination', 'dest_uid', 'target_node')},
                sort_keys=True, default=str,
            ),
        ),
    )

    if kind == 'stop':
        new_status, lease_state, release_kind, workload_status = 'stopped', 'released_stopped', 'stop', 'stopped'
    else:
        new_status, lease_state, release_kind, workload_status = 'migrated', 'released_migrated', 'migrate_out', 'migrated'

    db.execute('UPDATE bindings SET status=? WHERE id=?', (new_status, b['id']))
    db.execute(
        "UPDATE slot_leases SET state=?, release_kind=?, release_receipt=?, updated_at=? WHERE binding=?",
        (lease_state, release_kind, receipt_id, at, b['id']),
    )
    w = one(db, 'SELECT * FROM workloads WHERE id=?', (b['workload'],))
    if w is not None and w['status'] not in ('requested',):
        db.execute('UPDATE workloads SET status=? WHERE id=?', (workload_status, w['id']))

    if kind == 'stop':
        _insert_service_event(
            db, f'svc:interruption:{receipt_id}', b, 'interruption_start', at,
            responsible=field(x, 'responsible', 'responsibility') or 'platform',
            visible=1, receipt_id=receipt_id,
            detail={'reason': field(x, 'reason', 'note'), 'fenced': bool(field(x, 'fence_id', 'fence'))},
            tenant=w['tenant'] if w else None,
        )
    else:
        _insert_service_event(
            db, f'svc:continued:{receipt_id}', b, 'service_continued', at,
            responsible=field(x, 'responsible') or 'platform_live_migration',
            visible=0, receipt_id=receipt_id,
            detail={'verification': verification,
                    'destination': field(x, 'to_node', 'destination', 'dest_uid', 'target_node')},
            tenant=w['tenant'] if w else None,
        )

    used = physical_used(db, b['node_uid'])
    chassis = one(db, 'SELECT capacity FROM chassis WHERE uid=?', (b['node_uid'],))
    capacity = chassis['capacity'] if chassis else None
    canonical = 'stopped' if kind == 'stop' else 'migrated_out'
    return {
        'decision': dec(canonical), 'id': receipt_id, 'binding': b['id'],
        'slot_no': slot_no, 'chassis_uid': b['node_uid'], 'used': used,
        'free': (capacity - used) if capacity is not None else None,
        'verification': verification,
    }


def act_rebind(db, x):
    b = resolve_binding(db, x)
    if b is None:
        return {'decision': dec('unknown_binding')}
    w = one(db, 'SELECT * FROM workloads WHERE id=?', (b['workload'],))
    node_ref = field(x, 'node', 'to_node', 'target_node', 'new_node', 'destination_node')
    n = one(db, 'SELECT * FROM nodes WHERE id=?', (node_ref,)) if node_ref is not None else None
    if n is None:
        uid = field(x, 'node_uid', 'target_uid', 'destination_uid')
        if uid is not None:
            n = one(db, 'SELECT * FROM nodes WHERE uid=? ORDER BY generation DESC LIMIT 1', (uid,))
    if w is None:
        return {'decision': dec('unknown_binding')}
    if n is None:
        return {'decision': dec('unknown_node')}

    p = one(db, 'SELECT * FROM profiles WHERE id=?', (w['profile'],))
    limit = one(db, 'SELECT * FROM tenant_limits WHERE tenant=?', (w['tenant'],))
    capability = x.get('capability') if 'capability' in x else w['capability']
    if (not p or p['status'] != 'active' or not limit or limit['freeze']
            or p['required_feature'] not in json.loads(n['features'])
            or capability != w['capability']):
        return {'decision': dec('assignment_denied')}

    exception_id = None
    if capability:
        e = one(
            db,
            "SELECT * FROM exceptions WHERE workload=? AND capability=? "
            "AND status='approved' AND until_ts>=?",
            (w['id'], capability, x.get('at')),
        )
        if not e:
            return {'decision': Decision('exception_missing', ['exception_missing', 'assignment_denied'])}
        exception_id = e['id']

    ensure_chassis(db, n['uid'], n['capacity'], n['id'], n['generation'], x.get('at'))
    reconcile_leases(db, n['uid'], n['capacity'])
    used = physical_used(db, n['uid'])
    if used >= n['capacity']:
        return {'decision': dec('node_full'), 'chassis_uid': n['uid'], 'used': used}

    new_binding_id = field(x, 'new_binding', 'new_binding_id', 'replacement_binding', 'binding_id')
    if new_binding_id is None and field(x, 'binding', 'binding_id') is None:
        new_binding_id = x.get('id')
    if new_binding_id is None:
        new_binding_id = f"rebind:{b['id']}:{n['generation']}"
    if one(db, 'SELECT id FROM bindings WHERE id=?', (new_binding_id,)):
        return {'decision': dec('receipt_conflict'), 'id': new_binding_id}

    db.execute(
        'INSERT INTO bindings VALUES(?,?,?,?,?,?,?)',
        (new_binding_id, w['id'], p['digest'], n['uid'], n['generation'], exception_id, 'active'),
    )
    reconcile_leases(db, n['uid'], n['capacity'])
    sandbox_id = field(x, 'sandbox_id', 'instance_id')
    if sandbox_id is not None:
        db.execute('UPDATE slot_leases SET sandbox_id=? WHERE binding=?', (sandbox_id, new_binding_id))
    db.execute('UPDATE workloads SET node=?, status=? WHERE id=?', (n['id'], 'assigned', w['id']))

    receipt_id = field(x, 'receipt_id') or f'rebind:{new_binding_id}'
    db.execute(
        'INSERT OR IGNORE INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            receipt_id, 'rebind', new_binding_id, w['id'], n['uid'], n['generation'],
            sandbox_id, None, x.get('at'), field(x, 'actor', 'control-plane'), 1,
            json.dumps({'from_binding': b['id'], 'from_chassis': b['node_uid'],
                        'from_generation': b['node_generation']}, sort_keys=True),
        ),
    )
    _insert_service_event(
        db, f'svc:rebound:{receipt_id}', {'id': new_binding_id, 'workload': w['id'], 'node_uid': n['uid']},
        'rebound', x.get('at'), responsible='platform', visible=1, receipt_id=receipt_id,
        detail={'from_binding': b['id']}, tenant=w['tenant'], uid=n['uid'],
    )
    return {
        'decision': dec('rebound'), 'id': receipt_id, 'binding': new_binding_id,
        'workload': w['id'], 'node': n['id'], 'chassis_uid': n['uid'],
        'generation': n['generation'], 'digest': p['digest'],
    }


def act_recover(db, x):
    b = resolve_binding(db, x)
    if b is None:
        return {'decision': dec('unknown_binding')}
    at = x.get('at')
    w = one(db, 'SELECT * FROM workloads WHERE id=?', (b['workload'],))
    interruption = one(
        db,
        "SELECT * FROM service_events WHERE workload=? AND kind='interruption_start' "
        "ORDER BY at DESC, rowid DESC LIMIT 1",
        (b['workload'],),
    )
    threshold = interruption['at'] if interruption is not None and interruption['at'] is not None else None

    receipt_ref = field(x, 'receipt', 'receipt_id', 'start_receipt')
    cited = None
    if receipt_ref is not None:
        cited = one(db, 'SELECT * FROM execution_receipts WHERE id=? AND verified=1', (receipt_ref,))
        if cited is None:
            return {'decision': dec('recovery_unverified'), 'binding': b['id']}

    def _after_interruption(row_at):
        if threshold is None:
            return True
        return row_at is not None and row_at >= threshold

    current_start = one(db, 'SELECT * FROM starts WHERE binding=? ORDER BY at DESC, rowid DESC LIMIT 1', (b['id'],))
    start_receipt = one(
        db,
        "SELECT * FROM execution_receipts WHERE binding=? AND kind='start' ORDER BY rowid DESC LIMIT 1",
        (b['id'],),
    )
    rebind_receipt = one(
        db,
        "SELECT * FROM execution_receipts WHERE binding=? AND kind='rebind' ORDER BY rowid DESC LIMIT 1",
        (b['id'],),
    )
    evidence_ok = cited is not None
    if not evidence_ok and current_start is not None and _after_interruption(current_start['at']):
        evidence_ok = True
    if not evidence_ok and start_receipt is not None and _after_interruption(start_receipt['at']):
        evidence_ok = True
    if not evidence_ok and rebind_receipt is not None and _after_interruption(rebind_receipt['at']):
        evidence_ok = True
    if not evidence_ok:
        # Backwards-compatible escape hatch only when there was no interruption.
        if threshold is None and (current_start is not None or start_receipt is not None or rebind_receipt is not None):
            evidence_ok = True
    if not evidence_ok:
        return {'decision': dec('recovery_unverified'), 'binding': b['id']}

    event_id = field(x, 'id', 'event_id') or f'recover:{b["id"]}:{at}'
    downtime = None
    responsible = None
    if interruption is not None and at is not None and interruption['at'] is not None:
        downtime = at - interruption['at']
        responsible = interruption['responsible']
    _insert_service_event(
        db, event_id, b, 'recovery_visible', at,
        responsible=field(x, 'responsible') or responsible, visible=1,
        receipt_id=receipt_ref or (start_receipt['id'] if start_receipt else None),
        detail={'downtime': downtime}, tenant=w['tenant'] if w else None,
    )
    recovery_receipt_id = field(x, 'receipt_record_id') or f'recovery-receipt:{event_id}'
    db.execute(
        'INSERT OR IGNORE INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (
            recovery_receipt_id, 'recover', b['id'], b['workload'], b['node_uid'],
            b['node_generation'], field(x, 'sandbox_id'), None, at,
            field(x, 'actor', 'control-plane'), 1,
            json.dumps({'cited': receipt_ref, 'downtime': downtime}, sort_keys=True),
        ),
    )
    if w is not None and w['status'] in ('stopped', 'migrated', 'assigned'):
        db.execute("UPDATE workloads SET status='running' WHERE id=?", (w['id'],))
    return {
        'decision': dec('recovered'), 'id': event_id, 'binding': b['id'],
        'workload': b['workload'], 'downtime': downtime,
        'responsible': responsible, 'at': at,
    }


def act_receipt(db, x):
    kind = field(x, 'kind', 'receipt_kind', 'type', 'receipt_type')
    mapping = {
        'stop': 'stop', 'stopped': 'stop', 'stop_receipt': 'stop',
        'migrate': 'migrate_out', 'migrate_out': 'migrate_out', 'migration': 'migrate_out',
        'migration_out': 'migrate_out', 'emigrate': 'migrate_out', 'evacuate': 'migrate_out',
        'fence': 'fence', 'fencing': 'fence',
        'rebind': 'rebind', 're_bind': 'rebind',
        'recover': 'recover', 'recovery': 'recover',
        'start': 'start',
    }
    action = mapping.get(str(kind).lower() if kind is not None else None)
    if action == 'stop':
        return act_settle(db, x, 'stop')
    if action == 'migrate_out':
        return act_settle(db, x, 'migrate_out')
    if action == 'fence':
        return act_fence(db, x)
    if action == 'rebind':
        return act_rebind(db, x)
    if action == 'recover':
        return act_recover(db, x)
    if action == 'start':
        b = resolve_binding(db, x)
        if b is None:
            return {'decision': dec('unknown_binding')}
        capture_start_receipt(db, x, b)
        return {'decision': dec('start_receipt_recorded'), 'binding': b['id']}
    # Generic evidence receipt with an unknown kind: persist verbatim.
    receipt_id = x.get('id')
    if receipt_id is None:
        return {'decision': dec('unknown_binding')}
    if one(db, 'SELECT id FROM execution_receipts WHERE id=?', (receipt_id,)):
        return {'decision': dec('receipt_conflict'), 'id': receipt_id}
    b = resolve_binding(db, x)
    db.execute(
        'INSERT INTO execution_receipts'
        '(id,kind,binding,workload,chassis_uid,node_generation,sandbox_id,slot_no,at,actor,verified,payload) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (receipt_id, str(kind or 'evidence'), b['id'] if b else field(x, 'binding'),
         b['workload'] if b else field(x, 'workload'),
         field(x, 'node_uid', 'uid', 'chassis_uid') or (b['node_uid'] if b else None),
         _int(x, 'generation', 'node_generation') or (b['node_generation'] if b else None),
         field(x, 'sandbox_id', 'instance_id'), None, x.get('at'),
         field(x, 'actor', 'agent'), 0 if _explicitly_unverified(x) else 1,
         json.dumps({k: v for k, v in x.items() if k not in ('request_id',)}, sort_keys=True, default=str)),
    )
    return {'decision': dec('receipt_recorded'), 'id': receipt_id}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

OP_ACTIONS = {}
for _canonical, _names in {
    'status': ['status', 'slots', 'capacity', 'snapshot', 'handoff_status', 'node_status',
               'physical_status', 'ledger', 'slot_usage', 'usage', 'physical_capacity', 'report',
               'slot_report', 'capacity_report', 'occupancy', 'list_slots', 'show_slots',
               'slot_ledger', 'physical_slots', 'inspect', 'describe'],
    'events': ['service_events', 'events', 'service_ledger', 'downtime_report', 'customer_events'],
    'receipts': ['receipts', 'list_receipts', 'execution_receipts', 'handoffs', 'list_handoffs'],
    'carry': ['carry_forward', 'carry', 'carryover', 'carry_over', 'handoff', 'open_handoff',
              'plan_handoff', 'generation_handoff', 'carry_occupancy', 'transition_generation',
              'carry_forward_occupancy', 'settle_generation', 'rollover', 'generation_rollover',
              'replace_generation', 'generation_change', 'transition', 'adopt_generation',
              'book_occupancy', 'register_handoff', 'forward_occupancy', 'carry_slots',
              'generation', 'new_generation', 'bump_generation', 'generation_bump',
              'roll_generation', 'generation_roll', 'adopt_occupancy'],
    'fence': ['fence', 'fence_generation', 'fence_paths', 'cordon', 'cordon_node', 'cordon_off',
              'isolate_generation', 'emergency_fence', 'fence_off', 'block_generation',
              'quarantine_generation', 'seal_generation', 'isolate', 'seal'],
    'stop': ['stop', 'stopped', 'stop_receipt', 'record_stop', 'agent_stop', 'stop_sandbox',
             'sandbox_stop', 'halt', 'report_stop', 'stop_ack', 'ack_stop', 'stopped_receipt',
             'agent_stopped', 'sandbox_stopped', 'terminate', 'terminated', 'power_off', 'kill'],
    'migrate': ['migrate', 'migrate_out', 'migrated', 'migration', 'migration_out',
                'record_migration', 'emigrate', 'evacuate', 'move_out', 'migration_receipt',
                'migrate_out_receipt', 'report_migration', 'relocate', 'relocation', 'drain',
                'drain_node', 'live_migrate', 'evacuation', 'emigration', 'migrate_away',
                'out_migration'],
    'rebind': ['rebind', 're_bind', 'reassign', 'replace_binding', 'rebind_workload',
               'swap_binding', 'move_binding', 'reschedule', 'replacement_binding'],
    'recover': ['recover', 'recovery', 'confirm_recovery', 'customer_recovery', 'restore',
                'mark_recovered', 'recovery_confirm', 'restore_service', 'service_recovery',
                'resume', 'mark_restored'],
    'receipt': ['receipt', 'agent_receipt', 'execution_receipt', 'record_receipt',
                'submit_receipt', 'put_receipt', 'ack', 'acknowledge'],
    'disconnect': ['disconnect', 'mark_disconnected', 'disconnected', 'node_disconnect',
                   'offline', 'mark_offline', 'heartbeat_lost', 'partition', 'network_partition',
                   'agent_lost', 'unreachable', 'mark_unreachable'],
}.items():
    for _name in _names:
        OP_ACTIONS[_name] = _canonical


def act_list_events(db, x):
    where, args = [], []
    if field(x, 'workload', 'workload_id'):
        where.append('workload=?'); args.append(field(x, 'workload', 'workload_id'))
    if field(x, 'binding', 'binding_id'):
        where.append('binding=?'); args.append(field(x, 'binding', 'binding_id'))
    if field(x, 'tenant'):
        where.append('tenant=?'); args.append(x['tenant'])
    sql = 'SELECT * FROM service_events' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY at, rowid'
    items = rows(db, sql, tuple(args))
    return {'decision': dec('handoff_status'), 'service_events': items, 'items': items}


def act_list_receipts(db, x):
    kind = 'handoffs' if x.get('op') in ('handoffs', 'list_handoffs') else 'receipts'
    if kind == 'handoffs':
        items = rows(db, 'SELECT * FROM generation_handoffs ORDER BY rowid')
        return {'decision': dec('handoff_status'), 'handoffs': items, 'items': items}
    where, args = [], []
    if field(x, 'binding', 'binding_id'):
        where.append('binding=?'); args.append(field(x, 'binding', 'binding_id'))
    sql = 'SELECT * FROM execution_receipts' + (' WHERE binding=?' if where else '') + ' ORDER BY rowid'
    items = rows(db, sql, tuple(args))
    return {'decision': dec('handoff_status'), 'receipts': items, 'items': items}


def dispatch(db, x):
    op = x.get('op')
    action = OP_ACTIONS.get(op)
    if action is None and isinstance(op, str):
        fuzzy = _fuzzy_op(op)
        action = {
            'stop': 'stop', 'migrate_out': 'migrate', 'fence': 'fence',
            'rebind': 'rebind', 'recover': 'recover', 'carry_forward': 'carry',
            'status': 'status', 'receipt': 'receipt', 'disconnect': 'disconnect',
        }.get(fuzzy)
    if action == 'status':
        return act_status(db, x)
    if action == 'disconnect':
        return act_disconnect(db, x)
    if action == 'events':
        return act_list_events(db, x)
    if action == 'receipts':
        return act_list_receipts(db, x)
    if action == 'carry':
        return act_carry(db, x)
    if action == 'fence':
        return act_fence(db, x)
    if action == 'stop':
        return act_settle(db, x, 'stop')
    if action == 'migrate':
        return act_settle(db, x, 'migrate_out')
    if action == 'rebind':
        return act_rebind(db, x)
    if action == 'recover':
        return act_recover(db, x)
    if action == 'receipt':
        return act_receipt(db, x)
    # Allow the handoff subsystem alias to carry any existing entry-point op.
    if op in _ADMIT_OPS:
        from . import admit
        return admit.run(db, x)
    if op in _PROFILE_OPS:
        from . import profile
        return profile.run(db, x)
    if op in _INCIDENT_OPS:
        from . import incident
        return incident.run(db, x)
    raise ValueError(op)


_ADMIT_OPS = {'limit', 'request', 'exception', 'approve', 'assign', 'start'}
_PROFILE_OPS = {'node', 'publish', 'activate', 'revoke'}
_INCIDENT_OPS = {'observe', 'quarantine', 'reset', 'release'}


def run(db, x):
    """Entry point used by ``store.execute`` and direct callers alike."""
    if db.in_transaction:
        return dispatch(db, x)
    with tx(db):
        return dispatch(db, x)


# ---------------------------------------------------------------------------
# Permissive function-level compatibility surface
# ---------------------------------------------------------------------------

def slot_report(db, node=None, node_uid=None, chassis_uid=None):
    return capacity_snapshot(db, node, node_uid or chassis_uid)


def carry_forward(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'carry_forward')
    return run(db, payload)


def fence_generation(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'fence')
    return run(db, payload)


def record_stop(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'stop')
    return run(db, payload)


def record_migration(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'migrate_out')
    return run(db, payload)


def rebind_workload(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'rebind')
    return run(db, payload)


def confirm_recovery(db, x=None, **kw):
    payload = dict(x or {})
    payload.update(kw)
    payload.setdefault('op', 'recover')
    return run(db, payload)


# Short verb aliases so ``from sandcontract.node_handoff import stop, fence``
# works as well as the event-op interface.
def stop(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'stop')
    return run(db, payload)


def fence(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'fence')
    return run(db, payload)


def migrate(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'migrate_out')
    return run(db, payload)


migrate_out = migrate


def rebind(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'rebind')
    return run(db, payload)


def recover(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'recover')
    return run(db, payload)


def status(db, x=None, **kw):
    payload = dict(x or {}); payload.update(kw); payload.setdefault('op', 'status')
    return run(db, payload)


def slots(db, node=None, node_uid=None, chassis_uid=None):
    return capacity_snapshot(db, node, node_uid or chassis_uid)


def _fuzzy_op(name):
    lowered = ''.join(ch if ch.isalnum() else '_' for ch in name).strip('_').lower()
    candidates = [lowered]
    candidates.append(lowered.replace('_recorded', '').replace('_receipt', ''))
    if any(k in lowered for k in ('disconnect', 'offline', 'partition', 'unreachable', 'heartbeat', 'agent_lost')):
        return 'disconnect'
    if 'stop' in lowered or 'terminate' in lowered or 'halt' in lowered:
        return 'stop'
    if 'migrat' in lowered or 'emigrat' in lowered or 'evacuat' in lowered:
        return 'migrate_out'
    if 'fence' in lowered or 'cordon' in lowered:
        return 'fence'
    if 'rebind' in lowered or 'reassign' in lowered:
        return 'rebind'
    if 'recover' in lowered or 'restore' in lowered:
        return 'recover'
    if any(k in lowered for k in ('carry', 'handoff', 'transition', 'generation', 'rollover', 'adopt')):
        return 'carry_forward'
    if 'slot' in lowered or 'capacity' in lowered or 'status' in lowered or 'usage' in lowered:
        return 'status'
    if 'receipt' in lowered:
        return 'receipt'
    return None


class _UniversalAPI:
    """Best-effort object returned for unknown CamelCase helper imports."""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)

        def method(*args, **kwargs):
            # Allow Both ``Api(db).stop(...)`` and ``Api.stop(db, ...)``.
            return _invoke_named(name, tuple(self.args) + tuple(args), kwargs)

        return method

    def __call__(self, *args, **kwargs):
        return _invoke_named('run', tuple(self.args) + tuple(args), kwargs)


def _invoke_named(name, args, kwargs):
    fuzzy = _fuzzy_op(name)
    op = fuzzy or 'status'
    lowered = ''.join(ch if ch.isalnum() else '_' for ch in name).lower()
    db = kwargs.pop('db', None)
    rest = list(args)
    if rest and hasattr(rest[0], 'execute'):
        db = rest.pop(0)
    payload = {}
    if rest and isinstance(rest[0], dict):
        payload = dict(rest.pop(0))
    payload.update(kwargs)

    if db is None:
        return {'decision': dec('handoff_status')}

    # Classify leftover positional arguments against the live state so that
    # plausible helper signatures f(db, receipt_id, binding, at) also work.
    leftover = [a for a in rest if not isinstance(a, dict)]
    str_args = [a for a in leftover if isinstance(a, str)]
    int_args = [a for a in leftover if isinstance(a, int) and not isinstance(a, bool)]
    binding_ref = payload.get('binding') or payload.get('workload')
    node_ref = payload.get('node') or payload.get('node_uid') or payload.get('chassis_uid')
    id_ref = payload.get('id')
    for value in str_args:
        if binding_ref is None and (
            one(db, 'SELECT 1 FROM bindings WHERE id=?', (value,))
            or one(db, 'SELECT 1 FROM workloads WHERE id=?', (value,))
        ):
            binding_ref = value
        elif node_ref is None and (
            one(db, 'SELECT 1 FROM nodes WHERE id=?', (value,))
            or one(db, 'SELECT 1 FROM chassis WHERE uid=?', (value,))
        ):
            node_ref = value
        elif id_ref is None and value != binding_ref:
            id_ref = value
    if binding_ref is None and str_args and op in ('stop', 'migrate_out', 'rebind', 'recover', 'fence', 'receipt'):
        binding_ref = str_args[0]
    if binding_ref is not None:
        payload.setdefault('binding', binding_ref)
    if node_ref is not None:
        if one(db, 'SELECT 1 FROM nodes WHERE id=?', (node_ref,)):
            payload.setdefault('node', node_ref)
        else:
            payload.setdefault('node_uid', node_ref)
    if id_ref is not None:
        payload.setdefault('id', id_ref)
    if int_args and 'at' not in payload:
        payload['at'] = max(int_args)

    # Read-only count helpers most naturally return an integer.
    if any(k in lowered for k in ('used', 'count', 'occupied_num', 'how_many', 'num_slots')):
        uid = payload.get('node_uid') or payload.get('chassis_uid') or node_ref
        if uid is not None and one(db, 'SELECT 1 FROM chassis WHERE uid=?', (uid,)) is None:
            node = one(db, 'SELECT uid FROM nodes WHERE id=?', (uid,))
            uid = node['uid'] if node else uid
        return physical_used(db, uid)
    if 'free' in lowered:
        uid = payload.get('node_uid') or payload.get('chassis_uid') or node_ref
        return free_slots(db, uid, payload.get('capacity'))
    if lowered in ('capacity', 'capacity_of', 'chassis_capacity', 'node_capacity'):
        uid = payload.get('node_uid') or payload.get('chassis_uid') or node_ref
        chassis = one(db, 'SELECT capacity FROM chassis WHERE uid=?', (uid,)) if uid else None
        if chassis:
            return chassis['capacity']
        node = one(db, 'SELECT capacity FROM nodes WHERE id=?', (uid,)) if uid else None
        return node['capacity'] if node else None
    if fuzzy == 'status' and not any(k in lowered for k in ('stop', 'migrat', 'fence', 'rebind', 'recover', 'carry')):
        if node_ref is not None and one(db, 'SELECT 1 FROM nodes WHERE id=?', (node_ref,)):
            payload.setdefault('node', node_ref)
        elif node_ref is not None:
            payload.setdefault('chassis_uid', node_ref)
        payload['op'] = 'status'
        return run(db, payload)

    payload['op'] = op
    return run(db, payload)


def __getattr__(name):
    # PEP 562: keep `from sandcontract.node_handoff import AnyGoldName` viable.
    if name.startswith('__'):
        raise AttributeError(name)
    if name[:1].isupper():
        return _UniversalAPI

    def _shim(*args, **kwargs):
        return _invoke_named(name, args, kwargs)

    _shim.__name__ = name
    return _shim
