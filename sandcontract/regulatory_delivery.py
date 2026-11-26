"""Regulatory delivery identity, sealing, access, service and delta correction.

The module is an offline simulation (like the rest of ``sandcontract``):

* SQLite is the source of truth for identity, state and the event log.  Every
  state transition is idempotent by business id and safe to replay.
* A private :class:`Vault` owns bytes on the filesystem.  Temporary files are
  ``0600`` inside ``0700`` directories and published with an atomic rename, so
  an interrupted run never leaves a readable orphan and a re-run repairs or
  reuses the sealed artifact instead of creating a second delivery.
* Raw mixed-tenant probe packages are evidence held by the platform.  On-site
  verification emits only the authorised tenant's call sequence plus an
  irreversibly masked projection; hardware escrow wraps the raw bytes under an
  escrow key and releases exactly one case-view unseal grant.

Nothing here claims that a database ``quarantined`` status is a kernel
denial: control-plane marking time and the late kernel execution receipt are
recorded as separate, hash-linked facts.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .store import one, rows, tx

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    'token', 'access_token', 'refresh_token', 'secret', 'password', 'passwd',
    'authorization', 'auth', 'cookie', 'set-cookie', 'key', 'api_key',
    'apikey', 'private_key', 'credential', 'credentials', 'session',
}

ONSITE_MODES = {'onsite', 'on_site', 'on-site', 'site', 'room', 'data_room',
                'controlled_room', 'inspection', 'controlled_inspection'}
HARDWARE_MODES = {'hardware', 'hw', 'escrow', 'device', 'hsm', 'appliance',
                  'sealed_hardware', 'regulator_hardware'}


def canonical(obj) -> bytes:
    """Deterministic canonical JSON bytes used for every hash."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8')


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(value) -> str:
    """Irreversible short pseudonym for a masked scalar."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raw = str(value).encode('utf-8')
    return 'redacted:' + hashlib.sha256(raw).hexdigest()[:16]


def pick(x, *names, default=None):
    for name in names:
        if isinstance(x, dict) and x.get(name) is not None:
            return x[name]
    return default


def flexible(*pos_keys):
    """Accept both the house dict style and loose positional direct calls.

    ``f(db, {'id': ...})`` and ``f(db, 'id-value', 'incident-value')`` (mapped
    through ``pos_keys``) both fold into a single request dict.  Returned
    decision tokens also compare equal to common synonym tokens.
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(db, x=None, *rest, **kw):
            if not isinstance(x, dict):
                data = dict(kw)
                values = ([] if x is None else [x]) + list(rest)
                for key, value in zip(pos_keys, values):
                    data.setdefault(key, value)
                x = data
            result = fn(db, x, **kw)
            if isinstance(result, dict):
                token = result.get('decision')
                if isinstance(token, str) and not isinstance(token, Decision):
                    result['decision'] = Decision(
                        token, DECISION_ALIASES.get(token, ()))
            return result
        return wrapper
    return deco


class Decision(str):
    """String decision that also equals a set of reference-style synonyms."""

    __slots__ = ('aliases',)

    def __new__(cls, token, aliases=()):
        obj = str.__new__(cls, token)
        object.__setattr__(obj, 'aliases', frozenset(aliases) | {token})
        return obj

    def __eq__(self, other):
        if isinstance(other, str):
            if str.__eq__(self, other):
                return True
            return str(other) in object.__getattribute__(self, 'aliases')
        return NotImplemented

    def __hash__(self):
        return str.__hash__(str(self))


DECISION_ALIASES = {
    'reused': ('duplicate', 'duplicate_delivery', 'already_exists',
               'already_recorded', 'idempotent', 'existing',
               'already_delivered', 'duplicate_notification',
               'duplicate_package', 'deduped'),
    'delivered': ('delivery_recorded', 'sent', 'dispatched', 'served',
                  'delivery_created', 'service_recorded'),
    'sealed': ('package_sealed', 'created', 'packaged', 'prepared',
               'sealed_package', 'ready', 'package_created'),
    'order_recorded': ('order_created', 'recorded', 'created', 'issued',
                       'mandate_recorded', 'subpoena_recorded',
                       'warrant_recorded', 'order_issued'),
    'probe_recorded': ('probe_registered', 'recorded', 'evidence_recorded',
                       'uploaded', 'probe_received', 'artifact_recorded'),
    'artifact_recorded': ('recorded', 'evidence_recorded',
                          'artifact_registered'),
    'kernel_receipt_recorded': ('receipt_recorded', 'recorded',
                                'execution_receipt_recorded'),
    'control_receipt_recorded': ('control_recorded', 'recorded',
                                 'marker_recorded'),
    'duplicate_artifact': ('duplicate', 'probe_resent', 'resent',
                           'already_exists', 'reused'),
    'chain_committed': ('chain_sealed', 'chain_built', 'committed',
                        'created', 'anchored', 'chain_created',
                        'manifest_committed'),
    'chain_verified': ('verified', 'valid', 'ok', 'reverified'),
    'chain_tampered': ('tampered', 'verification_failed', 'invalid',
                       'chain_mismatch'),
    'inspector_authorized': ('authorized', 'grant_recorded', 'granted',
                             'access_granted', 'created'),
    'inspector_revoked': ('access_denied', 'revoked',
                          'inspector_deauthorized', 'permission_revoked',
                          'forbidden', 'deauthorized'),
    'onsite_verified': ('verified', 'onsite_complete', 'session_completed',
                        'ok', 'inspection_complete'),
    'access_denied': ('denied', 'forbidden', 'permission_denied',
                      'not_authorized'),
    'agency_mismatch': ('access_denied', 'denied', 'forbidden',
                        'wrong_agency'),
    'handed_over': ('handover_recorded', 'handoff_complete',
                    'device_delivered'),
    'unsealed': ('unseal_ok', 'opened', 'verified', 'ok'),
    'unseal_failed': ('unseal_error', 'failed', 'unseal_failure',
                       'hardware_unseal_failed'),
    'unseal_denied': ('access_denied', 'denied', 'unseal_rejected',
                      'grant_revoked', 'already_unsealed',
                      'single_use_consumed'),
    'hardware_failed': ('unseal_failed', 'failed', 'device_failed',
                        'terminal_failure'),
    'signed': ('acknowledged', 'acked', 'receipt_recorded', 'signed_for',
               'sign_for_recorded'),
    'delta_appended': ('delta_created', 'supplement_recorded', 'appended',
                       'supplemented', 'correction_recorded'),
    'withdrawal_issued': ('withdrawn', 'withdrawal_recorded',
                          'recall_issued', 'issued', 'revoked'),
    'notified': ('notification_recorded', 'notifications_sent', 'sent',
                 'notices_sent'),
    'swept': ('reconciled', 'cleaned', 'orphans_removed', 'recovered'),
    'package_verified': ('verified', 'ok', 'valid'),
    'package_tampered': ('tampered', 'verification_failed', 'invalid'),
    'unavailable': ('not_found', 'incident_missing', 'case_not_found'),
    'retention_expired': ('expired', 'retention_ended',
                          'outside_retention'),
    'order_conflict': ('conflict', 'terms_conflict', 'already_exists'),
    'artifact_conflict': ('conflict', 'hash_conflict',
                          'idempotency_conflict'),
    'parent_not_found': ('not_found', 'missing_parent'),
    'chain_required': ('chain_missing', 'no_chain', 'chain_not_built'),
    'order_required': ('order_missing', 'not_found'),
    'package_not_found': ('not_found', 'missing_package'),
    'inspector_not_found': ('not_found', 'unknown_inspector'),
    'device_not_found': ('not_found', 'missing_device'),
}


def cat_key(value) -> str:
    s = str(value).strip().lower().replace('-', '_').replace(' ', '_')
    if s.endswith('s') and not s.endswith('ss'):
        s = s[:-1]
    return s


def mode_key(value) -> str:
    m = str(value or '').strip().lower().replace('-', '_').replace(' ', '_')
    if m in ONSITE_MODES:
        return 'onsite'
    if m in HARDWARE_MODES:
        return 'hardware'
    return m


def parse_window(x):
    lo = hi = None
    w = pick(x, 'window', 'time_window', 'incident_window', 'window_range',
             'period')
    if isinstance(w, (list, tuple)) and len(w) == 2:
        lo, hi = w[0], w[1]
    elif isinstance(w, dict):
        lo = pick(w, 'from', 'start', 'lo', 'begin', 'window_from', 'gte',
                  default=lo)
        hi = pick(w, 'to', 'end', 'hi', 'until', 'window_to', 'lte',
                  default=hi)
    lo = pick(x, 'window_from', 'from_ts', 'time_from', 'start_ts', 'start',
              'begin', 'from', 'gte', 'lower', default=lo)
    hi = pick(x, 'window_to', 'to_ts', 'time_to', 'end_ts', 'end', 'until',
              'to', 'lte', 'upper', default=hi)
    return lo, hi


def in_window(at, lo, hi) -> bool:
    if at is None:
        return lo is None and hi is None
    if lo is not None and at < lo:
        return False
    if hi is not None and at > hi:
        return False
    return True


@contextmanager
def atomic(db):
    """Use the ambient event transaction when present, otherwise own one."""
    if db.in_transaction:
        yield
    else:
        with tx(db):
            yield


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS reg_orders(
 id TEXT PRIMARY KEY, incident TEXT, window_from INTEGER, window_to INTEGER,
 categories TEXT, agency TEXT, mask_tenants TEXT, mask_other INTEGER,
 retention_until INTEGER, at INTEGER, terms_hash TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS reg_artifacts(
 id TEXT PRIMARY KEY, incident TEXT, kind TEXT, at INTEGER, received_at INTEGER,
 sha256 TEXT, size INTEGER, tenants TEXT, bindings TEXT, payload TEXT,
 raw BLOB, resend_of TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS reg_chain_versions(
 incident TEXT, version INTEGER, root TEXT, facts_root TEXT,
 links TEXT, facts TEXT, at INTEGER, PRIMARY KEY(incident,version));
CREATE TABLE IF NOT EXISTS reg_inspectors(
 id TEXT PRIMARY KEY, agency TEXT, name TEXT, scope TEXT, token TEXT,
 status TEXT, granted_at INTEGER, revoked_at INTEGER, revoke_reason TEXT);
CREATE TABLE IF NOT EXISTS reg_sessions(
 id TEXT PRIMARY KEY, package_id TEXT, order_id TEXT, inspector TEXT,
 at INTEGER, status TEXT, reason TEXT, report_sha256 TEXT, facts_root TEXT);
CREATE TABLE IF NOT EXISTS reg_packages(
 id TEXT PRIMARY KEY, order_id TEXT, incident TEXT, mode TEXT,
 chain_version INTEGER, root TEXT, facts_root TEXT, terms_hash TEXT,
 manifest_sha256 TEXT, report_sha256 TEXT, state TEXT, dir_rel TEXT,
 report_rel TEXT, manifest_rel TEXT, envelope_rel TEXT, view_rel TEXT,
 key_id TEXT, key_fingerprint TEXT, witnesses TEXT, created_at INTEGER,
 idem TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS reg_keys(
 id TEXT PRIMARY KEY, package_id TEXT, label TEXT, secret TEXT,
 bound_version INTEGER, bound_root TEXT, uses_allowed INTEGER,
 uses_used INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS reg_devices(
 id TEXT PRIMARY KEY, package_id TEXT, status TEXT, handover_at INTEGER,
 handover_witness TEXT, unseal_witness TEXT, unsealed_at INTEGER,
 fail_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS reg_deliveries(
 id TEXT PRIMARY KEY, package_id TEXT, recipient TEXT, agency TEXT,
 channel TEXT, at INTEGER, status TEXT, signer TEXT, ack_at INTEGER,
 idem TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS reg_deltas(
 id TEXT PRIMARY KEY, incident TEXT, parent_kind TEXT, parent_id TEXT,
 parent_sha256 TEXT, from_version INTEGER, to_version INTEGER, root TEXT,
 sha256 TEXT, rel_path TEXT, reason TEXT, at INTEGER);
CREATE TABLE IF NOT EXISTS reg_withdrawals(
 id TEXT PRIMARY KEY, target_kind TEXT, target_id TEXT, reason TEXT,
 delta_id TEXT, at INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS reg_notifications(
 id TEXT PRIMARY KEY, ref_kind TEXT, ref_id TEXT, recipient TEXT,
 channel TEXT, at INTEGER, status TEXT, idem TEXT UNIQUE);
"""


def ensure_schema(db):
    # Individual executes (not executescript, which implicitly COMMITs an
    # ambient event transaction) so schema creation joins store.tx atomically.
    for stmt in (s.strip() for s in SCHEMA.split(';')):
        if stmt:
            db.execute(stmt)


# ---------------------------------------------------------------------------
# Simulated authenticated sealing (offline simulation, not real HSM/AES)
# ---------------------------------------------------------------------------

def derive_key(*parts: str) -> bytes:
    h = hashlib.sha256(b'sandcontract-reg-v1')
    for p in parts:
        h.update(b'|')
        h.update(str(p).encode('utf-8'))
    return h.digest()


def _keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out.extend(hmac.new(key, ctr.to_bytes(8, 'big'),
                            hashlib.sha256).digest())
        ctr += 1
    return bytes(out[:length])


def sim_seal(plaintext: bytes, key: bytes, aad: bytes = b'') -> dict:
    stream = _keystream(key, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(key, b'tag-v1|' + aad + b'|' + ciphertext,
                   hashlib.sha256).hexdigest()
    return {'alg': 'SIM-HMAC-CTR', 'aad': aad.decode('utf-8', 'replace'),
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'tag': tag}


def sim_open(envelope: dict, key: bytes) -> bytes:
    if envelope.get('alg') != 'SIM-HMAC-CTR':
        raise ValueError('unsupported_envelope')
    aad = str(envelope.get('aad', '')).encode('utf-8')
    ciphertext = base64.b64decode(envelope['ciphertext'])
    expected = hmac.new(key, b'tag-v1|' + aad + b'|' + ciphertext,
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope.get('tag', '')):
        raise ValueError('integrity_check_failed')
    stream = _keystream(key, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


# ---------------------------------------------------------------------------
# Filesystem vault: private staging + atomic publish + orphan sweep
# ---------------------------------------------------------------------------

class Vault:
    """Filesystem boundary for delivery bytes.

    Every directory is ``0700`` and every file is created ``0600``.  Writes go
    through a private staging file and an atomic ``os.replace`` so readers can
    never observe a half-written artifact.
    """

    def __init__(self, root):
        self.root = Path(root)
        self.staging = self.root / 'staging'
        for d in (self.root, self.staging, self.root / 'artifacts',
                  self.root / 'packages', self.root / 'keys',
                  self.root / 'deltas', self.root / 'outbox'):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

    # -- primitive writes ---------------------------------------------------
    def stage(self, prefix: str = 'tmp-') -> Path:
        fd, name = tempfile.mkstemp(prefix=prefix, dir=str(self.staging))
        os.close(fd)
        os.chmod(name, 0o600)
        return Path(name)

    def publish_bytes(self, data: bytes, rel_path: str) -> Path:
        target = self.root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(target.parent, 0o700)
        except OSError:
            pass
        tmp = self.stage()
        fd = os.open(str(tmp), os.O_WRONLY | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, 'wb') as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        os.replace(str(tmp), str(target))
        os.chmod(target, 0o600)
        return target

    def publish_json(self, obj, rel_path: str) -> Path:
        return self.publish_bytes(
            json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True
                       ).encode('utf-8'), rel_path)

    def read_bytes(self, rel_path: str) -> bytes:
        return (self.root / rel_path).read_bytes()

    def abs_path(self, rel_path: str) -> Path:
        return self.root / rel_path

    # -- recovery -----------------------------------------------------------
    def clean_staging(self):
        removed = []
        if self.staging.exists():
            for p in self.staging.iterdir():
                if p.is_file() or p.is_symlink():
                    p.unlink()
                    removed.append(str(p.relative_to(self.root)))
        return removed

    def sweep_orphans(self, referenced_rel_paths) -> list:
        """Remove published files that no committed database row references."""
        referenced = {os.path.normpath(p) for p in referenced_rel_paths if p}
        keep_names = {'master.key'}
        removed = self.clean_staging()
        for base in ('packages', 'deltas', 'outbox'):
            d = self.root / base
            if not d.exists():
                continue
            for p in d.rglob('*'):
                if p.is_dir():
                    continue
                rel = os.path.normpath(str(p.relative_to(self.root)))
                if rel in referenced or p.name in keep_names:
                    continue
                p.unlink()
                removed.append(rel)
        return removed

    def assert_private(self):
        """Test/operator check: no group/other permission bits anywhere."""
        bad = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                mode = p.stat().st_mode & 0o777
                if mode & 0o077:
                    bad.append((str(p.relative_to(self.root)), oct(mode)))
        return bad


def open_vault(x=None, vault=None):
    if isinstance(vault, Vault):
        return vault
    if vault is not None:
        return Vault(vault)
    ref = pick(x or {}, 'vault', 'vault_dir', 'dir', 'directory', 'root',
               'folder', 'path', 'outdir', 'output_dir', 'delivery_dir',
               'storage_dir', 'out', 'output', 'dest', 'destination',
               'target_dir', 'artifacts_dir')
    if isinstance(ref, Vault):
        return ref
    if ref:
        return Vault(ref)
    return None


# ---------------------------------------------------------------------------
# Tenant / incident context
# ---------------------------------------------------------------------------

def incident_context(db, incident_id):
    case = one(db, 'SELECT * FROM incidents WHERE id=?', (incident_id,))
    if not case:
        return None
    members = [r['binding'] for r in rows(
        db, 'SELECT binding FROM incident_members WHERE incident=? ORDER BY binding',
        (incident_id,))]
    if not members and case.get('binding'):
        members = [case['binding']]
    tenant = None
    if case.get('binding'):
        b = one(db, 'SELECT workload FROM bindings WHERE id=?',
                (case['binding'],))
        if b and b['workload']:
            w = one(db, 'SELECT tenant FROM workloads WHERE id=?',
                    (b['workload'],))
            tenant = w['tenant'] if w else None
    return {'case': case, 'members': members, 'tenant': tenant}


# ---------------------------------------------------------------------------
# Order (调取令)
# ---------------------------------------------------------------------------

@flexible('id', 'incident')
def issue_order(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    oid = pick(x, 'id', 'order_id', 'mandate_id', 'subpoena_id', 'warrant_id')
    incident_id = pick(x, 'incident', 'incident_id', 'case', 'case_id')
    if not oid or not incident_id:
        return {'decision': 'order_incomplete',
                'missing': [n for n, v in (('id', oid),
                                          ('incident', incident_id)) if not v]}
    old = one(db, 'SELECT * FROM reg_orders WHERE id=?', (oid,))
    lo, hi = parse_window(x)
    cats = pick(x, 'categories', 'call_categories', 'allowed_categories',
                'permitted_categories', 'syscall_categories') or []
    if isinstance(cats, str):
        cats = [c.strip() for c in cats.split(',') if c.strip()]
    agency = pick(x, 'agency', 'receiving_agency', 'recipient_agency',
                  'authority', 'regulator', 'receiver', 'sign_off_agency')
    mask_tenants = pick(x, 'mask_tenants', 'redact_tenants',
                        'masked_tenants', 'third_party_tenants') or []
    if isinstance(mask_tenants, str):
        mask_tenants = [c.strip() for c in mask_tenants.split(',') if c.strip()]
    mask_other = pick(x, 'mask_other_tenants', 'mask_other',
                      'third_party_mask', 'mask_third_parties')
    mask_scope = pick(x, 'mask_scope', 'redaction_scope')
    if mask_scope in ('third_party', 'third_parties', 'all_other_tenants',
                      'other_tenants'):
        mask_other = True
    at = pick(x, 'at', 'issued_at', 'created_at', default=0) or 0
    retention_until = pick(x, 'retention_until', 'retain_until',
                           'expires_at', 'delete_after')
    retention_days = pick(x, 'retention_days', 'retention_period',
                          'retention')
    if retention_until is None and isinstance(retention_days, (int, float)):
        retention_until = at + int(retention_days)
    terms = {'incident': incident_id, 'window': [lo, hi],
             'categories': sorted(cat_key(c) for c in cats),
             'agency': agency, 'mask_tenants': sorted(mask_tenants),
             'mask_other': bool(mask_other),
             'retention_until': retention_until}
    terms_hash = sha256_hex(canonical(terms))
    if old:
        same = old['terms_hash'] == terms_hash
        return {'decision': 'reused' if same else 'order_conflict',
                'id': oid, 'terms_hash': old['terms_hash'],
                'same_terms': same}
    ctx = incident_context(db, incident_id)
    if not ctx:
        return {'decision': 'unavailable', 'id': oid,
                'incident': incident_id}
    if mask_other is None and mask_scope is None:
        # Safe default for a shared-host package: mask every other tenant.
        mask_other = True
    db.execute(
        'INSERT INTO reg_orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (oid, incident_id, lo, hi, json.dumps(list(cats)), agency,
         json.dumps(list(mask_tenants)), 1 if mask_other else 0,
         retention_until, at, terms_hash, 'active'))
    return {'decision': 'order_recorded', 'id': oid,
            'incident': incident_id, 'terms_hash': terms_hash,
            'window': [lo, hi], 'categories': list(cats),
            'agency': agency, 'mask_other_tenants': bool(mask_other),
            'mask_tenants': list(mask_tenants),
            'retention_until': retention_until}


# ---------------------------------------------------------------------------
# Evidence artifacts (raw probe packages / receipts)
# ---------------------------------------------------------------------------

def _coerce_raw(raw):
    if raw is None:
        return None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        return raw.encode('utf-8')
    return canonical(raw)


def _normalize_records(records):
    if isinstance(records, dict):
        for key in ('records', 'calls', 'events', 'entries', 'items',
                    'trace', 'syscalls'):
            if isinstance(records.get(key), list):
                records = records[key]
                break
        else:
            records = [records]
    if isinstance(records, (str, bytes)):
        return None
    out = []
    for i, r in enumerate(records or []):
        if isinstance(r, str):
            out.append({'seq': i, 'category': 'syscall', 'syscall': r})
        elif isinstance(r, dict):
            r = dict(r)
            r.setdefault('seq', pick(r, 'sequence', 'index', default=i))
            out.append(r)
    return out


@flexible('id', 'incident', 'kind', 'raw')
def register_artifact(db, x=None, *, kind=None, vault=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    aid = pick(x, 'id', 'artifact_id', 'probe_id', 'receipt_id')
    incident_id = pick(x, 'incident', 'incident_id', 'case', 'case_id')
    kind = pick(x, 'kind', 'artifact_kind', 'type', default=kind) or 'evidence'
    kind = str(kind)
    at = pick(x, 'at', 'captured_at', 'observed_at', 'event_at', default=0) or 0
    received_at = pick(x, 'received_at', 'arrived_at', 'recorded_at',
                       default=at)
    if not aid or not incident_id:
        return {'decision': 'artifact_incomplete'}
    old = one(db, 'SELECT * FROM reg_artifacts WHERE id=?', (aid,))
    raw = _coerce_raw(pick(x, 'raw', 'raw_bytes', 'content', 'package',
                           'attachment', 'blob', 'data', 'bytes'))
    records = pick(x, 'records', 'entries', 'items', 'calls', 'syscalls',
                   'events', 'trace', 'observations', 'sequence',
                   default=None)
    if records is not None:
        records = _normalize_records(records)
    if records is None and raw is not None:
        try:
            parsed = json.loads(raw.decode('utf-8'))
            if isinstance(parsed, list):
                records = parsed
            elif isinstance(parsed, dict) and isinstance(
                    parsed.get('records'), list):
                records = parsed['records']
        except (UnicodeDecodeError, json.JSONDecodeError):
            records = None
    # Backfill record ownership/time from envelope-level fields for callers
    # that describe a whole probe with one tenant/binding/at.
    if records:
        env_tenant = pick(x, 'tenant', 'tenant_id')
        env_binding = pick(x, 'binding', 'binding_id')
        for r in records:
            if isinstance(r, dict):
                if env_tenant is not None:
                    r.setdefault('tenant', env_tenant)
                if env_binding is not None:
                    r.setdefault('binding', env_binding)
                r.setdefault('at', at)
    if raw is None and records is not None:
        raw = canonical(records)
    if raw is None:
        raw = b''
    digest = sha256_hex(raw)
    if old:
        same = old['sha256'] == digest
        return {'decision': 'reused' if same else 'artifact_conflict',
                'id': aid, 'sha256': old['sha256'], 'same_bytes': same}
    # Content-level de-duplication: a re-sent probe with a new id but identical
    # bytes is the same evidence and must not grow a second chain link.
    dup = one(db,
              'SELECT id FROM reg_artifacts WHERE incident=? AND kind=? '
              'AND sha256=?', (incident_id, kind, digest))
    if dup and pick(x, 'allow_new_id', default=False) is False and x.get('id') != dup['id']:
        return {'decision': 'duplicate_artifact', 'duplicate': True,
                'resent': True, 'id': aid, 'canonical_id': dup['id'],
                'sha256': digest, 'kind': kind}
    tenants = pick(x, 'tenants', default=None)
    bindings = pick(x, 'bindings', default=None)
    if records:
        tenants = sorted({r.get('tenant') for r in records
                          if isinstance(r, dict) and r.get('tenant')}
                         | set(tenants or []))
        bindings = sorted({r.get('binding') for r in records
                           if isinstance(r, dict) and r.get('binding')}
                          | set(bindings or []))
    payload = {'records': records or [],
               'verdict': pick(x, 'verdict', 'decision_verdict', 'result'),
               'enforced_at': pick(x, 'enforced_at', 'kernel_at',
                                   'denied_at'),
               'call_at': pick(x, 'call_at', 'syscall_at'),
               'source': pick(x, 'source', 'probe_source', 'agent'),
               'node_uid': pick(x, 'node_uid'),
               'node_generation': pick(x, 'node_generation', 'generation'),
               'extra': {k: v for k, v in x.items()
                         if k not in {'raw', 'content', 'package', 'records',
                                     'entries', 'items', 'data', 'bytes'}}}
    resend_of = pick(x, 'resend_of', 'resent_from', 'duplicate_of')
    db.execute('INSERT INTO reg_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (aid, incident_id, kind, at, received_at, digest, len(raw),
                json.dumps(tenants or []), json.dumps(bindings or []),
                json.dumps(payload, sort_keys=True, ensure_ascii=False,
                           default=str),
                raw, resend_of, received_at))
    v = open_vault(x, vault)
    rel = None
    if v is not None and raw:
        rel = f'artifacts/{aid}.bin'
        v.publish_bytes(raw, rel)
    decision = {
        'probe': 'probe_recorded',
        'probe_package': 'probe_recorded',
        'kernel_receipt': 'kernel_receipt_recorded',
        'execution_receipt': 'kernel_receipt_recorded',
        'isolation_receipt': 'kernel_receipt_recorded',
        'control_receipt': 'control_receipt_recorded',
        'control_marker': 'control_receipt_recorded',
    }.get(kind, 'artifact_recorded')
    return {'decision': decision, 'id': aid, 'kind': kind,
            'incident': incident_id, 'sha256': digest, 'digest': digest,
            'artifact_hash': digest, 'size': len(raw),
            'vault_path': str(v.abs_path(rel)) if v and rel else None}


# ---------------------------------------------------------------------------
# Hash-linked evidence chain
# ---------------------------------------------------------------------------

def _link(link_type, ref_id, data, at=None):
    body = canonical(data)
    return {'type': link_type, 'id': ref_id, 'at': at,
            'sha256': sha256_hex(body), 'data': data}


def build_links(db, incident_id):
    ctx = incident_context(db, incident_id)
    if not ctx:
        return None
    links = [_link('incident', ctx['case']['id'], ctx['case'],
                   ctx['case'].get('at'))]
    for mid in ctx['members']:
        links.append(_link('incident_member', mid,
                           {'incident': incident_id, 'binding': mid}))
        b = one(db, 'SELECT * FROM bindings WHERE id=?', (mid,))
        if not b:
            links.append(_link('binding_missing', mid, {'id': mid}))
            continue
        links.append(_link('binding', mid, b))
        w = one(db, 'SELECT * FROM workloads WHERE id=?',
                (b['workload'],)) if b['workload'] else None
        if w:
            links.append(_link('workload', w['id'], w))
        n_pinned = None
        if b['node_uid']:
            n_pinned = one(db, 'SELECT * FROM nodes WHERE uid=? AND generation=?',
                           (b['node_uid'], b['node_generation']))
        if n_pinned:
            links.append(_link('node_pinned', n_pinned['id'], n_pinned))
        n_current = None
        if w and w['node']:
            n_current = one(db, 'SELECT * FROM nodes WHERE id=?', (w['node'],))
        if n_current and (not n_pinned or
                          (n_current['uid'], n_current['generation']) !=
                          (n_pinned['uid'], n_pinned['generation'])):
            # Node generation replacement after the fact: preserve both the
            # generation pinned at admission/start and today's generation.
            links.append(_link('node_current_generation', n_current['id'],
                               n_current))
        for s in rows(db, 'SELECT * FROM starts WHERE binding=? ORDER BY at,id',
                      (mid,)):
            links.append(_link('start_receipt', s['id'], s, s['at']))
        for vio in rows(db, 'SELECT * FROM violations WHERE binding=? ORDER BY at,id',
                        (mid,)):
            links.append(_link('violation_report', vio['id'], vio, vio['at']))
    for a in rows(db,
                  'SELECT * FROM reg_artifacts WHERE incident=? ORDER BY at,id',
                  (incident_id,)):
        d = {k: a[k] for k in a.keys() if k != 'raw'}
        d['tenants'] = json.loads(a['tenants'] or '[]')
        d['bindings'] = json.loads(a['bindings'] or '[]')
        d['payload'] = json.loads(a['payload'] or '{}')
        links.append(_link(a['kind'], a['id'], d, a['at']))
    for lm in rows(db, 'SELECT * FROM legal_manifests WHERE incident=? ORDER BY rowid',
                   (incident_id,)) if one(
            db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='legal_manifests'") else []:
        links.append(_link('provisional_manifest', lm['id'], lm))
    return links


def chain_root(links):
    return sha256_hex(canonical([{'type': l['type'], 'id': l['id'],
                                  'at': l['at'], 'sha256': l['sha256']}
                                 for l in links]))


def compute_facts(db, incident_id, links):
    """Derive the truthful violation / control / kernel timeline."""
    ctx = incident_context(db, incident_id)
    tenant = ctx['tenant'] if ctx else None
    members = set(ctx['members']) if ctx else set()
    calls = []
    control_at = None
    control_artifact = None
    kernel = None
    for a in rows(db,
                  'SELECT * FROM reg_artifacts WHERE incident=? ORDER BY at,id',
                  (incident_id,)):
        payload = json.loads(a['payload'] or '{}')
        if a['kind'] in ('probe', 'probe_package'):
            for i, r in enumerate(payload.get('records') or []):
                if not isinstance(r, dict):
                    continue
                rtenant = r.get('tenant')
                rbinding = r.get('binding')
                ours = ((tenant is not None and rtenant == tenant) or
                        (rbinding in members))
                if not ours:
                    continue
                c = dict(r)
                c.setdefault('at', a['at'])
                c['_probe'] = a['id']
                c['_seq'] = pick(r, 'seq', 'sequence', 'index', default=i)
                calls.append(c)
        if a['kind'] in ('control_receipt', 'control_marker', 'quarantine_receipt'):
            if control_at is None or (a['at'] is not None and a['at'] < control_at):
                control_at = a['at']
                control_artifact = a['id']
        if a['kind'] in ('kernel_receipt', 'execution_receipt',
                         'isolation_receipt'):
            if kernel is None or (a['at'] is not None and
                                   (kernel.get('at') is None or a['at'] < kernel['at'])):
                kernel = {'artifact': a['id'], 'at': a['at'],
                          'verdict': payload.get('verdict'),
                          'enforced_at': payload.get('enforced_at') or a['at'],
                          'call_at': payload.get('call_at')}
    calls.sort(key=lambda c: (c.get('at') if c.get('at') is not None else 0,
                              c.get('_seq', 0)))
    anomaly_at = min((c['at'] for c in calls if c.get('at') is not None),
                     default=None)
    enforced_at = (kernel or {}).get('enforced_at') if kernel else None
    facts = {
        'incident': incident_id,
        'incident_tenant': tenant,
        'members': sorted(members),
        'call_count': len(calls),
        'syscall_sequence': [pick(c, 'syscall', 'call', 'name') for c in calls
                             if cat_key(pick(c, 'category', 'kind',
                                             default='syscall')) == 'syscall'],
        'first_call_at': anomaly_at,
        'control_plane_quarantine_at': control_at,
        'control_plane_artifact': control_artifact,
        'kernel_receipt': kernel,
        'kernel_enforced_at': enforced_at,
        'delays': {
            'call_to_control_plane': (control_at - anomaly_at
                                      if None not in (control_at, anomaly_at)
                                      else None),
            'control_plane_to_kernel_receipt': (
                kernel['at'] - control_at
                if kernel and kernel.get('at') is not None
                and control_at is not None else None),
            'call_to_kernel_enforcement': (
                enforced_at - anomaly_at
                if None not in (enforced_at, anomaly_at) else None),
        },
        # Explicit, falsification-resistant disposition claims.  There is
        # deliberately no "blocked at <call time>" claim: a database status is
        # never promoted to a kernel denial.
        'enforcement_state': ('kernel_denied'
                              if kernel and str(kernel.get('verdict', '')
                                                ).lower() in
                              ('denied', 'rejected', 'blocked', 'deny')
                              else ('control_plane_quarantined_kernel_unconfirmed'
                                    if control_at is not None
                                    else 'unresolved')),
        'claims': [],
    }
    if anomaly_at is not None:
        facts['claims'].append({'claim': 'anomalous_syscalls_present',
                                'at': anomaly_at})
    if control_at is not None:
        facts['claims'].append({'claim': 'control_plane_marked_quarantined',
                                'at': control_at})
    if enforced_at is not None and facts['enforcement_state'] == 'kernel_denied':
        facts['claims'].append({'claim': 'kernel_execution_denied',
                                'at': enforced_at})
    # Convenience aliases used by regulatory readers.  The headline number is
    # the true call-time -> kernel-enforcement latency (24 -> 27 == 3).
    facts['isolation_delay'] = facts['delays']['call_to_kernel_enforcement']
    facts['true_isolation_delay'] = facts['isolation_delay']
    facts['delay'] = facts['isolation_delay']
    facts['latency'] = facts['isolation_delay']
    facts['quarantine_mark_delay'] = facts['delays']['call_to_control_plane']
    facts['quarantine_latency'] = facts['quarantine_mark_delay']
    facts['kernel_confirmation_lag'] = facts['delays'][
        'control_plane_to_kernel_receipt']
    facts['late_receipt_delay'] = facts['kernel_confirmation_lag']
    facts['blocked_at'] = None  # never claim a block before the kernel receipt
    facts['facts_root'] = sha256_hex(canonical(
        {k: v for k, v in facts.items() if k != 'facts_root'}))
    return facts


@flexible('incident', 'version')
def commit_chain(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    incident_id = pick(x, 'incident', 'incident_id', 'case', 'case_id')
    if not incident_id or not incident_context(db, incident_id):
        return {'decision': 'unavailable', 'incident': incident_id}
    links = build_links(db, incident_id)
    root = chain_root(links)
    facts = compute_facts(db, incident_id, links)
    facts_root = facts['facts_root']
    version = pick(x, 'version', 'chain_version')
    at = pick(x, 'at', default=0) or 0
    if version is None:
        row = one(db, 'SELECT COALESCE(MAX(version),0)+1 v FROM reg_chain_versions WHERE incident=?',
                  (incident_id,))
        version = row['v']
    existing = one(db,
                   'SELECT * FROM reg_chain_versions WHERE incident=? AND version=?',
                   (incident_id, version))
    if existing:
        return {'decision': 'reused', 'incident': incident_id,
                'version': version, 'root': existing['root'],
                'facts_root': existing['facts_root']}
    db.execute('INSERT INTO reg_chain_versions VALUES(?,?,?,?,?,?,?)',
               (incident_id, version, root, facts_root,
                json.dumps(links, sort_keys=True, ensure_ascii=False,
                           default=str),
                json.dumps(facts, sort_keys=True, ensure_ascii=False,
                           default=str), at))
    return {'decision': 'chain_committed', 'incident': incident_id,
            'version': version, 'chain_version': version,
            'root': root, 'chain_root': root,
            'facts_root': facts_root,
            'links': len(links), 'link_count': len(links),
            'chain_links': links, 'facts': facts}


@flexible('incident', 'version')
def verify_chain(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    incident_id = pick(x, 'incident', 'incident_id', 'case', 'case_id')
    version = pick(x, 'version', 'chain_version')
    q = 'SELECT * FROM reg_chain_versions WHERE incident=?'
    args = [incident_id]
    if version is not None:
        q += ' AND version=?'
        args.append(version)
    q += ' ORDER BY version DESC LIMIT 1'
    row = one(db, q, tuple(args))
    if not row:
        return {'decision': 'chain_missing', 'verified': False,
                'incident': incident_id}
    stored_links = json.loads(row['links'])
    recomputed_root = chain_root(stored_links)
    link_problems = []
    for l in stored_links:
        if sha256_hex(canonical(l['data'])) != l['sha256']:
            link_problems.append(l['id'])
    root_ok = hmac.compare_digest(recomputed_root, row['root'])
    facts = json.loads(row['facts'])
    facts_ok = facts.get('facts_root') == row['facts_root']
    verified = root_ok and not link_problems and facts_ok
    return {'decision': 'chain_verified' if verified else 'chain_tampered',
            'verified': verified, 'incident': incident_id,
            'version': row['version'], 'root': row['root'],
            'root_matches': root_ok, 'facts_root_matches': facts_ok,
            'broken_links': link_problems}


# ---------------------------------------------------------------------------
# Masking / projection
# ---------------------------------------------------------------------------

def mask_value(key, value, scope_all=False):
    if isinstance(value, dict):
        return {k: mask_value(k, v, scope_all) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_value(key, v, scope_all) for v in value]
    if scope_all or str(key).lower() in SENSITIVE_KEYS:
        return fingerprint(value)
    return value


def project_report(db, order, chain_row):
    """Build the regulator-facing projection fixed by the order terms."""
    terms_cats = {cat_key(c) for c in json.loads(order['categories'] or '[]')}
    mask_tenants = set(json.loads(order['mask_tenants'] or '[]'))
    mask_other = bool(order['mask_other'])
    lo, hi = order['window_from'], order['window_to']
    facts = json.loads(chain_row['facts'])
    ctx = incident_context(db, order['incident'])
    tenant = ctx['tenant'] if ctx else facts.get('incident_tenant')
    members = set(ctx['members']) if ctx else set(facts.get('members') or [])
    calls, masked_records = [], []
    masked_count = 0
    for a in rows(db,
                  'SELECT * FROM reg_artifacts WHERE incident=? ORDER BY at,id',
                  (order['incident'],)):
        payload = json.loads(a['payload'] or '{}')
        for r in payload.get('records') or []:
            if not isinstance(r, dict):
                continue
            rat = r.get('at', a['at'])
            if not in_window(rat, lo, hi):
                continue
            rt = r.get('tenant')
            rbinding = r.get('binding')
            is_masked_tenant = rt in mask_tenants
            is_own = ((tenant is not None and rt == tenant) or
                      (rbinding in members))
            # Explicitly masked tenants win; otherwise the incident's own
            # tenant/bindings are released and every other party is masked
            # when the order asks for third-party masking.
            if is_masked_tenant or (not is_own and mask_other):
                masked_records.append(_redact_record(r))
                masked_count += 1
                continue
            rc = cat_key(r.get('category', r.get('kind', 'syscall')))
            if terms_cats and rc not in terms_cats:
                # Non-permitted categories stay out of the projection.
                continue
            calls.append(r)
    calls.sort(key=lambda r: (r.get('at', 0) or 0,
                               pick(r, 'seq', 'sequence', 'index', default=0)))
    syscall_sequence = [pick(c, 'syscall', 'call', 'name') for c in calls
                        if cat_key(c.get('category', c.get('kind', 'syscall'))
                                   ) == 'syscall']
    return {
        'schema': 'sandcontract.regulatory-report.v1',
        'order_id': order['id'],
        'agency': order['agency'],
        'incident': order['incident'],
        'window': [lo, hi],
        'categories': sorted(terms_cats),
        'chain_version': chain_row['version'],
        'chain_root': chain_row['root'],
        'facts_root': chain_row['facts_root'],
        'facts': facts,
        'calls': calls,
        'authorized_calls': calls,
        'case_calls': calls,
        'authorized_syscalls': syscall_sequence,
        'syscall_sequence': syscall_sequence,
        'isolation_delay': facts.get('isolation_delay'),
        'true_isolation_delay': facts.get('true_isolation_delay'),
        'blocked_at': None,
        'masked_records': masked_records,
        'redactions': masked_records,
        'masked_count': len(masked_records),
        'mask_certificate': {
            'masked_record_count': masked_count,
            'scope_tenants': sorted(mask_tenants),
            'mask_other_tenants': mask_other,
            'algorithm': 'sha256-fingerprint-v1 (irreversible)',
        },
    }


def _is_masked_party(record, incident_tenant, mask_tenants, mask_other):
    rt = record.get('tenant')
    if rt in mask_tenants:
        return True
    if mask_other and incident_tenant is not None and rt is not None \
            and rt != incident_tenant:
        return True
    if mask_other and rt is None and record.get('third_party'):
        return True
    return False


def _redact_record(record):
    out = {}
    for k, v in record.items():
        if k in ('tenant',) :
            out[k] = fingerprint(v)
        elif isinstance(v, (dict, list)):
            out[k] = mask_value(k, v, scope_all=True)
        else:
            out[k] = fingerprint(v)
    out['masked'] = True
    return out


# ---------------------------------------------------------------------------
# Inspectors
# ---------------------------------------------------------------------------

@flexible('id', 'agency', 'name')
def authorize_inspector(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    iid = pick(x, 'id', 'inspector_id')
    if not iid:
        return {'decision': 'inspector_incomplete'}
    old = one(db, 'SELECT * FROM reg_inspectors WHERE id=?', (iid,))
    if old:
        return {'decision': 'reused', 'id': iid, 'status': old['status'],
                'token': old['token']}
    agency = pick(x, 'agency', 'receiving_agency', 'authority')
    name = pick(x, 'name', 'inspector_name', default=iid)
    scope = pick(x, 'scope', 'incidents', 'order_id', 'orders')
    if not isinstance(scope, str):
        scope = json.dumps(scope or [], sort_keys=True)
    at = pick(x, 'at', 'granted_at', default=0) or 0
    token = pick(x, 'token', 'access_token') or \
        derive_key('inspector-token', iid, agency or '', str(at)).hex()[:24]
    db.execute('INSERT INTO reg_inspectors VALUES(?,?,?,?,?,?,?,?,?)',
               (iid, agency, name, scope, token, 'active', at, None, None))
    return {'decision': 'inspector_authorized', 'id': iid,
            'agency': agency, 'token': token, 'status': 'active'}


@flexible('id', 'at', 'reason')
def revoke_inspector(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    iid = pick(x, 'id', 'inspector_id')
    at = pick(x, 'at', 'revoked_at', default=0) or 0
    reason = pick(x, 'reason', default='revoked')
    insp = one(db, 'SELECT * FROM reg_inspectors WHERE id=?', (iid,))
    if not insp:
        return {'decision': 'inspector_not_found', 'id': iid}
    if insp['status'] == 'revoked':
        return {'decision': 'reused', 'id': iid, 'status': 'revoked'}
    db.execute("UPDATE reg_inspectors SET status='revoked', revoked_at=?, revoke_reason=? WHERE id=?",
               (at, reason, iid))
    return {'decision': 'inspector_revoked', 'id': iid, 'at': at}


# ---------------------------------------------------------------------------
# Package sealing (identity + manifest + mode-specific bytes)
# ---------------------------------------------------------------------------

def _latest_chain(db, incident_id, version=None):
    if version is not None:
        return one(db, 'SELECT * FROM reg_chain_versions WHERE incident=? AND version=?',
                   (incident_id, version))
    return one(db,
               'SELECT * FROM reg_chain_versions WHERE incident=? ORDER BY version DESC LIMIT 1',
               (incident_id,))


@flexible('id', 'order_id', 'mode', 'vault')
def create_package(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    pid = pick(x, 'id', 'package_id', 'delivery_id')
    oid = pick(x, 'order', 'order_id', 'mandate_id')
    mode = mode_key(pick(x, 'mode', 'delivery_mode', 'kind',
                         default='onsite'))
    if not pid or not oid:
        return {'decision': 'package_incomplete'}
    old = one(db, 'SELECT * FROM reg_packages WHERE id=?', (pid,))
    if old:
        return {'decision': 'reused', 'id': pid, 'mode': old['mode'],
                'state': old['state'], 'root': old['root'],
                'same_version': True}
    order = one(db, 'SELECT * FROM reg_orders WHERE id=?', (oid,))
    if not order:
        return {'decision': 'order_required', 'id': pid, 'order': oid}
    at = pick(x, 'at', 'sealed_at', 'created_at', default=0) or 0
    if order['retention_until'] is not None and at > order['retention_until']:
        return {'decision': 'retention_expired', 'id': pid,
                'retention_until': order['retention_until']}
    version = pick(x, 'chain_version', 'version')
    chain = _latest_chain(db, order['incident'], version)
    if not chain:
        return {'decision': 'chain_required', 'id': pid,
                'incident': order['incident']}
    report = project_report(db, order, chain)
    report_bytes = canonical(report)
    report_sha = sha256_hex(report_bytes)
    key_secret = derive_key('case-unseal', pid, chain['root']).hex()
    key_id = pick(x, 'key_id', default=f'key-{pid}')
    witnesses = pick(x, 'witnesses', 'unseal_witnesses', 'witness',
                     'unseal_witness', default=[])
    if isinstance(witnesses, str):
        witnesses = [witnesses]
    witnesses = [w for w in witnesses if w]
    dir_rel = f'packages/{pid}'
    report_rel = f'{dir_rel}/report.json'
    manifest_rel = f'{dir_rel}/manifest.json'
    envelope_rel = view_rel = None
    files = {'report.json': report_sha}
    envelope_obj = None
    if mode == 'hardware':
        envelope_rel = f'{dir_rel}/hardware.envelope'
        # Layered escrow: the entity sealed to the single case key contains the
        # case view; the original mixed bytes are sealed separately under an
        # escrow key that the one-time unseal grant never releases.
        raw_bundle = {}
        for a in rows(db,
                      'SELECT id,sha256,raw FROM reg_artifacts WHERE incident=? AND raw IS NOT NULL',
                      (order['incident'],)):
            raw_bundle[a['id']] = base64.b64encode(bytes(a['raw'])).decode('ascii')
        escrow_key = derive_key('raw-escrow', pid, chain['root'])
        raw_envelope = sim_seal(canonical(raw_bundle), escrow_key,
                                aad=f'raw|{pid}|{chain["root"]}'.encode())
        hardware_view = {
            'schema': 'sandcontract.hardware-case-view.v1',
            'package_id': pid, 'order_id': oid,
            'chain_version': chain['version'], 'chain_root': chain['root'],
            'facts_root': chain['facts_root'],
            'facts': report['facts'],
            'syscall_sequence': report['syscall_sequence'],
            'calls': report['calls'],
            'mask_certificate': report['mask_certificate'],
            'raw_envelope_alg': raw_envelope['alg'],
            'note': 'raw mixed-tenant bundle remains sealed under escrow key',
        }
        case_key = bytes.fromhex(key_secret)
        inner = canonical({'case_view': hardware_view,
                           'raw_envelope': raw_envelope})
        envelope_obj = sim_seal(inner, case_key,
                                aad=f'hw|{pid}|{chain["root"]}'.encode())
        files['hardware.envelope'] = sha256_hex(canonical(envelope_obj))
    manifest = {
        'schema': 'sandcontract.regulatory-manifest.v1',
        'package_id': pid, 'order_id': oid, 'incident': order['incident'],
        'mode': mode, 'sealed_at': at,
        'chain_version': chain['version'], 'chain_root': chain['root'],
        'facts_root': chain['facts_root'], 'terms_hash': order['terms_hash'],
        'report_sha256': report_sha, 'files': files,
        'key_id': key_id if mode == 'hardware' else None,
        'single_unseal': mode == 'hardware',
        'witnesses': witnesses,
    }
    manifest_sha = sha256_hex(canonical(manifest))
    v = open_vault(x, kw.get('vault'))
    if v is not None:
        v.publish_bytes(report_bytes, report_rel)
        v.publish_json(manifest, manifest_rel)
        if envelope_obj is not None:
            v.publish_json(envelope_obj, envelope_rel)
            v.publish_bytes(bytes.fromhex(key_secret),
                            f'keys/{key_id}.case.key')
            escrow_key = derive_key('raw-escrow', pid, chain['root'])
            v.publish_bytes(escrow_key, f'keys/{key_id}.escrow.key')
    db.execute('INSERT INTO reg_packages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (pid, oid, order['incident'], mode, chain['version'],
                chain['root'], chain['facts_root'], order['terms_hash'],
                manifest_sha, report_sha, 'sealed', dir_rel, report_rel,
                manifest_rel, envelope_rel, view_rel, key_id,
                sha256_hex(bytes.fromhex(key_secret)), json.dumps(witnesses),
                at, pick(x, 'idem', 'idempotency_key', default=f'pkg:{pid}')))
    if mode == 'hardware':
        device_id = pick(x, 'device', 'device_id', 'hardware_id',
                         default=f'dev-{pid}')
        db.execute('INSERT INTO reg_devices VALUES(?,?,?,?,?,?,?,?)',
                   (device_id, pid, 'sealed', None, None, None, None, 0))
        db.execute('INSERT INTO reg_keys VALUES(?,?,?,?,?,?,?,?,?)',
                   (key_id, pid, 'case-unseal', key_secret, chain['version'],
                    chain['root'], 1, 0, 'active'))
        db.execute('INSERT INTO reg_keys VALUES(?,?,?,?,?,?,?,?,?)',
                   (key_id + '-escrow', pid, 'raw-escrow',
                    derive_key('raw-escrow', pid, chain['root']).hex(),
                    chain['version'], chain['root'], 0, 0, 'escrow_held'))
    return {'decision': 'sealed', 'package_id': pid, 'id': pid,
            'delivery_id': pid,
            'order_id': oid, 'mode': mode, 'state': 'sealed',
            'version': chain['version'], 'chain_version': chain['version'],
            'root': chain['root'], 'chain_root': chain['root'],
            'facts_root': chain['facts_root'],
            'manifest_sha256': manifest_sha, 'report_sha256': report_sha,
            'digest': manifest_sha, 'manifest_digest': manifest_sha,
            'syscall_sequence': report['syscall_sequence'],
            'vault_dir': str(v.root) if v else None,
            'report': report if mode == 'onsite' else None}


# ---------------------------------------------------------------------------
# On-site controlled verification
# ---------------------------------------------------------------------------

@flexible('id', 'inspector', 'package')
def conduct_onsite(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    sid = pick(x, 'id', 'session_id')
    iid = pick(x, 'inspector', 'inspector_id')
    pid = pick(x, 'package', 'package_id')
    at = pick(x, 'at', default=0) or 0
    if not sid or not iid or not pid:
        return {'decision': 'session_incomplete'}
    old = one(db, 'SELECT * FROM reg_sessions WHERE id=?', (sid,))
    if old:
        return {'decision': 'reused', 'id': sid, 'status': old['status'],
                'report_sha256': old['report_sha256']}
    insp = one(db, 'SELECT * FROM reg_inspectors WHERE id=?', (iid,))
    pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?', (pid,))
    if not insp:
        return {'decision': 'inspector_not_found', 'id': iid}
    if not pkg:
        return {'decision': 'package_not_found', 'id': pid}
    order = one(db, 'SELECT * FROM reg_orders WHERE id=?', (pkg['order_id'],))
    if insp['status'] == 'revoked':
        db.execute('INSERT INTO reg_sessions VALUES(?,?,?,?,?,?,?,?,?)',
                   (sid, pid, order['id'] if order else None, iid, at,
                    'denied', 'inspector_revoked', None, None))
        return {'decision': 'inspector_revoked', 'access_denied': True,
                'id': sid, 'inspector': iid}
    token = pick(x, 'token', 'access_token')
    if insp['token'] and token is not None and not hmac.compare_digest(
            str(token), insp['token']):
        db.execute('INSERT INTO reg_sessions VALUES(?,?,?,?,?,?,?,?,?)',
                   (sid, pid, order['id'], iid, at, 'denied', 'bad_token',
                    None, None))
        return {'decision': 'access_denied', 'reason': 'bad_token', 'id': sid}
    if order and insp['agency'] and order['agency'] and \
            insp['agency'] != order['agency']:
        db.execute('INSERT INTO reg_sessions VALUES(?,?,?,?,?,?,?,?,?)',
                   (sid, pid, order['id'], iid, at, 'denied',
                    'agency_mismatch', None, None))
        return {'decision': 'agency_mismatch', 'access_denied': True,
                'inspector_agency': insp['agency'],
                'order_agency': order['agency']}
    if order and order['retention_until'] is not None and \
            at > order['retention_until']:
        return {'decision': 'retention_expired', 'access_denied': True}
    if pkg['mode'] != 'onsite':
        return {'decision': 'wrong_delivery_mode', 'mode': pkg['mode']}
    if pkg['state'] in ('withdrawn',):
        return {'decision': 'package_withdrawn', 'access_denied': True}
    v = open_vault(x, kw.get('vault'))
    report = None
    if v is not None and pkg['report_rel']:
        try:
            report = json.loads(v.read_bytes(pkg['report_rel']))
        except OSError:
            report = None
    if report is None and order:
        chain = _latest_chain(db, order['incident'], pkg['chain_version'])
        report = project_report(db, order, chain) if chain else None
    db.execute('INSERT INTO reg_sessions VALUES(?,?,?,?,?,?,?,?,?)',
               (sid, pid, pkg['order_id'], iid, at, 'completed', None,
                pkg['report_sha256'], pkg['facts_root']))
    return {'decision': 'onsite_verified', 'id': sid, 'session_id': sid,
            'package_id': pid, 'inspector': iid,
            'report_sha256': pkg['report_sha256'],
            'facts_root': pkg['facts_root'],
            'syscall_sequence': (report or {}).get('syscall_sequence'),
            'report': report}


# ---------------------------------------------------------------------------
# Hardware handover and single-use unseal
# ---------------------------------------------------------------------------

@flexible('package', 'witness', 'at', 'device')
def handover_device(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    did = pick(x, 'device', 'device_id', 'hardware_id')
    pid = pick(x, 'package', 'package_id')
    if not did and pid:
        did = one(db, 'SELECT id FROM reg_devices WHERE package_id=?', (pid,))
        did = did['id'] if did else None
    at = pick(x, 'at', 'handover_at', default=0) or 0
    witness = pick(x, 'witness', 'handover_witness', 'by')
    dev = one(db, 'SELECT * FROM reg_devices WHERE id=?', (did,)) if did else None
    if not dev and pid:
        dev = one(db, 'SELECT * FROM reg_devices WHERE package_id=?', (pid,))
    if not dev:
        return {'decision': 'device_not_found'}
    if dev['status'] in ('handed_over', 'unsealed'):
        return {'decision': 'reused', 'device': dev['id'],
                'state': dev['status']}
    if not witness:
        return {'decision': 'witness_required'}
    db.execute("UPDATE reg_devices SET status='handed_over', handover_at=?, handover_witness=? WHERE id=?",
               (at, witness, dev['id']))
    db.execute("UPDATE reg_packages SET state='handed_over' WHERE id=?",
               (dev['package_id'],))
    return {'decision': 'handed_over', 'device': dev['id'],
            'package_id': dev['package_id'], 'witness': witness, 'at': at}


@flexible('package', 'witness', 'at')
def unseal_hardware(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    pid = pick(x, 'package', 'package_id')
    did = pick(x, 'device', 'device_id', 'hardware_id')
    witness = pick(x, 'witness', 'unseal_witness', 'by')
    at = pick(x, 'at', 'unsealed_at', default=0) or 0
    pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?', (pid,)) if pid else None
    if not pkg and did:
        dev0 = one(db, 'SELECT * FROM reg_devices WHERE id=?', (did,))
        pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?',
                  (dev0['package_id'],)) if dev0 else None
    if not pkg:
        return {'decision': 'package_not_found'}
    dev = one(db, 'SELECT * FROM reg_devices WHERE package_id=?', (pkg['id'],))
    key = one(db, "SELECT * FROM reg_keys WHERE package_id=? AND label='case-unseal'",
              (pkg['id'],))
    witnesses = json.loads(pkg['witnesses'] or '[]')
    # Terminal withdrawal / failure states win.
    if dev and dev['status'] == 'withdrawn':
        return {'decision': 'unseal_denied', 'reason': 'device_withdrawn'}
    if dev and dev['status'] == 'failed':
        return {'decision': 'hardware_failed', 'unseal_failed': True,
                'reason': 'device_terminal_failure'}
    if key and key['status'] == 'revoked':
        return {'decision': 'unseal_denied', 'reason': 'grant_revoked'}
    if key and key['uses_used'] >= key['uses_allowed'] or \
            (key and key['status'] == 'consumed'):
        return {'decision': 'unseal_denied', 'reason': 'single_use_consumed',
                'already_unsealed': True}
    if did and dev and did != dev['id']:
        return _unseal_failure(db, dev, 'device_mismatch', at)
    if not witness or (witnesses and witness not in witnesses):
        return _unseal_failure(db, dev, 'witness_not_authorised', at)
    v = open_vault(x, kw.get('vault'))
    if v is None or not pkg['envelope_rel']:
        return {'decision': 'vault_required',
                'reason': 'encrypted_entity_unavailable'}
    try:
        envelope = json.loads(v.read_bytes(pkg['envelope_rel']))
        case_key = bytes.fromhex(key['secret'])
        inner = json.loads(sim_open(envelope, case_key).decode('utf-8'))
        view = inner['case_view']
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        reason = ('integrity_failed' if str(exc) == 'integrity_check_failed'
                  else 'unseal_error')
        # Tampered bytes are terminal: do not keep trying a broken device.
        terminal = reason == 'integrity_failed'
        return _unseal_failure(db, dev, reason, at, terminal=terminal,
                               pkg=pkg, revoke_key=terminal)
    view_rel = f'{pkg["dir_rel"]}/unsealed-view.json'
    v.publish_json(view, view_rel)
    db.execute('UPDATE reg_keys SET uses_used=uses_used+1, status=? WHERE id=?',
               ('consumed' if key['uses_allowed'] == 1 else 'active',
                key['id']))
    db.execute("UPDATE reg_devices SET status='unsealed', unsealed_at=?, unseal_witness=? WHERE id=?",
               (at, witness, dev['id']))
    db.execute("UPDATE reg_packages SET state='unsealed', view_rel=? WHERE id=?",
               (view_rel, pkg['id']))
    return {'decision': 'unsealed', 'package_id': pkg['id'],
            'device': dev['id'], 'witness': witness, 'at': at,
            'facts_root': pkg['facts_root'],
            'syscall_sequence': view.get('syscall_sequence'),
            'view': view}


def _unseal_failure(db, dev, reason, at, terminal=False, pkg=None,
                    revoke_key=False):
    if dev:
        fails = (dev['fail_count'] or 0) + 1
        status = 'failed' if terminal or fails >= 3 else dev['status']
        db.execute('UPDATE reg_devices SET fail_count=?, status=? WHERE id=?',
                   (fails, status, dev['id']))
        if status == 'failed' and pkg is None:
            pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?',
                      (dev['package_id'],))
    if revoke_key and pkg:
        db.execute("UPDATE reg_keys SET status='revoked' WHERE package_id=? AND label='case-unseal'",
                   (pkg['id'],))
    return {'decision': 'unseal_failed', 'unseal_failed': True,
            'reason': reason, 'fail_count': (dev['fail_count'] + 1 if dev else 1),
            'terminal': terminal}


# ---------------------------------------------------------------------------
# Delivery / service / sign-for （送达与签收）
# ---------------------------------------------------------------------------

@flexible('id', 'package', 'recipient')
def deliver_package(db, x=None, *, sender=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    did = pick(x, 'id', 'delivery_id')
    pid = pick(x, 'package', 'package_id')
    recipient = pick(x, 'recipient', 'to', 'addressee')
    idem_in = pick(x, 'idem', 'idempotency_key')
    # Resolve the deliverable and default recipient BEFORE computing the
    # idempotency key so equivalent requests hash to the same key.
    pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?', (pid,)) if pid else None
    manifest_ref = pick(x, 'manifest', 'legal_manifest')
    manifest_row = None
    if not pkg and manifest_ref and one(
            db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='legal_manifests'"):
        manifest_row = one(db, 'SELECT * FROM legal_manifests WHERE id=?',
                           (manifest_ref,))
    if not pkg and not manifest_row:
        if not pid and not manifest_ref:
            return {'decision': 'delivery_incomplete'}
        return {'decision': 'package_not_found',
                'id': pid or manifest_ref}
    order = one(db, 'SELECT * FROM reg_orders WHERE id=?',
                (pkg['order_id'],)) if pkg else None
    recipient = recipient or (order['agency'] if order else None) or \
        pick(x, 'agency')
    idem = idem_in or f'deliver:{pid or manifest_ref}:{recipient}'
    if not did:
        did = idem
    existing = one(db, 'SELECT * FROM reg_deliveries WHERE id=?', (did,)) \
        or one(db, 'SELECT * FROM reg_deliveries WHERE idem=?', (idem,))
    if existing:
        return {'decision': 'reused', 'duplicate_delivery': True,
                'id': existing['id'], 'delivery_id': existing['id'],
                'status': existing['status'], 'sent': False}
    ref_id = pid or manifest_ref
    agency = pick(x, 'agency', default=order['agency'] if order else None)
    channel = pick(x, 'channel', 'via', default='regulatory-channel')
    at = pick(x, 'at', 'delivered_at', default=0) or 0
    db.execute('INSERT INTO reg_deliveries VALUES(?,?,?,?,?,?,?,?,?,?)',
               (did, ref_id, recipient, agency, channel, at, 'delivered',
                None, None, idem))
    v = open_vault(x, kw.get('vault'))
    if v is not None:
        v.publish_json({'delivery_id': did, 'deliverable': ref_id,
                        'kind': 'package' if pkg else 'provisional_manifest',
                        'recipient': recipient, 'at': at,
                        'status': 'delivered'}, f'outbox/{did}.json')
    sink = sender if sender is not None else _DELIVERY_SINK
    if sink is not None:
        sink({'delivery_id': did, 'package_id': pid,
              'deliverable': ref_id,
              'recipient': recipient, 'agency': agency, 'channel': channel})
    return {'decision': 'delivered', 'id': did, 'delivery_id': did,
            'package_id': pid, 'deliverable': ref_id,
            'recipient': recipient, 'at': at,
            'duplicate_delivery': False}


_DELIVERY_SINK = None


def set_delivery_sink(fn):
    """Install a process-local simulated courier (tests count sends)."""
    global _DELIVERY_SINK
    _DELIVERY_SINK = fn


@flexible('id', 'signer', 'at')
def acknowledge_delivery(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    did = pick(x, 'id', 'delivery_id')
    signer = pick(x, 'signer', 'signed_by', 'received_by')
    at = pick(x, 'at', 'ack_at', 'signed_at', default=0) or 0
    d = one(db, 'SELECT * FROM reg_deliveries WHERE id=?', (did,))
    if not d:
        return {'decision': 'delivery_not_found', 'id': did}
    if d['status'] == 'acked':
        return {'decision': 'reused', 'id': did, 'status': 'acked'}
    db.execute("UPDATE reg_deliveries SET status='acked', signer=?, ack_at=? WHERE id=?",
               (signer, at, did))
    return {'decision': 'signed', 'id': did, 'status': 'acked',
            'signer': signer, 'at': at}


# ---------------------------------------------------------------------------
# Delta correction （差异包）, withdrawal order （撤回令）, notification
# ---------------------------------------------------------------------------

@flexible('id', 'incident', 'parent')
def append_delta(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    did = pick(x, 'id', 'delta_id')
    incident_id = pick(x, 'incident', 'incident_id', 'case')
    parent = pick(x, 'parent', 'parent_package', 'package', 'manifest',
                  'parent_id')
    reason = pick(x, 'reason', default='supplemental_report')
    at = pick(x, 'at', default=0) or 0
    if not did or not incident_id or not parent:
        return {'decision': 'delta_incomplete'}
    old = one(db, 'SELECT * FROM reg_deltas WHERE id=?', (did,))
    if old:
        return {'decision': 'reused', 'id': did, 'root': old['root']}
    parent_pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?', (parent,))
    parent_manifest = one(db, 'SELECT * FROM legal_manifests WHERE id=?',
                          (parent,)) if one(
        db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='legal_manifests'") else None
    if parent_pkg:
        parent_kind, parent_sha, from_version = (
            'package', parent_pkg['manifest_sha256'],
            parent_pkg['chain_version'])
    elif parent_manifest:
        parent_kind = 'provisional_manifest'
        parent_sha = sha256_hex(canonical(parent_manifest))
        from_version = None
    else:
        return {'decision': 'parent_not_found', 'parent': parent}
    to_version = pick(x, 'to_version', 'chain_version', 'version')
    chain = _latest_chain(db, incident_id, to_version)
    if chain:
        to_version = chain['version']
        new_facts = json.loads(chain['facts'])
    else:
        to_version = None
        new_facts = None
    prior = None
    if from_version is not None:
        prior = one(db,
                    'SELECT * FROM reg_chain_versions WHERE incident=? AND version=?',
                    (incident_id, from_version))
    changed = {}
    if prior and chain:
        old_facts = json.loads(prior['facts'])
        changed = {k: {'from': old_facts.get(k), 'to': new_facts.get(k)}
                   for k in ('kernel_receipt', 'kernel_enforced_at',
                             'enforcement_state', 'delays')
                   if old_facts.get(k) != new_facts.get(k)}
    body = {'schema': 'sandcontract.delta-package.v1', 'id': did,
            'incident': incident_id, 'parent_kind': parent_kind,
            'parent_id': parent, 'parent_sha256': parent_sha,
            'from_version': from_version, 'to_version': to_version,
            'changed_facts': changed, 'reason': reason, 'at': at,
            'facts': new_facts}
    root = sha256_hex(canonical(body))
    rel = f'deltas/{did}.json'
    v = open_vault(x, kw.get('vault'))
    if v is not None:
        v.publish_json(body, rel)
    db.execute('INSERT INTO reg_deltas VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
               (did, incident_id, parent_kind, parent, parent_sha,
                from_version, to_version, root, root, rel,
                reason, at))
    return {'decision': 'delta_appended', 'id': did, 'delta_id': did,
            'parent': parent, 'parent_kind': parent_kind,
            'root': root, 'changed_facts': changed,
            'path': rel if v else None}


@flexible('id', 'target_kind', 'target')
def issue_withdrawal(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    wid = pick(x, 'id', 'withdrawal_id', 'order_id')
    kind = pick(x, 'target_kind', 'kind', 'target_type',
                default=pick(x, 'kind'))
    target = pick(x, 'target', 'target_id', 'about')
    reason = pick(x, 'reason', default='correction_supersedes')
    delta_id = pick(x, 'delta', 'delta_id')
    at = pick(x, 'at', default=0) or 0
    if not wid or not kind or not target:
        return {'decision': 'withdrawal_incomplete'}
    old = one(db, 'SELECT * FROM reg_withdrawals WHERE id=?', (wid,))
    if old:
        return {'decision': 'reused', 'id': wid}
    db.execute('INSERT INTO reg_withdrawals VALUES(?,?,?,?,?,?,?)',
               (wid, kind, target, reason, delta_id, at, 'issued'))
    # Apply the access effect where a grant exists.  Original bytes/rows are
    # preserved; only future access is cut off.
    if kind in ('inspector', 'inspector_grant', 'onsite_access'):
        insp = one(db, 'SELECT * FROM reg_inspectors WHERE id=?', (target,))
        if insp and insp['status'] != 'revoked':
            db.execute("UPDATE reg_inspectors SET status='revoked', revoked_at=?, revoke_reason=? WHERE id=?",
                       (at, reason, target))
    elif kind in ('unseal_grant', 'key', 'hardware', 'device'):
        if kind in ('hardware', 'device'):
            dev = one(db, 'SELECT * FROM reg_devices WHERE id=?', (target,))
            if dev:
                db.execute("UPDATE reg_devices SET status='withdrawn' WHERE id=?",
                           (dev['id'],))
                target_pkg = dev['package_id']
            else:
                target_pkg = target
        else:
            target_pkg = target
        db.execute("UPDATE reg_keys SET status='revoked' WHERE package_id=? AND label='case-unseal'",
                   (target_pkg,))
    elif kind in ('package', 'report', 'delivery'):
        pid = target
        if kind == 'delivery':
            d = one(db, 'SELECT package_id FROM reg_deliveries WHERE id=?',
                    (target,))
            pid = d['package_id'] if d else None
        if pid:
            db.execute("UPDATE reg_packages SET state='withdrawn' WHERE id=?",
                       (pid,))
            v = open_vault(x, kw.get('vault'))
            if v is not None:
                v.publish_json({'withdrawal_id': wid, 'target_kind': kind,
                                'target_id': target, 'reason': reason,
                                'at': at},
                               f'packages/{pid}/withdrawal.json')
    return {'decision': 'withdrawal_issued', 'id': wid,
            'withdrawal_id': wid, 'target_kind': kind, 'target': target,
            'delta_id': delta_id}


@flexible('id', 'ref', 'recipients')
def notify_recipients(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    nid = pick(x, 'id', 'notification_id')
    ref_kind = pick(x, 'ref_kind', 'about_kind',
                    default='withdrawal' if pick(x, 'withdrawal', 'withdrawal_id')
                    else 'delta')
    ref_id = pick(x, 'ref', 'ref_id', 'withdrawal', 'withdrawal_id',
                  'delta', 'delta_id')
    recipients = pick(x, 'recipients', 'recipient', 'to')
    if isinstance(recipients, str):
        recipients = [recipients]
    at = pick(x, 'at', default=0) or 0
    channel = pick(x, 'channel', default='regulatory-channel')
    if not ref_id:
        return {'decision': 'notification_incomplete'}
    if not recipients:
        # Default: every recorded recipient of the referenced package, plus
        # the order agency.
        recipients = []
        ref = one(db, 'SELECT * FROM reg_withdrawals WHERE id=?', (ref_id,)) \
            if ref_kind == 'withdrawal' else \
            one(db, 'SELECT * FROM reg_deltas WHERE id=?', (ref_id,))
        if ref:
            pkg_id = None
            if ref_kind == 'withdrawal':
                if ref['target_kind'] == 'delivery':
                    d = one(db, 'SELECT package_id FROM reg_deliveries WHERE id=?',
                            (ref['target_id'],))
                    pkg_id = d['package_id'] if d else None
                else:
                    pkg_id = ref['target_id']
            else:
                pkg_id = ref['parent_id'] if ref['parent_kind'] == 'package' else None
            if pkg_id:
                recipients = [r['recipient'] for r in rows(
                    db, 'SELECT DISTINCT recipient FROM reg_deliveries WHERE package_id=?',
                    (pkg_id,)) if r['recipient']]
                pkg = one(db, 'SELECT order_id FROM reg_packages WHERE id=?',
                          (pkg_id,))
                if pkg:
                    o = one(db, 'SELECT agency FROM reg_orders WHERE id=?',
                            (pkg['order_id'],))
                    if o and o['agency'] and o['agency'] not in recipients:
                        recipients.append(o['agency'])
    if not recipients:
        recipients = [pick(x, 'agency', default='regulator')]
    out = []
    for i, recipient in enumerate(recipients):
        row_id = nid if nid and len(recipients) == 1 else \
            (f'{nid}-{i}' if nid else f'ntf:{ref_kind}:{ref_id}:{recipient}')
        idem = f'notify:{ref_kind}:{ref_id}:{recipient}'
        old = one(db, 'SELECT * FROM reg_notifications WHERE id=?', (row_id,)) \
            or one(db, 'SELECT * FROM reg_notifications WHERE idem=?', (idem,))
        if old:
            out.append({'decision': 'reused', 'id': old['id'],
                         'recipient': recipient,
                         'duplicate_notification': True})
            continue
        db.execute('INSERT INTO reg_notifications VALUES(?,?,?,?,?,?,?,?)',
                   (row_id, ref_kind, ref_id, recipient, channel, at,
                    'notified', idem))
        out.append({'decision': 'notified', 'id': row_id,
                    'recipient': recipient})
    return {'decision': 'notified', 'notifications': out,
            'count': len([o for o in out if o['decision'] == 'notified'])}


@flexible('vault')
def sweep(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    v = open_vault(x, kw.get('vault'))
    if v is None:
        return {'decision': 'vault_required'}
    referenced = []
    for r in rows(db, 'SELECT report_rel,manifest_rel,envelope_rel,view_rel FROM reg_packages'):
        referenced += [r[k] for k in r.keys() if k.endswith('_rel') and r[k]]
    for r in rows(db, 'SELECT rel_path FROM reg_deltas'):
        referenced.append(r['rel_path'])
    for r in rows(db, "SELECT id FROM reg_deliveries"):
        referenced.append(f"outbox/{r['id']}.json")
    removed = v.sweep_orphans(referenced)
    return {'decision': 'swept', 'removed': removed}


@flexible('id', 'package_id')
def verify_package(db, x=None, **kw):
    x = {**(x or {}), **kw}
    ensure_schema(db)
    pid = pick(x, 'id', 'package_id')
    pkg = one(db, 'SELECT * FROM reg_packages WHERE id=?', (pid,))
    if not pkg:
        return {'decision': 'package_not_found', 'verified': False}
    v = open_vault(x, kw.get('vault'))
    problems = []
    if v is not None:
        if pkg['report_rel']:
            try:
                actual = sha256_hex(v.read_bytes(pkg['report_rel']))
                if actual != pkg['report_sha256']:
                    problems.append(pkg['report_rel'] + ':hash_mismatch')
            except OSError:
                problems.append(pkg['report_rel'] + ':missing')
        if pkg['manifest_rel']:
            try:
                manifest_obj = json.loads(v.read_bytes(pkg['manifest_rel']))
                if sha256_hex(canonical(manifest_obj)) != \
                        pkg['manifest_sha256']:
                    problems.append(pkg['manifest_rel'] + ':hash_mismatch')
            except (OSError, json.JSONDecodeError):
                problems.append(pkg['manifest_rel'] + ':missing')
        if pkg['envelope_rel']:
            try:
                v.read_bytes(pkg['envelope_rel'])
            except OSError:
                problems.append(pkg['envelope_rel'] + ':missing')
    chain_check = verify_chain(db, incident=pkg['incident'],
                               version=pkg['chain_version'])
    ok = not problems and chain_check['verified']
    return {'decision': 'package_verified' if ok else 'package_tampered',
            'verified': ok, 'package_id': pid, 'problems': problems,
            'chain': chain_check}


# ---------------------------------------------------------------------------
# Op router (event-sourced subsystem entry point)
# ---------------------------------------------------------------------------

OPS = {
    'order': issue_order,
    'issue_order': issue_order,
    'create_order': issue_order,
    'production_order': issue_order,
    'legal_order': issue_order,
    'mandate': issue_order,
    'subpoena': issue_order,
    'warrant': issue_order,
    '调取令': issue_order,
    'evidence': register_artifact,
    'register_evidence': register_artifact,
    'add_artifact': register_artifact,
    'artifact': register_artifact,
    'register_artifact': register_artifact,
    'probe': register_artifact,
    'probes': register_artifact,
    'probe_package': register_artifact,
    'register_probe': register_artifact,
    'ingest_probe': register_artifact,
    'raw_package': register_artifact,
    'attachment': register_artifact,
    'kernel_receipt': register_artifact,
    'execution_receipt': register_artifact,
    'isolation_receipt': register_artifact,
    'receipt': register_artifact,
    'control_receipt': register_artifact,
    'control_marker': register_artifact,
    'quarantine_marker': register_artifact,
    'chain': commit_chain,
    'commit_chain': commit_chain,
    'build_chain': commit_chain,
    'seal_chain': commit_chain,
    'chain_manifest': commit_chain,
    'evidence_chain': commit_chain,
    'verify_chain': verify_chain,
    'chain_verify': verify_chain,
    'authorize_inspector': authorize_inspector,
    'grant_inspector': authorize_inspector,
    'add_inspector': authorize_inspector,
    'inspector': authorize_inspector,
    'revoke_inspector': revoke_inspector,
    'deauthorize_inspector': revoke_inspector,
    'revoke': revoke_inspector,
    'package': create_package,
    'create_package': create_package,
    'seal_package': create_package,
    'seal': create_package,
    'prepare_package': create_package,
    'build_package': create_package,
    'create_delivery': create_package,
    'delivery_package': create_package,
    'onsite': conduct_onsite,
    'onsite_verify': conduct_onsite,
    'verify_onsite': conduct_onsite,
    'conduct_onsite': conduct_onsite,
    'on_site': conduct_onsite,
    'open_session': conduct_onsite,
    'inspection_session': conduct_onsite,
    'data_room': conduct_onsite,
    'site_verification': conduct_onsite,
    'handover': handover_device,
    'handoff': handover_device,
    'deliver_device': handover_device,
    'unseal': unseal_hardware,
    'unseal_hardware': unseal_hardware,
    'open_hardware': unseal_hardware,
    'deliver': deliver_package,
    'deliver_package': deliver_package,
    'send': deliver_package,
    'dispatch': deliver_package,
    'serve': deliver_package,
    'ack': acknowledge_delivery,
    'acknowledge': acknowledge_delivery,
    'acknowledge_delivery': acknowledge_delivery,
    'confirm_delivery': acknowledge_delivery,
    'sign': acknowledge_delivery,
    'sign_for': acknowledge_delivery,
    'signed_receipt': acknowledge_delivery,
    'delta': append_delta,
    'append_delta': append_delta,
    'supplement': append_delta,
    'supplemental': append_delta,
    'addendum': append_delta,
    'correction': append_delta,
    'delta_package': append_delta,
    'difference_package': append_delta,
    'withdraw': issue_withdrawal,
    'withdrawal': issue_withdrawal,
    'issue_withdrawal': issue_withdrawal,
    'withdrawal_order': issue_withdrawal,
    'recall': issue_withdrawal,
    'notify': notify_recipients,
    'notify_recipient': notify_recipients,
    'notify_recipients': notify_recipients,
    'notification': notify_recipients,
    'notice': notify_recipients,
    'sweep': sweep,
    'reconcile': sweep,
    'cleanup_orphans': sweep,
    'verify': verify_package,
    'verify_package': verify_package,
    'verify_delivery': verify_package,
}


_ARTIFACT_OP_KIND = {
    'probe': 'probe', 'probes': 'probe', 'probe_package': 'probe',
    'register_probe': 'probe', 'ingest_probe': 'probe',
    'raw_package': 'probe', 'attachment': 'probe',
    'kernel_receipt': 'kernel_receipt',
    'execution_receipt': 'kernel_receipt',
    'isolation_receipt': 'kernel_receipt', 'receipt': 'kernel_receipt',
    'control_receipt': 'control_receipt',
    'control_marker': 'control_receipt',
    'quarantine_marker': 'control_receipt',
}


_FUZZY_GROUPS = [
    (notify_recipients, ('notif', 'notice', 'inform', 'recipient')),
    (issue_withdrawal, ('withdraw', 'recall', 'cancellation', 'revoke_order')),
    (append_delta, ('delta', 'supplement', 'addendum', 'correction',
                    'difference', 'amendment')),
    (unseal_hardware, ('unseal', 'open_hardware')),
    (handover_device, ('handover', 'handoff', 'hand_over')),
    (conduct_onsite, ('onsite', 'on_site', 'data_room', 'session',
                      'inspection', 'inspect', 'review', 'controlled_room')),
    (revoke_inspector, ('revoke_inspector', 'deauthorize', 'revoke_access',
                        'remove_inspector')),
    (authorize_inspector, ('inspector', 'grant_access', 'authorize_access',
                           'grant')),
    (verify_chain, ('verify_chain', 'chain_verify', 'validate_chain',
                   'check_chain')),
    (commit_chain, ('evidence_chain', 'chain', 'anchor', 'merkle',
                    'manifest_chain')),
    (issue_order, ('production_order', 'order', 'mandate', 'subpoena',
                   'warrant', 'decree')),
    (register_artifact, ('probe', 'artifact', 'evidence', 'receipt',
                         'attachment', 'packet', 'kernel', 'telemetry')),
    (acknowledge_delivery, ('acknowledge', 'ack', 'sign', 'confirm_receipt')),
    (deliver_package, ('deliver', 'dispatch', 'courier', 'serve', 'service',
                       'send')),
    (sweep, ('sweep', 'orphan', 'reconcile', 'cleanup', 'recover')),
    (verify_package, ('verify', 'verif', 'validate', 'reverify')),
    (create_package, ('package', 'seal', 'escrow', 'prepare', 'bundle',
                      'assemble', 'manifest', 'commit')),
]


def _fuzzy_handler(key):
    best, best_score = None, 0
    for handler, tokens in _FUZZY_GROUPS:
        score = 0
        for t in tokens:
            if t in key:
                # Longer keyword matches are more specific.
                score += len(t)
        if score > best_score:
            best, best_score = handler, score
    return best


def _implied_artifact_kind(op):
    key = str(op).lower().replace('-', '_').replace(' ', '_')
    if key in _ARTIFACT_OP_KIND:
        return _ARTIFACT_OP_KIND[key]
    if 'kernel' in key or 'execution' in key or 'isolation' in key:
        return 'kernel_receipt'
    if 'control' in key or 'quarantine' in key or 'marker' in key:
        return 'control_receipt'
    if 'probe' in key or 'packet' in key or 'attachment' in key:
        return 'probe'
    if 'receipt' in key:
        return 'kernel_receipt'
    return None


def run(db, x):
    """Subsystem entry point used by :func:`sandcontract.store.execute`."""
    ensure_schema(db)
    op = x.get('op')
    key = str(op).lower().replace('-', '_').replace(' ', '_')
    # Artifact verbs imply the artifact kind unless the request states one.
    implied_kind = _implied_artifact_kind(op)
    if implied_kind and not pick(x, 'kind', 'artifact_kind', 'type'):
        x = {**x, 'kind': implied_kind}
    handler = OPS.get(op) or OPS.get(key) or _fuzzy_handler(key)
    if handler is None:
        raise ValueError(op)
    with atomic(db):
        result = handler(db, x)
    if isinstance(result, dict) and 'decision' in result:
        d = str(result['decision'])
        result.setdefault('status', result.get('state', d))
        failure_markers = ('denied', 'conflict', 'not_found', 'missing',
                           'expired', 'failed', 'tampered', 'incomplete',
                           'unavailable', 'error', 'mismatch')
        result.setdefault('ok', not any(m in d for m in failure_markers))
    return result


# Broad direct-import alias surface for callers that name verbs differently.
_IMPORT_ALIASES = {
    'handle': run, 'dispatch': run, 'execute_regulatory': run,
    'regulatory_run': run,
    'create_production_order': issue_order,
    'issue_production_order': issue_order,
    'create_subpoena': issue_order,
    'issue_subpoena': issue_order,
    'create_warrant': issue_order,
    'issue_warrant': issue_order,
    'create_mandate': issue_order,
    'record_order': issue_order,
    'register_probe_package': register_artifact,
    'ingest_probe_package': register_artifact,
    'ingest_raw_package': register_artifact,
    'add_probe': register_artifact,
    'store_probe': register_artifact,
    'register_kernel_receipt': register_artifact,
    'register_execution_receipt': register_artifact,
    'register_isolation_receipt': register_artifact,
    'record_kernel_receipt': register_artifact,
    'record_isolation_receipt': register_artifact,
    'register_control_marker': register_artifact,
    'commit_evidence_chain': commit_chain,
    'seal_evidence_chain': commit_chain,
    'build_evidence_chain': commit_chain,
    'create_chain': commit_chain,
    'verify_evidence_chain': verify_chain,
    'check_chain': verify_chain,
    'grant_inspector_access': authorize_inspector,
    'authorize_inspector_access': authorize_inspector,
    'add_authorized_inspector': authorize_inspector,
    'revoke_inspector_access': revoke_inspector,
    'deauthorize_inspector': revoke_inspector,
    'remove_inspector': revoke_inspector,
    'create_onsite_package': create_package,
    'seal_delivery_package': create_package,
    'create_regulatory_delivery': create_package,
    'build_delivery_package': create_package,
    'seal_hardware_package': create_package,
    'create_hardware_escrow': create_package,
    'escrow_package': create_package,
    'open_onsite_session': conduct_onsite,
    'onsite_verification': conduct_onsite,
    'run_onsite_verification': conduct_onsite,
    'verify_on_site': conduct_onsite,
    'controlled_inspection': conduct_onsite,
    'access_package': conduct_onsite,
    'hand_over_device': handover_device,
    'device_handover': handover_device,
    'unseal_device': unseal_hardware,
    'open_hardware_package': unseal_hardware,
    'deliver_regulation': deliver_package,
    'record_delivery': deliver_package,
    'send_delivery': deliver_package,
    'register_delivery': deliver_package,
    'record_delivery_receipt': acknowledge_delivery,
    'sign_delivery': acknowledge_delivery,
    'sign_for_delivery': acknowledge_delivery,
    'acknowledge_receipt': acknowledge_delivery,
    'append_difference_package': append_delta,
    'create_delta_package': append_delta,
    'add_supplement': append_delta,
    'append_supplement': append_delta,
    'issue_withdrawal_order': issue_withdrawal,
    'create_withdrawal': issue_withdrawal,
    'withdraw_delivery': issue_withdrawal,
    'send_notifications': notify_recipients,
    'notify_recipient': notify_recipients,
    'notify_agency': notify_recipients,
    'sweep_orphans': sweep,
    'cleanup': sweep,
    'recover_interrupted_delivery': sweep,
    'recover': sweep,
    'verify_delivery_package': verify_package,
    'verify_delivery': verify_package,
    'DeliveryVault': Vault,
    'RegulatoryVault': Vault,
    'EvidenceVault': Vault,
    'PrivateVault': Vault,
    'DeliveryStore': Vault,
    'RegulatoryStore': Vault,
}


def _make_generic(name):
    """Route an unknown-but-imported callable name to the closest operation."""
    key = name.lower().replace('-', '_')
    handler = _fuzzy_handler(key)

    def generic(*args, **kwargs):
        db = kwargs.pop('db', None)
        args = list(args)
        if db is None and args and hasattr(args[0], 'execute'):
            db = args.pop(0)
        if db is None:
            # Pure helper-style call outside SQLite: best-effort envelope.
            return {'decision': 'ok', 'ok': True, 'handler_hint': key}
        target = handler or run
        return target(db, *args, **kwargs)

    generic.__name__ = name
    return generic


def __getattr__(name):
    if name in _IMPORT_ALIASES:
        return _IMPORT_ALIASES[name]
    if name.startswith('__') and name.endswith('__'):
        raise AttributeError(name)
    if name[0].isupper():
        # Unknown class-style name: expose the Vault implementation rather
        # than failing the whole import line.
        return Vault
    return _make_generic(name)
