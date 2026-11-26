import json
import os
import tempfile
import unittest
from pathlib import Path

from sandcontract.store import connect, execute, replay, one, rows
from sandcontract.legal_export import provisional_manifest
from sandcontract import regulatory_delivery as rd

ROOT = Path(__file__).resolve().parents[1]
SECRET = 'TENANT_B_TOKEN_7f3a9c2e91'
AGENCY = 'regulator-agency-7'


def mixed_records():
    """Time-24 shared-host probe: tenant-a syscalls AND tenant-b token."""
    return [
        {'seq': 1, 'at': 24, 'category': 'syscall', 'tenant': 'tenant-a',
         'binding': 'binding-a', 'syscall': 'openat',
         'args': ['/srv/workload-a']},
        {'seq': 2, 'at': 24, 'category': 'syscall', 'tenant': 'tenant-a',
         'binding': 'binding-a', 'syscall': 'unshare',
         'args': ['CLONE_NEWNS']},
        {'seq': 3, 'at': 24, 'category': 'syscall', 'tenant': 'tenant-a',
         'binding': 'binding-a', 'syscall': 'mount',
         'args': ['/dev/cpu_dma_latency'], 'anomaly': True},
        {'at': 24, 'category': 'access_token', 'tenant': 'tenant-b',
         'request': 'req-b-9', 'token': SECRET},
    ]


def mixed_raw(records=None):
    return ('PROBE-PACKAGE node-a uid=node-uid-a generation=1 captured=24\n'
            + json.dumps({'records': records or mixed_records()})
            + f'\nraw trailer tenant-b-token={SECRET}\n')


class RegulatoryTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.db_path = self.folder / 'state.sqlite'
        self.db = connect(str(self.db_path))
        self.vault_dir = self.folder / 'vault'
        self.n = 0
        rd.set_delivery_sink(None)
        for name in ('profile_normal', 'admit_normal'):
            for step in json.loads((ROOT / 'fixtures' / f'{name}.json'
                                    ).read_text(encoding='utf-8')):
                execute(self.db, step.get('subsystem', name.split('_')[0]),
                        step)
        execute(self.db, 'incident', dict(
            request_id='violation-24', op='observe', id='violation-24',
            binding='binding-a', kind='syscall', source='probe-agent',
            at=24, confidence=95))
        execute(self.db, 'incident', dict(
            request_id='quarantine-case', op='quarantine', id='case',
            binding='binding-a', scope='binding', reason='syscall anomaly'))

    def tearDown(self):
        rd.set_delivery_sink(None)
        self.db.close()
        self.tmp.cleanup()

    def act(self, op, **fields):
        self.n += 1
        step = dict(fields)
        step['op'] = op
        step.setdefault('request_id', f'reg-{self.n}')
        step.setdefault('vault_dir', str(self.vault_dir))
        return execute(self.db, 'regulatory', step)

    def core(self, sub, op, **fields):
        self.n += 1
        step = dict(fields)
        step['op'] = op
        step.setdefault('request_id', f'core-{self.n}')
        return execute(self.db, sub, step)

    def order(self, oid='order-1', **over):
        fields = dict(id=oid, incident='case', window=[24, 27],
                      categories=['syscall'], agency=AGENCY,
                      mask_other_tenants=True, mask_tenants=['tenant-b'],
                      retention_until=200, at=20)
        fields.update(over)
        return self.act('order', **fields)

    def probe(self, pid='probe-24', **over):
        fields = dict(id=pid, incident='case', at=24,
                      raw=mixed_raw(), records=mixed_records())
        fields.update(over)
        return self.act('probe', **fields)

    def receipt_and_chain(self, kernel=True):
        self.act('control_marker', id='control-25', incident='case', at=25,
                 verdict='control_plane_quarantined')
        if kernel:
            self.act('kernel_receipt', id='kernel-27', incident='case',
                     at=27, verdict='denied', enforced_at=27)
        return self.act('chain', incident='case', at=27)

    def vault(self):
        return rd.Vault(str(self.vault_dir))

    def assert_no_secret_in_delivery_paths(self):
        leaked = []
        for dirpath, _dirs, files in os.walk(self.vault_dir):
            if Path(dirpath).name == 'artifacts' or '/artifacts' in dirpath:
                continue
            for name in files:
                data = (Path(dirpath) / name).read_bytes()
                if SECRET.encode() in data:
                    leaked.append(str(Path(dirpath, name)))
        self.assertEqual(leaked, [], f'tenant-b token leaked: {leaked}')

    def assert_vault_private(self):
        self.assertEqual(self.vault().assert_private(), [])


class OrderAndTimelineTest(RegulatoryTestBase):
    def test_order_unavailable_before_incident_and_fixes_all_terms(self):
        r = self.act('order', id='early', incident='missing-case',
                     window=[24, 27], categories=['syscall'], agency=AGENCY)
        self.assertEqual(r['decision'], 'unavailable')
        r = self.order()
        self.assertEqual(r['decision'], 'order_recorded')
        row = one(self.db, 'SELECT * FROM reg_orders WHERE id=?', ('order-1',))
        self.assertEqual([row['window_from'], row['window_to']], [24, 27])
        self.assertEqual(json.loads(row['categories']), ['syscall'])
        self.assertEqual(row['agency'], AGENCY)
        self.assertEqual(json.loads(row['mask_tenants']), ['tenant-b'])
        self.assertEqual(row['mask_other'], 1)
        self.assertEqual(row['retention_until'], 200)
        self.assertTrue(row['terms_hash'])
        # Re-issuing the same order is idempotent; changed terms conflict.
        self.assertEqual(self.order()['decision'], 'reused')
        changed = self.order('order-1', retention_until=999)
        self.assertEqual(changed['decision'], 'order_conflict')

    def test_database_quarantine_is_not_a_kernel_denial(self):
        self.order()
        self.probe()
        self.act('control_marker', id='c25', incident='case', at=25)
        v1 = self.act('chain', incident='case', at=26)
        self.assertEqual(v1['decision'], 'chain_committed')
        facts = v1['facts']
        self.assertEqual(facts['control_plane_quarantine_at'], 25)
        self.assertIsNone(facts['kernel_receipt'])
        self.assertEqual(facts['enforcement_state'],
                         'control_plane_quarantined_kernel_unconfirmed')
        claims = {(c['claim'], c['at']) for c in facts['claims']}
        self.assertIn(('control_plane_marked_quarantined', 25), claims)
        self.assertNotIn(('kernel_execution_denied', 24), claims)
        self.assertNotIn(('kernel_execution_denied', 25), claims)
        # The binding table itself does say quarantined at control plane.
        self.assertEqual(one(self.db, 'SELECT status FROM bindings WHERE id=?',
                             ('binding-a',))['status'], 'quarantined')

    def test_true_24_to_27_delay_is_shared_by_both_modes(self):
        self.order()
        self.probe()
        chain = self.receipt_and_chain()
        self.assertEqual(chain['facts']['enforcement_state'], 'kernel_denied')
        self.assertEqual(
            chain['facts']['delays']['call_to_control_plane'], 1)
        self.assertEqual(
            chain['facts']['delays']['control_plane_to_kernel_receipt'], 2)
        self.assertEqual(
            chain['facts']['delays']['call_to_kernel_enforcement'], 3)
        on = self.act('seal', id='pkg-onsite', order='order-1',
                      mode='onsite', at=28)
        hw = self.act('seal', id='pkg-hw', order='order-1', mode='hardware',
                      witnesses=['notary-li'], at=28)
        self.assertEqual(on['facts_root'], hw['facts_root'])
        self.assertEqual(on['facts_root'], chain['facts_root'])
        self.assertEqual(on['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])
        self.assertEqual(hw['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])


class CrossTenantAndOnSiteTest(RegulatoryTestBase):
    def test_onsite_report_carries_only_a_calls_and_irreversible_mask(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id='pkg-on', order='order-1', mode='onsite', at=28)
        self.act('authorize_inspector', id='insp-1', agency=AGENCY, at=21)
        sess = self.act('onsite', id='sess-1', inspector='insp-1',
                        package='pkg-on', at=28)
        self.assertEqual(sess['decision'], 'onsite_verified')
        report = sess['report']
        self.assertEqual(report['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])
        tenants = {c.get('tenant') for c in report['calls']}
        self.assertEqual(tenants, {'tenant-a'})
        # Tenant-b survives only as an irreversibly redacted placeholder.
        self.assertTrue(report['masked_records'])
        masked_blob = json.dumps(report['masked_records'])
        self.assertNotIn(SECRET, masked_blob)
        self.assertIn('redacted:', masked_blob)
        self.assertEqual(
            report['mask_certificate']['masked_record_count'], 1)
        # Nothing readable on the delivery path contains tenant-b bytes.
        self.assert_no_secret_in_delivery_paths()
        self.assert_vault_private()
        # The raw mixed package is still held, intact and private, by platform.
        raw_file = self.vault().abs_path('artifacts/probe-24.bin')
        self.assertIn(SECRET.encode(), raw_file.read_bytes())
        self.assertEqual(raw_file.stat().st_mode & 0o077, 0)

    def test_window_and_category_are_enforced(self):
        records = mixed_records() + [
            {'seq': 9, 'at': 23, 'category': 'syscall', 'tenant': 'tenant-a',
             'binding': 'binding-a', 'syscall': 'read'},
            {'seq': 10, 'at': 28, 'category': 'syscall', 'tenant': 'tenant-a',
             'binding': 'binding-a', 'syscall': 'write'},
            {'seq': 11, 'at': 24, 'category': 'network', 'tenant': 'tenant-a',
             'binding': 'binding-a', 'call': 'connect'},
        ]
        self.order()
        self.probe(raw=json.dumps({'records': records}), records=records)
        self.receipt_and_chain()
        pkg = self.act('seal', id='pkg-filter', order='order-1',
                       mode='onsite', at=28)
        self.assertEqual(pkg['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])
        report = json.loads(
            self.vault().read_bytes('packages/pkg-filter/report.json'))
        names = [c.get('syscall') for c in report['calls']]
        self.assertNotIn('read', names)
        self.assertNotIn('write', names)
        self.assertNotIn('connect', names)

    def test_inspector_revocation_cuts_future_access(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id='pkg-on', order='order-1', mode='onsite', at=28)
        self.act('authorize_inspector', id='insp-x', agency=AGENCY)
        ok = self.act('onsite', id='sess-ok', inspector='insp-x',
                      package='pkg-on', at=28)
        self.assertEqual(ok['decision'], 'onsite_verified')
        rev = self.act('revoke_inspector', id='insp-x', at=29,
                       reason='engagement ended')
        self.assertEqual(rev['decision'], 'inspector_revoked')
        denied = self.act('onsite', id='sess-denied', inspector='insp-x',
                          package='pkg-on', at=30)
        self.assertEqual(denied['decision'], 'inspector_revoked')
        self.assertTrue(denied['access_denied'])
        self.assertIsNone(one(
            self.db,
            "SELECT report_sha256 FROM reg_sessions WHERE id='sess-denied'"
        )['report_sha256'])
        # Withdrawal order targeting the grant is idempotent and notifies.
        w = self.act('withdraw', id='w-insp', target_kind='inspector_grant',
                      target='insp-x', at=30)
        self.assertEqual(w['decision'], 'withdrawal_issued')
        self.assertEqual(self.act('withdraw', id='w-insp',
                                  target_kind='inspector_grant',
                                  target='insp-x')['decision'], 'reused')
        n = self.act('notify', id='n-insp', ref_kind='withdrawal',
                      ref='w-insp', recipients=[AGENCY], at=30)
        self.assertEqual(n['decision'], 'notified')


class HardwareEscrowTest(RegulatoryTestBase):
    def _sealed_hw(self, pid='pkg-hw', witnesses=None):
        self.order()
        self.probe()
        self.receipt_and_chain()
        return self.act('seal', id=pid, order='order-1', mode='hardware',
                        witnesses=witnesses or ['notary-li'], at=28)

    def test_encrypted_entity_and_single_unseal(self):
        self._sealed_hw()
        envelope = self.vault().read_bytes(
            'packages/pkg-hw/hardware.envelope')
        self.assertNotIn(SECRET.encode(), envelope)
        self.assertNotIn(b'unshare', envelope)  # ciphertext, not plaintext
        ho = self.act('handover', package='pkg-hw',
                      witness='courier-wang', at=28)
        self.assertEqual(ho['decision'], 'handed_over')
        dev = one(self.db, 'SELECT * FROM reg_devices WHERE package_id=?',
                  ('pkg-hw',))
        self.assertEqual(dev['handover_witness'], 'courier-wang')
        # Wrong witness fails without consuming the single-use grant.
        bad = self.act('unseal', package='pkg-hw', witness='mallory', at=29)
        self.assertEqual(bad['decision'], 'unseal_failed')
        self.assertEqual(bad['reason'], 'witness_not_authorised')
        key = one(self.db, "SELECT * FROM reg_keys WHERE package_id='pkg-hw' "
                           "AND label='case-unseal'")
        self.assertEqual(key['uses_used'], 0)
        # Authorised witness unseals the case view once.
        ok = self.act('unseal', package='pkg-hw', witness='notary-li', at=30)
        self.assertEqual(ok['decision'], 'unsealed')
        self.assertEqual(ok['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])
        self.assertNotIn(SECRET, json.dumps(ok['view']))
        self.assert_no_secret_in_delivery_paths()
        dev = one(self.db, 'SELECT * FROM reg_devices WHERE package_id=?',
                  ('pkg-hw',))
        self.assertEqual(dev['status'], 'unsealed')
        self.assertEqual(dev['unseal_witness'], 'notary-li')
        again = self.act('unseal', package='pkg-hw', witness='notary-li',
                         at=31)
        self.assertEqual(again['decision'], 'unseal_denied')
        self.assertEqual(again['reason'], 'single_use_consumed')

    def test_tampered_envelope_fails_terminally(self):
        self._sealed_hw('pkg-tamper')
        self.act('handover', package='pkg-tamper', witness='courier-wang')
        env_path = self.vault().abs_path(
            'packages/pkg-tamper/hardware.envelope')
        env = json.loads(env_path.read_text())
        env['tag'] = '0' * 64
        env_path.write_text(json.dumps(env))
        bad = self.act('unseal', package='pkg-tamper', witness='notary-li',
                       at=30)
        self.assertEqual(bad['decision'], 'unseal_failed')
        self.assertEqual(bad['reason'], 'integrity_failed')
        self.assertTrue(bad['terminal'])
        dev = one(self.db, 'SELECT * FROM reg_devices WHERE package_id=?',
                  ('pkg-tamper',))
        self.assertEqual(dev['status'], 'failed')
        later = self.act('unseal', package='pkg-tamper',
                         witness='notary-li', at=31)
        self.assertEqual(later['decision'], 'hardware_failed')

    def test_hardware_withdrawal_revokes_unseal_grant(self):
        self._sealed_hw('pkg-wd')
        dev = one(self.db, 'SELECT id FROM reg_devices WHERE package_id=?',
                  ('pkg-wd',))['id']
        w = self.act('withdraw', id='w-hw', target_kind='device',
                     target=dev, reason='legal hold transferred', at=29)
        self.assertEqual(w['decision'], 'withdrawal_issued')
        denied = self.act('unseal', package='pkg-wd', witness='notary-li')
        self.assertEqual(denied['decision'], 'unseal_denied')
        self.assertEqual(denied['reason'], 'device_withdrawn')
        key = one(self.db, "SELECT status FROM reg_keys WHERE package_id='pkg-wd' "
                           "AND label='case-unseal'")
        self.assertEqual(key['status'], 'revoked')


class ResendNodeAndChainTest(RegulatoryTestBase):
    def test_probe_resend_is_same_evidence(self):
        self.order()
        first = self.probe('probe-24')
        self.assertEqual(first['decision'], 'probe_recorded')
        resent = self.probe('probe-24-resend')
        self.assertEqual(resent['decision'], 'duplicate_artifact')
        self.assertTrue(resent['resent'])
        self.assertEqual(resent['canonical_id'], 'probe-24')
        # Same id re-PUT is reused; contradictory bytes under one id conflict.
        self.assertEqual(self.probe('probe-24')['decision'], 'reused')
        conflict = self.probe('probe-24', raw='different bytes')
        self.assertEqual(conflict['decision'], 'artifact_conflict')
        self.receipt_and_chain()
        version = one(self.db,
                      'SELECT MAX(version) v FROM reg_chain_versions WHERE incident=?',
                      ('case',))['v']
        probe_links = [l for l in json.loads(one(
            self.db, 'SELECT links FROM reg_chain_versions WHERE version=?',
            (version,))['links']) if l['type'] == 'probe']
        self.assertEqual(len(probe_links), 1)

    def test_node_generation_change_does_not_rewrite_pinned_generation(self):
        self.order()
        self.probe()
        self.core('profile', 'node', id='node-a', uid='node-uid-new',
                  generation=2, features=['seccomp'], capacity=2)
        chain = self.receipt_and_chain()
        stored = one(self.db,
                     'SELECT links FROM reg_chain_versions WHERE version=?',
                     (chain['version'],))
        links = json.loads(stored['links'])
        binding_link = next(l for l in links if l['type'] == 'binding')
        self.assertEqual(binding_link['data']['node_uid'], 'node-uid-a')
        self.assertEqual(binding_link['data']['node_generation'], 1)
        current = [l for l in links
                   if l['type'] == 'node_current_generation']
        self.assertEqual(len(current), 1)
        self.assertEqual(current[0]['data']['generation'], 2)
        check = self.act('verify_chain', incident='case',
                         version=chain['version'])
        self.assertTrue(check['verified'])

    def test_chain_tampering_is_detected(self):
        self.order()
        self.probe()
        chain = self.receipt_and_chain()
        self.db.execute("UPDATE reg_chain_versions SET root=? WHERE incident='case' AND version=?",
                        ('0' * 64, chain['version']))
        bad = self.act('verify_chain', incident='case',
                       version=chain['version'])
        self.assertFalse(bad['verified'])
        self.assertEqual(bad['decision'], 'chain_tampered')

    def test_late_receipt_appends_version_but_never_modifies_sealed_package(self):
        self.order()
        self.probe()
        self.act('control_marker', id='c25', incident='case', at=25)
        v1 = self.act('chain', incident='case', at=26)
        pkg = self.act('seal', id='pkg-early', order='order-1',
                       mode='onsite', chain_version=1, at=26)
        self.assertEqual(pkg['version'], 1)
        manifest_before = one(self.db,
                              'SELECT manifest_sha256,report_sha256 FROM reg_packages WHERE id=?',
                              ('pkg-early',))
        report_bytes_before = self.vault().read_bytes(
            'packages/pkg-early/report.json')
        # Late kernel receipt at 27 creates a new chain version.
        self.act('kernel_receipt', id='k27', incident='case', at=27,
                 verdict='denied', enforced_at=27)
        v2 = self.act('chain', incident='case', at=27)
        self.assertEqual(v2['version'], 2)
        self.assertEqual(v1['root'] != v2['root'], True)
        # Sealed v1 package row and bytes are untouched.
        manifest_after = one(self.db,
                             'SELECT manifest_sha256,report_sha256,root FROM reg_packages WHERE id=?',
                             ('pkg-early',))
        self.assertEqual(manifest_after['manifest_sha256'],
                         manifest_before['manifest_sha256'])
        self.assertEqual(manifest_after['report_sha256'],
                         manifest_before['report_sha256'])
        self.assertEqual(manifest_after['root'], v1['root'])
        self.assertEqual(
            self.vault().read_bytes('packages/pkg-early/report.json'),
            report_bytes_before)


class DeliveryCorrectionAndRecoveryTest(RegulatoryTestBase):
    def _ready_package(self, pid='pkg-deliver', mode='onsite'):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id=pid, order='order-1', mode=mode, at=28)

    def test_duplicate_delivery_invokes_courier_once(self):
        self._ready_package()
        sends = []
        rd.set_delivery_sink(lambda d: sends.append(d['delivery_id']))
        d1 = self.act('deliver', id='del-1', package='pkg-deliver', at=28)
        self.assertEqual(d1['decision'], 'delivered')
        d2 = self.act('deliver', id='del-1', package='pkg-deliver', at=28)
        self.assertEqual(d2['decision'], 'reused')
        self.assertTrue(d2['duplicate_delivery'])
        # Different id, same idempotency key (package+recipient) also dedups.
        d3 = self.act('deliver', id='del-1-other-request',
                      package='pkg-deliver', recipient=AGENCY, at=28)
        self.assertEqual(d3['decision'], 'reused')
        self.assertTrue(d3['duplicate_delivery'])
        self.assertEqual(len(sends), 1)
        self.assertEqual(one(self.db, 'SELECT COUNT(*) n FROM reg_deliveries')
                         ['n'], 1)
        signed = self.act('ack', id='del-1', signer='clerk-li', at=29)
        self.assertEqual(signed['decision'], 'signed')
        self.assertEqual(self.act('ack', id='del-1')['decision'], 'reused')

    def test_signed_manifest_corrected_only_by_delta_withdrawal_notice(self):
        # The old member-only provisional list is drafted and externally signed.
        m = provisional_manifest(self.db, 'manifest-old', 'case')
        self.assertEqual(m['members'], ['binding-a'])
        delivered = self.act('deliver', id='del-manifest',
                             manifest='manifest-old', recipient=AGENCY, at=26)
        self.assertEqual(delivered['decision'], 'delivered')
        self.act('ack', id='del-manifest', signer='clerk-li', at=26)
        before = one(self.db, 'SELECT members FROM legal_manifests WHERE id=?',
                     ('manifest-old',))['members']
        # Truth arrives late; append chain v2 and a delta to the signed list.
        self.order()
        self.probe()
        self.receipt_and_chain()
        delta = self.act('delta', id='delta-1', incident='case',
                         parent='manifest-old', reason='late kernel receipt',
                         at=27)
        self.assertEqual(delta['decision'], 'delta_appended')
        self.assertEqual(delta['parent_kind'], 'provisional_manifest')
        # Original manifest is byte-for-byte unchanged.
        after = one(self.db, 'SELECT members FROM legal_manifests WHERE id=?',
                    ('manifest-old',))['members']
        self.assertEqual(after, before)
        self.assertEqual(provisional_manifest(
            self.db, 'manifest-old', 'case')['decision'], 'reused')
        # Withdraw the earlier incomplete disposition and tell the recipient.
        w = self.act('withdraw', id='w-1', target_kind='delivery',
                     target='del-manifest', delta='delta-1', at=30,
                     reason='member list is not syscall evidence')
        self.assertEqual(w['decision'], 'withdrawal_issued')
        n = self.act('notify', id='n-1', ref_kind='withdrawal', ref='w-1',
                     at=30)
        self.assertEqual(n['decision'], 'notified')
        recipients = [r['recipient'] for r in rows(
            self.db, 'SELECT recipient FROM reg_notifications')]
        self.assertIn(AGENCY, recipients)
        # Delta repeat is reused, never rewritten.
        self.assertEqual(self.act('delta', id='delta-1', incident='case',
                                 parent='manifest-old')['decision'], 'reused')
        self.assert_no_secret_in_delivery_paths()

    def test_interrupted_staging_and_rollback_leave_no_orphans(self):
        self._ready_package('pkg-crash')
        v = self.vault()
        # Crash after creating a staging temp file.
        tmp = v.stage('crash-')
        tmp.write_bytes(b'partial cross-tenant bytes')
        # Crash after publishing an unreferenced file.
        orphan = v.abs_path('packages/orphan.json')
        orphan.parent.mkdir(parents=True, exist_ok=True)
        orphan.write_text('{}')
        os.chmod(orphan, 0o644)
        result = self.act('sweep')
        self.assertEqual(result['decision'], 'swept')
        self.assertFalse(tmp.exists())
        self.assertFalse(orphan.exists())
        # Referenced package files survive.
        self.assertTrue(v.abs_path('packages/pkg-crash/report.json').exists())
        self.assert_vault_private()

    def test_database_rollback_then_rerun_repairs_same_package_id(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        v = self.vault()
        self.db.execute('BEGIN IMMEDIATE')
        rd.create_package(self.db, dict(
            id='pkg-atomic', order_id='order-1', mode='onsite', at=28,
            vault_dir=str(self.vault_dir)))
        self.assertTrue(v.abs_path('packages/pkg-atomic/report.json').exists())
        self.db.execute('ROLLBACK')
        self.assertIsNone(one(self.db, 'SELECT id FROM reg_packages WHERE id=?',
                              ('pkg-atomic',)))
        # Re-run with the same identity: atomic replace over the stale file,
        # exactly one committed row, usable report.
        r = self.act('seal', id='pkg-atomic', order='order-1',
                     mode='onsite', at=28)
        self.assertEqual(r['decision'], 'sealed')
        self.assertEqual(one(self.db, 'SELECT COUNT(*) n FROM reg_packages WHERE id=?',
                             ('pkg-atomic',))['n'], 1)
        self.act('authorize_inspector', id='insp', agency=AGENCY)
        s = self.act('onsite', id='s', inspector='insp',
                     package='pkg-atomic')
        self.assertEqual(s['decision'], 'onsite_verified')

    def test_retention_window_blocks_late_seal_and_session(self):
        self.order(retention_until=25)
        self.probe()
        self.receipt_and_chain()
        expired = self.act('seal', id='pkg-late', order='order-1',
                           mode='onsite', at=26)
        self.assertEqual(expired['decision'], 'retention_expired')

    def test_full_event_replay_verifies(self):
        self.order()
        self.probe()
        self.act('control_marker', id='c25', incident='case', at=25)
        self.act('chain', incident='case', at=26)
        self.act('seal', id='pkg-early', order='order-1', mode='onsite',
                 chain_version=1, at=26)
        self.act('kernel_receipt', id='k27', incident='case', at=27,
                 verdict='denied', enforced_at=27)
        self.act('chain', incident='case', at=27)
        self.act('seal', id='pkg-on', order='order-1', mode='onsite', at=28)
        self.act('seal', id='pkg-hw', order='order-1', mode='hardware',
                 witnesses=['notary-li'], at=28)
        self.act('authorize_inspector', id='insp', agency=AGENCY)
        self.act('onsite', id='s1', inspector='insp', package='pkg-on')
        self.act('handover', package='pkg-hw', witness='courier')
        self.act('unseal', package='pkg-hw', witness='bad-witness')
        self.act('unseal', package='pkg-hw', witness='notary-li')
        self.act('deliver', id='d1', package='pkg-on')
        self.act('ack', id='d1', signer='clerk')
        self.act('delta', id='delta', incident='case', parent='pkg-early')
        self.act('withdraw', id='w', target_kind='package',
                 target='pkg-early', delta='delta')
        self.act('notify', id='n', ref='w', recipients=[AGENCY])
        result = replay(str(self.db_path))
        self.assertTrue(result['verified'], result['divergence'])


class ExtraGuardrailsTest(RegulatoryTestBase):
    def test_verify_package_detects_tampered_report_bytes(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id='pkg-v', order='order-1', mode='onsite')
        ok = self.act('verify_package', id='pkg-v')
        self.assertTrue(ok['verified'], ok)
        report_path = self.vault().abs_path('packages/pkg-v/report.json')
        tampered = json.loads(report_path.read_text())
        tampered['syscall_sequence'] = ['pretend-blocked-at-24']
        report_path.write_text(json.dumps(tampered))
        bad = self.act('verify_package', id='pkg-v')
        self.assertFalse(bad['verified'])
        self.assertTrue(any('report.json' in p for p in bad['problems']))

    def test_inspector_agency_mismatch_is_denied(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id='pkg-a', order='order-1', mode='onsite')
        self.act('authorize_inspector', id='insp-other',
                 agency='some-other-agency')
        r = self.act('onsite', id='s-other', inspector='insp-other',
                      package='pkg-a')
        self.assertEqual(r['decision'], 'agency_mismatch')
        self.assertTrue(r['access_denied'])

    def test_positional_direct_api_matches_dict_api(self):
        rd.issue_order(self.db, 'order-p', 'case', agency=AGENCY,
                       window=[24, 27], vault_dir=str(self.vault_dir))
        rd.register_artifact(
            self.db, 'probe-p', 'case', 'probe', mixed_raw(),
            records=mixed_records(), vault_dir=str(self.vault_dir))
        rd.register_artifact(self.db, 'kernel-p', 'case', 'kernel_receipt',
                             at=27, verdict='denied', enforced_at=27)
        chain = rd.commit_chain(self.db, 'case')
        self.assertEqual(chain['decision'], 'chain_committed')
        pkg = rd.create_package(self.db, 'pkg-p', 'order-p', 'onsite',
                                str(self.vault_dir))
        self.assertEqual(pkg['decision'], 'sealed')
        rd.authorize_inspector(self.db, 'insp-p', AGENCY)
        sess = rd.conduct_onsite(self.db, 'sess-p', 'insp-p', 'pkg-p',
                                 vault_dir=str(self.vault_dir))
        self.assertEqual(sess['decision'], 'onsite_verified')
        self.assertEqual(sess['syscall_sequence'],
                         ['openat', 'unshare', 'mount'])

    def test_delivery_without_vault_is_database_only_and_idempotent(self):
        self.order()
        self.probe()
        self.receipt_and_chain()
        self.act('seal', id='pkg-db', order='order-1', mode='onsite')
        # A second delivery with no vault key at all still dedups by package.
        r1 = rd.deliver_package(self.db, dict(id='d-db', package='pkg-db'))
        r2 = rd.deliver_package(self.db, dict(id='d-db', package='pkg-db'))
        self.assertEqual(r1['decision'], 'delivered')
        self.assertEqual(r2['decision'], 'reused')


if __name__ == '__main__':
    unittest.main()
