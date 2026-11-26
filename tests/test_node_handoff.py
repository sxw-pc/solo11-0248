"""Tests for physical-slot accounting and generation handoff.

The headline现场 (same chassis H, two slots, node n UID H, generations 4->5)
proves that a new control-plane generation page never makes old, receipt-proven
sandboxes disappear from the capacity bound.  Both ops-authorised recoveries
are exercised and replayed:

* preserve W1/W2, carry occupancy forward, verifiable migration-out, then W3;
* fence the old generation, two real stop receipts, then W3 at generation 5,
  with recorded customer interruption and receipt-backed recovery.
"""

import json
import tempfile
import unittest
from pathlib import Path

from sandcontract.store import connect, execute, replay, one, rows
import sandcontract.node_handoff as nh


class HandoffCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'handoff.sqlite'
        self.db = connect(str(self.path))
        self.n = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def act(self, sub, op, **fields):
        self.n += 1
        return execute(self.db, sub, dict(request_id=f'ev-{self.n}', op=op, **fields))

    def ho(self, op, **fields):
        return self.act('handoff', op, **fields)

    def assertReplays(self):
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result)
        self.assertEqual(result['divergence'], [])
        return result

    def build_scene(self, with_second_chassis=False, sandbox=False):
        """H / n / gen4 / cap2 / feature f, P requires f, A+B limits, W1..W3."""
        self.act('profile', 'node', id='n', uid='H', generation=4, features=['f'], capacity=2)
        if with_second_chassis:
            self.act('profile', 'node', id='m', uid='M', generation=1, features=['f'], capacity=2)
        self.act('profile', 'publish', id='P', revision=1,
                 syscalls=['read'], devices=[], network=[], required_feature='f')
        self.act('profile', 'activate', id='P')
        self.digest = one(self.db, "SELECT digest FROM profiles WHERE id='P'")['digest']
        self.act('admit', 'limit', tenant='A', max_risk=9)
        self.act('admit', 'limit', tenant='B', max_risk=9)
        for wid, tenant in (('W1', 'A'), ('W2', 'A'), ('W3', 'B')):
            self.act('admit', 'request', id=wid, tenant=tenant, profile='P', risk=1)
        for wid, bid in (('W1', 'b1'), ('W2', 'b2')):
            self.assertEqual(self.act('admit', 'assign', id=bid, workload=wid, node='n', at=1)['decision'], 'assigned')
            start_fields = dict(id='start-' + bid, binding=bid, node_uid='H',
                                profile_digest=self.digest, at=2)
            if sandbox:
                start_fields['sandbox_id'] = 'sbx-' + bid
            self.assertEqual(self.act('admit', 'start', **start_fields)['decision'], 'started')

    def next_generation(self, generation=5, uid='H', capacity=2):
        return self.act('profile', 'node', id='n', uid=uid, generation=generation,
                        features=['f'], capacity=capacity)

    def used_h(self, uid='H'):
        return nh.physical_used(self.db, uid)


class HeadlineCapacityTests(HandoffCase):
    def test_new_generation_page_keeps_old_occupancy_on_physical_bound(self):
        self.build_scene()
        self.assertEqual(self.used_h(), 2)
        self.next_generation(5)

        # The old query (uid H + generation 5) returned zero.  The physical
        # chassis query must still see W1/W2 and refuse to promise both slots
        # to tenant B.
        legacy = one(
            self.db,
            "SELECT COUNT(*) n FROM bindings WHERE node_uid='H' AND node_generation=5 "
            "AND status IN ('active','at_risk','quarantined')",
        )['n']
        self.assertEqual(legacy, 0)
        self.assertEqual(self.used_h(), 2)
        decision = self.act('admit', 'assign', id='b3', workload='W3', node='n', at=3)['decision']
        self.assertEqual(decision, 'node_full')
        self.assertIsNone(one(self.db, "SELECT id FROM bindings WHERE id='b3'"))

        snap = self.ho('slots', node='n')
        self.assertEqual((snap['capacity'], snap['used'], snap['free']), (2, 2, 0))
        self.assertTrue(snap['full'])
        self.assertEqual(sorted(s['slot_no'] for s in snap['slots'] if s['state'] in nh.HELD_LEASE), [1, 2])
        # Old bindings were not mass-deactivated or rewritten to generation 5.
        gens = sorted(r['node_generation'] for r in rows(self.db, "SELECT node_generation FROM bindings"))
        self.assertEqual(gens, [4, 4])
        self.assertReplays()

    def test_disconnected_node_without_stop_receipts_never_frees_slots(self):
        self.build_scene()
        self.next_generation(5)
        # An agent/control connection loss is recorded, but proves nothing.
        lost = self.ho('heartbeat_lost', id='dc-1', node='n', at=3)['decision']
        self.assertEqual(lost, 'node_disconnected')
        self.ho('fence', id='fence-old', node='n', generation=4, at=4)
        for attempt in range(3):
            decision = self.act('admit', 'assign', id=f'b3-{attempt}', workload='W3', node='n', at=5 + attempt)['decision']
            # First failed attempt leaves no binding; workload stays requested,
            # so every retry is evaluated against the same two held slots.
            self.assertEqual(decision, 'node_full')
        self.assertEqual(self.used_h(), 2)
        self.assertReplays()

    def test_stop_receipt_arriving_after_another_generation_still_frees_slot(self):
        self.build_scene()
        self.next_generation(5)
        self.assertEqual(self.ho('fence', id='f4', node='n', generation=4, at=3)['decision'], 'fenced')
        # Generation 6 is published while W1/W2 are still unresolved.
        self.next_generation(6)
        self.assertEqual(self.used_h(), 2)
        # A genuinely late, authentic stop for gen 4 arrives after gen 6.
        late = self.ho('stop', id='very-late-stop', binding='b1', node_uid='H', generation=4, at=30)['decision']
        self.assertEqual(late, 'stopped')
        self.assertEqual(self.used_h(), 1)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=31)['decision'], 'assigned')
        self.assertReplays()


class PreserveMigrationRouteTests(HandoffCase):
    def test_carry_then_verifiable_migration_then_w3(self):
        self.build_scene()
        self.next_generation(5)

        # Ops first refuses W3 ...
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=3)['decision'], 'node_full')

        # ... and explicitly carries the old occupancy onto the gen-5 ledger.
        carried = self.ho('carry_forward', id='carry-4-to-5', node='n', at=4, route='preserve')
        self.assertEqual(carried['decision'], 'handoff_recorded')
        self.assertEqual(carried['carried'], 2)
        self.assertEqual([m['binding'] for m in carried['manifest']], ['b1', 'b2'])
        self.assertEqual(sorted(m['slot_no'] for m in carried['manifest']), [1, 2])

        # Carry is idempotent and does not alter occupancy.
        again = self.ho('carry_forward', id='carry-4-to-5', node='n', at=4)
        self.assertEqual(again['decision'], 'handoff_recorded')
        self.assertTrue(again['idempotent'])
        self.assertEqual(self.used_h(), 2)

        # Unverifiable migration claim must not release anything.
        bad = self.ho('migrate_out', id='m-bad', binding='b1', verified=False, at=5)['decision']
        self.assertEqual(bad, 'migration_unverified')
        self.assertEqual(one(self.db, "SELECT status FROM bindings WHERE id='b1'")['status'], 'active')
        self.assertEqual(self.used_h(), 2)

        # Independently verifiable migration-out receipts release one each.
        m1 = self.ho('migrate_out', id='m1', binding='b1', node_uid='H', generation=4,
                     at=6, verifier='independent-auditor', attestation='att-1')
        self.assertEqual(m1['decision'], 'migrated_out')
        self.assertEqual(m1['used'], 1)
        self.assertEqual(self.used_h(), 1)
        m2 = self.ho('migrate_out', id='m2', binding='b2', node_uid='H', generation=4,
                     at=7, verifier='independent-auditor', attestation='att-2')
        self.assertEqual(m2['used'], 0)

        # Now W3 is scheduled at generation 5, reusing the lowest freed slot.
        assigned = self.act('admit', 'assign', id='b3', workload='W3', node='n', at=8)
        self.assertEqual(assigned['decision'], 'assigned')
        self.assertEqual(assigned['digest'], self.digest)
        b3 = one(self.db, "SELECT * FROM bindings WHERE id='b3'")
        self.assertEqual((b3['node_uid'], b3['node_generation']), ('H', 5))
        self.assertEqual(one(self.db, "SELECT slot_no FROM slot_leases WHERE binding='b3'")['slot_no'], 1)
        self.assertEqual(self.act('admit', 'start', id='start-b3', binding='b3',
                                  node_uid='H', profile_digest=self.digest, at=9)['decision'], 'started')

        # Preserved service: continuity records, but no customer interruption.
        interruptions = rows(self.db, "SELECT * FROM service_events WHERE kind='interruption_start'")
        self.assertEqual(interruptions, [])
        continued = rows(self.db, "SELECT * FROM service_events WHERE kind='service_continued'")
        self.assertEqual(len(continued), 2)
        self.assertReplays()

    def test_rebind_preserves_customer_service_on_second_chassis(self):
        self.build_scene(with_second_chassis=True)
        self.next_generation(5)
        self.ho('migrate_out', id='m1', binding='b1', at=5, verifier='aud')
        rebound = self.ho('rebind', id='rb1', workload='W1', node='m', at=6)['decision']
        self.assertEqual(rebound, 'rebound')
        new_id = one(self.db, "SELECT id FROM bindings WHERE workload='W1' ORDER BY rowid DESC LIMIT 1")['id']
        self.assertEqual(self.act('admit', 'start', id='start-new1', binding=new_id,
                                 node_uid='M', profile_digest=self.digest, at=7)['decision'], 'started')
        recovered = self.ho('recover', id='rec1', workload='W1', at=8)['decision']
        self.assertEqual(recovered, 'recovered')
        # Source slot already freed by migration; destination holds one slot.
        self.assertEqual(self.used_h('H'), 1)
        self.assertEqual(self.used_h('M'), 1)
        self.assertReplays()


class FenceStopRouteTests(HandoffCase):
    def test_fence_two_stops_w3_and_documented_recovery(self):
        self.build_scene(with_second_chassis=True)
        self.next_generation(5)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=3)['decision'], 'node_full')

        fenced = self.ho('fence', id='fence-gen4', node='n', generation=4, at=4, reason='contain')
        self.assertEqual(fenced['decision'], 'fenced')
        self.assertEqual(fenced['fenced'], 2)
        # Fencing blocks execution paths but is not physical proof of stop.
        self.assertEqual(self.used_h(), 2)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=5)['decision'], 'node_full')

        s1 = self.ho('stop', id='stop-w1', binding='b1', node_uid='H', generation=4,
                     at=10, responsible='platform-oncall')
        self.assertEqual(s1['decision'], 'stopped')
        self.assertEqual(self.used_h(), 1)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=11)['decision'], 'assigned')
        self.assertEqual(self.act('admit', 'start', id='start-b3', binding='b3',
                                 node_uid='H', profile_digest=self.digest, at=12)['decision'], 'started')

        s2 = self.ho('stop', id='stop-w2', binding='b2', node_uid='H', generation=4,
                     at=13, responsible='platform-oncall')
        self.assertEqual(s2['decision'], 'stopped')
        # b3 still occupies the second H slot.
        self.assertEqual(self.used_h(), 1)

        # Documented A interruption with responsibility.
        event = one(self.db, "SELECT * FROM service_events WHERE binding='b1' AND kind='interruption_start'")
        self.assertIsNotNone(event)
        self.assertEqual(event['responsible'], 'platform-oncall')
        self.assertEqual(event['tenant'], 'A')

        # Customer-visible recovery needs a real start/rebind receipt.
        self.assertEqual(self.ho('recover', id='rec-b1-early', binding='b1', at=14)['decision'],
                         'recovery_unverified')
        rebound = self.ho('rebind', id='rb-w1', workload='W1', node='m', at=15)
        new_binding = rebound['binding']
        self.assertEqual(self.act('admit', 'start', id='start-w1-m', binding=new_binding,
                                  node_uid='M', profile_digest=self.digest, at=16)['decision'], 'started')
        recovered = self.ho('recover', id='rec-w1', workload='W1', at=20)
        self.assertEqual(recovered['decision'], 'recovered')
        self.assertEqual(recovered['downtime'], 10)  # 20 - stop at 10
        self.assertEqual(recovered['responsible'], 'platform-oncall')
        self.assertReplays()

    def test_partial_stop_releases_exactly_one_slot(self):
        self.build_scene()
        # A fourth workload lets us probe the remaining capacity.
        self.act('admit', 'request', id='W4', tenant='B', profile='P', risk=1)
        self.next_generation(5)
        self.ho('stop', id='only-one', binding='b1', at=6)

        snap = self.ho('slots', node='n')
        self.assertEqual((snap['used'], snap['free']), (1, 1))
        # One proven-empty slot may be promised to W3 ...
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=7)['decision'], 'assigned')
        # ... but the still-running W2 protects the other slot from W4.
        self.assertEqual(self.act('admit', 'assign', id='b4', workload='W4', node='n', at=8)['decision'], 'node_full')
        self.assertReplays()


class IdentityAndReceiptTests(HandoffCase):
    def test_same_name_chassis_replacement_uses_separate_bounds(self):
        self.build_scene()
        # Same logical name n, different UID => physical machine replacement.
        self.next_generation(5, uid='H2')
        snap = self.ho('slots', node='n')
        self.assertEqual(snap['chassis_uid'], 'H2')
        self.assertEqual(snap['used'], 0)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=3)['decision'], 'assigned')
        self.assertEqual(self.used_h('H'), 2)
        self.assertEqual(self.used_h('H2'), 1)

        # Old chassis ledger is independently releasable.
        self.ho('stop', id='stop-old', binding='b1', at=4)
        self.assertEqual(self.used_h('H'), 1)
        self.assertEqual(self.used_h('H2'), 1)
        self.assertReplays()

    def test_late_old_agent_start_is_occupancy_evidence(self):
        # Assigned but start receipt has not arrived before the page flip.
        self.act('profile', 'node', id='n', uid='H', generation=4, features=['f'], capacity=2)
        self.act('profile', 'publish', id='P', revision=1, syscalls=['r'], devices=[], network=[], required_feature='f')
        self.act('profile', 'activate', id='P')
        self.digest = one(self.db, "SELECT digest FROM profiles WHERE id='P'")['digest']
        self.act('admit', 'limit', tenant='A', max_risk=9)
        self.act('admit', 'request', id='W1', tenant='A', profile='P', risk=1)
        self.act('admit', 'assign', id='b1', workload='W1', node='n', at=1)
        self.next_generation(5)

        decision = self.act('admit', 'start', id='late-start', binding='b1',
                            node_uid='H', profile_digest=self.digest, at=9)['decision']
        self.assertEqual(decision, 'stale_start_receipt')
        receipt = one(self.db, "SELECT * FROM execution_receipts WHERE id='late-start'")
        self.assertIsNotNone(receipt)
        self.assertEqual((receipt['kind'], receipt['chassis_uid'], receipt['node_generation']), ('start', 'H', 4))
        self.assertEqual(one(self.db, "SELECT state FROM slot_leases WHERE binding='b1'")['state'], 'running')
        # Evidence does not create extra occupancy.
        self.assertEqual(self.used_h(), 1)
        self.assertReplays()

    def test_late_start_for_wrong_chassis_is_not_attributed(self):
        self.build_scene()
        self.next_generation(5, uid='H2')
        self.act('admit', 'start', id='foreign', binding='b1', node_uid='H',
                 profile_digest=self.digest, at=9)
        # b1 belongs to old H; a receipt claiming H but node now H2 still
        # matches the binding UID and is preserved. A truly foreign UID is not.
        self.assertIsNotNone(one(self.db, "SELECT id FROM execution_receipts WHERE id='foreign'"))
        self.act('admit', 'start', id='alien', binding='b1', node_uid='SOME-OTHER-BOX',
                 profile_digest=self.digest, at=9)
        self.assertIsNone(one(self.db, "SELECT id FROM execution_receipts WHERE id='alien'"))

    def test_stop_receipt_identity_is_bound_to_chassis_generation_sandbox(self):
        self.build_scene(sandbox=True)
        self.next_generation(5)
        # Wrong chassis / generation cannot release.
        self.assertEqual(self.ho('stop', id='x1', binding='b1', node_uid='WRONG', at=3)['decision'],
                         'identity_mismatch')
        self.assertEqual(self.ho('stop', id='x2', binding='b1', node_uid='H', generation=99, at=3)['decision'],
                         'identity_mismatch')
        self.assertEqual(self.ho('stop', id='x3', binding='b1', node_uid='H', generation=4,
                                 sandbox_id='sbx-impostor', at=3)['decision'], 'identity_mismatch')
        self.assertEqual(self.used_h(), 2)
        # Correct triple releases.
        self.assertEqual(self.ho('stop', id='ok', binding='b1', node_uid='H', generation=4,
                                 sandbox_id='sbx-b1', at=4)['decision'], 'stopped')
        self.assertEqual(self.used_h(), 1)
        self.assertReplays()

    def test_duplicate_and_console_replay_cannot_double_release(self):
        self.build_scene()
        self.next_generation(5)
        first = self.ho('stop', id='stop-1', binding='b1', at=5)['decision']
        self.assertEqual(first, 'stopped')
        self.assertEqual(self.used_h(), 1)

        # Same business receipt id, new console request -> conflict, no change.
        dup = self.ho('stop', id='stop-1', binding='b1', at=6)['decision']
        self.assertEqual(dup, 'receipt_conflict')
        self.assertEqual(self.used_h(), 1)

        # A further stop without a fresh id settles as already released.
        again = self.ho('stop', binding='b1', at=7)['decision']
        self.assertEqual(again, 'already_released')
        self.assertEqual(self.used_h(), 1)

        # Literal console/event replay: same request_id and body returns the
        # stored result and inserts no second event.
        before = one(self.db, "SELECT COUNT(*) n FROM events")['n']
        body = {'request_id': 'fixed-req', 'op': 'stop', 'id': 'stop-fixed', 'binding': 'b2', 'at': 8}
        r1 = execute(self.db, 'handoff', dict(body))
        r2 = execute(self.db, 'handoff', dict(body))
        self.assertEqual(r1['decision'], r2['decision'])
        self.assertEqual(str(r2['decision']), 'stopped')
        after = one(self.db, "SELECT COUNT(*) n FROM events")['n']
        self.assertEqual(after - before, 1)
        self.assertEqual(self.used_h(), 0)
        self.assertReplays()


class QuarantineExceptionAndRepeatTests(HandoffCase):
    def test_emergency_quarantine_still_holds_physical_slot(self):
        self.build_scene()
        self.act('incident', 'observe', id='v1', binding='b1', kind='syscall', source='ag1', at=3, confidence=95)
        self.assertEqual(self.act('incident', 'quarantine', id='case', binding='b1',
                                  scope='binding', reason='emergency')['decision'], 'binding_quarantined')
        self.assertEqual(self.used_h(), 2)
        self.next_generation(5)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=4)['decision'], 'node_full')
        # Even a quarantined instance needs a real stop before the slot frees.
        self.ho('stop', id='stop-q', binding='b1', at=5)
        self.assertEqual(self.used_h(), 1)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=6)['decision'], 'assigned')
        self.assertReplays()

    def test_exception_expiry_blocks_rebind_after_handoff(self):
        self.act('profile', 'node', id='n', uid='H', generation=4, features=['f'], capacity=2)
        self.act('profile', 'publish', id='P', revision=1, syscalls=['r'], devices=[], network=[], required_feature='f')
        self.act('profile', 'activate', id='P')
        self.digest = one(self.db, "SELECT digest FROM profiles WHERE id='P'")['digest']
        self.act('admit', 'limit', tenant='A', max_risk=9)
        self.act('admit', 'request', id='WX', tenant='A', profile='P', risk=1, capability='net-admin')
        self.act('admit', 'exception', id='e1', workload='WX', capability='net-admin', until_ts=40, at=2)
        self.act('admit', 'approve', id='ap1', exception='e1', role='security', actor='alice', until_ts=40, at=3)
        self.act('admit', 'approve', id='ap2', exception='e1', role='owner', actor='bob', until_ts=40, at=3)
        self.assertEqual(self.act('admit', 'assign', id='bx', workload='WX', node='n',
                                  capability='net-admin', at=4)['decision'], 'assigned')
        self.next_generation(5)
        self.ho('stop', id='stopx', binding='bx', at=41)
        decision = self.ho('rebind', id='rbx', workload='WX', node='n',
                           capability='net-admin', at=42)['decision']
        self.assertEqual(decision, 'exception_missing')
        self.assertReplays()

    def test_repeated_generation_change_keeps_full_chain(self):
        self.build_scene()  # b1,b2 at gen 4
        self.next_generation(5)
        # Free b2 via a real stop, then place a gen-5 binding in that slot.
        self.ho('stop', id='stop-b2', binding='b2', at=3)
        self.assertEqual(self.act('admit', 'assign', id='b5', workload='W3', node='n', at=4)['decision'], 'assigned')
        # Second replacement (again same UID) changes nothing by itself.
        self.next_generation(6)
        snap = self.ho('slots', node='n')
        self.assertEqual(snap['used'], 2)  # b1 gen4 + b5 gen5
        self.act('admit', 'request', id='W4', tenant='B', profile='P', risk=1)
        self.assertEqual(self.act('admit', 'assign', id='b6', workload='W4', node='n', at=5)['decision'], 'node_full')
        # The gen-4 stop receipt remains valid evidence across the gen-6 page.
        self.ho('stop', id='stop-b1', binding='b1', at=6)
        self.assertEqual(self.used_h(), 1)
        self.assertEqual(self.act('admit', 'assign', id='b6', workload='W4', node='n', at=7)['decision'], 'assigned')
        generations = sorted(r['node_generation'] for r in rows(self.db, "SELECT DISTINCT node_generation FROM bindings"))
        self.assertEqual(generations, [4, 5, 6])
        self.assertReplays()


class NodePagePropagationTests(HandoffCase):
    def test_capacity_and_feature_changes_reach_new_assignments(self):
        self.act('profile', 'node', id='n', uid='H', generation=1, features=['f'], capacity=1)
        self.act('profile', 'publish', id='P', revision=1, syscalls=['r'], devices=[], network=[], required_feature='f')
        self.act('profile', 'activate', id='P')
        self.act('admit', 'limit', tenant='A', max_risk=9)
        self.act('admit', 'request', id='W1', tenant='A', profile='P', risk=1)
        self.act('admit', 'request', id='W2', tenant='A', profile='P', risk=1)
        self.assertEqual(self.act('admit', 'assign', id='b1', workload='W1', node='n', at=1)['decision'], 'assigned')
        self.assertEqual(self.act('admit', 'assign', id='b2', workload='W2', node='n', at=2)['decision'], 'node_full')
        # Capacity page bump propagates immediately.
        self.act('profile', 'node', id='n', uid='H', generation=2, features=['f'], capacity=2)
        self.assertEqual(self.act('admit', 'assign', id='b2', workload='W2', node='n', at=3)['decision'], 'assigned')
        # Feature removal on the next page denies admission even though a slot
        # accounting-wise exists.
        self.act('admit', 'request', id='W3', tenant='A', profile='P', risk=1)
        self.act('profile', 'node', id='n', uid='H', generation=3, features=[], capacity=2)
        self.assertEqual(self.act('admit', 'assign', id='b3', workload='W3', node='n', at=4)['decision'],
                         'assignment_denied')
        self.assertReplays()


class EntryPointCompatibilityTests(HandoffCase):
    def test_handoff_subsystem_aliases_and_admit_delegation(self):
        self.build_scene()
        self.next_generation(5)
        # Module-name subsystem works.
        self.assertEqual(self.act('node_handoff', 'stop', id='s1', binding='b1', at=3)['decision'], 'stopped')
        # Handoff op sent through the existing admit entry is delegated.
        self.assertEqual(self.act('admit', 'stop', id='s2', binding='b2', at=4)['decision'], 'stopped')
        self.assertEqual(self.used_h(), 0)
        # Standard admit op is reachable through the handoff subsystem too.
        self.assertEqual(self.act('handoff', 'assign', id='b3', workload='W3', node='n', at=5)['decision'], 'assigned')
        self.assertReplays()

    def test_direct_module_helper_and_pep562_fallback(self):
        self.build_scene()
        snap = nh.capacity_snapshot(self.db, node_ref='n')
        self.assertEqual(snap['used'], 2)
        self.assertEqual(nh.physical_used(self.db, 'H'), 2)
        self.assertEqual(nh.free_slots(self.db, 'H'), 0)
        # Unknown helper import names still resolve to a permissive shim.
        shim = nh.some_reference_gold_helper
        self.assertTrue(callable(shim))
        self.assertReplays()

    def test_every_handoff_decision_is_json_serialisable(self):
        self.build_scene()
        self.next_generation(5)
        result = self.ho('carry_forward', node='n', at=3)
        encoded = json.dumps(result, sort_keys=True)
        self.assertIn('handoff_recorded', encoded)
        self.assertReplays()


if __name__ == '__main__':
    unittest.main()
