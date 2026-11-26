import json
import tempfile
import unittest
from pathlib import Path

from sandcontract.store import connect, execute, replay, one, rows
from sandcontract.incident_indemnity import downtime_minutes, bank_position, UNAVAILABILITY

ROOT = Path(__file__).resolve().parents[1]
TENANT = 'tenant-a'
WORKLOAD = 'workload-a'
BINDING = 'binding-a'
INCIDENT = 'incident-a'
POLICY_A = 'insurer-A'   # business interruption cover
POLICY_B = 'insurer-B'   # on-site response / forensics cover
RATE = 10
PLATFORM = 'platform-co'
CUSTOMER = 'tenant-T'


class IndemnityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'state.sqlite'))
        self.n = 0
        for name in ('profile_normal', 'admit_normal'):
            for x in json.loads((ROOT / 'fixtures' / f'{name}.json').read_text(encoding='utf8')):
                execute(self.db, x.get('subsystem', name.split('_')[0]), x)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def ind(self, op, **fields):
        self.n += 1
        return execute(self.db, 'indemnity',
                       dict(request_id=f'ind-{self.n}', op=op, **fields))

    def inc(self, op, **fields):
        self.n += 1
        return execute(self.db, 'incident',
                       dict(request_id=f'case-{self.n}', op=op, **fields))

    def open_incident(self, scope='binding'):
        self.inc('observe', id='v1', binding=BINDING, kind='syscall', source='agent-a',
                 at=15, confidence=95)
        if scope == 'tenant':
            self.inc('observe', id='v2', binding=BINDING, kind='syscall', source='agent-b',
                     at=16, confidence=90)
        return self.inc('quarantine', id=INCIDENT, binding=BINDING, scope=scope,
                        reason='forbidden syscall')

    def release_incident(self, at=34):
        self.inc('reset', id='reset-a', binding=BINDING,
                 node_uid='node-uid-a', new_digest=self._new_digest(), at=at - 2)
        return self.inc('release', incident=INCIDENT, new_profile='profile-a', at=at)

    def _new_digest(self):
        # publish + activate revision 2 like the incident fixtures do
        execute(self.db, 'profile',
                dict(request_id=f'pub-{self.n}-1', op='publish', id='profile-a', revision=2,
                     syscalls=['read'], devices=['null'], network=[], required_feature='seccomp'))
        execute(self.db, 'profile',
                dict(request_id=f'act-{self.n}-1', op='activate', id='profile-a'))
        return one(self.db, 'SELECT digest FROM profiles WHERE id=?', ('profile-a',))['digest']

    def standard_facts(self, isolation=20, release=32, ready=36, recovery=37,
                       window=(10, 50)):
        self.ind('run_window', id='win', workload=WORKLOAD,
                 start_min=window[0], end_min=window[1])
        self.ind('isolation', id='iso', incident=INCIDENT, at=isolation)
        self.ind('node_ready', id='ready', incident=INCIDENT, at=ready)
        self.ind('recovery', id='rec', incident=INCIDENT, at=recovery)
        return release

    def standard_policies(self, a_terms=None, b_terms=None):
        a = dict(id=POLICY_A, revision=1, effective_at=1,
                 covers=[UNAVAILABILITY, 'investigation', 'extra_compute'],
                 waiting_min=0, cap=None, coinsurance=1.0, exclusions=[])
        b = dict(id=POLICY_B, revision=1, effective_at=1,
                 covers=['forensics'], waiting_min=0, cap=None,
                 coinsurance=1.0, exclusions=[])
        if a_terms:
            a.update(a_terms)
        if b_terms:
            b.update(b_terms)
        self.assertEqual(self.ind('policy', **a)['decision'], 'policy_recorded')
        self.assertEqual(self.ind('policy', **b)['decision'], 'policy_recorded')

    def standard_notices(self, both_claim_unavailability=True):
        lines_a = [{'id': 'la-u', 'line_type': UNAVAILABILITY, 'amount': 170},
                   {'id': 'la-inv', 'line_type': 'investigation', 'voucher_id': 'v-inv'},
                   {'id': 'la-ec', 'line_type': 'extra_compute', 'voucher_id': 'v-ec'}]
        lines_b = [{'id': 'lb-u', 'line_type': UNAVAILABILITY, 'amount': 170},
                   {'id': 'lb-fo', 'line_type': 'forensics', 'voucher_id': 'v-fo'}]
        if not both_claim_unavailability:
            lines_b = [lines_b[1]]
        ra = self.ind('notice', notice='notice-A', incident=INCIDENT, policy=POLICY_A, at=21,
                      lines=lines_a)
        rb = self.ind('notice', notice='notice-B', incident=INCIDENT, policy=POLICY_B, at=22,
                      lines=lines_b)
        return ra, rb

    def standard_fees_and_credit(self):
        self.assertEqual(self.ind('fee', id='v-inv', incident=INCIDENT, kind='investigation',
                                  amount=30)['decision'], 'fee_recorded')
        self.assertEqual(self.ind('fee', id='v-ec', incident=INCIDENT, kind='extra_compute',
                                  amount=20)['decision'], 'fee_recorded')
        self.assertEqual(self.ind('fee', id='v-fo', incident=INCIDENT, kind='forensics',
                                  amount=50)['decision'], 'fee_recorded')
        self.assertEqual(self.ind('credit', id='cr-early', incident=INCIDENT, minutes=8,
                                  amount=80)['decision'], 'credit_recorded')

    def settle(self, route, settlement='set-1'):
        return self.ind('settle', settlement=settlement, incident=INCIDENT, route=route,
                        minute_rate=RATE, customer=CUSTOMER, platform=PLATFORM, at=40)

    def payable(self, settlement='set-1'):
        return rows(self.db, "SELECT * FROM settlement_lines WHERE settlement=? AND status='payable'",
                    (settlement,))

    def denied_reasons(self, settlement='set-1'):
        return [r['denied_reason'] for r in
                rows(self.db, "SELECT * FROM settlement_lines WHERE settlement=? AND status='denied'",
                     (settlement,))]

    # ------------------------------------------------------------------
    def test_notice_requires_incident_and_rejects_duplicate(self):
        self.assertEqual(self.ind('notice', notice='n1', incident='ghost', policy=POLICY_A,
                                  at=5, lines=[])['decision'], 'unavailable')
        self.open_incident()
        self.standard_policies()
        self.assertEqual(self.ind('notice', notice='n1', incident=INCIDENT, policy=POLICY_A,
                                  at=21, lines=[])['decision'], 'drafted')
        # same notice id reused against another policy is a conflict, not a second draft
        self.assertEqual(self.ind('notice', notice='n1', incident=INCIDENT, policy=POLICY_B,
                                  at=22, lines=[])['decision'], 'notice_conflict')
        # identical resubmission is idempotent reuse rather than a new notice
        self.assertEqual(self.ind('notice', notice='n1', incident=INCIDENT, policy=POLICY_A,
                                  at=23, lines=[])['decision'], 'reused')

    def test_downtime_needs_execution_facts_not_incident_clocks(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices()
        # open/release database times alone never define downtime
        self.release_incident()
        dt = downtime_minutes(self.db, INCIDENT)
        self.assertFalse(dt['complete'])
        self.assertEqual(dt['minutes'], 0)
        self.assertIsNone(dt['start'])
        # even after isolation + node-ready, without customer confirmation no end
        self.ind('run_window', id='win', workload=WORKLOAD, start_min=10, end_min=50)
        self.ind('isolation', id='iso', incident=INCIDENT, at=20)
        self.ind('node_ready', id='ready', incident=INCIDENT, at=36)
        dt = downtime_minutes(self.db, INCIDENT)
        self.assertFalse(dt['complete'])
        self.assertIsNone(dt['end'])
        # recovery at 37 while control-plane release was 32: real interval is 20-37
        self.assertEqual(self.ind('recovery', id='rec', incident=INCIDENT, at=37)['decision'],
                         'fact_recorded')
        dt = downtime_minutes(self.db, INCIDENT)
        self.assertTrue(dt['complete'])
        self.assertEqual((dt['start'], dt['end'], dt['minutes']), (20, 37, 17))
        # facts cannot be reordered: ready before isolation is rejected
        self.assertEqual(self.ind('node_ready', id='ready2', incident=INCIDENT,
                                  at=19)['decision'], 'timeline_order_violation')
        self.assertEqual(self.ind('isolation', id='iso2', incident=INCIDENT,
                                  at=21)['decision'], 'fact_conflict')

    def test_settle_before_full_evidence_is_refused(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices()
        self.ind('run_window', id='win', workload=WORKLOAD, start_min=10, end_min=50)
        self.ind('isolation', id='iso', incident=INCIDENT, at=20)
        r = self.settle('insurer_direct')
        self.assertEqual(r['decision'], 'downtime_incomplete')
        self.assertFalse(r['complete'])
        self.assertIsNone(one(self.db, 'SELECT id FROM settlements WHERE incident=?', (INCIDENT,)))

    def test_insurer_direct_route_no_double_recovery(self):
        self.open_incident()
        self.standard_policies()
        ra, rb = self.standard_notices()
        self.assertEqual(ra['policy_revision'], 1)
        self.assertEqual(rb['policy_revision'], 1)
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        r = self.settle('insurer_direct')
        self.assertEqual(r['decision'], 'settled')
        # the 17-minute truth survives, not the 12-minute open->release shortcut
        self.assertEqual(r['downtime_minutes'], 17)
        self.assertEqual(r['interval'], {'start': 20, 'end': 37})
        self.assertEqual(r['total_loss'], 170)
        # customer keeps the 8-minute early credit and gets 9 minutes in cash only
        self.assertEqual(r['platform_credit_minutes'], 8)
        self.assertEqual(r['platform_credit_amount'], 80)
        self.assertEqual(r['customer_cash'], 90)
        self.assertEqual(r['customer_total'], 170)
        # every unavailability fragment is allocated exactly once
        unavail = [l for l in r['lines'] if l['line_type'] == UNAVAILABILITY]
        payable_u = [l for l in unavail if l['status'] == 'payable']
        self.assertEqual(len(payable_u), 9)
        self.assertTrue(all(l['payee'] == CUSTOMER and l['policy'] == POLICY_A
                            for l in payable_u))
        self.assertEqual(sum(l['amount'] for l in payable_u), 90)
        # B's copy of the customer-credit line never pays: excluded cover
        b_u = [l for l in unavail if l['notice'] == 'notice-B']
        self.assertTrue(b_u)
        self.assertTrue(all(l['status'] == 'denied' and l['denied_reason'] == 'coverage_excluded'
                            for l in b_u))
        # A does not re-pay minutes already credited to the customer
        offsets = self.denied_reasons()
        self.assertEqual(offsets.count('platform_credit_offset'), 8)
        # fees belong to their own category; B only pays independently verified forensics
        fee_pay = [l for l in self.payable() if l['line_type'] != UNAVAILABILITY]
        by_kind = {l['line_type']: l for l in fee_pay}
        self.assertEqual(by_kind['investigation']['amount'], 30)
        self.assertEqual(by_kind['investigation']['policy'], POLICY_A)
        self.assertEqual(by_kind['extra_compute']['amount'], 20)
        self.assertEqual(by_kind['extra_compute']['policy'], POLICY_A)
        # forensics still disputed -> not payable until independently verified
        self.assertNotIn('forensics', by_kind)
        self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
        # verification after settlement cannot rewrite the locked ledger
        self.assertEqual(one(self.db, "SELECT amount FROM fee_vouchers WHERE id='v-fo'")
                         ['amount'], 50)
        # platform receivables are only the fee items; nothing owed on credited minutes
        self.assertEqual(r['platform_receivable'], 50)
        # single settlement only
        self.assertEqual(self.settle('insurer_direct')['decision'], 'settlement_conflict')

    def test_forensics_verification_feeds_only_policy_b_once(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
        r = self.settle('insurer_direct', settlement='set-fo')
        fo = [l for l in r['lines'] if l['line_type'] == 'forensics']
        pay = [l for l in fo if l['status'] == 'payable']
        self.assertEqual(len(pay), 1)
        self.assertEqual(pay[0]['amount'], 40)
        self.assertEqual(pay[0]['policy'], POLICY_B)
        self.assertEqual(pay[0]['payee'], PLATFORM)
        # a late duplicate report of the same voucher creates no second benefit
        self.assertEqual(self.ind('fee', id='v-fo-copy', incident=INCIDENT, kind='forensics',
                                  amount=50)['decision'], 'fee_recorded')
        # without a claim line it simply never enters the ledger; assert no fragment reuse
        frags = [l['fragment'] for l in self.payable('set-fo')]
        self.assertEqual(len(frags), len(set(frags)))

    def test_platform_topup_route_indemnifies_platform_for_credits(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices()
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        r = self.settle('platform_topup', settlement='set-top')
        self.assertEqual(r['decision'], 'settled')
        # platform tops credits up from 8 to the full 17 minutes
        self.assertEqual(r['platform_credit_minutes'], 17)
        self.assertEqual(r['platform_credit_amount'], 170)
        self.assertEqual(r['customer_cash'], 0)
        self.assertEqual(r['customer_total'], 170)
        # A now pays the platform the bank value of the credits it funded
        u_pay = [l for l in self.payable('set-top') if l['line_type'] == UNAVAILABILITY]
        self.assertEqual(len(u_pay), 17)
        self.assertTrue(all(l['payee'] == PLATFORM and l['policy'] == POLICY_A for l in u_pay))
        self.assertEqual(sum(l['amount'] for l in u_pay), 170)
        # receivable equals bank-real value; B still owes nothing on unavailability
        self.assertEqual(r['platform_receivable'], 170 + 30 + 20)
        self.assertTrue(all(l['policy'] != POLICY_B for l in u_pay))

    def test_bounced_payment_keeps_booked_right_and_bank_apart(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
        self.standard_facts()
        self.release_incident()
        r = self.settle('insurer_direct', settlement='set-bank')
        due = rows(self.db, "SELECT * FROM payments WHERE settlement='set-bank' AND status='booked'")
        a_due = sum(p['amount'] for p in due if p['policy'] == POLICY_A)
        self.assertEqual(a_due, 90 + 30 + 20)
        b_due = sum(p['amount'] for p in due if p['policy'] == POLICY_B)
        self.assertEqual(b_due, 40)
        # A presents part, then one transfer bounces; receivable stays on the books
        self.assertEqual(self.ind('payment', id='pay-1', settlement='set-bank', policy=POLICY_A,
                                  payee=CUSTOMER, amount=90, status='presented', at=41,
                                  bank_reference='tx-1')['decision'], 'payment_recorded')
        self.assertEqual(self.ind('payment', id='pay-2', settlement='set-bank', policy=POLICY_A,
                                  payee=PLATFORM, amount=50, status='bounced', at=42,
                                  bank_reference='tx-2')['decision'], 'payment_recorded')
        pos = bank_position(self.db, 'set-bank')
        self.assertEqual(pos[POLICY_A]['booked'], 140)
        self.assertEqual(pos[POLICY_A]['presented'], 90)
        self.assertEqual(pos[POLICY_A]['bounced'], 50)
        self.assertEqual(pos[POLICY_A]['received'], 40)
        # re-presented transfer restores the cash without creating a new obligation
        self.assertEqual(self.ind('payment', id='pay-3', settlement='set-bank', policy=POLICY_A,
                                  payee=PLATFORM, amount=50, status='re_presented', at=44,
                                  bank_reference='tx-3')['decision'], 'payment_recorded')
        pos = bank_position(self.db, 'set-bank')
        self.assertEqual(pos[POLICY_A]['received'], 90)
        self.assertEqual(pos[POLICY_A]['booked'], 140)
        self.assertEqual(self.ind('payment', id='pay-1', settlement='set-bank', policy=POLICY_A,
                                  payee=CUSTOMER, amount=90, status='presented', at=45,
                                  bank_reference='dup')['decision'], 'duplicate_payment')

    def test_waiting_period_cap_and_coinsurance(self):
        self.open_incident()
        self.standard_policies(a_terms=dict(waiting_min=2, cap=100, coinsurance=0.5))
        # B only covers forensics; A is the sole unavailability carrier
        self.assertEqual(self.ind('notice', notice='notice-A', incident=INCIDENT, policy=POLICY_A,
                                  at=21, lines=[
                                      {'id': 'la-u', 'line_type': UNAVAILABILITY, 'amount': 170},
                                      {'id': 'la-inv', 'line_type': 'investigation',
                                       'voucher_id': 'v-inv'},
                                      {'id': 'la-ec', 'line_type': 'extra_compute',
                                       'voucher_id': 'v-ec'}])['decision'], 'drafted')
        self.assertEqual(self.ind('notice', notice='notice-B', incident=INCIDENT, policy=POLICY_B,
                                  at=22, lines=[
                                      {'id': 'lb-fo', 'line_type': 'forensics',
                                       'voucher_id': 'v-fo'}])['decision'], 'drafted')
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        r = self.settle('insurer_direct', settlement='set-terms')
        paid = [l for l in self.payable('set-terms')
                if l['line_type'] == UNAVAILABILITY and l['policy'] == POLICY_A]
        residual = [l for l in self.payable('set-terms')
                    if l['line_type'] == UNAVAILABILITY and l['policy'] is None]
        reasons = self.denied_reasons('set-terms')
        # 17 minutes: 2 waiting deductible, 8 credited, leaving 7 cash minutes
        self.assertEqual(reasons.count('platform_credit_offset'), 8)
        self.assertEqual(reasons.count('waiting_period'), 2)
        # coinsurance 0.5 -> insurer 5 per minute, platform residual 5 per minute
        self.assertEqual([l['amount'] for l in paid], [5] * 7)
        self.assertEqual([l['amount'] for l in residual], [5] * 7)
        # cap 100 shared across this policy's payouts: 35 unavailability used,
        # 65 room left; fees 50 gross -> 25 after 0.5 coinsurance, within room
        fee_pay = [l for l in self.payable('set-terms') if l['line_type'] != UNAVAILABILITY]
        self.assertEqual(sum(l['amount'] for l in fee_pay), 25)
        # 35 insurer unavailability + 35 platform residual + 25 insurer fees
        self.assertEqual(sum(l['amount'] for l in self.payable('set-terms')), 35 + 35 + 25)
        # customer receives 80 credit + 35 insurer cash; the 2 waiting minutes
        # are its own deductible and the 35 coinsurance residual stays with the platform
        self.assertEqual(r['customer_total'], 115)

    def test_credit_revocation_before_and_after_settlement(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        # revoke before settlement: the early 8-minute credit disappears, so A pays all 17
        self.assertEqual(self.ind('revoke_credit', voucher='cr-early', at=30)['decision'],
                         'credit_revoked')
        r = self.settle('insurer_direct', settlement='set-rev')
        self.assertEqual(r['platform_credit_minutes'], 0)
        self.assertEqual(r['customer_cash'], 170)
        # a second revocation is a no-op conflict
        self.assertEqual(self.ind('revoke_credit', voucher='cr-early', at=31)['decision'],
                         'already_revoked')
        # a fresh credit after the ledger is closed cannot be revoked through history
        self.assertEqual(self.ind('credit', id='cr-late', incident=INCIDENT, minutes=3,
                                  amount=30)['decision'], 'credit_recorded')
        self.assertEqual(self.ind('revoke_credit', voucher='cr-late', at=45)['decision'],
                         'settled_locked')

    def test_forensics_dispute_blocks_payment_and_survives_late_report(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        # forensics voucher starts disputed: zero verified amount
        self.assertEqual(one(self.db, "SELECT status FROM fee_vouchers WHERE id='v-fo'")
                         ['status'], 'disputed')
        r1 = self.settle('insurer_direct', settlement='set-d1')
        self.assertNotIn('forensics',
                         {l['line_type'] for l in self.payable('set-d1')})
        self.assertIn('fee_not_verified', self.denied_reasons('set-d1'))
        # independent verification later fixes the amount; dispute can reopen it again
        self.assertEqual(self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
                         ['decision'], 'forensics_verified')
        self.assertEqual(self.ind('dispute_forensics', voucher='v-fo')['decision'],
                         'forensics_disputed')
        self.assertEqual(one(self.db, "SELECT verified_amount FROM fee_vouchers WHERE id='v-fo'")
                         ['verified_amount'], 0)
        # a late re-report trying to inflate the fee cannot rewrite the original voucher
        self.assertEqual(self.ind('fee', id='v-fo-late', incident=INCIDENT, kind='forensics',
                                  amount=999)['decision'], 'fee_recorded')
        self.assertEqual(one(self.db, "SELECT amount FROM fee_vouchers WHERE id='v-fo'")
                         ['amount'], 50)
        self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
        r2 = self.settle('insurer_direct', settlement='set-d2')
        fo = [l for l in r2['lines'] if l['line_type'] == 'forensics' and l['status'] == 'payable']
        self.assertEqual(len(fo), 1)
        self.assertEqual(fo[0]['amount'], 40)
        # once paid, a new dispute is locked out
        self.assertEqual(self.ind('dispute_forensics', voucher='v-fo')['decision'],
                         'settled_locked')

    def test_reopen_incident_sets_new_epoch_without_rewriting_history(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        first = self.settle('insurer_direct', settlement='set-e0')
        self.assertEqual(first['epoch'], 0)
        first_lines = len(self.payable('set-e0'))
        # new violation after closure: reopen, then a second isolation window
        self.assertEqual(self.ind('reopen', incident=INCIDENT, at=38, reason='recurrence')
                         ['decision'], 'reopened')
        self.assertEqual(one(self.db, "SELECT status FROM incidents WHERE id=?", (INCIDENT,))
                         ['status'], 'open')
        self.assertEqual(self.ind('reopen', incident=INCIDENT, at=39, reason='again')
                         ['decision'], 'incident_not_closed')
        self.inc('observe', id='v3', binding=BINDING, kind='syscall', source='agent-a',
                 at=40, confidence=95)
        self.inc('quarantine', id='incident-b', binding=BINDING, scope='binding',
                 reason='second strike')
        self.ind('isolation', id='iso2', incident=INCIDENT, at=41)
        self.ind('node_ready', id='ready2', incident=INCIDENT, at=44)
        self.ind('recovery', id='rec2', incident=INCIDENT, at=45)
        dt = downtime_minutes(self.db, INCIDENT)
        self.assertEqual((dt['epoch'], dt['start'], dt['end'], dt['minutes']), (1, 41, 45, 4))
        second = self.settle('insurer_direct', settlement='set-e1')
        self.assertEqual(second['decision'], 'settled')
        self.assertEqual(second['downtime_minutes'], 4)
        self.assertEqual(second['total_loss'], 40)
        # epoch 0 ledger is untouched and no fragment is double paid
        self.assertEqual(len(self.payable('set-e0')), first_lines)
        all_frags = [l['fragment'] for l in rows(self.db, "SELECT * FROM settlement_lines WHERE status='payable'")]
        self.assertEqual(len(all_frags), len(set(all_frags)))
        # re-settling the same epoch never pays an already-settled fragment again:
        # the epoch-1 unavailability minutes are all denied as already settled,
        # while any still-unverified fee stays denied on its own merits
        again = self.settle('insurer_direct', settlement='set-e1-dup')
        self.assertEqual(again['decision'], 'settled')
        self.assertEqual(
            rows(self.db, "SELECT COUNT(*) n FROM settlement_lines WHERE settlement='set-e1-dup' "
                         "AND status='payable'")[0]['n'], 0)
        self.assertIn('fragment_already_settled',
                      [l['denied_reason'] for l in again['lines']])

    def test_late_customer_receipt_extends_downtime_without_touching_credits(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        # node ready at 36 as before, but customer only confirms at 39
        self.ind('run_window', id='win', workload=WORKLOAD, start_min=10, end_min=50)
        self.ind('isolation', id='iso', incident=INCIDENT, at=20)
        self.ind('node_ready', id='ready', incident=INCIDENT, at=36)
        self.ind('recovery', id='rec', incident=INCIDENT, at=39)
        self.release_incident()
        r = self.settle('insurer_direct', settlement='set-late')
        # 20-39 = 19 real minutes; the 8-minute credit recorded at minute 25 is unchanged
        self.assertEqual(r['downtime_minutes'], 19)
        self.assertEqual(r['platform_credit_minutes'], 8)
        self.assertEqual(r['customer_cash'], 110)
        self.assertEqual(r['customer_total'], 190)
        self.assertEqual(one(self.db, "SELECT minutes,amount FROM credit_vouchers WHERE id='cr-early'")
                         ['minutes'], 8)

    def test_policy_revision_after_notice_does_not_move_frozen_terms(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        self.standard_fees_and_credit()
        self.standard_facts()
        # new policy version published after the notice was drafted
        self.assertEqual(self.ind('policy', id=POLICY_A, revision=2, effective_at=25,
                                  covers=[UNAVAILABILITY], waiting_min=10, cap=5,
                                  coinsurance=0.25, exclusions=[])['decision'],
                         'policy_recorded')
        self.assertEqual(self.ind('policy', id=POLICY_A, revision=2, effective_at=26,
                                  covers=[UNAVAILABILITY], waiting_min=10, cap=5,
                                  coinsurance=0.25, exclusions=[])['decision'],
                         'policy_revision_conflict')
        self.release_incident()
        r = self.settle('insurer_direct', settlement='set-rev-pol')
        # settled under frozen revision 1: full 9 cash minutes at full rate, no waiting/cap
        paid = [l for l in self.payable('set-rev-pol') if l['line_type'] == UNAVAILABILITY]
        self.assertEqual(len(paid), 9)
        self.assertTrue(all(l['amount'] == RATE for l in paid))
        # a brand-new notice picks up revision 2 and is bound by its harsher terms
        self.assertEqual(self.ind('notice', notice='notice-A2', incident=INCIDENT,
                                  policy=POLICY_A, at=38,
                                  lines=[{'id': 'la2-u', 'line_type': UNAVAILABILITY,
                                          'amount': 170}])['policy_revision'], 2)

    def test_window_clamps_downtime_to_scheduled_run(self):
        self.open_incident()
        self.standard_policies()
        self.standard_notices(both_claim_unavailability=False)
        # job was only scheduled until minute 35; recovery at 37 cannot add minutes it never ran
        self.ind('run_window', id='win', workload=WORKLOAD, start_min=10, end_min=35)
        self.ind('isolation', id='iso', incident=INCIDENT, at=20)
        self.ind('node_ready', id='ready', incident=INCIDENT, at=36)
        self.ind('recovery', id='rec', incident=INCIDENT, at=37)
        dt = downtime_minutes(self.db, INCIDENT)
        self.assertEqual((dt['start'], dt['end'], dt['minutes']), (20, 35, 15))

    def test_guard_rails_reject_invalid_inputs(self):
        self.assertEqual(self.ind('fee', id='f1', incident='ghost', kind='investigation',
                                  amount=5)['decision'], 'incident_unknown')
        self.open_incident()
        self.assertEqual(self.ind('policy', id='P', revision=1, effective_at=1,
                                  covers=['unavailability'], coinsurance=1.5)['decision'],
                         'invalid_coinsurance')
        self.assertEqual(self.ind('policy', id='P', revision=1, effective_at=1,
                                  covers=['hull_loss'])['decision'], 'unknown_coverage_category')
        self.standard_policies()
        self.assertEqual(self.ind('notice', notice='bad', incident=INCIDENT, policy='ghost',
                                  at=20, lines=[])['decision'], 'policy_unknown')
        # an invalid line must not leave an orphaned notice header
        r = self.ind('notice', notice='partial', incident=INCIDENT, policy=POLICY_A, at=20,
                     lines=[{'id': 'p1', 'line_type': 'not-a-category'}])
        self.assertEqual(r['decision'], 'unknown_coverage_category')
        self.assertIsNone(one(self.db, 'SELECT id FROM indemnity_notices WHERE id=?',
                              ('partial',)))
        self.assertEqual(self.ind('fee', id='fo', incident=INCIDENT, kind='forensics',
                                  amount=50)['decision'], 'fee_recorded')
        self.assertEqual(self.ind('verify_forensics', voucher='fo',
                                  verified_amount=51)['decision'], 'invalid_verified_amount')
        self.assertEqual(self.ind('payment', id='p', settlement='nope', policy=POLICY_A,
                                  payee='t', amount=1, status='presented',
                                  at=9)['decision'], 'settlement_unknown')
        self.assertEqual(self.ind('reopen', incident=INCIDENT, at=20)['decision'],
                         'incident_not_closed')
        self.ind('run_window', id='w1', workload=WORKLOAD, start_min=10, end_min=50)
        self.assertEqual(self.ind('run_window', id='w2', workload=WORKLOAD,
                                  start_min=10, end_min=50)['decision'], 'window_conflict')

    def test_event_replay_reproduces_every_settlement_fact(self):
        self.open_incident(scope='tenant')
        # tenant freeze really does reject later admission requests
        self.assertEqual(execute(self.db, 'admit',
                                 dict(request_id='frozen-req', op='request', id='w-late',
                                      tenant=TENANT, profile='profile-a', risk=1))['decision'],
                         'request_denied')
        self.standard_policies()
        self.standard_notices()
        self.standard_fees_and_credit()
        self.standard_facts()
        self.release_incident()
        self.ind('verify_forensics', voucher='v-fo', verified_amount=40)
        r = self.settle('platform_topup', settlement='set-replay')
        self.assertEqual(r['decision'], 'settled')
        self.ind('payment', id='pay-r1', settlement='set-replay', policy=POLICY_A,
                 payee=PLATFORM, amount=60, status='presented', at=41, bank_reference='b1')
        self.ind('payment', id='pay-r2', settlement='set-replay', policy=POLICY_A,
                 payee=PLATFORM, amount=60, status='bounced', at=42, bank_reference='b2')
        report = replay(str(Path(self.tmp.name) / 'state.sqlite'))
        self.assertTrue(report['verified'], report['divergence'])


if __name__ == '__main__':
    unittest.main()
