"""双边结算验收：物理用量与客户可收用量各有依据。

覆盖题目要求的七类情形：
代次回卷、迁机重叠、代理双报、隔离后仍耗时、银行退票、客户贷记、
迟到执行证明；并完整演练甲/乙两种当期方案与事件回放。
"""
import json
import tempfile
import unittest
from pathlib import Path

from sandcontract.store import connect, execute, replay, one, rows
from sandcontract import usage_settlement as us

ROOT = Path(__file__).resolve().parents[1]


class SettlementCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.sqlite'
        self.db = connect(str(self.path))
        self.n = 0

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def act(self, sub, op, **fields):
        self.n += 1
        return execute(self.db, sub,
                       dict(request_id=f'custom-{self.n}', op=op, **fields))

    def st(self, op, **fields):
        return self.act('settlement', op, **fields)

    def fixture(self, name):
        sub = name.split('_')[0]
        out = []
        for x in json.loads((ROOT / 'fixtures' / f'{name}.json').read_text('utf8')):
            out.append(execute(self.db, x.get('subsystem', sub), x))
        return out

    # ------------------------------------------------------------------
    # shared two-tenant / one-chassis world with the 400->490 window
    # ------------------------------------------------------------------
    def pair_world(self, turnover=True, customer_rate=1, provider_rate=1,
                   bill_amount=90, deposit=True):
        self.act('profile', 'node', id='node-h', uid='chassis-H',
                 generation=1, features=['seccomp'], capacity=4)
        self.act('profile', 'publish', id='prof', revision=1,
                 syscalls=['read'], devices=[], network=[],
                 required_feature='seccomp')
        self.act('profile', 'activate', id='prof')
        for t in ('tenant-a', 'tenant-b'):
            self.act('admit', 'limit', tenant=t, max_risk=5)
        self.act('admit', 'request', id='wa', tenant='tenant-a',
                 profile='prof', risk=1)
        self.act('admit', 'request', id='wb', tenant='tenant-b',
                 profile='prof', risk=1)
        self.act('admit', 'assign', id='ba', workload='wa',
                 node='node-h', at=10)
        self.act('admit', 'assign', id='bb', workload='wb',
                 node='node-h', at=11)
        gen = 1
        if turnover:
            # 节点换代：同一 chassis uid 推进 generation，旧 binding 变 at_risk
            self.act('profile', 'node', id='node-h', uid='chassis-H',
                     generation=2, features=['seccomp'], capacity=4)
            self.act('profile', 'publish', id='prof', revision=2,
                     syscalls=['read'], devices=[], network=[],
                     required_feature='seccomp')
            self.assertEqual(
                one(self.db, "SELECT status FROM bindings WHERE id='ba'")['status'],
                'at_risk')
            self.st('meter', id='m-old', chassis='chassis-H', generation=1,
                    start_ts=0, end_ts=50, counter_from=900, counter_to=980)
            gen = 2
        # 400 -> 490 = 90 physical CPU seconds in the disputed window
        self.st('meter', id='m-h', chassis='chassis-H', generation=gen,
                start_ts=100, end_ts=200, counter_from=400, counter_to=490)
        # two independent execution receipts: 30 + 30 proven
        self.st('receipt', id='ra', workload='wa', binding='ba',
                chassis='chassis-H', generation=gen,
                start_ts=110, end_ts=140, seconds=30)
        self.st('receipt', id='rb', workload='wb', binding='bb',
                chassis='chassis-H', generation=gen,
                start_ts=150, end_ts=180, seconds=30)
        # shared temporary slot: only A-or-B can be proven for extra 30
        self.st('disjunction', id='dj', meter_interval_id='m-h', seconds=30,
                candidates=['wa', 'wb'], basis='shared_generation_turnover_slot')
        # naive agent page labels the whole extra 30 as A (A=60, B=30)
        self.st('capture_page', page_id='page-h',
                rows=[{'binding': 'ba', 'cpu_seconds': 60},
                      {'binding': 'bb', 'cpu_seconds': 30}])
        self.st('provider_bill', id='bill-h', provider='provider-x',
                meter_interval_id='m-h', seconds=90, amount=bill_amount, at=210)
        if deposit:
            self.st('deposit_facility', id='dep1',
                    party='shared-compute-risk-pool', limit_amount=5000, at=0)
        return {'gen': gen, 'customer_rate': customer_rate,
                'provider_rate': provider_rate}

    # ==================================================================
    # flagship: Plan A (reserve) and Plan B (deposit)
    # ==================================================================
    def test_plan_a_reserve_invoices_undisputed_and_suspends_30(self):
        self.pair_world()
        r = self.st('settle', id='setA', meter_interval_id='m-h',
                    page_id='page-h', bill_id='bill-h', plan='A', at=300)
        self.assertEqual(r['decision'], 'settled')
        self.assertEqual((r['physical_seconds'], r['certain_seconds'],
                          r['disputed_seconds'], r['gap_seconds']), (90, 60, 30, 30))
        # page labels are audit-only claims: never 60 for A
        self.assertEqual(r['page_claims'], {'tenant-a': 60, 'tenant-b': 30})
        self.assertEqual(r['tenant_seconds'],
                         {'tenant-a': 30, 'tenant-b': 30})
        # formal invoices are exactly the undisputed 30+30
        inv = sorted((i['tenant'], i['seconds'], i['amount'])
                     for i in r['invoices'])
        self.assertEqual(inv, [('tenant-a', 30, 30), ('tenant-b', 30, 30)])
        # no 15/15 averaging anywhere
        self.assertNotIn(15, [i['seconds'] for i in r['invoices']])
        # platform reserve pays provider the full valid 90 bill once
        pp = r['provider_payments']
        self.assertEqual(len(pp), 1)
        self.assertEqual(pp[0]['amount'], 90)
        self.assertTrue(pp[0]['effective'])
        self.assertEqual(pp[0]['funding'], {'platform_reserve': 90})
        ps = us.provider_statement(self.db, bill_id='bill-h')
        self.assertEqual((ps['paid_effective'], ps['outstanding']), (90, 0))
        # 30s suspense keeps original window + A/B candidates, unsplit
        sus = r['suspense']
        self.assertEqual(sus['seconds'], 30)
        self.assertEqual(sus['candidates'], ['wa', 'wb'])
        self.assertEqual(sus['state'], 'open_pending_proof')
        self.assertEqual(sus['window'][0]['counter_from'], 400)
        self.assertEqual(sus['window'][0]['counter_to'], 490)
        self.assertEqual(sus['bridge'], 'platform_reserve')
        # customer balances are only the undisputed invoices
        self.assertEqual(r['balances']['tenant-a']['balance_due'], 30)
        self.assertEqual(r['balances']['tenant-b']['balance_due'], 30)

    def test_plan_a_late_proof_to_b_recovers_suspense_never_repays_provider(self):
        self.pair_world()
        self.st('settle', id='setA', meter_interval_id='m-h',
                bill_id='bill-h', plan='A', at=300)
        # independent device return proves the disputed 30 were W乙's
        self.assertEqual(
            self.st('proof', id='proof-b', meter_interval_id='m-h',
                    workload='wb', seconds=30,
                    source='device-independent-return', at=400)['decision'],
            'proof_recorded')
        r = self.st('resolve', id='res-a', settlement='setA',
                    proof_id='proof-b', at=401)
        self.assertEqual(r['decision'], 'dispute_resolved')
        # A stays 30; B now owes its own 30 plus supplementary 30
        self.assertEqual(r['balances']['tenant-a']['balance_due'], 30)
        self.assertEqual(r['balances']['tenant-b']['balance_due'], 60)
        late = one(self.db, "SELECT id FROM us_docs WHERE settlement='setA' "
                            "AND doc_type='invoice' AND id LIKE '%late%'")
        self.assertTrue(late)
        self.assertEqual(
            self.st('pay_customer', id='pay-b-late',
                    invoice_id=late['id'], amount=30, at=410)['decision'],
            'customer_payment_recorded')
        ov = us.overview(self.db, 'setA')
        self.assertEqual(ov['suspense']['state'], 'recovered')
        # provider still paid exactly once / 90
        ps = us.provider_statement(self.db, bill_id='bill-h')
        self.assertEqual(len(ps['payments']), 1)
        self.assertEqual(ps['paid_effective'], 90)
        self.assertEqual(ps['outstanding'], 0)

    def test_plan_b_deposit_notices_then_invoice_and_refund(self):
        # unit price 1 -> money figures equal the narrated seconds (60/30/90)
        self.pair_world()
        r = self.st('settle', id='setB', meter_interval_id='m-h',
                    bill_id='bill-h', plan='B',
                    deposit_facility='dep1', at=300)
        self.assertEqual(r['decision'], 'settled')
        # no formal customer invoice in plan B at period close
        self.assertEqual(r['invoices'], [])
        self.assertEqual(sorted((n['tenant'], n['seconds']) for n in r['notices']),
                         [('tenant-a', 30), ('tenant-b', 30)])
        self.assertTrue(all(n['detail']['formal_invoice'] is False
                            for n in r['notices']))
        # provider receives 90 once: platform 60 undisputed + deposit 30 dispute
        pp = r['provider_payments'][0]
        self.assertEqual(pp['amount'], 90)
        self.assertEqual(pp['funding'],
                         {'platform': 60, 'shared_risk_deposit': 30})
        dep = us.deposit_state(self.db, 'dep1')
        self.assertEqual((dep['occupied'], dep['available']), (30, 4970))
        self.assertEqual(r['suspense']['bridge'], 'shared_risk_deposit')
        self.assertEqual(r['suspense']['state'],
                         'secured_by_deposit_pending_proof')
        # clarify: disputed 30 really belong to B
        self.st('proof', id='proof-b2', meter_interval_id='m-h',
                workload='wb', seconds=30, at=400)
        rr = self.st('resolve', id='res-b', settlement='setB',
                     proof_id='proof-b2', at=401)
        inv = sorted((i['tenant'], i['seconds'], i['amount'])
                     for i in rr['invoices'])
        self.assertEqual(inv, [('tenant-a', 30, 30), ('tenant-b', 60, 60)])
        # deposit not returned before the proven tenant pays
        self.assertEqual(
            self.st('refund_deposit', id='refund-early',
                    settlement='setB', at=402)['decision'],
            'collection_outstanding')
        self.st('pay_customer', id='pay-a',
                invoice_id='setB:inv-final:tenant-a', amount=30, at=410)
        self.st('pay_customer', id='pay-b',
                invoice_id='setB:inv-final:tenant-b', amount=60, at=411)
        rf = self.st('refund_deposit', id='refund-1',
                     settlement='setB', at=420)
        self.assertEqual(rf['decision'], 'deposit_refunded')
        self.assertEqual(us.deposit_state(self.db, 'dep1')['occupied'], 0)
        self.assertEqual(us.overview(self.db, 'setB')['suspense']['state'],
                         'closed_deposit_returned')
        # append-only: a second refund is refused
        self.assertEqual(
            self.st('refund_deposit', id='refund-2',
                    settlement='setB', at=421)['decision'],
            'deposit_already_refunded')
        # provider paid once throughout
        ps = us.provider_statement(self.db, bill_id='bill-h')
        self.assertEqual(ps['paid_effective'], 90)
        self.assertEqual(len([p for p in ps['payments'] if p['effective']]), 1)

    # ==================================================================
    # 代次回卷 / counter wrap
    # ==================================================================
    def test_generation_rollback_and_counter_wrap_are_rejected(self):
        # stale generation after a newer generation is known
        self.assertEqual(self.st('meter', id='h2', chassis='H', generation=2,
                                 start_ts=0, end_ts=10,
                                 counter_from=0, counter_to=10)['decision'],
                         'meter_recorded')
        stale = self.st('meter', id='h1-late', chassis='H', generation=1,
                        counter_from=5, counter_to=9)
        self.assertEqual(stale['decision'], 'stale_generation')
        self.assertIsNone(one(self.db,
                              "SELECT id FROM us_meter_intervals WHERE id='h1-late'"))

        # backwards counter delta is a rollback
        self.assertEqual(self.st('meter', id='c1', chassis='C', generation=1,
                                 counter_from=400, counter_to=490)['decision'],
                         'meter_recorded')
        wrap = self.st('meter', id='c-wrap', chassis='C', generation=1,
                       counter_from=5, counter_to=60)
        self.assertEqual(wrap['decision'], 'counter_wrap')
        self.assertIsNone(one(self.db,
                              "SELECT id FROM us_meter_intervals WHERE id='c-wrap'"))
        # healthy monotonic continuation is accepted from the prior top
        self.assertEqual(self.st('meter', id='c2', chassis='C', generation=1,
                                 counter_from=490, counter_to=520)['decision'],
                         'meter_recorded')
        # overlapping counter range is rejected
        self.assertEqual(self.st('meter', id='c3', chassis='C', generation=1,
                                 counter_from=500, counter_to=530)['decision'],
                         'interval_overlap')
        # a new generation may restart the counter low: sequences are partitioned
        self.assertEqual(self.st('meter', id='c-gen2', chassis='C', generation=2,
                                 counter_from=0, counter_to=30)['decision'],
                         'meter_recorded')
        totals = {r['chassis'] + str(r['generation']): r['s'] for r in rows(
            self.db, 'SELECT chassis, generation, SUM(seconds) s '
                     'FROM us_meter_intervals GROUP BY chassis, generation')}
        self.assertEqual(totals['C1'], 120)   # 90 + 30 only
        self.assertEqual(totals['C2'], 30)

    # ==================================================================
    # 代理双报
    # ==================================================================
    def test_agent_duplicate_report_counts_each_second_once(self):
        first = self.st('meter', id='m-1', chassis='H', generation=1,
                        start_ts=0, end_ts=10,
                        counter_from=400, counter_to=490)
        self.assertEqual(first['decision'], 'meter_recorded')
        # same natural interval resent under a new id -> duplicate
        dup = self.st('meter', id='m-2-resend', chassis='H', generation=1,
                       start_ts=0, end_ts=10,
                       counter_from=400, counter_to=490)
        self.assertEqual(dup['decision'], 'meter_duplicate')
        # same id replay -> reused
        self.assertEqual(self.st('meter', id='m-1', chassis='H', generation=1,
                                 start_ts=0, end_ts=10,
                                 counter_from=400, counter_to=490)['decision'],
                         'reused')
        self.assertEqual(one(self.db,
                             'SELECT COUNT(*) n, COALESCE(SUM(seconds),0) s '
                             'FROM us_meter_intervals')['s'], 90)
        # page resend is captured once
        page_rows = [{'binding': 'ba', 'cpu_seconds': 7}]
        self.assertEqual(self.st('capture_page', page_id='p1',
                                 rows=page_rows)['decision'], 'captured')
        self.assertEqual(self.st('capture_page', page_id='p1',
                                 rows=page_rows)['decision'], 'reused')
        self.assertEqual(one(self.db,
                             'SELECT COALESCE(SUM(cpu_seconds),0) s '
                             'FROM usage_rows')['s'], 7)
        # receipt natural-key resend is also de-duplicated
        self.act('profile', 'node', id='n', uid='u', generation=1,
                 features=['seccomp'], capacity=2)
        self.act('profile', 'publish', id='p', revision=1, syscalls=['r'],
                 devices=[], network=[], required_feature='seccomp')
        self.act('profile', 'activate', id='p')
        self.act('admit', 'limit', tenant='t', max_risk=2)
        self.act('admit', 'request', id='w', tenant='t', profile='p', risk=1)
        self.assertEqual(self.st('receipt', id='r1', workload='w',
                                 chassis='u', generation=1, seconds=5)['decision'],
                         'receipt_recorded')
        self.assertEqual(self.st('receipt', id='r2-resend', workload='w',
                                 chassis='u', generation=1,
                                 seconds=5)['decision'], 'receipt_duplicate')
        self.assertEqual(one(self.db, 'SELECT COUNT(*) n FROM us_receipts')['n'], 1)

    # ==================================================================
    # 迁机重叠
    # ==================================================================
    def _migration_world(self):
        self.act('profile', 'node', id='n1', uid='chassis-1', generation=1,
                 features=['seccomp'], capacity=2)
        self.act('profile', 'node', id='n2', uid='chassis-2', generation=1,
                 features=['seccomp'], capacity=2)
        self.act('profile', 'publish', id='p', revision=1, syscalls=['r'],
                 devices=[], network=[], required_feature='seccomp')
        self.act('profile', 'activate', id='p')
        self.act('admit', 'limit', tenant='t', max_risk=3)
        self.act('admit', 'request', id='w', tenant='t', profile='p', risk=1)
        self.act('admit', 'assign', id='b1', workload='w', node='n1', at=1)
        # H1 50 physical seconds, H2 40 physical seconds; windows overlap 10s
        self.st('meter', id='m1', chassis='chassis-1', generation=1,
                start_ts=0, end_ts=100, counter_from=100, counter_to=150)
        self.st('meter', id='m2', chassis='chassis-2', generation=1,
                start_ts=90, end_ts=200, counter_from=200, counter_to=240)
        mig = self.st('migrate', id='hm', workload='w', old_binding='b1',
                      new_binding='b2', new_chassis='chassis-2',
                      new_generation=1, cutover_ts=95, overlap_seconds=10,
                      overlap_start=90, overlap_end=100, at=95)
        self.assertEqual(mig['decision'], 'migration_recorded')
        self.st('receipt', id='rc1', workload='w', binding='b1',
                chassis='chassis-1', generation=1,
                start_ts=0, end_ts=100, seconds=50)
        self.st('receipt', id='rc2', workload='w', binding='b2',
                chassis='chassis-2', generation=1,
                start_ts=90, end_ts=200, seconds=40)
        self.st('provider_bill', id='bill1', provider='px',
                meter_interval_id='m1', seconds=50, amount=50)
        self.st('provider_bill', id='bill2', provider='px',
                meter_interval_id='m2', seconds=40, amount=40)

    def test_migration_overlap_charged_once_and_paid_once_per_chassis(self):
        self._migration_world()
        r = self.st('reconcile', id='setm',
                    meter_interval_ids=['m1', 'm2'])
        self.assertEqual(r['decision'], 'reconciled')
        # 90 physical; 90 gross receipt seconds; 10s handoff double-run removed
        self.assertEqual(r['physical_seconds'], 90)
        self.assertEqual(r['certain_seconds'], 80)
        self.assertEqual(r['tenant_seconds'], {'t': 80})
        reasons = {x['reason']: x['seconds'] for x in r['responsibility']}
        self.assertEqual(reasons.get('migration_overlap'), 10)
        self.assertEqual(r['gap_seconds'], 0)
        # plan A pays both distinct chassis bills once and invoices 80
        plan = self.st('execute_plan', settlement='setm', plan='A',
                       bill_ids=['bill1', 'bill2'], at=300)
        self.assertEqual(plan['decision'], 'plan_executed')
        self.assertEqual(len(plan['provider_payments']), 2)
        self.assertEqual(sum(p['amount'] for p in plan['provider_payments']
                             if p['effective']), 90)
        self.assertEqual([i['amount'] for i in plan['invoices']], [80])
        # the old chassis interval cannot enter a second provider bill
        again = self.st('provider_bill', id='bill1-dup', provider='py',
                        meter_interval_id='m1', seconds=10, amount=10)
        self.assertEqual(again['decision'], 'meter_seconds_already_billed')
        # nor can the already-paid bill be paid again
        extra = self.st('pay_provider', id='pp-extra', bill_id='bill1', amount=50)
        self.assertEqual(extra['decision'], 'bill_already_paid')
        # resending the old meter interval adds nothing
        self.assertEqual(self.st('meter', id='m1-resend', chassis='chassis-1',
                                  generation=1, start_ts=0, end_ts=100,
                                  counter_from=100, counter_to=150)['decision'],
                          'meter_duplicate')

    # ==================================================================
    # 隔离后仍耗时 + active binding 也不能默认收费
    # ==================================================================
    def test_post_isolation_kernel_burn_is_listed_responsibility(self):
        self.fixture('profile_normal')
        self.fixture('admit_normal')
        self.assertEqual(
            self.act('incident', 'observe', id='v1', binding='binding-a',
                     kind='syscall', source='agent-a', at=10,
                     confidence=95)['decision'], 'credible')
        self.assertEqual(
            self.act('incident', 'quarantine', id='case-iso',
                     binding='binding-a', scope='binding',
                     reason='isolated')['decision'], 'binding_quarantined')
        self.assertEqual(
            one(self.db, "SELECT status FROM bindings WHERE id='binding-a'")['status'],
            'quarantined')
        # 50 physical seconds after isolation ...
        self.st('meter', id='m-iso', chassis='node-uid-a', generation=1,
                start_ts=20, end_ts=40, counter_from=100, counter_to=150)
        # ... only 30 independently proven usable execution seconds ...
        self.st('receipt', id='r-iso', workload='workload-a',
                binding='binding-a', chassis='node-uid-a', generation=1,
                start_ts=20, end_ts=32, seconds=30)
        # ... the other 20 are kernel burn while the customer is locked out
        up = self.st('unavailable', id='up-iso', binding='binding-a',
                     chassis='node-uid-a', generation=1,
                     start_ts=32, end_ts=40, seconds=20,
                     reason='isolated_kernel', incident_id='case-iso')
        self.assertEqual(up['decision'], 'period_recorded')
        self.st('provider_bill', id='bill-iso', provider='px',
                meter_interval_id='m-iso', seconds=50, amount=50)
        r = self.st('settle', id='set-iso', meter_interval_id='m-iso',
                    bill_id='bill-iso', plan='A', at=50)
        self.assertEqual(r['decision'], 'settled')
        self.assertEqual(r['certain_seconds'], 30)
        self.assertEqual(r['responsibility_seconds'], 20)
        self.assertEqual(r['gap_seconds'], 0)
        self.assertEqual([i['amount'] for i in r['invoices']], [30])
        alloc = [(c['detail']['reason'], c['seconds'])
                 for c in r['cost_allocations']]
        self.assertIn(('isolated_kernel', 20), alloc)
        # provider is still paid for all proven physical time
        self.assertEqual(us.provider_statement(self.db, bill_id='bill-iso')
                         ['paid_effective'], 50)

    def test_active_binding_with_only_agent_label_is_not_charged(self):
        # no turnover -> binding stays active
        self.pair_world(turnover=False)
        self.st('meter', id='m-only', chassis='chassis-H', generation=1,
                start_ts=300, end_ts=310, counter_from=500, counter_to=520)
        self.st('capture_page', page_id='page-claim',
                rows=[{'binding': 'ba', 'cpu_seconds': 20}])
        r = self.st('settle', id='set-active', meter_interval_id='m-only',
                    page_id='page-claim', at=320)
        self.assertEqual(r['decision'], 'reconciled')
        # no execution receipt -> nothing certain; all 20 unexplained physical
        self.assertEqual(r['certain_seconds'], 0)
        self.assertEqual(r['unexplained_seconds'], 20)
        self.assertEqual(r['gap_seconds'], 20)
        # attribution unknown does NOT make physical time unpayable:
        # the provider's valid 20s bill is still settled from platform funds
        self.assertEqual(self.st('provider_bill', id='bill-only', provider='px',
                                 meter_interval_id='m-only', seconds=20,
                                 amount=20)['decision'], 'provider_bill_recorded')
        plan = self.st('execute_plan', settlement='set-active', plan='A',
                       bill_id='bill-only', at=321)
        self.assertEqual(plan['invoices'], [])
        self.assertEqual(plan['balances'], {})
        self.assertEqual(plan['provider_payments'][0]['amount'], 20)
        self.assertTrue(plan['provider_payments'][0]['effective'])
        self.assertEqual(us.provider_statement(self.db, bill_id='bill-only')
                         ['outstanding'], 0)
        sus = us.suspense_state(self.db, 'set-active')
        self.assertEqual(sus['seconds'], 20)
        self.assertEqual(sus['candidates'], [])

    def test_new_generation_cannot_recycle_same_window_into_second_bill(self):
        self.assertEqual(self.st('meter', id='w1', chassis='H', generation=1,
                                 start_ts=0, end_ts=100,
                                 counter_from=0, counter_to=90)['decision'],
                         'meter_recorded')
        self.st('provider_bill', id='wb1', provider='px',
                meter_interval_id='w1', seconds=90, amount=90)
        # generation bump that reuses the exact old wall window is refused
        recycled = self.st('meter', id='w2', chassis='H', generation=2,
                           start_ts=0, end_ts=100,
                           counter_from=0, counter_to=90)
        self.assertEqual(recycled['decision'], 'generation_window_overlap')
        self.assertIsNone(one(self.db,
                               "SELECT id FROM us_meter_intervals WHERE id='w2'"))
        # therefore no second provider payable can be built on that window
        self.assertEqual(self.st('provider_bill', id='wb2', provider='py',
                                 meter_interval_id='w2', seconds=90,
                                 amount=90)['decision'],
                         'unknown_meter_interval')
        self.st('pay_provider', id='wp1', bill_id='wb1', amount=90)
        self.assertEqual(us.provider_statement(self.db, bill_id='wb1')
                         ['paid_effective'], 90)

    def test_contract_that_disallows_cpu_is_not_billed(self):
        self.pair_world()
        self.st('contract', id='c-a', tenant='tenant-a',
                customer_rate=1, cpu_billable=False)
        r = self.st('reconcile', id='set-c', meter_interval_id='m-h')
        # A's proven 30 are contract-blocked; only B remains chargeable
        self.assertNotIn('tenant-a', r['tenant_seconds'])
        self.assertEqual(r['tenant_seconds'], {'tenant-b': 30})
        reasons = {x['reason']: x['seconds'] for x in r['responsibility']}
        self.assertEqual(reasons.get('contract_not_cpu_billable'), 30)

    # ==================================================================
    # 银行退票（供应商侧）与 换供应商
    # ==================================================================
    def test_provider_payment_bounce_then_retry_pays_once(self):
        self.pair_world()
        self.st('settle', id='setP', meter_interval_id='m-h',
                bill_id='bill-h', plan='A', at=300)
        pay_id = 'setP:ppay:bill-h'
        self.assertEqual(
            self.st('bounce_provider', id='ev-bounce',
                    payment_id=pay_id, at=310,
                    reason='bank returned transfer')['decision'],
            'provider_payment_bounced')
        ps = us.provider_statement(self.db, bill_id='bill-h')
        self.assertEqual(ps['paid_effective'], 0)
        self.assertEqual(ps['outstanding'], 90)
        self.assertFalse(ps['payments'][0]['effective'])
        # a repeated bounce event is idempotent and a second bounce refused
        self.assertEqual(self.st('bounce_provider', id='ev-bounce',
                                 payment_id=pay_id, at=310)['decision'], 'reused')
        self.assertEqual(self.st('bounce_provider', id='ev-bounce-2',
                                 payment_id=pay_id, at=311)['decision'],
                         'payment_already_bounced')
        # retry with a new payment credential settles the bill once
        self.assertEqual(self.st('pay_provider', id='pp-retry',
                                 bill_id='bill-h', amount=90, at=320)['decision'],
                         'provider_payment_recorded')
        self.assertEqual(self.st('pay_provider', id='pp-again',
                                 bill_id='bill-h', amount=90, at=321)['decision'],
                         'bill_already_paid')
        ps = us.provider_statement(self.db, bill_id='bill-h')
        effective = [p for p in ps['payments'] if p['effective']]
        self.assertEqual(len(effective), 1)
        self.assertEqual(ps['paid_effective'], 90)
        self.assertEqual(ps['outstanding'], 0)

    def test_provider_switch_requires_append_reversal_before_new_bill(self):
        self.st('meter', id='m', chassis='H', generation=1,
                counter_from=0, counter_to=90)
        self.assertEqual(self.st('provider_bill', id='bill-p1', provider='P1',
                                 meter_interval_id='m', seconds=90,
                                 amount=90)['decision'], 'provider_bill_recorded')
        # switch provider: P2 cannot bill the same meter seconds outright
        self.assertEqual(self.st('provider_bill', id='bill-p2', provider='P2',
                                 meter_interval_id='m', seconds=90,
                                 amount=90)['decision'],
                         'meter_seconds_already_billed')
        # append-only correction reverses the unpaid P1 bill ...
        self.assertEqual(self.st('reverse_provider_bill', id='rev-1',
                                 bill_id='bill-p1',
                                 reason='switch supplier')['decision'],
                         'provider_bill_reversed')
        # ... then P2 may bill and be paid once
        self.assertEqual(self.st('provider_bill', id='bill-p2', provider='P2',
                                 meter_interval_id='m', seconds=90,
                                 amount=90)['decision'], 'provider_bill_recorded')
        self.assertEqual(self.st('pay_provider', id='pp-p2',
                                 bill_id='bill-p2', amount=90)['decision'],
                         'provider_payment_recorded')
        # a paid bill cannot be erased by reversal; corrections stay append-only
        self.assertEqual(self.st('reverse_provider_bill', id='rev-2',
                                 bill_id='bill-p2')['decision'],
                         'bill_paid_reversal_denied')
        self.assertEqual(us.provider_statement(self.db, bill_id='bill-p2')
                         ['paid_effective'], 90)

    # ==================================================================
    # 客户贷记 + 客户银行退票：旧发票金额永不被改写
    # ==================================================================
    def test_customer_credit_note_and_bounce_are_append_only(self):
        # someone books the naive page-label charge A=60
        self.assertEqual(self.st('invoice', id='inv-a-naive',
                                 tenant='tenant-a', seconds=60,
                                 unit_rate=1, at=1)['decision'], 'invoice_issued')
        inv_before = one(self.db, "SELECT amount FROM us_docs WHERE id='inv-a-naive'")
        self.assertEqual(inv_before['amount'], 60)
        # correct the unattested shared-slot 30 with a formal credit note
        cn = self.st('credit', id='cn-1', tenant='tenant-a', amount=30,
                     corrects_id='inv-a-naive',
                     reason='remove unattested shared-slot 30s', at=2)
        self.assertEqual(cn['decision'], 'credit_note_issued')
        stmt = us.tenant_statement(self.db, 'tenant-a')
        self.assertEqual(stmt['balance_due'], 30)
        # cannot over-credit the original invoice
        self.assertEqual(self.st('credit', id='cn-2-big', tenant='tenant-a',
                                 amount=999, corrects_id='inv-a-naive')['decision'],
                         'credit_exceeds_invoice')
        # customer pays the corrected 30 ... then the bank payment bounces
        self.assertEqual(self.st('pay_customer', id='pay-1',
                                 invoice_id='inv-a-naive', amount=30, at=3)
                         ['decision'], 'customer_payment_recorded')
        self.assertEqual(us.tenant_statement(self.db, 'tenant-a')['balance_due'], 0)
        self.assertEqual(self.st('bounce_customer', id='bn-1',
                                 payment_id='pay-1', at=4,
                                 reason='insufficient funds')['decision'],
                         'customer_payment_bounced')
        self.assertEqual(us.tenant_statement(self.db, 'tenant-a')['balance_due'], 30)
        # retry with a new payment settles
        self.assertEqual(self.st('pay_customer', id='pay-2',
                                 invoice_id='inv-a-naive', amount=30, at=5)
                         ['decision'], 'customer_payment_recorded')
        stmt = us.tenant_statement(self.db, 'tenant-a')
        self.assertEqual(stmt['balance_due'], 0)
        self.assertEqual(stmt['paid_effective'], 30)
        # the original credential is physically unchanged at 60
        inv_after = one(self.db, "SELECT amount FROM us_docs WHERE id='inv-a-naive'")
        self.assertEqual(inv_after['amount'], 60)
        self.assertEqual(one(self.db, "SELECT amount FROM us_docs WHERE id='cn-1'")
                         ['amount'], 30)
        self.assertEqual(one(self.db,
                             "SELECT COUNT(*) n FROM us_doc_events "
                             "WHERE doc_id='pay-1' AND kind='bounced'")['n'], 1)

    # ==================================================================
    # 方案互斥：退票与补证交错也不能改选 / 重付
    # ==================================================================
    def test_plan_choice_is_mutually_exclusive_through_bounce_and_proof(self):
        self.pair_world()
        self.st('settle', id='setX', meter_interval_id='m-h',
                bill_id='bill-h', plan='A', at=300)
        # cannot switch to plan B once A artifacts exist
        conflict = self.st('execute_plan', settlement='setX', plan='B',
                           deposit_facility='dep1')
        self.assertEqual(conflict['decision'], 'plan_conflict')
        # provider payment bounces while the 30s is still unresolved
        self.st('bounce_provider', id='x-bounce',
                payment_id='setX:ppay:bill-h', at=310)
        # late proof lands in the middle: A recovery path still honoured
        self.st('proof', id='x-proof', meter_interval_id='m-h',
                workload='wa', seconds=30, at=400)
        res = self.st('resolve', id='x-res', settlement='setX',
                      proof_id='x-proof', at=401)
        self.assertEqual(res['decision'], 'dispute_resolved')
        self.assertEqual(res['balances']['tenant-a']['balance_due'], 60)
        # still cannot retroactively choose B
        self.assertEqual(self.st('execute_plan', settlement='setX', plan='B',
                                 deposit_facility='dep1')['decision'],
                         'plan_conflict')
        # settle the bounced provider transfer once with a new credential
        self.assertEqual(self.st('pay_provider', id='x-pp-retry',
                                 bill_id='bill-h', amount=90, at=410)['decision'],
                         'provider_payment_recorded')
        ps = us.provider_statement(self.db, bill_id='bill-h')
        self.assertEqual(len([p for p in ps['payments'] if p['effective']]), 1)
        self.assertEqual(ps['paid_effective'], 90)

    def test_proof_outside_candidate_set_is_rejected(self):
        self.pair_world()
        self.st('settle', id='setC', meter_interval_id='m-h',
                bill_id='bill-h', plan='A', at=300)
        # unrelated third workload cannot claim the A-or-B slot
        self.act('profile', 'activate', id='prof')
        self.act('admit', 'limit', tenant='tenant-c', max_risk=5)
        self.act('admit', 'request', id='wc', tenant='tenant-c',
                 profile='prof', risk=1)
        self.st('proof', id='proof-c', meter_interval_id='m-h',
                workload='wc', seconds=30, at=400)
        self.assertEqual(self.st('resolve', id='res-c', settlement='setC',
                                 proof_id='proof-c', at=401)['decision'],
                         'proof_outside_candidates')
        # a proper proof still resolves afterwards
        self.st('proof', id='proof-a', meter_interval_id='m-h',
                workload='wa', seconds=30, at=402)
        self.assertEqual(self.st('resolve', id='res-c2', settlement='setC',
                                 proof_id='proof-a', at=403)['decision'],
                         'dispute_resolved')

    # ==================================================================
    # 客户签收：签收可核验告知不等于正式发票
    # ==================================================================
    def test_customer_sign_off_is_append_only_and_not_an_invoice(self):
        self.pair_world()
        r = self.st('settle', id='set-sign', meter_interval_id='m-h',
                    plan='B', deposit_facility='dep1', at=300)
        notice_a = next(n['id'] for n in r['notices']
                        if n['tenant'] == 'tenant-a')
        ack = self.st('acknowledge', id='ack-1', settlement='set-sign',
                      tenant='tenant-a', doc_id=notice_a,
                      actor='tenant-a-billing', at=301)
        self.assertEqual(ack['decision'], 'acknowledged')
        # duplicate natural sign-off is refused, duplicate id is reused
        self.assertEqual(self.st('acknowledge', id='ack-2',
                                 settlement='set-sign', tenant='tenant-a',
                                 doc_id=notice_a, at=302)['decision'],
                         'already_acknowledged')
        self.assertEqual(self.st('acknowledge', id='ack-1',
                                 settlement='set-sign', tenant='tenant-a',
                                 doc_id=notice_a, at=301)['decision'], 'reused')
        ov = us.overview(self.db, 'set-sign')
        self.assertEqual(len(ov['acknowledgements']), 1)
        # signing a usage notice still posts no invoice / receivable
        self.assertEqual(ov['invoices'], [])
        self.assertEqual(ov['balances']['tenant-a']['balance_due'], 0)
        self.assertEqual(one(self.db,
                             'SELECT COUNT(*) n FROM us_acknowledgements '
                             "WHERE settlement='set-sign'")['n'], 1)

    # ==================================================================
    # event / request replay
    # ==================================================================
    def test_same_request_id_is_idempotent(self):
        self.pair_world()
        step = {'request_id': 'fixed-pay', 'op': 'pay_provider',
                'id': 'pp-fixed', 'bill_id': 'bill-h', 'amount': 90, 'at': 9}
        r1 = execute(self.db, 'settlement', step)
        r2 = execute(self.db, 'settlement', dict(step))
        self.assertEqual(r1, r2)
        self.assertEqual(r1['decision'], 'provider_payment_recorded')
        self.assertEqual(one(self.db,
                              "SELECT COUNT(*) n FROM us_docs WHERE id='pp-fixed'")
                         ['n'], 1)
        # a changed body under same request id is a conflict, not a payment
        changed = execute(self.db, 'settlement',
                          dict(step, amount=90, funding={'x': 1}))
        self.assertEqual(changed['decision'], 'request_conflict')

    def test_full_settlement_replay_verifies(self):
        self.pair_world(customer_rate=2, provider_rate=2, bill_amount=180)
        # duplicate ingestion events exercise replay de-duplication branches
        self.st('meter', id='m-h-resend', chassis='chassis-H', generation=2,
                start_ts=100, end_ts=200, counter_from=400, counter_to=490)
        self.st('settle', id='setR', meter_interval_id='m-h',
                page_id='page-h', bill_id='bill-h', plan='A', at=300,
                customer_rate=2, provider_rate=2)
        self.st('acknowledge', id='r-ack', settlement='setR',
                tenant='tenant-a', doc_id='setR:inv:tenant-a', at=301)
        self.st('bounce_provider', id='r-bounce',
                payment_id='setR:ppay:bill-h', at=310)
        self.st('pay_provider', id='r-pp-2', bill_id='bill-h',
                amount=180, at=320)
        self.st('proof', id='r-proof', meter_interval_id='m-h',
                workload='wb', seconds=30, at=400)
        self.st('resolve', id='r-res', settlement='setR',
                proof_id='r-proof', at=401)
        late_id = 'setR:inv-late:r-proof'
        self.st('credit', id='r-cn', tenant='tenant-b', amount=10,
                corrects_id=late_id, reason='sla goodwill', at=402)
        self.st('pay_customer', id='r-pay-b1', invoice_id=late_id,
                amount=50, at=403)
        self.st('bounce_customer', id='r-bn', payment_id='r-pay-b1', at=404)
        self.st('pay_customer', id='r-pay-b2', invoice_id=late_id,
                amount=50, at=405)
        # plan B world on a separate settlement/deposit for replay breadth
        self.st('meter', id='m-b2', chassis='chassis-H', generation=3,
                counter_from=0, counter_to=30)
        self.st('deposit_facility', id='dep2', limit_amount=9999)
        rep = replay(str(self.path))
        self.assertTrue(rep['verified'], rep)
        self.assertGreater(rep['events'], 20)


if __name__ == '__main__':
    unittest.main()
