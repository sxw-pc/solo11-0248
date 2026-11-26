import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute,replay,one,rows
ROOT=Path(__file__).resolve().parents[1]

class SecretRecoveryTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite';self.db=connect(str(self.path));self.n=0
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def act(self,op,**fields):
  self.n+=1;return execute(self.db,'secret',dict(request_id=f's-{self.n}',op=op,**fields))
 def admit(self,op,**fields):
  self.n+=1;return execute(self.db,'admit',dict(request_id=f'a-{self.n}',op=op,**fields))['decision']
 def incident(self,op,**fields):
  self.n+=1;return execute(self.db,'incident',dict(request_id=f'i-{self.n}',op=op,**fields))['decision']
 def base(self):
  for name in ('profile_normal','admit_normal'):
   sub=name.split('_')[0]
   for x in json.loads((ROOT/'fixtures'/f'{name}.json').read_text(encoding='utf-8')):execute(self.db,x.get('subsystem',sub),x)
 def scenario(self,snapshot=True):
  # dataset D serves K1 v1; W (workload-a on node-a) holds write lease L1 and
  # has confirmed records 81..86 to the customer; replica snapshot reaches 84.
  self.base()
  self.assertEqual(self.act('dataset',id='D',key_id='K1',version=1,at=1)['decision'],'dataset_recorded')
  r=self.act('lease',id='L1',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='write',expires_at=100,at=10)
  self.assertEqual(r['decision'],'issued')
  for rec in range(81,87):self.assertEqual(self.act('customer_ack',id=f'ack-{rec}',dataset='D',record=rec,at=rec-70)['decision'],'ack_recorded')
  if snapshot:self.assertEqual(self.act('snapshot',id='S1',dataset='D',up_to=84,key_id='K1',version=1,at=15)['decision'],'snapshot_recorded')
 def copies(self):
  self.assertEqual(self.act('copy',id='C1',key_id='K1',version=1,holder='sidecar-1',kind='sidecar',online=True,at=12)['decision'],'copy_recorded')
  self.assertEqual(self.act('copy',id='C2',key_id='K1',version=1,holder='backup-1',kind='backup',online=True,at=12)['decision'],'copy_recorded')
  self.assertEqual(self.act('copy',id='C3',key_id='K1',version=1,holder='agent-off-1',kind='offline_agent',online=False,at=12)['decision'],'copy_recorded')
 def compromise(self):
  r=self.act('compromise',id='CMP',key_id='K1',version=1,evidence='custody-log-77',at=20)
  self.assertEqual(r['decision'],'compromise_recorded')
  return r
 def fence_db(self,at=30):
  self.assertEqual(self.act('fence',id='F-db',key_id='K1',version=1,holder='db',at=at)['decision'],'fence_recorded')
 def fence_rest(self,at=31):
  self.assertEqual(self.act('fence',id='F-l1',key_id='K1',version=1,holder='L1',at=at)['decision'],'fence_recorded')
  self.assertEqual(self.act('fence',id='F-c1',key_id='K1',version=1,holder='sidecar-1',at=at)['decision'],'fence_recorded')
  self.assertEqual(self.act('fence',id='F-c2',key_id='K1',version=1,holder='backup-1',at=at)['decision'],'fence_recorded')
  self.assertEqual(self.act('destroy',id='F-c3',key_id='K1',version=1,holder='agent-off-1',attestation='zeroize-99',at=at)['decision'],'copy_destroyed')
 def start_b(self):
  digest=one(self.db,'SELECT digest FROM profiles WHERE id=?',('profile-a',))['digest']
  self.assertEqual(self.admit('request',id='workload-b',tenant='tenant-a',profile='profile-a',risk=1),'requested')
  self.assertEqual(self.admit('assign',id='binding-b',workload='workload-b',node='node-a',at=9),'assigned')
  self.assertEqual(self.admit('start',id='start-b',binding='binding-b',node_uid='node-uid-a',profile_digest=digest,at=10),'started')

 def test_lease_requires_start_and_binds_identity(self):
  self.base()
  self.act('dataset',id='D',key_id='K1',version=1,at=1)
  self.assertEqual(self.act('lease',id='L0',workload='workload-a',start_id='start-z',dataset='D',key_id='K1',version=1,purpose='write',expires_at=100,at=5)['decision'],'unavailable')
  r=self.act('lease',id='L1',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='write',expires_at=100,at=10)
  self.assertEqual(r['decision'],'issued');self.assertEqual(r['generation'],1)
  row=one(self.db,'SELECT * FROM key_leases WHERE id=?',('L1',))
  self.assertEqual((row['workload'],row['start_id'],row['generation'],row['key_id'],row['version'],row['purpose'],row['expires_at']),('workload-a','start-a',1,'K1',1,'write',100))
  self.assertEqual(self.act('lease',id='L1',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='write',expires_at=100,at=11)['decision'],'reused')
  self.assertEqual(self.act('lease',id='L1',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='read',expires_at=100,at=11)['decision'],'conflict')
  self.assertEqual(self.act('lease',id='L2',workload='workload-b',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='read',expires_at=100,at=11)['decision'],'lease_binding_mismatch')
  self.assertEqual(self.act('lease',id='L3',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='read',expires_at=5,at=11)['decision'],'expired_lease')
  self.assertEqual(self.act('lease',id='L4',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='admin',expires_at=100,at=11)['decision'],'invalid_purpose')
  self.assertEqual(self.act('lease',id='L5',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='write',expires_at=100,at=11)['decision'],'writer_conflict')

 def test_holders_lists_every_live_copy(self):
  self.scenario();self.copies()
  st=self.act('status',key_id='K1',version=1,at=18)
  self.assertEqual(sorted(st['open_holders']),['L1','agent-off-1','backup-1','db','sidecar-1'])
  kinds={h['holder']:h['kind'] for h in st['holders']}
  self.assertEqual(kinds,{'db':'database','L1':'lease','sidecar-1':'sidecar','backup-1':'backup','agent-off-1':'offline_agent'})
  self.assertFalse(st['compromised'])
  self.assertEqual(self.act('copy',id='C9',key_id='K9',version=1,holder='x',kind='backup',online=True,at=18)['decision'],'unknown_key')
  self.assertEqual(self.act('copy',id='C1',key_id='K1',version=1,holder='other',kind='backup',online=True,at=18)['decision'],'duplicate_copy')

 def test_halt_rebuild_path_with_late_db_receipt(self):
  self.scenario();self.copies();self.compromise()
  self.assertEqual(self.act('strategy',id='ST',key_id='K1',version=1,mode='halt_rebuild',at=20)['decision'],'strategy_recorded')
  self.assertEqual(self.act('halt',id='H',workload='workload-a',dataset='D',at=21)['decision'],'halted')
  # control-plane revocation is recorded, yet the token is still accepted
  self.assertEqual(one(self.db,'SELECT state FROM key_leases WHERE id=?',('L1',))['state'],'revoked')
  st=self.act('status',key_id='K1',version=1,at=22)
  self.assertTrue(st['old_key_live'])
  self.assertEqual(sorted(st['open_holders']),['L1','agent-off-1','backup-1','db','sidecar-1'])
  # rebuild cannot start before the database physically rejects K1
  self.assertEqual(self.act('customer_log',id='CL',dataset='D',records=[85,86],at=29)['decision'],'log_recorded')
  self.assertEqual(self.act('rebuild',id='RB',dataset='D',to_key='K2',to_version=2,at=29)['decision'],'db_not_fenced')
  self.fence_db(at=30)
  r=self.act('rebuild',id='RB2',dataset='D',to_key='K2',to_version=2,at=32)
  self.assertEqual(r['decision'],'rebuilt')
  self.assertEqual(r['sources'],{'snapshot':84,'customer-log':2})
  self.assertEqual(r['downtime'],11)
  pages=rows(self.db,'SELECT * FROM dataset_pages WHERE dataset=? ORDER BY record',('D',))
  self.assertEqual(len(pages),86)
  self.assertTrue(all(p['key_id']=='K2' and p['version']==2 for p in pages))
  # revocation is not done while any holder can still decrypt
  self.assertEqual(self.act('complete',id='DONE',key_id='K1',version=1,at=33)['decision'],'holders_open')
  self.fence_rest(at=33)
  self.assertEqual(self.act('complete',id='DONE2',key_id='K1',version=1,at=35)['decision'],'recovery_complete')
  st=self.act('status',key_id='K1',version=1,at=36)
  self.assertFalse(st['old_key_live'])
  self.assertEqual(st['datasets'][0]['restored_at'],32)
  self.assertTrue(replay(str(self.path))['verified'])

 def test_managed_transition_path_keeps_service_and_unmasked_window(self):
  self.scenario();self.copies();self.start_b();self.compromise()
  self.assertEqual(self.act('strategy',id='ST',key_id='K1',version=1,mode='managed_transition',at=20)['decision'],'strategy_recorded')
  r=self.act('convert',id='CV',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=21)
  self.assertEqual(r['decision'],'staged')
  self.assertEqual(r['sources'],{'live':6,'snapshot':80})
  r=self.act('takeover',id='TO',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=22)
  self.assertEqual(r['decision'],'took_over');self.assertEqual(r['downtime'],0)
  # atomic handoff: exactly one write lease, old instance retired in the same step
  writers=rows(self.db,"SELECT id FROM key_leases WHERE dataset='D' AND purpose='write' AND state='issued'")
  self.assertEqual([w['id'] for w in writers],['TO:lease'])
  self.assertEqual(one(self.db,'SELECT state FROM key_leases WHERE id=?',('L1',))['state'],'revoked')
  pages=rows(self.db,'SELECT * FROM dataset_pages WHERE dataset=?',('D',))
  self.assertEqual(len(pages),86)
  self.assertFalse([p for p in pages if p['key_id']=='K1'])
  # the new serving version does not mask the old-key-usable window
  st=self.act('status',key_id='K1',version=1,at=23)
  self.assertTrue(st['old_key_live'])
  self.assertIn('db',st['open_holders'])
  self.assertEqual(self.act('complete',id='DONE',key_id='K1',version=1,at=23)['decision'],'holders_open')
  self.fence_db(at=30);self.fence_rest(at=31)
  self.assertEqual(self.act('complete',id='DONE2',key_id='K1',version=1,at=35)['decision'],'recovery_complete')
  self.assertFalse(self.act('status',key_id='K1',version=1,at=36)['old_key_live'])
  self.assertTrue(replay(str(self.path))['verified'])

 def test_convert_interruption_leaves_no_orphan_pages(self):
  self.scenario(snapshot=False);self.start_b();self.compromise()
  self.act('strategy',id='ST',key_id='K1',version=1,mode='managed_transition',at=20)
  # without the snapshot the prefix has no source: conversion fails atomically
  r=self.act('convert',id='CV',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=21)
  self.assertEqual(r['decision'],'missing_source');self.assertEqual(r['record'],1)
  self.assertEqual(rows(self.db,'SELECT * FROM staged_pages'),[])
  before=rows(self.db,'SELECT * FROM dataset_pages ORDER BY record')
  self.assertEqual(len(before),6)
  self.assertTrue(all(p['key_id']=='K1' for p in before))
  # staged conversion is invisible until cutover; interruption changes nothing
  self.act('snapshot',id='S1',dataset='D',up_to=84,key_id='K1',version=1,at=15)
  self.assertEqual(self.act('convert',id='CV2',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=22)['decision'],'staged')
  self.assertEqual(rows(self.db,'SELECT * FROM dataset_pages ORDER BY record'),before)
  self.assertEqual(one(self.db,'SELECT serving_key FROM datasets WHERE id=?',('D',))['serving_key'],'K1')
  self.assertEqual(self.act('takeover',id='TO',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=23)['decision'],'took_over')
  pages=rows(self.db,'SELECT * FROM dataset_pages WHERE dataset=?',('D',))
  self.assertEqual(len(pages),86)
  self.assertFalse([p for p in pages if p['key_id']=='K1'])
  self.assertEqual(rows(self.db,'SELECT * FROM staged_pages'),[])

 def test_snapshot_gap_requires_customer_logs(self):
  self.scenario();self.compromise()
  self.act('strategy',id='ST',key_id='K1',version=1,mode='halt_rebuild',at=20)
  self.act('halt',id='H',workload='workload-a',dataset='D',at=21)
  self.fence_db(at=30)
  r=self.act('rebuild',id='RB',dataset='D',to_key='K2',to_version=2,at=31)
  self.assertEqual(r['decision'],'missing_source');self.assertEqual(r['record'],85)
  self.assertEqual(self.act('customer_log',id='CL1',dataset='D',records=[85],at=31)['decision'],'log_recorded')
  r=self.act('rebuild',id='RB2',dataset='D',to_key='K2',to_version=2,at=32)
  self.assertEqual(r['decision'],'missing_source');self.assertEqual(r['record'],86)
  # a log for a record the customer never confirmed is not a valid source
  self.assertEqual(self.act('customer_log',id='CLX',dataset='D',records=[90],at=32)['decision'],'unacked_record')
  self.assertEqual(self.act('customer_log',id='CL2',dataset='D',records=[86],at=32)['decision'],'log_recorded')
  self.assertEqual(self.act('rebuild',id='RB3',dataset='D',to_key='K2',to_version=2,at=33)['decision'],'rebuilt')

 def test_offline_agent_needs_attested_destroy(self):
  self.scenario();self.copies();self.compromise()
  self.assertEqual(self.act('fence',id='F1',key_id='K1',version=1,holder='agent-off-1',at=21)['decision'],'holder_offline')
  self.assertEqual(self.act('destroy',id='D1',key_id='K1',version=1,holder='agent-off-1',at=21)['decision'],'attestation_missing')
  self.assertEqual(self.act('destroy',id='D2',key_id='K1',version=1,holder='sidecar-1',attestation='x',at=21)['decision'],'holder_online')
  self.assertEqual(self.act('fence',id='F2',key_id='K1',version=1,holder='nobody',at=21)['decision'],'unknown_holder')
  r=self.act('destroy',id='D3',key_id='K1',version=1,holder='agent-off-1',attestation='zeroize-99',at=22)
  self.assertEqual(r['decision'],'copy_destroyed')
  self.assertNotIn('agent-off-1',r['open_holders'])
  self.assertEqual(self.act('destroy',id='D4',key_id='K1',version=1,holder='agent-off-1',attestation='zeroize-99',at=23)['decision'],'duplicate_fence')

 def test_duplicate_takeover_rejected(self):
  self.scenario();self.start_b();self.compromise()
  self.act('strategy',id='ST',key_id='K1',version=1,mode='managed_transition',at=20)
  self.act('convert',id='CV',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=21)
  self.assertEqual(self.act('takeover',id='TO',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=22)['decision'],'took_over')
  self.assertEqual(self.act('takeover',id='TO2',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=23)['decision'],'no_staged_conversion')
  self.assertEqual(self.act('lease',id='L9',workload='workload-a',start_id='start-a',dataset='D',key_id='K2',version=2,purpose='write',expires_at=300,at=24)['decision'],'writer_conflict')
  writers=rows(self.db,"SELECT id FROM key_leases WHERE dataset='D' AND purpose='write' AND state='issued'")
  self.assertEqual(len(writers),1)

 def test_late_ack_forces_reconversion_before_takeover(self):
  self.scenario();self.start_b();self.compromise()
  self.act('strategy',id='ST',key_id='K1',version=1,mode='managed_transition',at=20)
  self.act('convert',id='CV',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=21)
  # old writer confirms one more record while the conversion is staged
  self.assertEqual(self.act('customer_ack',id='ack-87',dataset='D',record=87,at=22)['decision'],'ack_recorded')
  self.assertEqual(self.act('takeover',id='TO',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=23)['decision'],'no_staged_conversion')
  self.assertEqual(self.act('convert',id='CV2',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=24)['decision'],'staged')
  self.assertEqual(self.act('takeover',id='TO2',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=25)['decision'],'took_over')
  p=one(self.db,'SELECT * FROM dataset_pages WHERE dataset=? AND record=87',('D',))
  self.assertEqual((p['key_id'],p['version']),('K2',2))

 def test_customer_read_facts_survive_recovery(self):
  self.scenario();self.copies()
  self.assertEqual(self.act('read',id='R1',dataset='D',record=81,key_id='K1',version=1,at=17)['classification'],'legitimate')
  self.assertEqual(self.act('read',id='R2',dataset='D',record=84,key_id='K1',version=1,at=18)['classification'],'legitimate')
  self.compromise()
  self.assertEqual(self.act('read',id='R3',dataset='D',record=85,key_id='K1',version=1,at=21)['classification'],'exposed_window')
  self.act('strategy',id='ST',key_id='K1',version=1,mode='halt_rebuild',at=21)
  self.act('halt',id='H',workload='workload-a',dataset='D',at=22)
  self.act('customer_log',id='CL',dataset='D',records=[85,86],at=28)
  self.fence_db(at=30)
  self.act('rebuild',id='RB',dataset='D',to_key='K2',to_version=2,at=32)
  self.fence_rest(at=33)
  self.assertEqual(self.act('complete',id='DONE',key_id='K1',version=1,at=40)['decision'],'recovery_complete')
  reads=self.act('reads',dataset='D')['reads']
  self.assertEqual([(r['record'],r['classification']) for r in reads],[(81,'legitimate'),(84,'legitimate'),(85,'exposed_window')])
  for rec in (81,84,85):
   p=one(self.db,'SELECT * FROM dataset_pages WHERE dataset=? AND record=?',('D',rec))
   self.assertEqual(p['key_id'],'K2')
  self.assertTrue(replay(str(self.path))['verified'])

 def test_late_replication_report_only_appends(self):
  self.scenario();self.copies();self.start_b();self.compromise()
  self.act('strategy',id='ST',key_id='K1',version=1,mode='managed_transition',at=20)
  self.act('convert',id='CV',dataset='D',to_key='K2',to_version=2,boundary='hsm-1',at=21)
  self.act('takeover',id='TO',dataset='D',workload='workload-b',start_id='start-b',expires_at=200,at=22)
  self.fence_db(at=30);self.fence_rest(at=31)
  self.assertEqual(self.act('complete',id='DONE',key_id='K1',version=1,at=35)['decision'],'recovery_complete')
  fences_before=rows(self.db,'SELECT * FROM key_fences ORDER BY id')
  evidence_before=rows(self.db,'SELECT * FROM key_compromises')
  # a belated report surfaces another offline copy of the stolen key
  r=self.act('copy',id='C4',key_id='K1',version=1,holder='agent-off-2',kind='offline_agent',online=False,at=40)
  self.assertEqual(r['decision'],'late_copy_recorded')
  # delivered revocation evidence is untouched; scope and notification only grow
  self.assertEqual(rows(self.db,'SELECT * FROM key_fences ORDER BY id'),fences_before)
  self.assertEqual(rows(self.db,'SELECT * FROM key_compromises'),evidence_before)
  notes=self.act('notifications')['notifications']
  self.assertEqual(notes[-1]['kind'],'affected_scope_extended')
  st=self.act('status',key_id='K1',version=1,at=41)
  self.assertTrue(st['old_key_live'])
  self.assertIn('agent-off-2',st['open_holders'])
  self.assertEqual(self.act('complete',id='DONE2',key_id='K1',version=1,at=42)['decision'],'holders_open')
  self.assertEqual(self.act('destroy',id='F-c4',key_id='K1',version=1,holder='agent-off-2',attestation='zeroize-100',at=43)['decision'],'copy_destroyed')
  self.assertEqual(self.act('complete',id='DONE3',key_id='K1',version=1,at=44)['decision'],'recovery_complete')
  self.assertTrue(replay(str(self.path))['verified'])

 def test_new_version_row_does_not_prove_old_key_dead_or_data_safe(self):
  self.scenario();self.copies();self.start_b();self.compromise()
  # the naive fix: add a K2 lease row and admit by the latest version
  self.assertEqual(self.act('lease',id='L2',workload='workload-b',start_id='start-b',dataset='D',key_id='K2',version=2,purpose='read',expires_at=200,at=21)['decision'],'issued')
  st=self.act('status',key_id='K1',version=1,at=22)
  self.assertTrue(st['old_key_live'])
  self.assertEqual(self.act('complete',id='DONE',key_id='K1',version=1,at=22)['decision'],'holders_open')
  # confirmed records 85..86 still have no K2-readable source
  self.act('strategy',id='ST',key_id='K1',version=1,mode='halt_rebuild',at=22)
  self.act('halt',id='H',workload='workload-a',dataset='D',at=23)
  self.fence_db(at=30)
  self.assertEqual(self.act('rebuild',id='RB',dataset='D',to_key='K2',to_version=2,at=31)['decision'],'missing_source')
  self.act('customer_log',id='CL',dataset='D',records=[85,86],at=31)
  self.fence_rest(at=32)
  self.assertEqual(self.act('complete',id='DONE2',key_id='K1',version=1,at=33)['decision'],'still_serving_compromised_key')
  self.assertEqual(self.act('rebuild',id='RB2',dataset='D',to_key='K2',to_version=2,at=34)['decision'],'rebuilt')
  self.assertEqual(self.act('complete',id='DONE3',key_id='K1',version=1,at=35)['decision'],'recovery_complete')
  self.assertTrue(replay(str(self.path))['verified'])

 def test_compromise_feeds_isolation_and_blocks_new_lease(self):
  self.scenario();self.compromise()
  v=one(self.db,"SELECT * FROM violations WHERE id='CMP:signal:binding-a'")
  self.assertIsNotNone(v)
  self.assertEqual((v['kind'],v['source'],v['confidence']),('secret-compromise','custody-log',100))
  self.assertEqual(self.incident('quarantine',id='case',binding='binding-a',scope='binding',reason='key theft'),'binding_quarantined')
  self.assertEqual(self.act('lease',id='L9',workload='workload-a',start_id='start-a',dataset='D',key_id='K2',version=2,purpose='read',expires_at=100,at=21)['decision'],'binding_quarantined')
  self.assertEqual(self.act('lease',id='L8',workload='workload-a',start_id='start-a',dataset='D',key_id='K1',version=1,purpose='read',expires_at=100,at=21)['decision'],'key_compromised')
  self.assertTrue(replay(str(self.path))['verified'])

 def test_compromise_and_strategy_guards(self):
  self.scenario()
  self.assertEqual(self.act('compromise',id='CX',key_id='K9',version=1,evidence='e',at=20)['decision'],'unknown_key')
  self.assertEqual(self.act('fence',id='F0',key_id='K1',version=1,holder='db',at=19)['decision'],'no_compromise')
  self.assertEqual(self.act('strategy',id='S0',key_id='K1',version=1,mode='halt_rebuild',at=19)['decision'],'no_compromise')
  self.compromise()
  self.assertEqual(self.act('compromise',id='CMP2',key_id='K1',version=1,evidence='other',at=21)['decision'],'already_compromised')
  self.assertEqual(self.act('compromise',id='CMP',key_id='K1',version=1,evidence='other',at=21)['decision'],'duplicate_report')
  self.assertEqual(self.act('strategy',id='S1',key_id='K1',version=1,mode='restart',at=20)['decision'],'invalid_strategy')
  self.assertEqual(self.act('strategy',id='S2',key_id='K1',version=1,mode='halt_rebuild',at=20)['decision'],'strategy_recorded')
  self.assertEqual(self.act('strategy',id='S3',key_id='K1',version=1,mode='managed_transition',at=21)['decision'],'strategy_conflict')

if __name__=='__main__':unittest.main()
