import json,tempfile,unittest
from pathlib import Path
import sandcontract
from sandcontract.store import connect,execute,replay,one,rows
from sandcontract import policy_compile as pc

ROOT=Path(__file__).resolve().parents[1]
assert Path(sandcontract.__file__).resolve().is_relative_to(ROOT)

# K1: old kernel, only the legacy clone entry point for process creation.
K1={'kernel_build':'build-k1-sha','kernel_version':'5.10-old','filter_version':'bpf-v1',
    'syscall_table':{'process_create':[{'entry':56,'abi':'amd64'}],
                     'read':[{'entry':0,'abi':'amd64'}],'write':[{'entry':1,'abi':'amd64'}],
                     'ptrace':[{'entry':101,'abi':'amd64'}]},
    'filter_caps':['arg32','arg64']}
# K2: new kernel, clone3 aliases the same semantic call through another entry.
K2={'kernel_build':'build-k2-sha','kernel_version':'6.1-new','filter_version':'bpf-v2',
    'syscall_table':{'process_create':[{'entry':56,'abi':'amd64'},{'entry':435,'abi':'amd64'}],
                     'read':[{'entry':0,'abi':'amd64'}],'write':[{'entry':1,'abi':'amd64'}],
                     'ptrace':[{'entry':101,'abi':'amd64'}]},
    'filter_caps':['arg32','arg64']}
# Vendor backport: old version string, but the table/capabilities are actually new.
K2_BACKPORT=dict(K2,kernel_build='build-backport-sha',kernel_version='5.10-old')
# Same version string as K2, but the filter engine cannot fetch 64-bit arguments.
K2_NARROW=dict(K2,kernel_build='build-narrow-sha',filter_caps=['arg32'])

POLICY={'default':'deny',
        'syscall_rules':[
         {'call':'process_create','action':'allow','mask':0x3d00,'width':64},
         {'call':'ptrace','action':'deny'}],
        'devices':[{'name':'null','action':'allow'},{'name':'kmsg','action':'deny'}],
        'network':[{'name':'egress:10.0.0.0/8','action':'allow'}]}

class PolicyCompileTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite'
  self.db=connect(str(self.path));self.n=0
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def act(self,sub,op,**fields):
  self.n+=1
  return execute(self.db,sub,dict(request_id=f'req-{self.n}',op=op,**fields))
 def register(self,nid,uid,gen,att,cap=4):
  return self.act('profile','node',id=nid,uid=uid,generation=gen,features=['seccomp'],capacity=cap,attestation=att)
 def publish(self,pid='P',rev=1,policy=POLICY,syscalls=('clone','clone3','read','write','ptrace')):
  return self.act('profile','publish',id=pid,revision=rev,syscalls=list(syscalls),devices=['null'],network=['egress'],required_feature='seccomp',policy=policy)
 def activate(self,pid='P'):return self.act('profile','activate',id=pid)
 def compile(self,pid,node):return self.act('policy_compile','compile',profile=pid,node=node)
 def load(self,rid,cid,uid,gen,fh):return self.act('policy_compile','load',id=rid,compilation=cid,node_uid=uid,node_generation=gen,filter_hash=fh)
 def digest_of(self,pid='P'):return one(self.db,'SELECT digest FROM profiles WHERE id=?',(pid,))['digest']
 def comp_row(self,cid):return one(self.db,'SELECT * FROM compilations WHERE id=?',(cid,))
 def request_w(self,wid='W',tenant='t'):
  self.act('admit','limit',tenant=tenant,max_risk=5)
  return self.act('admit','request',id=wid,tenant=tenant,profile='P',risk=2)
 def full_n1(self):
  self.register('N1','uid-n1',1,K1);self.publish();self.activate()
  c=self.compile('P','N1');self.load('rcpt-n1',c['compilation_id'],'uid-n1',1,c['filter_hash'])
  return c
 def assertReplayClean(self):self.assertTrue(replay(str(self.path))['verified'])

 def test_legacy_fixtures_and_digest_unchanged(self):
  for f in ('profile_normal','admit_normal','incident_normal','profile_failure','admit_failure','incident_failure'):
   sub=f.split('_')[0]
   for step in json.loads((ROOT/'fixtures'/f'{f}.json').read_text(encoding='utf-8')):execute(self.db,step.get('subsystem',sub),step)
  # legacy digest formula is byte-identical to the historical fixtures (rev1
  # and rev2), so old event logs and load receipts remain verifiable
  self.assertEqual(one(self.db,"SELECT profile_digest FROM starts WHERE id='start-a'")['profile_digest'],'2aaab9770b8e5d103876615ee9c8e3782b84c5fe396d06cbe1d5440def008d59')
  self.assertEqual(one(self.db,"SELECT new_digest FROM resets WHERE id='reset-a'")['new_digest'],'f5a4d49d02701f586b0389c19db6d6a64d00b1d6fab2e89fbc25e00be7219e2a')
  self.assertEqual(self.act('policy_compile','compile',profile='profile-a',node='node-a')['decision'],'legacy_profile_not_compilable')
  self.assertReplayClean()

 def test_invalid_policy_and_attestation_are_rejected(self):
  self.register('N1','uid-n1',1,K1)
  bad=dict(POLICY,default='allow')
  self.assertEqual(self.publish(policy=bad)['decision'],'invalid_policy')
  bad2=dict(POLICY,syscall_rules=[{'call':'process_create','action':'allow','mask':1,'width':128}])
  self.assertEqual(self.publish(policy=bad2)['decision'],'invalid_policy')
  bad3=dict(POLICY,syscall_rules=POLICY['syscall_rules']+[{'call':'ptrace','action':'deny'}])
  self.assertEqual(self.publish(policy=bad3)['decision'],'invalid_policy')
  self.assertEqual(self.register('NX','uid-x',1,{'kernel_build':'b','filter_version':'v'})['decision'],'invalid_attestation')
  self.assertIsNone(one(self.db,'SELECT * FROM node_attestations WHERE node_uid=?',('uid-x',)))

 def test_rule_order_and_alias_spelling_do_not_change_allowance(self):
  reordered=dict(POLICY,syscall_rules=list(reversed(POLICY['syscall_rules'])),
                 devices=list(reversed(POLICY['devices'])),network=list(reversed(POLICY['network'])))
  self.publish('P1',policy=POLICY);self.publish('P2',policy=reordered)
  self.assertEqual(self.digest_of('P1'),self.digest_of('P2'))
  self.register('N1','uid-n1',1,K1)
  self.activate('P1');self.activate('P2')
  c1=execute(self.db,'policy_compile',{'request_id':'c1','op':'compile','profile':'P1','node':'N1'})
  c2=execute(self.db,'policy_compile',{'request_id':'c2','op':'compile','profile':'P2','node':'N1'})
  self.assertEqual(c1['filter_hash'],c2['filter_hash'])
  lines=json.loads(self.comp_row(c1['compilation_id'])['filter_bytes'])
  entries={(l['entry'],l['verdict']) for l in lines if 'entry' in l}
  self.assertEqual(entries,{(56,'allow_masked'),(101,'deny')})
  self.assertEqual(lines[-1],{'default':'deny'})

 def test_activate_needs_real_attestation_and_table_entries(self):
  self.act('profile','node',id='N0',uid='uid-n0',generation=1,features=['seccomp'],capacity=2)
  self.register('N1','uid-n1',1,K1)
  missing=dict(K1,kernel_build='build-missing',syscall_table={k:v for k,v in K1['syscall_table'].items() if k!='process_create'})
  self.register('NM','uid-nm',1,missing)
  self.publish()
  r=self.activate()
  self.assertEqual(r['decision'],'active')
  # feature-only and incomplete-table nodes are excluded; only N1 qualifies
  self.assertEqual(r['nodes'],['N1'])
  self.assertIsNone(one(self.db,'SELECT * FROM node_attestations WHERE node_uid=?',('uid-n0',)))
  # a second activation attempt finds no draft anymore
  self.assertEqual(self.activate()['decision'],'not_draft')

 def test_half_baked_clone_only_filter_cannot_run_on_k2(self):
  self.register('N1','uid-n1',1,K1);self.register('N2','uid-n2',1,K2)
  self.publish();r=self.activate()
  self.assertEqual(sorted(r['nodes']),['N1','N2'])
  self.request_w()
  # no compiled+loaded contract anywhere: admission must not infer compatibility
  self.assertEqual(self.act('admit','assign',id='b2',workload='W',node='N2',at=10)['decision'],'contract_not_loaded')
  c1=self.compile('P','N1');self.assertEqual(c1['decision'],'compiled')
  # the K1 bytes only know entry 56; presenting them as the K2 receipt is a failure
  c2=self.compile('P','N2')
  self.assertEqual(self.load('fake-rcpt',c2['compilation_id'],'uid-n2',1,c1['filter_hash'])['decision'],'load_failed')
  self.assertEqual(one(self.db,"SELECT status FROM load_receipts WHERE id='fake-rcpt'")['status'],'failed')
  self.assertEqual(self.act('admit','assign',id='b2',workload='W',node='N2',at=11)['decision'],'contract_not_loaded')
  # real K2 compilation covers BOTH alias entries and keeps default deny
  lines=json.loads(self.comp_row(c2['compilation_id'])['filter_bytes'])
  pc2={l['entry']:l['verdict'] for l in lines if 'entry' in l}
  self.assertEqual(pc2[56],'allow_masked');self.assertEqual(pc2[435],'allow_masked')
  self.assertEqual(lines[-1],{'default':'deny'})
  self.assertNotEqual(c1['filter_hash'],c2['filter_hash'])
  # after the failed receipt is kept on record, the genuine byte-equal receipt still proves the load
  self.assertEqual(self.load('rcpt-n2',c2['compilation_id'],'uid-n2',1,c2['filter_hash'])['decision'],'loaded')
  self.assertEqual(self.act('admit','assign',id='b2',workload='W',node='N2',at=12)['decision'],'assigned')
  # start must prove the exact bytes; a clone-only start is rejected
  self.assertEqual(self.act('admit','start',id='s-bad',binding='b2',node_uid='uid-n2',profile_digest=self.digest_of(),filter_hash=c1['filter_hash'],at=13)['decision'],'filter_hash_mismatch')
  self.assertEqual(self.act('admit','start',id='s-ok',binding='b2',node_uid='uid-n2',profile_digest=self.digest_of(),filter_hash=c2['filter_hash'],at=14)['decision'],'started')
  ev=one(self.db,"SELECT * FROM start_evidence WHERE start_id='s-ok'")
  self.assertEqual((ev['filter_hash'],ev['kernel_build']),(c2['filter_hash'],'build-k2-sha'))
  self.assertReplayClean()

 def test_delivery_path_a_pin_workload_on_measured_n1(self):
  c1=self.full_n1();self.register('N2','uid-n2',1,K2)
  self.act('admit','limit',tenant='t',max_risk=5)
  self.act('admit','request',id='W',tenant='t',profile='P',risk=2)
  self.assertEqual(self.act('admit','assign',id='b2a',workload='W',node='N2',at=10)['decision'],'contract_not_loaded')
  self.assertEqual(self.act('admit','assign',id='b1',workload='W',node='N1',at=10)['decision'],'assigned')
  self.assertEqual(self.act('admit','start',id='s1',binding='b1',node_uid='uid-n1',profile_digest=self.digest_of(),filter_hash=c1['filter_hash'],at=11)['decision'],'started')
  self.assertEqual(one(self.db,"SELECT status FROM workloads WHERE id='W'")['status'],'running')
  self.assertReplayClean()

 def test_argument_width_reject_is_persisted_and_never_loosened(self):
  self.register('N2','uid-n2',1,K2_NARROW);self.publish();self.activate()
  r=self.compile('P','N2')
  self.assertEqual(r['decision'],'arg_width_unsupported')
  row=self.comp_row(r['compilation_id'])
  self.assertEqual(row['status'],'rejected');self.assertIsNone(row['filter_hash'])
  # replaying the compile returns the same recorded rejection, not a new allowance
  self.assertEqual(self.compile('P','N2')['decision'],'arg_width_unsupported')
  self.request_w()
  self.assertEqual(self.act('admit','assign',id='b',workload='W',node='N2',at=10)['decision'],'contract_not_loaded')
  # engine upgrade (new node generation) expressing 64-bit fetch unlocks a fresh compilation
  self.register('N2','uid-n2-r2',2,K2)
  r2=self.compile('P','N2');self.assertEqual(r2['decision'],'compiled')
  self.assertNotEqual(r['compilation_id'],r2['compilation_id'])
  self.assertEqual(self.comp_row(r['compilation_id'])['status'],'rejected')

 def test_backport_decided_by_table_and_caps_not_version_string(self):
  self.register('OLD','uid-old',1,K1)
  self.register('BP','uid-bp',1,K2_BACKPORT)  # same version string as K1, real clone3 backport
  self.register('NW','uid-nw',1,K2_NARROW)    # same version string as K2, missing arg64
  self.publish();self.activate()
  bp=self.compile('P','BP');self.assertEqual(bp['decision'],'compiled')
  entries={l['entry'] for l in json.loads(self.comp_row(bp['compilation_id'])['filter_bytes']) if 'entry' in l}
  self.assertEqual(entries,{56,101,435})
  self.assertEqual(self.compile('P','NW')['decision'],'arg_width_unsupported')

 def test_unexpressed_entry_is_rejected_not_silently_allowed(self):
  k=dict(K1,kernel_build='build-no-ptrace',syscall_table={k:v for k,v in K1['syscall_table'].items() if k!='ptrace'})
  self.register('N','uid-n',1,k)
  # activation fails when no node can express every governed call...
  self.publish()
  self.assertEqual(self.activate()['decision'],'no_compatible_node')
  # ...and a policy using only expressible calls activates, while a wider policy
  # later fails compilation rather than silently dropping its deny rule
  narrow={'default':'deny','syscall_rules':[{'call':'process_create','action':'allow','mask':0x3d00,'width':64}],
          'devices':[{'name':'null','action':'allow'}],'network':[]}
  self.publish('Q',policy=narrow,syscalls=('clone','read'))
  self.assertEqual(self.activate('Q')['decision'],'active')
  wide=dict(narrow,syscall_rules=narrow['syscall_rules']+[{'call':'ptrace','action':'deny'}])
  self.publish('R',policy=wide,syscalls=('clone','ptrace','read'))
  self.assertEqual(self.activate('R')['decision'],'no_compatible_node')
  r=execute(self.db,'policy_compile',{'request_id':'rc','op':'compile','profile':'Q','node':'N'})
  self.assertEqual(r['decision'],'compiled')

 def test_node_rebuild_invalidates_old_contract_and_late_receipt(self):
  c=self.full_n1()
  self.register('N1','uid-n1-r2',2,dict(K1,kernel_build='build-k1-rebuilt'))
  self.request_w()
  self.assertEqual(self.act('admit','assign',id='b',workload='W',node='N1',at=10)['decision'],'contract_not_loaded')
  # late receipt proving the old kernel cannot authorize the rebuilt node
  self.assertEqual(self.load('late',c['compilation_id'],'uid-n1',1,c['filter_hash'])['decision'],'stale_load_receipt')
  c2=self.compile('P','N1');self.assertEqual(c2['decision'],'compiled')
  self.assertNotEqual(c['filter_hash'],c2['filter_hash'])
  self.assertEqual(self.load('rcpt2',c2['compilation_id'],'uid-n1-r2',2,c2['filter_hash'])['decision'],'loaded')
  self.assertEqual(self.act('admit','assign',id='b',workload='W',node='N1',at=11)['decision'],'assigned')

 def test_profile_reversion_rebinds_artifacts_but_keeps_old_evidence(self):
  c1=self.full_n1();self.request_w()
  self.act('admit','assign',id='b',workload='W',node='N1',at=10)
  self.act('admit','start',id='s1',binding='b',node_uid='uid-n1',profile_digest=self.digest_of(),filter_hash=c1['filter_hash'],at=11)
  old_digest=self.digest_of()
  rev2=dict(POLICY,syscall_rules=[{'call':'process_create','action':'allow','mask':0x1d00,'width':64},{'call':'ptrace','action':'deny'}])
  self.assertEqual(self.publish(rev=2,policy=rev2)['decision'],'published')
  self.activate()
  self.assertEqual(one(self.db,"SELECT status FROM bindings WHERE id='b'")['status'],'at_risk')
  self.assertEqual(one(self.db,"SELECT status FROM workloads WHERE id='W'")['status'],'running')
  ev=one(self.db,"SELECT * FROM start_evidence WHERE start_id='s1'")
  self.assertEqual((ev['filter_hash'],one(self.db,"SELECT profile_digest FROM starts WHERE id='s1'")['profile_digest']),(c1['filter_hash'],old_digest))
  c2=self.compile('P','N1');self.assertNotEqual(c1['filter_hash'],c2['filter_hash'])
  # the old receipt cannot satisfy the new profile revision
  self.request_w('W2')
  self.assertEqual(self.act('admit','assign',id='b2',workload='W2',node='N1',at=12)['decision'],'contract_not_loaded')
  self.load('rcpt2',c2['compilation_id'],'uid-n1',1,c2['filter_hash'])
  self.assertEqual(self.act('admit','assign',id='b2',workload='W2',node='N1',at=13)['decision'],'assigned')
  self.assertReplayClean()

 def test_revocation_replay_and_running_workload_keep_their_evidence(self):
  c=self.full_n1();self.request_w()
  self.act('admit','assign',id='b',workload='W',node='N1',at=10)
  self.assertEqual(self.act('admit','start',id='s1',binding='b',node_uid='uid-n1',profile_digest=self.digest_of(),filter_hash=c['filter_hash'],at=11)['decision'],'started')
  self.assertEqual(self.act('profile','revoke',id='P',revision=1)['decision'],'revoked')
  # confirmed start is never relabeled; workload keeps running under its period evidence
  self.assertEqual(one(self.db,"SELECT status FROM workloads WHERE id='W'")['status'],'running')
  self.assertEqual(one(self.db,"SELECT filter_hash FROM start_evidence WHERE start_id='s1'")['filter_hash'],c['filter_hash'])
  self.assertEqual(self.act('profile','revoke',id='P',revision=1)['decision'],'revoked')
  self.assertEqual(self.act('profile','revoke',id='P',revision=99)['decision'],'stale_revocation')
  self.request_w('W2')
  self.assertEqual(self.act('admit','assign',id='b2',workload='W2',node='N1',at=12)['decision'],'assignment_denied')
  self.assertReplayClean()

 def test_late_load_receipt_after_revoke_grants_no_authority(self):
  c=self.full_n1()
  self.assertEqual(self.act('profile','revoke',id='P',revision=1)['decision'],'revoked')
  # receipt eventually arrives and is recorded, but no new request can use it
  self.assertEqual(self.load('late',c['compilation_id'],'uid-n1',1,c['filter_hash'])['decision'],'loaded')
  self.request_w()
  self.assertEqual(self.act('admit','assign',id='b',workload='W',node='N1',at=10)['decision'],'assignment_denied')

 def test_load_receipt_idempotent_and_replay_deterministic(self):
  self.register('N1','uid-n1',1,K1);self.publish();self.activate()
  c=self.compile('P','N1')
  first={'request_id':'fixed-load','op':'load','id':'rcpt','compilation':c['compilation_id'],'node_uid':'uid-n1','node_generation':1,'filter_hash':c['filter_hash']}
  self.assertEqual(execute(self.db,'policy_compile',first)['decision'],'loaded')
  self.assertEqual(execute(self.db,'policy_compile',dict(first))['decision'],'loaded')
  self.assertEqual(len(rows(self.db,"SELECT * FROM load_receipts WHERE compilation_id=?",(c['compilation_id'],))),1)
  self.assertReplayClean()

 def test_artifact_binds_profile_node_attestation_and_bytes(self):
  self.register('N1','uid-n1',1,K1);self.register('N2','uid-n2',1,K2)
  self.publish();self.activate()
  c1=self.compile('P','N1');c2=self.compile('P','N2')
  r1=self.comp_row(c1['compilation_id'])
  self.assertEqual((r1['profile'],r1['node_uid'],r1['node_generation']),('P','uid-n1',1))
  self.assertEqual(r1['attestation_digest'],one(self.db,'SELECT attestation_digest FROM node_attestations WHERE node_uid=?',('uid-n1',))['attestation_digest'])
  self.assertNotEqual(r1['filter_hash'],self.comp_row(c2['compilation_id'])['filter_hash'])
  # a kernel rebuild changes the artifact even if entry numbers happen to match
  self.register('N1','uid-n1b',2,dict(K1,kernel_build='build-k1-sha-v2'))
  c3=self.compile('P','N1')
  self.assertNotEqual(c1['filter_hash'],c3['filter_hash'])

 def test_release_requires_loaded_contract_for_policy_profile(self):
  c=self.full_n1();self.request_w()
  self.act('admit','assign',id='b',workload='W',node='N1',at=10)
  self.act('admit','start',id='s1',binding='b',node_uid='uid-n1',profile_digest=self.digest_of(),filter_hash=c['filter_hash'],at=11)
  self.act('incident','observe',id='v1',binding='b',kind='syscall',source='agent-a',at=12,confidence=95)
  self.act('incident','quarantine',id='case',binding='b',scope='binding',reason='violation')
  rev2=dict(POLICY,syscall_rules=[{'call':'process_create','action':'allow','mask':0x1d00,'width':64},{'call':'ptrace','action':'deny'}])
  self.publish(rev=2,policy=rev2);self.activate();new=self.digest_of()
  self.act('incident','reset',id='reset',binding='b',node_uid='uid-n1',new_digest=new,at=13)
  # new revision has no loaded contract yet: release cannot proceed
  self.assertEqual(self.act('incident','release',incident='case',new_profile='P',at=14)['decision'],'release_unverified')
  c2=self.compile('P','N1');self.load('rcpt2',c2['compilation_id'],'uid-n1',1,c2['filter_hash'])
  self.assertEqual(self.act('incident','release',incident='case',new_profile='P',at=15)['decision'],'released')
  self.assertReplayClean()

if __name__=='__main__':unittest.main()
