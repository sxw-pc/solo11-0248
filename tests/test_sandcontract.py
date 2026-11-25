import json,tempfile,unittest
from pathlib import Path
import sandcontract
from sandcontract.store import connect,execute,replay,one
ROOT=Path(__file__).resolve().parents[1]
assert Path(sandcontract.__file__).resolve().is_relative_to(ROOT)
print('module_file',sandcontract.__file__)

class Workflows(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite';self.db=connect(str(self.path));self.n=0
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def act(self,sub,op,**fields):
  self.n+=1;return execute(self.db,sub,dict(request_id=f'custom-{self.n}',op=op,**fields))['decision']
 def fixture(self,name):
  sub=name.split('_')[0]
  return [execute(self.db,x.get('subsystem',sub),x) for x in json.loads((ROOT/'fixtures'/f'{name}.json').read_text(encoding='utf-8'))]
 def base(self):self.fixture('profile_normal');self.fixture('admit_normal')
 def test_six_fixtures_and_replay(self):
  results=[]
  for kind in ('normal','failure'):
   for sub in ('profile','admit','incident'):results+=self.fixture(f'{sub}_{kind}')
  self.assertIn('tenant_frozen',[x['decision'] for x in results]);self.assertIn('released',[x['decision'] for x in results])
  self.assertTrue(replay(str(self.path))['verified'])
 def test_profile_activation_needs_node_feature(self):
  self.act('profile','publish',id='p',revision=1,syscalls=['read'],devices=[],network=[],required_feature='seccomp')
  self.assertEqual(self.act('profile','activate',id='p'),'no_compatible_node')
 def test_profile_revision_marks_running_binding_at_risk(self):
  self.base()
  self.act('profile','publish',id='profile-a',revision=2,syscalls=['read'],devices=[],network=[],required_feature='seccomp')
  self.assertEqual(one(self.db,'SELECT status FROM bindings WHERE id=?',('binding-a',))['status'],'at_risk')
  self.assertEqual(self.act('admit','start',id='again',binding='binding-a',node_uid='node-uid-a',profile_digest='wrong',at=10),'stale_start_receipt')
 def test_tenant_risk_limit_controls_request(self):
  self.fixture('profile_normal');self.act('admit','limit',tenant='t',max_risk=1)
  self.assertEqual(self.act('admit','request',id='w',tenant='t',profile='profile-a',risk=2),'request_denied')
 def test_two_distinct_approvals_required(self):
  self.fixture('profile_normal');self.act('admit','limit',tenant='t',max_risk=3);self.act('admit','request',id='w',tenant='t',profile='profile-a',risk=2)
  self.act('admit','exception',id='e',workload='w',capability='net-admin',until_ts=50,at=2)
  self.assertEqual(self.act('admit','approve',id='a1',exception='e',role='security',actor='alice',until_ts=45,at=3),'pending_second_role')
  self.assertEqual(self.act('admit','approve',id='a2',exception='e',role='owner',actor='alice',until_ts=45,at=4),'pending_second_role')
  self.assertEqual(self.act('admit','assign',id='b',workload='w',node='node-a',capability='net-admin',at=5),'exception_missing')
  self.assertEqual(self.act('admit','approve',id='a3',exception='e',role='owner',actor='bob',until_ts=45,at=6),'approved')
 def test_node_capacity_and_generation_are_bound(self):
  self.base()
  self.assertEqual(self.act('profile','node',id='node-a',uid='node-uid-new',generation=2,features=['seccomp'],capacity=2),'node_recorded')
  self.assertEqual(self.act('admit','start',id='late',binding='binding-a',node_uid='node-uid-a',profile_digest=one(self.db,'SELECT digest FROM profiles WHERE id=?',('profile-a',))['digest'],at=10),'stale_start_receipt')
 def test_exception_expiry_blocks_late_start(self):
  self.fixture('profile_normal');self.fixture('admit_normal')
  digest=one(self.db,'SELECT digest FROM profiles WHERE id=?',('profile-a',))['digest']
  self.assertEqual(self.act('admit','start',id='late',binding='binding-a',node_uid='node-uid-a',profile_digest=digest,at=90),'stale_start_receipt')
 def test_noise_does_not_freeze_tenant(self):
  self.base()
  self.assertEqual(self.act('incident','observe',id='noise',binding='binding-a',kind='syscall',source='agent-a',at=10,confidence=30),'noise')
  self.assertEqual(self.act('incident','quarantine',id='case',binding='binding-a',scope='tenant',reason='one sample'),'insufficient_evidence')
  self.assertEqual(one(self.db,'SELECT freeze FROM tenant_limits WHERE tenant=?',('tenant-a',))['freeze'],0)
 def test_tenant_quarantine_requires_two_sources(self):
  self.base();self.act('incident','observe',id='v1',binding='binding-a',kind='syscall',source='agent-a',at=10,confidence=95)
  self.assertEqual(self.act('incident','quarantine',id='case',binding='binding-a',scope='tenant',reason='one source'),'tenant_scope_denied')
  self.act('incident','observe',id='v2',binding='binding-a',kind='syscall',source='agent-b',at=11,confidence=90)
  self.assertEqual(self.act('incident','quarantine',id='case2',binding='binding-a',scope='tenant',reason='two sources'),'tenant_frozen')
  self.assertEqual(self.act('admit','request',id='new',tenant='tenant-a',profile='profile-a',risk=1),'request_denied')
 def test_release_requires_new_profile_and_reset(self):
  self.base();self.act('incident','observe',id='v1',binding='binding-a',kind='syscall',source='agent-a',at=10,confidence=95)
  self.act('incident','quarantine',id='case',binding='binding-a',scope='binding',reason='violation')
  self.assertEqual(self.act('incident','release',incident='case',new_profile='profile-a',at=12),'release_unverified')
  self.act('profile','publish',id='profile-a',revision=2,syscalls=['read'],devices=['null'],network=[],required_feature='seccomp');self.act('profile','activate',id='profile-a')
  new=one(self.db,'SELECT digest FROM profiles WHERE id=?',('profile-a',))['digest']
  self.act('incident','reset',id='reset',binding='binding-a',node_uid='node-uid-a',new_digest=new,at=13)
  self.assertEqual(self.act('incident','release',incident='case',new_profile='profile-a',at=14),'released')
 def test_request_identity_conflict(self):
  x={'request_id':'same','op':'limit','tenant':'t','max_risk':2}
  self.assertEqual(execute(self.db,'admit',x)['decision'],'limit_recorded')
  self.assertEqual(execute(self.db,'admit',dict(x,max_risk=3))['decision'],'request_conflict')
 def test_profile_revocation_blocks_new_binding(self):
  self.fixture('profile_normal');self.act('admit','limit',tenant='t',max_risk=3)
  self.act('admit','request',id='w',tenant='t',profile='profile-a',risk=1)
  self.assertEqual(self.act('profile','revoke',id='profile-a',revision=1),'revoked')
  self.assertEqual(self.act('admit','assign',id='binding',workload='w',node='node-a',at=5),'assignment_denied')
 def test_violation_identity_is_not_counted_twice(self):
  self.base()
  self.assertEqual(self.act('incident','observe',id='signal',binding='binding-a',kind='syscall',source='agent-a',at=10,confidence=95),'credible')
  self.assertEqual(self.act('incident','observe',id='signal',binding='binding-a',kind='syscall',source='agent-b',at=11,confidence=95),'duplicate_signal')
  self.assertEqual(self.act('incident','quarantine',id='case',binding='binding-a',scope='tenant',reason='replayed source'),'tenant_scope_denied')

if __name__=='__main__':unittest.main()
