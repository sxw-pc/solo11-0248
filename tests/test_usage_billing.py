import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.usage import capture_page,provisional_charge

class UsageBillingTest(unittest.TestCase):
 def test_binding_changes_tenant_charge(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    for name in ('profile_normal','admit_normal'):
     for x in json.loads((root/'fixtures'/f'{name}.json').read_text(encoding='utf8')):execute(db,x.get('subsystem',name.split('_')[0]),x)
    self.assertEqual(capture_page(db,'p',[{'binding':'binding-a','cpu_seconds':7}])['decision'],'captured')
    self.assertEqual(provisional_charge(db,'c','tenant-a',2)['amount'],14)
   finally:db.close()
