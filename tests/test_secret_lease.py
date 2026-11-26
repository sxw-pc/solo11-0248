import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.secret_lease import provisional_lease

class SecretLeaseTest(unittest.TestCase):
 def test_start_changes_secret_lease_eligibility(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    self.assertEqual(provisional_lease(db,'l','start-a','key')['decision'],'unavailable')
    for name in ('profile_normal','admit_normal'):
     for x in json.loads((root/'fixtures'/f'{name}.json').read_text(encoding='utf8')):execute(db,x.get('subsystem',name.split('_')[0]),x)
    self.assertEqual(provisional_lease(db,'l','start-a','key')['decision'],'issued')
   finally:db.close()
