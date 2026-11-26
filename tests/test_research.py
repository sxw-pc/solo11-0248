import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.research import submit
from sandcontract.bounty import provisional_offer

class ResearchTest(unittest.TestCase):
 def test_report_changes_provisional_offer(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    for x in json.loads((root/'fixtures/profile_normal.json').read_text(encoding='utf8')):execute(db,x.get('subsystem','profile'),x)
    self.assertEqual(provisional_offer(db,'o','r',40)['decision'],'unavailable')
    submit(db,'r','researcher','profile-a','digest')
    self.assertEqual(provisional_offer(db,'o','r',40)['decision'],'offered')
   finally:db.close()
