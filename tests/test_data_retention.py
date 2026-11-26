import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.data_retention import provisional_record

class RetentionTest(unittest.TestCase):
 def test_start_changes_retention_record(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    self.assertEqual(provisional_record(db,'r','start-a','archive-a')['decision'],'unavailable')
    for name in ('profile_normal','admit_normal'):
     for x in json.loads((root/'fixtures'/f'{name}.json').read_text(encoding='utf8')):execute(db,x.get('subsystem',name.split('_')[0]),x)
    self.assertEqual(provisional_record(db,'r','start-a','archive-a')['decision'],'recorded')
   finally:db.close()
