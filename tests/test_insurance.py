import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.insurance import provisional_notice

class InsuranceTest(unittest.TestCase):
 def test_quarantine_changes_insurer_notice(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    self.assertEqual(provisional_notice(db,'n','case','policy')['decision'],'unavailable')
    for name in ('profile_normal','admit_normal'):
     for x in json.loads((root/'fixtures'/f'{name}.json').read_text(encoding='utf8')):execute(db,x.get('subsystem',name.split('_')[0]),x)
    execute(db,'incident',dict(request_id='violation',op='observe',id='v',binding='binding-a',kind='syscall',source='s',at=10,confidence=90))
    execute(db,'incident',dict(request_id='quarantine',op='quarantine',id='case',binding='binding-a',scope='binding',reason='proof'))
    self.assertEqual(provisional_notice(db,'n','case','policy')['decision'],'drafted')
   finally:db.close()
