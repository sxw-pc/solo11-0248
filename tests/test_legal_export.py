import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute
from sandcontract.legal_export import provisional_manifest

class LegalExportTest(unittest.TestCase):
 def test_incident_changes_provisional_manifest(self):
  root=Path(__file__).resolve().parents[1]
  with tempfile.TemporaryDirectory() as folder:
   db=connect(str(Path(folder)/'state.sqlite'))
   try:
    for name in ('profile_normal','admit_normal'):
     for x in json.loads((root/'fixtures'/f'{name}.json').read_text(encoding='utf8')):execute(db,x.get('subsystem',name.split('_')[0]),x)
    self.assertEqual(provisional_manifest(db,'m','case')['decision'],'unavailable')
    execute(db,'incident',dict(request_id='violation',op='observe',id='v',binding='binding-a',kind='syscall',source='s',at=10,confidence=90))
    execute(db,'incident',dict(request_id='quarantine',op='quarantine',id='case',binding='binding-a',scope='binding',reason='proof'))
    self.assertEqual(provisional_manifest(db,'m','case')['members'],['binding-a'])
   finally:db.close()
