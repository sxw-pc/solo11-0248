import argparse,json
from pathlib import Path
from .store import connect,execute,replay,rows
def main():
 p=argparse.ArgumentParser();p.add_argument('command',choices=['profile','admit','incident','retention','erasure','demo','report','replay']);p.add_argument('--db',required=True);p.add_argument('--fixture');a=p.parse_args()
 if a.command=='replay':result=replay(a.db)
 else:
  db=connect(a.db)
  if a.command=='report':result=rows(db,'SELECT * FROM events ORDER BY seq')
  else:
   files=[Path('fixtures')/f'{sub}_{kind}.json' for kind in ('normal','failure') for sub in ('profile','admit','incident')] if a.command=='demo' else [Path(a.fixture)]
   result=[]
   for f in files:
    for step in json.loads(f.read_text(encoding='utf-8')):result.append(execute(db,step.get('subsystem',a.command if a.command!='demo' else f.stem.split('_')[0]),step))
  db.close()
 print(json.dumps(result,ensure_ascii=False,indent=2))
 if a.command=='replay' and not result['verified']:raise SystemExit(2)
if __name__=='__main__':main()
