"""Kernel-capability-bound sandbox contract compiler and loader.

A profile's syscall/device/network summary cannot prove the same execution
effect on different kernels: an alias entry point (clone vs clone3), an
argument-width limit that an older filter cannot express, or a backported
filter capability all change what "required_feature=seccomp" actually means.

This module turns a profile's explicit call semantics into deterministic
filter bytes for one attested node kernel, and only authorizes a binding once
a real load receipt proves those exact bytes were loaded. Rejected
compilations and failed loads are retained as evidence instead of being
silently retried into a wider allowance.
"""
import hashlib,json
from .store import one,rows

ACTIONS=('allow','deny')
WIDTHS=(32,64)

def canonical_policy(pol):
 """Validate and canonicalize an explicit policy. Ordering and alias spelling
 of rules must not change the compiled allowance, so the result is sorted."""
 if not isinstance(pol,dict):return None
 rules=pol.get('syscall_rules')
 if not isinstance(rules,list) or not rules:return None
 canon=[]
 seen=set()
 for r in rules:
  if not isinstance(r,dict):return None
  call=r.get('call');action=r.get('action')
  if not isinstance(call,str) or not call or action not in ACTIONS:return None
  mask=r.get('mask');width=r.get('width',64)
  if not isinstance(width,int) or width not in WIDTHS:return None
  if mask is not None and (not isinstance(mask,int) or mask<0 or mask>=1<<width):return None
  key=(call,action,mask,width)
  if key in seen:return None
  seen.add(key)
  canon.append({'call':call,'action':action,'mask':mask,'width':width})
 canon.sort(key=lambda r:(r['call'],r['action'],r['mask'] if r['mask'] is not None else -1,r['width']))
 devices=pol.get('devices',[])
 network=pol.get('network',[])
 if not isinstance(devices,list) or not isinstance(network,list):return None
 for item in devices+network:
  if not isinstance(item,dict) or not item.get('name') or item.get('action') not in ACTIONS:return None
 devices=sorted(devices,key=lambda d:(d['name'],d['action']))
 network=sorted(network,key=lambda d:(d['name'],d['action']))
 if pol.get('default','deny')!='deny':return None
 return {'default':'deny','syscall_rules':canon,'devices':devices,'network':network}

def policy_digest(pol):
 return hashlib.sha256(json.dumps(pol,sort_keys=True).encode()).hexdigest()

def validate_attestation(att):
 """A node proves a kernel build, its real syscall table, its filter engine
 version and its expression capabilities. kernel_version is descriptive only;
 vendor backports mean a version string can never be a whitelist."""
 if not isinstance(att,dict):return None
 build=att.get('kernel_build');fver=att.get('filter_version');table=att.get('syscall_table');caps=att.get('filter_caps')
 if not isinstance(build,str) or not build or not isinstance(fver,str) or not fver:return None
 if not isinstance(table,dict) or not table:return None
 for call,entries in table.items():
  if not isinstance(call,str) or not isinstance(entries,list) or not entries:return None
  for e in entries:
   if not isinstance(e,dict) or not isinstance(e.get('entry'),int) or e['entry']<0 or not e.get('abi'):return None
 if not isinstance(caps,list) or not caps or any(not isinstance(c,str) for c in caps):return None
 return {'kernel_build':build,'kernel_version':att.get('kernel_version'),'filter_version':fver,'syscall_table':table,'filter_caps':caps}

def attestation_digest(att):
 return hashlib.sha256(json.dumps(att,sort_keys=True).encode()).hexdigest()

def _mask_ok(rule,att):
 """A masked allow is only expressible when the kernel filter can fetch an
 argument of the required width. A 64-bit mask on a 32-bit-only filter is a
 reject, never a wider allow."""
 if rule['action']!='allow' or rule['mask'] is None:return True
 return f'arg{rule["width"]}' in att['filter_caps']

def _build_filter(pol,att):
 """Compile canonical rules against one syscall table. Returns (lines,
 unexpressed) where unexpressed is a list of (call,reason)."""
 lines=[];unexpressed=[]
 bycall={r['call']:r for r in pol['syscall_rules']}
 for call,rule in sorted(bycall.items()):
  entries=att['syscall_table'].get(call,[])
  if not entries:
   unexpressed.append((call,'entry_absent'));continue
  if not _mask_ok(rule,att):
   unexpressed.append((call,'arg_width_unsupported'));continue
  for e in sorted(entries,key=lambda e:e['entry']):
   if rule['action']=='deny':lines.append({'entry':e['entry'],'verdict':'deny','mask':None,'width':rule['width']})
   elif rule['mask'] is None:lines.append({'entry':e['entry'],'verdict':'allow','mask':None,'width':rule['width']})
   else:lines.append({'entry':e['entry'],'verdict':'allow_masked','mask':rule['mask'],'width':rule['width']})
 for d in pol['devices']:lines.append({'device':d['name'],'verdict':d['action']})
 for d in pol['network']:lines.append({'network':d['name'],'verdict':d['action']})
 lines.append({'default':'deny'})
 return lines,unexpressed

def filter_hash(pol,att,lines):
 """Filter bytes bind profile version/policy, kernel build+syscall table,
 filter engine and the compiled lines. Alias-equivalent entries compile to
 identical bytes; a different kernel build or table cannot reuse the hash."""
 material={'profile_policy':pol,'kernel_build':att['kernel_build'],'filter_version':att['filter_version'],'syscall_table':att['syscall_table'],'filter_caps':att['filter_caps'],'lines':lines}
 return hashlib.sha256(json.dumps(material,sort_keys=True).encode()).hexdigest()

def _load_node(db,x):
 n=one(db,'SELECT * FROM nodes WHERE id=?',(x['node'],))
 if not n:return None,None
 att=one(db,'SELECT * FROM node_attestations WHERE node_uid=? AND node_generation=?',(n['uid'],n['generation']))
 return n,att

def loaded_contract(db,node_uid,node_generation,profile_digest):
 """The single authorization fact reused by assign/start/release: a compiled
 contract for exactly this profile digest and node generation, whose real
 load receipt was accepted."""
 return one(db,"""SELECT c.* FROM compilations c JOIN load_receipts l ON l.compilation_id=c.id
  WHERE c.profile_digest=? AND c.node_uid=? AND c.node_generation=? AND c.status='compiled' AND l.status='loaded'""",
  (profile_digest,node_uid,node_generation))

def run(db,x):
 op=x['op']
 if op=='compile':
  p=one(db,'SELECT * FROM profiles WHERE id=?',(x['profile'],))
  if not p:return {'decision':'unknown_profile'}
  if p['status']!='active':return {'decision':'profile_not_active'}
  pol=json.loads(p['policy']) if p['policy'] else None
  if not pol:return {'decision':'legacy_profile_not_compilable'}
  n,att=_load_node(db,x)
  if not n:return {'decision':'unknown_node'}
  if not att:return {'decision':'node_attestation_missing'}
  cid=policy_digest({'profile_digest':p['digest'],'node_uid':n['uid'],'node_generation':n['generation']})
  prior=one(db,'SELECT * FROM compilations WHERE id=?',(cid,))
  if prior:
   return {'decision':'compiled' if prior['status']=='compiled' else prior['reject_reason'],'compilation_id':cid,'filter_hash':prior['filter_hash']}
  lines,unexpressed=_build_filter(pol,json.loads(att['attestation']))
  if unexpressed:
   reason=unexpressed[0][1]
   db.execute('INSERT INTO compilations VALUES(?,?,?,?,?,?,?,?,?,?)',(cid,p['id'],p['digest'],n['uid'],n['generation'],att['attestation_digest'],None,json.dumps(lines,sort_keys=True),'rejected',reason))
   return {'decision':reason,'compilation_id':cid,'unexpressed':unexpressed}
  fh=filter_hash(pol,json.loads(att['attestation']),lines)
  db.execute('INSERT INTO compilations VALUES(?,?,?,?,?,?,?,?,?,?)',(cid,p['id'],p['digest'],n['uid'],n['generation'],att['attestation_digest'],fh,json.dumps(lines,sort_keys=True),'compiled',None))
  return {'decision':'compiled','compilation_id':cid,'filter_hash':fh}
 if op=='load':
  c=one(db,'SELECT * FROM compilations WHERE id=?',(x['compilation'],))
  if not c:return {'decision':'unknown_compilation'}
  n=one(db,'SELECT * FROM nodes WHERE uid=? AND generation=?',(c['node_uid'],c['node_generation']))
  att=one(db,'SELECT * FROM node_attestations WHERE node_uid=? AND node_generation=?',(c['node_uid'],c['node_generation'])) if n else None
  if not n or not att:
   return {'decision':'stale_load_receipt'}
  if x.get('node_uid')!=n['uid'] or x.get('node_generation')!=n['generation']:
   return {'decision':'stale_load_receipt'}
  prior=one(db,'SELECT * FROM load_receipts WHERE compilation_id=? AND status=?',(c['id'],'loaded'))
  if prior:return {'decision':'loaded','receipt_id':prior['id']}
  if one(db,'SELECT id FROM load_receipts WHERE id=?',(x['id'],)):return {'decision':'load_receipt_conflict'}
  if x.get('filter_hash')!=c['filter_hash'] or c['status']!='compiled':
   # failed receipts are evidence too: retained for audit, never silently retried away
   db.execute('INSERT INTO load_receipts VALUES(?,?,?,?,?,?)',(x['id'],c['id'],n['uid'],n['generation'],x.get('filter_hash'),'failed'))
   return {'decision':'load_failed'}
  db.execute('INSERT INTO load_receipts VALUES(?,?,?,?,?,?)',(x['id'],c['id'],n['uid'],n['generation'],c['filter_hash'],'loaded'))
  return {'decision':'loaded','receipt_id':x['id'],'filter_hash':c['filter_hash']}
 raise ValueError(op)
