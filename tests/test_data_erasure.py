import json,tempfile,unittest
from pathlib import Path
from sandcontract.store import connect,execute,replay,one,rows
from sandcontract import data_retention,data_erasure as de

ROOT=Path(__file__).resolve().parents[1]

class ErasureBase(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.folder=Path(self.tmp.name)
  self.db=connect(str(self.folder/'state.sqlite'));self.vault=str(self.folder/'vault');self.n=0
  self._start_workload();self._build_media_landscape()
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def _rid(self,prefix):
  self.n+=1;return f'{prefix}-{self.n}'
 def act(self,op,**fields):
  return execute(self.db,'erasure',dict(request_id=self._rid('req'),op=op,**fields))
 def _start_workload(self):
  for name in ('profile_normal','admit_normal'):
   for x in json.loads((ROOT/'fixtures'/f'{name}.json').read_text(encoding='utf8')):
    execute(self.db,x.get('subsystem',name.split('_')[0]),x)
  self.assertEqual(execute(self.db,'retention',{'request_id':'rr','op':'provisional','id':'rr','start_id':'start-a','archive_id':'archive-A'})['decision'],'recorded')
  # Two independent evidence sources establish a real incident for the legal hold.
  execute(self.db,'incident',{'request_id':'e-v1','op':'observe','id':'ev-1','binding':'binding-a','kind':'syscall','source':'agent-a','at':10,'confidence':95})
  execute(self.db,'incident',{'request_id':'e-v2','op':'observe','id':'ev-2','binding':'binding-a','kind':'syscall','source':'agent-b','at':11,'confidence':90})
  execute(self.db,'incident',{'request_id':'e-case','op':'quarantine','id':'incident-a','binding':'binding-a','scope':'binding','reason':'court case','at':12})
 def _build_media_landscape(self,pre_seal=True):
  # Two physical media, each with a controller remap area.
  self.assertEqual(self.act('register_media',id='media-1',kind='nvme')['decision'],'media_registered')
  self.assertEqual(self.act('register_media',id='media-2',kind='ssd')['decision'],'media_registered')
  def block(bid,media,extent,remap,state='dedicated'):
   self.assertEqual(self.act('register_block',id=bid,media=media,extent=extent,remap_extent=remap,bytes_hash=f'hash-{bid}',state=state)['decision'],'block_registered')
  # Tenant A pages 12..18 across blocks; page 15 lives on a shared compression block.
  block('blk-a12','media-1','e12','remap-a12');block('blk-a13','media-1','e13','remap-a13')
  block('blk-a14','media-1','e14','remap-a14');block('blk-shared','media-1','e15','remap-shared',state='shared')
  block('blk-a16','media-2','e16','remap-a16');block('blk-a17','media-2','e17','remap-a17')
  block('blk-a18','media-2','e18','remap-a18')
  block('blk-b21','media-2','e21','remap-b21')
  # Wrapping keys: K甲 has a datacenter copy, a cache copy and an offline DR copy.
  self.assertEqual(self.act('register_key',id='K-A',tenant='tenant-a')['decision'],'key_registered')
  for cid,loc in (('K-A-dc','datacenter'),('K-A-cache','cache'),('K-A-dr','offsite-dr')):
   self.assertEqual(self.act('register_key_copy',id=cid,key_id='K-A',location=loc,kind=loc)['decision'],'key_copy_registered')
  self.assertEqual(self.act('register_key',id='K-B',tenant='tenant-b')['decision'],'key_registered')
  for cid,loc in (('K-B-dc','datacenter'),('K-B-dr','offsite-dr')):
   self.assertEqual(self.act('register_key_copy',id=cid,key_id='K-B',location=loc,kind=loc)['decision'],'key_copy_registered')
  # Independent sealing key for the legal hold on page 18.
  self.assertEqual(self.act('register_key',id='K-seal-18',tenant='tenant-a')['decision'],'key_registered')
  self.assertEqual(self.act('register_key_copy',id='K-seal-18-dc',key_id='K-seal-18',location='datacenter')['decision'],'key_copy_registered')
  self.assertEqual(self.act('register_archive',id='archive-A',tenant='tenant-a')['decision'],'archive_registered')
  self.assertEqual(self.act('register_archive',id='archive-B',tenant='tenant-b')['decision'],'archive_registered')
  for page,bid in ((12,'blk-a12'),(13,'blk-a13'),(14,'blk-a14'),(15,'blk-shared'),(16,'blk-a16'),(17,'blk-a17'),(18,'blk-a18')):
   self.assertEqual(self.act('register_page',archive='archive-A',page_no=page,tenant='tenant-a',block_id=bid,key_id='K-A')['decision'],'page_registered')
  # Tenant B references the same underlying compression block for its own page.
  self.assertEqual(self.act('register_page',archive='archive-B',page_no=15,tenant='tenant-b',block_id='blk-shared',key_id='K-B')['decision'],'page_registered')
  self.assertEqual(self.act('register_page',archive='archive-B',page_no=21,tenant='tenant-b',block_id='blk-b21',key_id='K-B')['decision'],'page_registered')
  # Snapshot and object copies of A must also disappear.
  self.assertEqual(self.act('register_snapshot',id='snap-A',archive='archive-A',tenant='tenant-a',block_id='blk-a12',key_id='K-A')['decision'],'snapshot_registered')
  self.assertEqual(self.act('register_copy',id='copy-A-remote',archive='archive-A',tenant='tenant-a',location='object-store-2',block_id='blk-a16',key_id='K-A')['decision'],'copy_registered')
  self.assertEqual(self.act('register_write',id='write-15',start_id='start-a',tenant='tenant-a',archive='archive-A',page_no=15,block_id='blk-shared',key_id='K-A')['decision'],'write_registered')
  # Court hold: tenant A page 18 only, until_ts=500, tied to a sealed incident.
  self.assertEqual(self.act('register_hold',id='hold-18',tenant='tenant-a',archive='archive-A',page_from=18,page_to=18,until_ts=500,seal_key_id='K-seal-18',incident='incident-a')['decision'],'hold_registered')
  if pre_seal:
   self.assertEqual(self.act('seal_evidence',id='incident-ev-18',id_hold='hold-18',archive='archive-A',page_no=18,vault_root=self.vault)['decision'],'evidence_sealed')
 def _receipt(self,job,kind,target,fault=None):
  extra=de._expected_extra(self.db,kind,target)
  payload=de.receipt_payload(job,kind,target,extra)
  if fault=='tamper':payload=payload.replace('"token":','"token":"x","x":',1)
  rid=self._rid('rcpt')
  return self.act('register_receipt',id=rid,job=job,kind=kind,target=target,payload=payload)
 def _erase_receipts(self,job,block_ids):
  for bid in block_ids:self.assertEqual(self._receipt(job,'erase',bid)['decision'],'receipt_registered')
 def _key_receipts(self,job,copy_ids):
  for cid in copy_ids:self.assertEqual(self._receipt(job,'destroy',cid)['decision'],'receipt_registered')
 def _run_full(self,strategy,block_ids,key_copies,seal_copies=()):
  r=self.act('erase',id=f'job-{strategy}',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy=strategy,vault_root=self.vault)
  self.assertEqual(r['decision'],'erasure_started');job=r['job']
  # Every controller / offline-custodian receipt is lodged before the stages need it.
  self._erase_receipts(job,block_ids)
  self._key_receipts(job,key_copies)
  decisions=[]
  for _ in range(8):
   r=self.act('proceed',job=job)
   decisions.append(r['decision'])
   if r['decision'] in ('certified','partial_certified'):break
  self.assertIn(r['decision'],('certified','partial_certified'),decisions)
  for cid in seal_copies:self._key_receipts(job,[cid])
  return job,r

class PhysicalErasureTest(ErasureBase):
 def test_shared_block_rewritten_and_b_stays_byte_readable(self):
  before=de.read_page(self.db,'archive-B',15)
  job,r=self._run_full('physical',
   ['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],
   ['K-A-dc','K-A-cache','K-A-dr'])
  self.assertEqual(r['decision'],'partial_certified')
  # B's page 15 moved to a B-dedicated block and keeps its byte identity.
  after=de.read_page(self.db,'archive-B',15)
  self.assertTrue(after['readable']);self.assertEqual(before['fingerprint'],after['fingerprint'])
  self.assertTrue(after['block'].endswith('--dedicated--tenant-b'))
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-shared'")['state'],'erased')
  self.assertEqual(de.read_page(self.db,'archive-B',21)['readable'],True)
  # A's readable path is physically gone for every non-held page.
  for page in (12,13,14,15,16,17):
   probe=de.read_page(self.db,'archive-A',page)
   self.assertFalse(probe['readable'],page);self.assertEqual(probe['reason'],'physical_erased')
  # Held page 18 remains available only via the sealed evidence and seal key.
  p18=de.read_page(self.db,'archive-A',18)
  self.assertTrue(p18['readable']);self.assertEqual(p18['via'],'sealed_evidence');self.assertEqual(p18['seal_key'],'K-seal-18')
  self.assertNotEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a18'")['state'],'erased')
  # Every K甲 copy, including the offline DR copy, is destroyed with evidence.
  for cid in ('K-A-dc','K-A-cache','K-A-dr'):
   self.assertEqual(one(self.db,'SELECT state FROM key_copies WHERE id=?',(cid,))['state'],'destroyed')
  self.assertEqual(one(self.db,"SELECT state FROM wrapping_keys WHERE id='K-A'")['state'],'destroyed')
  # K-B and its copies are untouched.
  self.assertEqual(one(self.db,"SELECT state FROM wrapping_keys WHERE id='K-B'")['state'],'active')
 def test_remap_area_without_controller_receipt_blocks_certification(self):
  r=self.act('erase',id='job-remap',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  job=r['job'];self.act('proceed',job=job);self.act('proceed',job=job)
  # A block whose controller never reports the remap area cannot be certified.
  self.db.execute("UPDATE blocks SET remap_extent=NULL WHERE id='blk-a13'")
  self.assertEqual(self.act('proceed',job=job)['decision'],'remap_unverified')
  self.assertIsNone(one(self.db,"SELECT * FROM certificates WHERE job=?",(job,)))
 def test_tampered_external_receipt_is_rejected(self):
  r=self.act('erase',id='job-tamper',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  job=r['job'];self.act('proceed',job=job);self.act('proceed',job=job)
  self.assertEqual(self._receipt(job,'erase','blk-a12',fault='tamper')['decision'],'receipt_rejected')
  self.assertEqual(self.act('proceed',job=job)['decision'],'erase_receipt_missing')
 def test_offline_dr_key_receipt_required(self):
  r=self.act('erase',id='job-dr',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  job=r['job'];self.act('proceed',job=job);self.act('proceed',job=job)
  self._erase_receipts(job,['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'])
  self.act('proceed',job=job)
  # Only the datacenter and cache copies are attested; the offline DR copy still holds the key.
  self._key_receipts(job,['K-A-dc','K-A-cache'])
  miss=self.act('proceed',job=job)
  self.assertEqual(miss['decision'],'key_destruction_unverified')
  self.assertEqual(miss['copies'][0]['location'],'offsite-dr')
  self.assertIsNone(one(self.db,"SELECT * FROM certificates WHERE job=?",(job,)))
 def test_hold_expiry_releases_page_18_and_revokes_partial_certificate(self):
  job,_=self._run_full('physical',['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],['K-A-dc','K-A-cache','K-A-dr'])
  partial=one(self.db,"SELECT * FROM certificates WHERE job=? AND kind='partial'",(job,))
  self.assertEqual(partial['state'],'issued')
  # Before the agreed deadline the hold cannot be released.
  self.assertEqual(self.act('release_hold',hold='hold-18',at=499)['decision'],'hold_not_expired')
  # Sealed incident evidence survives the deletion request.
  self.assertEqual(self.act('release_hold',hold='hold-18',at=501)['decision'],'erase_receipt_missing')
  self._erase_receipts(job,['blk-a18'])
  self.assertEqual(self.act('release_hold',hold='hold-18',at=501)['decision'],'key_destruction_unverified')
  self._key_receipts(job,['K-seal-18-dc'])
  rel=self.act('release_hold',hold='hold-18',at=501)
  self.assertEqual(rel['decision'],'hold_released');self.assertTrue(rel['revoked'])
  self.assertEqual(one(self.db,"SELECT state FROM certificates WHERE id=?",(partial['id'],))['state'],'revoked')
  full=one(self.db,"SELECT * FROM certificates WHERE id=?",(rel['certificate'],))
  self.assertEqual(full['kind'],'full');self.assertEqual(full['state'],'issued');self.assertEqual(full['revokes_cert'],partial['id'])
  self.assertFalse(de.read_page(self.db,'archive-A',18)['readable'])
  ev=one(self.db,"SELECT * FROM sealed_evidence WHERE hold='hold-18'")
  self.assertEqual(ev['state'],'retained_evidence')
  self.assertEqual(one(self.db,"SELECT state FROM archives WHERE id='archive-A'")['state'],'erased')
 def test_duplicate_erasure_is_idempotent_and_resumes_interrupted_job(self):
  job,_=self._run_full('physical',['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],['K-A-dc','K-A-cache','K-A-dr'])
  again=self.act('erase',id='job-dup',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  self.assertEqual(again['decision'],'already_erased')
  # Revoking the certificate does not silently start a second destructive job.
  self.assertEqual(self.act('revoke_certificate',certificate=one(self.db,"SELECT id FROM certificates WHERE job=? AND kind='partial'",(job,))['id'],reason='audit')['decision'],'certificate_revoked')
  retry=self.act('erase',id='job-retry',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  self.assertEqual(retry['decision'],'resume_required');self.assertEqual(retry['job'],job)

class CryptoErasureTest(ErasureBase):
 def test_crypto_shred_without_offline_dr_attestation_cannot_certify(self):
  r=self.act('erase',id='job-crypto-dr',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='crypto',vault_root=self.vault)
  job=r['job']
  self.act('proceed',job=job);self.act('proceed',job=job)
  self._key_receipts(job,['K-A-dc','K-A-cache'])
  miss=self.act('proceed',job=job)
  self.assertEqual(miss['decision'],'key_destruction_unverified')
  self.assertIn({'copy':'K-A-dr','location':'offsite-dr'},miss['copies'])
  self.assertIsNone(one(self.db,"SELECT * FROM certificates WHERE job=?",(job,)))
  self._key_receipts(job,['K-A-dr'])
  self.assertEqual(self.act('proceed',job=job)['decision'],'keys_destroyed')
  self.assertEqual(self.act('proceed',job=job)['decision'],'partial_certified')
 def test_crypto_shred_isolates_a_and_destroys_every_k_a_copy(self):
  before=de.read_page(self.db,'archive-B',15)
  job,r=self._run_full('crypto',[],[ 'K-A-dc','K-A-cache','K-A-dr'])
  self.assertEqual(r['decision'],'partial_certified')
  after=de.read_page(self.db,'archive-B',15)
  self.assertTrue(after['readable']);self.assertEqual(before['fingerprint'],after['fingerprint'])
  # B's key cannot unwrap any surviving A ciphertext.
  for p in rows(self.db,"SELECT * FROM archive_pages WHERE archive='archive-A' AND tenant='tenant-a'"):
   self.assertNotEqual(p['key_id'],'K-B')
  for page in (12,13,14,15,16,17):
   probe=de.read_page(self.db,'archive-A',page)
   self.assertFalse(probe['readable']);self.assertEqual(probe['reason'],'key_destroyed')
  # Physical ciphertext still occupies media until normal reclamation.
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a12'")['state'],'retained_cipher')
  p18=de.read_page(self.db,'archive-A',18)
  self.assertTrue(p18['readable']);self.assertEqual(p18['via'],'sealed_evidence')
  # Reclamation needs the same per-media controller receipts, then frees capacity.
  self.assertEqual(self.act('reclaim',job=job)['decision'],'erase_receipt_missing')
  self._erase_receipts(job,['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'])
  rec=self.act('reclaim',job=job)
  self.assertEqual(rec['decision'],'reclaimed');self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a12'")['state'],'erased')
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a18'")['state'],'retained')
  self.assertEqual(de.read_page(self.db,'archive-B',21)['readable'],True)
 def test_seal_failure_leaves_no_partial_sealed_state_and_resumes(self):
  # Drop the custodian pre-seal so the job must perform the sealing itself.
  self.db.execute("DELETE FROM sealed_evidence WHERE id='incident-ev-18'")
  r=self.act('erase',id='job-sealfail',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='crypto',vault_root=self.vault)
  job=r['job'];self.assertEqual(self.act('proceed',job=job)['decision'],'isolated')
  self.assertEqual(self.act('proceed',job=job,fault='seal')['decision'],'seal_failed')
  # Nothing was sealed or erased; the stage remains pending and resumable.
  self.assertEqual(rows(self.db,"SELECT id FROM sealed_evidence WHERE hold='hold-18' AND id LIKE 'seal-%'"),[])
  self.assertEqual(one(self.db,"SELECT state FROM erasure_stages WHERE job=? AND stage='seal'",(job,))['state'],'pending')
  self.assertEqual(self.act('proceed',job=job)['decision'],'sealed')
 def test_crypto_hold_expiry_erases_retained_cipher_with_remap_receipts(self):
  job,_=self._run_full('crypto',[],['K-A-dc','K-A-cache','K-A-dr'])
  # Held ciphertext remains retained and readable through the seal key.
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a18'")['state'],'retained')
  self.assertTrue(de.read_page(self.db,'archive-A',18)['readable'])
  self.assertEqual(self.act('release_hold',hold='hold-18',at=501)['decision'],'erase_receipt_missing')
  self._erase_receipts(job,['blk-a18'])
  self.assertEqual(self.act('release_hold',hold='hold-18',at=501)['decision'],'key_destruction_unverified')
  self._key_receipts(job,['K-seal-18-dc'])
  rel=self.act('release_hold',hold='hold-18',at=501)
  self.assertEqual(rel['decision'],'hold_released')
  self.assertFalse(de.read_page(self.db,'archive-A',18)['readable'])
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a18'")['state'],'erased')
  # Incident evidence is preserved, only the customer's readable path disappears.
  self.assertEqual(one(self.db,"SELECT state FROM sealed_evidence WHERE hold='hold-18'")['state'],'retained_evidence')
  self.assertEqual(de.read_page(self.db,'archive-B',21)['readable'],True)

class GatingAndReplayTest(ErasureBase):
 def test_erasure_requires_start_backed_retention_record(self):
  missing=self.act('erase',id='job-no-rec',tenant='tenant-a',archive='archive-A',start_id='start-unknown',strategy='physical',vault_root=self.vault)
  self.assertEqual(missing['decision'],'retention_record_missing')
  self.assertIsNone(one(self.db,"SELECT * FROM erasure_jobs WHERE id='job-no-rec'"))
  # Other tenant cannot delete A's archive.
  self.assertEqual(self.act('erase',id='job-b',tenant='tenant-b',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)['decision'],'tenant_mismatch')
 def test_cross_database_filesystem_events_replay_to_evidenced_state(self):
  job,_=self._run_full('physical',['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],['K-A-dc','K-A-cache','K-A-dr'])
  result=replay(str(self.folder/'state.sqlite'))
  self.assertTrue(result['verified'],result['divergence'])
  # Vault evidence is content-addressed: replayed writes reproduce identical digests.
  cert=one(self.db,"SELECT vault_path FROM certificates WHERE job=? AND kind='partial'",(job,))
  self.assertTrue(Path(cert['vault_path']).exists())
 def test_crypto_events_replay_with_identical_key_and_block_states(self):
  self._run_full('crypto',[],['K-A-dc','K-A-cache','K-A-dr'])
  result=replay(str(self.folder/'state.sqlite'))
  self.assertTrue(result['verified'],result['divergence'])
  self.assertEqual(one(self.db,"SELECT state FROM wrapping_keys WHERE id='K-A'")['state'],'destroyed')
  self.assertEqual(one(self.db,"SELECT state FROM wrapping_keys WHERE id='K-B'")['state'],'active')
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a12'")['state'],'retained_cipher')
 def test_interrupted_physical_job_resumes_only_to_evidenced_stage(self):
  r=self.act('erase',id='job-crash',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  job=r['job']
  self.assertEqual(self.act('proceed',job=job)['decision'],'isolated')
  self.assertEqual(self.act('proceed',job=job)['decision'],'sealed')
  # A crash inside the erase stage: one receipt lands, the rest never do.
  self._erase_receipts(job,['blk-a12'])
  self.assertEqual(self.act('proceed',job=job)['decision'],'erase_receipt_missing')
  stages={s['stage']:s['state'] for s in rows(self.db,'SELECT stage,state FROM erasure_stages WHERE job=?',(job,))}
  self.assertEqual(stages['erase'],'pending');self.assertEqual(stages['isolate'],'complete')
  # The one attested block is not marked erased until the whole stage can complete.
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a12'")['state'],'dedicated')
  self._erase_receipts(job,['blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'])
  self.assertEqual(self.act('proceed',job=job)['decision'],'erased')
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-a12'")['state'],'erased')
  self._key_receipts(job,['K-A-dc','K-A-cache','K-A-dr'])
  self.assertEqual(self.act('proceed',job=job)['decision'],'keys_destroyed')
  self.assertEqual(self.act('proceed',job=job)['decision'],'partial_certified')
 def test_compression_block_across_tenants_is_not_erased_before_rewrite(self):
  # Direct erase attempt on the shared block is impossible through a job: isolate runs first.
  r=self.act('erase',id='job-order',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  job=r['job']
  self.assertEqual(one(self.db,"SELECT state FROM erasure_stages WHERE job=? AND stage='isolate'",(job,))['state'],'pending')
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-shared'")['state'],'shared')
  self.act('proceed',job=job)
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-shared'")['state'],'a_only')
  self.assertTrue(one(self.db,"SELECT id FROM blocks WHERE id='blk-shared--dedicated--tenant-b'"))
 def test_rewritten_b_block_is_in_manifest_but_never_erased_by_a(self):
  job,_=self._run_full('physical',['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],['K-A-dc','K-A-cache','K-A-dr'])
  migrated=one(self.db,"SELECT state FROM erasure_manifests WHERE job=? AND kind='block' AND ref_id='blk-shared--dedicated--tenant-b'",(job,))
  self.assertEqual(migrated['state'],'migrated')
  self.assertEqual(one(self.db,"SELECT state FROM blocks WHERE id='blk-shared--dedicated--tenant-b'")['state'],'dedicated')
  # No erase receipt was ever requested against B's dedicated block.
  self.assertIsNone(one(self.db,"SELECT id FROM external_receipts WHERE job=? AND target='blk-shared--dedicated--tenant-b'",(job,)))
 def test_legal_hold_outside_archive_pages_is_rejected_at_intake(self):
  self.assertEqual(self.act('register_hold',id='hold-wide',tenant='tenant-a',archive='archive-A',page_from=18,page_to=99,until_ts=500,seal_key_id='K-seal-18')['decision'],'hold_registered')
  r=self.act('erase',id='job-bad-hold',tenant='tenant-a',archive='archive-A',start_id='start-a',strategy='physical',vault_root=self.vault)
  self.assertEqual(r['decision'],'hold_outside_archive')
  self.assertIsNone(one(self.db,"SELECT * FROM erasure_jobs WHERE id='job-bad-hold'"))
 def test_certificate_carries_exact_tenant_byte_range_and_deadline(self):
  job,_=self._run_full('physical',['blk-a12','blk-a13','blk-a14','blk-shared','blk-a16','blk-a17'],['K-A-dc','K-A-cache','K-A-dr'])
  cert=one(self.db,"SELECT * FROM certificates WHERE job=? AND kind='partial'",(job,))
  scope=json.loads(cert['scope'])
  self.assertEqual(cert['tenant'],'tenant-a')
  self.assertEqual(scope['retained_holds'],[{'hold':'hold-18','pages':[18,18],'until_ts':500}])
  self.assertEqual(scope['erased_pages'],[12,13,14,15,16,17])
  self.assertEqual(scope['destroyed_keys'],['K-A'])

if __name__=='__main__':unittest.main()
