"""Admin visual settings protect secrets, target boundaries and real test semantics."""
import importlib.util,json,sys,unittest,io
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('ops_vision_fixture',Path(__file__).with_name('test_ops_api.py'));fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

class VisionSettings(unittest.TestCase):
 def setUp(self):
  self.f=fixture.OpsApi();self.f.setUp();self.addCleanup(self.f.tearDown);self.m=self.f.ops_mod;self.c=self.f.ops;self.h=self.f.bearer
 def local(self,**kw):return dict({'enabled':True,'mode':'local','base_url':'http://127.0.0.1:8082/v1','model':'internvl3-1b'},**kw)
 def post(self,url,body):return self.c.post('/api/vision'+url,headers=self.h,json=body)
 def test_two_auth_layers_and_local_settings(self):
  self.assertEqual(self.f.bare.get('/api/vision').status_code,401);self.assertEqual(self.c.get('/api/vision').status_code,401)
  r=self.post('',self.local());self.assertEqual(r.status_code,200,r.text);self.assertFalse(r.json()['config']['api_key_set']);self.assertEqual(self.c.get('/api/vision',headers=self.h).json()['config']['model'],'internvl3-1b')
  self.assertEqual(self.post('',self.local(enabled=False)).status_code,200);self.assertEqual(self.post('/check',{}).status_code,400)
 def test_local_target_fixed_and_external_public_https(self):
  for u in ['http://127.0.0.1:8081/v1','http://172.17.0.1:8000','https://127.0.0.1/v1']:
   self.assertEqual(self.post('',self.local(base_url=u)).status_code,400)
  for u in ['http://example.com/v1','https://a:b@example.com/v1','https://example.com/v1?api_key=secret']:
   self.assertEqual(self.post('',self.local(mode='external',base_url=u,api_key='secret')).status_code,400)
  with patch.object(self.m.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):self.assertEqual(self.post('',self.local(mode='external',base_url='https://example.com/v1',api_key='secret')).status_code,400)
 def test_secret_not_returned_audited_or_reused_across_target_changes(self):
  payload=self.local(mode='external',base_url='https://example.com/v1',model='test-vision',api_key='VISION-SECRET-fixture')
  with patch.object(self.m.socket,'getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))]):
   r=self.post('',payload);self.assertEqual(r.status_code,200,r.text);self.assertNotIn(payload['api_key'],r.text)
   self.assertEqual(self.post('',dict(payload,api_key='')).status_code,200)
   self.assertEqual(self.post('',dict(payload,model='another',api_key='')).status_code,400)
   self.assertNotIn(payload['api_key'],self.c.get('/api/vision',headers=self.h).text)
  c=self.m.db();rows=c.execute("SELECT * FROM admin_audit WHERE action='vision_config'").fetchall();self.assertNotIn(payload['api_key'],str([dict(x) for x in rows]));c.close()
 def test_connection_success_does_not_claim_image_success(self):
  self.assertEqual(self.post('',self.local()).status_code,200)
  class Opener:
   def open(self,*a,**k):return io.BytesIO(json.dumps({'data':[{'id':'internvl3-1b'}]}).encode())
  with patch.object(self.m.urllib.request,'build_opener',return_value=Opener()):r=self.post('/check',{})
  self.assertTrue(r.json()['ok']);self.assertEqual(r.json()['kind'],'connection');self.assertIn('尚未证明识图效果',r.json()['message'])
 def test_actual_image_requires_consent_and_input_bound(self):
  self.assertEqual(self.post('',self.local()).status_code,200)
  for p in [{},{'consent':False,'image':'abc'},{'consent':True,'image':'x'*1500001},{'consent':True,'image':'not base64'}]:self.assertEqual(self.post('/test',p).status_code,400)
 def test_check_state_defaults_to_the_dedicated_writable_config_directory(self):
  import os
  with patch.dict(os.environ):
   os.environ.pop('QINGSU_VISION_CHECK',None)
   m=fixture.load(fixture.BACKEND/'ops/admin_api.py','vision_directory_contract')
  self.assertEqual(Path(m.VISION_CHECK).parent,Path(m.VISION_CONFIG).parent)
  self.assertEqual(Path(m.VISION_CHECK).name,'check.json')

if __name__=='__main__':unittest.main()
