"""scripts/test-os-security-api.py - Flask環境でOS更新APIの認証・適用条件・固定引数を検証。"""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'payload/server-gui'))
from flask import Flask

source = ROOT / 'payload/server-gui/server_gui/modules/admin.py'
spec = importlib.util.spec_from_file_location('server_gui.modules.os_security_admin_test', source)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.app = Flask(__name__);self.app.testing=True;self.app.secret_key='isolated-test-only'
        self.app.register_blueprint(module.bp);self.client=self.app.test_client()
        for name,value in (('_os_update_active',lambda:False),
                           ('verify_admin_password',lambda value:value=='valid-test-password')):
            patcher=patch.object(module,name,value);patcher.start();self.addCleanup(patcher.stop)
        patcher=patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='queued',stderr=''))
        self.run=patcher.start();self.addCleanup(patcher.stop)

    def authenticate(self):
        with self.client.session_transaction() as session:
            session['user']='test';session['csrf_token']='test-token'

    def post(self,payload):
        return self.client.post('/admin/api/os-security/run',json=payload,headers={'X-CSRF-Token':'test-token'})

    def test_unauthenticated_is_rejected(self):
        self.assertEqual(self.client.get('/admin/api/os-security/status').status_code,401)
        self.assertEqual(self.post({'action':'plan'}).status_code,401)
        self.run.assert_not_called()

    def test_csrf_is_required(self):
        self.authenticate()
        self.assertEqual(self.client.post('/admin/api/os-security/run',json={'action':'plan'}).status_code,403)
        self.run.assert_not_called()

    def test_invalid_action_and_plan_id_are_rejected(self):
        self.authenticate()
        for payload in ([1],{'action':'reboot'},{'action':'apply','plan_id':'../etc'}):
            self.assertEqual(self.post(payload).status_code,400)
        self.run.assert_not_called()

    def test_apply_requires_password(self):
        self.authenticate()
        self.assertEqual(self.post({'action':'apply','plan_id':'a'*32,'password':'wrong'}).status_code,403)
        self.run.assert_not_called()

    def test_apply_requires_boolean_acknowledgements(self):
        self.authenticate()
        self.assertEqual(self.post({'action':'apply','plan_id':'a'*32,'password':'valid-test-password',
                                  'maintenance_confirmed':1,'recovery_confirmed':True}).status_code,400)
        self.run.assert_not_called()

    def test_dispatch_does_not_put_password_in_arguments(self):
        self.authenticate()
        payload={'action':'apply','plan_id':'a'*32,'password':'valid-test-password',
                 'maintenance_confirmed':True,'recovery_confirmed':True}
        self.assertEqual(self.post(payload).status_code,202)
        args=self.run.call_args.args[0]
        self.assertIn('--maintenance-confirmed',args);self.assertIn('--recovery-confirmed',args)
        self.assertNotIn('valid-test-password',args)
        self.assertNotIn('reboot',args)

    def test_busy_worker_is_rejected(self):
        self.authenticate()
        with patch.object(module,'_os_update_active',return_value=True):
            self.assertEqual(self.post({'action':'plan'}).status_code,409)
        self.run.assert_not_called()

    def test_interrupted_worker_is_reported(self):
        self.authenticate()
        self.run.return_value.stdout=json.dumps({'phase':'applying'})
        result=self.client.get('/admin/api/os-security/status')
        self.assertEqual(result.json['phase'],'interrupted')


if __name__ == '__main__':
    unittest.main()
