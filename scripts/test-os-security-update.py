"""scripts/test-os-security-update.py - OS更新の範囲・改変検知・適用前条件を検証する。"""
import hashlib
import contextlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest
import sys
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'payload/server-gui/server_gui/os_security_update.py'
spec = importlib.util.spec_from_file_location('os_update', SOURCE)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def pkg(name, evr='1-1', arch='x86_64', repo='baseos', obsoletes=()):
    return SimpleNamespace(name=name, evr=evr, arch=arch, reponame=repo, obsoletes=obsoletes)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        replacement = patch.object(module, 'ROOT', self.root); replacement.start(); self.addCleanup(replacement.stop)

    def test_only_stable_repositories_are_eligible(self):
        self.assertNotIn('almalinux-testing', module.STABLE_REPOS)
        self.assertNotIn('elrepo', module.STABLE_REPOS)
        self.assertNotIn('epel', module.STABLE_REPOS)

    def test_replace_previous_version_is_allowed(self):
        base = SimpleNamespace(transaction=SimpleNamespace(install_set=[pkg('curl', '2-1')], remove_set=[pkg('curl')]))
        self.assertEqual(module.validate_transaction(base)[0]['evr'], '2-1')

    def test_unrelated_removal_is_blocked(self):
        base = SimpleNamespace(transaction=SimpleNamespace(install_set=[pkg('curl')], remove_set=[pkg('NetworkManager')]))
        with self.assertRaises(RuntimeError): module.validate_transaction(base)

    def test_el8_dbxtool_obsolete_requires_exact_fwupd_metadata(self):
        base = SimpleNamespace(transaction=SimpleNamespace(
            install_set=[pkg('fwupd', obsoletes=['dbxtool < 9'])], remove_set=[pkg('dbxtool')]))
        module.validate_transaction(base)
        base.transaction.install_set[0].obsoletes = []
        with self.assertRaises(RuntimeError): module.validate_transaction(base)

    def test_transaction_drift_is_blocked(self):
        base = SimpleNamespace(transaction=SimpleNamespace(install_set=[pkg('curl', '3-1')], remove_set=[]))
        with self.assertRaises(RuntimeError):
            module.validate_transaction(base, [module.package_row(pkg('curl', '2-1'))])

    def test_empty_transaction_is_supported(self):
        self.assertEqual(module.validate_transaction(SimpleNamespace(transaction=None)), [])

    def test_network_and_boot_impact_are_visible(self):
        rows = [module.package_row(pkg(name)) for name in ('NetworkManager', 'firewalld', 'glibc', 'kernel-core', 'grub2-common')]
        impact = module.impact(rows)
        self.assertIn('NetworkManager', impact['WAN/LAN・DHCP・VPN'])
        self.assertIn('glibc', impact['OS基盤・認証'])
        self.assertIn('grub2-common', impact['カーネル・起動環境'])

    def test_apply_requires_both_confirmations_before_any_side_effect(self):
        with patch.object(module, 'checked_plan') as load:
            for maintenance, recovery in ((False, False), (True, False), (False, True)):
                with self.assertRaises(RuntimeError): module.apply_update('a'*32, maintenance, recovery)
            load.assert_not_called()

    def test_traversal_plan_id_is_rejected(self):
        with self.assertRaises(RuntimeError): module.checked_plan('../etc')

    def test_expired_plan_is_rejected(self):
        job = self.root / ('a'*32);job.mkdir()
        module.write_json(job/'plan.json', {'created_at': time.time()-module.MAX_AGE-1, 'os':'9.8'})
        with patch.object(module, 'release', return_value='9.8'):
            with self.assertRaises(RuntimeError): module.checked_plan('a'*32)

    def test_rpmdb_drift_is_rejected_before_local_rpms_are_added(self):
        base=Mock();base.close=Mock()
        with patch.object(module,'base_for',return_value=base), patch.object(module,'rpmdb_hash',return_value='changed'):
            with self.assertRaises(RuntimeError): module.local_transaction(self.root, {'rpmdb_hash':'original'})
            base.add_remote_rpms.assert_not_called()

    def test_payload_hash_change_is_rejected(self):
        path=self.root/'package.rpm';path.write_bytes(b'changed')
        row=dict(module.package_row(pkg('curl')),path=str(path),sha256=hashlib.sha256(b'original').hexdigest())
        plan={'rpmdb_hash':'same','payload':[row],'packages':[module.package_row(pkg('curl'))]}
        base=Mock()
        with patch.object(module,'base_for',return_value=base),patch.object(module,'rpmdb_hash',return_value='same'):
            with self.assertRaises(RuntimeError):module.local_transaction(self.root,plan)
            base.add_remote_rpms.assert_not_called()

    def test_health_regression_is_reported(self):
        before={'services':{'sshd':'active'},'route':'default via test','local_gui':True,'mitigation_active':True}
        after={'services':{'sshd':'inactive'},'route':'','local_gui':False,'mitigation_active':False}
        self.assertEqual(len(module.compare_health(before,after)),4)

    def test_health_no_change_is_not_an_error(self):
        state={'services':{'sshd':'active'},'route':'default via test','local_gui':True,'mitigation_active':True}
        self.assertEqual(module.compare_health(state,state),[])

    def test_atomic_state_write(self):
        module.save_state({'phase':'ready'})
        self.assertEqual(module.read_json(self.root/'state.json')['phase'],'ready')
        self.assertFalse((self.root/'state.tmp').exists())

    def test_apply_requires_successful_test(self):
        with patch.object(module,'checked_plan',return_value=(self.root,{})),patch.object(module,'preflight') as preflight:
            with self.assertRaises(RuntimeError):module.apply_update('a'*32,True,True)
            preflight.assert_not_called()

    def test_base_excludes_testing_and_forces_signature_checks(self):
        stable=SimpleNamespace(id='baseos',enabled=True,gpgkey=['file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux'])
        app=SimpleNamespace(id='appstream',enabled=True,gpgkey=stable.gpgkey)
        testing=SimpleNamespace(id='almalinux-testing',enabled=True,disable=Mock())
        third=SimpleNamespace(id='elrepo',enabled=True,disable=Mock())
        base=Mock();base.conf=SimpleNamespace(read=Mock());base.repos.all.return_value=[stable,app,testing,third]
        with patch.dict(sys.modules,{'dnf':SimpleNamespace(Base=lambda:base)}):
            module.base_for(self.root,test=True)
        testing.disable.assert_called_once();third.disable.assert_called_once()
        self.assertTrue(base.conf.gpgcheck);self.assertTrue(base.conf.localpkg_gpgcheck)
        self.assertEqual(base.conf.installonly_limit,0)
        self.assertEqual(base.conf.tsflags,['test'])

    def test_foreign_repo_key_is_blocked(self):
        repo=SimpleNamespace(id='baseos',enabled=True,gpgkey=['file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Other'])
        base=Mock();base.conf=SimpleNamespace(read=Mock());base.repos.all.return_value=[repo]
        with patch.dict(sys.modules,{'dnf':SimpleNamespace(Base=lambda:base)}):
            with self.assertRaises(RuntimeError):module.base_for(self.root)
        base.fill_sack.assert_not_called()

    def test_local_rpm_bad_signature_is_blocked(self):
        path=self.root/'package.rpm';path.write_bytes(b'payload')
        row=dict(module.package_row(pkg('curl')),path=str(path),sha256=hashlib.sha256(b'payload').hexdigest())
        plan={'rpmdb_hash':'same','payload':[row],'packages':[module.package_row(pkg('curl'))]}
        base=Mock();base.add_remote_rpms.return_value=[pkg('curl')];base.package_signature_check.return_value=(2,'bad signature')
        base.add_remote_rpms.return_value[0].localPkg=lambda: str(path)
        with patch.object(module,'base_for',return_value=base),patch.object(module,'rpmdb_hash',return_value='same'), \
                patch.object(module,'keyring',return_value=(self.root/'key',self.root/'keydb')), \
                patch.object(module,'verify_signed_rpm',side_effect=RuntimeError('bad signature')):
            with self.assertRaises(RuntimeError):module.local_transaction(self.root,plan)
            base.package_install.assert_not_called()

    def test_unknown_primary_fingerprint_is_rejected(self):
        output='pub::::::::::\nfpr:::::::::0000000000000000000000000000000000000000:\n'
        with patch.object(module,'release',return_value='9.8'), \
                patch.object(module,'command',return_value=SimpleNamespace(stdout=output)) as run:
            with self.assertRaises(RuntimeError):module.keyring(self.root)
            self.assertEqual(run.call_count,1)

    def test_unsigned_rpm_is_rejected_even_with_success_exit_code(self):
        with patch.object(module,'command',return_value=SimpleNamespace(stdout='Header SHA256 digest: OK\nPayload SHA256 digest: OK')):
            with self.assertRaises(RuntimeError):module.verify_signed_rpm(self.root/'unsigned.rpm',self.root/'keydb')

    def test_apply_displays_reboot_message_without_reboot_command(self):
        row=module.package_row(pkg('kernel-core','2-1'))
        plan={'transaction_test_ok':True,'packages':[row],'download_bytes':1,'os':'9.8','reboot_expected':True}
        state={'services':{name:'active' for name in ('NetworkManager','firewalld','sshd','server-gui')},
               'route':'default via test','local_gui':True,'mitigation_active':True,'direct_rules':[]}
        transaction=Mock();transaction.__enter__=Mock(return_value=transaction);transaction.__exit__=Mock(return_value=False)
        verification=Mock();verification.__enter__=Mock(return_value=verification);verification.__exit__=Mock(return_value=False)
        verification.sack.query.return_value.installed.return_value=[pkg('kernel-core','2-1')]
        @contextlib.contextmanager
        def backup(path,*args,**kwargs):
            Path(path).write_bytes(b'test archive');yield Mock()
        with patch.object(module,'checked_plan',return_value=(self.root,plan)), \
                patch.object(module,'preflight'),patch.object(module,'local_transaction',return_value=transaction), \
                patch.object(module,'health',return_value=state),patch.object(module.tarfile,'open',side_effect=backup), \
                patch.object(module,'keyring',return_value=(self.root/'key',self.root/'keydb')), \
                patch.object(module,'command') as command,patch.object(module,'base_for',return_value=verification), \
                patch.object(module,'kernel_state',return_value={'cve_2026_98432_running_fixed':False}), \
                patch.object(module,'boot_id',return_value='before-reboot'):
            module.apply_update('a'*32,True,True)
        result=module.read_json(self.root/'state.json')
        self.assertEqual(result['phase'],'applied');self.assertTrue(result['reboot_required'])
        self.assertIn('OSを再起動',result['message'])
        self.assertFalse(any(call.args[0][0] in ('reboot','shutdown') for call in command.call_args_list))

    def test_reboot_prompt_clears_only_after_os_boot_id_changes(self):
        module.save_state({'phase':'applied','reboot_required':True,'applied_boot_id':'first'})
        with patch.object(module,'release',return_value='9.8'), \
                patch.object(module,'kernel_state',return_value={'cve_2026_98432_running_fixed':False}), \
                patch.object(module,'boot_id',return_value='first'):
            self.assertTrue(module.status()['reboot_required'])
        with patch.object(module,'release',return_value='9.8'), \
                patch.object(module,'kernel_state',return_value={'cve_2026_98432_running_fixed':False}), \
                patch.object(module,'boot_id',return_value='second'):
            state=module.status();self.assertFalse(state['reboot_required'])
            self.assertFalse(state['kernel']['cve_2026_98432_running_fixed'])

    def test_forwarding_rule_change_is_reported_with_services_still_active(self):
        before={'services':{'firewalld':'active'},'route':'default via test','local_gui':True,
                'mitigation_active':True,'direct_rules':['ipv4 nat POSTROUTING 1 -j MASQUERADE']}
        after=dict(before,direct_rules=[])
        self.assertIn('directルール',module.compare_health(before,after)[0])

    def test_custom_kernel_is_not_declared_fixed_by_version_alone(self):
        with patch.dict(sys.modules,{'rpm':SimpleNamespace(labelCompare=lambda a,b:1)}), \
                patch.object(module.os,'uname',return_value=SimpleNamespace(release='6.6.1-1.elrepo.x86_64'),create=True):
            self.assertFalse(module.kernel_state('9.8')['cve_2026_98432_running_fixed'])

    def test_official_kernel_at_or_above_minimum_is_reported_fixed(self):
        with patch.dict(sys.modules,{'rpm':SimpleNamespace(labelCompare=lambda a,b:0)}), \
                patch.object(module.os,'uname',return_value=SimpleNamespace(release='5.14.0-687.61.2.el9_8.x86_64'),create=True):
            self.assertTrue(module.kernel_state('9.8')['cve_2026_98432_running_fixed'])


if __name__ == '__main__':
    unittest.main()
