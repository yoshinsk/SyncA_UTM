"""scripts/test-firewall-lan-access.py - LAN許可の範囲、冪等性と失敗時復元を検証。"""
import ast
import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'payload/server-gui/server_gui/modules/firewall.py'


class LanAccessTests(unittest.TestCase):
    def setUp(self):
        """外部コマンドを模擬し、実機のファイアウォールを変更せず検証する。"""
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
        names = {'_lan_rule', '_lan_candidates', '_set_lan_access', '_lan_policy_ready'}
        functions = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)
                                    and n.name in names], type_ignores=[])
        self.env = {'ipaddress': ipaddress, 'json': json}
        exec(compile(functions, str(SOURCE), 'exec'), self.env)
        self.states = {True: False, False: False}
        self.commands = []
        self.fail_runtime = False
        self.env['sudo_run'] = self.command

    def command(self, argv):
        """永続・実行時設定を独立に保持し、実行時変更の失敗を再現する。"""
        self.commands.append(argv)
        permanent = '--permanent' in argv
        op = argv[-1]
        ok, error = True, ''
        if '--query-rich-rule=' in op:
            ok = self.states[permanent]
        elif '--add-rich-rule=' in op or '--remove-rich-rule=' in op:
            if self.fail_runtime and not permanent:
                ok, error = False, 'simulated runtime failure'
            else:
                self.states[permanent] = '--add-rich-rule=' in op
        return SimpleNamespace(ok=ok, returncode=0 if ok else 1, stdout='', stderr=error)

    def test_rule_is_bounded_on_both_sides_without_protocol_limit(self):
        rule = self.env['_lan_rule']('192.168.1.0/24')
        self.assertIn('source address="192.168.1.0/24"', rule)
        self.assertIn('destination address="192.168.1.0/24"', rule)
        self.assertNotIn('port', rule)
        self.assertNotIn('protocol', rule)

    def test_enable_and_disable_both_states_without_reload(self):
        for enabled in (True, False):
            self.assertTrue(self.env['_set_lan_access']('192.168.1.0/24', enabled)['ok'])
            self.assertEqual(self.states, {True: enabled, False: enabled})
        self.assertFalse(any('--reload' in c or '--direct' in c for c in self.commands))
        self.assertTrue(all('--policy=synca-lan-internal' in c for c in self.commands))

    def test_idempotent_enable(self):
        self.states = {True: True, False: True}
        self.env['_set_lan_access']('192.168.1.0/24', True)
        self.assertEqual(len(self.commands), 2)

    def test_runtime_failure_rolls_back_new_permanent_rule(self):
        self.fail_runtime = True
        result = self.env['_set_lan_access']('192.168.1.0/24', True)
        self.assertFalse(result['ok'])
        self.assertEqual(self.states, {True: False, False: False})

    def test_failed_disable_restores_existing_permanent_rule(self):
        self.states = {True: True, False: True}
        self.fail_runtime = True
        self.assertFalse(self.env['_set_lan_access']('192.168.1.0/24', False)['ok'])
        self.assertEqual(self.states, {True: True, False: True})

    def test_query_error_never_changes_rules(self):
        self.env['sudo_run'] = lambda argv: SimpleNamespace(
            ok=False, returncode=252, stdout='', stderr='DBus unavailable')
        self.assertFalse(self.env['_set_lan_access']('192.168.1.0/24', True)['ok'])
        self.assertEqual(self.states, {True: False, False: False})

    def test_candidates_exclude_wan_and_nontrusted_and_host_routes(self):
        addresses = [{'ifname': name, 'addr_info': [{'local': ip, 'prefixlen': prefix,
                       'scope': 'global'}]} for name, ip, prefix in (
                           ('br-lan', '192.168.1.1', 24), ('wan', '10.0.0.2', 24),
                           ('guest', '192.168.2.1', 24), ('vpn', '10.1.1.1', 32))]

        def discover(argv):
            if 'address' in argv:
                value = json.dumps(addresses)
            elif 'route' in argv:
                value = '[{"dev":"wan"}]'
            else:
                value = 'public' if 'guest' in argv[-1] else 'trusted'
            return SimpleNamespace(ok=True, stdout=value)

        self.env['sudo_run'] = discover
        self.assertEqual(self.env['_lan_candidates'](),
                         [{'interface': 'br-lan', 'subnet': '192.168.1.0/24'}])

    def test_missing_policy_read_is_nonmutating(self):
        self.assertFalse(self.env['_lan_policy_ready']())
        self.assertEqual(len(self.commands), 2)

    def test_policy_initialization_is_trusted_to_trusted(self):
        self.env['_reload_firewall_and_refresh_fail2ban'] = lambda: (True, '')
        self.assertTrue(self.env['_lan_policy_ready'](create=True))
        operations = [c[-1] for c in self.commands]
        self.assertIn('--add-ingress-zone=trusted', operations)
        self.assertIn('--add-egress-zone=trusted', operations)
        self.assertIn('--set-target=CONTINUE', operations)
        self.assertIn('--set-priority=-109', operations)
        self.assertFalse(any('ANY' in op or 'HOST' in op for op in operations))

    def test_policy_scope_collision_is_rejected(self):
        self.env['sudo_run'] = lambda argv: SimpleNamespace(
            ok=True, stdout='synca-lan-internal' if argv[-1] == '--get-policies' else 'ANY')
        with self.assertRaises(ValueError):
            self.env['_lan_policy_ready'](create=True)

    def test_existing_policy_is_checked_without_reload(self):
        def existing(argv):
            value = ('synca-lan-internal' if argv[-1] == '--get-policies' else
                     '  ingress-zones: trusted\n  egress-zones: trusted\n'
                     '  target: CONTINUE\n  priority: -109\n')
            return SimpleNamespace(ok=True, stdout=value)
        self.env['sudo_run'] = existing
        self.assertTrue(self.env['_lan_policy_ready'](create=True))

    def test_policy_runtime_permanent_mismatch_is_rejected(self):
        self.env['sudo_run'] = lambda argv: SimpleNamespace(
            ok=True, stdout='synca-lan-internal' if '--permanent' in argv else '')
        with self.assertRaises(ValueError):
            self.env['_lan_policy_ready'](create=True)


if __name__ == '__main__':
    unittest.main()
