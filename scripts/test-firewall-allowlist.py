"""scripts/test-firewall-allowlist.py

Test bulk IP-set source moves and the bounded GUI command count.
"""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[1] / 'payload/server-gui/server_gui/modules/firewall.py'


def namespace():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    selected = {'_apply_public_ipset_allowlist', '_remove_source_from_other_zones'}
    functions = ast.Module(body=[node for node in tree.body
                                 if isinstance(node, ast.FunctionDef) and node.name in selected], type_ignores=[])
    env = {}
    exec(compile(functions, str(SOURCE), 'exec'), env)
    return env


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self.env = namespace()
        self.zones = {'public', 'japan', 'drop', 'trusted'}
        self.membership = {'public': 'ipset:first', 'japan': '', 'drop': 'ipset:cn-ipv4 ipset:kr-ipv4', 'trusted': ''}
        self.commands = []

        def command(argv):
            self.commands.append(argv)
            if argv[-1] == '--list-sources':
                return SimpleNamespace(ok=True, stdout=self.membership[argv[-2]], stderr='')
            return SimpleNamespace(ok=True, stdout='', stderr='')

        self.env.update({
            '_zone_names': lambda: self.zones,
            'sudo_run': Mock(side_effect=command),
            '_describe_zone': Mock(return_value={'services': [], 'ports': [], 'forward_ports': []}),
            '_collect_firewall_change': lambda argv, changed, errors, **kwargs: changed.append(argv),
            '_remove_allowlist_drop_guards': Mock(),
            '_direct_rule_lines': lambda **kwargs: set(),
            '_build_drop_zone_guard_rules': lambda: [],
            '_reload_firewall_and_refresh_fail2ban': Mock(return_value=(True, '')),
        })

    def test_bulk_moves_query_each_zone_once(self):
        names = ['first'] + [f'allow{i}' for i in range(12)]
        result = self.env['_apply_public_ipset_allowlist']('japan', names, True)
        self.assertTrue(result['ok'])
        queries = [argv for argv in self.commands if argv[-1] == '--list-sources']
        self.assertEqual(len(queries), len(self.zones))
        self.env['_describe_zone'].assert_called_once_with('public', permanent=True)
        changed = result['changed']
        remove = ['firewall-cmd', '--permanent', '--zone', 'public', '--remove-source', 'ipset:first']
        add = ['firewall-cmd', '--permanent', '--zone', 'japan', '--add-source', 'ipset:first']
        self.assertLess(changed.index(remove), changed.index(add))
        self.assertFalse(any('ipset:cn-ipv4' in argv or 'ipset:kr-ipv4' in argv for argv in changed))

    def test_read_failure_does_not_change_existing_policy(self):
        self.env['sudo_run'] = Mock(return_value=SimpleNamespace(ok=False, stdout='', stderr='DBus unavailable'))
        collect = Mock()
        self.env['_collect_firewall_change'] = collect
        result = self.env['_apply_public_ipset_allowlist']('japan', ['first'], True)
        self.assertFalse(result['ok'])
        self.assertEqual(result['error'], 'DBus unavailable')
        collect.assert_not_called()
        self.env['_reload_firewall_and_refresh_fail2ban'].assert_not_called()

    def test_failed_move_keeps_snapshot_membership(self):
        sources = {'public': {'ipset:first'}, 'japan': set()}
        errors = []
        self.env['_collect_firewall_change'] = lambda argv, changed, errors, **kwargs: errors.append('move failed')
        self.env['_remove_source_from_other_zones']('ipset:first', 'japan', [], errors, sources)
        self.assertIn('ipset:first', sources['public'])
        self.assertEqual(errors, ['move failed'])


if __name__ == '__main__':
    unittest.main()
