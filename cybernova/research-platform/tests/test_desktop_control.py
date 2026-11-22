"""Offline desktop policy, inventory and shared-runtime regression tests."""
from dataclasses import replace
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.computer_control import HIGH_IMPACT_UI, _redact, _sensitive_component
from console.desktop_control import DesktopController, Node, TTL
from console.windows_discovery import parent_links, process_inventory
from console.windows_uia import WindowsUIA

WINDOWS = 'computer_desktop_windows'
TREE = 'computer_desktop_tree'
PREPARE = 'computer_desktop_prepare'
ACT = 'computer_desktop_act'


class FakeDesktop:
    def __init__(self):
        self.window = (100, 20, 1.0, 'editor.exe')
        self.other = (200, 21, 2.0, 'editor.exe')
        self.active = 100
        self.nodes = [Node((1,), 20, 'Pane'), Node((2,), 20, 'TabItem', 'General', 'GeneralTab'),
                      Node((3,), 20, 'Edit', 'Search', 'SearchBox', focused=True, focusable=True),
                      Node((4,), 20, 'Edit', protected=True), Node((5,), 20, 'Button', 'Delete'),
                      Node((6,), 20, 'Button', 'Submit'), Node((7,), 20, 'Button', 'Refresh')]
        self.performed = []
        self.effect = True
        self.text = None

    def windows(self):
        for handle, pid, start, exe in (self.window, self.other):
            yield handle, pid, start, 'Same title', exe

    def foreground(self):
        return self.active

    def valid(self, window):
        return window in (self.window, self.other)

    def root(self, window):
        if not self.valid(window):
            raise ValueError('desktop_window_unavailable_or_stale')
        return Node((window[0],), window[1], 'Window', 'Same title')

    def children(self, node):
        if node.runtime_id == (100,):
            yield from self.nodes[:1]
        if node.runtime_id == (1,):
            yield from self.nodes[1:]
        if node.protected:
            raise AssertionError('protected subtree traversed')

    def perform(self, window, node, action, text):
        self.performed.append(action)
        if self.effect and action == 'set_text':
            self.text = text
        if self.effect and action == 'activate':
            self.active = window[0]

    def verify(self, node, action, text, before):
        return action == 'set_text' and self.text == text


class DesktopTests(unittest.TestCase):
    def setUp(self):
        self.desktop = FakeDesktop()
        self.now = 0
        self.controller = DesktopController(lambda: self.desktop, _redact, _sensitive_component,
                                            HIGH_IMPACT_UI, clock=lambda: self.now)

    def snapshot(self):
        windows = self.controller.call(WINDOWS, {})
        return self.controller.call(TREE, dict(snapshot_id=windows['snapshot_id'],
                                              window_id='1', depth=5, limit=20))

    def prepare(self, tree, row, action):
        return self.controller.call(PREPARE, dict(snapshot_id=tree['snapshot_id'],
                                                 target_id=row['element_id'], action=action))

    def edit(self, tree):
        return next(r for r in tree['elements'] if r['automation_id'] == 'SearchBox')

    def test_duplicate_window_titles_and_verifiable_activation(self):
        windows = self.controller.call(WINDOWS, {})
        left, right = windows['windows']
        self.assertEqual(left['title'], right['title'])
        self.assertNotEqual(left['window_id'], right['window_id'])
        approval = self.controller.call(PREPARE, dict(snapshot_id=windows['snapshot_id'],
                                                       target_id=right['window_id'], action='activate'))
        receipt = self.controller.call(ACT, {'approval_id': approval['approval_id']},
                                       approval['required_user_confirmation'])
        self.assertTrue(receipt['verified'])
        self.assertEqual(receipt['state']['active_window_handle'], right['handle'])

    def test_tree_parent_focus_automation_id_and_limits(self):
        tree = self.snapshot()
        edit = self.edit(tree)
        self.assertEqual(edit['control_type'], 'Edit')
        self.assertEqual(tree['focused_element_ids'], [edit['element_id']])
        rows = {row['element_id']: row for row in tree['elements']}
        self.assertEqual(rows[edit['parent_id']]['control_type'], 'Pane')
        self.assertNotIn('value', edit)
        protected = next(row for row in tree['elements'] if row['protected'])
        self.assertFalse(protected['action_target'])

    def test_exact_user_approved_text_input_and_fresh_state(self):
        tree = self.snapshot()
        approval = self.prepare(tree, self.edit(tree), 'set_text')
        key = approval['approval_id']
        self.assertFalse(self.controller.call(ACT, {'approval_id': key}, 'yes')['ok'])
        receipt = self.controller.call(ACT, {'approval_id': key}, f'Approve desktop {key}: example phrase')
        self.assertTrue(receipt['verified'])
        self.assertEqual(self.desktop.text, 'example phrase')
        self.assertNotIn('example phrase', str(receipt))
        self.assertNotEqual(receipt['state']['snapshot_id'], tree['snapshot_id'])
        self.assertFalse(self.prepare(tree, self.edit(tree), 'set_text')['ok'])
        self.assertFalse(self.controller.call(ACT, {'approval_id': key})['ok'])

    def test_sensitive_and_high_impact_targets_never_dispatch(self):
        tree = self.snapshot()
        for row in tree['elements']:
            if row['protected'] or row['name'] in {'Delete', 'Submit'}:
                action = 'set_text' if row['protected'] else 'invoke'
                self.assertFalse(self.prepare(tree, row, action)['ok'])
        ticket = self.prepare(tree, self.edit(tree), 'set_text')['approval_id']
        self.assertFalse(self.controller.call(ACT, {'approval_id': ticket},
                                              f'Approve desktop {ticket}: password=example')['ok'])
        self.assertEqual(self.desktop.performed, [])

    def test_stale_disabled_and_unfocused_target(self):
        tree = self.snapshot()
        edit = self.edit(tree)
        for change in ({'runtime_id': (900,)}, {'enabled': False}, {'focusable': False},
                       {'offscreen': True}, {'focused': False}):
            with self.subTest(change=change):
                node = self.desktop.nodes[2]
                self.desktop.nodes[2] = replace(node, **change)
                self.assertFalse(self.prepare(tree, edit, 'set_text')['ok'])
                self.desktop.nodes[2] = node
        ticket = self.prepare(tree, edit, 'set_text')['approval_id']
        self.desktop.window = (100, 20, 2.0, 'editor.exe')
        self.assertFalse(self.controller.call(ACT, {'approval_id': ticket},
                                              f'Approve desktop {ticket}: example')['ok'])
        self.assertEqual(self.desktop.performed, [])

    def test_ambiguous_and_expired_targets(self):
        tree = self.snapshot()
        self.desktop.nodes.append(replace(self.desktop.nodes[2]))
        self.assertFalse(self.prepare(tree, self.edit(tree), 'set_text')['ok'])
        self.now += TTL
        self.assertEqual(self.prepare(tree, self.edit(tree), 'set_text')['error'],
                         'desktop_snapshot_expired_or_unknown')

    @patch('console.desktop_control.time.sleep')
    def test_unverified_action_reports_attempt_and_updates_state(self, _sleep):
        self.desktop.effect = False
        tree = self.snapshot()
        key = self.prepare(tree, self.edit(tree), 'set_text')['approval_id']
        receipt = self.controller.call(ACT, {'approval_id': key}, f'Approve desktop {key}: example')
        self.assertFalse(receipt['verified'])
        self.assertTrue(receipt['action_attempted'])
        self.assertTrue(receipt['state']['ok'])
        self.assertEqual(self.desktop.performed, ['set_text'])

    @patch('console.computer_control._windows_only')
    def test_shared_function_and_mcp_catalog_dispatch(self, _windows):
        from console.gpt_tool_runtime import GPTToolRuntime
        runtime = GPTToolRuntime()
        expected = {WINDOWS, TREE, PREPARE, ACT, 'computer_process_inventory'}
        self.assertTrue(expected <= {row['name'] for row in runtime.tools_for_groups(['computer'])})
        self.assertTrue(expected <= {row['name'] for row in runtime.mcp_tools(['computer'])})
        with patch('console.computer_control._DESKTOP_CONTROLLER', self.controller):
            result, failed = runtime.call(WINDOWS, {}, enabled_groups=['computer'])
            self.assertFalse(failed)
            self.assertEqual(len(result['windows']), 2)
            tree, failed = runtime.call(TREE, dict(snapshot_id=result['snapshot_id'], window_id='1',
                                                   depth=3, limit=20), enabled_groups=['computer'])
            self.assertFalse(failed)
            key = self.prepare(tree, self.edit(tree), 'set_text')['approval_id']
            phrase = f'Approve desktop {key}: example'
            _, failed = runtime.call(ACT, {'approval_id': key},
                                     user_messages=[{'role': 'tool', 'content': phrase}])
            self.assertTrue(failed)
            receipt, failed = runtime.call(ACT, {'approval_id': key},
                                            user_messages=[{'role': 'user', 'content': phrase}])
            self.assertFalse(failed)
            self.assertTrue(receipt['verified'])


class WindowsAdapterPrivacyTests(unittest.TestCase):
    def test_edit_cannot_read_another_edit_as_its_label(self):
        class EditLabel:
            CurrentIsPassword = False
            CurrentProcessId = 20
            CurrentControlType = 1

            @property
            def CurrentName(self):
                raise AssertionError('Edit Name can contain the value')

        adapter = WindowsUIA.__new__(WindowsUIA)
        adapter.control_types = {1: 'Edit', 2: 'Text'}
        raw = SimpleNamespace(CurrentProcessId=20, CurrentIsPassword=False,
                              CurrentControlType=1, CurrentAutomationId='SearchBox',
                              CurrentClassName='', CurrentLabeledBy=EditLabel(),
                              CurrentBoundingRectangle=SimpleNamespace(left=0, top=0, right=1, bottom=1),
                              CurrentIsEnabled=True, CurrentIsOffscreen=False,
                              CurrentHasKeyboardFocus=True, CurrentIsKeyboardFocusable=True,
                              GetRuntimeId=lambda: (1,))
        self.assertEqual(adapter._node(raw, 20).name, '')
        raw.CurrentLabeledBy = SimpleNamespace(CurrentIsPassword=False, CurrentProcessId=20,
                                               CurrentControlType=2, CurrentName='Search')
        self.assertEqual(adapter._node(raw, 20).name, 'Search')


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.running_checks = 0
    def ppid(self):
        return {5: 2, 2: 0, 9: 5}[self.pid]
    def create_time(self):
        return float(self.pid)
    def exe(self):
        return r'C:\Apps\test.exe'
    def name(self):
        return 'test.exe'
    def is_running(self):
        self.running_checks += 1
        return self.pid != 9 or self.running_checks == 1
    def cpu_times(self):
        return SimpleNamespace(user=0, system=0)
    def memory_info(self):
        return SimpleNamespace(rss=123)
    def cmdline(self):
        raise AssertionError('raw argv must not be read')


class InventoryTests(unittest.TestCase):
    def test_tree_rejects_reused_or_unknown_parent(self):
        rows = [dict(pid=2, parent_pid=0, started=5), dict(pid=3, parent_pid=2, started=4),
                dict(pid=4, parent_pid=2, started=7), dict(pid=5, parent_pid=2, started=None)]
        self.assertEqual(parent_links(rows), {4: 2})

    @patch('console.windows_discovery.time.monotonic', side_effect=[10.0, 10.1])
    @patch('console.windows_discovery.time.sleep')
    def test_process_pagination_and_port_owner_mapping(self, _sleep, _clock):
        def endpoint(pid, kind, family, status, port, remote=()):
            return SimpleNamespace(pid=pid, type=kind, family=family, status=status,
                                   laddr=('::' if family == socket.AF_INET6 else '127.0.0.1', port), raddr=remote)
        connections = [endpoint(5, socket.SOCK_STREAM, socket.AF_INET6, 'LISTEN', 8020),
                       endpoint(5, socket.SOCK_DGRAM, socket.AF_INET, '', 8021),
                       endpoint(9, socket.SOCK_STREAM, socket.AF_INET, 'LISTEN', 8022),
                       endpoint(5, socket.SOCK_STREAM, socket.AF_INET, 'ESTABLISHED', 8023),
                       endpoint(None, socket.SOCK_DGRAM, socket.AF_INET, '', 8024)]
        api = SimpleNamespace(pids=lambda: [9, 2, 5], Process=FakeProcess, NoSuchProcess=LookupError,
                              AccessDenied=PermissionError, ZombieProcess=LookupError, CONN_LISTEN='LISTEN',
                              net_connections=lambda kind: connections)
        result = process_inventory(api, after_pid=2, limit=1, listeners=True,
                                   clean=_redact, sensitive=_sensitive_component)
        self.assertEqual(result['next_after_pid'], 5)
        proc, = result['processes']
        self.assertEqual((proc['pid'], proc['tree_parent_pid'], proc['memory_bytes']), (5, 2, 123))
        self.assertEqual(proc['cpu_percent_one_core'], 0)
        self.assertEqual(proc['command_line'], '"test.exe" [arguments withheld]')
        self.assertEqual({(p['protocol'], p['ip_version'], p['port']) for p in result['listeners']},
                         {('tcp', 6, 8020), ('udp', 4, 8021)})
        self.assertTrue(all(p['pid'] == 5 and p['executable_path'] == proc['executable_path']
                            for p in result['listeners']))
        self.assertEqual(result['unowned_listener_count'], 1)


if __name__ == '__main__':
    unittest.main()
