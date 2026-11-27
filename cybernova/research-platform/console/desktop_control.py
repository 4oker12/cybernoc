"""Bounded desktop snapshots and single-use, explicitly approved UIA actions."""
from __future__ import annotations

import re
import secrets
import time
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

TTL = 300
MAX_SNAPSHOTS = 16
ACTIONS = ("activate", "focus", "set_text", "select", "expand", "collapse", "scroll_up", "scroll_down", "invoke")
SAFE_INVOKE_LABELS = {"back", "refresh", "details", "properties"}
SENSITIVE = re.compile(r"(?i)pass(?:word|wd|code|phrase)|pwd|pin\b|token|credential|secret|api.?key|"
                       r"sign.?in|log.?in|authenticat|security.?code|payment|card.?number|"
                       r"\u043f\u0430\u0440\u043e\u043b|\u043f\u0438\u043d.?\u043a\u043e\u0434|\u0442\u043e\u043a\u0435\u043d")
NAVIGATION_TYPES = {"Button", "TabItem", "TreeItem", "ListItem", "MenuItem", "Hyperlink", "ComboBox", "Edit"}
SCROLL_TYPES = {"List", "Tree", "Pane", "Group", "Table", "DataGrid"}
HIDDEN_SUBTREES = {"Document", "Edit", "Text", "Custom", "Terminal"}
RESTRICTED_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "openconsole.exe", "windowsterminal.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe", "vivaldi.exe", "msedgewebview2.exe",
    "credentialuibroker.exe", "consent.exe", "logonui.exe", "lockapp.exe", "runas.exe",
}
SYSTEM_PROCESSES = {"systemsettings.exe", "applicationframehost.exe", "taskmgr.exe", "mmc.exe",
                    "control.exe", "securityhealthsystray.exe", "sechealthui.exe", "systemsettingsadminflows.exe"}


@dataclass
class Node:
    runtime_id: tuple
    pid: int
    kind: str
    name: str = ""
    automation_id: str = ""
    class_name: str = ""
    rect: tuple = (0, 0, 0, 0)
    enabled: bool = True
    offscreen: bool = False
    focused: bool = False
    focusable: bool = False
    protected: bool = False
    # Only held within one adapter call/thread; never stored in a snapshot or ticket.
    raw: object = field(default=None, repr=False)

    @property
    def identity(self):
        return (self.runtime_id, self.pid, self.kind, self.name, self.automation_id, self.class_name)


class DesktopController:
    def __init__(self, adapter_factory, clean, sensitive, high_impact, clock=time.monotonic):
        self.adapter_factory = adapter_factory
        self.clean = clean
        self.sensitive = sensitive
        self.high_impact = high_impact
        self.clock = clock
        self.snapshots = OrderedDict()
        self.tickets = OrderedDict()

    def _label(self, label, limit):
        return self.clean(label)[:limit] if not self.sensitive(label) and not SENSITIVE.search(label) else ""

    def _put(self, cache, key, value):
        self._expire(cache)
        cache[key] = (self.clock() + TTL, value)
        while len(cache) > MAX_SNAPSHOTS:
            cache.popitem(last=False)

    def _expire(self, cache):
        while cache and next(iter(cache.values()))[0] <= self.clock():
            cache.popitem(last=False)

    def _get(self, cache, key, error, *, consume=False):
        self._expire(cache)
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{32}", key) or key not in cache:
            raise ValueError(error)
        return (cache.pop(key) if consume else cache[key])[1]

    def _windows(self, adapter):
        refs = {}
        output = []
        foreground = adapter.foreground()
        for handle, pid, started, title, executable, instance in adapter.windows():
            if len(output) >= 50:
                break
            key = str(len(output) + 1)
            if started is not None and instance:
                refs[key] = (handle, pid, started, executable, instance)
            output.append({"window_id": key if key in refs else None, "handle": handle, "pid": pid,
                           "title": self._label(title, 160), "executable": self._label(executable, 80),
                           "active": handle == foreground})
        snapshot = secrets.token_hex(16)
        self._put(self.snapshots, snapshot, ("windows", refs))
        return {"ok": True, "snapshot_id": snapshot, "windows": output,
                "active_window_handle": foreground, "possibly_truncated": len(output) == 50,
                "ui_data_is_untrusted": True}

    def _tree(self, adapter, window, depth, limit):
        root = adapter.root(window)
        foreground = adapter.foreground()
        entries = []
        pending = deque([(iter((root,)), (), None, 0)])
        omitted = False
        deadline = self.clock() + 3
        # Breadth-first with lazy sibling enumeration; no unbounded descendants().
        while pending and self.clock() < deadline:
            iterator, ancestors, parent, level = pending[0]
            node = next(iterator, None)
            if node is None:
                pending.popleft()
                continue
            if len(entries) == limit:
                omitted = True
                break
            lineage = ancestors + (node.identity,)
            key = str(len(entries) + 1)
            entries.append((key, parent, node, lineage))
            if node.protected or node.kind in HIDDEN_SUBTREES or node.pid != window[1] or self._inspect_only(window):
                continue
            if level < depth:
                pending.append((iter(adapter.children(node)), lineage, key, level + 1))
            elif not omitted:
                omitted = adapter.has_children(node)
        return entries, foreground, omitted or bool(pending)

    @staticmethod
    def _inspect_only(window):
        return not window[3] or window[3].lower() in RESTRICTED_PROCESSES

    def _tree_snapshot(self, adapter, window, depth, limit):
        entries, foreground, truncated = self._tree(adapter, window, depth, limit)
        ids = Counter(node.runtime_id for _, _, node, _ in entries)
        snapshot = secrets.token_hex(16)
        refs = {}
        rows = []
        for key, parent, node, lineage in entries:
            if (not self._inspect_only(window) and not node.protected and node.pid == window[1]
                    and all(ancestor[0] for ancestor in lineage) and ids[node.runtime_id] == 1):
                refs[key] = lineage
            rows.append({"element_id": key, "parent_id": parent, "action_target": key in refs,
                         "automation_id": self._label(node.automation_id, 100), "control_type": node.kind,
                         "name": self._label(node.name, 120), "bounding_rectangle": list(node.rect),
                         "enabled": node.enabled, "visible": not node.offscreen, "offscreen": node.offscreen,
                         "focused": foreground == window[0] and node.focused, "protected": node.protected})
        self._put(self.snapshots, snapshot, ("tree", window, depth, limit, refs))
        return {"ok": True, "snapshot_id": snapshot, "elements": rows, "active": foreground == window[0],
                "focused_element_ids": [row["element_id"] for row in rows if row["focused"]],
                "truncated": truncated, "ui_data_is_untrusted": True}

    def _check(self, adapter, window, node, lineage, action):
        if action == "activate":
            return
        labels = [(part[3], part[4], part[5]) for part in lineage]
        if (self._inspect_only(window) or node.protected or node.pid != window[1]
                or not node.enabled or node.offscreen or adapter.foreground() != window[0]):
            raise ValueError("desktop_target_unavailable_or_blocked")
        if any(SENSITIVE.search(value) for group in labels for value in group):
            raise ValueError("desktop_sensitive_target_blocked")
        if any(self.high_impact.search(value) for group in labels for value in group):
            raise ValueError("desktop_high_impact_action_blocked")
        if action in {"focus", "set_text"} and not node.focusable:
            raise ValueError("desktop_target_not_focusable")
        allowed = {
            "focus": NAVIGATION_TYPES, "set_text": {"Edit"}, "select": {"ListItem", "TabItem", "TreeItem"},
            "expand": {"MenuItem", "ComboBox", "TreeItem"}, "collapse": {"MenuItem", "ComboBox", "TreeItem"},
            "scroll_up": SCROLL_TYPES, "scroll_down": SCROLL_TYPES, "invoke": {"Button"},
        }
        if node.kind not in allowed[action]:
            raise ValueError("desktop_control_type_blocked")
        if action == "invoke" and node.name.strip().lower() not in SAFE_INVOKE_LABELS:
            raise ValueError("desktop_button_not_reviewed_navigation")
        if window[3].lower() in SYSTEM_PROCESSES and action not in {"focus", "scroll_up", "scroll_down"}:
            raise ValueError("desktop_system_action_blocked")
        if action == "set_text" and (not node.automation_id or not node.focused):
            raise ValueError("desktop_text_requires_automation_id_and_current_focus")

    def _resolve(self, adapter, snapshot, target):
        if snapshot[0] == "windows":
            window = snapshot[1].get(target)
            if window is None or not adapter.valid(window):
                raise ValueError("desktop_window_unavailable_or_stale")
            return window, None, (), []
        _, window, depth, limit, refs = snapshot
        identity = refs.get(target)
        if identity is None:
            raise ValueError("desktop_element_unavailable_or_stale")
        entries, _, _ = self._tree(adapter, window, depth, limit)
        matches = [(node, lineage) for _, _, node, lineage in entries
                   if node.runtime_id == identity[-1][0]]
        if len(matches) != 1 or matches[0][1] != identity:
            raise ValueError("desktop_element_unavailable_or_stale")
        return window, *matches[0], entries

    def _prepare(self, adapter, snapshot_id, target_id, action):
        if not isinstance(target_id, str) or not target_id.isascii() or not target_id.isdecimal() or len(target_id) > 3:
            raise ValueError("desktop_target_id_invalid")
        if not isinstance(action, str) or action not in ACTIONS:
            raise ValueError("desktop_action_invalid")
        snapshot = self._get(self.snapshots, snapshot_id, "desktop_snapshot_expired_or_unknown")
        if (action == "activate") != (snapshot[0] == "windows"):
            raise ValueError("desktop_action_snapshot_mismatch")
        window, node, lineage, _ = self._resolve(adapter, snapshot, target_id)
        self._check(adapter, window, node, lineage, action)
        nonce = secrets.token_hex(16)
        self._put(self.tickets, nonce, (snapshot_id, target_id, action))
        phrase = f"Approve desktop {nonce}" + (": <exact non-sensitive text>" if action == "set_text" else "")
        return {"ok": True, "approval_required": True, "approval_id": nonce, "action": action,
                "window_handle": window[0], "pid": window[1], "executable": self._label(window[3], 80),
                "target_name": self._label(node.name, 120) if node else None,
                "target_automation_id": self._label(node.automation_id, 100) if node else None,
                "required_user_confirmation": phrase, "ui_data_is_untrusted": True}

    def _act(self, adapter, approval_id, latest_user):
        snapshot_id, target, action = self._get(self.tickets, approval_id, "desktop_approval_expired_or_unknown")
        phrase = f"Approve desktop {approval_id}"
        text = None
        if action == "set_text":
            if not isinstance(latest_user, str) or not latest_user.startswith(phrase + ": "):
                raise ValueError("desktop_exact_user_approval_required")
            text = latest_user[len(phrase) + 2:]
            if (not 1 <= len(text) <= 500 or not text.isprintable() or not text.strip()
                    or SENSITIVE.search(text) or self.clean(text) != text or "://" in text):
                raise ValueError("desktop_input_not_permitted")
        elif latest_user != phrase:
            raise ValueError("desktop_exact_user_approval_required")
        snapshot = self._get(self.snapshots, snapshot_id, "desktop_snapshot_expired_or_unknown")
        window, node, lineage, before = self._resolve(adapter, snapshot, target)
        self._check(adapter, window, node, lineage, action)
        # Revoke all previous UI references before mutation, even if the provider errors.
        self.snapshots.clear()
        self.tickets.clear()
        dispatched = False
        verified = False
        evidence = "postcondition_not_observed"
        try:
            dispatched = True
            state = adapter.perform(window, node, action, text)
            for delay in (0, 0.1, 0.2):
                if delay:
                    time.sleep(delay)
                if action == "invoke":
                    # A generic UI change can be unrelated to the click. Report it as
                    # evidence, not as verification of the button's intended effect.
                    if not adapter.valid(window):
                        break
                    changed = adapter.foreground() != window[0]
                    if not changed:
                        after, _, _ = self._tree(adapter, window, snapshot[2], snapshot[3])
                        changed = self._signature(before) != self._signature(after)
                    if changed:
                        evidence = "ui_state_changed"
                        break
                elif action == "activate":
                    verified = adapter.valid(window) and adapter.foreground() == window[0]
                    evidence = "foreground_window_matches" if verified else evidence
                else:
                    current_window, current, current_lineage, _ = self._resolve(adapter, snapshot, target)
                    self._check(adapter, current_window, current, current_lineage, action)
                    verified = adapter.verify(current, action, text, state)
                    evidence = "control_postcondition_matches" if verified else evidence
                if verified:
                    break
        except Exception:
            # Provider messages can contain field contents. Never echo them or retry a write.
            evidence = "action_or_verification_unavailable"
        try:
            if snapshot[0] == "tree" and adapter.valid(window):
                observed = self._tree_snapshot(adapter, window, snapshot[2], snapshot[3])
            else:
                observed = self._windows(adapter)
        except Exception:
            observed = None
        return {"ok": verified, "verified": verified, "action_attempted": dispatched, "evidence": evidence,
                "state": observed, **({"error": "desktop_action_not_verified"} if not verified else {})}

    @staticmethod
    def _signature(entries):
        return [(parent, node.identity, node.enabled, node.offscreen, node.focused, node.rect)
                for _, parent, node, _ in entries]

    def call(self, name, args, latest_user=""):
        try:
            adapter = self.adapter_factory()
            if name == "computer_desktop_windows" and not args:
                return self._windows(adapter)
            if name == "computer_desktop_tree" and set(args) == {"snapshot_id", "window_id", "depth", "limit"}:
                depth, limit = args["depth"], args["limit"]
                if (type(depth) is not int or not 0 <= depth <= 10 or type(limit) is not int or not 1 <= limit <= 100
                        or not isinstance(args["window_id"], str)):
                    raise ValueError("desktop_tree_arguments_invalid")
                snapshot = self._get(self.snapshots, args["snapshot_id"], "desktop_snapshot_expired_or_unknown")
                if snapshot[0] != "windows":
                    raise ValueError("desktop_window_snapshot_required")
                window, _, _, _ = self._resolve(adapter, snapshot, args["window_id"])
                return self._tree_snapshot(adapter, window, depth, limit)
            if name == "computer_desktop_prepare" and set(args) == {"snapshot_id", "target_id", "action"}:
                return self._prepare(adapter, **args)
            if name == "computer_desktop_act" and set(args) == {"approval_id"}:
                return self._act(adapter, args["approval_id"], latest_user)
            raise ValueError("desktop_arguments_invalid")
        except ValueError as exc:
            # Return only our stable machine-readable codes, not raw provider errors.
            code = str(exc)
            return {"ok": False, "error": code if re.fullmatch(r"desktop_[a-z_]+", code) else "desktop_unavailable"}
        except Exception:
            return {"ok": False, "error": "desktop_unavailable"}


# UI Automation COM objects live on one dedicated thread, including their creation.
# The existing shared runtime serializes calls; the worker also protects direct callers.
WORKER = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cybernova-uia")
