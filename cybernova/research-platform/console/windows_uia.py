"""Windows UIA transport, imported only on the desktop worker."""
from __future__ import annotations

import ntpath

try:
    from .desktop_control import Node, SENSITIVE, RESTRICTED_PROCESSES, HIDDEN_SUBTREES
except ImportError:
    from desktop_control import Node, SENSITIVE, RESTRICTED_PROCESSES, HIDDEN_SUBTREES

# UIAutomation ScrollAmount: NoAmount, SmallDecrement, SmallIncrement.
NO_SCROLL, SMALL_UP, SMALL_DOWN = 2, 1, 4


class WindowsUIA:
    def __init__(self, processes):
        import win32gui
        import win32process
        from pywinauto.uia_defines import IUIA, get_elem_interface
        import comtypes
        import sys
        # The initial import of pywinauto chooses the COM model. Join that
        # model on this worker as well, including when already imported elsewhere.
        comtypes.CoInitializeEx(sys.coinit_flags)
        self.gui = win32gui
        self.process = win32process
        self.processes = processes
        # Do not reuse pywinauto's COM singleton across threads: the legacy
        # tools may already have initialized it in a different apartment.
        definitions = IUIA()
        client = definitions.ui_automation_client
        self.control_types = definitions.known_control_type_ids
        clsid = comtypes.GUID("{FF48DBA4-60EF-4201-AA87-54103EEF594E}")  # CUIAutomation
        self.api = comtypes.CoCreateInstance(clsid, interface=client.IUIAutomation,
                                             clsctx=comtypes.CLSCTX_INPROC_SERVER)
        # Providers are out-of-process and can be slow. UIAutomation2 is best effort;
        # not all OS/typelib combinations expose it.
        from comtypes import COMError
        try:
            timeouts = self.api.QueryInterface(client.IUIAutomation2)
            timeouts.ConnectionTimeout = 1000
            timeouts.TransactionTimeout = 2000
        except (AttributeError, COMError):
            pass
        self.walker = self.api.ControlViewWalker
        self.pattern = get_elem_interface
        self.foreground = win32gui.GetForegroundWindow

    def _identity(self, handle):
        if (not self.gui.IsWindow(handle) or not self.gui.IsWindowVisible(handle)
                or self.gui.GetAncestor(handle, 2) != handle):  # GA_ROOT
            raise ValueError("desktop_window_unavailable_or_stale")
        _, pid = self.process.GetWindowThreadProcessId(handle)
        started, executable = None, ""
        try:
            proc = self.processes.Process(pid)
            started = proc.create_time()
            executable = ntpath.basename(proc.exe())
            if not proc.is_running():
                raise ValueError("desktop_window_unavailable_or_stale")
        except self.processes.Error:
            pass
        return handle, pid, started, executable

    def windows(self):
        handles = []
        self.gui.EnumWindows(lambda handle, _: handles.append(handle) or True, None)
        active = self.foreground()
        for handle in dict.fromkeys([active, *handles]):
            try:
                handle, pid, started, exe = self._identity(handle)
                title = self.gui.GetWindowText(handle) if exe.lower() not in RESTRICTED_PROCESSES and exe else ""
                if title or handle == active or exe.lower() in RESTRICTED_PROCESSES:
                    yield handle, pid, started, title, exe
            except (ValueError, self.gui.error):
                continue

    def valid(self, window):
        try:
            return self._identity(window[0]) == window
        except (ValueError, self.gui.error):
            return False

    def root(self, window):
        if not self.valid(window):
            raise ValueError("desktop_window_unavailable_or_stale")
        raw = self.api.ElementFromHandle(window[0])
        return self._node(raw, window[1], root=True, inspect_only=(
            not window[3] or window[3].lower() in RESTRICTED_PROCESSES))

    def _node(self, raw, owner_pid, *, root=False, inspect_only=False):
        # Read password state before names or other provider-supplied strings. A failed
        # property read propagates; it must never be treated as a non-password element.
        pid = raw.CurrentProcessId
        protected = bool(raw.CurrentIsPassword) or pid != owner_pid or inspect_only
        kind = self.control_types.get(raw.CurrentControlType, "Unknown")
        automation_id, class_name, name = "", "", ""
        if not protected:
            automation_id = raw.CurrentAutomationId or ""
            class_name = raw.CurrentClassName or ""
            protected = bool(SENSITIVE.search(automation_id) or SENSITIVE.search(class_name))
            if not protected and kind == "Edit":
                # Do not read Edit Name (some providers expose the value as Name).
                label = raw.CurrentLabeledBy
                if (label and not label.CurrentIsPassword and label.CurrentProcessId == owner_pid
                        and self.control_types.get(label.CurrentControlType) == "Text"):
                    label_name = label.CurrentName or ""
                    protected = bool(SENSITIVE.search(label_name))
                    if not protected:
                        name = label_name
            elif not protected and (root or kind not in HIDDEN_SUBTREES):
                name = raw.CurrentName or ""
                protected = bool(SENSITIVE.search(name))
        rect = raw.CurrentBoundingRectangle
        return Node(runtime_id=tuple(raw.GetRuntimeId() or ()), pid=pid, kind=kind,
                    name="" if protected else name, automation_id="" if protected else automation_id,
                    class_name="" if protected else class_name,
                    rect=(rect.left, rect.top, rect.right, rect.bottom), enabled=bool(raw.CurrentIsEnabled),
                    offscreen=bool(raw.CurrentIsOffscreen), focused=bool(raw.CurrentHasKeyboardFocus),
                    focusable=bool(raw.CurrentIsKeyboardFocusable), protected=protected, raw=raw)

    def children(self, node):
        child = self.walker.GetFirstChildElement(node.raw)
        while child:
            yield self._node(child, node.pid)
            child = self.walker.GetNextSiblingElement(child)

    def perform(self, window, node, action, text):
        if not self.valid(window):
            raise ValueError("desktop_window_unavailable_or_stale")
        if action == "activate":
            if self.gui.IsIconic(window[0]):
                self.gui.ShowWindow(window[0], 9)  # SW_RESTORE
            self.gui.SetForegroundWindow(window[0])
            return None
        raw = node.raw
        if (self.foreground() != window[0] or raw.CurrentIsPassword or not raw.CurrentIsEnabled
                or raw.CurrentIsOffscreen):
            raise ValueError("desktop_target_changed")
        current = self._node(raw, window[1])
        if current.protected or current.identity != node.identity:
            raise ValueError("desktop_target_changed")
        if action == "focus":
            raw.SetFocus()
        elif action == "set_text":
            field = self.pattern(raw, "Value")
            if field.CurrentIsReadOnly or raw.CurrentIsPassword or not raw.CurrentHasKeyboardFocus:
                raise ValueError("desktop_field_not_writable")
            field.SetValue(text)
        elif action == "select":
            self.pattern(raw, "SelectionItem").Select()
        elif action in {"expand", "collapse"}:
            pattern = self.pattern(raw, "ExpandCollapse")
            (pattern.Expand if action == "expand" else pattern.Collapse)()
        elif action in {"scroll_up", "scroll_down"}:
            pattern = self.pattern(raw, "Scroll")
            if not pattern.CurrentVerticallyScrollable:
                raise ValueError("desktop_not_scrollable")
            before = pattern.CurrentVerticalScrollPercent
            pattern.Scroll(NO_SCROLL, SMALL_UP if action == "scroll_up" else SMALL_DOWN)
            return before
        elif action == "invoke":
            self.pattern(raw, "Invoke").Invoke()
        return None

    def verify(self, node, action, text, before):
        raw = node.raw
        if raw.CurrentIsPassword:
            return False
        if action == "focus":
            return bool(raw.CurrentHasKeyboardFocus)
        if action == "set_text":
            # Compare in memory only, on the freshly revalidated, non-password target.
            return self.pattern(raw, "Value").CurrentValue == text
        if action == "select":
            return bool(self.pattern(raw, "SelectionItem").CurrentIsSelected)
        if action in {"expand", "collapse"}:
            return self.pattern(raw, "ExpandCollapse").CurrentExpandCollapseState == (1 if action == "expand" else 0)
        if action in {"scroll_up", "scroll_down"}:
            after = self.pattern(raw, "Scroll").CurrentVerticalScrollPercent
            return after != -1 and (after < before if action == "scroll_up" else after > before)
        return False
