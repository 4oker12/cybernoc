"""Opt-in read-only smoke: run on an interactive Windows desktop with pywinauto."""
import platform
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.gpt_tool_runtime import GPTToolRuntime


def run():
    if platform.system() != "Windows":
        raise SystemExit("Run this probe on an interactive Windows desktop")
    runtime = GPTToolRuntime()
    try:
        def call(name, args):
            result, failed = runtime.call(name, args, enabled_groups=["computer"])
            if failed or not result.get("ok"):
                raise AssertionError(f"{name}: {result.get('error', 'failed')}")
            return result

        inventory = call("computer_process_inventory", {"after_pid": -1, "limit": 10, "listeners": True})
        if not inventory["processes"]:
            raise AssertionError("No processes discovered")
        windows = call("computer_desktop_windows", {})
        active = next((row for row in windows["windows"] if row["active"] and row["window_id"]), None)
        if not active:
            raise AssertionError("No foreground window accessible from this session")
        tree = call("computer_desktop_tree", {"snapshot_id": windows["snapshot_id"],
                                              "window_id": active["window_id"], "depth": 2, "limit": 20})
        if not tree["elements"] or tree["elements"][0]["parent_id"] is not None:
            raise AssertionError("No UI Automation root")
        print(f"PASS: {len(inventory['processes'])} processes; listener status: {inventory['listener_status']}; "
              f"{len(windows['windows'])} windows; {len(tree['elements'])} UIA nodes (root-only is valid)")
    finally:
        runtime.close()


if __name__ == "__main__":
    run()
