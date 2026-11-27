"""Guard the local Windows/Linux launcher against accidental Vast coupling."""
from pathlib import Path
from unittest.mock import patch
import importlib.util
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console.portable_runtime import MODULES

SPEC = importlib.util.spec_from_file_location("cybernova_native_local_test", ROOT / "portable" / "native.py")
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


class LocalOnlyLauncherTests(unittest.TestCase):
    def test_default_local_configuration_never_requires_vast(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "data"
            native.init(data, "ollama", "cybernova-local:test")
            values = native._load(data)
            self.assertEqual(values["CYBERNOVA_LLM_PROVIDER"], "ollama")
            self.assertEqual(values["CYBERNOVA_OLLAMA_URL"],
                             "http://127.0.0.1:11434/api/chat")
            self.assertEqual(values["CYBERNOVA_MCP_URL"], "http://127.0.0.1:18792/mcp")
            self.assertEqual(values["CYBERNOVA_ACCESS_HOST"], "127.0.0.1")
            self.assertEqual(values["CYBERNOVA_LLM_BASE_URL"], "")
            self.assertFalse(any("VAST" in key for key in values))
            python = native._python(data)
            python.parent.mkdir(parents=True, exist_ok=True)
            python.touch()
            with patch.object(native.subprocess, "call", return_value=0) as start:
                self.assertEqual(native.run(data), 0)
            command = start.call_args.args[0]
            env = start.call_args.kwargs["env"]
            self.assertEqual(command[-2:], ["-m", "console.portable_runtime"])
            self.assertEqual(env["CYBERNOVA_LLM_PROVIDER"], "ollama")
            self.assertEqual(env["CYBERNOVA_MCP_URL"], "http://127.0.0.1:18792/mcp")

    def test_supervisor_starts_local_components_not_remote_tunnel_clients(self):
        self.assertEqual(MODULES, (
            "console.portable_tool_gateway",
            "console.communication_mcp",
            "console.server",
            "console.tunnel_access",
        ))
        self.assertFalse(any("vast" in module.lower() or "ssh" in module.lower()
                             for module in MODULES))


if __name__ == "__main__":
    unittest.main()
