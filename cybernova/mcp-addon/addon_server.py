"""Launch the original CyberSec Vast MCP server with extra deployment tools.

The original server.py is imported intact (not edited); every existing tool
remains registered. The wrapper then adds deployment tools to the same instance.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
import sys

ORIGINAL = Path("/workspace/cybersec-vast-mcp-v02/server.py")
HERE = Path(__file__).resolve().parent

def load_server():
    if not ORIGINAL.is_file():
        raise RuntimeError("Original MCP server missing")
    sys.path.insert(0,str(ORIGINAL.parent))
    sys.path.insert(0,str(HERE))
    spec=importlib.util.spec_from_file_location("cybersec_vast_original",ORIGINAL)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load original MCP server")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server=getattr(module,"mcp",None)
    if server is None or not callable(getattr(server,"tool",None)):
        raise RuntimeError("Original MCP server has no compatible mcp object")
    from registry import register
    register(server)
    from events_bridge import register as register_events
    register_events(server)
    return server

if __name__=="__main__":
    load_server().run(transport="stdio")
