"""Read-only MCP stdio bridge; connect only via authenticated Secure MCP Tunnel."""
from typing import Literal
try:
 from mcp.server.mcpserver import MCPServer
except ImportError:
 from mcp.server.fastmcp import FastMCP as MCPServer
from core import health,run_diagnostic
mcp=MCPServer("CyberSec Vast Bridge")
@mcp.tool()
def bridge_health()->dict:
 return health()
@mcp.tool()
def vast_diagnostic(kind:Literal["gpu","disk","memory","python","torch_cuda","ollama"])->dict:
 return run_diagnostic(kind)
if __name__=="__main__":
 mcp.run(transport="stdio")
