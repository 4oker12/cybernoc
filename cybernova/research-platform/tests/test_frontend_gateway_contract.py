"""Keep the browser's literal HTTP calls, Console routes and gateway in sync."""
import ast
import re
import unittest
from pathlib import Path

from console.tunnel_access import ALLOWED_GET, ALLOWED_POST, allowed_path


STATIC = Path(__file__).resolve().parents[1] / "console" / "static"
SERVER = STATIC.parent / "server.py"
CALL = re.compile(r"\b(?P<function>fetch|requestJson)\s*\(\s*['\"](?P<path>/api/[^'\"?]+)")
METHOD = re.compile(r"\bmethod\s*:\s*['\"](?P<method>GET|POST)['\"]")
LINK = re.compile(r"\b(?:href|src)=['\"](?P<path>/api/[^'\"?]+)")


def call_body(source, opening):
    """Return one JS call without accidentally reading the next request's method."""
    depth = 0
    quote = None
    escaped = False
    for index in range(opening, len(source)):
        char = source[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return source[opening:index + 1]
    raise AssertionError("Unclosed JavaScript HTTP call")


class FrontendGatewayContractTests(unittest.TestCase):
    @staticmethod
    def console_routes():
        routes = set()
        for node in ast.walk(ast.parse(SERVER.read_text(encoding="utf-8"))):
            for decorator in getattr(node, "decorator_list", ()):
                if (isinstance(decorator, ast.Call) and
                        isinstance(decorator.func, ast.Attribute) and
                        isinstance(decorator.func.value, ast.Name) and
                        decorator.func.value.id == "app" and
                        decorator.func.attr in {"get", "post"} and
                        decorator.args and isinstance(decorator.args[0], ast.Constant)):
                    routes.add((decorator.args[0].value, decorator.func.attr.upper()))
        return routes

    def test_every_browser_call_is_registered_and_allowed_with_its_method(self):
        routes = self.console_routes()
        calls = set()
        for path in STATIC.glob("*.js"):
            source = path.read_text(encoding="utf-8")
            for match in CALL.finditer(source):
                if match["function"] == "requestJson":
                    method = "POST"
                else:
                    body = call_body(source, source.index("(", match.start()))
                    found = METHOD.search(body)
                    method = found["method"] if found else "GET"
                calls.add((match["path"], method))
        for match in LINK.finditer((STATIC / "index.html").read_text(encoding="utf-8")):
            calls.add((match["path"], "GET"))
        self.assertGreater(len(calls), 25, "Browser request extraction stopped working")
        for route, method in sorted(calls):
            with self.subTest(route=route, method=method):
                if route != "/api/diagnostics/export":  # Served inside the gateway.
                    self.assertIn((route, method), routes)
                self.assertTrue(allowed_path(route, method))

    def test_gateway_does_not_expose_unregistered_api_or_wrong_methods(self):
        routes = self.console_routes()
        for method, paths in (("GET", ALLOWED_GET), ("POST", ALLOWED_POST)):
            for path in paths:
                with self.subTest(path=path, method=method):
                    if path == "/api/diagnostics/export":  # Served inside the gateway.
                        continue
                    self.assertIn((path, method), routes)
        for path in ("/api/siwc/tokens", "/api/admin", "/mcp"):
            self.assertFalse(allowed_path(path, "GET"))
            self.assertFalse(allowed_path(path, "POST"))


if __name__ == "__main__":
    unittest.main()
