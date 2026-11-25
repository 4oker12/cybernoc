"""Patchright-first synchronous Chromium backend selection for Cybernova.

Patchright is the default. Playwright is retained as a controlled fallback and
can be selected explicitly with CYBERNOVA_BROWSER_BACKEND=playwright.
"""
from __future__ import annotations

from importlib import import_module
import os


def backend_order() -> tuple[str, ...]:
    requested = os.environ.get("CYBERNOVA_BROWSER_BACKEND", "patchright").strip().lower()
    if requested in {"", "patchright", "auto"}:
        return ("patchright", "playwright")
    if requested == "playwright":
        return ("playwright",)
    raise ValueError("browser_backend_invalid")


def launch_with_backend(launcher):
    """Start an engine and run its Chromium launcher, falling back once.

    Returns (runtime, backend_name, launch_result, fallback_reason).
    Only Patchright import/start/launch failures trigger the Playwright fallback.
    The exception message is never persisted because it can contain local paths.
    """
    fallback_reason = None
    for backend in backend_order():
        try:
            sync_playwright = import_module(f"{backend}.sync_api").sync_playwright
            runtime = sync_playwright().start()
        except Exception as exc:
            if backend == "patchright":
                fallback_reason = type(exc).__name__
                continue
            raise RuntimeError("browser_backend_unavailable:playwright") from None

        try:
            result = launcher(runtime)
            return runtime, backend, result, fallback_reason
        except Exception as exc:
            try:
                runtime.stop()
            except Exception:
                pass
            if backend == "patchright":
                fallback_reason = type(exc).__name__
                continue
            raise

    raise RuntimeError("browser_backend_unavailable")
