"""Shared operator preflight rules for DeepSeek/Qwen and local Account GPT.

The repository-root AGENTS.md is the canonical, human-readable contract.
This bounded excerpt is injected into both runtime model adapters.
No network access and no user secrets are read by this module.
"""
from __future__ import annotations

from pathlib import Path
import re


FALLBACK = """
CYBERNOVA OPERATING RULES:
- ChatGPT in the user's main project conversation is the principal coordinator,
  architect and reviewer. The local DeepSeek/Qwen model is the research and
  execution agent. Account GPT inside the local UI is a separate session unless
  explicitly connected; never assume shared chat history or tools.
- Before update/install/restart/listener: identify Windows CMD context,
  repository branch and clean status; inspect listening ports and PID owners.
- Never kill all Python/processes or remove/reset files to fix conflicts.
  On a port conflict stop, identify the owner, and request approval for any
  targeted shutdown. Prefer Ctrl+C in the existing runtime console.
- User commands must be valid Windows CMD, grouped into one copy-ready block
  with numbered stages and a clear failure stage; do not mix shell syntaxes.
- Only fast-forward Git updates from a verified origin; preserve local edits.
- Current deployment is the local laptop, NOT Vast. Historical names do not
  prove an active Vast connection.
- Distinguish code in GitHub, local installed revision, running listeners,
  successful HTTP responses, and end-to-end functional verification.
"""


def load_operational_contract() -> str:
    """Load bounded sections of AGENTS.md; always retain a safe fallback.

    If packaged without the repository root, the fallback remains in force.
    File content is only read from the exact expected root, not from the cwd.
    """
    try:
        root = Path(__file__).resolve().parents[3]
        path = root / "AGENTS.md"
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 30000:
            return FALLBACK.strip()
        source = path.read_text(encoding="utf-8")
        matches = list(re.finditer(r"(?m)^## ([0-9]+)\. [^\n]+$", source))
        sections = []
        for index, match in enumerate(matches):
            section_no = int(match.group(1))
            if section_no not in (1, 2, 3, 4, 6):
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
            sections.append(source[match.start():end].strip())
        if not sections:
            return FALLBACK.strip()
        # Keep prompt size bounded for latency and token consumption.
        return (FALLBACK.strip() + "\n\nREPOSITORY POLICY:\n" +
                "\n\n".join(sections))[:8500]
    except (OSError, ValueError, IndexError, UnicodeError):
        return FALLBACK.strip()


OPERATIONAL_CONTRACT = load_operational_contract()
