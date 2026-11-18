"""Cybernova first-party local browser chat console.

Run only on loopback, reached via authenticated SSH port forwarding.
No reverse proxy exposure, signup, credentials, database or production access.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
from threading import RLock
import time
from urllib import request, error, parse

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

try:
    from .agent import Agent, MCPClient, MODEL, OLLAMA_URL
    from .followups import generate_followups
except ImportError:
    from agent import Agent, MCPClient, MODEL, OLLAMA_URL
    from followups import generate_followups

ROOT = Path(__file__).resolve().parent
MAX_SESSIONS = 24
SESSION_TTL_SECONDS = 7200
MAX_HISTORY = 16
sessions: OrderedDict[str, dict] = OrderedDict()
sessions_lock = RLock()
agent = Agent()
app = FastAPI(title="Cybernova Console", version="0.1.0", docs_url=None, redoc_url=None,
              openapi_url=None)

ALLOWED_HOSTS = frozenset({"127.0.0.1:18794", "localhost:18794"})


@app.middleware("http")
async def localhost_only(request: Request, call_next):
    # Binding to 127.0.0.1 is mandatory. Header validation also reduces
    # browser-based localhost rebinding and CSRF from hostile public pages.
    host = request.headers.get("host", "").lower()
    if host not in ALLOWED_HOSTS:
        return JSONResponse({"detail": "invalid_host"}, status_code=403)
    origin = request.headers.get("origin", "")
    if origin and origin.lower().rstrip("/") not in {
            "http://127.0.0.1:18794", "http://localhost:18794"}:
        return JSONResponse({"detail": "invalid_origin"}, status_code=403)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and \
       not request.headers.get("content-type", "").lower().startswith("application/json"):
        return JSONResponse({"detail": "json_only"}, status_code=415)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'none'"
    )
    return response


class ChatRequest(BaseModel):
    session_id: str | None = Field(default=None, min_length=16, max_length=100)
    message: str = Field(min_length=1, max_length=10000)
    public_get: bool = False
    force_tools: bool = False


class ResetRequest(BaseModel):
    session_id: str | None = None


class FollowupsRequest(BaseModel):
    session_id: str = Field(min_length=16, max_length=100)
    turn: int = Field(ge=1)



def _session(session_id: str | None) -> tuple[str, dict]:
    now = time.monotonic()
    with sessions_lock:
        for key in list(sessions):
            if now - sessions[key]["last"] > SESSION_TTL_SECONDS:
                sessions.pop(key, None)
        if session_id and session_id in sessions:
            session = sessions[session_id]
            session["last"] = now
            sessions.move_to_end(session_id)
            return session_id, session
        key = secrets.token_urlsafe(24)
        session = {"last": now, "history": [], "lock": RLock(), "turns": 0,
                   "followups_turn": None, "followups": []}
        sessions[key] = session
        while len(sessions) > MAX_SESSIONS:
            sessions.popitem(last=False)
        return key, session


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html", media_type="text/html")


@app.get("/static/styles.css")
def styles():
    return FileResponse(ROOT / "static" / "styles.css", media_type="text/css")


@app.get("/static/app.js")
def javascript():
    return FileResponse(ROOT / "static" / "app.js", media_type="text/javascript")


def _ollama_health() -> bool:
    parsed = parse.urlsplit(OLLAMA_URL)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1"}:
        return False
    try:
        opener = request.build_opener(request.ProxyHandler({}))
        with opener.open("http://" + parsed.netloc + "/api/tags", timeout=2) as r:
            return r.status == 200
    except (OSError, TimeoutError, error.URLError):
        return False


@app.get("/api/status")
def status():
    try:
        mcp = MCPClient()
        tools = [t["name"] for t in mcp.initialize()]
        mcp_ok = True
    except Exception:
        tools, mcp_ok = [], False
    return {
        "model": MODEL,
        "ollama_ready": _ollama_health(),
        "mcp_ready": mcp_ok,
        "tools": tools,
        "public_get_default": False,
        "mode": "loopback_only",
        "version": "0.1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/chat")
def chat(payload: ChatRequest):
    sid, state = _session(payload.session_id)
    # Prevent overlapping turns in one session from corrupting model history.
    with state["lock"]:
        try:
            outcome = agent.run(
                state["history"], payload.message,
                public_get=payload.public_get,
                force_tools=payload.force_tools,
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail="agent_failed: " +
                                type(exc).__name__) from exc
        state["history"].append({"role": "user", "content": payload.message[:10000]})
        state["history"].append({"role": "assistant", "content": outcome["answer"][:16000]})
        state["history"] = state["history"][-MAX_HISTORY:]
        state["turns"] += 1
    return {"session_id": sid, "turn": state["turns"], **outcome}


@app.post("/api/followups")
def followups(payload: FollowupsRequest):
    """Suggest questions based on this session's last real Qwen reply.

    Inference is separate from /api/chat, so the main answer appears first.
    No tools, network target access, execution, or changes to permissions.
    """
    with sessions_lock:
        state = sessions.get(payload.session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="session_not_found")
    with state["lock"]:
        if state["turns"] != payload.turn:
            raise HTTPException(status_code=409, detail="stale_turn")
        if state.get("followups_turn") == payload.turn:
            return {"turn": payload.turn, "questions": state["followups"],
                    "source": "qwen", "cached": True}
        history = [dict(item) for item in state["history"][-6:]]
    try:
        questions = generate_followups(history)
    except Exception:
        # Suggestions are optional: never break chat or invent fallback text.
        return {"turn": payload.turn, "questions": [], "source": "unavailable"}
    with state["lock"]:
        if state["turns"] != payload.turn:
            raise HTTPException(status_code=409, detail="stale_turn")
        state["followups_turn"] = payload.turn
        state["followups"] = questions
    return {"turn": payload.turn, "questions": questions, "source": "qwen",
            "cached": False}


@app.post("/api/reset")
def reset(payload: ResetRequest):
    with sessions_lock:
        if payload.session_id in sessions:
            sessions.pop(payload.session_id)
    return {"ok": True, "message": "Session cleared"}


if __name__ == "__main__":
    import uvicorn
    # Never listen on 0.0.0.0: user accesses via SSH loopback forwarding only.
    uvicorn.run(app, host="127.0.0.1", port=18794, access_log=False)
