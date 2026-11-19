"""Cybernova first-party local browser chat console.

Run only on loopback, reached via authenticated SSH port forwarding.
No reverse proxy exposure, signup, credentials, database or production access.
"""
from __future__ import annotations

from collections import OrderedDict
from contextlib import asynccontextmanager
from functools import lru_cache
from datetime import datetime, timezone
import json
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
    from .tool_policy import REVIEWED_TOOLS
    from .traffic_intelligence import analyze_har, analyze_js, TrafficError
    from .traffic_tools import TrafficToolClient, LOCAL_TOOLS, MAX_ARTIFACTS
    from .domain_intelligence import PARSERS, DomainError
    from .domain_tools import DOMAIN_TOOLS
    from .scoped_network_tools import SCOPED_TOOLS
    from .lab_scanners import SCANNER_TOOLS, inventory
    from .communication import CommunicationStore, CommunicationError
    from .communication_tools import CommunicationToolClient, COMMUNICATION_TOOLS
    from .communication_worker import CommunicationWorker
    from .evidence import EvidenceJournal
except ImportError:
    from agent import Agent, MCPClient, MODEL, OLLAMA_URL
    from followups import generate_followups
    from tool_policy import REVIEWED_TOOLS
    from traffic_intelligence import analyze_har, analyze_js, TrafficError
    from traffic_tools import TrafficToolClient, LOCAL_TOOLS, MAX_ARTIFACTS
    from domain_intelligence import PARSERS, DomainError
    from domain_tools import DOMAIN_TOOLS
    from scoped_network_tools import SCOPED_TOOLS
    from lab_scanners import SCANNER_TOOLS, inventory
    from communication import CommunicationStore, CommunicationError
    from communication_tools import CommunicationToolClient, COMMUNICATION_TOOLS
    from communication_worker import CommunicationWorker
    from evidence import EvidenceJournal

ROOT = Path(__file__).resolve().parent
MAX_SESSIONS = 24
SESSION_TTL_SECONDS = 7200
MAX_HISTORY = 16
sessions: OrderedDict[str, dict] = OrderedDict()
sessions_lock = RLock()
agent = Agent()


@lru_cache(maxsize=1)
def communication_store() -> CommunicationStore:
    return CommunicationStore()


@asynccontextmanager
async def lifespan(app):
    worker = None
    if os.environ.get("CYBERNOVA_COMM_WORKER", "1") == "1":
        worker = CommunicationWorker(communication_store())
        worker.start()
    try:
        yield
    finally:
        if worker is not None:
            worker.stop()


app = FastAPI(title="Cybernova Console", version="0.2.0",
              docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)

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


class ResetRequest(BaseModel):
    session_id: str | None = None


class FollowupsRequest(BaseModel):
    session_id: str = Field(min_length=16, max_length=100)
    turn: int = Field(ge=1)


class ImportRequest(BaseModel):
    session_id: str | None = Field(default=None, min_length=16, max_length=100)
    kind: str = Field(pattern="^(har|javascript|openapi|log|config|python|dependencies|tls|pcap)$")
    content: str = Field(min_length=1, max_length=6_000_000)


class ApprovalRequest(BaseModel):
    session_id: str = Field(min_length=16, max_length=100)
    request_id: str = Field(min_length=16, max_length=100)
    decision: str = Field(pattern="^(approve|deny)$")



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
                   "followups_turn": None, "followups": [], "pending_approvals": {},
                   "traffic_artifacts": {}, "task_id": None}
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
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "ollama"}:
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
        remote_tools = [t["name"] for t in mcp.initialize()]
        mcp_ok = True
    except Exception:
        remote_tools, mcp_ok = [], False
    tools = remote_tools + [t["name"] for t in LOCAL_TOOLS + DOMAIN_TOOLS + SCOPED_TOOLS + SCANNER_TOOLS + COMMUNICATION_TOOLS]
    return {
        "model": MODEL,
        "ollama_ready": _ollama_health() if os.environ.get("CYBERNOVA_LLM_PROVIDER", "ollama") == "ollama" else False,
        "model_provider": os.environ.get("CYBERNOVA_LLM_PROVIDER", "ollama"),
        "model_remote_configured": os.environ.get("CYBERNOVA_LLM_PROVIDER") == "openai_compatible",
        "mcp_ready": mcp_ok,
        "tools": tools,
        "auto_executable": sorted(set(tools) & REVIEWED_TOOLS),
        "others_require_approval": sorted(set(tools) - REVIEWED_TOOLS),
        "tools_selection": "automatic_qwen",
        "http_get": "available_for_preconfigured_mcp_hosts_only",
        "traffic_intelligence": "offline_multi_domain_analysis",
        "scoped_network_checks": "DNS A/AAAA and verified TLS 443",
        "lab_scanners": inventory(),
        "import_kinds": ["har", "javascript"] + sorted(PARSERS),
        "communication": {"enabled": True, "durable_tasks": True,
                          "review_inbox": True, "qwen_worker": os.environ.get("CYBERNOVA_COMM_WORKER", "1") == "1",
                          "chatgpt_mcp": "separate_service_not_yet_connected"},
        "mode": "loopback_only",
        "version": "0.1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/import")
def import_artifact(payload: ImportRequest):
    """Parse user-supplied own HAR/JS into memory, permanently discard raw text.

    No body values, passwords, cookies or request payloads are sent to Qwen.
    This endpoint never performs remote HTTP or replays captured operations.
    """
    sid, state = _session(payload.session_id)
    with state["lock"]:
        if state["task_id"] is None:
            state["task_id"] = communication_store().create_task(
                "Импорт " + payload.kind, origin="human"
            )["task_id"]
        if len(state["traffic_artifacts"]) >= MAX_ARTIFACTS:
            raise HTTPException(status_code=409, detail="artifact_limit_reached")
        try:
            if payload.kind == "har":
                artifact = analyze_har(payload.content)
            elif payload.kind == "javascript":
                artifact = analyze_js(payload.content)
            else:
                artifact = PARSERS[payload.kind](payload.content)
        except (TrafficError, DomainError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)[:160]) from exc
        artifact_id = "ti_" + secrets.token_urlsafe(12)
        state["traffic_artifacts"][artifact_id] = artifact
        summary = {
            "artifact_id": artifact_id,
            "kind": artifact["kind"],
            "source_sha256": artifact["source_sha256"],
            "requests": artifact.get("requests_analyzed", 0),
            "endpoints": len(artifact.get("endpoints", [])),
            "js_api_paths": len(artifact.get("api_paths", [])),
            "observations": len(artifact.get("observations", [])),
            "raw_data_retained": False,
        }
        # Add only sanitized metadata to next Qwen context, never the capture.
        state["history"].append({
            "role": "user",
            "content": "Локально импортирован мой исследовательский артефакт: "
                       + json.dumps(summary, ensure_ascii=False)
                       + ". Для исследования доступны traffic_* и research_* инструменты.",
        })
        state["history"].append({
            "role": "assistant",
            "content": "Импорт обработан офлайн. Сохраняются только извлечённые "
                       "метаданные и гипотезы; сырые данные удалены. Жду задачу.",
        })
        state["history"] = state["history"][-MAX_HISTORY:]
        communication_store().append(
            state["task_id"], "controller", "system",
            "Артефакт импортирован офлайн: " + json.dumps(summary, ensure_ascii=False),
        )
    return {"session_id": sid, "task_id": state["task_id"], **summary}


@app.post("/api/chat")
def chat(payload: ChatRequest):
    sid, state = _session(payload.session_id)
    # Prevent overlapping turns in one session from corrupting model history.
    with state["lock"]:
        store = communication_store()
        if state["task_id"] is None:
            state["task_id"] = store.create_task(
                payload.message.strip()[:150], origin="human",
            )["task_id"]
        task_id = state["task_id"]
        # Include ChatGPT feedback and background Qwen results which arrived
        # while the browser was open, instead of using stale in-memory history.
        previous = store.read_dialog(task_id, limit=100)["messages"]
        persisted_history = []
        for message in previous:
            if message["actor"] == "controller" and message["kind"] == "system":
                persisted_history.append({"role": "user", "content": message["body"][:1500]})
            elif message["actor"] in {"human", "chatgpt"} and message["kind"] in {
                    "instruction", "feedback"}:
                persisted_history.append({"role": "user", "content":
                                          "[" + message["actor"] + "] " + message["body"]})
            elif message["actor"] == "qwen" and message["kind"] == "result":
                persisted_history.append({"role": "assistant", "content": message["body"]})
        if persisted_history:
            state["history"] = persisted_history[-MAX_HISTORY:]
        store.append(task_id, "human", "instruction", payload.message,
                     status="running")
        try:
            current_agent = Agent(
                ollama=agent.ollama,
                mcp_factory=lambda: CommunicationToolClient(
                    TrafficToolClient(MCPClient(), state["traffic_artifacts"]),
                    store, task_id,
                ),
            )
            outcome = current_agent.run(
                state["history"], payload.message,
                public_get=True,
                force_tools=True,
            )
        except Exception as exc:
            store.append(task_id, "controller", "system",
                         "Agent failed: " + type(exc).__name__, status="blocked")
            raise HTTPException(status_code=502, detail="agent_failed: " +
                                type(exc).__name__) from exc
        # Raw arguments are never exposed in the chat response.
        requests = outcome.pop("approval_requests", [])
        EvidenceJournal(store).record_tool_events(
            task_id, outcome.get("events") or [],
        )
        state["pending_approvals"].clear()
        for item in requests[:6]:
            state["pending_approvals"][item["request_id"]] = {
                **item, "turn": state["turns"] + 1,
            }
        state["history"].append({"role": "user", "content": payload.message[:10000]})
        state["history"].append({"role": "assistant", "content": outcome["answer"][:16000]})
        state["history"] = state["history"][-MAX_HISTORY:]
        state["turns"] += 1
        current_status = store.get_task(task_id)["status"]
        final_status = ("needs_review" if current_status == "needs_review"
                        else "blocked" if requests else "completed")
        event = store.append(task_id, "qwen", "result",
                             outcome["answer"][:12000], status=final_status)
    return {"session_id": sid, "task_id": task_id, "event_seq": event["seq"],
            "turn": state["turns"], **outcome}


@app.post("/api/approve")
def approve(payload: ApprovalRequest):
    """One-shot human authorization, bound to session, call, exact args and turn."""
    with sessions_lock:
        state = sessions.get(payload.session_id)
    if state is None:
        raise HTTPException(status_code=404, detail="session_not_found")
    with state["lock"]:
        item = state["pending_approvals"].pop(payload.request_id, None)
        if item is None:
            raise HTTPException(status_code=404, detail="approval_not_found_or_used")
        if item["turn"] != state["turns"]:
            raise HTTPException(status_code=409, detail="approval_from_previous_turn")
        if time.time() - item["created_at"] > 600:
            raise HTTPException(status_code=410, detail="approval_expired")
        if payload.decision == "deny":
            communication_store().append(
                state["task_id"], "human", "decision",
                "Отклонён вызов " + item["tool"],
            )
            return {"ok": True, "decision": "denied", "message": "Действие отклонено; "
                    "инструмент не запускался", "tool_calls": 0}
        try:
            # The reviewed agent checks the latest MCP schema before execution.
            current_agent = Agent(
                ollama=agent.ollama,
                mcp_factory=lambda: CommunicationToolClient(
                    TrafficToolClient(MCPClient(), state["traffic_artifacts"]),
                    communication_store(), state["task_id"]),
            )
            result = current_agent.execute_approved(item, state["history"])
        except Exception as exc:
            raise HTTPException(
                status_code=502, detail="approved_action_failed: " + type(exc).__name__
            ) from exc
        state["history"].append({
            "role": "user", "content": "Разрешаю один вызов MCP-инструмента: " + item["tool"],
        })
        state["history"].append({"role": "assistant", "content": result["answer"][:16000]})
        state["history"] = state["history"][-MAX_HISTORY:]
        state["turns"] += 1
        state["pending_approvals"].clear()
        communication_store().append(state["task_id"], "human", "decision",
                                     "Разрешён один вызов " + item["tool"])
        EvidenceJournal(communication_store()).record_tool_events(
            state["task_id"], result.get("events") or [],
        )
        communication_store().append(state["task_id"], "qwen", "result",
                                     str(result["answer"])[:12000],
                                     status="completed")
        return {"ok": True, "decision": "approved", "session_id": payload.session_id,
                "task_id": state["task_id"],
                "turn": state["turns"], **result}



@app.get("/api/comm/events")
def communication_updates(session_id: str, after_seq: int = 0):
    """Read messages for this browser session from the shared durable task."""
    with sessions_lock:
        state = sessions.get(session_id)
    if state is None or state.get("task_id") is None:
        raise HTTPException(status_code=404, detail="session_or_task_not_found")
    try:
        return communication_store().read_dialog(
            state["task_id"], after=after_seq, limit=50,
        )
    except CommunicationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc



@app.get("/api/comm/review-packet")
def communication_review_packet(session_id: str):
    """Copyable, provenance-aware task packet for an independent reviewer."""
    with sessions_lock:
        state = sessions.get(session_id)
    if state is None or not state.get("task_id"):
        raise HTTPException(status_code=404, detail="session_or_task_not_found")
    try:
        return {
            "task_id": state["task_id"],
            "packet": EvidenceJournal(communication_store()).review_packet(
                state["task_id"]
            ),
        }
    except CommunicationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class ReviewerFeedbackRequest(BaseModel):
    session_id: str = Field(min_length=16, max_length=100)
    message: str = Field(min_length=1, max_length=6000)
    event_key: str | None = Field(default=None, min_length=12, max_length=100)


@app.post("/api/comm/reviewer-feedback")
def communication_reviewer_feedback(payload: ReviewerFeedbackRequest):
    """User relays ChatGPT feedback; never impersonates authenticated ChatGPT.

    This is an explicit manual fallback on personal ChatGPT plans without a
    writable custom MCP connection. The Qwen worker resumes the same task.
    """
    with sessions_lock:
        state = sessions.get(payload.session_id)
    if state is None or not state.get("task_id"):
        raise HTTPException(status_code=404, detail="session_or_task_not_found")
    try:
        store = communication_store()
        item = store.append(
            state["task_id"], "human", "feedback",
            "Комментарий рецензента, переданный пользователем:\n" + payload.message,
            event_key=payload.event_key, status="queued",
        )
        return {
            "task_id": state["task_id"], "event_seq": item["seq"],
            "status": store.get_task(state["task_id"])["status"],
            "note": "Qwen worker will process this when available",
        }
    except CommunicationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/comm/evidence")
def communication_evidence(session_id: str):
    with sessions_lock:
        state = sessions.get(session_id)
    if state is None or not state.get("task_id"):
        raise HTTPException(status_code=404, detail="session_or_task_not_found")
    journal = EvidenceJournal(communication_store())
    return {
        "task_id": state["task_id"],
        "claims": journal.list_evidence(state["task_id"], limit=50),
        "tool_receipts": journal.list_tool_receipts(state["task_id"], limit=50),
    }


@app.get("/api/comm/tasks")
def communication_tasks():
    """List recent persisted tasks in the local Cybernova Web UI."""
    return {"tasks": communication_store().list_tasks(limit=25)}


class ResumeTaskRequest(BaseModel):
    task_id: str = Field(min_length=12, max_length=100)


@app.post("/api/comm/resume")
def communication_resume(payload: ResumeTaskRequest):
    """Resume an existing task in the current browser; do not execute Qwen."""
    store = communication_store()
    try:
        task = store.get_task(payload.task_id)
        dialog = store.read_dialog(payload.task_id, limit=100)
    except CommunicationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    sid, state = _session(None)
    with state["lock"]:
        state["task_id"] = payload.task_id
        state["history"] = [
            {"role": "assistant" if row["actor"] == "qwen" else "user",
             "content": row["body"][:10000]}
            for row in dialog["messages"]
            if row["actor"] in {"human", "qwen", "chatgpt"}
            and row["kind"] in {"instruction", "feedback", "result"}
        ][-MAX_HISTORY:]
        state["turns"] = len([x for x in state["history"] if x["role"] == "assistant"])
    return {"session_id": sid, "task": task,
            "messages": dialog["messages"], "turn": state["turns"]}


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
