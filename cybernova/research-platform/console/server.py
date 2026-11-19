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
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

try:
    from .agent import Agent, MCPClient, MODEL, OLLAMA_URL, APPROVAL_TTL_SECONDS
    from .followups import generate_followups
    from .tool_policy import REVIEWED_TOOLS
    from .traffic_intelligence import analyze_har, analyze_js, TrafficError
    from .traffic_tools import TrafficToolClient, LOCAL_TOOLS, MAX_ARTIFACTS
    from .domain_intelligence import PARSERS, DomainError
    from .domain_tools import DOMAIN_TOOLS
    from .scoped_network_tools import SCOPED_TOOLS
    from .browser_tools import BROWSER_TOOLS
    from .devtools_network import NETWORK_TOOLS
    from .research_web import RESEARCH_WEB_TOOLS
    from .safe_terminal import TERMINAL_TOOLS, safe_terminal
    from .research_web import research_web_call
    from .collaboration import CollaborationStore, CollaborationError, mentor_messages, researcher_messages, MENTOR_PROFILE
    from .shared_tool_support import preflight as gpt_tool_preflight
    from .lab_scanners import SCANNER_TOOLS, inventory
    from .communication import CommunicationStore, CommunicationError
    from .conversation_export import export_data, render_export, ConversationExportError
    from .communication_tools import CommunicationToolClient, COMMUNICATION_TOOLS
    from .developer_tools import DEV_TOOLS
    from .communication_worker import CommunicationWorker
    from .evidence import EvidenceJournal
    from .upload_limits import MAX_UPLOAD_FILE_BYTES, MAX_PCAP_BASE64_CHARS
    from .siwc import connection as chatgpt_connection, SIWCError
    from .siwc_inference import models as chatgpt_models, review as chatgpt_review, chat as chatgpt_chat
    from .siwc_chat_store import GPTChatStore, GPTChatError
    from .research_scope import ResearchScopeStore, scope_profile
    from .profile_settings import ProfileSettingsStore, ProfileSettingsError, user_context_for, mode_instructions_for
except ImportError:
    from agent import Agent, MCPClient, MODEL, OLLAMA_URL, APPROVAL_TTL_SECONDS
    from followups import generate_followups
    from tool_policy import REVIEWED_TOOLS
    from traffic_intelligence import analyze_har, analyze_js, TrafficError
    from traffic_tools import TrafficToolClient, LOCAL_TOOLS, MAX_ARTIFACTS
    from domain_intelligence import PARSERS, DomainError
    from domain_tools import DOMAIN_TOOLS
    from scoped_network_tools import SCOPED_TOOLS
    from browser_tools import BROWSER_TOOLS
    from devtools_network import NETWORK_TOOLS
    from research_web import RESEARCH_WEB_TOOLS
    from safe_terminal import TERMINAL_TOOLS, safe_terminal
    from research_web import research_web_call
    from collaboration import CollaborationStore, CollaborationError, mentor_messages, researcher_messages, MENTOR_PROFILE
    from shared_tool_support import preflight as gpt_tool_preflight
    from lab_scanners import SCANNER_TOOLS, inventory
    from communication import CommunicationStore, CommunicationError
    from conversation_export import export_data, render_export, ConversationExportError
    from communication_tools import CommunicationToolClient, COMMUNICATION_TOOLS
    from developer_tools import DEV_TOOLS
    from communication_worker import CommunicationWorker
    from evidence import EvidenceJournal
    from upload_limits import MAX_UPLOAD_FILE_BYTES, MAX_PCAP_BASE64_CHARS
    from siwc import connection as chatgpt_connection, SIWCError
    from siwc_inference import models as chatgpt_models, review as chatgpt_review, chat as chatgpt_chat
    from siwc_chat_store import GPTChatStore, GPTChatError
    from research_scope import ResearchScopeStore, scope_profile
    from profile_settings import ProfileSettingsStore, ProfileSettingsError, user_context_for, mode_instructions_for

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


@lru_cache(maxsize=1)
def gpt_chat_store() -> GPTChatStore:
    return GPTChatStore()


@lru_cache(maxsize=1)
def profile_settings_store() -> ProfileSettingsStore:
    return ProfileSettingsStore()


@lru_cache(maxsize=1)
def research_scope_store() -> ResearchScopeStore:
    return ResearchScopeStore()


@lru_cache(maxsize=1)
def collaboration_store() -> CollaborationStore:
    return CollaborationStore(communication_store())


collaboration_step_lock = RLock()


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


class ResearchScopeRequest(BaseModel):
    session_id: str | None = Field(default=None, min_length=16, max_length=100)
    hosts: list[str] = Field(default_factory=list, max_length=20)
    capture_detail: str = Field(default="evidence", pattern="^(metadata|evidence)$")


class ResetRequest(BaseModel):
    session_id: str | None = None


class FollowupsRequest(BaseModel):
    session_id: str = Field(min_length=16, max_length=100)
    turn: int = Field(ge=1)


class ImportRequest(BaseModel):
    session_id: str | None = Field(default=None, min_length=16, max_length=100)
    kind: str = Field(pattern="^(har|javascript|openapi|log|config|python|dependencies|tls|pcap)$")
    content: str = Field(min_length=1, max_length=MAX_PCAP_BASE64_CHARS)


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
                   "traffic_artifacts": {}, "scope": scope_profile([]), "task_id": None}
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


@app.get("/static/markdown.js")
def markdown_javascript():
    return FileResponse(ROOT / "static" / "markdown.js", media_type="text/javascript")


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



class ChatGPTReviewRequest(BaseModel):
    model: str = Field(min_length=1, max_length=160)
    prompt: str = Field(min_length=1, max_length=12000)
    session_id: str | None = Field(default=None, min_length=16, max_length=100)


class ChatGPTMessageRequest(BaseModel):
    thread_id: str | None = Field(default=None, min_length=20, max_length=100)
    model: str = Field(min_length=1, max_length=160)
    message: str = Field(min_length=1, max_length=10000)


class ProfileSettingsRequest(BaseModel):
    settings: dict


class CollaborationStartRequest(BaseModel):
    goal: str = Field(min_length=1, max_length=3000)
    model: str = Field(min_length=1, max_length=160)
    cycles: int = Field(default=5, ge=1, le=12)
    session_id: str | None = Field(default=None, min_length=16, max_length=100)


class CollaborationActionRequest(BaseModel):
    task_id: str = Field(min_length=12, max_length=100)


class CollaborationGoalEditRequest(CollaborationActionRequest):
    goal: str = Field(min_length=1, max_length=3000)
    cycles: int | None = Field(default=None, ge=1, le=12)


class SharedToolRequest(BaseModel):
    name: str = Field(pattern="^(google_search|research_source_open|safe_terminal)$")
    argument: str = Field(min_length=1, max_length=1600)


gpt_turn_lock = RLock()


@app.get("/api/conversation/export")
def conversation_export(mode: str, id: str, format: str = "md"):
    """Explicit, authenticated GET export; no model calls or external traffic."""
    if mode not in {"research", "gpt", "collab"} or format not in {"md", "json"}:
        raise HTTPException(status_code=422, detail="invalid_export_options")
    try:
        data = export_data(mode, id, communication_store(),
                           collaboration_store(), gpt_chat_store())
        content, media_type, extension = render_export(data, format)
    except (CommunicationError, CollaborationError, GPTChatError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ConversationExportError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    # The ID is a store-validated opaque identifier, never a user title.
    filename = "cybernova-" + mode + "-" + id + "." + extension
    return Response(
        content=content, media_type=media_type,
        headers={
            "Content-Disposition": 'attachment; filename="' + filename + '"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/collab/runs")
def collaboration_runs():
    return {"runs": collaboration_store().list_runs()}


@app.get("/api/collab/run")
def collaboration_run(task_id: str, after: int = 0):
    try:
        return collaboration_store().read(task_id, after=after)
    except (CollaborationError, CommunicationError, ValueError):
        raise HTTPException(status_code=404, detail="collaboration_not_found") from None


@app.post("/api/collab/start")
def collaboration_start(payload: CollaborationStartRequest):
    # Starting is a deliberate browser action. This authorizes a limited
    # number of calls to the user's connected ChatGPT plan and DeepSeek.
    try:
        available = {m["slug"] for m in chatgpt_models()}
        if payload.model not in available:
            raise HTTPException(status_code=409, detail="collab_model_unavailable")
        scope = scope_profile([])
        if payload.session_id:
            with sessions_lock:
                active_session = sessions.get(payload.session_id)
            if active_session is None:
                raise HTTPException(status_code=404, detail="session_not_found")
            with active_session["lock"]:
                scope = scope_profile(active_session["scope"]["hosts"],
                                      active_session["scope"]["capture_detail"])
        return collaboration_store().create(payload.goal, payload.model,
                                            payload.cycles, scope=scope)
    except (SIWCError, ProfileSettingsError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    except (CollaborationError, ValueError, CommunicationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@app.post("/api/collab/stop")
def collaboration_stop(payload: CollaborationActionRequest):
    # Wait for an in-flight agent answer before pausing, preserving evidence.
    with collaboration_step_lock:
        try:
            return collaboration_store().halt(payload.task_id)
        except (CollaborationError, CommunicationError):
            raise HTTPException(status_code=404, detail="collaboration_not_found") from None


@app.post("/api/collab/resume")
def collaboration_resume(payload: CollaborationActionRequest):
    try:
        return collaboration_store().resume(payload.task_id)
    except (CollaborationError, CommunicationError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/collab/finish")
def collaboration_finish(payload: CollaborationActionRequest):
    with collaboration_step_lock:
        try:
            return collaboration_store().finish(payload.task_id)
        except (CollaborationError, CommunicationError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/collab/goal")
def collaboration_update_goal(payload: CollaborationGoalEditRequest):
    # Revisions are only committed while paused: no mid-inference mutation.
    # The scope/permissions are managed separately and never expanded here.
    with collaboration_step_lock:
        try:
            return collaboration_store().update_goal(payload.task_id, payload.goal, payload.cycles)
        except (CollaborationError, CommunicationError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/collab/step")
def collaboration_step(payload: CollaborationActionRequest):
    # Sequential browser-driven turn: no unbounded background loops.
    # A concurrent stop can mark the run stopped during model I/O.
    with collaboration_step_lock:
        store = collaboration_store()
        try:
            run = store.read(payload.task_id)
            if run["state"] != "active":
                raise HTTPException(status_code=409, detail="collaboration_not_active")
            role = run["next_actor"]
            profile = profile_settings_store().load()
            tool_count = 0
            blocked = False
            if role == "chatgpt":
                history = mentor_messages(run)
                # Only the first mentor turn performs an automatic knowledge
                # lookup; subsequent turns evaluate DeepSeek's actual evidence.
                tool_evidence = gpt_tool_preflight(run["goal"], enabled=run["step"] == 0)
                if tool_evidence["context"] and len(history[-1]["content"]) + len(tool_evidence["context"]) <= 12000:
                    history[-1] = {**history[-1], "content":
                                   history[-1]["content"] + tool_evidence["context"]}
                outcome = chatgpt_chat(
                    run["model"], history,
                    user_context=user_context_for(profile, "chatgpt"),
                    profile_instructions=MENTOR_PROFILE + "\n\n" +
                                         mode_instructions_for(profile, "chatgpt"),
                )
            else:
                history, prompt = researcher_messages(run)
                scope = ResearchScopeStore(communication_store().path).load(payload.task_id)
                engine = Agent(
                    ollama=agent.ollama,
                    mcp_factory=lambda: CommunicationToolClient(
                        TrafficToolClient(MCPClient(), {}, scope=scope),
                        communication_store(), payload.task_id,
                    ),
                )
                outcome = engine.run(
                    history, prompt, scope=scope, public_get=True, force_tools=True,
                    user_context=user_context_for(profile, "researcher"),
                    profile_instructions=(
                        "Ты исследователь DeepSeek. ChatGPT выступает старшим инженером "
                        "и наставником. Выполняй разрешённые задания и передавай "
                        "проверяемые результаты, логику диагностики, ограничения и "
                        "реальные доказательства. Не выдумывай результаты.\n\n" +
                        mode_instructions_for(profile, "researcher")
                    ),
                )
                tool_count = outcome.get("tool_calls", 0)
                EvidenceJournal(communication_store()).record_tool_events(
                    payload.task_id, outcome.get("events") or [],
                )
                blocked = bool(outcome.get("approval_requests"))
            answer = str(outcome.get("answer", "")).strip()
            if blocked:
                answer += (
                    "\n\nТребуются отдельные разрешения на инструмент. "
                    "Автоматический обмен остановлен; действие не выполнялось."
                )
            next_run = store.advance(payload.task_id, role, answer, blocked=blocked)
            return {"run": next_run, "actor": role, "answer": answer,
                    "tool_calls": tool_count}
        except HTTPException:
            raise
        except (CollaborationError, CommunicationError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except (SIWCError, ProfileSettingsError) as exc:
            store.fail(payload.task_id, type(exc).__name__)
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except Exception as exc:
            store.fail(payload.task_id, type(exc).__name__)
            raise HTTPException(status_code=502,
                                detail="collaboration_step_failed:" + type(exc).__name__) from exc


@app.post("/api/tools/run")
def run_shared_utility(payload: SharedToolRequest):
    # Same three bounded read-only tools for both modes; no arbitrary shell.
    args = ({"query": payload.argument} if payload.name == "google_search"
            else {"url": payload.argument} if payload.name == "research_source_open"
            else {"command": payload.argument})
    try:
        if payload.name == "safe_terminal":
            result = safe_terminal(args["command"])
        else:
            result, _ = research_web_call(payload.name, args)
        return {"tool": payload.name, "result": result}
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)[:160]) from None


@app.get("/api/profile-settings")
def get_profile_settings():
    try:
        return {"settings": profile_settings_store().load()}
    except ProfileSettingsError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from None


@app.post("/api/profile-settings")
def save_profile_settings(payload: ProfileSettingsRequest):
    try:
        return {"settings": profile_settings_store().save(payload.settings)}
    except ProfileSettingsError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@app.get("/api/siwc/chats")
def siwc_chats():
    """List separate saved GPT dialogs. Not Qwen task sessions."""
    return {"threads": gpt_chat_store().list_threads()}


@app.get("/api/siwc/chat")
def siwc_chat_thread(thread_id: str):
    try:
        return gpt_chat_store().get_thread(thread_id)
    except GPTChatError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None


@app.post("/api/siwc/chat")
def siwc_chat_message(payload: ChatGPTMessageRequest):
    """Explicit user turn, no implicit Qwen history/tools or external fetch.

    Lock ensures two browser tabs cannot interleave turns in the same
    conversation. Commit the user+assistant pair only after a complete reply.
    """
    with gpt_turn_lock:
        store = gpt_chat_store()
        try:
            history = store.context(payload.thread_id) if payload.thread_id else []
            preflight = gpt_tool_preflight(payload.message.strip())
            message_for_model = payload.message.strip()
            if len(message_for_model) + len(preflight["context"]) <= 12000:
                message_for_model += preflight["context"]
            outgoing = history + [{"role": "user", "content": message_for_model}]
            profile = profile_settings_store().load()
            outcome = chatgpt_chat(
                payload.model, outgoing,
                user_context=user_context_for(profile, "chatgpt"),
                profile_instructions=mode_instructions_for(profile, "chatgpt"),
            )
            thread_id = store.save_exchange(
                payload.thread_id, payload.model, payload.message, outcome["answer"]
            )
        except GPTChatError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        except ProfileSettingsError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from None
        except SIWCError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
    return {"thread_id": thread_id, "model": payload.model,
            "answer": outcome["answer"], "source": outcome["source"],
            "tool_events": preflight["events"]}


@app.get("/api/siwc/status")
def siwc_status():
    try:
        return chatgpt_connection.status()
    except SIWCError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None


@app.post("/api/siwc/start")
def siwc_start():
    """A public OAuth client. Access to this endpoint is already Basic-auth gated."""
    try:
        return chatgpt_connection.start()
    except SIWCError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.get("/auth/callback")
def siwc_callback(code: str | None = None, state: str | None = None,
                  client_id: str | None = None, error: str | None = None):
    """Loopback-only OAuth callback; never return code, tokens, or claims."""
    try:
        chatgpt_connection.finish({"code": code, "state": state,
                                   "client_id": client_id, "error": error})
    except SIWCError:
        return RedirectResponse(url="/?chatgpt=error", status_code=303)
    return RedirectResponse(url="/?chatgpt=connected", status_code=303)


@app.get("/api/siwc/models")
def siwc_models():
    try:
        return {"models": chatgpt_models()}
    except SIWCError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.post("/api/siwc/review")
def siwc_review(payload: ChatGPTReviewRequest):
    """Explicit review; bind persistence to the selected task before network I/O."""
    task_id = None
    if payload.session_id:
        with sessions_lock:
            state = sessions.get(payload.session_id)
        if state is None:
            raise HTTPException(status_code=404, detail="session_not_found")
        with state["lock"]:
            task_id = state.get("task_id")
        if not task_id:
            raise HTTPException(status_code=409, detail="task_not_selected")
    try:
        profile = profile_settings_store().load()
        outcome = chatgpt_review(
            payload.model, payload.prompt,
            user_context=user_context_for(profile, "chatgpt"),
        )
    except ProfileSettingsError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from None
    except SIWCError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if task_id:
        item = communication_store().append(
            task_id, "chatgpt", "result", outcome["answer"][:12000])
        outcome["event_seq"] = item["seq"]
        outcome["task_id"] = task_id
    return outcome


@app.post("/api/siwc/disconnect")
def siwc_disconnect():
    try:
        return chatgpt_connection.disconnect()
    except SIWCError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None


@app.get("/api/status")
def status():
    try:
        mcp = MCPClient()
        remote_tools = [t["name"] for t in mcp.initialize()]
        mcp_ok = True
    except Exception:
        remote_tools, mcp_ok = [], False
    tools = remote_tools + [t["name"] for t in LOCAL_TOOLS + DOMAIN_TOOLS + SCOPED_TOOLS + SCANNER_TOOLS + BROWSER_TOOLS + NETWORK_TOOLS + RESEARCH_WEB_TOOLS + TERMINAL_TOOLS + COMMUNICATION_TOOLS + DEV_TOOLS]
    return {
        "model": MODEL,
        "source_commit": os.environ.get("CYBERNOVA_SOURCE_COMMIT","unknown"),
        "ollama_ready": _ollama_health() if os.environ.get("CYBERNOVA_LLM_PROVIDER", "ollama") == "ollama" else False,
        "model_provider": os.environ.get("CYBERNOVA_LLM_PROVIDER", "ollama"),
        "model_remote_configured": os.environ.get("CYBERNOVA_LLM_PROVIDER") == "openai_compatible",
        "mcp_ready": mcp_ok,
        "tools": tools,
        "auto_executable": sorted(set(tools) & REVIEWED_TOOLS),
        "others_require_approval": sorted(set(tools) - REVIEWED_TOOLS),
        "tools_selection": "automatic_model",
        "developer": {"mode": "task_isolated_git_worktree", "self_modification": True,
                      "code_edit": True, "unprivileged_tests": True,
                      "push_and_pr": "require_approval_and_write_credentials"},
        "http_get": "available_for_preconfigured_mcp_hosts_only",
        "traffic_intelligence": "offline_multi_domain_analysis",
        "scoped_network_checks": "DNS A/AAAA and verified TLS 443",
        "browser_network": "isolated_chromium_readonly_metadata",
        "web_research": {"provider": "Google Search HTML", "tools": ["google_search", "research_source_open"], "mode": "public_read_only", "requires_api_key": False},
        "research_scope": {"type": "owner_selected_per_task", "active_actions": "propose_and_confirm"},
        "browser": {"mode": "readonly_https_html", "configured_hosts": [x.strip() for x in os.environ.get("CYBERNOVA_BROWSER_HOSTS", "").split(",") if x.strip()], "live_javascript": False},
        "lab_scanners": inventory(),
        "import_kinds": ["har", "javascript"] + sorted(PARSERS),
        "upload_limit_bytes": MAX_UPLOAD_FILE_BYTES,
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
    # Enforce the same raw 32-MiB limit even for clients bypassing the UI.
    # Base64-encoded PCAP has larger transport representation.
    if payload.kind == "pcap":
        if len(payload.content) > MAX_PCAP_BASE64_CHARS:
            raise HTTPException(status_code=413, detail="pcap_too_large")
    elif len(payload.content.encode("utf-8")) > MAX_UPLOAD_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file_too_large")
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


@app.post("/api/research/scope")
def configure_research_scope(payload: ResearchScopeRequest):
    """Owner selects research targets; the LLM has no tool to extend them."""
    try:
        profile = scope_profile(payload.hosts, payload.capture_detail)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    sid, state = _session(payload.session_id)
    with state["lock"]:
        state["scope"] = profile
        if state.get("task_id"):
            research_scope_store().save(state["task_id"], profile)
    return {"session_id": sid, "scope": profile, "applies_to": "qwen_research_only"}


@app.get("/api/research/scope")
def get_research_scope(session_id: str | None = None):
    sid, state = _session(session_id)
    with state["lock"]:
        return {"session_id": sid, "scope": state["scope"]}


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
            research_scope_store().save(state["task_id"], state["scope"])
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
                    TrafficToolClient(MCPClient(), state["traffic_artifacts"], scope=state["scope"]),
                    store, task_id,
                ),
            )
            profile = profile_settings_store().load()
            outcome = current_agent.run(
                state["history"], payload.message,
                public_get=True,
                force_tools=True,
                scope=state["scope"],
                user_context=user_context_for(profile, "researcher"),
                profile_instructions=mode_instructions_for(profile, "researcher"),
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
        if time.time() - item["created_at"] > APPROVAL_TTL_SECONDS:
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
        state["scope"] = research_scope_store().load(payload.task_id)
        state["history"] = [
            {"role": "assistant" if row["actor"] == "qwen" else "user",
             "content": row["body"][:10000]}
            for row in dialog["messages"]
            if row["actor"] in {"human", "qwen", "chatgpt"}
            and row["kind"] in {"instruction", "feedback", "result"}
        ][-MAX_HISTORY:]
        state["turns"] = len([x for x in state["history"] if x["role"] == "assistant"])
    return {"session_id": sid, "task": task, "scope": state["scope"],
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
