"""Bounded live offline Qwen↔Controller↔review-feedback acceptance smoke.

No target scanning, credentials, or remote websites. Runs two Qwen turns
against the RFC5737 TEST-NET-1 address only. No OpenAI API or external MCP
connection is involved; this explicitly tests Cybernova's internal loop.
"""
from __future__ import annotations

import json
import time
from urllib.request import Request, build_opener, ProxyHandler

BASE = "http://127.0.0.1:18794"
OPENER = build_opener(ProxyHandler({}))


def request(path: str, payload: dict | None = None, timeout: float = 180) -> dict:
    headers = {"Accept": "application/json"}
    content = None
    if payload is not None:
        content = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = Request(BASE + path, method="POST" if content else "GET",
                  data=content, headers=headers)
    with OPENER.open(req, timeout=timeout) as response:
        return json.load(response)


def main():
    print("CYBERNOVA_LIVE_SMOKE_STARTED", flush=True)
    result = request("/api/chat", {
        "message": (
            "Это безопасный локальный проверочный сценарий Cybernova. "
            "НЕ выполняй активных сетевых запросов. "
            "Вызови офлайн MCP-функцию ip_network_summary с аргументом "
            "cidr='192.0.2.7/24', затем объясни сеть, "
            "отдельно отметив, какие данные получены инструментом. "
            "Запиши через comm_record_evidence одну скромную гипотезу, "
            "явно указав, что её надо перепроверить. "
            "Наконец, вызови comm_request_review с просьбой проверить "
            "корректность подсети. Не изобретай результаты."
        )
    }, timeout=240)
    sid = result["session_id"]
    task = result["task_id"]
    called = [e.get("name") for e in result.get("events", [])
              if e.get("name")]
    evidence = request("/api/comm/evidence?session_id=" + sid, timeout=15)
    print(json.dumps({
        "stage": "first_qwen_turn",
        "task_id": task,
        "tool_calls": result.get("tool_calls"),
        "selected_tools": called,
        "qwen_reported_evidence": len(evidence.get("claims", [])),
        "controller_receipts": len(evidence.get("tool_receipts", [])),
        "model_reply": bool(result.get("answer")),
    }, ensure_ascii=False), flush=True)

    followup = request("/api/comm/reviewer-feedback", {
        "session_id": sid,
        "message": (
            "Тестовое замечание независимого рецензента, "
            "переданное пользователем: проверь ещё раз, что "
            "192.0.2.7/24 относится к 192.0.2.0/24, "
            "отдели факт, полученный из офлайн-инструмента, от гипотезы."
        ),
        "event_key": "smoke_review_" + str(int(time.time())),
    }, timeout=20)
    assert followup["task_id"] == task
    after = followup["event_seq"]
    final_state = None
    final_response_found = False
    for attempt in range(150):
        time.sleep(2)
        dialog = request(
            "/api/comm/events?session_id=" + sid + "&after_seq=" + str(after),
            timeout=15,
        )
        final_state = dialog["task"]["status"]
        for event in dialog.get("messages", []):
            if event["actor"] == "qwen" and event["kind"] == "result":
                final_response_found = True
        if final_response_found:
            break
        if final_state == "blocked":
            break
    print(json.dumps({
        "stage": "review_roundtrip",
        "task_id": task,
        "result_after_reviewer_feedback": final_response_found,
        "task_status": final_state,
        "mechanism": "user-relayed feedback, not live ChatGPT MCP",
    }, ensure_ascii=False), flush=True)
    if not final_response_found:
        raise RuntimeError("qwen_did_not_continue_within_smoke_window")
    print("CYBERNOVA_LIVE_REVIEW_LOOP_PASSED", flush=True)


if __name__ == "__main__":
    main()
