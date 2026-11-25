"""Ollama adapter: native tool calling with structured JSON fallback.

No model-generated text is executed. All actions still go through the existing
file-scoped policy gate in cybernova_agent.tools.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any

from .common import MODEL

ACTIONS = ('plan', 'list_files', 'read_file', 'write_file', 'check_file', 'finish', 'ask_human', 'repo_status', 'repo_sync', 'install_python_tool')

SYS = '''You are Cybernova, a careful software development agent running locally on Vast.
Only work on one isolated project directory. You cannot use shell commands, network scanners,
external URLs, system changes or secrets. You can use these tools ONE AT A TIME:
plan {"steps":["..."],"acceptance":["..."]};
list_files {};
read_file {"path":"relative.py"};
write_file {"path":"relative.py", "content":"complete file contents"};
check_file {"path":"relative.py"} (Python/JSON/TOML parse; other text only checked non-empty);
finish {"summary":"what actually passed and remains untested"};
ask_human {"question":"what decision is required"}.
On the first decision outline a short plan using plan. Then perform one action at a time.
Prefer actual native tool calls. If tool calling is unavailable, respond with ONE valid JSON object
containing action, args, reason, confidence. No markdown outside JSON.
Inspect the results of each action. Verify new/modified files before changing them again.
NEVER claim runtime/unit tests passed unless a tool actually performed them.
Never repeat the same read-only action without a project change. Once the final file was written,
check_file for that file, then finish with a truthful summary. Use ask_human if blocked.
Do not call list_files repeatedly; the current files are summarized in tool results.
Git tools: repo_status {} reads the isolated checkout; repo_sync {} downloads ONLY
4oker12/cybernoc branch cybernova-autodeploy into github-src and verifies Git state.
This does not install or execute the downloaded code. install_python_tool {"name":"ruff"}
installs only an approved pinned Python CLI inside a project venv as a non-root user.
System-wide apt or arbitrary packages are not permitted. If a privileged operation
is required, ask_human with exact reason. Never repeat failed installation blindly.
Never initiate security testing on external targets.
'''


def _function(name: str, description: str, properties: dict, required=()) -> dict:
    return {'type': 'function', 'function': {'name': name, 'description': description,
       'parameters': {'type': 'object', 'properties': properties,
                      'required': list(required), 'additionalProperties': False}}}

TEXT = {'type': 'string'}
TOOLS = [
    _function('plan', 'Create a short plan and explicit acceptance criteria.',
              {'steps': {'type': 'array', 'items': TEXT}, 'acceptance': {'type': 'array', 'items': TEXT}}, ('steps', 'acceptance')),
    _function('list_files', 'List available project files.', {}),
    _function('read_file', 'Read one allowed project file.', {'path': TEXT}, ('path',)),
    _function('write_file', 'Create or replace one allowed project file; content is the full file text.',
              {'path': TEXT, 'content': TEXT}, ('path', 'content')),
    _function('check_file', 'Check one project file using available local parser/syntax checker.', {'path': TEXT}, ('path',)),
    _function('finish', 'Finish only after actual checks have passed; disclose limitations.',
              {'summary': TEXT}, ('summary',)),
    _function('ask_human', 'Ask a specific question when blocked.', {'question': TEXT}, ('question',)),
    _function('repo_status', 'Inspect approved isolated GitHub checkout (no remote shell).', {}),
    _function('repo_sync', 'Fetch approved cybernoc branch into isolated checkout; never execute it.', {}),
    _function('install_python_tool', 'Install pinned allowlisted Python CLI into project-only venv, non-root.', {'name': {'type':'string','enum':['ruff','pytest','httpx','rich']}}, ('name',)),
]

FALLBACK_SCHEMA = {
    'type': 'object', 'properties': {
        'action': {'type': 'string', 'enum': list(ACTIONS)},
        'args': {'type': 'object'},
        'reason': {'type': 'string'},
        'confidence': {'type': 'number', 'minimum': 0, 'maximum': 1},
    }, 'required': ['action', 'args'], 'additionalProperties': False,
}


def _object_from_text(text: str) -> Any:
    """Decode pure JSON or a single JSON object embedded in a text response."""
    text = text.strip()
    if not text:
        raise ValueError('Model produced no JSON text')
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        decoder = json.JSONDecoder()
        for i, ch in enumerate(text):
            if ch == '{':
                try:
                    obj, _ = decoder.raw_decode(text[i:])
                    return obj
                except json.JSONDecodeError:
                    pass
    raise ValueError('Model output contains no parseable JSON object')


def _arguments(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, str):
        value = _object_from_text(value)
    if not isinstance(value, dict):
        raise ValueError('Model tool arguments are not a JSON object')
    return value


def _normalize(value: Any, *, source: str) -> dict:
    """Accept the Ollama function shape and common JSON envelopes, not loose prose."""
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        raise ValueError('Model returned invalid action envelope')
    if 'tool_calls' in value and isinstance(value['tool_calls'], list):
        calls = value['tool_calls']
        if len(calls) != 1:
            raise ValueError('Model must select exactly one tool')
        value = calls[0]
    if isinstance(value.get('function'), dict):
        value = value['function']
    # Some models return tool/name/parameters rather than action/args.
    name = value.get('action', value.get('name', value.get('tool')))
    args = value.get('args', value.get('arguments', value.get('parameters')))
    if not isinstance(name, str) or name not in ACTIONS:
        raise ValueError('Model returned invalid action envelope')
    if args is None and name in ('list_files', 'repo_status', 'repo_sync'):
        args = {}
    args = _arguments(args)
    # Model claims are untrusted: actual policy enforcement happens in worker/tools.
    confidence = value.get('confidence', 0.5)
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        confidence = 0.5
    return {'action': name, 'args': args,
            'reason': str(value.get('reason') or ('Native tool call' if source == 'tool' else 'JSON decision'))[:400],
            'confidence': max(0.0, min(1.0, float(confidence)))}


def _decision_from_response(response: dict) -> dict:
    message = response.get('message')
    if not isinstance(message, dict):
        raise ValueError('Ollama response has no assistant message')
    calls = message.get('tool_calls')
    if isinstance(calls, list) and calls:
        if len(calls) != 1:
            raise ValueError('Model called multiple tools at once')
        return _normalize(calls[0], source='tool')
    body = message.get('content', '')
    if not isinstance(body, str) or not body.strip():
        raise ValueError('Local model returned no tool call or text decision')
    return _normalize(_object_from_text(body), source='text')


def _ollama(payload: dict, timeout: int) -> dict:
    request = urllib.request.Request('http://127.0.0.1:11434/api/chat',
        data=json.dumps(payload, ensure_ascii=False).encode('utf8'),
        headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(request, timeout=timeout) as response:
        obj = json.loads(response.read(2_500_000))
    if not isinstance(obj, dict):
        raise ValueError('Ollama returned non-object result')
    return obj


def chat(goal: str, history: list[dict], timeout=180, pending_checks=None, plan=None, verified_files=None, remaining_steps=None) -> dict:
    context = {'goal': goal[:1500], 'recent_tool_results': history[-10:],
        'pending_file_checks': sorted(pending_checks or []), 'verified_files': sorted(verified_files or []),
        'current_plan': plan or {}, 'remaining_steps': remaining_steps,
        'stage_hint': ('Begin with a short plan, then act' if not history
                       else 'Continue from last tool result; do not repeat read-only calls without file changes.')}
    if context['pending_file_checks']:
        context['stage_hint'] = ('Modified files need checking: '+', '.join(context['pending_file_checks'])+
                                 '. Use check_file on each, then finish. Never call list_files as a substitute.')
    elif context['verified_files']:
        context['stage_hint'] = ('Checks passed for '+', '.join(context['verified_files'])+
                                 '. If all planned files exist and meet acceptance criteria, call finish now; '
                                 'do not list files again. Otherwise create or check the next missing file.')
    if history and history[-1].get('action') == 'list_files':
        context['stage_hint'] += ' You have just listed the files. Do not call list_files again.'
    messages = [{'role':'system', 'content':SYS},
                {'role':'user', 'content':json.dumps(context, ensure_ascii=False)}]
    common = {'model': MODEL, 'messages': messages, 'stream':False,
              'options': {'temperature':0.1, 'num_ctx':8192, 'num_predict':2400}, 'keep_alive':'5m'}
    # First try Ollama's native tool-call channel (Qwen3-Coder declares tool support).
    first = dict(common, tools=TOOLS)
    first_error = None
    try:
        return _decision_from_response(_ollama(first, timeout))
    except urllib.error.HTTPError as exc:
        if exc.code not in (400, 422):
            raise
        first_error = f'Native tool interface rejected HTTP {exc.code}'
    except ValueError as exc:
        first_error = str(exc)
    # Recovery: require a strict schema and ask for *one* decision only.
    retry = dict(common, format=FALLBACK_SCHEMA)
    retry['messages'] = messages + [{'role':'user', 'content':
        'The preceding decision had an invalid interface: '+first_error[:180]+
        '. Return ONE JSON object with action, args, reason, confidence. '
        'Use only allowed actions and an object for args; no explanation outside JSON.'}]
    try:
        return _decision_from_response(_ollama(retry, timeout))
    except ValueError as exc:
        raise ValueError('Model returned invalid action envelope after native-tool and schema attempts: '
                         + str(exc)[:160]) from exc


def ollama_health():
    with urllib.request.urlopen('http://127.0.0.1:11434/api/tags',timeout=4) as response:
        data=json.loads(response.read(250000))
    return {'reachable':True, 'model_installed':any(x.get('name')==MODEL for x in data.get('models',[]))}
