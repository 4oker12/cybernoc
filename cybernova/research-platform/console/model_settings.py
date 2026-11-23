"""Safe local settings for the active Cybernova researcher model.

API keys are stored outside the repository in the native data directory. They
are never returned by the HTTP API or written to runtime.env.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from urllib import parse

try:
    from .agent import OLLAMA_URL, OllamaClient
    from .model_providers import ModelConfigError, OpenAICompatibleClient
except ImportError:
    from agent import OLLAMA_URL, OllamaClient
    from model_providers import ModelConfigError, OpenAICompatibleClient

_VALID_MODEL = re.compile(r"^[A-Za-z0-9_.:/+-]{1,160}$")
_ALLOWED_ENV = frozenset({
    "CYBERNOVA_LLM_PROVIDER", "CYBERNOVA_MODEL", "CYBERNOVA_LLM_BASE_URL",
    "CYBERNOVA_LLM_API_KEY_FILE", "CYBERNOVA_OLLAMA_URL", "CYBERNOVA_COMM_DB",
    "CYBERNOVA_BACKUP_KEY_FILE", "CYBERNOVA_ACCESS_SECRET_FILE",
    "CYBERNOVA_HTTP_SCOPE_FILE", "CYBERNOVA_ACCESS_HOST",
    "CYBERNOVA_MCP_URL", "CYBERNOVA_COMM_WORKER",
})


class ModelSettingsError(ValueError):
    """Safe, user-displayable model settings error."""


def _data_dir() -> Path:
    database = os.environ.get("CYBERNOVA_COMM_DB", "").strip()
    key_file = os.environ.get("CYBERNOVA_LLM_API_KEY_FILE", "").strip()
    source = database or key_file
    if not source:
        raise ModelSettingsError("native_data_directory_not_configured")
    path = Path(source).expanduser().absolute()
    data = path.parent
    if data.is_symlink() or not data.is_dir():
        raise ModelSettingsError("native_data_directory_unavailable")
    return data


def _read_runtime_env(data: Path) -> tuple[Path, dict[str, str]]:
    path = data / "runtime.env"
    if path.is_symlink() or not path.is_file():
        raise ModelSettingsError("runtime_configuration_unavailable")
    if path.stat().st_size > 65536:
        raise ModelSettingsError("runtime_configuration_too_large")
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise ModelSettingsError("runtime_configuration_unreadable") from None
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ModelSettingsError("runtime_configuration_invalid")
        name, value = line.split("=", 1)
        if name not in _ALLOWED_ENV or any(ord(char) < 32 for char in value):
            raise ModelSettingsError("runtime_configuration_invalid")
        values[name] = value
    if values.get("CYBERNOVA_LLM_PROVIDER") not in {"ollama", "openai_compatible"}:
        raise ModelSettingsError("runtime_provider_invalid")
    return path, values


def _key_path(data: Path, values: dict[str, str]) -> Path:
    configured = values.get("CYBERNOVA_LLM_API_KEY_FILE", "").strip()
    path = Path(configured).expanduser() if configured else data / "model_api_key"
    if not path.is_absolute():
        path = data / path
    try:
        if path.parent.resolve() != data.resolve():
            raise ModelSettingsError("api_key_path_outside_data_directory")
    except OSError:
        raise ModelSettingsError("api_key_path_invalid") from None
    return path


def _read_key(path: Path) -> str:
    if path.is_symlink():
        raise ModelSettingsError("api_key_file_invalid")
    if not path.exists():
        return ""
    if not path.is_file() or path.stat().st_size > 10000:
        raise ModelSettingsError("api_key_file_invalid")
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        raise ModelSettingsError("api_key_file_unreadable") from None


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(path.name + ".tmp-" + secrets.token_hex(8))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(str(temporary), flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def get_model_settings() -> dict:
    data = _data_dir()
    _, values = _read_runtime_env(data)
    provider = os.environ.get("CYBERNOVA_LLM_PROVIDER", values.get("CYBERNOVA_LLM_PROVIDER", "ollama"))
    model = os.environ.get("CYBERNOVA_MODEL", values.get("CYBERNOVA_MODEL", ""))
    base_url = os.environ.get("CYBERNOVA_LLM_BASE_URL", values.get("CYBERNOVA_LLM_BASE_URL", ""))
    key_path = _key_path(data, values)
    configured = bool(os.environ.get("CYBERNOVA_LLM_API_KEY", "").strip() or _read_key(key_path))
    return {
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "api_key_configured": configured,
        "api_key_hint": "Ключ сохранён локально" if configured else "Ключ не задан",
        "restart_required": False,
    }


def test_model_connection(payload: dict) -> dict:
    """Verify DeepSeek credentials and model availability without a billable completion."""
    if not isinstance(payload, dict):
        raise ModelSettingsError("invalid_model_settings")
    if payload.get("provider") != "openai_compatible":
        return {"status": "not_required"}
    base_url = payload.get("base_url", "")
    if not isinstance(base_url, str):
        raise ModelSettingsError("invalid_model_base_url")
    try:
        parsed = parse.urlsplit(base_url)
    except ValueError:
        raise ModelSettingsError("invalid_model_base_url") from None
    if parsed.hostname != "api.deepseek.com":
        return {"status": "not_checked", "provider": "openai_compatible"}
    model = payload.get("model")
    if not isinstance(model, str) or not _VALID_MODEL.fullmatch(model.strip()):
        raise ModelSettingsError("invalid_model_id")
    supplied_key = payload.get("api_key")
    if isinstance(supplied_key, str) and supplied_key.strip():
        api_key = supplied_key.strip()
    else:
        data = _data_dir()
        _, values = _read_runtime_env(data)
        key_path = _key_path(data, values)
        api_key = _read_key(key_path) or os.environ.get("CYBERNOVA_LLM_API_KEY", "").strip()
    if api_key and (
        not 8 <= len(api_key) <= 10000 or any(ord(char) < 32 for char in api_key)
    ):
        raise ModelSettingsError("invalid_api_key")
    try:
        client = OpenAICompatibleClient(
            base_url=base_url.strip(), model=model.strip(), api_key=api_key,
        )
        model_ids = client.list_models()
    except ModelConfigError as exc:
        code = str(exc)
        if code.endswith("_401") or code.endswith("_403"):
            raise ModelSettingsError("deepseek_authentication_failed") from None
        if code.endswith("_429"):
            raise ModelSettingsError("deepseek_rate_limited") from None
        if code in {"remote_api_key_required", "llm_base_url_required", "invalid_llm_url",
                    "remote_model_requires_https"}:
            raise ModelSettingsError(code) from None
        raise ModelSettingsError("deepseek_connection_failed") from None
    if model.strip() not in model_ids:
        raise ModelSettingsError("deepseek_model_not_available")
    return {"status": "connected", "provider": "DeepSeek", "model": model.strip()}


def apply_model_settings(payload: dict):
    if not isinstance(payload, dict):
        raise ModelSettingsError("invalid_model_settings")
    provider = payload.get("provider")
    model = payload.get("model")
    base_url = payload.get("base_url", "")
    api_key = payload.get("api_key")
    clear_api_key = payload.get("clear_api_key", False)
    if provider not in {"ollama", "openai_compatible"}:
        raise ModelSettingsError("invalid_model_provider")
    if not isinstance(model, str) or not _VALID_MODEL.fullmatch(model.strip()):
        raise ModelSettingsError("invalid_model_id")
    model = model.strip()
    if not isinstance(base_url, str) or len(base_url) > 500 or any(ord(c) < 32 for c in base_url):
        raise ModelSettingsError("invalid_model_base_url")
    if type(clear_api_key) is not bool:
        raise ModelSettingsError("invalid_clear_api_key")
    if api_key is not None and not isinstance(api_key, str):
        raise ModelSettingsError("invalid_api_key")
    if api_key is not None and clear_api_key:
        raise ModelSettingsError("choose_api_key_update_or_clear")
    if api_key is not None:
        api_key = api_key.strip()
        if api_key and (not 8 <= len(api_key) <= 10000 or any(ord(c) < 32 for c in api_key)):
            raise ModelSettingsError("invalid_api_key")

    data = _data_dir()
    env_path, values = _read_runtime_env(data)
    key_path = data / "model_api_key"
    old_key = _read_key(key_path)
    if clear_api_key:
        next_key = ""
    elif api_key:
        next_key = api_key
    else:
        next_key = old_key or os.environ.get("CYBERNOVA_LLM_API_KEY", "").strip()

    if provider == "openai_compatible":
        if not base_url.strip():
            raise ModelSettingsError("llm_base_url_required")
        # Constructor validates HTTPS, URL shape, model and remote key without
        # making a network request or disclosing the supplied credential.
        try:
            client = OpenAICompatibleClient(
                base_url=base_url.strip(), model=model, api_key=next_key,
            )
        except (ModelConfigError, ValueError) as exc:
            raise ModelSettingsError(str(exc)) from None
        base_url = base_url.strip()
    else:
        if base_url.strip():
            raise ModelSettingsError("base_url_only_for_remote_models")
        client = OllamaClient(
            endpoint=os.environ.get("CYBERNOVA_OLLAMA_URL", OLLAMA_URL),
            model=model,
        )
        base_url = ""

    values.update({
        "CYBERNOVA_LLM_PROVIDER": provider,
        "CYBERNOVA_MODEL": model,
        "CYBERNOVA_LLM_BASE_URL": base_url,
        "CYBERNOVA_LLM_API_KEY_FILE": str(key_path) if provider == "openai_compatible" else "",
    })
    encoded = "".join(name + "=" + value + "\n" for name, value in values.items())
    if len(encoded.encode("utf-8")) > 65536:
        raise ModelSettingsError("runtime_configuration_too_large")

    previous_key = old_key
    inline_key = os.environ.get("CYBERNOVA_LLM_API_KEY", "").strip()
    key_changed = clear_api_key or bool(api_key) or (
        provider == "openai_compatible" and not old_key and bool(inline_key)
    )
    try:
        if key_changed:
            if next_key:
                _atomic_write(key_path, next_key + "\n")
            elif key_path.exists():
                if key_path.is_symlink():
                    raise ModelSettingsError("api_key_file_invalid")
                key_path.unlink()
        _atomic_write(env_path, encoded)
    except OSError:
        # Restore the previous credential if the config write did not commit.
        try:
            if key_changed:
                if previous_key:
                    _atomic_write(key_path, previous_key + "\n")
                elif key_path.exists() and not key_path.is_symlink():
                    key_path.unlink()
        except OSError:
            pass
        raise ModelSettingsError("model_settings_write_failed") from None

    os.environ["CYBERNOVA_LLM_PROVIDER"] = provider
    os.environ["CYBERNOVA_MODEL"] = model
    os.environ["CYBERNOVA_LLM_BASE_URL"] = base_url
    os.environ["CYBERNOVA_LLM_API_KEY_FILE"] = (
        str(key_path) if provider == "openai_compatible" else ""
    )
    os.environ.pop("CYBERNOVA_LLM_API_KEY", None)
    return client, get_model_settings()
