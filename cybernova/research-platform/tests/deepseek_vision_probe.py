"""Opt-in paid live probe of native DeepSeek tool-result image input.

Only a synthetic PNG is transmitted. No browser, desktop or personal data is
captured. Uses existing local model configuration without printing credentials.
Run: python tests/deepseek_vision_probe.py --data-dir PATH
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import struct
import sys
import time
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console.model_providers import OpenAICompatibleClient, ModelConfigError
from console.model_settings import _read_runtime_env, _key_path, _read_key, ModelSettingsError

COLORS = {
    "red": (240, 30, 30), "green": (0, 170, 0), "blue": (30, 80, 240),
    "yellow": (255, 230, 0), "black": (0, 0, 0), "white": (255, 255, 255),
    "purple": (150, 0, 180), "orange": (255, 130, 0),
}


def make_png(order):
    width, height = len(order) * 80 + 10, 100
    row = bytearray()
    for x in range(width):
        index, offset = divmod(x - 10, 80)
        row.extend(COLORS[order[index]] if 0 <= index < len(order) and offset < 70 else (135, 135, 135))
    gray = bytes((135, 135, 135)) * width
    pixels = b"".join(b"\0" + (bytes(row) if 15 <= y < 85 else gray) for y in range(height))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    options = parser.parse_args()
    started = time.monotonic()
    try:
        data = options.data_dir.resolve()
        _, config = _read_runtime_env(data)
        if config.get("CYBERNOVA_LLM_PROVIDER") != "openai_compatible":
            raise ModelConfigError("probe_requires_deepseek_api")
        for key in ("CYBERNOVA_DEEPSEEK_THINKING", "CYBERNOVA_DEEPSEEK_REASONING_EFFORT"):
            if key in config:
                os.environ[key] = config[key]
        client = OpenAICompatibleClient(base_url=config["CYBERNOVA_LLM_BASE_URL"],
                                        model=config["CYBERNOVA_MODEL"],
                                        api_key=_read_key(_key_path(data, config)))
        if not client.supports_tool_images:
            raise ModelConfigError("probe_requires_supported_deepseek_flash_endpoint")
        order = secrets.SystemRandom().sample(list(COLORS), 6)
        image = "data:image/png;base64," + base64.b64encode(make_png(order)).decode("ascii")
        tools = [{"type": "function", "function": {
            "name": "vision_probe_capture", "description": "Return the synthetic test image.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        }}]
        messages = [{"role": "user", "content":
            "Call vision_probe_capture once. Read the image it returns. "
            "Report the six rectangle colors from left to right, separated by commas, "
            "using English color names only. Ignore gray gutters. Do not guess."}]
        first = client.chat(messages, tools)
        calls = first.get("tool_calls") or []
        if len(calls) != 1 or calls[0]["function"]["name"] != "vision_probe_capture":
            raise ModelConfigError("probe_tool_call_not_observed")
        assistant = {"role": "assistant", "content": first["content"], "tool_calls": calls}
        if "reasoning_content" in first:
            assistant["reasoning_content"] = first["reasoning_content"]
        messages.extend([assistant, {"role": "tool", "content": [
            {"type": "text", "text": "Synthetic test image. No color labels are provided."},
            {"type": "image_url", "image_url": {"url": image, "detail": "high"}},
        ]}])
        second = client.chat(messages, tools)
        answer = second.get("content", "")
        observed = re.findall(r"\b(?:" + "|".join(COLORS) + r")\b", answer.lower())
        passed = observed == order
        print(json.dumps({"model": client.model, "native_tool_image": True,
                          "passed": passed, "expected": order, "observed": observed,
                          "usage": [first.get("_usage"), second.get("_usage")],
                          "elapsed_seconds": round(time.monotonic() - started, 2)}, indent=2))
        return 0 if passed else 1
    except (ModelConfigError, ModelSettingsError, OSError, KeyError) as exc:
        # No raw response, file paths, credentials or request payloads in output.
        code = str(exc) if isinstance(exc, (ModelConfigError, ModelSettingsError)) else type(exc).__name__
        print(json.dumps({"passed": False, "error": code}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
