"""Deterministic OpenAI-compatible structured-output stub for integration CI."""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any


_request_lock = Lock()
_request_count = 0


def _value_for(schema: dict[str, Any], root: dict[str, Any]) -> Any:
    if "$ref" in schema:
        node: Any = root
        for part in schema["$ref"].removeprefix("#/").split("/"):
            if part:
                node = node[part]
        return _value_for(node, root)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    for branch in schema.get("anyOf", []):
        if branch.get("type") != "null":
            return _value_for(branch, root)
    kind = schema.get("type")
    if kind == "object" or "properties" in schema:
        required = set(schema.get("required", []))
        return {
            key: _value_for(value, root)
            for key, value in schema.get("properties", {}).items()
            if key in required or "default" not in value
        }
    if kind == "array":
        return [
            _value_for(schema.get("items", {}), root)
            for _ in range(int(schema.get("minItems", 0)))
        ]
    if kind == "boolean":
        return False
    if kind in {"integer", "number"}:
        return schema.get("minimum", 0)
    return schema.get("default", "deterministic integration response")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/stats":
            with _request_lock:
                count = _request_count
            self._send({"request_count": count})
            return
        self._send({"object": "list", "data": []})

    def do_POST(self) -> None:  # noqa: N802
        global _request_count
        if self.path == "/reset":
            with _request_lock:
                _request_count = 0
            self._send({"request_count": 0})
            return
        with _request_lock:
            _request_count += 1
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        model = request.get("model", "integration-model")
        message: dict[str, Any] = {"role": "assistant", "content": None}

        tools = request.get("tools") or []
        if tools:
            function = tools[0]["function"]
            schema = function.get("parameters", {})
            message["tool_calls"] = [
                {
                    "id": "integration-tool-call",
                    "type": "function",
                    "function": {
                        "name": function["name"],
                        "arguments": json.dumps(_value_for(schema, schema)),
                    },
                }
            ]
            finish_reason = "tool_calls"
        else:
            schema = (
                request.get("response_format", {})
                .get("json_schema", {})
                .get("schema", {"type": "object"})
            )
            message["content"] = json.dumps(_value_for(schema, schema))
            finish_reason = "stop"

        self._send(
            {
                "id": "chatcmpl-integration",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": finish_reason,
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 10,
                    "total_tokens": 20,
                },
            }
        )

    def _send(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
