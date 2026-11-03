#!/usr/bin/env python3
"""maskline MCP stdio server and plain command line mode.

Use:
  python3 server.py [--root FOLDER]      MCP tools over stdio
  python3 server.py --demo                scan three bundled examples
  python3 server.py FILE [--write PATH] [--root FOLDER]
                                          scan one file, print the report

Exit codes (command line mode): 0 = no findings, 1 = findings,
2 = usage error or a refused file.

The server speaks the subset of the MCP stdio JSON-RPC protocol that
two tools need (initialize, tools/list, tools/call). No secret value
is printed, logged, or put into an error text. Server log lines on
stderr hold counts only. The server never exits on malformed input:
it replies with a JSON-RPC error and continues.
"""

from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from maskline import (  # noqa: E402
    ScanRefused,
    format_report,
    load_rules,
    scan_file,
    scan_text,
)

SERVER_NAME = "maskline"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({PROTOCOL_VERSION, "2025-06-18"})

TOOLS = [
    {
        "name": "scan_text",
        "description": (
            "Scan text for leaked secret shapes and return findings "
            "plus a redacted copy. The secret values stay out of the "
            "result; each finding holds the line number, the rule "
            "name and a masked form."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan"}
            },
            "required": ["text"],
        },
    },
    {
        "name": "scan_file",
        "description": (
            "Scan one text file below the server root folder for "
            "leaked secret shapes and return findings plus a redacted "
            "copy. The server reads no file outside the root folder."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path of the file, relative to the root folder",
                }
            },
            "required": ["path"],
        },
    },
]

KNOWN_TOOLS = frozenset(t["name"] for t in TOOLS)


class MasklineError(Exception):
    """Invalid tool arguments. The text is fixed and holds no input."""


class MasklineServer:
    def __init__(self, root: str, rules_name=None):
        self.root = root
        self.rules, self.settings = load_rules(rules_name)

    def call_tool(self, name, arguments):
        if name not in KNOWN_TOOLS:
            raise MasklineError("unknown tool")
        if not isinstance(arguments, dict):
            raise MasklineError("arguments must be an object")
        if name == "scan_text":
            text = arguments.get("text", "")
            if not isinstance(text, str):
                raise MasklineError("text must be a string")
            result = scan_text(text, self.rules, self.settings)
            return result.as_tool_dict()
        if name == "scan_file":
            path = arguments.get("path", "")
            if not isinstance(path, str) or not path:
                raise MasklineError("path must be a non-empty string")
            result = scan_file(path, self.root, self.rules, self.settings)
            return result.as_tool_dict()
        raise MasklineError("unknown tool")


def _log(message: str) -> None:
    try:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def _as_bytes(stream):
    """Return a binary stream for any sys.stdin replacement."""
    buf = getattr(stream, "buffer", None)
    if buf is not None and isinstance(buf, (io.RawIOBase, io.BufferedIOBase)):
        return buf
    if isinstance(stream, (io.RawIOBase, io.BufferedIOBase, io.BytesIO)):
        return stream
    data = stream.read()
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return io.BytesIO(data or b"")


def _error_reply(request_id, code, message):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _valid_id(value) -> bool:
    """JSON-RPC ids are a string, an integer or null (N3)."""
    return value is None or isinstance(value, (str, int)) and not isinstance(value, bool)


def handle_message(server: MasklineServer, message):
    """Return the JSON-RPC reply object, or None for a notification.

    Never raises. A bad shape gives a fixed error reply. No text of
    the caller reaches a result, an error or a log line, except a
    valid request id that JSON-RPC requires in the reply.
    """
    has_id = isinstance(message, dict) and "id" in message
    raw_id = message.get("id") if has_id else None
    request_id = raw_id if _valid_id(raw_id) else None
    try:
        if not isinstance(message, dict):
            return _error_reply(None, -32600, "Invalid Request")
        is_notification = not has_id
        # A notification never gets a reply, even a bad one.
        if is_notification:
            return None
        if not _valid_id(raw_id):
            return _error_reply(None, -32600, "Invalid Request")
        if message.get("jsonrpc") != "2.0":
            return _error_reply(request_id, -32600, "Invalid Request")
        method = message.get("method")
        if not isinstance(method, str) or not method:
            return _error_reply(request_id, -32600, "Invalid Request")
        if method == "initialize":
            params = message.get("params")
            if params is not None and not isinstance(params, dict):
                return _error_reply(request_id, -32602, "Invalid params")
            client_version = (
                (params or {}).get("protocolVersion")
                if isinstance(params, dict)
                else None
            )
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": client_version
                    if client_version in SUPPORTED_PROTOCOL_VERSIONS
                    else PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": TOOLS},
            }
        if method == "tools/call":
            params = message.get("params")
            if not isinstance(params, dict):
                return _error_reply(request_id, -32602, "Invalid params")
            name = params.get("name")
            if name not in KNOWN_TOOLS:
                _log("tool=<unknown> refused")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "unknown tool"}],
                        "isError": True,
                    },
                }
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                _log("tool=" + name + " refused")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": "arguments must be an object",
                            }
                        ],
                        "isError": True,
                    },
                }
            try:
                payload = server.call_tool(name, arguments)
                content = json.dumps(payload, sort_keys=True)
                _log(
                    "tool="
                    + name
                    + " findings="
                    + str(len(payload["findings"]))
                )
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": content}],
                        "isError": False,
                    },
                }
            except (ScanRefused, MasklineError) as exc:
                _log("tool=" + name + " refused")
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": str(exc)}],
                        "isError": True,
                    },
                }
        return _error_reply(request_id, -32601, "Method not found")
    except Exception:
        # Last catch: a fixed text only. No exception text, no path,
        # no input. A notification still gets no reply.
        if not has_id:
            return None
        return _error_reply(request_id, -32603, "Internal error")


def serve(server: MasklineServer, instream, outstream) -> None:
    """Read newline JSON-RPC over stdio until the input ends.

    Never exits on malformed input. Reads bytes and decodes UTF-8 per
    line, so a bad line gives a parse error and the next line runs.
    A message that is not an object gets an Invalid Request reply.
    """
    binary = _as_bytes(instream)

    def emit(reply) -> None:
        try:
            line = json.dumps(reply, allow_nan=False)
        except Exception:
            line = json.dumps(
                _error_reply(None, -32603, "Internal error"),
                allow_nan=False,
            )
        try:
            outstream.write(line + "\n")
            outstream.flush()
        except (OSError, ValueError):
            pass

    while True:
        try:
            raw = binary.readline()
        except (OSError, ValueError):
            break
        if not raw:
            break
        try:
            text = raw.decode("utf-8", errors="strict")
        except (UnicodeDecodeError, AttributeError):
            emit(_error_reply(None, -32700, "Parse error"))
            continue
        line = text.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError):
            emit(_error_reply(None, -32700, "Parse error"))
            continue
        if not hasattr(message, "keys") or not isinstance(message, dict):
            emit(_error_reply(None, -32600, "Invalid Request"))
            continue
        reply = handle_message(server, message)
        if reply is not None:
            emit(reply)


def _parse_cli(argv: list[str]):
    """Return (rest, root, write_path, rules)."""
    root = "."
    rules = None
    write_path = None
    rest: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--root" and i + 1 < len(argv):
            root = argv[i + 1]
            i += 2
        elif arg == "--rules" and i + 1 < len(argv):
            rules = argv[i + 1]
            i += 2
        elif arg == "--write" and i + 1 < len(argv):
            write_path = argv[i + 1]
            i += 2
        elif arg.startswith("--root="):
            root = arg.split("=", 1)[1]
            i += 1
        elif arg.startswith("--rules="):
            rules = arg.split("=", 1)[1]
            i += 1
        elif arg.startswith("--write="):
            write_path = arg.split("=", 1)[1]
            i += 1
        else:
            rest.append(arg)
            i += 1
    return rest, root, write_path, rules


_SAFE_DISPLAY_RE = re.compile(
    r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|PWD|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"PRIVATE[_-]?KEY|CREDENTIAL)"
)


def display_name(name: str) -> str:
    """A safe display form of a file name for a report header (B2).

    Only the base name is considered, and the folder part is never
    printed. Every run of 17 or more characters of letters, digits
    and the secret delimiters is masked by the same rule as a
    finding (at most 2 characters at each end); when the name holds
    a secret-looking keyword, shorter runs are masked too. No other
    character can defeat the mask.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    if not base:
        return "<file>"

    def _mask(run: str) -> str:
        if len(run) <= 16:
            return "****"
        return run[:2] + "****" + run[-2:]

    masked = re.sub(
        r"[A-Za-z0-9+/_=-]{17,}", lambda m: _mask(m.group(0)), base
    )
    if _SAFE_DISPLAY_RE.search(base):
        masked = re.sub(
            r"[A-Za-z0-9+/_=-]{8,}", lambda m: _mask(m.group(0)), masked
        )
    return masked


def _demo(root: str, rules) -> int:
    base = Path(root).resolve() if root != "." else Path(__file__).resolve().parent
    repo_root = str(base)
    examples = [
        "examples/clean-build-log.txt",
        "examples/trace-leak-log.txt",
        "examples/agent-transcript.txt",
    ]
    try:
        out_folder = Path.cwd() / "redacted"
        out_folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        _log("usage error: cannot create the redacted folder")
        return 2
    worst = 0
    try:
        _server = MasklineServer(repo_root, rules)
    except Exception:
        _log("usage error: cannot load the rules file")
        return 2
    blocks: list[str] = []
    for rel in examples:
        try:
            result = scan_file(rel, repo_root, _server.rules, _server.settings)
        except ScanRefused as exc:
            blocks.append(
                "maskline report: "
                + rel
                + "\nRefused: "
                + str(exc)
                + "\nexit: 2"
            )
            worst = max(worst, 2)
            continue
        code = 1 if result.findings else 0
        blocks.append(format_report(rel, result) + "\nexit: " + str(code))
        worst = max(worst, code)
        name = Path(rel).stem + ".redacted.txt"
        try:
            (out_folder / name).write_text(result.redacted_text, encoding="utf-8")
        except OSError:
            _log("usage error: cannot write the redacted copy")
            return 2
    sys.stdout.write("\n\n".join(blocks) + "\n")
    return worst


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rest, root, write_path, rules = _parse_cli(argv)
    if "--demo" in rest:
        return _demo(root, rules)
    if rest and rest[0] in ("-h", "--help"):
        sys.stdout.write(__doc__ or "")
        return 0
    if not rest:
        if write_path:
            _log("usage error: --write needs a file to scan")
            return 2
        try:
            server = MasklineServer(root, rules)
        except Exception:
            _log("usage error: cannot load the rules file")
            return 2
        try:
            serve(server, sys.stdin, sys.stdout)
        except KeyboardInterrupt:
            return 130
        return 0
    if len(rest) > 1:
        _log("usage error: scan one file at a time")
        return 2
    filepath = rest[0]
    if filepath.startswith("-"):
        _log("usage error: unknown option")
        return 2
    try:
        server = MasklineServer(root, rules)
    except Exception:
        _log("usage error: cannot load the rules file")
        return 2
    try:
        result = scan_file(filepath, root, server.rules, server.settings)
    except ScanRefused as exc:
        _log(str(exc))
        return 2
    sys.stdout.write(format_report(display_name(filepath), result) + "\n")
    if write_path:
        try:
            Path(write_path).write_text(result.redacted_text, encoding="utf-8")
        except OSError:
            _log("usage error: cannot write the redacted copy")
            return 2
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
