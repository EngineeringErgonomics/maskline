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
stderr hold counts only.
"""

from __future__ import annotations

import json
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


class MasklineServer:
    def __init__(self, root: str, rules_name=None):
        self.root = root
        self.rules, self.settings = load_rules(rules_name)

    def call_tool(self, name: str, arguments: dict):
        if name == "scan_text":
            text = arguments.get("text", "")
            if not isinstance(text, str):
                raise ValueError("text must be a string")
            if not text:
                result = scan_text(text, self.rules, self.settings)
                return result.as_tool_dict()
            result = scan_text(text, self.rules, self.settings)
            return result.as_tool_dict()
        if name == "scan_file":
            path = arguments.get("path", "")
            if not isinstance(path, str) or not path:
                raise ValueError("path must be a non-empty string")
            result = scan_file(path, self.root, self.rules, self.settings)
            return result.as_tool_dict()
        raise ValueError("unknown tool: " + name)


def _log(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def handle_message(server: MasklineServer, message: dict):
    """Return the JSON-RPC reply object, or None for a notification."""
    method = message.get("method", "")
    request_id = message.get("id")
    if request_id is None:
        return None  # notification: no reply
    if method == "initialize":
        params = message.get("params", {}) or {}
        client_version = params.get("protocolVersion", PROTOCOL_VERSION)
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": client_version
                if isinstance(client_version, str) and client_version
                else PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = message.get("params", {}) or {}
        name = params.get("name", "")
        arguments = params.get("arguments", {}) or {}
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
        except (ScanRefused, ValueError) as exc:
            _log("tool=" + name + " refused")
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def serve(server: MasklineServer, instream, outstream) -> None:
    for raw in instream:
        if raw is None:
            continue
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            reply = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            outstream.write(json.dumps(reply) + "\n")
            outstream.flush()
            continue
        if not isinstance(message, dict):
            continue
        reply = handle_message(server, message)
        if reply is not None:
            outstream.write(json.dumps(reply) + "\n")
            outstream.flush()


def _parse_cli(argv: list[str]):
    """Return (mode, root, filepath, write_path, rules) or exit 2."""
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


def _demo(root: str, rules) -> int:
    base = Path(root).resolve() if root != "." else Path(__file__).resolve().parent
    # The demo scans the bundled examples. The root for scan_file is
    # this repository folder.
    repo_root = str(base)
    examples = [
        "examples/clean-build-log.txt",
        "examples/trace-leak-log.txt",
        "examples/agent-transcript.txt",
    ]
    out_folder = Path.cwd() / "redacted"
    out_folder.mkdir(parents=True, exist_ok=True)
    worst = 0
    _server = MasklineServer(repo_root, rules)
    for rel in examples:
        try:
            result = scan_file(rel, repo_root, _server.rules, _server.settings)
        except ScanRefused as exc:
            sys.stdout.write("maskline report: " + rel + "\nRefused: " + str(exc) + "\n")
            print("exit: 2")
            worst = max(worst, 2)
            print("")
            continue
        print(format_report(rel, result))
        code = 1 if result.findings else 0
        print("exit: " + str(code))
        worst = max(worst, code)
        name = Path(rel).stem + ".redacted.txt"
        (out_folder / name).write_text(result.redacted_text, encoding="utf-8")
        print("")
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
        server = MasklineServer(root, rules)
        serve(server, sys.stdin, sys.stdout)
        return 0
    if len(rest) > 1:
        _log("usage error: scan one file at a time")
        return 2
    filepath = rest[0]
    if filepath.startswith("-"):
        _log("usage error: unknown option")
        return 2
    server = MasklineServer(root, rules)
    try:
        result = scan_file(filepath, root, server.rules, server.settings)
    except ScanRefused as exc:
        _log(str(exc))
        return 2
    sys.stdout.write(format_report(filepath, result) + "\n")
    if write_path:
        Path(write_path).write_text(result.redacted_text, encoding="utf-8")
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
