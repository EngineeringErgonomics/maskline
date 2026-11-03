#!/usr/bin/env python3
"""Scripted MCP client for maskline.

Starts `python3 server.py` over stdio, runs initialize, tools/list and
tools/call for both tools, and asserts the mask rule: no full secret
value appears in any result or in the server error log.

Use: python3 tools/mcp_client.py [--server PATH] [--root FOLDER]

Exits 0 when the checks pass, 1 when a check fails. Synthetic secret
values are built from adjacent string fragments at run time.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Fragment-built synthetic values. No strong shape is one literal.
_FAKE_KEY = "EXAMPLE" + "FAKE" + "KEY" + "DONOT" + "USE" + "123456"
_FAKE_TOK = "EXAMPLEFAKE" + "BEARERTOKEN0123456789"
_FRAG_GH = "g" + "h" + "p" + "_" + "Ab1c" * 9


class Client:
    def __init__(self, server_path: str, root: str):
        self.proc = subprocess.Popen(
            [sys.executable, server_path, "--root", root],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._next_id = 1

    def _send(self, payload: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        assert self.proc.stdout is not None
        rid = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}})
        line = self.proc.stdout.readline()
        if not line:
            raise SystemExit("server closed the stream without a reply")
        return json.loads(line)

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": {}})

    def close(self) -> str:
        assert self.proc.stdin is not None and self.proc.stderr is not None
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        return self.proc.stderr.read()


def _fail(text: str) -> int:
    print("FAIL: " + text)
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    server_path = str(Path(__file__).resolve().parent.parent / "server.py")
    root = str(Path.cwd())
    i = 0
    while i < len(argv):
        if argv[i] == "--server" and i + 1 < len(argv):
            server_path = argv[i + 1]
            i += 2
        elif argv[i] == "--root" and i + 1 < len(argv):
            root = argv[i + 1]
            i += 2
        else:
            i += 1

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        sample = tmp_path / "sample.txt"
        sample.write_text(
            "hello\n"
            "+ export API_KEY=" + _FAKE_KEY + "\n"
            "Authorization: Bearer " + _FAKE_TOK + "\n"
            "token " + _FRAG_GH + " seen here\n",
            encoding="utf-8",
        )
        client = Client(server_path, root)

        init = client.request(
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {},
             "clientInfo": {"name": "mcp_client", "version": "1.0"}},
        )
        if init.get("result", {}).get("serverInfo", {}).get("name") != "maskline":
            return _fail("initialize did not name the maskline server")
        print("initialize: ok (server maskline)")

        client.notify("notifications/initialized")

        listed = client.request("tools/list")
        names = [t["name"] for t in listed.get("result", {}).get("tools", [])]
        if names != ["scan_text", "scan_file"]:
            return _fail("tools/list gave " + str(names))
        print("tools/list: ok (scan_text, scan_file)")

        call = client.request(
            "tools/call",
            {"name": "scan_text",
             "arguments": {"text": "Authorization: Bearer " + _FAKE_TOK + "\n"}},
        )
        result = call.get("result", {})
        if result.get("isError"):
            return _fail("scan_text call was an error")
        text_out = result["content"][0]["text"]
        payload = json.loads(text_out)
        if len(payload["findings"]) != 1 or payload["findings"][0]["rule"] != "bearer-token":
            return _fail("scan_text did not give one bearer-token finding")
        if _FAKE_TOK in text_out:
            return _fail("scan_text leaked a secret value")
        print("tools/call scan_text: ok (1 finding, value masked)")

        try:
            rel = str(sample.relative_to(Path(root).resolve()))
        except ValueError:
            rel = str(sample)
        call2 = client.request(
            "tools/call", {"name": "scan_file", "arguments": {"path": rel}}
        )
        result2 = call2.get("result", {})
        if result2.get("isError", True):
            # The sample is in a temporary folder. Start a second
            # client whose root is that folder.
            err = client.close()
            client = Client(server_path, str(tmp_path))
            client.request("initialize", {"protocolVersion": "2024-11-05",
                                          "capabilities": {}, "clientInfo":
                                          {"name": "mcp_client", "version": "1.0"}})
            call2 = client.request(
                "tools/call",
                {"name": "scan_file", "arguments": {"path": "sample.txt"}},
            )
            result2 = call2.get("result", {})
            if result2.get("isError"):
                return _fail("scan_file call was an error")
        text_out2 = result2["content"][0]["text"]
        payload2 = json.loads(text_out2)
        if len(payload2["findings"]) != 3:
            return _fail(
                "scan_file gave " + str(len(payload2["findings"]))
                + " findings, 3 expected"
            )
        if _FAKE_KEY in text_out2 or _FRAG_GH in text_out2 or _FAKE_TOK in text_out2:
            return _fail("scan_file leaked a secret value")
        print("tools/call scan_file: ok (3 findings, values masked)")

        unknown = client.request(
            "tools/call", {"name": "does_not_exist", "arguments": {}}
        )
        if not unknown.get("result", {}).get("isError"):
            return _fail("an unknown tool did not give isError")
        print("unknown tool: ok (isError)")

        err_log = client.close()
        if _FAKE_KEY in err_log or _FAKE_TOK in err_log or _FRAG_GH in err_log:
            return _fail("the server error log held a secret value")
        print("server log: ok (counts only)")
    print("mcp_client: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
