"""Tests for maskline. Standard library unittest. No network.

Synthetic secret values are built from adjacent string fragments at
run time, so no strong secret shape appears as one literal. Negative
fixtures cover a long git SHA, a UUID, a base64 image data line, and a
sentence with the word password.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import maskline
import server as mcp_server

REPO = Path(__file__).resolve().parent

# --- Fragment-built synthetic values ---------------------------------------

FAKE_KEY = "EXAMPLE" + "FAKE" + "KEY" + "DONOT" + "USE" + "123456"
FAKE_BEARER = "EXAMPLEFAKE" + "BEARERTOKEN0123456789"
FAKE_ASSIGN = "EXAMPLEFAKE" + "ASSEMBLEDTOKEN9876543210"
FAKE_GH = "g" + "h" + "p" + "_" + "Ab1c" * 9
FAKE_AWS = "A" + "K" + "I" + "A" + "EXAMPLEFAKE1234"
FAKE_SK = "s" + "k" + "-" + "p" + "r" + "oj" + "ExampleFake12345678"
FAKE_XOX = "x" + "o" + "x" + "b" + "-" + "ExampleFake123456"
FAKE_PEM = "-" * 5 + "BEGIN " + "EXAMPLE" + " PRIVATE KEY" + "-" * 5
FAKE_SHORT = "Dead" + "Beef" + "1234"
FAKE_ECHO = "Secret" + "Value" + "987654321"
FAKE_ENTROPY = "xQ7z" + "L9pK" + "mN2v" + "R8sT" + "wZ3y" + "H6jF" + "dG4b" + "qA9e" + "uM1c" + "kP5n"
FAKE_BASIC = "Basic" + "FakeCreds012345"
FAKE_BEARER16 = "AbCd" + "EfGh" + "IjKl" + "MnOp"

GIT_SHA = "abcdef0123456789abcdef0123456789abcdef01"
TEST_UUID = "8f3a2b1c-4d5e-4f60-9a1b-2c3d4e5f6071"
DATA_URL = (
    "data:image/png;base64,"
    + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYA"
    + "AAAAYAAjCB0C8AAAAASUVORK5CYII="
)

RULES, SETTINGS = maskline.load_rules(str(REPO / "rules.toml"))


def scan(text):
    return maskline.scan_text(text, RULES, SETTINGS)


def rule_names(result):
    return [f.rule for f in result.findings]


# --- Rule positive and negative fixtures ------------------------------------


class TestPemPrivateKey(unittest.TestCase):
    def test_detects_pem_header(self):
        result = scan(FAKE_PEM + "\n")
        self.assertIn("pem-private-key", rule_names(result))

    def test_certificate_header_not_flagged(self):
        header = "-" * 5 + "BEGIN CERTIFICATE" + "-" * 5
        result = scan(header + "\n")
        self.assertEqual([], result.findings)


class TestTokenPrefix(unittest.TestCase):
    def test_detects_gh_prefix(self):
        result = scan("token " + FAKE_GH + " seen\n")
        self.assertIn("token-prefix", rule_names(result))
        self.assertNotIn(FAKE_GH, result.redacted_text)

    def test_detects_cloud_prefix(self):
        result = scan("key id " + FAKE_AWS + " in log\n")
        self.assertIn("token-prefix", rule_names(result))

    def test_detects_sk_and_chat_prefix(self):
        self.assertIn("token-prefix", rule_names(scan("k=" + FAKE_SK + "\n")))
        self.assertIn("token-prefix", rule_names(scan("k=" + FAKE_XOX + "\n")))

    def test_plain_word_not_flagged(self):
        result = scan("the token bucket holds the rate\n")
        self.assertEqual([], result.findings)


class TestBearerToken(unittest.TestCase):
    def test_detects_bearer(self):
        text = "Authorization: Bearer " + FAKE_BEARER + "\n"
        result = scan(text)
        self.assertIn("bearer-token", rule_names(result))
        self.assertNotIn(FAKE_BEARER, result.redacted_text)

    def test_short_bearer_token_not_flagged(self):
        result = scan("Authorization: Bearer short\n")
        self.assertEqual([], result.findings)


class TestSecretAssignment(unittest.TestCase):
    def test_detects_assignment(self):
        text = "GITHUB_TOKEN=" + FAKE_ASSIGN + "\n"
        result = scan(text)
        self.assertIn("secret-assignment", rule_names(result))

    def test_detects_password_assignment(self):
        text = "db_password: " + FAKE_ASSIGN + "\n"
        self.assertIn("secret-assignment", rule_names(scan(text)))

    def test_short_value_not_flagged(self):
        self.assertEqual([], scan("count=3\n").findings)
        self.assertEqual([], scan("API_KEY=abc\n").findings)

    def test_password_sentence_not_flagged(self):
        text = "the password policy of the test system allows short test words\n"
        self.assertEqual([], scan(text).findings)

    def test_placeholder_not_flagged(self):
        self.assertEqual([], scan("API_KEY=your-key-here\n").findings)
        self.assertEqual([], scan("API_KEY=<insert-key-here>\n").findings)
        self.assertEqual([], scan("API_KEY=example\n").findings)
        self.assertEqual([], scan("API_KEY=$NOTSETVALUE1\n").findings)


class TestShellTrace(unittest.TestCase):
    def test_trace_export_flagged(self):
        text = "+ export API_KEY=" + FAKE_KEY + "\n"
        self.assertIn("shell-trace", rule_names(scan(text)))

    def test_trace_plain_name_value_flagged(self):
        text = "+ API_KEY=" + FAKE_KEY + "\n"
        self.assertIn("shell-trace", rule_names(scan(text)))

    def test_trace_make_not_flagged(self):
        self.assertEqual([], scan("+ make all\n").findings)

    def test_trace_header_with_bearer_flagged(self):
        text = (
            "+ curl -H 'Authorization: Bearer " + FAKE_BEARER
            + "' https://example.invalid/x\n"
        )
        result = scan(text)
        self.assertEqual(1, len(result.findings))
        self.assertNotIn(FAKE_BEARER, result.redacted_text)

    def test_trace_header_without_bearer_flagged(self):
        text = "+ curl -H 'Authorization: " + FAKE_BASIC + "' https://example.invalid/x\n"
        self.assertIn("shell-trace-header", rule_names(scan(text)))


class TestShellTraceEcho(unittest.TestCase):
    def test_trace_echo_flagged(self):
        text = "+ echo " + FAKE_ECHO + " | deploy\n"
        self.assertIn("shell-trace-echo", rule_names(scan(text)))

    def test_trace_printf_flagged(self):
        text = "++ printf %s " + FAKE_ECHO + "\n"
        self.assertIn("shell-trace-echo", rule_names(scan(text)))

    def test_trace_echo_short_word_not_flagged(self):
        self.assertEqual([], scan("+ echo hello\n").findings)
        self.assertEqual([], scan("+ echo step-ok\n").findings)


class TestHighEntropyRun(unittest.TestCase):
    def test_detects_high_entropy_run(self):
        result = scan("payload: " + FAKE_ENTROPY + "\n")
        self.assertIn("high-entropy-run", rule_names(result))

    def test_git_sha_not_flagged(self):
        self.assertEqual([], scan("commit " + GIT_SHA + " checked out\n").findings)

    def test_uuid_not_flagged(self):
        self.assertEqual([], scan("request id " + TEST_UUID + " handled\n").findings)

    def test_low_entropy_run_not_flagged(self):
        run = "ab" * 25
        self.assertEqual([], scan("value " + run + " end\n").findings)

    def test_data_url_not_flagged(self):
        result = scan("image " + DATA_URL + " loaded\n")
        self.assertEqual([], result.findings)


# --- Redaction invariants ---------------------------------------------------


class TestRedactionInvariants(unittest.TestCase):
    MULTI = (
        "+ export API_KEY=" + FAKE_KEY + "\n"
        + "noise line\n"
        + "Authorization: Bearer " + FAKE_BEARER + "\n"
        + "token " + FAKE_GH + " seen\n"
    )

    def test_no_secret_in_output(self):
        result = scan(self.MULTI)
        blob = result.redacted_text + json.dumps(
            [f.masked for f in result.findings]
        )
        for secret in (FAKE_KEY, FAKE_BEARER, FAKE_GH):
            self.assertNotIn(secret, blob)
        report = maskline.format_report("multi.txt", result)
        for secret in (FAKE_KEY, FAKE_BEARER, FAKE_GH):
            self.assertNotIn(secret, report)

    def test_line_count_unchanged(self):
        result = scan(self.MULTI)
        self.assertEqual(
            len(self.MULTI.splitlines()),
            len(result.redacted_text.splitlines()),
        )
        for text in ("one line no secret", "a\nb\nc", "with\n\nblank"):
            result = scan(text)
            self.assertEqual(
                len(text.splitlines()), len(result.redacted_text.splitlines())
            )

    def test_redacted_rescan_clean(self):
        result = scan(self.MULTI)
        again = scan(result.redacted_text)
        self.assertEqual([], again.findings)

    def test_short_value_fully_masked(self):
        text = "+ export API_KEY=" + FAKE_SHORT + "\n"
        result = scan(text)
        self.assertEqual(1, len(result.findings))
        self.assertEqual("****", result.findings[0].masked)
        self.assertNotIn(FAKE_SHORT, result.redacted_text)
        self.assertEqual("****", maskline.mask_value("x" * 16))
        self.assertNotEqual("****", maskline.mask_value("x" * 17))

    def test_long_value_mask_shape(self):
        masked = maskline.mask_value(FAKE_BEARER)
        self.assertEqual(FAKE_BEARER[:2] + "****" + FAKE_BEARER[-2:], masked)
        self.assertEqual(8, len(masked))

    def test_overlap_single_redaction(self):
        text = (
            "+ curl -H 'Authorization: Bearer " + FAKE_BEARER
            + "' https://example.invalid/x\n"
        )
        result = scan(text)
        self.assertEqual(1, len(result.findings))
        self.assertEqual(1, result.redacted_text.count("[REDACTED:"))
        self.assertNotIn(FAKE_BEARER, result.redacted_text)

    def test_report_has_not_checked_line(self):
        result = scan("plain text with no secret\n")
        report = maskline.format_report("plain.txt", result)
        self.assertIn("NOT checked", report)

    def test_masked_bearer_16_is_full_mask(self):
        result = scan("Authorization: Bearer " + FAKE_BEARER16 + "\n")
        self.assertEqual(1, len(result.findings))
        self.assertEqual("****", result.findings[0].masked)


class TestLoosePatternGuard(unittest.TestCase):
    """Guards against a loosened pattern: short and plain text stays clean."""

    def test_loose_pattern_guard(self):
        text = (
            "Authorization: Bearer short\n"
            "API_KEY=abc\n"
            "count=3\n"
            "the password policy allows short test words\n"
            "+ echo hello\n"
            "+ make all\n"
        )
        self.assertEqual([], scan(text).findings)


# --- Rules file -------------------------------------------------------------


class TestRulesFile(unittest.TestCase):
    EXPECTED_RULES = [
        "pem-private-key",
        "token-prefix",
        "bearer-token",
        "secret-assignment",
        "shell-trace",
        "shell-trace-echo",
        "shell-trace-header",
        "high-entropy-run",
    ]

    def test_rules_toml_has_all_rules(self):
        raw = (REPO / "rules.toml").read_text(encoding="utf-8")
        for name in self.EXPECTED_RULES:
            self.assertIn('name = "' + name + '"', raw)
        rules, settings = maskline.load_rules(str(REPO / "rules.toml"))
        self.assertEqual(self.EXPECTED_RULES, [r.name for r in rules])

    def test_fallback_parser_matches(self):
        raw = (REPO / "rules.toml").read_text(encoding="utf-8")
        data = maskline._parse_rules_fallback(raw)
        self.assertEqual(self.EXPECTED_RULES, [r["name"] for r in data["rule"]])
        self.assertEqual(5242880, data["settings"]["max_file_bytes"])


# --- File limits and refusals -----------------------------------------------


class TestScanFileLimits(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        base = Path(self._tmp.name)
        self.root = base / "root"
        self.root.mkdir()
        self.outside = base / "outside"
        self.outside.mkdir()

    def test_scan_file_inside_root(self):
        target = self.root / "note.txt"
        target.write_text("API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
        result = maskline.scan_file("note.txt", str(self.root), RULES, SETTINGS)
        self.assertEqual(1, len(result.findings))

    def test_scan_file_outside_root_refused(self):
        secret = self.outside / "leak.txt"
        secret.write_text("API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
        with self.assertRaises(maskline.ScanRefused) as ctx:
            maskline.scan_file(
                os.path.relpath(str(secret), str(self.root)),
                str(self.root),
                RULES,
                SETTINGS,
            )
        self.assertIn("outside", str(ctx.exception))
        self.assertNotIn(FAKE_KEY, str(ctx.exception))

    def test_symlink_outside_refused(self):
        secret = self.outside / "target.txt"
        secret.write_text("API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
        link = self.root / "link.txt"
        link.symlink_to(secret)
        with self.assertRaises(maskline.ScanRefused):
            maskline.scan_file("link.txt", str(self.root), RULES, SETTINGS)

    def test_scan_file_too_large_refused(self):
        # A file just over the 5 MB limit, made of short lines. The
        # message must carry the file-size refusal, so a doubled
        # file limit (which then hits only the text limit) fails.
        big = self.root / "big.txt"
        big.write_text(("x" * 100 + "\n") * 62000, encoding="utf-8")
        with self.assertRaises(maskline.ScanRefused) as ctx:
            maskline.scan_file("big.txt", str(self.root), RULES, SETTINGS)
        self.assertIn("file exceeds the 5 MB limit", str(ctx.exception))

    def test_scan_file_binary_refused(self):
        binary = self.root / "blob.bin"
        binary.write_bytes(b"\x00\x01\x02" + FAKE_KEY.encode("utf-8"))
        with self.assertRaises(maskline.ScanRefused) as ctx:
            maskline.scan_file("blob.bin", str(self.root), RULES, SETTINGS)
        self.assertNotIn(FAKE_KEY, str(ctx.exception))

    def test_scan_file_bad_utf8_refused(self):
        bad = self.root / "bad.txt"
        bad.write_bytes(b"\xff\xfe" + FAKE_KEY.encode("utf-8"))
        with self.assertRaises(maskline.ScanRefused):
            maskline.scan_file("bad.txt", str(self.root), RULES, SETTINGS)


# --- MCP protocol -------------------------------------------------------------


class TestMcpProtocol(unittest.TestCase):
    def _call(self, srv, message):
        return mcp_server.handle_message(srv, message)

    def test_mcp_scan_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "job.log").write_text(
                "+ export API_KEY=" + FAKE_KEY + "\n", encoding="utf-8"
            )
            srv = mcp_server.MasklineServer(str(root))
            reply = self._call(
                srv,
                {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                 "params": {"name": "scan_file", "arguments": {"path": "job.log"}}},
            )
            payload = json.loads(reply["result"]["content"][0]["text"])
            blob = reply["result"]["content"][0]["text"]
            self.assertEqual(1, len(payload["findings"]))
            self.assertEqual("[REDACTED:shell-trace]",
                             payload["redacted_text"].split("API_KEY=", 1)[1].strip())
            self.assertNotIn(FAKE_KEY, blob)

    def test_mcp_scan_text_no_value_in_result(self):
        srv = mcp_server.MasklineServer(str(REPO))
        reply = self._call(
            srv,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "scan_text",
                        "arguments": {"text": "Authorization: Bearer " + FAKE_BEARER}}},
        )
        blob = reply["result"]["content"][0]["text"]
        self.assertFalse(reply["result"]["isError"])
        self.assertNotIn(FAKE_BEARER, blob)

    def test_mcp_initialize_and_list(self):
        srv = mcp_server.MasklineServer(str(REPO))
        init = self._call(
            srv,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05"}},
        )
        self.assertEqual("maskline", init["result"]["serverInfo"]["name"])
        listed = self._call(srv, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = [t["name"] for t in listed["result"]["tools"]]
        self.assertEqual(["scan_text", "scan_file"], names)

    def test_mcp_unknown_tool_is_error(self):
        srv = mcp_server.MasklineServer(str(REPO))
        reply = self._call(
            srv,
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "nope", "arguments": {}}},
        )
        self.assertTrue(reply["result"]["isError"])

    def test_mcp_unknown_method(self):
        srv = mcp_server.MasklineServer(str(REPO))
        reply = self._call(srv, {"jsonrpc": "2.0", "id": 4, "method": "bogus"})
        self.assertEqual(-32601, reply["error"]["code"])

    def test_serve_handles_garbage(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        instream = io.StringIO(
            "\nnot json at all\n"
            + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"})
            + "\n"
        )
        outstream = io.StringIO()
        mcp_server.serve(srv, instream, outstream)
        replies = [json.loads(line) for line in outstream.getvalue().splitlines()]
        self.assertEqual(2, len(replies))
        self.assertEqual(-32700, replies[0]["error"]["code"])
        self.assertEqual(5, replies[1]["id"])


# --- Review fixes B1 to B3, N3, R4/R10/R11/R13/R14/R17 ----------------------


class TestReviewFixRound1(unittest.TestCase):
    def test_timing_hostile_keyword_runs(self):
        import time

        for unit in ("pwd", "TOKEN", "SecretToken", "SECRET", "KEY"):
            text = (unit * (200000 // len(unit) + 1))[:200000] + "\n"
            t0 = time.monotonic()
            result = scan(text)
            dt = time.monotonic() - t0
            self.assertLess(dt, 2.0, unit)
            self.assertEqual([], result.findings)

    def test_timing_five_mb_single_line(self):
        import time

        text = "pwd" * (5 * 1024 * 1024 // 3 + 1)
        text = text[: 5 * 1024 * 1024]
        self.assertEqual(5 * 1024 * 1024, len(text))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "oneline.txt"
            target.write_text(text, encoding="utf-8")
            t0 = time.monotonic()
            with self.assertRaises(maskline.ScanRefused):
                maskline.scan_file("oneline.txt", tmp, RULES, SETTINGS)
            self.assertLess(time.monotonic() - t0, 5.0)

    def test_timing_line_at_limit(self):
        import time

        text = ("pwdTOKEN" * 140000)[: 1024 * 1024]
        self.assertEqual(1024 * 1024, len(text))
        t0 = time.monotonic()
        result = scan(text)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertEqual([], result.findings)

    def test_scan_text_size_limit(self):
        # Many short lines, so only the total text limit can refuse.
        # The scan_text limit is 5 MB, the same as the file limit.
        text = ("x" * 100 + "\n") * 52000
        self.assertGreater(len(text), 5 * 1024 * 1024)
        with self.assertRaises(maskline.ScanRefused):
            scan(text)

    def test_unknown_tool_name_not_echoed(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        secret_name = FAKE_GH
        outstream = io.StringIO()
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": secret_name, "arguments": {}}}
        )
        mcp_server.serve(srv, io.StringIO(line + "\n"), outstream)
        reply = json.loads(outstream.getvalue().splitlines()[0])
        blob = json.dumps(reply)
        self.assertTrue(reply["result"]["isError"])
        self.assertEqual("unknown tool", reply["result"]["content"][0]["text"])
        self.assertNotIn(secret_name, blob)
        # The stderr capture runs through a subprocess below; here the
        # result must hold no name at all.
        self.assertNotIn("tool=", blob)

    def test_malformed_params_give_error_not_crash(self):
        srv = mcp_server.MasklineServer(str(REPO))
        cases = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "bogus"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": 42, "arguments": {}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "scan_text", "arguments": "bogus"}},
            {"jsonrpc": "2.0", "id": 4, "method": "initialize", "params": [1]},
        ]
        for case in cases:
            reply = mcp_server.handle_message(srv, case)
            self.assertIsNotNone(reply)
            self.assertIn("error" if "error" in reply else "result", reply)

    def test_batch_and_nonobject_give_error_reply(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        instream = io.StringIO("[{\"a\": 1}]\n42\n")
        outstream = io.StringIO()
        mcp_server.serve(srv, instream, outstream)
        replies = [json.loads(x) for x in outstream.getvalue().splitlines()]
        self.assertEqual(2, len(replies))
        for reply in replies:
            self.assertEqual(-32600, reply["error"]["code"])

    def test_nested_brackets_give_parse_error(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        instream = io.StringIO("[" * 100000 + "\n")
        outstream = io.StringIO()
        mcp_server.serve(srv, instream, outstream)
        replies = [json.loads(x) for x in outstream.getvalue().splitlines()]
        self.assertEqual(1, len(replies))
        self.assertEqual(-32700, replies[0]["error"]["code"])

    def test_parse_error_holds_no_input(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        secret = FAKE_BEARER
        instream = io.StringIO("not json " + secret + "\n")
        outstream = io.StringIO()
        mcp_server.serve(srv, instream, outstream)
        self.assertNotIn(secret, outstream.getvalue())

    def test_merge_extends_span_end(self):
        merged = maskline.merge_spans(
            [(0, 10, "rule-a", "x" * 10), (5, 20, "rule-b", "y" * 15)]
        )
        self.assertEqual(1, len(merged))
        self.assertEqual(0, merged[0][0])
        self.assertEqual(20, merged[0][1])
        text = "Authorization: Bearer " + FAKE_BEARER + "\n"
        result = scan(text)
        self.assertNotIn(FAKE_BEARER, result.redacted_text)
        for i in range(len(FAKE_BEARER) - 7):
            self.assertNotIn(FAKE_BEARER[i : i + 8], result.redacted_text)

    def test_sibling_prefix_path_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            root.mkdir()
            sibling = base / "rootx"
            sibling.mkdir()
            (sibling / "leak.txt").write_text(
                "API_KEY=" + FAKE_KEY + "\n", encoding="utf-8"
            )
            with self.assertRaises(maskline.ScanRefused):
                maskline.scan_file("../rootx/leak.txt", str(root), RULES, SETTINGS)

    def test_refusal_message_holds_no_path(self):
        marker = "SECRET" + "MARK" + "ER12345"
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "root"
            root.mkdir()
            with self.assertRaises(maskline.ScanRefused) as ctx:
                maskline.scan_file("../" + marker + ".txt", str(root), RULES, SETTINGS)
            self.assertNotIn(marker, str(ctx.exception))

    def test_unreadable_file_refused(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("mode 000 is readable as root")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "no-read.txt"
            target.write_text("API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
            os.chmod(target, 0)
            try:
                with self.assertRaises(maskline.ScanRefused) as ctx:
                    maskline.scan_file("no-read.txt", str(root), RULES, SETTINGS)
                self.assertNotIn(FAKE_KEY, str(ctx.exception))
            finally:
                os.chmod(target, 0o644)

    def test_overlong_path_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            long_rel = "/".join(["a" * 200] * 40) + ".txt"
            with self.assertRaises(maskline.ScanRefused):
                maskline.scan_file(long_rel, str(root), RULES, SETTINGS)

    def test_nul_byte_path_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(maskline.ScanRefused):
                maskline.scan_file("a\x00b.txt", tmp, RULES, SETTINGS)

    def test_error_result_holds_no_arguments(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        secret = FAKE_KEY
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "scan_file", "arguments": {"path": secret}}}
        )
        outstream = io.StringIO()
        mcp_server.serve(srv, io.StringIO(line + "\n"), outstream)
        self.assertNotIn(secret, outstream.getvalue())

    def test_stderr_holds_no_input_text(self):
        secret = FAKE_BEARER
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "scan_text",
                        "arguments": {"text": "Authorization: Bearer " + secret}}}
        )
        proc = subprocess.run(
            [sys.executable, str(REPO / "server.py"), "--root", str(REPO)],
            input=line + "\n", capture_output=True, text=True, timeout=30,
        )
        self.assertNotIn(secret, proc.stderr)
        self.assertNotIn(secret, proc.stdout)

    def test_stdout_is_valid_json_lines_only(self):
        secret = FAKE_KEY
        line = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "scan_text",
                        "arguments": {"text": "API_KEY=" + secret}}}
        )
        proc = subprocess.run(
            [sys.executable, str(REPO / "server.py"), "--root", str(REPO)],
            input=line + "\n", capture_output=True, text=True, timeout=30,
        )
        for out_line in proc.stdout.splitlines():
            json.loads(out_line)
        self.assertNotIn(secret, proc.stdout)

    def test_invalid_utf8_on_stdin(self):
        ping = b'{"jsonrpc": "2.0", "id": 9, "method": "ping"}\n'
        raw = ping + b"bad \xff\xfe line\n" + ping
        proc = subprocess.run(
            [sys.executable, str(REPO / "server.py"), "--root", str(REPO)],
            input=raw, capture_output=True, timeout=30,
        )
        self.assertEqual(0, proc.returncode)
        self.assertNotIn(b"Traceback", proc.stderr)
        replies = [json.loads(x) for x in proc.stdout.decode("utf-8").splitlines()]
        self.assertEqual(3, len(replies))
        self.assertEqual(-32700, replies[1]["error"]["code"])
        self.assertEqual(9, replies[0]["id"])
        self.assertEqual(9, replies[2]["id"])

    def test_display_name_redacts_secret_shapes(self):
        self.assertEqual("build.log", mcp_server.display_name("path/to/build.log"))
        long_secret = FAKE_BEARER
        self.assertNotEqual(long_secret, mcp_server.display_name(long_secret))
        self.assertNotIn("FAKE", mcp_server.display_name("x/" + long_secret))

    def test_demo_trailing_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(REPO / "server.py"), "--demo"],
                cwd=tmp, capture_output=True, text=True, timeout=30,
            )
            self.assertTrue(proc.stdout.endswith("\n"))
            self.assertFalse(proc.stdout.endswith("\n\n"))
            readme_path = REPO / "README.md"
            if readme_path.is_file():
                readme = readme_path.read_text(encoding="utf-8")
                import re

                blocks = re.findall(r"```text\n(.*?)```", readme, re.S)
                self.assertTrue(blocks)
                self.assertEqual(blocks[0], proc.stdout)


class TestReviewFixRound2(unittest.TestCase):
    def test_initialize_answers_supported_version(self):
        srv = mcp_server.MasklineServer(str(REPO))
        reply = mcp_server.handle_message(
            srv,
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "1999-01-01"}},
        )
        self.assertEqual(
            mcp_server.PROTOCOL_VERSION,
            reply["result"]["protocolVersion"],
        )
        reply2 = mcp_server.handle_message(
            srv,
            {"jsonrpc": "2.0", "id": 2, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
        )
        self.assertEqual("2025-06-18", reply2["result"]["protocolVersion"])

    def test_jsonrpc_version_enforced(self):
        srv = mcp_server.MasklineServer(str(REPO))
        reply = mcp_server.handle_message(
            srv, {"jsonrpc": "1.0", "id": 1, "method": "ping"}
        )
        self.assertEqual(-32600, reply["error"]["code"])
        reply = mcp_server.handle_message(srv, {"id": 2, "method": "ping"})
        self.assertEqual(-32600, reply["error"]["code"])

    def test_invalid_id_refused(self):
        srv = mcp_server.MasklineServer(str(REPO))
        for bad in (1.5, True, [1], {"a": 1}):
            reply = mcp_server.handle_message(
                srv, {"jsonrpc": "2.0", "id": bad, "method": "ping"}
            )
            self.assertEqual(-32600, reply["error"]["code"])
            self.assertIsNone(reply["id"])

    def test_nan_id_never_on_stdout(self):
        import io

        srv = mcp_server.MasklineServer(str(REPO))
        instream = io.StringIO(
            '{"jsonrpc": "2.0", "id": NaN, "method": "ping"}\n'
            '{"jsonrpc": "2.0", "id": 1e400, "method": "ping"}\n'
        )
        outstream = io.StringIO()
        mcp_server.serve(srv, instream, outstream)
        out = outstream.getvalue()
        self.assertNotIn("NaN", out)
        self.assertNotIn("Infinity", out)
        for line in out.splitlines():
            json.loads(line)

    def test_data_url_suffix_still_scanned(self):
        text = (
            "image data:image/png;base64,iVBORw0KGgoAAAAA ticket "
            + FAKE_GH + " end\n"
        )
        result = scan(text)
        self.assertIn("token-prefix", rule_names(result))
        self.assertNotIn(FAKE_GH, result.redacted_text)
        clean = scan("image " + DATA_URL + " loaded\n")
        self.assertEqual([], clean.findings)

    def test_cli_secret_filename_not_echoed(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = FAKE_GH + ".log"
            target = Path(tmp) / name
            target.write_text("clean line\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(REPO / "server.py"), name,
                 "--root", tmp],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotIn(FAKE_GH, proc.stdout)
            self.assertNotIn(FAKE_GH, proc.stderr)

    def test_cli_unreadable_exits_two(self):
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("mode 000 is readable as root")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "no-read.txt"
            target.write_text("API_KEY=" + FAKE_KEY + "\n", encoding="utf-8")
            os.chmod(target, 0)
            try:
                proc = subprocess.run(
                    [sys.executable, str(REPO / "server.py"), "no-read.txt",
                     "--root", tmp],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(2, proc.returncode)
                self.assertNotIn("Traceback", proc.stderr)
                self.assertNotIn(FAKE_KEY, proc.stderr)
            finally:
                os.chmod(target, 0o644)

    def test_timing_cli_hostile_file(self):
        import time

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "hostile.txt"
            for unit in ("pwd", "TOKEN"):
                target.write_text((unit * 40000)[: 200000 if unit == "TOKEN" else 200001] + "\n",
                                  encoding="utf-8")
                t0 = time.monotonic()
                proc = subprocess.run(
                    [sys.executable, str(REPO / "server.py"), "hostile.txt",
                     "--root", tmp],
                    capture_output=True, text=True, timeout=30,
                )
                self.assertLess(time.monotonic() - t0, 4.0, unit)
                self.assertEqual(0, proc.returncode)


# --- Exit codes ---------------------------------------------------------------


class TestExitCodes(unittest.TestCase):
    def _run(self, args, cwd=None):
        return subprocess.run(
            [sys.executable, str(REPO / "server.py")] + args,
            capture_output=True,
            text=True,
            cwd=str(cwd or REPO),
            timeout=30,
        )

    def test_cli_exit_code_with_leak_is_one(self):
        proc = self._run(["examples/trace-leak-log.txt"])
        self.assertEqual(1, proc.returncode)
        self.assertNotIn("EXAMPLEFAKE", proc.stdout)
        self.assertNotIn("EXAMPLEFAKE", proc.stderr)

    def test_cli_exit_code_clean_is_zero(self):
        proc = self._run(["examples/clean-build-log.txt"])
        self.assertEqual(0, proc.returncode)

    def test_demo_exit_is_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(["--demo"], cwd=tmp)
            self.assertEqual(1, proc.returncode)
            self.assertNotIn("EXAMPLEFAKE", proc.stdout)
            self.assertNotIn("EXAMPLEFAKE", proc.stderr)
            names = sorted(p.name for p in Path(tmp).glob("redacted/*.txt"))
            self.assertEqual(
                [
                    "agent-transcript.redacted.txt",
                    "clean-build-log.redacted.txt",
                    "trace-leak-log.redacted.txt",
                ],
                names,
            )


if __name__ == "__main__":
    unittest.main()
