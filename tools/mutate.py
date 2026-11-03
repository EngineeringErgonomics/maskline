#!/usr/bin/env python3
"""Mutation controls for maskline.

Copy the source files into a scratch folder, apply one deliberate
defect at a time, and run the named test. Each defect must make its
named test fail. The script prints a table and exits 1 if any defect
survives.

Use: python3 tools/mutate.py [--root FOLDER]
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FILES = [
    "README.md",
    "maskline.py",
    "server.py",
    "rules.toml",
    "test_maskline.py",
    "__init__.py",
    "examples/clean-build-log.txt",
    "examples/trace-leak-log.txt",
    "examples/agent-transcript.txt",
    "tools/mcp_client.py",
    "tools/mutate.py",
]

MUTANTS = [
    {
        "id": "M1",
        "name": "rule removed (bearer-token)",
        "file": "rules.toml",
        "old": 'name = "bearer-token"',
        "new": 'name = "bearer-token-removed"',
        "extra": (
            r"Bearer\s+(?P<value>[A-Za-z0-9_.+/=-]{16,})",
            r"BearerZZZ\s+(?P<value>[A-Za-z0-9_.+/=-]{16,})",
        ),
        "tests": ["test_maskline.TestRulesFile.test_rules_toml_has_all_rules"],
    },
    {
        "id": "M2",
        "name": "regex loosened (bearer length)",
        "file": "rules.toml",
        "old": "[A-Za-z0-9_.+/=-]{16,}",
        "new": "[A-Za-z0-9_.+/=-]{2,}",
        "tests": ["test_maskline.TestLoosePatternGuard.test_loose_pattern_guard"],
    },
    {
        "id": "M3",
        "name": "redaction skipped",
        "file": "maskline.py",
        "old": 'parts.append("[REDACTED:" + rule_name + "]")',
        "new": "parts.append(line[start:end])",
        "tests": [
            "test_maskline.TestRedactionInvariants.test_no_secret_in_output"
        ],
    },
    {
        "id": "M4",
        "name": "mask length changed",
        "file": "maskline.py",
        "old": 'return value[:2] + "****" + value[-2:]',
        "new": 'return value[:4] + "****" + value[-4:]',
        "tests": [
            "test_maskline.TestRedactionInvariants.test_long_value_mask_shape"
        ],
    },
    {
        "id": "M5",
        "name": "trace prefix one level only",
        "file": "rules.toml",
        "old": r"^(?P<plus>\+{1,})\s+(?:echo|printf",
        "new": r"^(?P<plus>\+)\s+(?:echo|printf",
        "tests": [
            "test_maskline.TestShellTraceEcho.test_trace_printf_flagged"
        ],
    },
    {
        "id": "M6",
        "name": "root check removed",
        "file": "maskline.py",
        "old": "if not inside or resolved == root_path:",
        "new": "if False:",
        "tests": [
            "test_maskline.TestScanFileLimits.test_scan_file_outside_root_refused"
        ],
    },
    {
        "id": "M7",
        "name": "symlink check removed",
        "file": "maskline.py",
        "old": "    resolved = target.resolve()",
        "new": "    resolved = target.absolute()",
        "tests": [
            "test_maskline.TestScanFileLimits.test_symlink_outside_refused"
        ],
    },
    {
        "id": "M8",
        "name": "text size limit removed",
        "file": "maskline.py",
        "old": "    if len(text) > MAX_SCAN_TEXT_CHARS:",
        "new": "    if False:",
        "tests": [
            "test_maskline.TestReviewFixRound1.test_scan_text_size_limit"
        ],
    },
    {
        "id": "M9",
        "name": "exit code always 0",
        "file": "server.py",
        "old": "    return 1 if result.findings else 0",
        "new": "    return 0",
        "tests": [
            "test_maskline.TestExitCodes.test_cli_exit_code_with_leak_is_one"
        ],
    },
    {
        "id": "M10",
        "name": "NOT-checked line removed",
        "file": "maskline.py",
        "old": "    lines.append(result.not_checked)",
        "new": "    lines.append('Checks complete.')",
        "tests": [
            "test_maskline.TestRedactionInvariants.test_report_has_not_checked_line"
        ],
    },
    {
        "id": "M11",
        "name": "overlap merge removed",
        "file": "maskline.py",
        "old": "        if merged and start <= int(merged[-1][1]):",
        "new": "        if False:",
        "tests": [
            "test_maskline.TestRedactionInvariants.test_overlap_single_redaction"
        ],
    },
    {
        "id": "M12",
        "name": "secret value in masked field",
        "file": "maskline.py",
        "old": "                    masked=mask_value(value),",
        "new": "                    masked=value,",
        "tests": [
            "test_maskline.TestRedactionInvariants.test_no_secret_in_output"
        ],
    },
    {
        "id": "M13",
        "name": "R4 root check by string prefix",
        "file": "maskline.py",
        "old": "        inside = os.path.commonpath([str(resolved), str(root_path)]) == str(\n"
        "            root_path\n"
        "        )",
        "new": "        inside = str(resolved).startswith(str(root_path))",
        "tests": [
            "test_maskline.TestReviewFixRound1.test_sibling_prefix_path_refused"
        ],
    },
    {
        "id": "M14",
        "name": "R10 error result includes arguments",
        "file": "server.py",
        "old": '"content": [{"type": "text", "text": str(exc)}],',
        "new": '"content": [{"type": "text", "text": str(exc) + " " + json.dumps(arguments)}],',
        "tests": [
            "test_maskline.TestReviewFixRound1.test_error_result_holds_no_arguments"
        ],
    },
    {
        "id": "M15",
        "name": "R11 stderr log includes input",
        "file": "server.py",
        "old": '+ str(len(payload["findings"]))',
        "new": '+ str(len(payload["findings"])) + " text=" + str(arguments)',
        "tests": [
            "test_maskline.TestReviewFixRound1.test_stderr_holds_no_input_text"
        ],
    },
    {
        "id": "M16",
        "name": "R13 merge end not extended",
        "file": "maskline.py",
        "old": "            if end > int(merged[-1][1]):\n                merged[-1][1] = end",
        "new": "            if False:\n                merged[-1][1] = end",
        "tests": [
            "test_maskline.TestReviewFixRound1.test_merge_extends_span_end"
        ],
    },
    {
        "id": "M17",
        "name": "R14 parse error echoes line",
        "file": "server.py",
        "old": "except (json.JSONDecodeError, ValueError, RecursionError):\n"
        '            emit(_error_reply(None, -32700, "Parse error"))',
        "new": "except (json.JSONDecodeError, ValueError, RecursionError):\n"
        '            emit(_error_reply(None, -32700, "Parse error: " + line[:300]))',
        "tests": [
            "test_maskline.TestReviewFixRound1.test_parse_error_holds_no_input"
        ],
    },
    {
        "id": "M18",
        "name": "R17 refusal text holds path",
        "file": "maskline.py",
        "old": '"scan_file refused: path is outside the allowed root folder"',
        "new": '"scan_file refused: path is outside the allowed root folder: " + raw_path',
        "tests": [
            "test_maskline.TestReviewFixRound1.test_refusal_message_holds_no_path"
        ],
    },
    {
        "id": "M19",
        "name": "B1 pem dash run unbounded",
        "file": "rules.toml",
        "old": "(?<!-)-{4,64}BEGIN",
        "new": "-{4,}BEGIN",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_pem_bounded_pattern"
        ],
    },
    {
        "id": "M20",
        "name": "B1 separator rescue removed",
        "file": "maskline.py",
        "old": "                if not _looks_like_name_value(line, anchor):",
        "new": "                if True:",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_n1_detection_shapes"
        ],
    },
    {
        "id": "M21",
        "name": "B2 display_name returns base name",
        "file": "server.py",
        "old": "    if not base:\n        return hash_form()",
        "new": "    return base\n    if not base:\n        return hash_form()",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_cli_file_name_shapes"
        ],
    },
    {
        "id": "M22",
        "name": "V10 window overlap removed",
        "file": "maskline.py",
        "old": "_NAME_CHUNK_OVERLAP = 256",
        "new": "_NAME_CHUNK_OVERLAP = 0",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_v10_window_overlap_finds_boundary"
        ],
    },
    {
        "id": "M23",
        "name": "V11 window duplicate filter removed",
        "file": "maskline.py",
        "old": "                    if key not in seen:",
        "new": "                    if True:",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_v11_window_duplicate_filter"
        ],
    },
    {
        "id": "M24",
        "name": "V22 data-url hidden span unbounded",
        "file": "maskline.py",
        "old": "    limit = min(len(line), start + _MAX_HIDDEN_CHARS)",
        "new": "    limit = len(line)",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_v22_data_url_span_bounded"
        ],
    },
    {
        "id": "M25",
        "name": "V29 window step skips overlap",
        "file": "maskline.py",
        "old": "                offset += _CHUNK_CHARS",
        "new": "                offset += _CHUNK_CHARS + _NAME_CHUNK_OVERLAP",
        "tests": [
            "test_maskline.TestReviewFixRound3.test_v29_window_step_keeps_overlap"
        ],
    },
]


def copy_tree(src: Path, dst: Path) -> None:
    for rel in FILES:
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, target)


def run_one(work: Path, mutant: dict) -> tuple[bool, str]:
    path = work / mutant["file"]
    text = path.read_text(encoding="utf-8")
    if mutant["old"] not in text:
        return False, "pattern not found in " + mutant["file"]
    text = text.replace(mutant["old"], mutant["new"], 1)
    extra = mutant.get("extra")
    if extra:
        text = text.replace(extra[0], extra[1], 1)
    path.write_text(text, encoding="utf-8")

    names = mutant["tests"]
    proc = subprocess.run(
        [sys.executable, "-m", "unittest"] + names,
        cwd=str(work),
        capture_output=True,
        text=True,
        timeout=120,
    )
    tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-4:])
    killed = proc.returncode != 0
    return killed, tail


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = REPO
    if "--root" in argv:
        idx = argv.index("--root")
        root = Path(argv[idx + 1]).resolve()

    rows: list[tuple[str, str, str, str]] = []
    survived = 0
    with tempfile.TemporaryDirectory(prefix="maskline-mutate-") as tmp:
        base = Path(tmp)
        for mutant in MUTANTS:
            work = base / mutant["id"]
            work.mkdir(parents=True)
            copy_tree(root, work)
            killed, note = run_one(work, mutant)
            status = "killed" if killed else "SURVIVED"
            if not killed:
                survived += 1
            rows.append(
                (mutant["id"], mutant["name"], ",".join(mutant["tests"]), status)
            )
            print(
                mutant["id"] + " " + status + "  " + mutant["name"]
            )
            if not killed:
                print("  test output tail:\n  " + note.replace("\n", "\n  "))

    print("")
    print("mutant | defect | killing test | status")
    print("---|---|---|---")
    for mid, defect, test_name, status in rows:
        print(mid + " | " + defect + " | " + test_name + " | " + status)
    total = len(rows)
    killed_count = total - survived
    print("")
    print("killed " + str(killed_count) + " of " + str(total) + " mutants")
    if survived:
        print("RESULT: FAIL (a mutant survived)")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
