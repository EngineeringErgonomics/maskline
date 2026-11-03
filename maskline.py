"""maskline scan core: find secret shapes in text and redact them.

Standard library only. No network. No logging of input text.
The public API is load_rules, scan_text, scan_file and format_report.
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and older
    tomllib = None

# ---------------------------------------------------------------------------
# Constants

NOT_CHECKED_NOTE = (
    "NOT checked: binary content, encoded or compressed forms, "
    "secrets split across lines, prose with no key shape, "
    "and secret formats not listed in rules.toml."
)

HEX_ONLY_MAX = 40  # a git-commit-sized hex run is not a finding
VALUE_GROUPS = ("value", "run")  # regex groups that hold the secret span

HEX_RE = re.compile(r"[0-9A-Fa-f]+")
UUID_RE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
SHA256_RE = re.compile(r"[0-9A-Fa-f]{64}")
DATA_URL_MARK = "data:image/"
END_OF_LINE = "\n"


# ---------------------------------------------------------------------------
# Data types


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    description: str
    entropy_min: float | None
    regex: re.Pattern = field(compare=False, repr=False)


@dataclass(frozen=True)
class Finding:
    """One merged span to redact. Holds the value in memory only."""

    line: int  # 1-based
    rule: str
    start: int
    end: int
    masked: str

    def as_public(self) -> dict[str, object]:
        return {"line": self.line, "rule": self.rule, "masked": self.masked}


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    redacted_text: str
    not_checked: str

    def as_tool_dict(self) -> dict[str, object]:
        return {
            "findings": [f.as_public() for f in self.findings],
            "redacted_text": self.redacted_text,
            "not_checked": self.not_checked,
        }


class ScanRefused(Exception):
    """The input is outside the limits. The text of this exception
    never holds input content."""


# ---------------------------------------------------------------------------
# Masked form


def mask_value(value: str) -> str:
    """Return a masked form that never holds the full value.

    Values of 16 characters or fewer are masked in full. Longer values
    keep the first 2 and the last 2 characters.
    """
    if len(value) <= 16:
        return "****"
    return value[:2] + "****" + value[-2:]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(text))
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values()
    )


# ---------------------------------------------------------------------------
# Rule loading: tomllib, with a small parser for the fixed subset in
# use, so the core also runs on Python 3.10 and older.


def render_rules_path(rules_path: str | Path | None) -> Path:
    if rules_path is not None:
        return Path(rules_path)
    here = Path(__file__).resolve().parent
    return here / "rules.toml"


def load_rules(
    rules_path: str | Path | None = None,
) -> tuple[list[Rule], dict[str, object]]:
    path = render_rules_path(rules_path)
    raw = path.read_bytes()
    if tomllib is not None:
        data = tomllib.loads(raw.decode("utf-8"))
    else:
        data = _parse_rules_fallback(raw.decode("utf-8"))
    settings = dict(data.get("settings", {}))
    settings.setdefault("max_file_bytes", 5242880)
    settings.setdefault("placeholder_values", [])
    settings.setdefault("placeholder_prefixes", [])
    rules: list[Rule] = []
    for entry in data["rule"]:
        pattern = entry["pattern"]
        entropy_min = entry.get("entropy_min")
        rules.append(
            Rule(
                name=entry["name"],
                pattern=pattern,
                description=entry.get("description", ""),
                entropy_min=float(entropy_min) if entropy_min is not None else None,
                regex=re.compile(pattern),
            )
        )
    return rules, settings


def _parse_rules_fallback(text: str) -> dict[str, object]:
    """Parse only the shapes that rules.toml uses: [settings] with an
    integer and string lists, and [[rule]] blocks with literal strings,
    quoted strings and a float."""
    settings: dict[str, object] = {}
    rules: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    section = ""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "[settings]":
            section = "settings"
            current = None
            continue
        if stripped == "[[rule]]":
            section = "rule"
            current = {}
            rules.append(current)
            continue
        if "=" not in stripped:
            continue
        key, _, rest = stripped.partition("=")
        key = key.strip()
        rest = rest.strip()
        if rest.startswith("'''"):
            body = rest[3:]
            if "'''" not in body:
                parts = [body]
                while i < len(lines):
                    chunk = lines[i]
                    i += 1
                    if "'''" in chunk:
                        parts.append(chunk.split("'''", 1)[0])
                        break
                    parts.append(chunk)
                body = "\n".join(parts)
            else:
                body = body.split("'''", 1)[0]
            value: object = body
        elif rest.startswith('"'):
            value = json.loads(rest)
        elif rest.startswith("["):
            value = json.loads(rest)
        else:
            try:
                value = int(rest)
            except ValueError:
                value = float(rest)
        target = settings if section == "settings" else current
        if target is not None:
            target[key] = value
    return {"settings": settings, "rule": rules}


# ---------------------------------------------------------------------------
# Hidden-span handling: base64 image data is not a secret shape.


def hidden_spans_for_line(line: str) -> list[tuple[int, int]]:
    """Spans that no rule may use as a finding.

    A data:image URL carries the image bytes after the comma. The whole
    run after the comma stays untouched.
    """
    spans: list[tuple[int, int]] = []
    idx = line.find(DATA_URL_MARK)
    if idx == -1:
        idx = line.find("base64,")
        if idx != -1 and line.find("data:", max(0, idx - 32), idx) == -1:
            return spans
    if idx == -1:
        return spans
    comma = line.find(",", idx)
    if comma == -1:
        return spans
    start = comma + 1
    end = len(line)
    while end > start and line[end - 1] in " \t\r\n\"')]}>":
        end -= 1
    spans.append((start, end))
    return spans


def _inside_hidden(
    start: int, end: int, hidden: list[tuple[int, int]]
) -> bool:
    for h_start, h_end in hidden:
        if start >= h_start and end <= h_end:
            return True
        if start < h_end and end > h_start:
            return True
    return False


# ---------------------------------------------------------------------------
# Value filters (apply to value and run groups, never to PEM)


def value_span(match: re.Match) -> tuple[int, int] | None:
    for group in VALUE_GROUPS:
        try:
            start, end = match.span(group)
        except IndexError:
            continue
        if start != -1:
            return start, end
    return None



def _drop_filter(
    value: str, rule: Rule, rule_name: str, settings: dict[str, object]
) -> bool:
    """True means: do not report this match."""
    if rule_name == "pem-private-key":
        return False
    lowered = value.lower()
    placeholders = settings.get("placeholder_values", [])
    if lowered in placeholders:
        return True
    prefixes = settings.get("placeholder_prefixes", [])
    if any(value.startswith(p) for p in prefixes):
        return True
    if "[REDACTED:" in value:
        return True
    if UUID_RE.fullmatch(value):
        return True
    if (
        HEX_RE.fullmatch(value)
        and len(value) <= HEX_ONLY_MAX
        and rule_name not in ("secret-assignment", "shell-trace")
    ):
        return True
    if SHA256_RE.fullmatch(value) and rule_name != "token-prefix":
        return True
    if rule.entropy_min is not None:
        if shannon_entropy(value) < rule.entropy_min:
            return True
    return False


# ---------------------------------------------------------------------------
# Scan


def scan_text(
    text: str, rules: list[Rule], settings: dict[str, object]
) -> ScanResult:
    """Scan text line by line. Merge overlapping spans on each line."""
    lines = text.split("\n")
    all_findings: list[Finding] = []
    redacted_lines: list[str] = []

    for line_index, line in enumerate(lines):
        line_number = line_index + 1
        hidden = hidden_spans_for_line(line)
        candidates: list[tuple[int, int, str, str]] = []  # start,end,rule,value

        for rule in rules:
            for match in rule.regex.finditer(line):
                span = value_span(match)
                if span is None:
                    span = match.span()
                start, end = span
                if start >= end:
                    continue
                value = line[start:end]
                if _inside_hidden(start, end, hidden):
                    continue
                if _drop_filter(value, rule, rule.name, settings):
                    continue
                candidates.append((start, end, rule.name, value))

        merged = merge_spans(candidates)
        for start, end, rule_name, value in merged:
            all_findings.append(
                Finding(
                    line=line_number,
                    rule=rule_name,
                    start=start,
                    end=end,
                    masked=mask_value(value),
                )
            )

        # Rebuild the line with the redaction marker in place of each
        # merged span.
        parts: list[str] = []
        pos = 0
        for start, end, rule_name, _value in merged:
            parts.append(line[pos:start])
            parts.append("[REDACTED:" + rule_name + "]")
            pos = end
        parts.append(line[pos:])
        redacted_lines.append("".join(parts))

    return ScanResult(
        findings=all_findings,
        redacted_text="\n".join(redacted_lines),
        not_checked=NOT_CHECKED_NOTE,
    )


def merge_spans(
    candidates: list[tuple[int, int, str, str]],
) -> list[tuple[int, int, str, str]]:
    """Merge overlapping or touching spans. The rule name of the span
    that starts first (and, on a tie, is longer) names the merged span.
    The value of the merged span is the widest value, so the masked
    form uses the full secret length."""
    if not candidates:
        return []
    priority = {
        "shell-trace": 40,
        "pem-private-key": 30,
        "token-prefix": 30,
        "shell-trace-echo": 25,
        "shell-trace-header": 25,
        "secret-assignment": 20,
        "bearer-token": 20,
        "high-entropy-run": 10,
    }

    def _rank(candidate: tuple[int, int, str, str]) -> tuple[int, int]:
        # A more specific rule names the merged span, then the wider
        # span. A shell-trace shape carries more context than a plain
        # assignment on the same span.
        return (priority.get(candidate[2], 0), candidate[1] - candidate[0])

    ordered = sorted(candidates, key=lambda c: c[0])
    merged: list[list[object]] = []
    for start, end, rule_name, value in ordered:
        if merged and start <= int(merged[-1][1]):
            if end > int(merged[-1][1]):
                merged[-1][1] = end
            current = merged[-1]
            candidate = (start, end, rule_name, value)
            holder = (
                int(current[0]),
                int(current[1]),
                str(current[2]),
                str(current[3]),
            )
            if _rank(candidate) > _rank(holder):
                current[2] = rule_name
            if len(value) > len(str(current[3])):
                current[3] = value
        else:
            merged.append([start, end, rule_name, value])
    return [(int(m[0]), int(m[1]), str(m[2]), str(m[3])) for m in merged]


# ---------------------------------------------------------------------------
# File scan with limits


def scan_file(
    path: str | Path,
    root: str | Path,
    rules: list[Rule],
    settings: dict[str, object],
) -> ScanResult:
    """Read one file below root and scan it. Refuse paths outside the
    root, symlink escapes, files that are too large, binary files and
    files that are not valid UTF-8. Messages hold no file content."""
    raw_path = str(path)
    root_path = Path(root).resolve()
    target = Path(raw_path)
    if not target.is_absolute():
        target = root_path / raw_path
    resolved = target.resolve()
    try:
        inside = os.path.commonpath([str(resolved), str(root_path)]) == str(
            root_path
        )
    except ValueError:
        inside = False
    if not inside or resolved == root_path:
        raise ScanRefused(
            "scan_file refused: path is outside the allowed root folder"
        )
    if not Path(resolved).is_file():
        raise ScanRefused("scan_file refused: file not found below the root folder")
    max_bytes = int(settings.get("max_file_bytes", 5242880))
    size = Path(resolved).stat().st_size
    if size > max_bytes:
        raise ScanRefused(
            "scan_file refused: file exceeds the 5 MB limit (file size "
            + str(size)
            + " bytes, limit "
            + str(max_bytes)
            + " bytes)"
        )
    raw = Path(resolved).read_bytes()
    if b"\x00" in raw[:4096]:
        raise ScanRefused("scan_file refused: binary file")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ScanRefused(
            "scan_file refused: file is not valid UTF-8 text"
        ) from None
    return scan_text(text, rules, settings)


# ---------------------------------------------------------------------------
# Report


def format_report(name: str, result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("maskline report: " + name)
    if result.findings:
        lines.append("Findings: " + str(len(result.findings)))
        counts: dict[str, int] = {}
        for finding in result.findings:
            counts[finding.rule] = counts.get(finding.rule, 0) + 1
        for rule_name in sorted(counts):
            lines.append("  " + rule_name + ": " + str(counts[rule_name]))
        for finding in result.findings:
            lines.append(
                "line "
                + str(finding.line)
                + ": "
                + finding.rule
                + " "
                + finding.masked
            )
    else:
        lines.append("Findings: none")
    lines.append(result.not_checked)
    return "\n".join(lines)
