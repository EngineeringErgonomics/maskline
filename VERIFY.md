# Verification plan for maskline

This file fixes the acceptance contract before the code. It names the
consumer, the journeys, the expected results and the defect controls.
The journeys run from a fresh clone with the commands in README.md.

## Consumer

A judge or a security reviewer who clones this repository and wants to
scan an agent transcript or a build log for leaked secrets before
sharing it. The consumer has Python 3.11 or newer, no network and no
key. The consumer runs the demo or connects an MCP client over stdio.

## Artifact identity

- Repository: maskline, one branch `main`, local git bundle for hand over.
- Entry point: `server.py` (MCP stdio server and `--demo` command line mode).
- Rules: `rules.toml`, read at start, named rules by shape.
- Fixtures: `examples/` (synthetic, safe placeholder values) plus
  fragment-built values in `test_maskline.py`.
- Scan core: Python 3 standard library only. No network. No model call.

## Journey J1: demo, no key, no network

Command:

    python3 server.py --demo

The demo scans three bundled synthetic inputs in order:

1. `examples/clean-build-log.txt`
2. `examples/trace-leak-log.txt` (fake leak values on shell-trace lines)
3. `examples/agent-transcript.txt` (fake token values in a transcript)

For each input the demo creates a redacted copy in a demo output folder,
prints the report, and records the exit code of that scan.

Acceptance oracle (independent of the implementation):

- Input 1: the report says no findings, exit status 0.
- Input 2: the report names the trace rule and the PEM rule with their
  line numbers, exit status 1.
- Input 3: the report names the bearer rule and the assignment rule with
  their line numbers, exit status 1.
- The demo process exits 1 because at least one input has findings.
- The exit code table holds: 0 = no findings, 1 = one or more findings,
  2 = usage error (file refused or bad arguments).
- `python3 server.py FILE` prints only the report; with `--write PATH`
  it also writes the redacted copy. README.md prints the exact expected
  demo output for comparison.
- The redacted copy has the same line count as the input and holds the
  marker `[REDACTED:<rule-name>]` in place of each secret value.
- No demo output (stdout or stderr) contains a full secret value. The
  fake values contain the word EXAMPLEFAKE; the verifier greps the demo
  output for EXAMPLEFAKE and expects zero hits.

## Journey J2: MCP tools over stdio

A scripted client (`tools/mcp_client.py`) starts `python3 server.py`
and runs the JSON-RPC calls below over stdio. The server implements the
small subset of the MCP stdio protocol that two tools need
(`initialize`, `tools/list`, `tools/call`) with the Python 3 standard
library, because the MCP Python SDK is not available without a network
install. README.md states this.

- `initialize` (protocol version 2024-11-05) returns the server name
  `maskline` and the tools capability. The `notifications/initialized`
  notification needs no reply. `ping` returns an empty result. An
  unknown method returns error code -32601. Invalid JSON returns error
  code -32700. Empty lines are ignored.
- `tools/list` returns exactly two tools: `scan_text` and `scan_file`.
- `tools/call` with `scan_text` on a fragment-built synthetic secret
  returns one JSON text content with `findings` (each with `line`,
  `rule`, `masked`) and `redacted_text`.
- `tools/call` with `scan_file` on a file below `--root` returns the
  same shape.
- `tools/call` with an unknown tool name returns `isError: true`.

Acceptance oracle:

- No tool result and no server log line contains a full secret value.
  The `masked` field holds at most the first 2 and last 2 characters,
  and only when the value is longer than 16 characters; values of 16
  characters or fewer are masked in full as `****`.
- Server log lines on stderr hold counts only, never input text.

## Journey J3: limits and refusals

- A file larger than 5 MB is refused with a clear limit message.
- A binary file is refused with a clear message.
- Text that is not valid UTF-8 is refused with a decode message.
- `scan_file` reads only files below the folder given with `--root`
  (default: the current folder). A path outside the root is refused.
- A symlink inside the root that points outside the root is refused.
- The command line mode uses the same checks and exits 2 on a refusal.

## Redaction invariants

1. No scan result, report, log line or exception text holds a full
   secret value.
2. The redacted copy has the same line count as the input.
3. A scan of the redacted copy finds nothing (idempotence). The marker
   `[REDACTED:<rule-name>]` must not itself match any rule.
4. Short values are fully masked; long values show at most 2 leading
   and 2 trailing characters in the `masked` field.
5. Overlapping findings on one line merge into one redaction, so no
   part of a secret value survives between two overlapping matches.

## Defect controls

Each rule has one positive fixture (flagged) and the negative fixtures
below apply to the whole rule set (not flagged):

- a 40-character git SHA line
- a UUID
- a base64 image data line
- a sentence with the word password and no value
- a short word assignment such as `count=3`
- a placeholder assignment: a value that starts with `your-`, `<`, or
  `$`, or a value equal to one of `example`, `changeme`, `placeholder`,
  `redacted`, `none`, `true`, `false` (any case)

`tools/mutate.py` applies 12 deliberate source defects in a scratch
copy and shows that a named test fails for each one (12 of 12 killed).

## Scope and prohibited effects

- No network access, no model call, no telemetry.
- No read outside the `--root` folder for `scan_file`.
- No write except an explicit `--write PATH` in command line mode and
  the demo output folder.
- No real secret value anywhere in the repository or its history.
  Strong secret shapes appear only as adjacent string fragments in test
  code, never as one literal.
