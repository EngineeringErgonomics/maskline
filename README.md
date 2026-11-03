# maskline

An MCP server that scans AI agent transcripts and build logs for leaked
secrets, including shell-trace lines, and returns a redacted copy with a
plain report. It cuts exposure from pasted logs and saves reviewers
manual checks before sharing.

## Purpose

Agent runs print secret values into transcripts and logs. A reviewer who
pastes a long log into an issue, a chat, or a report can miss one value
on one line. maskline gives them one fast check before sharing: it flags
leak shapes by line and by rule name, returns a redacted copy with the
same line count, and never prints the secret value itself.

## Prerequisites

- Python 3.11 or newer (the core also runs on 3.10 with its small
  fallback parser for `rules.toml`).
- No network. No key. No install step. The scan core uses the Python 3
  standard library only.
- An MCP client helps for the tool mode but is not required: the demo
  and single-file modes run as a plain command line.

## MCP note

The official MCP Python SDK is not required. To keep a clone-and-run
demo with no install step, `server.py` implements the small subset of
the MCP stdio JSON-RPC protocol that two tools need: `initialize`,
`tools/list` and `tools/call`. A scripted client in
`tools/mcp_client.py` tests this subset over stdio.

## How to run

Demo (one command, scans three bundled synthetic inputs):

    python3 server.py --demo

Scan one file and print a report. A relative path is resolved below
the root folder (the default root is the current folder):

    python3 server.py path/to/build.log

Scan one file and write the redacted copy:

    python3 server.py path/to/build.log --write build.redacted.log

Scan one file under a root folder. The file path is relative to the
root folder, so with `--root examples` the first command below names
the same file as the second one with the default root:

    python3 server.py trace-leak-log.txt --root examples
    python3 server.py examples/trace-leak-log.txt

MCP server over stdio:

    python3 server.py

or with an explicit root folder for `scan_file`:

    python3 server.py --root folder

MCP client configuration (stdio):

```json
{
  "mcpServers": {
    "maskline": {
      "command": "python3",
      "args": ["server.py", "--root", "."]
    }
  }
}
```

Scripted MCP client self-check:

    python3 tools/mcp_client.py

Unit tests:

    python3 -m unittest

Mutation controls (25 deliberate defects; each must fail a named test):

    python3 tools/mutate.py

## Tools

`scan_text` scans text given by the client. Example call arguments:

    {"text": "+ export API_KEY=EXAMPLEFAKEKEYDONOTUSE123456\n"}

Result (one JSON text content; the value stays out of the result):

```json
{"findings": [{"line": 1, "masked": "EX****56", "rule": "shell-trace"}], "not_checked": "NOT checked: binary content, encoded or compressed forms, secrets split across lines, prose with no key shape, and secret formats not listed in rules.toml.", "redacted_text": "+ export API_KEY=[REDACTED:shell-trace]\n"}
```

`scan_file` scans one text file below the server root folder. Example
call arguments:

    {"path": "examples/trace-leak-log.txt"}

`scan_file` refuses a path outside the root folder, a symlink that
points outside the root folder, a file that is larger than 5 MB, a
binary file, and a file that is not valid UTF-8. The refusal message
holds no file content.

## Expected demo output

`python3 server.py --demo` prints the text below and exits 1. It
creates three files in a `redacted/` folder in the current folder
(each line of the input has one line in the redacted copy):

```text
maskline report: examples/clean-build-log.txt
Findings: none
NOT checked: binary content, encoded or compressed forms, secrets split across lines, prose with no key shape, and secret formats not listed in rules.toml.
exit: 0

maskline report: examples/trace-leak-log.txt
Findings: 3
  pem-private-key: 1
  shell-trace: 1
  shell-trace-header: 1
line 3: shell-trace EX****56
line 4: shell-trace-header EX****89
line 6: pem-private-key --****--
NOT checked: binary content, encoded or compressed forms, secrets split across lines, prose with no key shape, and secret formats not listed in rules.toml.
exit: 1

maskline report: examples/agent-transcript.txt
Findings: 2
  bearer-token: 1
  secret-assignment: 1
line 3: secret-assignment EX****10
line 5: bearer-token EX****89
NOT checked: binary content, encoded or compressed forms, secrets split across lines, prose with no key shape, and secret formats not listed in rules.toml.
exit: 1
```

## Outputs

- Findings: line number, rule name, and a masked form. The masked form
  keeps the first 2 and the last 2 characters of a value only when the
  value is longer than 16 characters; a shorter value is fully masked
  as `****`.
- Redacted copy: each secret value is replaced by a marker such as
  `[REDACTED:shell-trace]`. The redacted copy has the same line count
  as the input.
- Report: counts per rule, one line per finding, and a line that names
  what was NOT checked.
- Exit codes in command line mode: 0 = no findings, 1 = one or more
  findings, 2 = usage error or a refused file (this includes an
  unreadable file, which gives exit 2 with the fixed refusal message
  and no traceback).
- MCP tool results: one JSON text content with `findings`,
  `redacted_text` and `not_checked`. Server log lines on stderr hold
  counts only.
- Report file names: the command line report header prints the base
  name only when every part of it, split at any character outside
  `[A-Za-z0-9_-]`, is at most 16 characters, holds no secret-looking
  keyword and matches no rule (ordinary names such as
  `trace-leak-log.txt` still show). Otherwise it prints
  `file: <8 hex digits of the SHA-256 of the name> lines: N`. The
  folder part is never printed, and an MCP result never prints the
  path or the name.
- Limits: `scan_text` accepts at most 5 MB of text. A line longer
  than 1 MB is refused; a longer line at or below the limit is
  scanned in bounded chunks with a small overlap, so detection at
  the chunk borders is near-exact (see Limitations). One MCP request
  line is at most 5 MB; a longer line gets error -32600 and the
  server keeps reading. CR counts as a line break for the line limit.

## Rules

The named rules live in `rules.toml` and match by shape:

- `pem-private-key`: a PEM private key header line.
- `token-prefix`: a known token prefix of a source host, chat service,
  cloud, or model provider.
- `bearer-token`: the value after `Bearer`.
- `secret-assignment`: a `KEY=value` or `key: value` line whose key
  name looks secret (for example names that hold SECRET, TOKEN,
  PASSWORD or API_KEY, in upper or lower case).
- `shell-trace`: a shell-trace line such as `+ export KEY=value` or
  `+ KEY=value` for a secret-looking name.
- `shell-trace-echo`: a shell-trace print line such as `+ echo value`
  or `++ printf %s value`.
- `shell-trace-header`: a shell-trace curl line with an authorization
  header value.
- `high-entropy-run`: a long run of 40 or more characters with mixed
  letters and digits, behind an entropy gate.

A placeholder value is not a finding: a value that starts with `your-`,
`<` or `$`, or that equals `example`, `changeme`, `placeholder`,
`redacted`, `none`, `true` or `false`. A git SHA, a UUID and a base64
image data line are not findings.

## Privacy statement

Nothing leaves the machine. There is no network call and no model call.
The server logs counts only and never logs input text. A result never
holds a full secret value.

## Limitations

- First pass only. maskline is a shape scanner, not a guarantee. It has
  false positives and false negatives. Do not treat a clean report as
  proof that a log is safe to share.
- Not checked: binary content, encoded or compressed forms, secrets
  split across lines, prose with no key shape, and secret formats not
  listed in `rules.toml`.
- Measured detection gaps (false negatives). Each one is a secret the
  scanner does NOT find today, unless a line says a case is now fixed:
  - N1(a), fixed: a `data:image/...,` or `...,base64,` marker hides
    only the image data run itself (at most 8192 characters of base64).
    Text after that run on the same line is scanned.
  - N1(b): the JSON key form `"password": "value"` is not matched (the
    assignment rule needs the keyword outside quote characters and
    before the separator).
  - N1(c): the authorization token form `curl -H 'Authorization: token VALUE'`
    (without the word `Bearer`) is not flagged.
  - N1(f): a PEM body: the header line is flagged and long body lines may be
    flagged by the entropy rule, but the last short body line of key
    material stays in the redacted copy.
  - N1(d): URL credentials of the form `https://user:VALUE@host` are not
    flagged unless another rule matches the value.
  - A value with zero-width or look-alike characters inside it is
    not matched as one value.
  - A value that holds `[REDACTED:` or starts with `$`, `<`, `[` or
    `your-` is never a finding (it is treated as already redacted or
    as a placeholder).
- Long lines: a line longer than 1 MB is refused. A line at or below
  the limit is scanned in 64 KiB windows with a 256 character overlap;
  a key name or a value that crosses a window border outside the
  overlap can still be missed.
- Supported shell-trace shapes: a line that starts with one or more
  `+` characters, then `export NAME=value` or `NAME=value` for a
  secret-looking name; `echo` and `printf` print lines; curl lines
  with an authorization header. Known misses: other command names on a
  trace line, secret values in traces of shells with a different
  prefix, and values that the shell expanded into the middle of a
  longer argument without a key name next to them.
- The high-entropy rule flags long random-looking runs; it may flag a
  long build identifier, and it misses secrets that are short or that
  have low entropy.
- The redaction marker keeps the line count but changes the line
  length. A tool that needs byte-stable output must not rely on it.
- Only files below the `--root` folder are read, up to 5 MB, UTF-8
  text only.

## Verification

`VERIFY.md` fixes the acceptance journeys: the demo, the MCP tools,
the refusal cases, the redaction invariants, and the defect controls.

## Licence

MIT. See `LICENSE`.
