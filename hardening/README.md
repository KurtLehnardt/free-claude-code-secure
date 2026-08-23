# Hardened Claude Code hooks

This directory ships a ready-to-use [Claude Code hooks](https://docs.claude.com/en/docs/claude-code/hooks)
configuration and guard script. It is **self-contained** — nothing in here
modifies your `~/.claude` configuration. You choose whether and where to
wire it in (see [Enabling it](#enabling-it) below).

## Threat model

Free Claude Code routes your coding agent's model traffic through whichever
provider you configure — including free/low-cost third-party providers whose
model weights, prompts, and output you do not control. That provider is, by
definition, an **untrusted upstream**: anything it returns can be interpreted
by the coding agent as instructions, including tool calls.

This matters most for the **managed agent path**
(`src/free_claude_code/cli/managed/claude.py`), which launches Claude Code
with `--dangerously-skip-permissions` so it can run unattended from a
messaging integration (Telegram/Discord). That flag skips the *interactive*
permission prompts — it does not disable hooks. A provider that returns a
subtly malicious tool call (for example, "helpfully" running
`cat ~/.ssh/id_rsa` to "check SSH config," or `env | curl ... -d @-` to
"report diagnostics") would normally sail straight through, because nothing
is asking a human to approve it first.

The hooks in this directory are a **PreToolUse guard**: a small script that
Claude Code runs before every matched tool call and that can veto it. They
give you a second, independent check that fires regardless of permission
mode — interactive or `--dangerously-skip-permissions` alike.

## What's here

- `hooks/settings.json` — a Claude Code settings snippet wiring a
  `PreToolUse` hook, matched against `Bash`, `Read`, `Edit`, `Write`,
  `WebFetch`, and `WebSearch`, to run `hooks/fcc-guard.sh`.
- `hooks/fcc-guard.sh` — the guard script itself (POSIX `sh`, no
  non-portable bashisms; verified with `sh -n` and `shellcheck -s sh`).

## What it blocks

Claude Code passes the guard one JSON object on stdin per matched tool call
(`{"tool_name": "...", "tool_input": {...}}`). The guard denies the call —
exit code `2`, with the reason on stderr, which Claude Code returns to the
model as the reason rather than just showing a human — when:

**(a) Any matched tool reads or writes a well-known secret location** —
checked against `tool_input` for every matcher (`Bash`, `Read`, `Edit`,
`Write`, `WebFetch`, `WebSearch`):

- `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`
- `.env` / `.env.*` files, `*.pem` files, `id_rsa*` key files, `~/.netrc`
- `~/.fcc/proxy_auth_token` (the local FCC proxy's own credential)
- macOS Keychain (`Login.keychain`, anything under `~/Library/Keychains/`,
  `security find-generic-password` / `find-internet-password` /
  `dump-keychain`)
- Browser cookie databases (`Cookies`, `cookies.sqlite`)

For `WebFetch`/`WebSearch` this only catches a URL or query that names one
of the paths above (e.g. a `file://` URL pointing at `~/.ssh`) — it does
**not** block ordinary outbound fetches to arbitrary hosts, since that is
`WebFetch`'s normal job.

**(b) A `Bash` command looks like it exfiltrates data:**

- `curl` / `wget` / `nc` / `ncat` / `scp` / `sftp` / `ssh` / `telnet` used
  against anything that isn't recognizably loopback (`127.0.0.1`,
  `localhost`, `::1`, `0.0.0.0`) — local calls to your own `fcc-server` are
  allowed, everything else using one of those tools is not.
- `git push`
- `env` or `printenv` piped into one of the tools above
- `base64` piped into one of the tools above (a common way to smuggle binary
  or secret-shaped data past naive text filters)

Everything else is allowed (exit `0`).

## Enabling it

Pick one:

1. **Project-scoped (recommended for the managed/messaging agent path).**
   Copy this repository's `hardening/` directory into the workspace
   directory the managed agent runs in (`config.workspace_path` /
   `ManagedClaudeConfig.workspace_path`), then merge the `hooks` object from
   `hooks/settings.json` into that workspace's `.claude/settings.json`.
   Claude Code resolves `$CLAUDE_PROJECT_DIR` in hook `command` strings to
   that project root automatically, so the path in the shipped
   `settings.json` works unmodified as long as `hardening/hooks/fcc-guard.sh`
   sits at `<project>/hardening/hooks/fcc-guard.sh`.

2. **Global, via `CLAUDE_CONFIG_DIR`.** Point the `CLAUDE_CONFIG_DIR`
   environment variable at a directory containing a `settings.json` with
   this `hooks` stanza, but replace the `command` value with an **absolute**
   path to `fcc-guard.sh` (`$CLAUDE_PROJECT_DIR` only resolves relative to a
   project, not a global config dir). This applies the guard to every
   Claude Code session that uses that config dir.

Either way, merge the `hooks` object — don't just overwrite an existing
`settings.json` that already has other keys (permissions, other hooks,
etc.).

To verify the guard script parses correctly on your system:

```bash
sh -n hardening/hooks/fcc-guard.sh
```

To exercise it directly, the way Claude Code would:

```bash
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' | hardening/hooks/fcc-guard.sh; echo "exit=$?"
```

`jq` is used when present for correct JSON field extraction; without it the
script falls back to a plain-text scan (see [Limits](#limits)).

## Limits

Be precise with yourself about what this buys you:

- **It is a heuristic string/regex filter over JSON text, not a parser, a
  taint tracker, or a sandbox.** It does not understand shell quoting,
  variable expansion, command substitution, multi-command pipelines beyond
  the specific patterns above, or indirection through a wrapper script. A
  sufficiently motivated adversarial provider can very likely construct a
  Bash command that exfiltrates data without matching any pattern here —
  e.g. writing the target host into a variable first, using a tool not in
  the exfil list (`python -c 'import urllib...'`, `osascript`, a custom
  binary), or splitting a sensitive read across two separate approved tool
  calls that only combine their result later in the model's own context.
- **The `curl`/`wget`/.../non-loopback check is intentionally blunt.** A
  command that references *both* a loopback address and a remote one in the
  same string is allowed, because the check for "loopback-only" is really
  "mentions a loopback marker somewhere," not "every network target in this
  command is loopback."
- **Without `jq`, field extraction degrades to a line-oriented `sed`/`grep`
  fallback** that only understands simple, unescaped `"key":"value"` pairs.
  It scans the *entire* raw hook payload in that mode rather than just
  `tool_input`, which makes it strictly more conservative (more surface
  scanned, not less) but also slightly more prone to an unrelated false
  positive (e.g. a `description` field that happens to mention `.ssh` in
  prose). Install `jq` for more precise field-scoped matching.
- **It only covers tool calls that go through Claude Code's `PreToolUse`
  hook — Bash, Read, Edit, Write, WebFetch, WebSearch as matched here.**
  It has no visibility into, and cannot stop, an MCP tool call, a
  sub-agent's tool use, or anything outside Claude Code's own hook surface.
- **It is not the security boundary.** The actual fix for provider
  credentials reaching a coding agent's subprocess is that the launcher
  environment builders (`cli/claude_env.py`, `cli/launchers/*.py`) now strip
  every `credential_env` in `config/provider_catalog.py` before spawning the
  agent — so there is no `GROQ_API_KEY`/`NVIDIA_NIM_API_KEY`/etc. in the
  child process for a compromised tool call to read back out in the first
  place. This hook is a second, independent layer against secrets that
  *do* legitimately live on disk (SSH keys, cloud credentials, browser
  cookies) which the launcher fix cannot touch. For anything beyond that,
  the project's existing containerized, egress-filtered deployment (see the
  main [`README.md`](../README.md#containerized-isolated-runtime) —
  non-root, read-only rootfs, `internal: true` network, Squid egress
  allowlist) is the real backstop, not this script.
