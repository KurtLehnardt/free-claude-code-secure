# Claude Code security hooks

Free Claude Code ships a **default-on** `PreToolUse` security guard for its
Claude Code launchers. Every `fcc-claude` session, and every managed
(messaging / `fcc-desktop`) Claude Code task, launches with the guard already
registered. You do not have to enable anything.

The guard is a packaged Python console script (`fcc-hook-guard`, from
`src/free_claude_code/security/`) so it survives `uv tool install` and is on
`PATH` next to `fcc-claude`. The launchers register it by appending
`--settings '<json>'` to the `claude` invocation; that JSON **merges** with your
existing `~/.claude` configuration (permissions, other hooks, MCP servers) and
never replaces it.

## Threat model

Free Claude Code routes your coding agent's model traffic through whichever
provider you configure — including free/low-cost third-party providers whose
weights, prompts, and output you do not control. That provider is an
**untrusted upstream**: anything it returns can be interpreted by the coding
agent as instructions, including tool calls.

This matters most for the **managed agent path**
(`src/free_claude_code/cli/managed/claude.py`), which launches Claude Code with
`--dangerously-skip-permissions` so it can run unattended from a messaging
integration (Telegram/Discord) and from `fcc-desktop`. That flag skips the
*interactive* permission prompts — it does **not** disable hooks. A provider
that returns a subtly malicious tool call (for example "helpfully" running
`cat ~/.ssh/id_rsa` to "check SSH config," or `env | curl … -d @-` to "report
diagnostics") would otherwise sail straight through, because nothing asks a
human to approve it first.

The guard is a second, independent check that fires **regardless of permission
mode** — interactive or `--dangerously-skip-permissions` alike. It runs before
every matched tool call and can veto it.

## How it works (the contract)

Claude Code writes one JSON object to the guard's stdin per matched tool call,
e.g. `{"tool_name": "Bash", "tool_input": {"command": "curl https://x"}}`. The
guard replies on the documented Claude Code 2.1.x `PreToolUse` contract:

- **Allow** → exit 0 with no stdout ("no opinion"; the normal permission flow
  proceeds).
- **Deny** → exit 0 with a JSON object on stdout:

  ```json
  {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                          "permissionDecision": "deny",
                          "permissionDecisionReason": "fcc-hook-guard: …"}}
  ```

  Claude Code feeds `permissionDecisionReason` back to the model, so the deny
  both stops the call and tells the agent *why* (and what to do instead).

The registered matcher is
`Bash|Read|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch|Grep|Glob`.

## Design philosophy

The guard denies **only high-signal dangerous operations** and is deliberately
tuned to leave ordinary development work alone. It blocks the patterns a
compromised provider would use to steal secrets or exfiltrate data; it does not
try to sandbox the agent or approve/deny everything. Concretely, these all stay
allowed: `git commit`, `git push origin main` (and force-push to a *named*
remote), `git reset --hard`, `pytest`, `npm test`/`npm install <pkg>`,
`pip install <pkg>`, `rm -rf node_modules`, `chmod +x`, `curl http://127.0.0.1…`
(the local proxy), `ssh-keygen`, local `rsync`, reading/editing project source,
and reading `.env.example` / `.env.sample` templates.

## What it blocks

Grouped by category (see `src/free_claude_code/security/hook_guard.py` for the
exact rules — each rule carries a plain-English reason):

1. **Secret file access — read OR write** (all matched tools). Credential
   directories (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`,
   `~/.azure`, `~/.gnupg`, `~/.config/gh`); `.env` / `.env.*` secret files
   (templates like `.env.example` are allowed); `*.pem` / `*.key` / `*.p12`
   private keys; `id_rsa*` / `id_ed25519*`; `~/.netrc`, `~/.npmrc`, `~/.pypirc`,
   `~/.git-credentials`; FCC's own `~/.fcc/proxy_auth_token` and `~/.fcc/.env`;
   macOS Keychains (`~/Library/Keychains`, `security dump-keychain`); browser
   cookie / saved-login databases; `/etc/shadow`; shell/REPL history
   (`~/.zsh_history`, `~/.bash_history`, …); SSH `authorized_keys`.
2. **Exfiltration (Bash).** `curl`/`wget`/`nc`/`ncat`/`scp`/`sftp`/`ssh`/
   `telnet`/`socat`, and `rsync` to a remote spec, against a **non-loopback**
   host; piping `env`/`printenv` or `base64` into a network tool; `/dev/tcp/`
   socket redirects; DNS exfiltration (a long encoded label in `dig`/`nslookup`/
   `host`); `sendmail`/`mailx`/`mail -s`; inline `python`/`node`/`ruby`/`perl`
   one-liners that open a socket to a non-loopback host; `git push` to an
   ad-hoc URL remote.
3. **Remote code execution.** `curl … | sh` / `| bash` (and other
   pipe-to-interpreter forms), `bash <(curl …)`, `$(curl …)`, `pip`/`pipx`/
   `uv pip install` from a URL/VCS spec, `npm`/`pnpm`/`yarn install` of a
   git/URL spec, `npx` against a URL/GitHub spec.
4. **Privilege escalation / persistence / system tampering.** `sudo`/`doas`;
   disabling SIP / Gatekeeper / firewall (`csrutil disable`,
   `spctl --master-disable`, `pfctl -d`, `ufw disable`, …); editing
   `/etc/sudoers` or PAM; launchd persistence (`launchctl load`,
   `~/Library/LaunchAgents`); cron/at persistence; writing to shell startup
   files (`~/.zshrc`, `~/.bashrc`, …); `chmod 777`; appending SSH keys
   (`ssh-copy-id`, `>> authorized_keys`).
5. **Destructive.** `rm -rf /` / `~` / `$HOME` / `/*`; fork bombs; `dd` to a
   raw disk device; `mkfs`/`newfs`/`wipefs`/`shred`/`diskutil erase`.
6. **Cloud-metadata SSRF (WebFetch + Bash).** `169.254.169.254`,
   `metadata.google.internal`, `fd00:ec2::254`, `169.254.170.2`,
   `100.100.100.200`.

For `WebFetch`/`WebSearch` the guard only trips on a URL/query that *names* a
secret path or a metadata endpoint — it does **not** block ordinary outbound
fetches, since that is `WebFetch`'s job.

## Opting out

Set `FCC_DISABLE_SECURITY_HOOKS=1` in the launcher's environment to omit the
`--settings` guard registration entirely. Any other value (or unset) keeps it
on. Use this if a rule blocks something you legitimately need and you accept the
risk.

Known deliberate false-blocks (the cost of the "block by default" posture):

- **`curl`/`wget` to a non-loopback host is denied.** Use the `WebFetch` tool or
  the local proxy (`127.0.0.1`) for legitimate fetches. This is the primary
  exfiltration channel, so it is blocked even though it also stops manual remote
  `curl`.
- **`sudo`/`doas` is denied.** The agent should not need root; run privileged
  steps yourself.
- **Reading `.env` (non-template), `*.pem`, and `*.key` is denied**, even for
  your own project's files. Use `.env.example` or ask for the specific value.

## Trust model

Hooks provided via `claude --settings` at startup run automatically; Claude Code
does **not** show a review/acknowledgement dialog for them, and the managed path
runs with `--dangerously-skip-permissions` anyway. So a normal `fcc-claude` run
picks up the guard silently, with no extra prompt. (Claude Code's separate
workspace-*folder* trust dialog is unrelated to this and unaffected. If an
administrator has set the managed-policy `allowManagedHooksOnly`, `--settings`
hooks may be suppressed — an uncommon configuration.)

## Standalone shell variant (legacy / non-FCC setups)

`hooks/fcc-guard.sh` + `hooks/settings.json` are the original standalone POSIX
`sh` prototype. The packaged `fcc-hook-guard` **supersedes** it for FCC
launchers and covers many more categories. The shell script is kept for setups
where the Python package is not installed — e.g. wiring a guard into a global
`CLAUDE_CONFIG_DIR` or a container image by hand. It implements only categories
(1) and part of (2). To wire it in manually, merge the `hooks` object from
`hooks/settings.json` into the relevant `.claude/settings.json`, pointing
`command` at an absolute path to `hooks/fcc-guard.sh`.

## Limits — be precise about what this buys you

- **It is a heuristic regex filter over tool-call JSON, not a shell parser, a
  taint tracker, or a sandbox.** It does not understand shell quoting, variable
  expansion, command substitution, pipelines beyond the specific patterns above,
  or indirection through a wrapper script. A motivated adversarial provider can
  very likely construct a command that exfiltrates data without matching any
  rule — writing a host into a variable first, using an interpreter or binary
  not on the list, obfuscating a path, or splitting a sensitive read across two
  separate approved tool calls that only recombine in the model's own context.
- **The non-loopback check is intentionally blunt.** A command that mentions
  *both* a loopback address and a remote one is allowed, because the check is
  "mentions a loopback marker somewhere," not "every target is loopback."
- **It only sees Claude Code's own `PreToolUse` tools.** It has no visibility
  into MCP tool calls, a sub-agent's tool use, or anything outside the matched
  tool set.
- **It fails open.** On any internal parse error it allows the call, so a guard
  bug cannot brick every tool call. That means it is not a hard boundary.
- **It is not the security boundary.** Two stronger layers do the real work:
  (a) the launcher environment builders (`cli/claude_env.py`) already **strip
  every provider credential** (`GROQ_API_KEY`, `NVIDIA_NIM_API_KEY`, …) before
  spawning the agent, so those secrets are not in the child process for a
  compromised tool call to read back out; and (b) the project's containerized,
  egress-filtered deployment (see the main
  [`README.md`](../README.md#containerized-isolated-runtime) — non-root,
  read-only rootfs, `internal: true` network, Squid egress allowlist) is the
  real backstop. This guard is a best-effort third layer against secrets that
  legitimately live on disk (SSH keys, cloud credentials, browser cookies) and
  against the most common exfiltration and secret-access patterns — not a
  guarantee that unauthorized access is prevented.

To exercise the guard the way Claude Code would:

```bash
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' \
  | fcc-hook-guard; echo "exit=$?"
```
