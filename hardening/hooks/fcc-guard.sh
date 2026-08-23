#!/bin/sh
# fcc-guard.sh -- Claude Code PreToolUse hook.
#
# Heuristically blocks tool calls that read/write a well-known secret
# location, or that use a Bash command to exfiltrate data over the network.
# See ../README.md for the threat model this defends against and, just as
# important, what it does NOT catch.
#
# --- Claude Code hook contract (PreToolUse) -------------------------------
# Claude Code invokes this script once per matched tool call and writes one
# JSON object to its stdin, e.g.:
#   {"tool_name": "Bash", "tool_input": {"command": "curl https://x"}}
# This script's exit code is the decision:
#   exit 0  -> allow the tool call to proceed.
#   exit 2  -> BLOCK the tool call; this script's stderr is returned to
#              Claude as the reason (fed back into the conversation, not
#              just shown to the human).
#   other   -> non-blocking error; Claude Code shows stderr as a warning to
#              the user but the tool call still proceeds. This script never
#              exits non-zero/non-2, so that path should not occur in
#              practice.
# On any internal parsing problem (e.g. jq missing and the fallback parser
# not recognizing the payload) this script fails OPEN (exit 0) rather than
# blocking every tool call -- it is a best-effort heuristic layer, not the
# security boundary. See README.md "Limits".
# ---------------------------------------------------------------------------

set -u

INPUT=$(cat)

deny() {
    printf 'fcc-guard: blocked - %s\n' "$1" >&2
    exit 2
}

have_jq() {
    command -v jq >/dev/null 2>&1
}

# Print the hook payload's "tool_name" field, or empty on any failure.
tool_name() {
    if have_jq; then
        result=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
        if [ -n "$result" ]; then
            printf '%s' "$result"
            return 0
        fi
    fi
    # No jq (or jq produced nothing): fall back to a plain-text scan of the
    # raw payload for a flat "tool_name":"..." pair. This does not handle
    # escaped quotes inside the value, which real tool names never contain.
    printf '%s' "$INPUT" |
        tr -d '\n' |
        sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
        head -n 1
}

# Print the text to scan for dangerous patterns: the "tool_input" object
# when it can be isolated, otherwise the entire raw payload. Scanning the
# whole payload is a strict superset of scanning just tool_input, so this
# fallback can only make the guard MORE conservative, never less.
tool_input_text() {
    if have_jq; then
        result=$(printf '%s' "$INPUT" | jq -c '.tool_input // {}' 2>/dev/null)
        if [ -n "$result" ]; then
            printf '%s' "$result"
            return 0
        fi
    fi
    printf '%s' "$INPUT"
}

NAME=$(tool_name)
CONTENT=$(tool_input_text)

# --- (a) sensitive-path patterns: applies to every matched tool ----------
# Built by concatenation (rather than one dense line) so each guarded
# location stays independently readable and diffable.
SENSITIVE_RE='(^|/)\.ssh(/|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|(^|/)\.aws(/|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|\.config/gcloud'
SENSITIVE_RE="$SENSITIVE_RE"'|(^|/)\.kube(/|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|(^|/)\.docker(/|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|(^|/)\.env([.][A-Za-z0-9_.-]*)?([^A-Za-z0-9_.]|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|\.pem([^A-Za-z0-9_]|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|id_rsa'
SENSITIVE_RE="$SENSITIVE_RE"'|(^|/)\.netrc([^A-Za-z0-9_]|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|\.fcc/proxy_auth_token'
SENSITIVE_RE="$SENSITIVE_RE"'|Login\.keychain'
SENSITIVE_RE="$SENSITIVE_RE"'|/Keychains/'
SENSITIVE_RE="$SENSITIVE_RE"'|security[[:space:]]+(find-generic-password|find-internet-password|dump-keychain)'
SENSITIVE_RE="$SENSITIVE_RE"'|Cookies([^A-Za-z0-9_]|$)'
SENSITIVE_RE="$SENSITIVE_RE"'|cookies\.sqlite'

# --- (b) Bash exfiltration patterns ---------------------------------------
EXFIL_TOOLS_RE='(^|[^A-Za-z0-9_])(curl|wget|nc|ncat|scp|sftp|ssh|telnet)([^A-Za-z0-9_]|$)'
LOOPBACK_RE='(127\.0\.0\.1|localhost|::1|0\.0\.0\.0)'
GIT_PUSH_RE='(^|[^A-Za-z0-9_])git([[:space:]]|$).*push([^A-Za-z0-9_]|$)'
ENV_PIPE_RE='(^|[^A-Za-z0-9_])(env|printenv)([^A-Za-z0-9_].*)?\|.*(curl|wget|nc|ncat|scp|sftp|ssh|telnet)([^A-Za-z0-9_]|$)'
BASE64_NET_RE='(^|[^A-Za-z0-9_])base64([^A-Za-z0-9_].*)?\|.*(curl|wget|nc|ncat|scp|sftp|ssh|telnet)([^A-Za-z0-9_]|$)'

matches() {
    # matches PATTERN TEXT
    printf '%s' "$2" | grep -Eq "$1"
}

case "$NAME" in
    Read | Edit | Write | WebFetch | WebSearch)
        if matches "$SENSITIVE_RE" "$CONTENT"; then
            deny "$NAME targets a sensitive path or credential store"
        fi
        ;;
    Bash)
        if matches "$SENSITIVE_RE" "$CONTENT"; then
            deny "Bash command references a sensitive path or credential store"
        fi
        if matches "$GIT_PUSH_RE" "$CONTENT"; then
            deny "Bash command runs git push"
        fi
        if matches "$BASE64_NET_RE" "$CONTENT"; then
            deny "Bash command pipes base64-encoded data into a network tool"
        fi
        if matches "$ENV_PIPE_RE" "$CONTENT"; then
            deny "Bash command pipes env/printenv into a network tool"
        fi
        if matches "$EXFIL_TOOLS_RE" "$CONTENT" && ! matches "$LOOPBACK_RE" "$CONTENT"; then
            deny "Bash command uses a network/transfer tool against a non-loopback target"
        fi
        ;;
esac

exit 0
