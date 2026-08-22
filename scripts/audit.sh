#!/bin/sh
# audit.sh - heuristic static scan for unauthorized secret logging / exfiltration.
#
# WHAT THIS IS: a grep/heuristic based sweep of a Python source tree looking for
# lines that plausibly print, log, or ship secrets (env vars, headers, api keys,
# tokens, passwords) somewhere they should not go. It is pattern matching on
# text, not a parser and not a dataflow/taint analyzer.
#
# WHAT THIS IS NOT: a guarantee of safety. It cannot prove the absence of a leak
# (a secret laundered through an extra variable, a helper function, string
# concatenation across lines, or dynamic attribute access will often be missed)
# and it cannot prove every hit is a real leak (a log line that just mentions
# the word "token" in an English sentence will still be reported). Treat every
# finding as a prompt for a human to go read the surrounding code -- this
# complements code review, it does not replace it.
#
# CATEGORIES DETECTED
#   ENV_DUMP     os.environ (or dict(os.environ)) passed wholesale into
#                print()/logger.*()/json.dump()/json.dumps() (the latter
#                covers both the dump-to-string and dump-to-file forms, e.g.
#                json.dump(os.environ, f)).
#   HEADER_LOG   .headers passed wholesale into print()/logger.*(), or literal
#                Authorization / x-api-key / api-key / Bearer tokens appearing
#                inside a print()/logger.*() call.
#   SECRET_LOG   identifiers such as api_key, apikey, secret, token, password,
#                auth_token, ANTHROPIC_AUTH_TOKEN, the sk_/ghp_ token-value
#                prefixes, GITHUB_TOKEN, and OPENAI_API_KEY appearing inside a
#                print()/logger.*() call.
#   SECRET_WRITE open(path, 'w'/'a') or Path.write_text(...) with a
#                secret-shaped variable name in the surrounding lines.
#   EXFIL        requests/httpx/aiohttp/urllib POST/PUT/PATCH/GET-style calls
#                whose visible kwargs (headers=/params=/json=/data=/body=)
#                mention env vars, headers, or key-like variable names.
#                NOTE: this proxy's entire job is forwarding a credential to an
#                upstream provider, so EXFIL hits are ALWAYS reported at REVIEW
#                tier, never HIGH -- grep cannot tell "the intended provider"
#                from "an attacker's endpoint". A human has to look.
#
# SEVERITY / EXIT CODE
#   Each finding is tagged HIGH, or one of the INFO-tier labels below:
#     ALLOWLISTED  - the matched line carries an inline `# audit-ignore` marker.
#     GATED        - the match sits within a few lines of a LOG_RAW_* /
#                    log_raw_* debug-flag check (this codebase gates verbose
#                    raw-payload logging behind explicit opt-in settings; see
#                    config/settings.py LOG_RAW_API_PAYLOADS et al).
#     REDACTED     - the match sits within a few lines of a call/helper whose
#                    name contains "redact" (this codebase has
#                    core/diagnostics.py::redact_sensitive_error_text() and
#                    config/logging_config.py redaction regexes for exactly
#                    this purpose).
#     REVIEW       - HEADER_LOG/SECRET_LOG match with no string-interpolation
#                    marker on the line (looks like a static English message
#                    that happens to contain the word, e.g. "token configured",
#                    not an interpolated secret value); or any EXFIL match.
#   The script exits 1 if any HIGH finding remains after the above, exits 0
#   otherwise (including "clean" and "only INFO-tier findings").
#
# ALLOWLIST MECHANISM
#   1. Inline marker: append `# audit-ignore` to the offending line. That
#      single line is downgraded to ALLOWLISTED and never counts toward the
#      exit code, but it still prints so it stays visible for review.
#   2. Automatic context allowlisting: GATED and REDACTED above. These are not
#      a fixed list of hardcoded file paths (fragile) -- they are detected by
#      proximity to LOG_RAW_*/log_raw_* or *redact* in the surrounding lines,
#      so newly added gated debug paths or redaction helpers are recognized
#      without editing this script.
#   3. Optional allowlist file: pass -a/--allowlist FILE (or drop a file named
#      audit.allowlist next to this script) containing one extended-regex
#      pattern per line (matched against "path:line:text"); blank lines and
#      lines starting with # are ignored. Any finding whose "path:line:text"
#      matches a pattern is downgraded to ALLOWLISTED. Use this for cases the
#      inline marker cannot reach (e.g. generated files).
#
# USAGE
#   audit.sh [--allowlist FILE] [TARGET_DIR]
#   TARGET_DIR defaults to ./src, falling back to the repo's
#   src/free_claude_code if run from the repo root.
#
# REQUIREMENTS: POSIX sh + grep -E. Uses ripgrep (rg) automatically if present
# on PATH (faster); otherwise falls back to `grep -rEn`. No other deps.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROG_NAME=$(basename -- "$0")

usage() {
    cat <<EOF
Usage: ${PROG_NAME} [-a|--allowlist FILE] [-h|--help] [TARGET_DIR]

Heuristic scan for unauthorized secret logging / exfiltration in a Python
source tree. See the header comment of this script for full details on
categories, severity tiers, and the allowlist mechanism.

Arguments:
  TARGET_DIR          Directory to scan (default: ./src, or the repo's
                       src/free_claude_code if that exists instead).

Options:
  -a, --allowlist FILE  Extra allowlist file of extended-regex patterns,
                         one per line, matched against "path:line:text".
                         Defaults to audit.allowlist next to this script if
                         present.
  -h, --help             Show this help and exit.

Exit status:
  0  scan completed, no HIGH-confidence findings (or none at all)
  1  scan completed, at least one HIGH-confidence finding
  2  usage error / bad invocation
EOF
}

ALLOWLIST_FILE=""
TARGET_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            usage
            exit 0
            ;;
        -a | --allowlist)
            [ $# -ge 2 ] || {
                echo "${PROG_NAME}: --allowlist requires an argument" >&2
                exit 2
            }
            ALLOWLIST_FILE="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "${PROG_NAME}: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -n "$TARGET_DIR" ]; then
                echo "${PROG_NAME}: unexpected extra argument: $1" >&2
                usage >&2
                exit 2
            fi
            TARGET_DIR="$1"
            shift
            ;;
    esac
done

if [ -z "$TARGET_DIR" ]; then
    if [ -d "./src" ]; then
        TARGET_DIR="./src"
    elif [ -d "./src/free_claude_code" ]; then
        TARGET_DIR="./src/free_claude_code"
    else
        echo "${PROG_NAME}: no TARGET_DIR given and ./src not found" >&2
        usage >&2
        exit 2
    fi
fi

if [ ! -d "$TARGET_DIR" ]; then
    echo "${PROG_NAME}: target directory not found: ${TARGET_DIR}" >&2
    exit 2
fi

if [ -z "$ALLOWLIST_FILE" ] && [ -f "${SCRIPT_DIR}/audit.allowlist" ]; then
    ALLOWLIST_FILE="${SCRIPT_DIR}/audit.allowlist"
fi
if [ -n "$ALLOWLIST_FILE" ] && [ ! -f "$ALLOWLIST_FILE" ]; then
    echo "${PROG_NAME}: allowlist file not found: ${ALLOWLIST_FILE}" >&2
    exit 2
fi

USE_RG=0
if command -v rg >/dev/null 2>&1; then
    USE_RG=1
fi

# --- scratch space -----------------------------------------------------
# BSD mktemp (macOS) and GNU mktemp (Linux) disagree on what a bare `-t`
# flag means, so we sidestep that entirely: build an explicit template path
# under TMPDIR ourselves (both implementations accept a full template ending
# in XXXXXX with no -t needed) and fall back to a plain mkdir with a
# restrictive mode if mktemp is missing or fails for any reason.
_tmp_base="${TMPDIR:-/tmp}"
case "$_tmp_base" in
    */) _tmp_base="${_tmp_base%/}" ;;
esac
WORKDIR=$(mktemp -d "${_tmp_base}/audit_sh.XXXXXX" 2>/dev/null) || WORKDIR=""
if [ -z "$WORKDIR" ] || [ ! -d "$WORKDIR" ]; then
    WORKDIR="${_tmp_base}/audit_sh.$$"
    mkdir -m 700 -- "$WORKDIR" 2>/dev/null || {
        echo "${PROG_NAME}: could not create a scratch directory under ${_tmp_base}" >&2
        exit 2
    }
fi
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

FINDINGS_FILE="${WORKDIR}/findings.tsv" # category<TAB>severity<TAB>reason<TAB>path<TAB>line<TAB>text
: >"$FINDINGS_FILE"

HIGH_COUNT=0
INFO_COUNT=0

# --- helpers -------------------------------------------------------------

# raw_grep PATTERN  -> emits "path:line:text" for PATTERN across TARGET_DIR,
# restricted to *.py files, case-insensitive extended regex.
raw_grep() {
    pattern="$1"
    if [ "$USE_RG" -eq 1 ]; then
        rg -n -i --no-heading -g '*.py' -e "$pattern" -- "$TARGET_DIR" 2>/dev/null || true
    else
        grep -rEni --include='*.py' -- "$pattern" "$TARGET_DIR" 2>/dev/null || true
    fi
}

# window FILE START END -> prints lines START..END of FILE (clamped at 1).
window() {
    file="$1"
    start="$2"
    end="$3"
    [ "$start" -lt 1 ] && start=1
    sed -n "${start},${end}p" -- "$file" 2>/dev/null || true
}

# classify FILE LINE TEXT CATEGORY -> prints "SEVERITY<TAB>REASON" to stdout.
# CATEGORY is one of ENV_DUMP/HEADER_LOG/SECRET_LOG/SECRET_WRITE/EXFIL; only
# HEADER_LOG/SECRET_LOG get the interpolation-marker REVIEW downgrade, and
# EXFIL is always REVIEW at best (never HIGH) per the header note above.
classify() {
    file="$1"
    line="$2"
    text="$3"
    category="$4"

    ctx_start=$((line - 3))
    ctx_end=$((line + 3))
    ctx=$(window "$file" "$ctx_start" "$ctx_end")
    key="${file}:${line}:${text}"

    case "$text" in
        *'# audit-ignore'*)
            printf 'ALLOWLISTED\tinline # audit-ignore marker\n'
            return
            ;;
    esac

    if [ -n "$ALLOWLIST_FILE" ]; then
        while IFS= read -r pat; do
            case "$pat" in
                '' | '#'*) continue ;;
            esac
            if printf '%s\n' "$key" | grep -Eq -- "$pat" 2>/dev/null; then
                printf 'ALLOWLISTED\tmatched allowlist pattern: %s\n' "$pat"
                return
            fi
        done <"$ALLOWLIST_FILE"
    fi

    if printf '%s' "$ctx" | grep -Eqi 'log_raw_'; then
        printf 'GATED\tnear a LOG_RAW_*/log_raw_* debug-flag check\n'
        return
    fi

    if printf '%s' "$ctx" | grep -Eqi 'redact'; then
        printf 'REDACTED\tnear a redact*() helper call\n'
        return
    fi

    if [ "$category" = "EXFIL" ]; then
        printf 'REVIEW\toutbound call carries secret-shaped data; confirm destination is an intended upstream provider, not attacker-controlled\n'
        return
    fi

    if [ "$category" = "HEADER_LOG" ] || [ "$category" = "SECRET_LOG" ]; then
        # Two independent signals for "this looks like a real value, not just
        # an English sentence that mentions the word":
        #   has_interp    - f-string/.format()/%-format/string-concat marker
        #                   (catches logger.info(f"api_key={api_key}") even
        #                   though quote-stripping below hides it).
        #   has_bare_word - the keyword still appears after stripping simple
        #                   quoted string spans, i.e. it is used as a bare
        #                   identifier/attribute (print(token), print(x.token))
        #                   rather than only inside a string literal.
        has_interp=0
        if printf '%s' "$text" | grep -Eq '\{|%[sr]|\.format\(|f["'"'"']|\+[[:space:]]*[A-Za-z_]'; then
            has_interp=1
        fi
        stripped=$(printf '%s' "$text" | sed -E 's/"[^"]*"//g; s/'"'"'[^'"'"']*'"'"'//g')
        has_bare_word=0
        if printf '%s' "$stripped" | grep -Eqi "${SECRET_KEYWORDS}|Authorization|x-api-key|api-key|Bearer|\.headers\b"; then
            has_bare_word=1
        fi
        if [ "$has_interp" -eq 0 ] && [ "$has_bare_word" -eq 0 ]; then
            printf 'REVIEW\tno string-interpolation marker and no bare identifier outside quotes; likely a static message mentioning the word\n'
            return
        fi
    fi

    printf 'HIGH\tmatches category pattern with no gating/redaction/interpolation mitigation found nearby\n'
}

# record CATEGORY PATTERN -> runs raw_grep, classifies each hit, appends to
# FINDINGS_FILE. Skips non-existent files defensively (race with editors etc).
record() {
    category="$1"
    pattern="$2"
    raw_grep "$pattern" | while IFS=: read -r file line text; do
        [ -f "$file" ] || continue
        case "$line" in
            '' | *[!0-9]*) continue ;;
        esac
        result=$(classify "$file" "$line" "$text" "$category")
        severity=$(printf '%s' "$result" | cut -f1)
        reason=$(printf '%s' "$result" | cut -f2-)
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$category" "$severity" "$reason" "$file" "$line" "$text" >>"$FINDINGS_FILE"
    done
}

# record_with_window CATEGORY ANCHOR_PATTERN NEARBY_PATTERN -> like record()
# but only keeps an anchor hit if NEARBY_PATTERN also matches somewhere in a
# window around the anchor line (used for SECRET_WRITE: "open(...,'w') NEAR a
# secret-shaped variable", since the variable is often on a following line).
record_with_window() {
    category="$1"
    anchor_pattern="$2"
    nearby_pattern="$3"
    raw_grep "$anchor_pattern" | while IFS=: read -r file line text; do
        [ -f "$file" ] || continue
        case "$line" in
            '' | *[!0-9]*) continue ;;
        esac
        ctx=$(window "$file" "$((line - 2))" "$((line + 4))")
        if ! printf '%s' "$ctx" | grep -Eqi -- "$nearby_pattern"; then
            continue
        fi
        result=$(classify "$file" "$line" "$text" "$category")
        severity=$(printf '%s' "$result" | cut -f1)
        reason=$(printf '%s' "$result" | cut -f2-)
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$category" "$severity" "$reason" "$file" "$line" "$text" >>"$FINDINGS_FILE"
    done
}

# record_multiline CATEGORY ANCHOR_PATTERN PAYLOAD_PATTERN -> like
# record_with_window but for EXFIL: keep the HTTP-call anchor line only if a
# following window (kwargs often wrap onto the next few lines) mentions
# env/headers/key-like content.
record_multiline() {
    record_with_window "$1" "$2" "$3"
}

# \bsk_ and \bghp_ are token-value prefixes (Stripe-style secret keys, GitHub
# personal access tokens); the leading \b keeps them from firing on unrelated
# words that merely contain the substring (e.g. "task_id", "desk_lookup").
# GITHUB_TOKEN and OPENAI_API_KEY are already implied by the generic
# token/api[_-]?key terms above but are listed explicitly for readability.
SECRET_KEYWORDS='api[_-]?key|apikey|secret|token|password|auth_token|ANTHROPIC_AUTH_TOKEN|\bsk_|\bghp_|GITHUB_TOKEN|OPENAI_API_KEY'

# 1. ENV_DUMP -------------------------------------------------------------
# json\.(dump|dumps) covers both json.dumps(os.environ) (to a string) and
# json.dump(os.environ, f) (wholesale env write straight to a file handle).
record 'ENV_DUMP' \
    '(print|logger\.[a-zA-Z_]+|json\.(dump|dumps))\(.*(os\.environ|dict\(os\.environ\))'

# 2. HEADER_LOG -------------------------------------------------------------
record 'HEADER_LOG' \
    '(print|logger\.[a-zA-Z_]+)\(.*\.headers\b'
record 'HEADER_LOG' \
    '(print|logger\.[a-zA-Z_]+)\(.*(Authorization|x-api-key|api-key|Bearer)'

# 3. SECRET_LOG -------------------------------------------------------------
record 'SECRET_LOG' \
    "(print|logger\\.[a-zA-Z_]+)\\(.*(${SECRET_KEYWORDS})"

# 4. SECRET_WRITE (open(...,'w') or Path.write_text near a secret variable) -
record_with_window 'SECRET_WRITE' \
    "open\\([^)]*['\"][wa]['\"]" \
    "${SECRET_KEYWORDS}"
record_with_window 'SECRET_WRITE' \
    '\.write_text\(' \
    "${SECRET_KEYWORDS}"

# 5. EXFIL (outbound HTTP call with secret-shaped payload/params/headers) ---
# Note: the payload-side alternation deliberately does NOT include the bare
# word "headers" -- every anchor line with a headers= kwarg would trivially
# contain that substring in the kwarg name itself, making the check a no-op.
# Instead it looks for `.headers` attribute access (forwarding someone else's
# headers object wholesale, e.g. headers=incoming_request.headers) or an
# actual env/key-like identifier in the value.
record_multiline 'EXFIL' \
    '\b(requests|httpx|aiohttp|urllib\.request|client|session)\.[a-zA-Z_]*(post|put|patch|get|stream|request|urlopen)\(' \
    "(headers[[:space:]]*=|params[[:space:]]*=|json[[:space:]]*=|data[[:space:]]*=|body[[:space:]]*=).*(os\\.environ|\\.headers\\b|${SECRET_KEYWORDS})"

# Dedupe: a single line can match more than one pattern within the same
# category (e.g. HEADER_LOG has two patterns). Keep the first classification
# per (category, file, line).
DEDUPED="${WORKDIR}/findings.dedup.tsv"
awk -F '\t' '!seen[$1 FS $4 FS $5]++' "$FINDINGS_FILE" >"$DEDUPED"
mv "$DEDUPED" "$FINDINGS_FILE"

# --- report ----------------------------------------------------------------

CATEGORY_ORDER='ENV_DUMP HEADER_LOG SECRET_LOG SECRET_WRITE EXFIL'

echo "audit.sh -- heuristic secret-logging / exfiltration scan"
echo "target: ${TARGET_DIR}"
if [ -n "$ALLOWLIST_FILE" ]; then
    echo "allowlist: ${ALLOWLIST_FILE}"
fi
if [ "$USE_RG" -eq 1 ]; then
    echo "engine: ripgrep"
else
    echo "engine: grep -rEn"
fi
echo "This is a heuristic static scan, not a guarantee. Review every finding."
echo

for category in $CATEGORY_ORDER; do
    cat_rows=$(awk -F '\t' -v c="$category" '$1==c' "$FINDINGS_FILE")
    [ -z "$cat_rows" ] && continue

    echo "== ${category} =========================================================="
    printf '%s\n' "$cat_rows" | while IFS='	' read -r cat sev reason file line text; do
        printf '%s:%s: %s [%s]: %s\n' "$file" "$line" "$cat" "$sev" "$text"
        printf '    reason: %s\n' "$reason"
    done
    echo
done

TOTAL=$(wc -l <"$FINDINGS_FILE" | tr -d ' ')
HIGH_COUNT=$(awk -F '\t' '$2=="HIGH"' "$FINDINGS_FILE" | wc -l | tr -d ' ')
INFO_COUNT=$((TOTAL - HIGH_COUNT))

echo "== summary =================================================================="
for category in $CATEGORY_ORDER; do
    n=$(awk -F '\t' -v c="$category" '$1==c' "$FINDINGS_FILE" | wc -l | tr -d ' ')
    n_high=$(awk -F '\t' -v c="$category" '$1==c && $2=="HIGH"' "$FINDINGS_FILE" | wc -l | tr -d ' ')
    printf '%-14s total=%-4s high=%s\n' "$category" "$n" "$n_high"
done
echo "-----------------------------------------------------------------------------"
printf 'TOTAL findings: %s (HIGH: %s, INFO-tier: %s)\n' "$TOTAL" "$HIGH_COUNT" "$INFO_COUNT"
echo

if [ "$HIGH_COUNT" -gt 0 ]; then
    echo "RESULT: FAIL -- ${HIGH_COUNT} HIGH-confidence finding(s). Review the lines above."
    exit 1
fi

echo "RESULT: PASS -- no HIGH-confidence findings (INFO-tier items, if any, still deserve a look)."
exit 0
