#!/bin/sh
set -eu

# Supply-chain-hardened installer for Free Claude Code.
#
# Every remotely downloaded installer script or release artifact is verified
# against a pinned sha256 in scripts/install.checksums BEFORE it is executed or
# extracted. The installer is FAIL-CLOSED: a component whose expected checksum is
# missing or the literal token REPLACE_ME is refused unless --allow-unpinned is
# passed. Free Claude Code itself is installed from a git checkout pinned to an
# exact commit, not an unversioned archive.
#
# npm-distributed agents (Cline, DeepSeek Harness) are pinned to an exact
# version (never a floating "latest") and are fetched via `npm pack` into an
# isolated temp dir -- a plain artifact download that runs no lifecycle
# scripts -- so the downloaded tarball can be sha256-verified against the same
# manifest and FAIL-CLOSED policy as every other component before anything is
# installed. Residual trust: this verifies the package ARTIFACT; it does not
# and cannot sandbox the package's own preinstall/postinstall scripts, which
# still execute with your user's privileges during the final
# `npm install -g <verified-tarball>` step, same as any npm package. That is a
# property of npm's package model, not a gap in this installer's verification.

FCC_REPO_URL="https://github.com/alishahryar1/free-claude-code"
# Default pinned Free Claude Code commit (real, verified main HEAD).
FCC_COMMIT="9372cfa5e2dc48fe1adf9743473f3763b3b08592"
PYTHON_VERSION="3.14.0"
MIN_UV_VERSION="0.11.16"
# uv is pinned to a versioned astral-sh/uv release artifact (not the rolling
# astral.sh/uv/install.sh script). The per-platform sha256 lives in the manifest.
UV_VERSION="0.11.16"
UV_RELEASE_BASE_URL="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
CLAUDE_INSTALL_URL="https://claude.ai/install.sh"
CODEX_INSTALL_URL="https://chatgpt.com/codex/install.sh"
PI_INSTALL_URL="https://pi.dev/install.sh"
OPENCODE_INSTALL_URL="https://opencode.ai/install"
MIN_OPENCODE_VERSION="1.18.18"
MIN_CLINE_VERSION="3.0.55"
# Exact npm pin for fresh Cline installs (no floating "latest"). An
# already-installed Cline satisfying >=MIN_CLINE_VERSION is left unchanged;
# see ensure_cline. Pinned to the same version because it is also the oldest
# version this installer has verified compatible.
CLINE_PACKAGE="cline@$MIN_CLINE_VERSION"
HERMES_INSTALL_URL="https://hermes-agent.nousresearch.com/install.sh"
MIN_HERMES_VERSION="0.20.4"
DSH_VERSION="0.1.0-rc.8"
DSH_PACKAGE="@deepseek-ai/dsh@$DSH_VERSION"
GROK_INSTALL_URL="https://x.ai/cli/install.sh"
MIN_GROK_VERSION="1.0.5"
MUSE_INSTALL_URL="https://dev.meta.ai/install.sh"
MIN_MUSE_VERSION="0.2.1"
RTK_VERSION="0.44.2"
RTK_RELEASE_BASE_URL="https://github.com/rtk-ai/rtk/releases/download/v$RTK_VERSION"
FCC_MACOS_BUNDLE_ID="io.github.alishahryar1.free-claude-code"
FCC_MACOS_OWNER_FILE=".free-claude-code-owner"
# Include retired entry points so updates reject older FCC processes before replacement.
FCC_COMMANDS="fcc-desktop fcc-server fcc-claude fcc-codex fcc-pi fcc-opencode fcc-cline fcc-hermes fcc-dsh fcc-grok fcc-muse fcc-init free-claude-code"

dry_run=0
voice_nim=0
voice_local=0
voice_all=0
install_claude=1
install_codex=1
install_pi=1
install_opencode=1
install_cline=0
install_hermes=1
install_dsh=1
install_grok=1
install_muse=1
enable_rtk=0
torch_backend=""
allow_unpinned=0
refresh_mode=0
checksums_file_cli=""
checksums_file=""
script_dir="."
fcc_ref="$FCC_COMMIT"
fcc_source_url=""
temporary_file=""
temporary_binary=""
temporary_dir=""
tool_bin=""
pi_available=0
rtk_path=""
expected_checksum=""
checksum_mode=""

show_usage() {
    cat <<'USAGE'
Usage: install.sh [options]

Installs or updates Free Claude Code and lets you choose which coding agents to install or verify.
Every downloaded installer script and release artifact -- including npm-distributed agents (Cline,
DeepSeek Harness), which are pinned to an exact version and packed via `npm pack` for verification
before install -- is checksum-verified against a pinned manifest (scripts/install.checksums) before
it runs. Unpinned components are refused unless you explicitly pass --allow-unpinned.

Options:
  --voice-nim              Install NVIDIA NIM voice transcription support.
  --voice-local            Install local Whisper voice transcription support.
  --voice-all              Install all voice transcription backends.
  --torch-backend VALUE    Use a uv PyTorch backend, such as cu130. Requires local voice.
  --rtk                    Install and configure RTK for the selected coding agents.
  --fcc-ref SHA            Install Free Claude Code at this git commit (default: pinned commit).
  --checksums PATH         Path to the checksum manifest (default: install.checksums beside this script).
  --allow-unpinned         Execute components without a pinned checksum. INSECURE; prints a warning.
  --refresh-checksums      Download each installer/artifact, print id=sha256 lines, and exit.
                           Does NOT execute anything and does NOT modify the manifest.
  --dry-run                Print commands without running them.
  --help                   Show this help text.
USAGE
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

installer_is_interactive() {
    [ -t 1 ] && ( : </dev/tty ) 2>/dev/null
}

prompt_yes_no() {
    question=$1
    default_answer=${2:-yes}
    case "$default_answer" in
        yes) prompt='[Y/n]' ;;
        no) prompt='[y/N]' ;;
        *) fail "Unsupported prompt default: $default_answer" ;;
    esac

    while :; do
        printf '%s %s ' "$question" "$prompt" >&4
        if ! IFS= read -r answer <&3; then
            fail "Could not read the installer selection."
        fi
        case "$answer" in
            '')
                if [ "$default_answer" = "yes" ]; then
                    return 0
                fi
                return 1
                ;;
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) printf 'Please answer Y or N.\n' >&4 ;;
        esac
    done
}

choose_coding_agents() {
    selection_input=$1
    selection_output=$2
    exec 3<"$selection_input"
    exec 4>"$selection_output"

    while :; do
        if prompt_yes_no "Install or verify Claude Code for fcc-claude?"; then
            install_claude=1
        else
            install_claude=0
        fi
        if prompt_yes_no "Install or verify Codex for fcc-codex?"; then
            install_codex=1
        else
            install_codex=0
        fi
        if prompt_yes_no "Install or verify Pi for fcc-pi?"; then
            install_pi=1
        else
            install_pi=0
        fi
        if prompt_yes_no "Install or verify OpenCode for fcc-opencode?"; then
            install_opencode=1
        else
            install_opencode=0
        fi

        if [ "$install_cline" -eq 1 ]; then
            cline_default=yes
        else
            cline_default=no
        fi
        if prompt_yes_no "Install or verify Cline CLI for fcc-cline?" "$cline_default"; then
            install_cline=1
        else
            install_cline=0
        fi

        if [ "$install_hermes" -eq 1 ]; then
            hermes_default=yes
        else
            hermes_default=no
        fi
        if prompt_yes_no "Install or verify Hermes Agent for fcc-hermes?" "$hermes_default"; then
            install_hermes=1
        else
            install_hermes=0
        fi

        if [ "$install_dsh" -eq 1 ]; then
            dsh_default=yes
        else
            dsh_default=no
        fi
        if prompt_yes_no "Install or verify DeepSeek Harness for fcc-dsh?" "$dsh_default"; then
            install_dsh=1
        else
            install_dsh=0
        fi

        if [ "$install_grok" -eq 1 ]; then
            grok_default=yes
        else
            grok_default=no
        fi
        if prompt_yes_no "Install or verify Grok Build for fcc-grok?" "$grok_default"; then
            install_grok=1
        else
            install_grok=0
        fi

        if [ "$install_muse" -eq 1 ]; then
            muse_default=yes
        else
            muse_default=no
        fi
        if prompt_yes_no "Install or verify Muse Code for fcc-muse?" "$muse_default"; then
            install_muse=1
        else
            install_muse=0
        fi

        if [ "$install_claude" -eq 1 ] || [ "$install_codex" -eq 1 ] || [ "$install_pi" -eq 1 ] || [ "$install_opencode" -eq 1 ] || [ "$install_cline" -eq 1 ] || [ "$install_hermes" -eq 1 ] || [ "$install_dsh" -eq 1 ] || [ "$install_grok" -eq 1 ] || [ "$install_muse" -eq 1 ]; then
            break
        fi
        printf 'Select at least one coding agent.\n\n' >&4
    done

    if [ "$enable_rtk" -eq 0 ] &&
        prompt_yes_no "Enable RTK token optimization globally for the selected coding agents?" no; then
        enable_rtk=1
    fi

    exec 3<&-
    exec 4>&-
}

step() {
    printf '\n==> %s\n' "$1"
}

quote_arg() {
    case "$1" in
        *[!A-Za-z0-9_./:@%+=,-]*|"")
            escaped=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
            printf '"%s"' "$escaped"
            ;;
        *)
            printf '%s' "$1"
            ;;
    esac
}

print_command() {
    printf '+'
    for arg in "$@"; do
        printf ' '
        quote_arg "$arg"
    done
    printf '\n'
}

run() {
    print_command "$@"
    if [ "$dry_run" -eq 1 ]; then
        return 0
    fi

    if "$@"; then
        return 0
    else
        status=$?
    fi

    fail "Command failed with exit code $status: $1"
}

cleanup() {
    if [ -n "$temporary_file" ] && [ -e "$temporary_file" ]; then
        rm -f "$temporary_file"
    fi
    if [ -n "$temporary_binary" ] && [ -e "$temporary_binary" ]; then
        rm -f "$temporary_binary"
    fi
    if [ -n "$temporary_dir" ] && [ -d "$temporary_dir" ]; then
        rm -rf "$temporary_dir"
    fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# ---------------------------------------------------------------------------
# Checksum manifest + verification
# ---------------------------------------------------------------------------

resolve_script_dir() {
    case "$0" in
        /*) script_dir=$(dirname "$0") ;;
        *) script_dir=$(dirname "$(pwd)/$0") ;;
    esac
}

resolve_checksums_file() {
    if [ -n "$checksums_file_cli" ]; then
        checksums_file=$checksums_file_cli
    elif [ -n "${FCC_CHECKSUMS_FILE:-}" ]; then
        checksums_file=$FCC_CHECKSUMS_FILE
    else
        checksums_file="$script_dir/install.checksums"
    fi
}

require_sha256_tool() {
    [ "$dry_run" -eq 0 ] || return 0
    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1; then
        return 0
    fi
    fail "This installer requires sha256sum or 'shasum -a 256' for checksum verification. Install one, then rerun."
}

compute_sha256() {
    file=$1
    if command -v sha256sum >/dev/null 2>&1; then
        out=$(sha256sum "$file") || return 1
    elif command -v shasum >/dev/null 2>&1; then
        out=$(shasum -a 256 "$file") || return 1
    else
        return 1
    fi
    printf '%s' "${out%% *}"
}

# Print the pinned sha256 for a component id, or nothing if absent.
manifest_lookup() {
    lookup_id=$1
    [ -f "$checksums_file" ] || return 0
    while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
        case "$manifest_line" in
            '#'*|'') continue ;;
        esac
        manifest_key=${manifest_line%%=*}
        manifest_value=${manifest_line#*=}
        manifest_key=$(printf '%s' "$manifest_key" | tr -d '[:space:]')
        if [ "$manifest_key" = "$lookup_id" ]; then
            # Strip any inline comment (from the first '#') and all surrounding
            # whitespace so "id=REPLACE_ME # note" still reads as the REPLACE_ME
            # sentinel (fail-closed) rather than a bogus pin. Valid values (hex or
            # REPLACE_ME) never contain '#'.
            manifest_value=${manifest_value%%#*}
            printf '%s' "$(printf '%s' "$manifest_value" | tr -d '[:space:]')"
            return 0
        fi
    done < "$checksums_file"
}

print_unpinned_banner() {
    {
        printf '%s\n' '********************************************************************************'
        printf '%s\n' '*                   SECURITY WARNING: --allow-unpinned is set                 *'
        printf '%s\n' '*                                                                            *'
        printf '%s\n' '* Checksum verification is DISABLED for every component whose sha256 is       *'
        printf '%s\n' '* missing or REPLACE_ME in the manifest. Downloaded installer scripts and     *'
        printf '%s\n' '* release artifacts will be EXECUTED WITHOUT integrity verification.          *'
        printf '%s\n' '* This exposes you to supply-chain tampering and man-in-the-middle attacks.   *'
        printf '%s\n' '* Only continue if you fully trust your network path and every upstream       *'
        printf '%s\n' '* vendor. Prefer pinning real hashes via --refresh-checksums instead.         *'
        printf '%s\n' '********************************************************************************'
    } >&2
}

# Decide how a component must be handled. Sets expected_checksum and checksum_mode
# to "verify" or "skip", or fails closed.
resolve_component_checksum() {
    component_id=$1
    label=$2
    expected_checksum=$(manifest_lookup "$component_id")

    if [ -n "$expected_checksum" ] && [ "$expected_checksum" != "REPLACE_ME" ]; then
        checksum_mode="verify"
        return 0
    fi

    if [ "$allow_unpinned" -eq 1 ]; then
        checksum_mode="skip"
        printf 'warning: no pinned sha256 for component "%s" (%s); executing UNVERIFIED because --allow-unpinned is set.\n' "$component_id" "$label" >&2
        return 0
    fi

    if [ ! -f "$checksums_file" ]; then
        fail "Checksum manifest not found at $checksums_file. This hardened installer refuses to run downloaded code without it. Run from a repository checkout, set FCC_CHECKSUMS_FILE, pass --checksums <path>, or re-run with --allow-unpinned (NOT recommended)."
    fi

    fail "No pinned sha256 for component \"$component_id\" ($label) in $checksums_file (value is missing or REPLACE_ME). Refusing to run unverified code. Run 'install.sh --refresh-checksums' to compute it, review it against a trusted source, paste the id=hash line into the manifest, then rerun; or re-run with --allow-unpinned to bypass verification (NOT recommended)."
}

# Verify an already-downloaded file for a component, or fail.
verify_downloaded_file() {
    file=$1
    label=$2
    component_id=$3

    resolve_component_checksum "$component_id" "$label"

    actual_checksum=$(compute_sha256 "$file") || fail "Could not compute the sha256 of the downloaded $label file."

    if [ "$checksum_mode" = "skip" ]; then
        printf 'warning: %s executed without verification; computed sha256=%s (component id: %s)\n' "$label" "$actual_checksum" "$component_id" >&2
        return 0
    fi

    if [ "$actual_checksum" != "$expected_checksum" ]; then
        fail "Checksum verification failed for $label (component id: $component_id): expected $expected_checksum, computed $actual_checksum. Refusing to continue."
    fi
    printf 'Verified %s against pinned sha256 (component id: %s).\n' "$label" "$component_id"
}

refresh_one() {
    refresh_id=$1
    refresh_url=$2
    refresh_tmp=$(mktemp "${TMPDIR:-/tmp}/fcc-refresh.XXXXXX") || {
        printf '# %s: could not create a temporary file\n' "$refresh_id" >&2
        return 0
    }
    if curl -fsSL "$refresh_url" -o "$refresh_tmp"; then
        if [ -s "$refresh_tmp" ]; then
            refresh_hash=$(compute_sha256 "$refresh_tmp") || refresh_hash=""
            if [ -n "$refresh_hash" ]; then
                printf '%s=%s\n' "$refresh_id" "$refresh_hash"
            else
                printf '# %s: could not compute sha256\n' "$refresh_id" >&2
            fi
        else
            printf '# %s: downloaded file was empty (%s)\n' "$refresh_id" "$refresh_url" >&2
        fi
    else
        printf '# %s: download failed (%s)\n' "$refresh_id" "$refresh_url" >&2
    fi
    rm -f "$refresh_tmp"
}

# Like refresh_one, but for an npm package: fetches the exact published
# tarball via `npm pack` (no lifecycle scripts run) instead of curl, then
# hashes it. Requires npm; silently skipped (with a comment) if unavailable
# so --refresh-checksums still works on platforms without Node.js.
refresh_npm_pack() {
    refresh_id=$1
    refresh_spec=$2

    if ! command -v npm >/dev/null 2>&1; then
        printf '# %s: npm not available; skipping\n' "$refresh_id" >&2
        return 0
    fi

    refresh_dir=$(mktemp -d "${TMPDIR:-/tmp}/fcc-refresh-npm.XXXXXX") || {
        printf '# %s: could not create a temporary directory\n' "$refresh_id" >&2
        return 0
    }
    if npm pack "$refresh_spec" --pack-destination "$refresh_dir" --ignore-scripts >/dev/null 2>&1; then
        refresh_tarball=$(find "$refresh_dir" -maxdepth 1 -name '*.tgz' -type f | head -n 1)
        if [ -n "$refresh_tarball" ] && [ -f "$refresh_tarball" ]; then
            refresh_hash=$(compute_sha256 "$refresh_tarball") || refresh_hash=""
            if [ -n "$refresh_hash" ]; then
                printf '%s=%s\n' "$refresh_id" "$refresh_hash"
            else
                printf '# %s: could not compute sha256\n' "$refresh_id" >&2
            fi
        else
            printf '# %s: npm pack did not produce a tarball (%s)\n' "$refresh_id" "$refresh_spec" >&2
        fi
    else
        printf '# %s: npm pack failed (%s)\n' "$refresh_id" "$refresh_spec" >&2
    fi
    rm -rf "$refresh_dir"
}

refresh_all_checksums() {
    printf '# install.sh --refresh-checksums output.\n'
    printf '# Review every hash against a trusted source (vendor release page / published\n'
    printf '# checksums) before pasting it into %s, replacing REPLACE_ME.\n' "$checksums_file"
    printf '# Platform: %s %s\n' "$(uname -s)" "$(uname -m)"
    refresh_one "claude-installer" "$CLAUDE_INSTALL_URL"
    refresh_one "codex-installer" "$CODEX_INSTALL_URL"
    refresh_one "pi-installer" "$PI_INSTALL_URL"
    refresh_one "opencode-installer" "$OPENCODE_INSTALL_URL"
    refresh_one "hermes-installer" "$HERMES_INSTALL_URL"
    refresh_one "grok-installer" "$GROK_INSTALL_URL"
    refresh_one "muse-installer" "$MUSE_INSTALL_URL"
    select_uv_release
    refresh_one "$uv_component_id" "$uv_archive_url"
    select_rtk_release
    refresh_one "$rtk_component_id" "$rtk_archive_url"
    refresh_npm_pack "npm-cline-$MIN_CLINE_VERSION" "$CLINE_PACKAGE"
    refresh_npm_pack "npm-dsh-$DSH_VERSION" "$DSH_PACKAGE"
}

add_path_entry() {
    [ -n "$1" ] || return 0
    case ":$PATH:" in
        *":$1:"*) ;;
        *) PATH="$1:$PATH" ;;
    esac
}

add_known_bin_directories() {
    if [ -n "${XDG_BIN_HOME:-}" ]; then
        add_path_entry "$XDG_BIN_HOME"
    fi

    if [ -n "${HOME:-}" ]; then
        add_path_entry "$HOME/.local/bin"
        add_path_entry "$HOME/.cargo/bin"
        add_path_entry "$HOME/.opencode/bin"
        add_path_entry "${XDG_DATA_HOME:-$HOME/.local/share}/pi-node/current/bin"
    fi

    export PATH
    hash -r 2>/dev/null || true
}

add_npm_bin_directories() {
    [ "$dry_run" -eq 0 ] || return 0
    add_known_bin_directories
    if command -v npm >/dev/null 2>&1; then
        pi_npm_prefix=$(npm prefix -g 2>/dev/null || npm config get prefix 2>/dev/null || true)
        if [ -n "$pi_npm_prefix" ]; then
            add_path_entry "$pi_npm_prefix/bin"
            export PATH
            hash -r 2>/dev/null || true
        fi
    fi
}

fcc_process_ids() {
    command_name=$1

    if command -v pgrep >/dev/null 2>&1; then
        {
            pgrep -x "$command_name" 2>/dev/null || true
            pgrep -f "(^|/)${command_name}([[:space:]]|$)" 2>/dev/null || true
        } | sort -nu
        return 0
    fi

    ps -A -o pid= -o args= 2>/dev/null |
        awk -v command_name="$command_name" '
            BEGIN {
                pattern = "(^|/)" command_name "([[:space:]]|$)"
            }
            {
                process_id = $1
                sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "")
                if ($0 ~ pattern) {
                    print process_id
                }
            }
        ' || true
}

assert_no_fcc_processes_running() {
    running=""
    for command_name in $FCC_COMMANDS; do
        process_ids=$(fcc_process_ids "$command_name")
        [ -n "$process_ids" ] || continue

        for process_id in $process_ids; do
            process="$command_name (PID $process_id)"
            if [ -n "$running" ]; then
                running="$running, $process"
            else
                running=$process
            fi
        done
    done

    if [ -n "$running" ]; then
        fail "Free Claude Code is still running ($running). Stop those processes, then rerun the installer."
    fi
}

require_command() {
    if [ "$dry_run" -eq 0 ] && ! command -v "$1" >/dev/null 2>&1; then
        fail "$1 is required. Install it first, then rerun this installer."
    fi
}

# download_verify_and_run URL INTERPRETER LABEL COMPONENT_ID [NON_INTERACTIVE] [ARGS...]
download_verify_and_run() {
    url=$1
    interpreter=$2
    label=$3
    component_id=$4
    shift 4
    non_interactive=0
    if [ "$#" -gt 0 ]; then
        non_interactive=$1
        shift
    fi

    if [ "$dry_run" -eq 1 ]; then
        print_command curl -fsSL "$url" -o "<temporary-script>"
        printf '+ verify sha256 of <temporary-script> against %s (component: %s)\n' "$checksums_file" "$component_id"
        if [ "$non_interactive" -eq 1 ]; then
            printf '+ CODEX_NON_INTERACTIVE=1 '
            quote_arg "$interpreter"
            printf ' <temporary-script>'
            for arg in "$@"; do
                printf ' '
                quote_arg "$arg"
            done
            printf '\n'
        else
            print_command "$interpreter" "<temporary-script>" "$@"
        fi
        return 0
    fi

    temporary_file=$(mktemp "${TMPDIR:-/tmp}/fcc-install.XXXXXX") || fail "Unable to create a temporary file for $label."
    print_command curl -fsSL "$url" -o "$temporary_file"
    if curl -fsSL "$url" -o "$temporary_file"; then
        :
    else
        status=$?
        fail "Could not download the $label installer (curl exit code $status)."
    fi

    if [ ! -s "$temporary_file" ]; then
        fail "The downloaded $label installer was empty."
    fi

    verify_downloaded_file "$temporary_file" "$label" "$component_id"

    if [ "$non_interactive" -eq 1 ]; then
        printf '+ CODEX_NON_INTERACTIVE=1 '
        quote_arg "$interpreter"
        printf ' '
        quote_arg "$temporary_file"
        for arg in "$@"; do
            printf ' '
            quote_arg "$arg"
        done
        printf '\n'
        if CODEX_NON_INTERACTIVE=1 "$interpreter" "$temporary_file" "$@"; then
            :
        else
            status=$?
            fail "$label installation failed with exit code $status."
        fi
    else
        print_command "$interpreter" "$temporary_file" "$@"
        if "$interpreter" "$temporary_file" "$@"; then
            :
        else
            status=$?
            fail "$label installation failed with exit code $status."
        fi
    fi

    rm -f "$temporary_file"
    temporary_file=""
}

# npm_pack_verify_and_install_global PACKAGE_SPEC LABEL COMPONENT_ID
#
# Fetches the exact published npm tarball for PACKAGE_SPEC via `npm pack`
# into an isolated temp dir. `npm pack` on a registry spec is a plain
# artifact download -- it does not run the target package's lifecycle
# scripts -- so the downloaded bytes can be sha256-verified against the
# pinned manifest exactly like every other downloaded artifact in this
# installer (see verify_downloaded_file), fail-closed by the same
# --allow-unpinned policy. Only after verification does it install globally
# FROM the verified local tarball, so the bytes that get installed are
# exactly the bytes that were hashed (no second, unverified registry
# round-trip).
#
# Residual trust: this verifies the package ARTIFACT. It does not sandbox
# the npm package's own preinstall/postinstall scripts, which still run
# with the invoking user's privileges during the final `npm install -g`,
# same as any npm package -- that is inherent to npm's package model and is
# not fixable with a shell-level checksum gate alone.
npm_pack_verify_and_install_global() {
    package_spec=$1
    label=$2
    component_id=$3

    if [ "$dry_run" -eq 1 ]; then
        print_command npm pack "$package_spec" --pack-destination "<temporary-dir>" --ignore-scripts
        printf '+ verify sha256 of the packed %s tarball against %s (component: %s)\n' "$label" "$checksums_file" "$component_id"
        print_command npm install -g --no-fund --no-audit=false "<verified-tarball>"
        return 0
    fi

    require_command npm

    temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/fcc-npm-pack.XXXXXX") || fail "Unable to create a temporary directory for $label."
    print_command npm pack "$package_spec" --pack-destination "$temporary_dir" --ignore-scripts
    if npm pack "$package_spec" --pack-destination "$temporary_dir" --ignore-scripts >/dev/null; then
        :
    else
        status=$?
        fail "Could not download the $label npm package ($package_spec; npm pack exit code $status)."
    fi

    npm_tarball=$(find "$temporary_dir" -maxdepth 1 -name '*.tgz' -type f | head -n 1)
    [ -n "$npm_tarball" ] && [ -f "$npm_tarball" ] || fail "npm pack did not produce a tarball for $label ($package_spec)."

    verify_downloaded_file "$npm_tarball" "$label" "$component_id"

    run npm install -g --no-fund --no-audit=false "$npm_tarball"

    rm -rf "$temporary_dir"
    temporary_dir=""
}

verify_command() {
    command_name=$1
    display_name=$2

    if [ "$dry_run" -eq 1 ]; then
        print_command "$command_name" --version
        return 0
    fi

    command_path=$(command -v "$command_name" 2>/dev/null) || fail "$display_name was installed, but '$command_name' is not available on PATH."
    run "$command_path" --version
}

pi_command_is_compatible() {
    pi_command_path=$(command -v pi 2>/dev/null) || return 1
    pi_help=$("$pi_command_path" --help 2>/dev/null) || return 1
    case "$pi_help" in
        *--extension*) ;;
        *) return 1 ;;
    esac
    case "$pi_help" in
        *--models*) return 0 ;;
        *) return 1 ;;
    esac
}

verify_pi_command() {
    if [ "$dry_run" -eq 1 ]; then
        printf '+ pi --help (verify --extension and --models support)\n'
        print_command pi --version
        return 0
    fi

    pi_command_path=$(command -v pi 2>/dev/null) || fail "Pi was installed, but 'pi' is not available on PATH."
    pi_command_is_compatible || fail "The 'pi' command at $pi_command_path is not a compatible Pi Coding Agent."
    run "$pi_command_path" --version
}

verify_rtk_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command env RTK_TELEMETRY_DISABLED=1 rtk --version
        print_command env RTK_TELEMETRY_DISABLED=1 rtk gain
        return 0
    fi

    rtk_path=$(command -v rtk 2>/dev/null) || fail "RTK was installed, but 'rtk' is not available on PATH."
    print_command env RTK_TELEMETRY_DISABLED=1 "$rtk_path" --version
    if ! RTK_TELEMETRY_DISABLED=1 "$rtk_path" --version; then
        fail "The 'rtk' command at $rtk_path is not a compatible Rust Token Killer installation. Remove the conflicting command from PATH, then rerun the installer."
    fi

    print_command env RTK_TELEMETRY_DISABLED=1 "$rtk_path" gain
    if ! RTK_TELEMETRY_DISABLED=1 "$rtk_path" gain; then
        fail "The 'rtk' command at $rtk_path is not a compatible Rust Token Killer installation. Remove the conflicting command from PATH, then rerun the installer."
    fi
}

select_rtk_release() {
    rtk_platform=$(uname -s)
    rtk_architecture=$(uname -m)
    case "$rtk_platform:$rtk_architecture" in
        Linux:x86_64|Linux:amd64)
            rtk_asset_name="rtk-x86_64-unknown-linux-musl.tar.gz"
            rtk_component_id="rtk-$RTK_VERSION-x86_64-unknown-linux-musl"
            ;;
        Linux:aarch64|Linux:arm64)
            rtk_asset_name="rtk-aarch64-unknown-linux-gnu.tar.gz"
            rtk_component_id="rtk-$RTK_VERSION-aarch64-unknown-linux-gnu"
            ;;
        Darwin:x86_64|Darwin:amd64)
            rtk_asset_name="rtk-x86_64-apple-darwin.tar.gz"
            rtk_component_id="rtk-$RTK_VERSION-x86_64-apple-darwin"
            ;;
        Darwin:aarch64|Darwin:arm64)
            rtk_asset_name="rtk-aarch64-apple-darwin.tar.gz"
            rtk_component_id="rtk-$RTK_VERSION-aarch64-apple-darwin"
            ;;
        *)
            fail "RTK $RTK_VERSION does not provide a release for $rtk_platform $rtk_architecture."
            ;;
    esac
    rtk_archive_url="$RTK_RELEASE_BASE_URL/$rtk_asset_name"
}

install_rtk() {
    select_rtk_release
    if [ "$dry_run" -eq 1 ]; then
        print_command curl -fsSL "$rtk_archive_url" -o "<temporary-archive>"
        printf '+ verify sha256 for %s against %s (component: %s)\n' "$rtk_asset_name" "$checksums_file" "$rtk_component_id"
        printf '+ extract rtk to %s\n' "${HOME:-~}/.local/bin/rtk"
        return 0
    fi

    [ -n "${HOME:-}" ] || fail "HOME is required to install RTK."
    temporary_file=$(mktemp "${TMPDIR:-/tmp}/fcc-rtk.XXXXXX") || fail "Unable to create a temporary RTK archive."
    print_command curl -fsSL "$rtk_archive_url" -o "$temporary_file"
    if curl -fsSL "$rtk_archive_url" -o "$temporary_file"; then
        :
    else
        status=$?
        fail "Could not download RTK $RTK_VERSION (curl exit code $status)."
    fi
    [ -s "$temporary_file" ] || fail "The downloaded RTK archive was empty."

    verify_downloaded_file "$temporary_file" "RTK $RTK_VERSION archive ($rtk_asset_name)" "$rtk_component_id"

    if rtk_archive_entries=$(tar -tzf "$temporary_file"); then
        :
    else
        fail "The verified RTK archive could not be inspected."
    fi
    [ "$rtk_archive_entries" = "rtk" ] || fail "The verified RTK archive did not contain exactly one root rtk executable."

    rtk_install_directory="$HOME/.local/bin"
    run mkdir -p "$rtk_install_directory"
    temporary_binary=$(mktemp "$rtk_install_directory/.rtk.XXXXXX") || fail "Unable to create a temporary RTK executable."
    print_command tar -xOzf "$temporary_file" rtk
    if tar -xOzf "$temporary_file" rtk >"$temporary_binary"; then
        :
    else
        fail "The verified RTK archive could not be extracted."
    fi
    [ -s "$temporary_binary" ] || fail "The verified RTK executable was empty."
    run chmod +x "$temporary_binary"
    run mv "$temporary_binary" "$rtk_install_directory/rtk"
    temporary_binary=""
    rm -f "$temporary_file"
    temporary_file=""
}

ensure_rtk() {
    if command -v rtk >/dev/null 2>&1; then
        printf 'RTK already found on PATH; verifying it without updating it.\n'
    else
        install_rtk
        add_known_bin_directories
    fi

    verify_rtk_command
}

run_rtk_init() {
    print_command env RTK_TELEMETRY_DISABLED=1 rtk "$@"
    if [ "$dry_run" -eq 1 ]; then
        return 0
    fi

    if RTK_TELEMETRY_DISABLED=1 "$rtk_path" "$@"; then
        return 0
    else
        status=$?
    fi

    fail "RTK configuration failed with exit code $status. Correct the reported RTK error, then rerun the installer."
}

ensure_rtk_claude_config_directory() {
    if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        rtk_claude_config_directory=$CLAUDE_CONFIG_DIR
    else
        [ -n "${HOME:-}" ] || fail "HOME is required to configure RTK for Claude Code."
        rtk_claude_config_directory="$HOME/.claude"
    fi
    run mkdir -p "$rtk_claude_config_directory"
}

configure_rtk_for_selected_agents() {
    [ "$enable_rtk" -eq 1 ] || return 0

    step "Installing and configuring RTK token optimization"
    ensure_rtk

    if [ "$install_claude" -eq 1 ]; then
        ensure_rtk_claude_config_directory
        run_rtk_init init --global --auto-patch
    fi
    if [ "$install_codex" -eq 1 ]; then
        run_rtk_init init --global --codex
    fi
    if [ "$install_pi" -eq 1 ] && [ "$pi_available" -eq 1 ]; then
        run_rtk_init init --global --agent pi
    fi
    if [ "$install_opencode" -eq 1 ]; then
        run_rtk_init init --global --opencode
    fi
    if [ "$install_cline" -eq 1 ]; then
        printf 'Optional for each project: cd <project> && RTK_TELEMETRY_DISABLED=1 rtk init --agent cline\n'
    fi
}

ensure_claude() {
    if command -v claude >/dev/null 2>&1; then
        printf 'Claude Code already found on PATH; verifying it.\n'
    else
        download_verify_and_run "$CLAUDE_INSTALL_URL" bash "Claude Code" claude-installer
        add_known_bin_directories
    fi

    verify_command claude "Claude Code"
}

ensure_codex() {
    if command -v codex >/dev/null 2>&1; then
        printf 'Codex already found on PATH; verifying it.\n'
    else
        download_verify_and_run "$CODEX_INSTALL_URL" sh "Codex" codex-installer 1
        add_known_bin_directories
    fi

    verify_command codex "Codex"
}

ensure_pi() {
    pi_available=0
    add_npm_bin_directories
    existing_pi_path=$(command -v pi 2>/dev/null || true)

    if [ "$dry_run" -eq 1 ] && command -v pi >/dev/null 2>&1; then
        printf 'Pi already found on PATH; verifying it.\n'
    elif pi_command_is_compatible; then
        printf 'Pi already found on PATH; verifying it.\n'
    else
        if [ -n "$existing_pi_path" ]; then
            printf "The existing 'pi' command at %s is not Pi Coding Agent; installing Pi.\n" "$existing_pi_path"
        fi
        download_verify_and_run "$PI_INSTALL_URL" sh "Pi" pi-installer
        add_npm_bin_directories

        if [ "$dry_run" -eq 0 ]; then
            current_pi_path=$(command -v pi 2>/dev/null || true)
            if [ -z "$current_pi_path" ] ||
                { [ -n "$existing_pi_path" ] &&
                    [ "$current_pi_path" = "$existing_pi_path" ] &&
                    ! pi_command_is_compatible; }; then
                printf 'Pi was not installed; continuing without it.\n'
                return 0
            fi
        fi
    fi

    verify_pi_command
    pi_available=1
}

current_opencode_version() {
    if output=$(opencode --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        /^[[:space:]]*((opencode( version)?[[:space:]]+)|v)?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?[[:space:]]*$/ &&
        match($0, /[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

verify_opencode_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command opencode --version
        return 0
    fi

    command_path=$(command -v opencode 2>/dev/null) || fail "OpenCode was installed, but 'opencode' is not available on PATH."
    version=$(current_opencode_version) || fail "OpenCode is present, but 'opencode --version' did not return a valid semantic version."
    if ! stable_version_is_supported "$version" "$MIN_OPENCODE_VERSION"; then
        fail "Stable OpenCode V1 $MIN_OPENCODE_VERSION or newer is required; found OpenCode $version after installation."
    fi
    printf 'Verified OpenCode %s.\n' "$version"
}

ensure_opencode() {
    if [ "$dry_run" -eq 1 ]; then
        if command -v opencode >/dev/null 2>&1; then
            print_command opencode --version
            printf 'A compatible OpenCode will be preserved; an older version will be upgraded with opencode upgrade.\n'
        else
            download_verify_and_run "$OPENCODE_INSTALL_URL" bash "OpenCode" opencode-installer
        fi
        verify_opencode_command
        return 0
    fi

    if command -v opencode >/dev/null 2>&1; then
        version=$(current_opencode_version) || fail "OpenCode is present, but 'opencode --version' did not return a valid semantic version."
        if stable_version_is_supported "$version" "$MIN_OPENCODE_VERSION"; then
            printf 'OpenCode %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_OPENCODE_VERSION"
            return 0
        fi
        printf 'OpenCode %s does not satisfy stable V1 >=%s; upgrading it with OpenCode.\n' "$version" "$MIN_OPENCODE_VERSION"
        run opencode upgrade
        add_known_bin_directories
    else
        download_verify_and_run "$OPENCODE_INSTALL_URL" bash "OpenCode" opencode-installer
        add_known_bin_directories
    fi

    verify_opencode_command
}

current_cline_version() {
    if output=$(cline --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        /^[[:space:]]*((cline( version)?[[:space:]]+)|v)?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?[[:space:]]*$/ &&
        match($0, /[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

verify_cline_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command cline --version
        return 0
    fi

    command -v cline >/dev/null 2>&1 || fail "Cline was installed, but 'cline' is not available on PATH."
    version=$(current_cline_version) || fail "Cline is present, but 'cline --version' did not return a valid semantic version."
    if ! stable_version_is_supported "$version" "$MIN_CLINE_VERSION"; then
        fail "Stable Cline $MIN_CLINE_VERSION or newer is required; found Cline $version after installation."
    fi
    printf 'Verified Cline %s.\n' "$version"
}

ensure_cline() {
    add_npm_bin_directories

    if [ "$dry_run" -eq 1 ]; then
        if command -v cline >/dev/null 2>&1; then
            print_command cline --version
            printf 'A compatible Cline will be preserved; an older version will be upgraded with cline update.\n'
        elif command -v npm >/dev/null 2>&1; then
            npm_pack_verify_and_install_global "$CLINE_PACKAGE" "Cline $MIN_CLINE_VERSION" "npm-cline-$MIN_CLINE_VERSION"
        else
            fail "Cline installation requires npm. Install Node.js from https://nodejs.org/en/download, then rerun the installer."
        fi
        verify_cline_command
        return 0
    fi

    if command -v cline >/dev/null 2>&1; then
        version=$(current_cline_version) || fail "Cline is present, but 'cline --version' did not return a valid semantic version."
        if stable_version_is_supported "$version" "$MIN_CLINE_VERSION"; then
            printf 'Cline %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_CLINE_VERSION"
            return 0
        fi
        printf 'Cline %s does not satisfy stable >=%s; upgrading it with Cline.\n' "$version" "$MIN_CLINE_VERSION"
        run cline update
    else
        command -v npm >/dev/null 2>&1 || fail "Cline installation requires npm. Install Node.js from https://nodejs.org/en/download, then rerun the installer."
        npm_pack_verify_and_install_global "$CLINE_PACKAGE" "Cline $MIN_CLINE_VERSION" "npm-cline-$MIN_CLINE_VERSION"
    fi

    add_npm_bin_directories
    verify_cline_command
}

current_hermes_version() {
    if output=$(hermes --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        match($0, /[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

verify_hermes_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command hermes --version
        return 0
    fi

    command -v hermes >/dev/null 2>&1 || fail "Hermes Agent was installed, but 'hermes' is not available on PATH."
    version=$(current_hermes_version) || fail "Hermes Agent is present, but 'hermes --version' did not return a valid semantic version."
    if ! stable_version_is_supported "$version" "$MIN_HERMES_VERSION"; then
        fail "Hermes Agent $MIN_HERMES_VERSION or newer is required; found Hermes $version after installation."
    fi
    printf 'Verified Hermes Agent %s.\n' "$version"
}

hermes_platform_is_supported() {
    hermes_platform=$(uname -s)
    hermes_architecture=$(uname -m)
    case "$hermes_platform:$hermes_architecture" in
        Linux:x86_64|Linux:amd64|Linux:aarch64|Linux:arm64|Darwin:aarch64|Darwin:arm64)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

confirm_hermes_platform() {
    if hermes_platform_is_supported; then
        return 0
    fi
    fail "Hermes Agent does not provide a supported release for $hermes_platform $hermes_architecture."
}

install_hermes() {
    confirm_hermes_platform
    download_verify_and_run "$HERMES_INSTALL_URL" bash "Hermes Agent" hermes-installer 0 --non-interactive --skip-setup
    add_known_bin_directories
}

ensure_hermes() {
    if [ "$dry_run" -eq 1 ]; then
        if command -v hermes >/dev/null 2>&1; then
            print_command hermes --version
            printf 'A compatible Hermes Agent will be preserved; an older version will be upgraded with the official installer.\n'
        else
            install_hermes
        fi
        verify_hermes_command
        return 0
    fi

    if command -v hermes >/dev/null 2>&1; then
        version=$(current_hermes_version) || fail "Hermes Agent is present, but 'hermes --version' did not return a valid semantic version."
        if stable_version_is_supported "$version" "$MIN_HERMES_VERSION"; then
            printf 'Hermes Agent %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_HERMES_VERSION"
            return 0
        fi
        printf 'Hermes Agent %s does not satisfy >=%s; upgrading it with the official installer.\n' "$version" "$MIN_HERMES_VERSION"
    fi

    install_hermes
    verify_hermes_command
}

current_dsh_version() {
    if output=$(dsh --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        match($0, /[0-9]+\.[0-9]+\.[0-9]+-[0-9A-Za-z][0-9A-Za-z.-]*/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

current_node_version() {
    if output=$(node --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        match($0, /[0-9]+\.[0-9]+\.[0-9]+/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

dsh_node_version_is_supported() {
    version=$1
    major=${version%%.*}
    rest=${version#*.}
    [ "$rest" != "$version" ] || return 1
    minor=${rest%%.*}
    case "$major:$minor" in
        *[!0-9:]*|:*) return 1 ;;
    esac
    if [ "$major" -eq 22 ]; then
        [ "$minor" -ge 19 ]
        return
    fi
    [ "$major" -ge 24 ]
}

dsh_toolchain_is_supported() {
    command -v node >/dev/null 2>&1 || return 1
    command -v npm >/dev/null 2>&1 || return 1
    version=$(current_node_version) || return 1
    dsh_node_version_is_supported "$version"
}

require_dsh_toolchain() {
    command -v node >/dev/null 2>&1 || fail "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0 and npm. Install Node.js, then rerun the installer."
    command -v npm >/dev/null 2>&1 || fail "DeepSeek Harness requires npm. Install npm, then rerun the installer."
    version=$(current_node_version) || fail "DeepSeek Harness requires a readable Node.js version."
    dsh_node_version_is_supported "$version" || fail "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0; found Node.js $version."
}

verify_dsh_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command dsh --version
        return 0
    fi

    command -v dsh >/dev/null 2>&1 || fail "DeepSeek Harness was installed, but 'dsh' is not available on PATH."
    version=$(current_dsh_version) || fail "DeepSeek Harness is present, but 'dsh --version' did not return its preview semantic version."
    [ "$version" = "$DSH_VERSION" ] || fail "DeepSeek Harness $DSH_VERSION is required; found $version after installation."
    printf 'Verified DeepSeek Harness %s.\n' "$version"
}

install_dsh_package() {
    require_dsh_toolchain
    npm_pack_verify_and_install_global "$DSH_PACKAGE" "DeepSeek Harness $DSH_VERSION" "npm-dsh-$DSH_VERSION"
    add_npm_bin_directories
}

ensure_dsh() {
    add_npm_bin_directories

    if [ "$dry_run" -eq 1 ]; then
        if command -v dsh >/dev/null 2>&1; then
            print_command dsh --version
            printf 'The exact supported DeepSeek Harness preview will be preserved; another version will be replaced.\n'
        else
            command -v node >/dev/null 2>&1 || fail "DeepSeek Harness requires Node.js ^22.19.0 or >=24.0.0 and npm. Install Node.js, then rerun the installer."
            command -v npm >/dev/null 2>&1 || fail "DeepSeek Harness requires npm. Install npm, then rerun the installer."
            npm_pack_verify_and_install_global "$DSH_PACKAGE" "DeepSeek Harness $DSH_VERSION" "npm-dsh-$DSH_VERSION"
        fi
        verify_dsh_command
        return 0
    fi

    require_dsh_toolchain
    if command -v dsh >/dev/null 2>&1; then
        version=$(current_dsh_version) || fail "DeepSeek Harness is present, but 'dsh --version' did not return its preview semantic version."
        if [ "$version" = "$DSH_VERSION" ]; then
            printf 'DeepSeek Harness %s already matches the supported preview; leaving it unchanged.\n' "$version"
            return 0
        fi
        printf 'DeepSeek Harness %s does not match %s; replacing it with the supported preview.\n' "$version" "$DSH_VERSION"
    fi

    install_dsh_package
    verify_dsh_command
}

current_grok_version() {
    if output=$(grok --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        /^[[:space:]]*(grok[[:space:]]+|v)?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?([[:space:]]+\([^\r\n]*\))?[[:space:]]*$/ &&
        match($0, /[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

verify_grok_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command grok --version
        return 0
    fi

    command -v grok >/dev/null 2>&1 || fail "Grok Build was installed, but 'grok' is not available on PATH."
    version=$(current_grok_version) || fail "Grok Build is present, but 'grok --version' did not return a valid semantic version."
    if ! stable_version_is_supported "$version" "$MIN_GROK_VERSION"; then
        fail "Stable Grok Build $MIN_GROK_VERSION or newer is required; found Grok Build $version after installation."
    fi
    printf 'Verified Grok Build %s.\n' "$version"
}

install_grok_build() {
    download_verify_and_run "$GROK_INSTALL_URL" bash "Grok Build" grok-installer
    add_known_bin_directories
}

ensure_grok() {
    if [ "$dry_run" -eq 1 ]; then
        if command -v grok >/dev/null 2>&1; then
            print_command grok --version
            printf 'A compatible Grok Build will be preserved; an older version will be upgraded with the official installer.\n'
        else
            install_grok_build
        fi
        verify_grok_command
        return 0
    fi

    if command -v grok >/dev/null 2>&1; then
        version=$(current_grok_version) || fail "Grok Build is present, but 'grok --version' did not return a valid semantic version."
        if stable_version_is_supported "$version" "$MIN_GROK_VERSION"; then
            printf 'Grok Build %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_GROK_VERSION"
            return 0
        fi
        printf 'Grok Build %s does not satisfy stable >=%s; upgrading it with the official installer.\n' "$version" "$MIN_GROK_VERSION"
    fi

    install_grok_build
    verify_grok_command
}

current_muse_version() {
    if output=$(muse --version 2>/dev/null); then
        :
    else
        return 1
    fi

    version=$(printf '%s\n' "$output" | awk '
        /^[[:space:]]*Muse Code[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+([[:space:]]+\([^\r\n]+\))?[[:space:]]*$/ &&
        match($0, /[0-9]+\.[0-9]+\.[0-9]+/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ')
    [ -n "$version" ] || return 1
    printf '%s\n' "$version"
}

verify_muse_command() {
    if [ "$dry_run" -eq 1 ]; then
        print_command muse --version
        return 0
    fi

    command -v muse >/dev/null 2>&1 || fail "Muse Code was installed, but 'muse' is not available on PATH."
    version=$(current_muse_version) || fail "Muse Code is present, but 'muse --version' did not return the expected 'Muse Code x.y.z' version."
    if ! stable_version_is_supported "$version" "$MIN_MUSE_VERSION"; then
        fail "Muse Code $MIN_MUSE_VERSION or newer is required; found Muse Code $version after installation."
    fi
    printf 'Verified Muse Code %s.\n' "$version"
}

install_muse_code() {
    case "$(uname -s)" in
        Darwin|Linux) ;;
        *) fail "Meta's official Muse Code installer supports macOS, Linux, and WSL only." ;;
    esac
    download_verify_and_run "$MUSE_INSTALL_URL" bash "Muse Code" muse-installer
    add_known_bin_directories
}

ensure_muse() {
    if [ "$dry_run" -eq 1 ]; then
        if command -v muse >/dev/null 2>&1; then
            print_command muse --version
            printf 'A compatible Muse Code will be preserved; an older version will be upgraded with the official installer.\n'
        else
            install_muse_code
        fi
        verify_muse_command
        return 0
    fi

    if command -v muse >/dev/null 2>&1; then
        version=$(current_muse_version) || fail "Muse Code is present, but 'muse --version' did not return the expected 'Muse Code x.y.z' version."
        if stable_version_is_supported "$version" "$MIN_MUSE_VERSION"; then
            printf 'Muse Code %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_MUSE_VERSION"
            return 0
        fi
        printf 'Muse Code %s does not satisfy >=%s; upgrading it with the official installer.\n' "$version" "$MIN_MUSE_VERSION"
    fi

    install_muse_code
    verify_muse_command
}

ensure_selected_coding_agents() {
    if [ "$install_claude" -eq 1 ]; then
        step "Ensuring Claude Code is installed"
        ensure_claude
    fi

    if [ "$install_codex" -eq 1 ]; then
        step "Ensuring Codex is installed"
        ensure_codex
    fi

    if [ "$install_pi" -eq 1 ]; then
        step "Checking or installing Pi"
        ensure_pi
    fi

    if [ "$install_opencode" -eq 1 ]; then
        step "Ensuring OpenCode is installed"
        ensure_opencode
    fi

    if [ "$install_cline" -eq 1 ]; then
        step "Ensuring Cline CLI is installed"
        ensure_cline
    fi

    if [ "$install_hermes" -eq 1 ]; then
        step "Ensuring Hermes Agent is installed"
        ensure_hermes
    fi

    if [ "$install_dsh" -eq 1 ]; then
        step "Ensuring DeepSeek Harness is installed"
        ensure_dsh
    fi

    if [ "$install_grok" -eq 1 ]; then
        step "Ensuring Grok Build is installed"
        ensure_grok
    fi

    if [ "$install_muse" -eq 1 ]; then
        step "Ensuring Muse Code is installed"
        ensure_muse
    fi

    if [ "$install_claude" -eq 0 ] && [ "$install_codex" -eq 0 ] && [ "$pi_available" -eq 0 ] && [ "$install_opencode" -eq 0 ] && [ "$install_cline" -eq 0 ] && [ "$install_hermes" -eq 0 ] && [ "$install_dsh" -eq 0 ] && [ "$install_grok" -eq 0 ] && [ "$install_muse" -eq 0 ]; then
        fail "No selected coding agent was installed. Re-run the installer and choose at least one."
    fi
}

current_uv_version() {
    if output=$(uv --version); then
        :
    else
        return 1
    fi

    case "$output" in
        uv\ *) version=${output#uv } ;;
        *) version=$output ;;
    esac
    version=${version%% *}

    case "$version" in
        [0-9]*.[0-9]*.[0-9]*) printf '%s\n' "$version" ;;
        *) return 1 ;;
    esac
}

stable_version_is_supported() {
    case "$1" in
        *-*) return 1 ;;
    esac

    current=${1%%+*}
    minimum=${2%%+*}

    old_ifs=$IFS
    IFS=.
    set -- $current
    current_major=${1:-0}
    current_minor=${2:-0}
    current_patch=${3:-0}
    set -- $minimum
    minimum_major=${1:-0}
    minimum_minor=${2:-0}
    minimum_patch=${3:-0}
    IFS=$old_ifs

    case "$current_major$current_minor$current_patch$minimum_major$minimum_minor$minimum_patch" in
        *[!0-9]*) return 1 ;;
    esac

    [ "$current_major" -gt "$minimum_major" ] && return 0
    [ "$current_major" -lt "$minimum_major" ] && return 1
    [ "$current_minor" -gt "$minimum_minor" ] && return 0
    [ "$current_minor" -lt "$minimum_minor" ] && return 1
    [ "$current_patch" -ge "$minimum_patch" ]
}

verify_uv() {
    if [ "$dry_run" -eq 1 ]; then
        print_command uv --version
        return 0
    fi

    command -v uv >/dev/null 2>&1 || fail "uv was installed, but it is not available on PATH."
    version=$(current_uv_version) || fail "uv is present, but 'uv --version' did not return a valid version."
    if ! stable_version_is_supported "$version" "$MIN_UV_VERSION"; then
        fail "Stable uv $MIN_UV_VERSION or newer is required; found uv $version after installation."
    fi

    printf 'Verified uv %s.\n' "$version"
}

select_uv_release() {
    uv_platform=$(uname -s)
    uv_architecture=$(uname -m)
    case "$uv_platform:$uv_architecture" in
        Linux:x86_64|Linux:amd64) uv_target="x86_64-unknown-linux-gnu" ;;
        Linux:aarch64|Linux:arm64) uv_target="aarch64-unknown-linux-gnu" ;;
        Darwin:x86_64|Darwin:amd64) uv_target="x86_64-apple-darwin" ;;
        Darwin:aarch64|Darwin:arm64) uv_target="aarch64-apple-darwin" ;;
        *) fail "uv $UV_VERSION does not provide a pinned release for $uv_platform $uv_architecture." ;;
    esac
    uv_asset_name="uv-$uv_target.tar.gz"
    uv_component_id="uv-$UV_VERSION-$uv_target"
    uv_archive_url="$UV_RELEASE_BASE_URL/$uv_asset_name"
}

install_uv_pinned() {
    select_uv_release
    if [ "$dry_run" -eq 1 ]; then
        print_command curl -fsSL "$uv_archive_url" -o "<temporary-archive>"
        printf '+ verify sha256 for %s against %s (component: %s)\n' "$uv_asset_name" "$checksums_file" "$uv_component_id"
        printf '+ extract uv to %s\n' "${HOME:-~}/.local/bin/uv"
        return 0
    fi

    [ -n "${HOME:-}" ] || fail "HOME is required to install uv."
    temporary_file=$(mktemp "${TMPDIR:-/tmp}/fcc-uv.XXXXXX") || fail "Unable to create a temporary uv archive."
    print_command curl -fsSL "$uv_archive_url" -o "$temporary_file"
    if curl -fsSL "$uv_archive_url" -o "$temporary_file"; then
        :
    else
        status=$?
        fail "Could not download uv $UV_VERSION (curl exit code $status)."
    fi
    [ -s "$temporary_file" ] || fail "The downloaded uv archive was empty."

    verify_downloaded_file "$temporary_file" "uv $UV_VERSION archive ($uv_asset_name)" "$uv_component_id"

    # Validate the archive layout BEFORE extracting: every entry must live under
    # the single expected top-level directory, with no absolute paths and no
    # parent-directory traversal. This bounds what an unexpected archive (only
    # reachable under --allow-unpinned) can drop, mirroring RTK's entry check.
    uv_expected_root="uv-$uv_target"
    if uv_archive_entries=$(tar -tzf "$temporary_file"); then
        :
    else
        fail "The verified uv archive could not be inspected."
    fi
    if ! printf '%s\n' "$uv_archive_entries" | while IFS= read -r uv_entry; do
            [ -n "$uv_entry" ] || continue
            case "$uv_entry" in
                /*|../*|*/../*|*/..|..) exit 3 ;;
            esac
            case "$uv_entry" in
                "$uv_expected_root"|"$uv_expected_root"/*) ;;
                *) exit 3 ;;
            esac
        done; then
        fail "The verified uv archive contained unexpected or unsafe entries (expected everything under $uv_expected_root/)."
    fi

    temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/fcc-uv-extract.XXXXXX") || fail "Unable to create a temporary uv extraction directory."
    print_command tar -xzf "$temporary_file" -C "$temporary_dir"
    if tar -xzf "$temporary_file" -C "$temporary_dir"; then
        :
    else
        fail "The verified uv archive could not be extracted."
    fi

    # Copy out only the uv binary from the validated, isolated extraction dir.
    uv_extracted="$temporary_dir/$uv_expected_root/uv"
    [ -f "$uv_extracted" ] || fail "The verified uv archive did not contain $uv_expected_root/uv."

    uv_install_directory="$HOME/.local/bin"
    run mkdir -p "$uv_install_directory"
    temporary_binary=$(mktemp "$uv_install_directory/.uv.XXXXXX") || fail "Unable to create a temporary uv executable."
    run cp "$uv_extracted" "$temporary_binary"
    run chmod +x "$temporary_binary"
    run mv "$temporary_binary" "$uv_install_directory/uv"
    temporary_binary=""
    rm -rf "$temporary_dir"
    temporary_dir=""
    rm -f "$temporary_file"
    temporary_file=""
}

# True (exit 0) when ensure_uv would download+extract the pinned uv artifact.
uv_needs_install() {
    command -v uv >/dev/null 2>&1 || return 0
    version=$(current_uv_version) || return 0
    if stable_version_is_supported "$version" "$MIN_UV_VERSION"; then
        return 1
    fi
    return 0
}

ensure_uv() {
    if [ "$dry_run" -eq 1 ]; then
        if command -v uv >/dev/null 2>&1; then
            print_command uv --version
            printf 'A compatible existing uv will be left unchanged; an obsolete one will be replaced by the pinned uv %s release artifact.\n' "$UV_VERSION"
        else
            printf 'uv is not installed; the pinned uv %s release artifact would be installed.\n' "$UV_VERSION"
            install_uv_pinned
            verify_uv
        fi
        return 0
    fi

    if command -v uv >/dev/null 2>&1; then
        version=$(current_uv_version) || fail "uv is present, but 'uv --version' did not return a valid version."
        if stable_version_is_supported "$version" "$MIN_UV_VERSION"; then
            printf 'uv %s already satisfies >=%s; leaving it unchanged.\n' "$version" "$MIN_UV_VERSION"
            return 0
        fi
        printf 'uv %s does not satisfy stable >=%s; installing the pinned uv %s release artifact.\n' "$version" "$MIN_UV_VERSION" "$UV_VERSION"
    else
        printf 'uv is not installed; installing the pinned uv %s release artifact.\n' "$UV_VERSION"
    fi

    install_uv_pinned
    add_known_bin_directories
    verify_uv
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --voice-nim)
                voice_nim=1
                ;;
            --voice-local)
                voice_local=1
                ;;
            --voice-all)
                voice_all=1
                ;;
            --torch-backend)
                shift
                [ "$#" -gt 0 ] || fail "--torch-backend requires a value."
                torch_backend=$1
                [ -n "$torch_backend" ] || fail "--torch-backend requires a non-empty value."
                ;;
            --torch-backend=*)
                torch_backend=${1#*=}
                [ -n "$torch_backend" ] || fail "--torch-backend requires a non-empty value."
                ;;
            --rtk)
                enable_rtk=1
                ;;
            --fcc-ref)
                shift
                [ "$#" -gt 0 ] || fail "--fcc-ref requires a value."
                fcc_ref=$1
                [ -n "$fcc_ref" ] || fail "--fcc-ref requires a non-empty value."
                ;;
            --fcc-ref=*)
                fcc_ref=${1#*=}
                [ -n "$fcc_ref" ] || fail "--fcc-ref requires a non-empty value."
                ;;
            --checksums)
                shift
                [ "$#" -gt 0 ] || fail "--checksums requires a value."
                checksums_file_cli=$1
                [ -n "$checksums_file_cli" ] || fail "--checksums requires a non-empty value."
                ;;
            --checksums=*)
                checksums_file_cli=${1#*=}
                [ -n "$checksums_file_cli" ] || fail "--checksums requires a non-empty value."
                ;;
            --allow-unpinned)
                allow_unpinned=1
                ;;
            --refresh-checksums)
                refresh_mode=1
                ;;
            --dry-run)
                dry_run=1
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                show_usage >&2
                fail "unknown option: $1"
                ;;
        esac
        shift
    done
}

validate_args() {
    include_local=$voice_local
    if [ "$voice_all" -eq 1 ]; then
        include_local=1
    fi

    if [ -n "$torch_backend" ] && [ "$include_local" -ne 1 ]; then
        fail "--torch-backend requires --voice-local or --voice-all."
    fi
}

fcc_ref_is_full_sha() {
    candidate=$1
    [ ${#candidate} -eq 40 ] || return 1
    case "$candidate" in
        *[!0-9a-fA-F]*) return 1 ;;
    esac
    return 0
}

package_spec() {
    include_nim=$voice_nim
    include_local=$voice_local

    if [ "$voice_all" -eq 1 ]; then
        include_nim=1
        include_local=1
    fi

    if [ "$include_nim" -eq 1 ] && [ "$include_local" -eq 1 ]; then
        printf 'free-claude-code[voice,voice_local] @ %s' "$fcc_source_url"
    elif [ "$include_nim" -eq 1 ]; then
        printf 'free-claude-code[voice] @ %s' "$fcc_source_url"
    elif [ "$include_local" -eq 1 ]; then
        printf 'free-claude-code[voice_local] @ %s' "$fcc_source_url"
    else
        printf 'free-claude-code @ %s' "$fcc_source_url"
    fi
}

clone_and_pin_fcc() {
    if [ "$dry_run" -eq 1 ]; then
        print_command git clone "$FCC_REPO_URL" "<temporary-checkout>"
        print_command git -C "<temporary-checkout>" checkout --detach "$fcc_ref"
        print_command git -C "<temporary-checkout>" rev-parse HEAD
        if fcc_ref_is_full_sha "$fcc_ref"; then
            printf '+ verify HEAD equals pinned commit %s\n' "$fcc_ref"
        else
            printf '+ warn: --fcc-ref %s is not a full 40-hex commit SHA (not cryptographically pinned)\n' "$fcc_ref"
        fi
        fcc_source_url="file://<temporary-checkout>"
        return 0
    fi

    temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/fcc-src.XXXXXX") || fail "Unable to create a temporary Free Claude Code checkout directory."
    fcc_checkout_dir="$temporary_dir/free-claude-code"
    run git clone "$FCC_REPO_URL" "$fcc_checkout_dir"
    run git -C "$fcc_checkout_dir" checkout --detach "$fcc_ref"

    print_command git -C "$fcc_checkout_dir" rev-parse HEAD
    head_commit=$(git -C "$fcc_checkout_dir" rev-parse HEAD) || fail "Could not resolve the checked-out Free Claude Code commit."

    if fcc_ref_is_full_sha "$fcc_ref"; then
        # git rev-parse emits lowercase hex; normalize both sides so an uppercase
        # --fcc-ref still compares equal instead of confusingly failing closed.
        fcc_ref_normalized=$(printf '%s' "$fcc_ref" | tr '[:upper:]' '[:lower:]')
        head_commit_normalized=$(printf '%s' "$head_commit" | tr '[:upper:]' '[:lower:]')
        if [ "$head_commit_normalized" != "$fcc_ref_normalized" ]; then
            fail "Free Claude Code commit verification failed: expected $fcc_ref, checked out $head_commit."
        fi
        printf 'Pinned Free Claude Code to verified commit %s.\n' "$head_commit"
    else
        printf 'warning: --fcc-ref "%s" is not a full 40-hex commit SHA; resolved to %s but NOT cryptographically pinned.\n' "$fcc_ref" "$head_commit" >&2
    fi

    fcc_source_url="file://$fcc_checkout_dir"
}

# True (exit 0) when the installed uv accepts --locked on 'uv tool install'.
uv_locked_supported() {
    command -v uv >/dev/null 2>&1 || return 1
    uv tool install --help 2>/dev/null | grep -q -- '--locked' || return 1
    return 0
}

install_free_claude_code() {
    assert_no_fcc_processes_running
    clone_and_pin_fcc
    spec=$(package_spec)

    # Build the uv tool install argument list incrementally so optional flags are
    # only added when the installed uv supports them.
    set -- uv tool install --force --refresh-package free-claude-code --python "$PYTHON_VERSION"

    # Pin FCC's full dependency closure (not just its own source tree) by making
    # uv honor the checkout's uv.lock. --locked is added ONLY when the installed
    # uv advertises it (capability check), so an older/newer uv that does not
    # accept the flag never breaks the install. If a future uv rejects --locked
    # for a "pkg[extras] @ file://<checkout>" requirement, remove it here and
    # install from the checkout in project mode instead, e.g.:
    #   (cd "$fcc_checkout_dir" && uv tool install --force --locked \
    #        --python "$PYTHON_VERSION" ".[voice,voice_local]")
    if uv_locked_supported; then
        set -- "$@" --locked
    fi

    if [ -n "$torch_backend" ]; then
        set -- "$@" --torch-backend "$torch_backend"
    fi

    set -- "$@" "$spec"
    run "$@"

    if [ "$dry_run" -eq 0 ] && [ -n "$temporary_dir" ] && [ -d "$temporary_dir" ]; then
        rm -rf "$temporary_dir"
        temporary_dir=""
    fi
}

configure_and_verify_free_claude_code() {
    run uv tool update-shell

    if [ "$dry_run" -eq 1 ]; then
        print_command uv tool dir --bin
        printf '+ verify fcc-desktop, fcc-server, fcc-claude, fcc-codex, fcc-pi, fcc-opencode, fcc-cline, fcc-hermes, fcc-dsh, fcc-grok, and fcc-muse in the uv tool bin directory\n'
        print_command fcc-server --version
        return 0
    fi

    print_command uv tool dir --bin
    if tool_bin=$(uv tool dir --bin); then
        :
    else
        status=$?
        fail "Could not determine the uv tool bin directory (exit code $status)."
    fi
    [ -n "$tool_bin" ] || fail "uv returned an empty tool bin directory."

    add_path_entry "$tool_bin"
    export PATH
    hash -r 2>/dev/null || true

    for command_name in fcc-desktop fcc-server fcc-claude fcc-codex fcc-pi fcc-opencode fcc-cline fcc-hermes fcc-dsh fcc-grok fcc-muse; do
        [ -x "$tool_bin/$command_name" ] || fail "Free Claude Code installation did not create $tool_bin/$command_name."
    done

    run "$tool_bin/fcc-server" --version
}

shell_quote() {
    escaped=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
    printf "'%s'" "$escaped"
}

macos_app_is_fcc_owned() {
    app_dir=$1
    owner_file="$app_dir/Contents/$FCC_MACOS_OWNER_FILE"
    [ -d "$app_dir" ] &&
        [ ! -L "$app_dir" ] &&
        [ -f "$owner_file" ] &&
        [ "$(cat "$owner_file")" = "$FCC_MACOS_BUNDLE_ID" ]
}

install_macos_desktop_app() {
    [ "$(uname -s)" = "Darwin" ] || return 0

    app_dir="$HOME/Applications/Free Claude Code.app"
    contents_dir="$app_dir/Contents"
    owner_file="$contents_dir/$FCC_MACOS_OWNER_FILE"
    executable_dir="$contents_dir/MacOS"
    executable_path="$executable_dir/fcc-desktop"
    resources_dir="$contents_dir/Resources"
    icon_path="$resources_dir/AppIcon.icns"
    desktop_dir="$HOME/Desktop"
    desktop_link="$desktop_dir/Free Claude Code.app"

    if [ -e "$app_dir" ] || [ -L "$app_dir" ]; then
        macos_app_is_fcc_owned "$app_dir" ||
            fail "An app not managed by Free Claude Code already exists at $app_dir. Move it, then rerun the installer."
    fi

    if [ "$dry_run" -eq 1 ]; then
        print_command mkdir -p "$executable_dir" "$resources_dir" "$desktop_dir"
        print_command fcc-desktop --export-icon "$icon_path"
        printf '+ write %s, %s, and %s\n' "$owner_file" "$contents_dir/Info.plist" "$executable_path"
        print_command ln -s "$app_dir" "$desktop_link"
        return 0
    fi

    mkdir -p "$executable_dir" "$resources_dir" "$desktop_dir"
    run "$tool_bin/fcc-desktop" --export-icon "$icon_path"
    [ -f "$icon_path" ] || fail "Free Claude Code did not export its macOS app icon to $icon_path."
    printf '%s\n' "$FCC_MACOS_BUNDLE_ID" > "$owner_file"
    cat > "$contents_dir/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>Free Claude Code</string>
    <key>CFBundleExecutable</key>
    <string>fcc-desktop</string>
    <key>CFBundleIdentifier</key>
    <string>io.github.alishahryar1.free-claude-code</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleName</key>
    <string>Free Claude Code</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMultipleInstancesProhibited</key>
    <true/>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
PLIST
    desktop_command=$(shell_quote "$tool_bin/fcc-desktop")
    {
        printf '%s\n' '#!/bin/sh'
        printf 'exec %s\n' "$desktop_command"
    } > "$executable_path"
    chmod +x "$executable_path"

    if [ -L "$desktop_link" ]; then
        if [ "$(readlink "$desktop_link")" = "$app_dir" ]; then
            rm -f "$desktop_link"
        else
            printf 'A non-FCC link already exists at %s; leaving it unchanged.\n' "$desktop_link"
            return 0
        fi
    elif [ -e "$desktop_link" ]; then
        printf 'A non-FCC item already exists at %s; leaving it unchanged.\n' "$desktop_link"
        return 0
    fi
    ln -s "$app_dir" "$desktop_link"
}

parse_args "$@"
validate_args
resolve_script_dir
resolve_checksums_file

if [ "$refresh_mode" -eq 1 ]; then
    step "Refreshing checksums (no code will be executed)"
    require_command curl
    require_command mktemp
    require_sha256_tool
    refresh_all_checksums
    printf '\nReview each hash above against a trusted source, then paste the id=hash lines into %s.\n' "$checksums_file" >&2
    exit 0
fi

if [ "$allow_unpinned" -eq 1 ]; then
    print_unpinned_banner
fi

add_known_bin_directories
if command -v cline >/dev/null 2>&1 || command -v npm >/dev/null 2>&1; then
    install_cline=1
fi
if ! command -v hermes >/dev/null 2>&1 && ! hermes_platform_is_supported; then
    install_hermes=0
fi
step "Checking for running Free Claude Code processes"
assert_no_fcc_processes_running

if ! installer_is_interactive && ! command -v dsh >/dev/null 2>&1; then
    if [ "$dry_run" -eq 1 ] && command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        install_dsh=1
    elif ! dsh_toolchain_is_supported; then
        install_dsh=0
    fi
fi

if installer_is_interactive; then
    step "Choosing coding agents"
    choose_coding_agents /dev/tty /dev/tty
fi

step "Checking installation prerequisites"
require_command curl
if [ "$install_claude" -eq 1 ] || [ "$install_opencode" -eq 1 ] || [ "$install_hermes" -eq 1 ] || [ "$install_grok" -eq 1 ] || [ "$install_muse" -eq 1 ]; then
    require_command bash
fi
require_command sh
require_command mktemp
# Free Claude Code is always installed from a pinned git checkout, so the clone
# path always runs and git is always required.
require_command git
# tar is only needed to extract the pinned uv and/or RTK release tarballs.
if uv_needs_install || { [ "$enable_rtk" -eq 1 ] && ! command -v rtk >/dev/null 2>&1; }; then
    require_command tar
fi
require_sha256_tool

ensure_selected_coding_agents
configure_rtk_for_selected_agents

step "Ensuring uv $MIN_UV_VERSION or newer is installed"
ensure_uv

step "Installing or updating Free Claude Code"
install_free_claude_code

step "Configuring PATH and verifying Free Claude Code"
configure_and_verify_free_claude_code

if [ "$(uname -s)" = "Darwin" ]; then
    step "Installing the Free Claude Code desktop launcher"
    install_macos_desktop_app
fi

if [ "$dry_run" -eq 1 ]; then
    printf '\nDry run complete. No changes were made.\n'
else
    if [ "$(uname -s)" = "Darwin" ]; then
        printf '\nFree Claude Code is installed and verified. Open Free Claude Code from Applications or the desktop to run it in the background.\n'
        printf 'For terminal use, start the proxy with: fcc-server\n'
    else
        printf '\nFree Claude Code is installed and verified. Start the proxy with: fcc-server\n'
    fi
    if [ "$install_claude" -eq 1 ]; then
        printf 'Run Claude Code with: fcc-claude\n'
    fi
    if [ "$install_codex" -eq 1 ]; then
        printf 'Run Codex with: fcc-codex\n'
    fi
    if [ "$pi_available" -eq 1 ]; then
        printf 'Run Pi with: fcc-pi\n'
    fi
    if [ "$install_opencode" -eq 1 ]; then
        printf 'Run OpenCode with: fcc-opencode\n'
    fi
    if [ "$install_cline" -eq 1 ]; then
        printf 'Run Cline with: fcc-cline\n'
    else
        printf 'The fcc-cline wrapper is ready after you install Cline CLI.\n'
    fi
    if [ "$install_hermes" -eq 1 ]; then
        printf 'Run Hermes Agent with: fcc-hermes\n'
    else
        printf 'The fcc-hermes wrapper is ready after you install Hermes Agent.\n'
    fi
    if [ "$install_dsh" -eq 1 ]; then
        printf 'Run DeepSeek Harness with: fcc-dsh\n'
    else
        printf 'The fcc-dsh wrapper is ready after you install DeepSeek Harness %s.\n' "$DSH_VERSION"
    fi
    if [ "$install_grok" -eq 1 ]; then
        printf 'Run Grok Build with: fcc-grok\n'
    else
        printf 'The fcc-grok wrapper is ready after you install Grok Build %s or newer.\n' "$MIN_GROK_VERSION"
    fi
    if [ "$install_muse" -eq 1 ]; then
        printf 'Run Muse Code with: fcc-muse\n'
    else
        printf 'The fcc-muse wrapper is ready after you install Muse Code %s or newer.\n' "$MIN_MUSE_VERSION"
    fi
fi
