#!/usr/bin/env bash
# TerminalPhone — Encrypted Push-to-Talk Voice over Tor
# A walkie-talkie style voice chat using Tor hidden services
# License: MIT

set -euo pipefail

#=============================================================================
# CONFIGURATION
#=============================================================================
APP_NAME="TerminalPhone"
VERSION="1.1.7"
BASE_DIR="$(cd "$(dirname "$0")" && pwd -P)"
DATA_DIR="$BASE_DIR/.terminalphone"
TOR_DIR="$DATA_DIR/tor_data"
TOR_CONF="$DATA_DIR/torrc"
ONION_FILE="$TOR_DIR/hidden_service/hostname"
SECRET_FILE="$DATA_DIR/shared_secret"
CONFIG_FILE="$DATA_DIR/config"
AUDIO_DIR="$DATA_DIR/audio"
PID_DIR="$DATA_DIR/pids"
PTT_FLAG="$DATA_DIR/run/ptt_$$"
CONNECTED_FLAG="$DATA_DIR/run/connected_$$"
RECV_PIPE="$DATA_DIR/run/recv_$$"
SEND_PIPE="$DATA_DIR/run/send_$$"
CIPHER_RUNTIME_FILE="$DATA_DIR/run/cipher_$$"
HMAC_RUNTIME_FILE="$DATA_DIR/run/hmac_$$"
NONCE_LOG_FILE="$DATA_DIR/run/nonces_$$"
AUTO_LISTEN_FLAG="$DATA_DIR/run/autolisten_$$"
AUTO_LISTEN_PID=""


# Defaults
LISTEN_PORT=7777
TOR_SOCKS_PORT=9050
OPUS_BITRATE=16       # kbps — good balance of quality and bandwidth for Tor
OPUS_FRAMESIZE=60     # ms
SAMPLE_RATE=8000      # Hz
PTT_KEY=" "           # spacebar
CHUNK_DURATION=1      # seconds per audio chunk
CIPHER="aes-256-cbc"  # OpenSSL cipher for encryption
SNOWFLAKE_ENABLED=0   # Snowflake bridge (off by default)
AUTO_LISTEN=0         # Auto-listen after Tor starts (off by default)
VOICE_EFFECT="none"   # Voice effect (none, deep, high, robot, echo, whisper, custom)
VOL_PTT=0             # Volume-down double-tap PTT (Termux only, experimental)
SHOW_CIRCUIT=0        # Show Tor circuit hops in call header (off by default)
TOR_CONTROL_PORT=9051 # Tor control port (used when SHOW_CIRCUIT=1)
EXCLUDE_NODES=""      # Tor ExcludeNodes (comma-separated country codes, e.g. {US},{GB})
HMAC_AUTH=0           # HMAC-sign all protocol messages (off by default)
SINGLE_HOP=0          # Single-hop hidden service (off by default, sacrifices server anonymity for speed)
PTT_CHIME="off"       # PTT notification chime (off, tone, double, chirp, ding, click, custom)
ALSA_DEV_CAPTURE="default"  # ALSA capture device (Linux only)
ALSA_DEV_PLAYBACK="default" # ALSA playback device (Linux only)

# Custom voice effect parameters (used when VOICE_EFFECT=custom)
VOICE_PITCH=0         # Pitch shift in cents (-600 to +600, 0=off)
VOICE_OVERDRIVE=0     # Overdrive gain (0=off, 5-20)
VOICE_FLANGER=0       # Flanger (0=off, 1=on)
VOICE_ECHO_DELAY=0    # Echo delay in ms (0=off, 20-200)
VOICE_ECHO_DECAY=5    # Echo decay (1-9 → 0.1-0.9)
VOICE_HIGHPASS=0      # Highpass filter freq in Hz (0=off, 300-2000)
VOICE_TREMOLO=0       # Tremolo speed in Hz (0=off, 5-40)

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
BLINK='\033[5m'
NC='\033[0m' # No Color
BG_RED='\033[41m'
BG_GREEN='\033[42m'
TOR_PURPLE='\033[38;2;125;70;152m'

# Platform detection
IS_TERMUX=0
IS_MACOS=0
if [ -n "${TERMUX_VERSION:-}" ] || { [ -n "${PREFIX:-}" ] && [[ "${PREFIX:-}" == *"com.termux"* ]]; }; then
    IS_TERMUX=1
elif [[ "$(uname -s)" == "Darwin" ]]; then
    IS_MACOS=1
fi

# Ensure Homebrew is in PATH on macOS (Apple Silicon: /opt/homebrew, Intel: /usr/local)
if [ $IS_MACOS -eq 1 ]; then
    for _brew_prefix in /opt/homebrew /usr/local; do
        if [ -x "$_brew_prefix/bin/brew" ]; then
            export PATH="$_brew_prefix/bin:$_brew_prefix/sbin:$PATH"
            break
        fi
    done
fi

# State
TOR_PID=""

CALL_ACTIVE=0
ORIGINAL_STTY=""

#=============================================================================
# HELPERS
#=============================================================================

# Portable case conversion (works with Bash 3.2 on macOS)
to_upper() { echo "$1" | tr '[:lower:]' '[:upper:]'; }
to_lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

# Strip control characters and ANSI escape sequences from untrusted input
sanitize_str() { echo "$1" | tr -d '\000-\011\013-\037\177' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g'; }

# Detect best ALSA capture device for Linux (PulseAudio/PipeWire > ALSA default)
detect_capture_device() {
    echo "${ALSA_DEV_CAPTURE:-default}"
}

# Detect best ALSA playback device for Linux (PulseAudio/PipeWire > ALSA default)
detect_playback_device() {
    echo "${ALSA_DEV_PLAYBACK:-default}"
}

# Cached Linux audio backend: "pulse" (PulseAudio/PipeWire) or "alsa".
# On modern desktops (PipeWire/PulseAudio) the bare ALSA "default" route often
# records silence or plays to the wrong sink, which is the root cause of issue #2
# (PC capture/playback dead while phone-to-phone works). PulseAudio's parec/pacat
# always target the user's real default source/sink and are provided by both
# PulseAudio and PipeWire (via pipewire-pulse + libpulse), so prefer them.
AUDIO_BACKEND=""
detect_audio_backend() {
    if [ -n "$AUDIO_BACKEND" ]; then
        echo "$AUDIO_BACKEND"
        return
    fi
    # Respect an explicit ALSA device override from settings.
    if [ "${ALSA_DEV_CAPTURE:-default}" != "default" ] || \
       [ "${ALSA_DEV_PLAYBACK:-default}" != "default" ]; then
        AUDIO_BACKEND="alsa"
    elif command -v parec &>/dev/null && command -v pacat &>/dev/null; then
        AUDIO_BACKEND="pulse"
    else
        AUDIO_BACKEND="alsa"
    fi
    echo "$AUDIO_BACKEND"
}

# Portable file size (macOS stat uses -f%z, GNU stat uses -c%s)
file_size() {
    if [ $IS_MACOS -eq 1 ]; then
        stat -f%z "$1" 2>/dev/null || echo 0
    else
        stat -c%s "$1" 2>/dev/null || echo 0
    fi
}

cleanup() {
    # Restore terminal
    if [ -n "$ORIGINAL_STTY" ]; then
        stty "$ORIGINAL_STTY" 2>/dev/null || true
    fi
    stty sane 2>/dev/null || true

    # Kill background processes
    kill_bg_processes

    # Remove temp files
    rm -f "$PTT_FLAG" "$CONNECTED_FLAG" "$RECV_PIPE" "$SEND_PIPE"
    rm -rf "$AUDIO_DIR" 2>/dev/null || true

    echo -e "\n${GREEN}${APP_NAME} shut down cleanly.${NC}"
}

kill_bg_processes() {
    # Kill any child processes
    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
        wait $pids 2>/dev/null || true
    fi

    # Kill stored PIDs
    if [ -d "$PID_DIR" ]; then
        for pidfile in "$PID_DIR"/*.pid; do
            [ -f "$pidfile" ] || continue
            local pid
            pid=$(cat "$pidfile" 2>/dev/null) || continue
            kill "$pid" 2>/dev/null || true
        done
        rm -f "$PID_DIR"/*.pid 2>/dev/null || true
    fi

    # Kill our Tor instance if running
    if [ -n "$TOR_PID" ] && kill -0 "$TOR_PID" 2>/dev/null; then
        kill "$TOR_PID" 2>/dev/null || true
    fi

}

save_pid() {
    local name="$1" pid="$2"
    mkdir -p "$PID_DIR"
    echo "$pid" > "$PID_DIR/${name}.pid"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[  OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_err() {
    echo -e "${RED}[FAIL]${NC} $1"
}

uid() {
    head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
    if [ -f "$SECRET_FILE" ]; then
        # Check if the file is OpenSSL-encrypted (starts with "Salted__")
        local magic
        magic=$(head -c 8 "$SECRET_FILE" 2>/dev/null | cat -v)
        if [[ "$magic" == "Salted__"* ]]; then
            # Encrypted secret — prompt for passphrase
            echo -ne "  ${BOLD}Enter passphrase to unlock shared secret: ${NC}"
            read -rs _unlock_pass
            echo ""
            if [ -n "$_unlock_pass" ]; then
                SHARED_SECRET=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
                    -pass "fd:3" -in "$SECRET_FILE" 3<<< "${_unlock_pass}" 2>/dev/null) || true
                if [ -z "$SHARED_SECRET" ]; then
                    log_warn "Failed to unlock secret (wrong passphrase?)"
                    log_info "You can re-enter the secret with option 4"
                else
                    log_ok "Shared secret unlocked"
                fi
            else
                log_warn "No passphrase entered — secret not loaded"
                SHARED_SECRET=""
            fi
        else
            # Plaintext secret (legacy) — load directly
            SHARED_SECRET=$(cat "$SECRET_FILE")
            if [ -n "$SHARED_SECRET" ]; then
                log_info "Plaintext secret detected"
                echo -ne "  ${BOLD}Protect it with a passphrase? [Y/n]: ${NC}"
                read -r _migrate
                if [ "$_migrate" != "n" ] && [ "$_migrate" != "N" ]; then
                    echo -ne "  ${BOLD}Choose a passphrase: ${NC}"
                    read -rs _new_pass
                    echo ""
                    if [ -n "$_new_pass" ]; then
                        echo -ne "  ${BOLD}Confirm passphrase: ${NC}"
                        read -rs _confirm_pass
                        echo ""
                        if [ "$_new_pass" = "$_confirm_pass" ]; then
                            echo -n "$SHARED_SECRET" | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
                                -pass "fd:3" -out "$SECRET_FILE" 3<<< "${_new_pass}" 2>/dev/null
                            chmod 600 "$SECRET_FILE"
                            log_ok "Secret encrypted with passphrase"
                        else
                            log_warn "Passphrases don't match — keeping plaintext"
                        fi
                    else
                        log_warn "Empty passphrase — keeping plaintext"
                    fi
                fi
            fi
        fi
    else
        SHARED_SECRET=""
    fi
}

save_config() {
    mkdir -p "$DATA_DIR"
    cat > "$CONFIG_FILE" << EOF
LISTEN_PORT=$LISTEN_PORT
TOR_SOCKS_PORT=$TOR_SOCKS_PORT
OPUS_BITRATE=$OPUS_BITRATE
OPUS_FRAMESIZE=$OPUS_FRAMESIZE
PTT_KEY="$PTT_KEY"
CIPHER="$CIPHER"
SNOWFLAKE_ENABLED=$SNOWFLAKE_ENABLED
AUTO_LISTEN=$AUTO_LISTEN
VOICE_EFFECT="$VOICE_EFFECT"
VOICE_PITCH=$VOICE_PITCH
VOICE_OVERDRIVE=$VOICE_OVERDRIVE
VOICE_FLANGER=$VOICE_FLANGER
VOICE_ECHO_DELAY=$VOICE_ECHO_DELAY
VOICE_ECHO_DECAY=$VOICE_ECHO_DECAY
VOICE_HIGHPASS=$VOICE_HIGHPASS
VOICE_TREMOLO=$VOICE_TREMOLO
VOL_PTT=$VOL_PTT
SHOW_CIRCUIT=$SHOW_CIRCUIT
EXCLUDE_NODES="$EXCLUDE_NODES"
HMAC_AUTH=$HMAC_AUTH
SINGLE_HOP=$SINGLE_HOP
PTT_CHIME="$PTT_CHIME"
ALSA_DEV_CAPTURE="$ALSA_DEV_CAPTURE"
ALSA_DEV_PLAYBACK="$ALSA_DEV_PLAYBACK"
EOF
}

#=============================================================================
# DEPENDENCY INSTALLER
#=============================================================================

check_dep() {
    command -v "$1" &>/dev/null
}

install_deps() {
    echo -e "\n${BOLD}${CYAN}═══ Dependency Installer ═══${NC}\n"

    local deps_needed=()
    local all_deps
    local pkg_names_apt="tor opus-tools sox socat openssl alsa-utils pulseaudio-utils"
    local pkg_names_dnf="tor opus-tools sox socat openssl alsa-utils pulseaudio-utils"
    local pkg_names_pacman="tor opus-tools sox socat openssl alsa-utils libpulse"
    local pkg_names_pkg="tor opus-tools sox socat openssl-tool ffmpeg termux-api pulseaudio"
    local pkg_names_brew="tor opus-tools sox socat openssl"

    # Shared deps + platform-specific
    if [ $IS_TERMUX -eq 1 ]; then
        all_deps=(tor opusenc opusdec sox socat openssl ffmpeg termux-microphone-record pulseaudio)
    elif [ $IS_MACOS -eq 1 ]; then
        all_deps=(tor opusenc opusdec sox socat openssl rec play)
    else
        all_deps=(tor opusenc opusdec sox socat openssl arecord aplay)
    fi

    # Check which deps are missing
    for dep in "${all_deps[@]}"; do
        if check_dep "$dep"; then
            log_ok "$dep found"
        else
            deps_needed+=("$dep")
            log_warn "$dep NOT found"
        fi
    done

    if [ ${#deps_needed[@]} -eq 0 ]; then
        echo -e "\n${GREEN}All dependencies are installed!${NC}"
        return 0
    fi

    echo -e "\n${YELLOW}Missing dependencies: ${deps_needed[*]}${NC}"
    echo -ne "\n${BOLD}Install missing dependencies? [Y/n]: ${NC}"
    read -r _install_confirm
    if [ "$_install_confirm" = "n" ] || [ "$_install_confirm" = "N" ]; then
        echo -e "\n  ${YELLOW}Installation skipped.${NC}"
        return 1
    fi
    echo ""

    # Use sudo only if available and not on Termux
    local SUDO="sudo"
    if [ $IS_TERMUX -eq 1 ]; then
        SUDO=""
        log_info "Termux detected — installing without sudo"
    elif ! check_dep sudo; then
        SUDO=""
    fi

    # Detect package manager and install
    if [ $IS_TERMUX -eq 1 ]; then
        log_info "Detected Termux"
        log_info "Upgrading existing packages first..."
        pkg upgrade -y
        pkg install -y $pkg_names_pkg
        echo -e "\n${YELLOW}${BOLD}NOTE:${NC} You must also install the ${BOLD}Termux:API${NC} app from F-Droid"
        echo -e "      for microphone access.\n"
    elif [ $IS_MACOS -eq 1 ]; then
        # macOS: install Homebrew if not present, then use brew
        if ! check_dep brew; then
            log_info "Homebrew not found — installing Homebrew first..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            # Add Homebrew to PATH for this session
            for _brew_prefix in /opt/homebrew /usr/local; do
                if [ -x "$_brew_prefix/bin/brew" ]; then
                    export PATH="$_brew_prefix/bin:$_brew_prefix/sbin:$PATH"
                    break
                fi
            done
            if ! check_dep brew; then
                log_err "Homebrew installation failed"
                log_err "Install Homebrew manually: https://brew.sh"
                return 1
            fi
            log_ok "Homebrew installed"
        fi
        log_info "Installing dependencies via Homebrew..."
        brew install $pkg_names_brew
    elif check_dep apt-get; then
        log_info "Detected apt package manager"
        $SUDO apt-get update -qq
        $SUDO apt-get install -y $pkg_names_apt
    elif check_dep dnf; then
        log_info "Detected dnf package manager"
        $SUDO dnf install -y $pkg_names_dnf
    elif check_dep pacman; then
        log_info "Detected pacman package manager"
        $SUDO pacman -S --noconfirm $pkg_names_pacman
    else
        log_err "No supported package manager found!"
        log_err "Please install manually: tor, opus-tools, sox, socat, openssl"
        return 1
    fi

    # Verify
    echo -e "\n${BOLD}Verifying installation...${NC}"
    local failed=0
    for dep in "${all_deps[@]}"; do
        if check_dep "$dep"; then
            log_ok "$dep"
        else
            log_err "$dep still missing!"
            failed=1
        fi
    done

    if [ $failed -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}All dependencies installed successfully!${NC}"
    else
        echo -e "\n${RED}Some dependencies could not be installed.${NC}"
        return 1
    fi
}

#=============================================================================
# TOR HIDDEN SERVICE
#=============================================================================

setup_tor() {
    mkdir -p "$TOR_DIR/hidden_service"
    chmod 700 "$TOR_DIR/hidden_service"

    if [ "$SINGLE_HOP" -eq 1 ]; then
        cat > "$TOR_CONF" << EOF
SocksPort 0
DataDirectory $TOR_DIR/data
HiddenServiceNonAnonymousMode 1
HiddenServiceSingleHopMode 1
HiddenServiceDir $TOR_DIR/hidden_service
HiddenServicePort $LISTEN_PORT 127.0.0.1:$LISTEN_PORT
Log notice file $TOR_DIR/tor.log
EOF
        log_info "Single-hop mode: server anonymity DISABLED for lower latency"
    else
        cat > "$TOR_CONF" << EOF
SocksPort $TOR_SOCKS_PORT
DataDirectory $TOR_DIR/data
HiddenServiceDir $TOR_DIR/hidden_service
HiddenServicePort $LISTEN_PORT 127.0.0.1:$LISTEN_PORT
Log notice file $TOR_DIR/tor.log
EOF
    fi

    # Locate and add GeoIP files (required for ip-to-country lookups)
    local geoip="" geoip6=""
    for dir in "${PREFIX:-}/share/tor" "/usr/share/tor" "/usr/local/share/tor"; do
        [ -f "$dir/geoip" ] && geoip="$dir/geoip"
        [ -f "$dir/geoip6" ] && geoip6="$dir/geoip6"
        [ -n "$geoip" ] && break
    done
    if [ -n "$geoip" ]; then
        echo "GeoIPFile $geoip" >> "$TOR_CONF"
        [ -n "$geoip6" ] && echo "GeoIPv6File $geoip6" >> "$TOR_CONF"
    fi

    # Append ControlPort config if circuit display is enabled
    if [ "$SHOW_CIRCUIT" -eq 1 ]; then
        cat >> "$TOR_CONF" << EOF

ControlPort $TOR_CONTROL_PORT
CookieAuthentication 1
EOF
        log_info "ControlPort enabled for circuit display"
    fi

    # Append ExcludeNodes if configured
    if [ -n "$EXCLUDE_NODES" ]; then
        cat >> "$TOR_CONF" << EOF

ExcludeNodes $EXCLUDE_NODES
StrictNodes 1
EOF
        log_info "ExcludeNodes: $EXCLUDE_NODES"
    fi

    # Append snowflake bridge config if enabled
    if [ "$SNOWFLAKE_ENABLED" -eq 1 ] && check_dep snowflake-client; then
        local sf_bin
        sf_bin=$(command -v snowflake-client)
        cat >> "$TOR_CONF" << EOF

UseBridges 1
ClientTransportPlugin snowflake exec $sf_bin
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ ice=stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478
EOF
        log_info "Snowflake bridge enabled in torrc"
    elif [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        log_warn "Snowflake enabled but snowflake-client not found — skipping bridge"
    fi

    chmod 600 "$TOR_CONF"
}

install_snowflake() {
    if check_dep snowflake-client; then
        log_ok "snowflake-client already installed"
        return 0
    fi

    log_info "Installing snowflake-client..."

    local SUDO="sudo"
    if [ $IS_TERMUX -eq 1 ]; then
        SUDO=""
    elif ! check_dep sudo; then
        SUDO=""
    fi

    if [ $IS_TERMUX -eq 1 ]; then
        pkg install -y snowflake-client
    elif check_dep brew; then
        brew install snowflake
    elif check_dep apt-get; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y snowflake-client
    elif check_dep dnf; then
        $SUDO dnf install -y snowflake-client
    elif check_dep pacman; then
        $SUDO pacman -S --noconfirm snowflake-pt-client
    else
        log_err "No supported package manager found. Install snowflake-client manually."
        return 1
    fi

    if check_dep snowflake-client; then
        log_ok "snowflake-client installed successfully"
    else
        log_err "snowflake-client installation failed"
        return 1
    fi
}



start_tor() {
    if [ -n "$TOR_PID" ] && kill -0 "$TOR_PID" 2>/dev/null; then
        log_info "Tor is already running (PID $TOR_PID)"
        return 0
    fi


    setup_tor

    # Clear old log so we only see fresh output
    local tor_log="$TOR_DIR/tor.log"
    > "$tor_log"

    log_info "Starting Tor..."
    if [ ! -d "$TOR_DIR/data" ] && [ ! -f "$ONION_FILE" ]; then
        echo -e "  ${DIM}First bootstrap detected — Tor needs to download network consensus.${NC}"
        echo -e "  ${DIM}This is a one-time process and may take a minute or two.${NC}"
    fi
    if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        echo -e "  ${DIM}Snowflake bridge enabled — this may take longer than usual, please be patient.${NC}"
    fi
    tor -f "$TOR_CONF" &>/dev/null &
    TOR_PID=$!
    save_pid "tor" "$TOR_PID"

    # Monitor bootstrap progress from the log
    local waited=0
    local timeout=120
    if [ ! -d "$TOR_DIR/data" ] && [ ! -f "$ONION_FILE" ]; then
        timeout=300
    fi
    local last_pct=""

    while [ $waited -lt $timeout ]; do
        # Check if Tor is still running
        if ! kill -0 "$TOR_PID" 2>/dev/null; then
            echo ""
            log_err "Tor process died! Check $tor_log"
            [ -f "$tor_log" ] && tail -5 "$tor_log" 2>/dev/null
            return 1
        fi

        # Parse latest bootstrap line from log
        local bootstrap_line=""
        bootstrap_line=$(grep -o "Bootstrapped [0-9]*%.*" "$tor_log" 2>/dev/null | tail -1 || true)

        if [ -n "$bootstrap_line" ]; then
            local pct=""
            pct=$(echo "$bootstrap_line" | grep -o '[0-9]*%' || true)
            if [ -n "$pct" ] && [ "$pct" != "$last_pct" ]; then
                echo -ne "\r  ${DIM}${bootstrap_line}${NC}                    "
                last_pct="$pct"
            fi

            # Check for 100%
            if [[ "$bootstrap_line" == *"100%"* ]]; then
                echo ""
                break
            fi
        else
            # No bootstrap line yet, show waiting indicator
            echo -ne "\r  ${DIM}Waiting for Tor to start...${NC} "
        fi

        sleep 1
        waited=$((waited + 1))
    done

    if [ $waited -ge $timeout ]; then
        echo ""
        log_err "Timed out waiting for Tor to bootstrap ($timeout seconds)"
        return 1
    fi

    # Wait for onion address file (should appear quickly after 100%)
    local addr_wait=0
    while [ ! -f "$ONION_FILE" ] && [ $addr_wait -lt 15 ]; do
        sleep 1
        addr_wait=$((addr_wait + 1))
    done

    if [ -f "$ONION_FILE" ]; then
        local onion
        onion=$(cat "$ONION_FILE")
        log_ok "Tor hidden service active"
        echo -e "  ${BOLD}${GREEN}Your address: ${WHITE}${onion}${NC}"
        return 0
    else
        log_err "Tor bootstrapped but hidden service address not found"
        return 1
    fi
}

stop_tor() {
    stop_auto_listener
    if [ -n "$TOR_PID" ] && kill -0 "$TOR_PID" 2>/dev/null; then
        kill "$TOR_PID" 2>/dev/null || true
        wait "$TOR_PID" 2>/dev/null || true
        TOR_PID=""
        log_ok "Tor stopped"
    else
        log_info "Tor is not running"
    fi
}

get_onion() {
    if [ -f "$ONION_FILE" ]; then
        cat "$ONION_FILE"
    else
        echo ""
    fi
}

rotate_onion() {
    echo -e "\n${BOLD}${CYAN}═══ Rotate Onion Address ═══${NC}\n"
    local old_onion
    old_onion=$(get_onion)
    if [ -n "$old_onion" ]; then
        echo -e "  ${DIM}Current: ${old_onion}${NC}"
    fi
    echo -e "  ${YELLOW}This will generate a new .onion address.${NC}"
    echo -e "  ${YELLOW}The old address will stop working.${NC}\n"
    echo -ne "  ${BOLD}Continue? [y/N]: ${NC}"
    read -r confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_info "Cancelled"
        return
    fi
    stop_tor
    rm -rf "$TOR_DIR/hidden_service"
    log_info "Old hidden service keys deleted"
    start_tor
}

#=============================================================================
# CIRCUIT HOP DISPLAY
#=============================================================================

# Map 2-letter country code to full name
cc_to_country() {
    case "$(to_lower "$1")" in
        ad) echo "Andorra";; ae) echo "UAE";; al) echo "Albania";; am) echo "Armenia";;
        at) echo "Austria";; au) echo "Australia";; az) echo "Azerbaijan";;
        ba) echo "Bosnia";; be) echo "Belgium";; bg) echo "Bulgaria";; br) echo "Brazil";;
        by) echo "Belarus";; ca) echo "Canada";; ch) echo "Switzerland";; cl) echo "Chile";;
        cn) echo "China";; co) echo "Colombia";; cr) echo "Costa Rica";;
        cy) echo "Cyprus";; cz) echo "Czechia";; de) echo "Germany";; dk) echo "Denmark";;
        dz) echo "Algeria";; ec) echo "Ecuador";; ee) echo "Estonia";; eg) echo "Egypt";;
        es) echo "Spain";; fi) echo "Finland";; fr) echo "France";;
        gb) echo "UK";; ge) echo "Georgia";; gr) echo "Greece";;
        hk) echo "Hong Kong";; hr) echo "Croatia";; hu) echo "Hungary";;
        id) echo "Indonesia";; ie) echo "Ireland";; il) echo "Israel";; in) echo "India";;
        iq) echo "Iraq";; ir) echo "Iran";; is) echo "Iceland";; it) echo "Italy";;
        jp) echo "Japan";; ke) echo "Kenya";; kg) echo "Kyrgyzstan";;
        kr) echo "South Korea";; kz) echo "Kazakhstan";;
        lb) echo "Lebanon";; li) echo "Liechtenstein";; lt) echo "Lithuania";;
        lu) echo "Luxembourg";; lv) echo "Latvia";;
        ma) echo "Morocco";; md) echo "Moldova";; me) echo "Montenegro";; mk) echo "N. Macedonia";;
        mt) echo "Malta";; mx) echo "Mexico";; my) echo "Malaysia";;
        ng) echo "Nigeria";; nl) echo "Netherlands";; no) echo "Norway";; nz) echo "New Zealand";;
        pa) echo "Panama";; pe) echo "Peru";; ph) echo "Philippines";; pk) echo "Pakistan";;
        pl) echo "Poland";; pt) echo "Portugal";;
        ro) echo "Romania";; rs) echo "Serbia";; ru) echo "Russia";;
        sa) echo "Saudi Arabia";; se) echo "Sweden";; sg) echo "Singapore";; si) echo "Slovenia";;
        sk) echo "Slovakia";; th) echo "Thailand";; tn) echo "Tunisia";; tr) echo "Turkey";;
        tw) echo "Taiwan";; ua) echo "Ukraine";; us) echo "USA";;
        uy) echo "Uruguay";; uz) echo "Uzbekistan";; ve) echo "Venezuela";;
        vn) echo "Vietnam";; za) echo "South Africa";;
        *) to_upper "$1";;
    esac
}

# Query Tor control port for active circuit hops
# Outputs one line per hop: "relay_name|country_name"
# Returns 1 if circuit info is unavailable
get_circuit_hops() {
    [ "$SHOW_CIRCUIT" -eq 0 ] && return 1

    local cookie_file="$TOR_DIR/data/control_auth_cookie"
    [ ! -f "$cookie_file" ] && return 1

    local cookie_hex
    cookie_hex=$(od -An -tx1 "$cookie_file" | tr -d ' \n' 2>/dev/null) || return 1
    [ -z "$cookie_hex" ] && return 1

    # Step 1: Get circuit status
    local circ_resp
    circ_resp=$({
        printf 'AUTHENTICATE %s\r\n' "$cookie_hex"
        printf 'GETINFO circuit-status\r\n'
        printf 'QUIT\r\n'
    } | socat - TCP:127.0.0.1:$TOR_CONTROL_PORT 2>/dev/null | tr -d '\r') || return 1

    echo "$circ_resp" | grep -q "^250 OK" || return 1

    # Find best BUILT circuit — prefer HS circuits
    local circuit_line
    circuit_line=$(echo "$circ_resp" | grep " BUILT " \
        | grep -E "PURPOSE=HS_SERVICE_INTRO|PURPOSE=HS_CLIENT_REND" | head -1) || true
    [ -z "$circuit_line" ] && circuit_line=$(echo "$circ_resp" | grep " BUILT " | head -1)
    [ -z "$circuit_line" ] && return 1

    # Extract path (field 3: comma-separated $FP~Name entries)
    local path
    path=$(echo "$circuit_line" | awk '{print $3}')
    [ -z "$path" ] && return 1

    # Parse relay names and fingerprints
    local names=() fps=()
    IFS=',' read -ra relays <<< "$path"
    for r in "${relays[@]}"; do
        local name fp
        if [[ "$r" == *"~"* ]]; then
            name="${r#*~}"; fp="${r%%~*}"
        else
            name="${r:0:8}..."; fp="$r"
        fi
        names+=("$name")
        fps+=("${fp#\$}")
    done
    [ ${#names[@]} -eq 0 ] && return 1

    # Step 2: Get IPs for all relays via ns/id (single session)
    local ns_resp
    ns_resp=$({
        printf 'AUTHENTICATE %s\r\n' "$cookie_hex"
        for fp in "${fps[@]}"; do
            printf 'GETINFO ns/id/%s\r\n' "$fp"
        done
        printf 'QUIT\r\n'
    } | socat - TCP:127.0.0.1:$TOR_CONTROL_PORT 2>/dev/null | tr -d '\r') || true

    local ips=()
    if [ -n "$ns_resp" ]; then
        while IFS= read -r rline; do
            ips+=("$(echo "$rline" | awk '{print $7}')")
        done <<< "$(echo "$ns_resp" | grep '^r ')"
    fi

    # Step 3: Resolve countries for all IPs (single session)
    local countries=()
    local has_ips=0
    for ip in "${ips[@]}"; do [ -n "$ip" ] && has_ips=1 && break; done

    if [ "$has_ips" -eq 1 ]; then
        local cc_resp
        cc_resp=$({
            printf 'AUTHENTICATE %s\r\n' "$cookie_hex"
            for ip in "${ips[@]}"; do
                [ -n "$ip" ] && printf 'GETINFO ip-to-country/%s\r\n' "$ip"
            done
            printf 'QUIT\r\n'
        } | socat - TCP:127.0.0.1:$TOR_CONTROL_PORT 2>/dev/null | tr -d '\r') || true

        if [ -n "$cc_resp" ]; then
            while IFS= read -r ccline; do
                local cc
                cc=$(echo "$ccline" | sed 's/.*=//')
                countries+=("$(cc_to_country "$cc")")
            done <<< "$(echo "$cc_resp" | grep 'ip-to-country')"
        fi
    fi

    # Output one line per hop: "name|country"
    local total=${#names[@]}
    for ((i = 0; i < total; i++)); do
        local country="${countries[$i]:-??}"
        echo "${names[$i]}|${country}"
    done
    return 0
}

#=============================================================================
# ENCRYPTION
#=============================================================================

set_shared_secret() {
    echo -e "\n${BOLD}${CYAN}═══ Set Shared Secret ═══${NC}\n"
    echo -e "${DIM}Both parties must use the same secret for the call to work.${NC}"
    echo -e "${DIM}Share this secret securely (in person, via encrypted message, etc.)${NC}\n"

    if [ -n "$SHARED_SECRET" ]; then
        echo -e "Current secret: ${DIM}(set)${NC}"
    else
        echo -e "Current secret: ${DIM}(none)${NC}"
    fi

    echo -ne "\n${BOLD}Enter shared secret: ${NC}"
    read -r new_secret

    if [ -z "$new_secret" ]; then
        log_warn "Secret not changed"
        return
    fi

    SHARED_SECRET="$new_secret"
    mkdir -p "$DATA_DIR"

    echo -ne "\n  ${BOLD}Protect with a passphrase? [Y/n]: ${NC}"
    read -r _protect
    if [ "$_protect" != "n" ] && [ "$_protect" != "N" ]; then
        echo -ne "  ${BOLD}Choose a passphrase: ${NC}"
        read -rs _pass
        echo ""
        if [ -n "$_pass" ]; then
            echo -ne "  ${BOLD}Confirm passphrase: ${NC}"
            read -rs _pass2
            echo ""
            if [ "$_pass" = "$_pass2" ]; then
                echo -n "$SHARED_SECRET" | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
                    -pass "fd:3" -out "$SECRET_FILE" 3<<< "${_pass}" 2>/dev/null
                chmod 600 "$SECRET_FILE"
                log_ok "Shared secret saved (encrypted with passphrase)"
                return
            else
                log_warn "Passphrases don't match"
            fi
        else
            log_warn "Empty passphrase"
        fi
        log_info "Falling back to plaintext storage"
    fi

    # Plaintext fallback
    echo -n "$SHARED_SECRET" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    log_ok "Shared secret saved"
}


# Encrypt a file
encrypt_file() {
    local infile="$1" outfile="$2"
    local c="$CIPHER"
    [ -f "$CIPHER_RUNTIME_FILE" ] && c=$(cat "$CIPHER_RUNTIME_FILE")
    openssl enc -"${c}" -pbkdf2 -iter 10000 -pass "fd:3" \
        -in "$infile" -out "$outfile" 3<<< "${SHARED_SECRET}" 2>/dev/null
}

# Decrypt a file
decrypt_file() {
    local infile="$1" outfile="$2"
    local c="$CIPHER"
    [ -f "$CIPHER_RUNTIME_FILE" ] && c=$(cat "$CIPHER_RUNTIME_FILE")
    openssl enc -d -"${c}" -pbkdf2 -iter 10000 -pass "fd:3" \
        -in "$infile" -out "$outfile" 3<<< "${SHARED_SECRET}" 2>/dev/null
}

#=============================================================================
# PROTOCOL SEND / VERIFY (HMAC)
#=============================================================================

# Send a protocol message, optionally HMAC-signed with random nonce
proto_send() {
    local msg="$1"
    local _hmac=0
    [ -f "$HMAC_RUNTIME_FILE" ] && _hmac=$(cat "$HMAC_RUNTIME_FILE" 2>/dev/null)
    [ -z "$_hmac" ] && _hmac="$HMAC_AUTH"
    if [ "$_hmac" -eq 1 ]; then
        local nonce sig signed_msg
        nonce=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
        signed_msg="${nonce}:${msg}"
        sig=$(printf '%s' "$signed_msg" | openssl dgst -sha256 -hmac "$SHARED_SECRET" -r 2>/dev/null | cut -d' ' -f1)
        echo "${signed_msg}|${sig}" >&4 2>/dev/null || true
    else
        echo "$msg" >&4 2>/dev/null || true
    fi
}

# Verify HMAC on a received message
# Outputs the raw message (without nonce) on stdout; returns 1 on failure
proto_verify() {
    local line="$1"
    local _hmac=0
    [ -f "$HMAC_RUNTIME_FILE" ] && _hmac=$(cat "$HMAC_RUNTIME_FILE" 2>/dev/null)
    [ -z "$_hmac" ] && _hmac="$HMAC_AUTH"
    if [ "$_hmac" -ne 1 ]; then
        echo "$line"
        return 0
    fi
    # Must contain | separator for HMAC
    if [[ "$line" != *"|"* ]]; then
        return 1
    fi
    local signed_msg="${line%|*}"
    local received_sig="${line##*|}"
    local expected_sig
    expected_sig=$(printf '%s' "$signed_msg" | openssl dgst -sha256 -hmac "$SHARED_SECRET" -r 2>/dev/null | cut -d' ' -f1)
    if [ "$received_sig" = "$expected_sig" ]; then
        # Reject replayed nonces
        local nonce="${signed_msg%%:*}"
        if grep -qF "$nonce" "$NONCE_LOG_FILE" 2>/dev/null; then
            return 1
        fi
        echo "$nonce" >> "$NONCE_LOG_FILE" 2>/dev/null
        # Strip nonce prefix (nonce:message → message)
        echo "${signed_msg#*:}"
        return 0
    fi
    return 1
}

#=============================================================================
# AUDIO PIPELINE
#=============================================================================

# Linux: capture raw S16_LE mono PCM for a fixed duration into a file.
# Uses PulseAudio/PipeWire (parec) when available, else falls back to ALSA.
linux_capture_timed() {
    local outfile="$1"
    local duration="$2"
    if [ "$(detect_audio_backend)" = "pulse" ]; then
        timeout "$duration" parec --rate="$SAMPLE_RATE" --channels=1 --format=s16le \
            > "$outfile" 2>/dev/null || true
    else
        arecord -D "$(detect_capture_device)" -f S16_LE -r "$SAMPLE_RATE" -c 1 -t raw \
            -d "$duration" -q "$outfile" 2>/dev/null
    fi
}

# Linux: start a continuous raw capture in the background, writing to $1.
# Sets REC_PID in the caller's shell so it can be stopped later.
linux_capture_start() {
    local outfile="$1"
    if [ "$(detect_audio_backend)" = "pulse" ]; then
        parec --rate="$SAMPLE_RATE" --channels=1 --format=s16le > "$outfile" 2>/dev/null &
    else
        arecord -D "$(detect_capture_device)" -f S16_LE -r "$SAMPLE_RATE" -c 1 -t raw \
            -q "$outfile" 2>/dev/null &
    fi
    REC_PID=$!
}

# Linux: play raw S16_LE mono PCM from a file at the given rate.
linux_play_file() {
    local infile="$1"
    local rate="$2"
    if [ "$(detect_audio_backend)" = "pulse" ]; then
        pacat --rate="$rate" --channels=1 --format=s16le < "$infile" 2>/dev/null || true
    else
        aplay -D "$(detect_playback_device)" -f S16_LE -r "$rate" -c 1 -q "$infile" 2>/dev/null || true
    fi
}

# Record a timed chunk of raw audio (used by audio test)
audio_record() {
    local outfile="$1"
    local duration="${2:-$CHUNK_DURATION}"

    if [ $IS_TERMUX -eq 1 ]; then
        local tmp_rec="$AUDIO_DIR/tmrec_$(uid).m4a"
        rm -f "$tmp_rec"
        termux-microphone-record -l "$((duration + 1))" -r "$SAMPLE_RATE" -f "$tmp_rec" &>/dev/null
        sleep "$duration"
        termux-microphone-record -q &>/dev/null || true
        sleep 0.5
        if [ -s "$tmp_rec" ]; then
            ffmpeg -y -i "$tmp_rec" -f s16le -ar "$SAMPLE_RATE" -ac 1 \
                "$outfile" &>/dev/null || log_warn "ffmpeg conversion failed"
        fi
        rm -f "$tmp_rec"
    elif [ $IS_MACOS -eq 1 ]; then
        rec -q -t raw -r "$SAMPLE_RATE" -e signed -b 16 -c 1 "$outfile" trim 0 "$duration" 2>/dev/null
    else
        linux_capture_timed "$outfile" "$duration"
    fi
}

# Start continuous recording in background (returns immediately)
# Sets REC_PID and REC_FILE globals
start_recording() {
    local _id=$(uid)

    if [ $IS_TERMUX -eq 1 ]; then
        REC_FILE="$AUDIO_DIR/msg_${_id}.m4a"
        rm -f "$REC_FILE"
        termux-microphone-record -l 120 -r "$SAMPLE_RATE" -f "$REC_FILE" &>/dev/null &
        REC_PID=$!
    elif [ $IS_MACOS -eq 1 ]; then
        REC_FILE="$AUDIO_DIR/msg_${_id}.tmp"
        rec -q -t raw -r "$SAMPLE_RATE" -e signed -b 16 -c 1 "$REC_FILE" 2>/dev/null &
        REC_PID=$!
    else
        REC_FILE="$AUDIO_DIR/msg_${_id}.tmp"
        linux_capture_start "$REC_FILE"
    fi
}

# Apply voice effect to raw PCM using sox
apply_voice_effect() {
    local infile="$1"
    local outfile="$2"
    local fmt="-t raw -r $SAMPLE_RATE -e signed -b 16 -c 1"
    case "$VOICE_EFFECT" in
        deep)
            sox $fmt "$infile" $fmt "$outfile" pitch -400 2>/dev/null
            ;;
        high)
            sox $fmt "$infile" $fmt "$outfile" pitch 500 2>/dev/null
            ;;
        robot)
            sox $fmt "$infile" $fmt "$outfile" overdrive 10 flanger 2>/dev/null
            ;;
        echo)
            sox $fmt "$infile" $fmt "$outfile" echo 0.8 0.88 60 0.4 2>/dev/null
            ;;
        whisper)
            sox $fmt "$infile" $fmt "$outfile" highpass 1000 tremolo 20 2>/dev/null
            ;;
        custom)
            # Build sox effects chain from individual parameters
            local effects=""
            [ "$VOICE_PITCH" -ne 0 ] 2>/dev/null && effects="$effects pitch $VOICE_PITCH"
            [ "$VOICE_OVERDRIVE" -gt 0 ] 2>/dev/null && effects="$effects overdrive $VOICE_OVERDRIVE"
            [ "$VOICE_FLANGER" -eq 1 ] 2>/dev/null && effects="$effects flanger"
            [ "$VOICE_ECHO_DELAY" -gt 0 ] 2>/dev/null && effects="$effects echo 0.8 0.88 $VOICE_ECHO_DELAY 0.${VOICE_ECHO_DECAY}"
            [ "$VOICE_HIGHPASS" -gt 0 ] 2>/dev/null && effects="$effects highpass $VOICE_HIGHPASS"
            [ "$VOICE_TREMOLO" -gt 0 ] 2>/dev/null && effects="$effects tremolo $VOICE_TREMOLO"
            if [ -n "$effects" ]; then
                sox $fmt "$infile" $fmt "$outfile" $effects 2>/dev/null
            else
                return 1  # no effects configured
            fi
            ;;
        *)
            return 1  # no effect
            ;;
    esac
}

# Stop recording and send the message
# Encodes, encrypts, base64-encodes, and writes to fd 4
stop_and_send() {
    local _id=$(uid)
    local raw_file="$AUDIO_DIR/tx_${_id}.tmp"
    local opus_file="$AUDIO_DIR/tx_o_${_id}.tmp"
    local enc_file="$AUDIO_DIR/tx_e_${_id}.tmp"

    # Stop the recording
    if [ $IS_TERMUX -eq 1 ]; then
        termux-microphone-record -q &>/dev/null || true
        kill "$REC_PID" 2>/dev/null || true
        wait "$REC_PID" 2>/dev/null || true
        sleep 0.3  # let file flush
        # Convert m4a → raw PCM
        if [ -s "$REC_FILE" ]; then
            if ! ffmpeg -y -i "$REC_FILE" -f s16le -ar "$SAMPLE_RATE" -ac 1 \
                "$raw_file" 2>/dev/null; then
                log_warn "ffmpeg conversion failed" >&2
            fi
        fi
        rm -f "$REC_FILE"
    else
        kill "$REC_PID" 2>/dev/null || true
        wait "$REC_PID" 2>/dev/null || true
        raw_file="$REC_FILE"  # already in raw format
    fi

    REC_PID=""
    REC_FILE=""

    # Apply voice effect if set
    if [ -s "$raw_file" ] && [ "$VOICE_EFFECT" != "none" ]; then
        local fx_file="$AUDIO_DIR/tx_fx_${_id}.tmp"
        if apply_voice_effect "$raw_file" "$fx_file"; then
            mv "$fx_file" "$raw_file"
        else
            rm -f "$fx_file" 2>/dev/null
        fi
    fi

    # Encode → encrypt → send
    if [ -s "$raw_file" ]; then
        opusenc --raw --raw-rate "$SAMPLE_RATE" --raw-chan 1 \
            --bitrate "$OPUS_BITRATE" --framesize "$OPUS_FRAMESIZE" \
            --speech --quiet \
            "$raw_file" "$opus_file" 2>/dev/null

        if [ -s "$opus_file" ]; then
            encrypt_file "$opus_file" "$enc_file" 2>/dev/null
            if [ -s "$enc_file" ]; then
                local enc_size
                enc_size=$(file_size "$enc_file")
                local size_kb=$(( enc_size * 10 / 1024 ))
                local size_whole=$(( size_kb / 10 ))
                local size_frac=$(( size_kb % 10 ))

                local b64
                b64=$(base64 < "$enc_file" | tr -d '\n')
                proto_send "AUDIO:${b64}"
                LAST_SENT_INFO="${size_whole}.${size_frac}KB"
            fi
        fi
    fi
    rm -f "$raw_file" "$opus_file" "$enc_file" 2>/dev/null
}

# Play audio (platform-aware)
audio_play() {
    local infile="$1"
    local rate="${2:-48000}"

    if [ $IS_TERMUX -eq 0 ] && [ $IS_MACOS -eq 0 ]; then
        # Linux: PulseAudio/PipeWire (pacat) when available, else ALSA aplay
        linux_play_file "$infile" "$rate"
    else
        # macOS / Termux: use sox play
        play -q -t raw -r "$rate" -e signed -b 16 -c 1 "$infile" 2>/dev/null || true
    fi
}



# Play an opus file
play_chunk() {
    local opus_file="$1"

    if [ $IS_TERMUX -eq 1 ] || [ $IS_MACOS -eq 1 ]; then
        # macOS / Termux: pipe decode directly to sox play
        opusdec --quiet --rate 48000 "$opus_file" - 2>/dev/null | \
            play -q -t raw -r 48000 -e signed -b 16 -c 1 - 2>/dev/null || true
    elif [ "$(detect_audio_backend)" = "pulse" ]; then
        # Linux (PulseAudio/PipeWire): pipe decode directly to pacat
        opusdec --quiet --rate 48000 "$opus_file" - 2>/dev/null | \
            pacat --rate=48000 --channels=1 --format=s16le 2>/dev/null || true
    else
        # Linux (ALSA): pipe decode directly to aplay with detected device
        local _pdev
        _pdev=$(detect_playback_device)
        opusdec --quiet --rate 48000 "$opus_file" - 2>/dev/null | \
            aplay -D "$_pdev" -f S16_LE -r 48000 -c 1 -q 2>/dev/null || true
    fi
}



#=============================================================================
# CALL CLEANUP — RESET EVERYTHING TO FRESH STATE
#=============================================================================

cleanup_call() {
    # Restore terminal to sane state
    if [ -n "$ORIGINAL_STTY" ]; then
        stty "$ORIGINAL_STTY" 2>/dev/null || true
    fi
    stty sane 2>/dev/null || true
    ORIGINAL_STTY=""

    # Close pipe file descriptors to unblock any blocking reads
    # NOTE: must use { } group so 2>/dev/null doesn't permanently redirect stderr
    { exec 3<&-; } 2>/dev/null || true
    { exec 4>&-; } 2>/dev/null || true

    # Kill all call-related processes by PID files
    for pidfile in "$PID_DIR"/socat.pid "$PID_DIR"/socat_call.pid "$PID_DIR"/recv_loop.pid; do
        if [ -f "$pidfile" ]; then
            local pid
            pid=$(cat "$pidfile" 2>/dev/null)
            if [ -n "$pid" ]; then
                kill "$pid" 2>/dev/null || true
                kill -9 "$pid" 2>/dev/null || true
            fi
            rm -f "$pidfile"
        fi
    done

    # Kill recording process if active
    if [ -n "$REC_PID" ]; then
        kill "$REC_PID" 2>/dev/null || true
        kill -9 "$REC_PID" 2>/dev/null || true
        REC_PID=""
    fi

    # Wait briefly for processes to die
    sleep 0.2

    # Kill volume monitor if active
    if [ -n "$VOL_MON_PID" ]; then
        kill "$VOL_MON_PID" 2>/dev/null || true
        kill -9 "$VOL_MON_PID" 2>/dev/null || true
        VOL_MON_PID=""
    fi

    # Remove all runtime files for this PID
    rm -f "$PTT_FLAG" "$CONNECTED_FLAG"
    rm -f "$RECV_PIPE" "$SEND_PIPE"
    rm -f "$CIPHER_RUNTIME_FILE"
    rm -f "$HMAC_RUNTIME_FILE"
    rm -f "$NONCE_LOG_FILE"
    rm -f "$DATA_DIR/run/remote_id_$$"
    rm -f "$DATA_DIR/run/remote_cipher_$$"
    rm -f "$DATA_DIR/run/relay_mode_$$"
    rm -f "$DATA_DIR/run/group_count_$$"
    rm -f "$DATA_DIR/run/incoming_$$"
    rm -f "$DATA_DIR/run/vol_ptt_trigger_$$"

    # Kill circuit refresh if active
    if [ -n "$CIRCUIT_REFRESH_PID" ]; then
        kill "$CIRCUIT_REFRESH_PID" 2>/dev/null || true
        CIRCUIT_REFRESH_PID=""
    fi

    # Clean temp audio files
    rm -f "$AUDIO_DIR"/*.tmp 2>/dev/null || true

    # Reset state variables
    CALL_ACTIVE=0
    REC_PID=""
}
#=============================================================================
# AUTO-LISTEN (BACKGROUND LISTENER)
#=============================================================================

start_auto_listener() {
    # Only start if auto-listen is enabled and Tor is running
    if [ "$AUTO_LISTEN" -ne 1 ]; then return 0; fi
    if [ -z "$SHARED_SECRET" ]; then return 0; fi
    if [ -z "$TOR_PID" ] || ! kill -0 "$TOR_PID" 2>/dev/null; then return 0; fi

    # Stop any existing listener first
    stop_auto_listener

    mkdir -p "$AUDIO_DIR" "$DATA_DIR/run"
    rm -f "$RECV_PIPE" "$SEND_PIPE" "$AUTO_LISTEN_FLAG"
    mkfifo "$RECV_PIPE" "$SEND_PIPE"

    socat "TCP-LISTEN:$LISTEN_PORT,reuseaddr" \
        "SYSTEM:touch $AUTO_LISTEN_FLAG; cat $SEND_PIPE & cat > $RECV_PIPE" &
    AUTO_LISTEN_PID=$!
    save_pid "socat" "$AUTO_LISTEN_PID"
}

stop_auto_listener() {
    if [ -n "$AUTO_LISTEN_PID" ]; then
        kill "$AUTO_LISTEN_PID" 2>/dev/null || true
        kill -9 "$AUTO_LISTEN_PID" 2>/dev/null || true
        AUTO_LISTEN_PID=""
    fi
    rm -f "$AUTO_LISTEN_FLAG" "$RECV_PIPE" "$SEND_PIPE"
}

#=============================================================================
# VOLUME-DOWN DOUBLE-TAP PTT MONITOR (Termux only, experimental)
#=============================================================================
VOL_MON_PID=""

start_vol_monitor() {
    local trigger_file="${1:-$DATA_DIR/run/vol_ptt_trigger_$$}"
    [ "$VOL_PTT" -ne 1 ] && return
    [ "$IS_TERMUX" -ne 1 ] && return
    if ! check_dep jq; then
        log_warn "jq not found — Volume PTT disabled"
        return
    fi
    if ! check_dep termux-volume; then
        log_warn "termux-volume not found — Volume PTT disabled"
        return
    fi

    rm -f "$trigger_file"

    (
        local last_vol=""
        local last_tap=0
        local restore_vol=""

        while [ -f "$CONNECTED_FLAG" ]; do
            local cur_vol
            cur_vol=$(termux-volume 2>/dev/null \
                | jq -r '.[] | select(.stream=="music") | .volume' 2>/dev/null \
                || echo "")

            # Remember the initial volume so we can restore after detection
            if [ -n "$cur_vol" ] && [ -z "$restore_vol" ]; then
                restore_vol="$cur_vol"
            fi

            if [ -n "$cur_vol" ] && [ -n "$last_vol" ]; then
                local drop=$(( last_vol - cur_vol ))

                if [ "$drop" -ge 2 ] 2>/dev/null; then
                    # Rapid double-tap: both presses landed in one poll cycle
                    touch "$trigger_file"
                    last_tap=0
                    # Restore volume for next use
                    if [ -n "$restore_vol" ]; then
                        termux-volume music "$restore_vol" 2>/dev/null || true
                        last_vol="$restore_vol"
                        sleep 0.5
                        continue
                    fi
                elif [ "$drop" -ge 1 ] 2>/dev/null; then
                    # Single press — check if second press follows within 1s
                    local now
                    now=$(date +%s)
                    if [ "$last_tap" -gt 0 ] && [ $((now - last_tap)) -le 1 ]; then
                        touch "$trigger_file"
                        last_tap=0
                        if [ -n "$restore_vol" ]; then
                            termux-volume music "$restore_vol" 2>/dev/null || true
                            last_vol="$restore_vol"
                            sleep 0.5
                            continue
                        fi
                    else
                        last_tap=$now
                    fi
                fi
            fi
            last_vol="$cur_vol"
            sleep 0.4
        done
    ) &
    VOL_MON_PID=$!
}

stop_vol_monitor() {
    if [ -n "$VOL_MON_PID" ]; then
        kill "$VOL_MON_PID" 2>/dev/null || true
        kill -9 "$VOL_MON_PID" 2>/dev/null || true
        VOL_MON_PID=""
    fi
    rm -f "$DATA_DIR/run/vol_ptt_trigger_$$"
}

# Check if an incoming call arrived on the background listener
check_auto_listen() {
    if [ -f "$AUTO_LISTEN_FLAG" ]; then
        rm -f "$AUTO_LISTEN_FLAG"
        touch "$CONNECTED_FLAG"
        echo -e "\n  ${GREEN}${BOLD}Incoming call detected!${NC}" >&2
        sleep 0.5
        in_call_session "$RECV_PIPE" "$SEND_PIPE" ""
        cleanup_call
        # Restart listener for next call
        start_auto_listener
        return 0
    fi
    return 1
}

# Start listening for incoming calls (manual, blocking)
listen_for_call() {
    if [ -z "$SHARED_SECRET" ]; then
        log_err "No shared secret set! Use option 4 first."
        return 1
    fi

    start_tor || return 1

    # Stop auto-listener if running (we'll do manual listen)
    stop_auto_listener

    local onion
    onion=$(get_onion)
    echo -e "\n${BOLD}${CYAN}═══ Listening for Calls ═══${NC}\n"
    echo -e "  ${GREEN}Your address:${NC} ${BOLD}${WHITE}$onion${NC}"
    echo -e "  ${GREEN}Listening on:${NC} port $LISTEN_PORT"
    echo -e "\n  ${DIM}Share your .onion address with the caller.${NC}"
    echo -e "  ${DIM}[Q] Stop listening  [B] Listen in background${NC}\n"

    mkdir -p "$AUDIO_DIR"
    log_info "Waiting for incoming connection..."

    rm -f "$RECV_PIPE" "$SEND_PIPE"
    mkfifo "$RECV_PIPE" "$SEND_PIPE"

    local incoming_flag="$DATA_DIR/run/incoming_$$"
    rm -f "$incoming_flag"

    socat "TCP-LISTEN:$LISTEN_PORT,reuseaddr" \
        "SYSTEM:touch $incoming_flag; cat $SEND_PIPE & cat > $RECV_PIPE" &
    local socat_pid=$!
    save_pid "socat" "$socat_pid"

    while [ ! -f "$incoming_flag" ]; do
        if ! kill -0 "$socat_pid" 2>/dev/null; then
            log_err "Listener stopped unexpectedly"
            rm -f "$RECV_PIPE" "$SEND_PIPE" "$incoming_flag"
            # Restart auto-listener if enabled
            start_auto_listener
            return 1
        fi
        # Read user input with 1-second timeout
        local user_input=""
        if read -r -t 1 user_input 2>/dev/null; then
            case "$user_input" in
                q|Q)
                    # Stop all listening (manual + auto), return to menu
                    kill "$socat_pid" 2>/dev/null || true
                    wait "$socat_pid" 2>/dev/null || true
                    rm -f "$RECV_PIPE" "$SEND_PIPE" "$incoming_flag"
                    stop_auto_listener
                    AUTO_LISTEN=0
                    save_config
                    log_info "Stopped listening."
                    return 0
                    ;;
                b|B)
                    # Move to background: kill manual socat, enable auto-listen
                    kill "$socat_pid" 2>/dev/null || true
                    wait "$socat_pid" 2>/dev/null || true
                    rm -f "$RECV_PIPE" "$SEND_PIPE" "$incoming_flag"
                    AUTO_LISTEN=1
                    save_config
                    start_auto_listener
                    log_ok "Listening in background. Returning to menu."
                    sleep 1
                    return 0
                    ;;
            esac
        fi
    done

    touch "$CONNECTED_FLAG"
    log_ok "Call connected!"
    in_call_session "$RECV_PIPE" "$SEND_PIPE" ""
    cleanup_call

    # Restart auto-listener if enabled
    start_auto_listener
}

# Call a remote .onion address
call_remote() {
    if [ -z "$SHARED_SECRET" ]; then
        log_err "No shared secret set! Use option 4 first."
        return 1
    fi

    echo -e "\n${BOLD}${CYAN}═══ Make a Call ═══${NC}\n"
    echo -ne "  ${BOLD}Enter .onion address: ${NC}"
    read -r remote_onion

    if [ -z "$remote_onion" ]; then
        log_warn "No address entered"
        return 1
    fi

    # Strip http(s):// prefix (some QR scanners auto-prepend it)
    remote_onion="${remote_onion#http://}"
    remote_onion="${remote_onion#https://}"

    # Append .onion if not present
    if [[ "$remote_onion" != *.onion ]]; then
        remote_onion="${remote_onion}.onion"
    fi

    start_tor || return 1

    echo -e "\n  ${DIM}Connecting to ${remote_onion}:${LISTEN_PORT} via Tor...${NC}"

    mkdir -p "$AUDIO_DIR"
    touch "$CONNECTED_FLAG"

    # Create named pipes
    rm -f "$RECV_PIPE" "$SEND_PIPE"
    mkfifo "$RECV_PIPE" "$SEND_PIPE"

    # Connect via Tor SOCKS proxy using socat
    socat "SOCKS4A:127.0.0.1:${remote_onion}:${LISTEN_PORT},socksport=${TOR_SOCKS_PORT}" \
          "SYSTEM:cat $SEND_PIPE & cat > $RECV_PIPE" &
    local socat_pid=$!
    save_pid "socat_call" "$socat_pid"

    # Animated connecting indicator while socat establishes connection
    (
        local dots=""
        while true; do
            for dots in "." ".." "..." "   "; do
                echo -ne "\r  ${CYAN}${BOLD}Connecting${dots}${NC}   " >&2
                sleep 0.3
            done
        done
    ) &
    local spinner_pid=$!

    # Give socat a moment to connect
    sleep 2

    if kill -0 "$socat_pid" 2>/dev/null; then
        in_call_session "$RECV_PIPE" "$SEND_PIPE" "$remote_onion" "$spinner_pid"
    else
        # Kill spinner and show error
        kill "$spinner_pid" 2>/dev/null || true
        wait "$spinner_pid" 2>/dev/null || true
        echo -ne "\r                              " >&2
        echo "" >&2
        log_err "Failed to connect. Check the address and ensure Tor is running."
    fi

    # Full cleanup after call ends
    cleanup_call
}

#=============================================================================
# RELAY MODE — N-CALLER GROUP BRIDGE
#=============================================================================

relay_mode() {
    clear
    echo -e "\n${BOLD}${CYAN}═══ Relay Mode (Group Bridge) ═══${NC}\n"
    echo -e "  ${DIM}Your device acts as a dumb relay that bridges multiple${NC}"
    echo -e "  ${DIM}callers together. It never decrypts anything — all${NC}"
    echo -e "  ${DIM}callers share a secret between themselves.${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}How it works:${NC}"
    echo -e "  ${DIM}• You share your .onion address with all participants${NC}"
    echo -e "  ${DIM}• Each caller dials your address (option 2 on their end)${NC}"
    echo -e "  ${DIM}• When anyone sends a message, it is forwarded to all others${NC}"
    echo -e "  ${DIM}• Works naturally with PTT — one person talks at a time${NC}"
    echo ""
    echo -e "  ${BOLD}${WHITE}Privacy:${NC}"
    echo -e "  ${DIM}• Callers stay anonymous (3-hop circuits on their side)${NC}"
    echo -e "  ${DIM}• No caller sees another's .onion address — only yours${NC}"
    echo -e "  ${DIM}• The relay cannot read messages (no shared secret)${NC}"
    echo -e "  ${DIM}• Enable single-hop mode in Tor Settings for lowest latency${NC}"
    echo ""
    echo -e "  ${YELLOW}All callers must use the same shared secret.${NC}"
    echo -e "  ${YELLOW}The relay operator does NOT need a shared secret.${NC}"
    echo ""
    echo -ne "  ${BOLD}Start relay? [Y/n]: ${NC}"
    read -r _relay_confirm
    if [ "$_relay_confirm" = "n" ] || [ "$_relay_confirm" = "N" ]; then
        return
    fi

    start_tor || return 1

    local relay_dir="$DATA_DIR/relay"
    mkdir -p "$relay_dir"
    rm -f "$relay_dir"/* 2>/dev/null

    # Write per-connection handler script
    cat > "$relay_dir/handler.sh" << 'RELAY_HANDLER_EOF'
#!/bin/bash
RELAY_DIR="$1"
ID="$$"
OUTFIFO="$RELAY_DIR/out_${ID}.fifo"

mkfifo "$OUTFIFO" 2>/dev/null || exit 1
touch "$RELAY_DIR/client_${ID}"

# Send relay greeting so clients detect group mode
printf 'RELAY:1\n'

# Broadcast group count to all connected clients
broadcast_count() {
    local count=0
    for cf in "$RELAY_DIR"/client_*; do
        [ -f "$cf" ] && count=$((count + 1))
    done
    for f in "$RELAY_DIR"/out_*.fifo; do
        [ -p "$f" ] || continue
        printf 'GROUP:%s\n' "$count" > "$f" 2>/dev/null &
    done
}

# Writer: reads from outbox FIFO, sends to network (stdout)
# Starts in background — blocks until keepalive writer opens below
while IFS= read -r msg; do
    printf '%s\n' "$msg"
done < "$OUTFIFO" &
WR_PID=$!

# Keepalive writer — prevents reader EOF when external writers close
exec 3>"$OUTFIFO"

# Announce updated group size (includes this new caller)
sleep 0.3
broadcast_count

# Reader: network (stdin) → broadcast to all other outboxes
# Only forward audio, chat, pings, and group updates
BYTES_IN=0
BYTES_OUT=0
while IFS= read -r line; do
    # Track inbound bytes
    BYTES_IN=$((BYTES_IN + ${#line}))
    # Strip HMAC wrapper if present (nonce:payload|sig → payload)
    local_payload="$line"
    case "$line" in *"|"*) local_payload="${line%|*}"; local_payload="${local_payload#*:}" ;; esac
    # Filter: only forward AUDIO:, MSG:, and PING. GROUP: is intentionally
    # excluded — the relay generates its own GROUP:N broadcasts, and forwarding
    # client-sent GROUP: would let an unauthenticated peer inject terminal
    # escape sequences into every participant's terminal (issue #1).
    case "$local_payload" in
        AUDIO:*|MSG:*|PING) ;;
        *) continue ;;
    esac
    for f in "$RELAY_DIR"/out_*.fifo; do
        [ "$f" = "$OUTFIFO" ] && continue
        [ -p "$f" ] || continue
        printf '%s\n' "$line" > "$f" 2>/dev/null &
        BYTES_OUT=$((BYTES_OUT + ${#line}))
    done
    # Write stats periodically (every message)
    echo "$BYTES_IN $BYTES_OUT" > "$RELAY_DIR/stats_${ID}"
done

# Client disconnected — cleanup
exec 3>&-
kill $WR_PID 2>/dev/null
wait $WR_PID 2>/dev/null

# Accumulate this caller's stats into persistent totals before removing
if [ -f "$RELAY_DIR/stats_${ID}" ]; then
    read -r _fi _fo < "$RELAY_DIR/stats_${ID}" 2>/dev/null || { _fi=0; _fo=0; }
    (
        flock 9
        _ti=0; _to=0
        [ -f "$RELAY_DIR/stats_total" ] && read -r _ti _to < "$RELAY_DIR/stats_total" 2>/dev/null
        echo "$((_ti + ${_fi:-0})) $((_to + ${_fo:-0}))" > "$RELAY_DIR/stats_total"
    ) 9>"$RELAY_DIR/.stats_lock"
fi
rm -f "$OUTFIFO" "$RELAY_DIR/client_${ID}" "$RELAY_DIR/stats_${ID}"

# Broadcast updated count (one fewer)
broadcast_count
RELAY_HANDLER_EOF
    chmod +x "$relay_dir/handler.sh"

    local onion
    onion=$(get_onion)
    echo ""
    echo -e "  ${GREEN}Relay address:${NC} ${BOLD}${WHITE}$onion${NC}"
    echo -e "  ${DIM}Share this address with all callers.${NC}"
    echo ""

    # Start socat with fork to accept multiple connections
    socat "TCP-LISTEN:$LISTEN_PORT,reuseaddr,fork" \
        "EXEC:bash $relay_dir/handler.sh $relay_dir" &
    local socat_pid=$!

    log_ok "Relay active — waiting for callers..."
    echo -e "  ${DIM}[Q] Stop relay${NC}\n"

    local start_time
    start_time=$(date +%s)

    local _bc_tick=0
    while kill -0 "$socat_pid" 2>/dev/null; do
        local count=0
        for _cf in "$relay_dir"/client_*; do
            [ -f "$_cf" ] && count=$((count + 1))
        done
        local uptime=$(( $(date +%s) - start_time ))
        local mins=$(( uptime / 60 ))
        local secs=$(( uptime % 60 ))
        # Sum data stats from all handlers + accumulated totals from disconnected callers
        local total_in=0 total_out=0
        for _sf in "$relay_dir"/stats_*; do
            [ -f "$_sf" ] || continue
            local _si _so
            read -r _si _so < "$_sf" 2>/dev/null || continue
            total_in=$((total_in + ${_si:-0}))
            total_out=$((total_out + ${_so:-0}))
        done
        # Format bytes to human-readable
        local in_display out_display
        if [ $total_in -ge 1048576 ]; then
            in_display="$((total_in / 1048576)).$((total_in % 1048576 / 104858))MB"
        elif [ $total_in -ge 1024 ]; then
            in_display="$((total_in / 1024))KB"
        else
            in_display="${total_in}B"
        fi
        if [ $total_out -ge 1048576 ]; then
            out_display="$((total_out / 1048576)).$((total_out % 1048576 / 104858))MB"
        elif [ $total_out -ge 1024 ]; then
            out_display="$((total_out / 1024))KB"
        else
            out_display="${total_out}B"
        fi
        printf "\r  ${BOLD}Callers:${NC} ${GREEN}%-3s${NC} ${DIM}Uptime: %dm %02ds${NC}  ${DIM}In:${NC} ${WHITE}%-8s${NC} ${DIM}Out:${NC} ${WHITE}%-8s${NC}   " \
            "$count" "$mins" "$secs" "$in_display" "$out_display" 2>/dev/null

        # Periodic GROUP:N broadcast to all clients (~every 10 seconds)
        _bc_tick=$((_bc_tick + 1))
        if [ $((_bc_tick % 5)) -eq 0 ] && [ "$count" -gt 0 ]; then
            for _bf in "$relay_dir"/out_*.fifo; do
                [ -p "$_bf" ] || continue
                printf 'GROUP:%s\n' "$count" > "$_bf" 2>/dev/null &
            done
        fi

        local input=""
        if read -r -t 2 input 2>/dev/null; then
            case "$input" in
                q|Q) break ;;
            esac
        fi
    done

    # Cleanup
    echo ""
    log_info "Stopping relay..."
    kill "$socat_pid" 2>/dev/null
    # Kill forked handler processes
    pkill -P "$socat_pid" 2>/dev/null
    wait "$socat_pid" 2>/dev/null
    # Remove any remaining FIFOs and markers
    rm -rf "$relay_dir"
    log_ok "Relay stopped"
    sleep 1
}

#=============================================================================
# IN-CALL SESSION — PTT VOICE LOOP
#=============================================================================

# Draw the call header (reusable for redraw after settings)
draw_call_header() {
    local _remote="${1:-}"
    local _rcipher="${2:-}"
    clear >&2
    # Row counter for ANSI cursor positioning (clear sets cursor to row 1)
    local _r=1

    if [ -n "$_remote" ]; then
        echo -e "\n${BOLD}${BG_GREEN}${WHITE} CALL CONNECTED ${NC} ${CYAN}${_remote}${NC}\n" >&2
    else
        echo -e "\n${BOLD}${BG_GREEN}${WHITE} CALL CONNECTED ${NC}\n" >&2
    fi
    _r=4  # \n(row1) + header(row2) + \n(row3) + echo-newline → cursor at row 4

    # Cipher info
    CIPHER_ROW=$_r
    local cipher_upper="$(to_upper "$CIPHER")"
    if [ -f "$DATA_DIR/run/relay_mode_$$" ]; then
        # Relay mode — no remote cipher, show relay indicator
        echo -e "  ${GREEN}●${NC} Local cipher:  ${WHITE}${cipher_upper}${NC}" >&2
        echo -e "  ${CYAN}●${NC} Mode:          ${BOLD}${WHITE}RELAY${NC} ${DIM}(group call)${NC}" >&2
    elif [ -n "$_rcipher" ]; then
        local rcipher_upper="$(to_upper "$_rcipher")"
        if [ "$_rcipher" = "$CIPHER" ]; then
            echo -e "  ${GREEN}●${NC} Local cipher:  ${WHITE}${cipher_upper}${NC}" >&2
            echo -e "  ${GREEN}●${NC} Remote cipher: ${WHITE}${rcipher_upper}${NC}" >&2
        else
            echo -e "  ${RED}●${NC} Local cipher:  ${WHITE}${cipher_upper}${NC}" >&2
            echo -e "  ${RED}●${NC} Remote cipher: ${WHITE}${rcipher_upper}${NC}" >&2
        fi
    else
        echo -e "  ${GREEN}●${NC} Local cipher:  ${WHITE}${cipher_upper}${NC}" >&2
        echo -e "  ${DIM}●${NC} Remote cipher: ${DIM}waiting...${NC}" >&2
    fi
    _r=$((_r + 2))

    # Snowflake bridge info
    if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        local tor_log="$TOR_DIR/tor.log"
        echo "" >&2; _r=$((_r + 1))
        echo -e "  ${TOR_PURPLE}●${NC} ${BOLD}Snowflake bridge${NC}" >&2; _r=$((_r + 1))
        if [ -f "$tor_log" ]; then
            local bridge_line=""
            bridge_line=$(grep "new bridge descriptor" "$tor_log" 2>/dev/null | tail -1 || true)
            if [ -n "$bridge_line" ]; then
                local bridge_name=""
                bridge_name=$(echo "$bridge_line" | sed -n "s/.*new bridge descriptor '\([^']*\)'.*/\1/p" || true)
                local bridge_fp=""
                bridge_fp=$(echo "$bridge_line" | sed -n 's/.*(\(fresh\|stale\)): \(.*\)/\2/p' || true)
                if [ -n "$bridge_name" ]; then
                    local fp_display="$bridge_fp"
                    if [ ${#fp_display} -gt 40 ]; then
                        fp_display="${fp_display:0:40}..."
                    fi
                    echo -e "    ${DIM}descriptor:${NC} ${WHITE}${bridge_name}${NC} ${DIM}— ${fp_display}${NC}" >&2
                    _r=$((_r + 1))
                fi
            fi
            local proxy_line=""
            proxy_line=$(grep 'Managed proxy.*snowflake' "$tor_log" 2>/dev/null | tail -1 || true)
            if [ -n "$proxy_line" ]; then
                if echo "$proxy_line" | grep -q "connected"; then
                    echo -e "    ${DIM}transport:${NC}  ${GREEN}connected${NC}" >&2
                else
                    echo -e "    ${DIM}transport:${NC}  ${YELLOW}connecting...${NC}" >&2
                fi
                _r=$((_r + 1))
            fi
        fi
    fi

    # Circuit hop display (vertical)
    CIRCUIT_START_ROW=0
    CIRCUIT_HOP_COUNT=0
    if [ "$SHOW_CIRCUIT" -eq 1 ]; then
        local _hop_data
        _hop_data=$(get_circuit_hops 2>/dev/null) || true
        if [ -n "$_hop_data" ]; then
            echo "" >&2; _r=$((_r + 1))
            echo -e "  ${TOR_PURPLE}●${NC} ${BOLD}Circuit${NC}" >&2; _r=$((_r + 1))
            CIRCUIT_START_ROW=$_r
            local _hop_i=0 _hop_total
            _hop_total=$(echo "$_hop_data" | wc -l)
            while IFS='|' read -r _hname _hcountry; do
                _hop_i=$((_hop_i + 1))
                local _hlabel="Relay"
                [ $_hop_i -eq 1 ] && _hlabel="Guard"
                [ $_hop_i -eq $_hop_total ] && _hlabel="Rendezvous"
                printf '    \033[2m%-13s\033[0m \033[1;37m%s\033[0m \033[2m(%s)\033[0m\n' "${_hlabel}:" "$_hname" "$_hcountry" >&2
                _r=$((_r + 1))
            done <<< "$_hop_data"
            CIRCUIT_HOP_COUNT=$_hop_i
        fi
    fi

    echo "" >&2; _r=$((_r + 1))

    # Static placeholders — updated in-place via ANSI positioning
    echo -e "  ${DIM}Last sent:  --${NC}" >&2
    SENT_INFO_ROW=$_r
    _r=$((_r + 1))

    echo -e "  ${DIM}Last recv:  --${NC}" >&2
    RECV_INFO_ROW=$_r
    _r=$((_r + 1))

    if [ -f "$DATA_DIR/run/relay_mode_$$" ]; then
        local _cached_gc=""
        [ -f "$DATA_DIR/run/group_count_$$" ] && _cached_gc=$(cat "$DATA_DIR/run/group_count_$$" 2>/dev/null)
        if [ -n "$_cached_gc" ]; then
            echo -e "  ${DIM}Group:      ${NC}${WHITE}${_cached_gc} callers${NC}" >&2
        else
            echo -e "  ${DIM}Group:      ${NC}${WHITE}connecting...${NC}" >&2
        fi
    else
        echo -e "  ${DIM}Remote:     ${NC}${GREEN}Idle${NC}" >&2
    fi
    REMOTE_STATUS_ROW=$_r
    _r=$((_r + 1))

    echo "" >&2; _r=$((_r + 1))

    # Static status bar
    if [ $IS_TERMUX -eq 1 ]; then
        echo -ne "  ${GREEN}${BOLD} Ready ${NC} ${DIM}[SPACE]=Talk [T]=Chat [S]=Settings [Q]=Hang up${NC}   " >&2
    else
        echo -ne "  ${GREEN}${BOLD} Ready ${NC} ${DIM}[SPACE]=Hold to Talk [T]=Chat [S]=Settings [Q]=Hang up${NC}   " >&2
    fi
    STATUS_ROW=$_r

    echo "" >&2
    echo "" >&2
}

# Refresh circuit hops in-place during a call (called from background loop)
refresh_circuit_display() {
    [ "$SHOW_CIRCUIT" -eq 0 ] && return
    [ "$CIRCUIT_START_ROW" -eq 0 ] && return
    [ "$CIRCUIT_HOP_COUNT" -eq 0 ] && return

    local _hop_data
    _hop_data=$(get_circuit_hops 2>/dev/null) || return
    [ -z "$_hop_data" ] && return

    local _hop_i=0 _hop_total
    _hop_total=$(echo "$_hop_data" | wc -l)

    printf '\033[s' >&2  # save cursor
    while IFS='|' read -r _hname _hcountry; do
        _hop_i=$((_hop_i + 1))
        [ $_hop_i -gt $CIRCUIT_HOP_COUNT ] && break  # don't overflow allocated rows
        local _hlabel="Relay"
        [ $_hop_i -eq 1 ] && _hlabel="Guard"
        [ $_hop_i -eq $_hop_total ] && _hlabel="Rendezvous"
        local _row=$((CIRCUIT_START_ROW + _hop_i - 1))
        printf '\033[%d;1H\033[K' "$_row" >&2
        printf '    \033[2m%-13s\033[0m \033[1;37m%s\033[0m \033[2m(%s)\033[0m' "${_hlabel}:" "$_hname" "$_hcountry" >&2
    done <<< "$_hop_data"
    printf '\033[u' >&2  # restore cursor
}

# Background circuit refresh loop (60-second interval)
start_circuit_refresh() {
    [ "$SHOW_CIRCUIT" -eq 0 ] && return
    [ "$CIRCUIT_START_ROW" -eq 0 ] && return
    (
        while [ -f "$CONNECTED_FLAG" ]; do
            sleep 60
            [ -f "$CONNECTED_FLAG" ] || break
            refresh_circuit_display
        done
    ) &
    CIRCUIT_REFRESH_PID=$!
}

in_call_session() {
    local recv_pipe="$1"
    local send_pipe="$2"
    local known_remote="${3:-}"
    local spinner_pid="${4:-}"

    CALL_ACTIVE=1
    rm -f "$PTT_FLAG"
    mkdir -p "$AUDIO_DIR"

    # Start volume-down double-tap monitor (Termux only)
    VOL_MON_PID=""
    local vol_trigger_file="$DATA_DIR/run/vol_ptt_trigger_$$"
    rm -f "$vol_trigger_file"
    start_vol_monitor "$vol_trigger_file"

    # Write cipher to runtime file so subshells can track changes
    echo "$CIPHER" > "$CIPHER_RUNTIME_FILE"
    echo "$HMAC_AUTH" > "$HMAC_RUNTIME_FILE"
    : > "$NONCE_LOG_FILE"

    # Open persistent file descriptors for the pipes
    exec 3< "$recv_pipe"  # fd 3 = read from remote
    exec 4> "$send_pipe"  # fd 4 = write to remote

    # Send our onion address and cipher for handshake
    local my_onion
    my_onion=$(get_onion)
    if [ -n "$my_onion" ]; then
        proto_send "ID:${my_onion}"
    fi
    proto_send "CIPHER:${CIPHER}"

    # Remote address and cipher (populated by handshake / receive loop)
    local remote_id_file="$DATA_DIR/run/remote_id_$$"
    local remote_cipher_file="$DATA_DIR/run/remote_cipher_$$"
    local relay_flag_file="$DATA_DIR/run/relay_mode_$$"
    rm -f "$remote_id_file" "$remote_cipher_file" "$relay_flag_file"

    # If we don't know the remote address yet (listener), wait briefly for handshake
    local remote_display="$known_remote"
    local remote_cipher=""
    if [ -z "$remote_display" ]; then
        # Read first line — could be RELAY:, ID:, or CIPHER:
        local first_line=""
        if read -r -t 3 first_line <&3 2>/dev/null; then
            # Check raw line for relay greeting (not HMAC-signed)
            if [[ "$first_line" == RELAY:* ]]; then
                touch "$relay_flag_file"
                remote_display="RELAY (group)"
                echo "$remote_display" > "$remote_id_file"
            else
                first_line=$(proto_verify "$first_line") || first_line=""
                if [[ "$first_line" == ID:* ]]; then
                    remote_display="${first_line#ID:}"
                    echo "$remote_display" > "$remote_id_file"
                elif [[ "$first_line" == CIPHER:* ]]; then
                    remote_cipher="${first_line#CIPHER:}"
                fi
            fi
        fi
    else
        # We know the remote (caller side) — check for RELAY: greeting
        local peek_line=""
        if read -r -t 2 peek_line <&3 2>/dev/null; then
            # Check raw line for relay greeting (not HMAC-signed)
            if [[ "$peek_line" == RELAY:* ]]; then
                touch "$relay_flag_file"
                remote_display="RELAY (group)"
            else
                peek_line=$(proto_verify "$peek_line") || peek_line=""
                if [[ "$peek_line" == CIPHER:* ]]; then
                    remote_cipher="${peek_line#CIPHER:}"
                fi
            fi
        fi
    fi

    # Try to read CIPHER: line (skip in relay mode — no cipher exchange)
    if [ -z "$remote_cipher" ] && [ ! -f "$relay_flag_file" ]; then
        local cline=""
        if read -r -t 1 cline <&3 2>/dev/null; then
            cline=$(proto_verify "$cline") || cline=""
            if [[ "$cline" == CIPHER:* ]]; then
                remote_cipher="${cline#CIPHER:}"
            fi
        fi
    fi

    # Save remote cipher for later redraws
    if [ -n "$remote_cipher" ]; then
        echo "$remote_cipher" > "$remote_cipher_file"
    fi

    # Kill connecting spinner and draw call header
    if [ -n "$spinner_pid" ]; then
        kill "$spinner_pid" 2>/dev/null || true
        wait "$spinner_pid" 2>/dev/null || true
    fi
    draw_call_header "$remote_display" "$remote_cipher"

    # Start periodic circuit refresh
    CIRCUIT_REFRESH_PID=""
    start_circuit_refresh

    # Start receive handler in background
    # Protocol: ID:<onion>, PTT_START, PTT_STOP, PING,
    #           or "AUDIO:<base64_encoded_encrypted_opus>"
    (
        while [ -f "$CONNECTED_FLAG" ]; do
            local line=""
            if read -r line <&3 2>/dev/null; then
                # Handle relay protocol messages BEFORE proto_verify
                # (these are sent by the relay, never HMAC-signed)
                if [[ "$line" == GROUP:* ]]; then
                    if [ ! -f "$relay_flag_file" ]; then
                        touch "$relay_flag_file"
                    fi
                    local _gcount
                    _gcount=$(sanitize_str "${line#GROUP:}")
                    # Cache count for header redraws (e.g., after mid-call settings)
                    echo "$_gcount" > "$DATA_DIR/run/group_count_$$"
                    printf '\033[s' >&2
                    printf '\033[%d;1H\033[K' "$REMOTE_STATUS_ROW" >&2
                    printf '  \033[2mGroup:      \033[0m\033[1;37m%s callers\033[0m' "$_gcount" >&2
                    printf '\033[u' >&2
                    continue
                fi
                if [[ "$line" == RELAY:* ]]; then
                    [ ! -f "$relay_flag_file" ] && touch "$relay_flag_file"
                    continue
                fi
                line=$(proto_verify "$line") || continue
                case "$line" in
                    PTT_START)
                        printf '\033[s' >&2
                        printf '\033[%d;1H\033[K' "$REMOTE_STATUS_ROW" >&2
                        printf '  \033[2mRemote:     \033[0m\033[1;31m● Recording\033[0m' >&2
                        printf '\033[u' >&2
                        if [ "$PTT_CHIME" != "off" ]; then
                            play_chime &
                        fi
                        ;;
                    PTT_STOP)
                        printf '\033[s' >&2
                        printf '\033[%d;1H\033[K' "$REMOTE_STATUS_ROW" >&2
                        printf '  \033[2mRemote:     \033[0m\033[1;32mIdle\033[0m' >&2
                        printf '\033[u' >&2
                        ;;
                    PING)
                        # silent — no display update
                        ;;
                    ID:*)
                        # Caller ID received (save but don't print — already in header)
                        local remote_addr="${line#ID:}"
                        echo "$remote_addr" > "$remote_id_file"
                        ;;
                    CIPHER:*)
                        # Remote side sent/changed their cipher — save and update display
                        local rc
                        rc=$(sanitize_str "${line#CIPHER:}")
                        echo "$rc" > "$remote_cipher_file" 2>/dev/null || true
                        # Read current local cipher from runtime file
                        local _cur_cipher="$CIPHER"
                        [ -f "$CIPHER_RUNTIME_FILE" ] && _cur_cipher=$(cat "$CIPHER_RUNTIME_FILE")
                        local _cu="$(to_upper "$_cur_cipher")"
                        local _ru="$(to_upper "$rc")"
                        # Update cipher lines in-place using ANSI cursor positioning (rows 4-5)
                        local _dot_color
                        if [ "$rc" = "$_cur_cipher" ]; then
                            _dot_color="$GREEN"
                        else
                            _dot_color="$RED"
                        fi
                        printf '\033[s' >&2
                        printf '\033[%d;1H\033[K' "$CIPHER_ROW" >&2
                        printf '  %b●%b Local cipher:  %b%s%b\r\n' "$_dot_color" "$NC" "$WHITE" "$_cu" "$NC" >&2
                        printf '\033[K' >&2
                        printf '  %b●%b Remote cipher: %b%s%b' "$_dot_color" "$NC" "$WHITE" "$_ru" "$NC" >&2
                        printf '\033[u' >&2
                        ;;
                    MSG:*)
                        # Encrypted text message received
                        local msg_b64="${line#MSG:}"
                        local _mid=$(uid)
                        local msg_enc="$AUDIO_DIR/msg_enc_${_mid}.tmp"
                        local msg_dec="$AUDIO_DIR/msg_dec_${_mid}.tmp"
                        echo "$msg_b64" | base64 -d > "$msg_enc" 2>/dev/null || true
                        if [ -s "$msg_enc" ]; then
                            if decrypt_file "$msg_enc" "$msg_dec" 2>/dev/null; then
                                local msg_text
                                msg_text=$(cat "$msg_dec" 2>/dev/null)
                                echo -e "\n  ${MAGENTA}${BOLD}[MSG]${NC} ${WHITE}${msg_text}${NC}" >&2
                            fi
                        fi
                        rm -f "$msg_enc" "$msg_dec" 2>/dev/null
                        ;;
                    AUDIO:*)
                        # Extract base64 data, decode, decrypt, play
                        local b64_data="${line#AUDIO:}"
                        local _rid=$(uid)
                        local enc_file="$AUDIO_DIR/recv_enc_${_rid}.tmp"
                        local dec_file="$AUDIO_DIR/recv_dec_${_rid}.tmp"

                        echo "$b64_data" | base64 -d > "$enc_file" 2>/dev/null || true
                        if [ -s "$enc_file" ]; then
                            if decrypt_file "$enc_file" "$dec_file" 2>/dev/null; then
                                # Calculate recv size
                                local _enc_sz=0
                                _enc_sz=$(file_size "$enc_file")
                                local _sz_kb=$(( _enc_sz * 10 / 1024 ))
                                local _sz_w=$(( _sz_kb / 10 ))
                                local _sz_f=$(( _sz_kb % 10 ))
                                local _recv_info="${_sz_w}.${_sz_f}KB"
                                # Update static "Last recv" row via ANSI positioning
                                printf '\033[s' >&2
                                printf '\033[%d;1H\033[K' "$RECV_INFO_ROW" >&2
                                printf '  \033[2mLast recv:  \033[0m\033[1;37m%s\033[0m' "$_recv_info" >&2
                                printf '\033[%d;1H\033[K' "$REMOTE_STATUS_ROW" >&2
                                printf '  \033[2mRemote:     \033[0m\033[1;32mIdle\033[0m' >&2
                                printf '\033[u' >&2

                                play_chunk "$dec_file" 2>/dev/null || true
                            fi
                        fi
                        rm -f "$enc_file" "$dec_file" 2>/dev/null
                        ;;
                    HANGUP)
                        # In relay mode, ignore HANGUP (others may still be connected)
                        if [ -f "$relay_flag_file" ]; then
                            continue
                        fi
                        # Direct call — remote party hung up
                        echo -e "\r\n\r\n  ${YELLOW}${BOLD}Remote party hung up.${NC}" >&2
                        rm -f "$CONNECTED_FLAG"
                        break
                        ;;
                esac
            else
                # Pipe closed or error — connection lost
                echo -e "\r\n\r\n  ${RED}${BOLD}Connection lost.${NC}" >&2
                rm -f "$CONNECTED_FLAG"
                break
            fi
        done
    ) &
    local recv_pid=$!
    save_pid "recv_loop" "$recv_pid"

    # Main PTT input loop
    ORIGINAL_STTY=$(stty -g)
    stty raw -echo -icanon min 0 time 1

    REC_PID=""
    REC_FILE=""
    LAST_SENT_INFO=""
    local ptt_active=0

    # Status bar is already drawn by draw_call_header

    while [ -f "$CONNECTED_FLAG" ]; do
        local key=""
        # Check volume-down double-tap trigger
        if [ -f "$vol_trigger_file" ]; then
            rm -f "$vol_trigger_file"
            key="$PTT_KEY"  # simulate PTT key press
        else
            key=$(dd bs=1 count=1 2>/dev/null) || true
        fi

        if [ "$key" = "$PTT_KEY" ]; then
            if [ $IS_TERMUX -eq 1 ]; then
                # TERMUX: Toggle mode
                if [ $ptt_active -eq 0 ]; then
                    ptt_active=1
                    printf '\033[s' >&2; printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
                    printf '  \033[41;1;37m \u25cf RECORDING \033[0m \033[2m[SPACE]=Send\033[0m        ' >&2
                    printf '\033[u' >&2
                    proto_send "PTT_START"
                    start_recording
                else
                    ptt_active=0
                    stop_and_send
                    proto_send "PTT_STOP"
                    # Update Last sent + status bar
                    printf '\033[s' >&2
                    printf '\033[%d;1H\033[K' "$SENT_INFO_ROW" >&2
                    printf '  \033[2mLast sent:  \033[0m\033[1;37m%s\033[0m' "$LAST_SENT_INFO" >&2
                    printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
                    printf '  \033[1;32m Sent! \033[0m \033[2m[SPACE]=Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
                    printf '\033[u' >&2
                fi
            else
                # LINUX: Hold-to-talk
                if [ $ptt_active -eq 0 ]; then
                    ptt_active=1
                    printf '\033[s' >&2; printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
                    printf '  \033[41;1;37;5m \u25cf RECORDING \033[0m                ' >&2
                    printf '\033[u' >&2
                    stty time 5  # longer timeout to span keyboard repeat delay
                    proto_send "PTT_START"
                    start_recording
                fi
            fi

        elif [ "$key" = "q" ] || [ "$key" = "Q" ]; then
            # If recording, cancel it
            if [ $ptt_active -eq 1 ] && [ -n "$REC_PID" ]; then
                if [ $IS_TERMUX -eq 1 ]; then
                    termux-microphone-record -q &>/dev/null || true
                fi
                kill "$REC_PID" 2>/dev/null || true
                wait "$REC_PID" 2>/dev/null || true
                rm -f "$REC_FILE" 2>/dev/null
                REC_PID=""
                REC_FILE=""
            fi
            echo -e "\r\n${YELLOW}Hanging up...${NC}" >&2
            proto_send "HANGUP"
            rm -f "$PTT_FLAG" "$CONNECTED_FLAG"
            break

        elif [ -z "$key" ]; then
            # No key pressed (timeout) — on Linux, release = stop and send
            if [ $IS_TERMUX -eq 0 ] && [ $ptt_active -eq 1 ]; then
                stty time 1  # restore fast timeout for key detection
                ptt_active=0
                stop_and_send
                proto_send "PTT_STOP"
                # Update Last sent + status bar
                printf '\033[s' >&2
                printf '\033[%d;1H\033[K' "$SENT_INFO_ROW" >&2
                printf '  \033[2mLast sent:  \033[0m\033[1;37m%s\033[0m' "$LAST_SENT_INFO" >&2
                printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
                printf '  \033[1;32m Sent! \033[0m \033[2m[SPACE]=Hold to Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
                printf '\033[u' >&2
            fi

        elif [ "$key" = "t" ] || [ "$key" = "T" ]; then
            # Text chat mode
            # Switch to cooked mode for text input
            stty "$ORIGINAL_STTY" 2>/dev/null || stty sane
            echo "" >&2
            echo -ne "  ${CYAN}${BOLD}MSG>${NC} " >&2
            local chat_msg=""
            read -r chat_msg
            if [ -n "$chat_msg" ]; then
                # Encrypt and send
                local _cid=$(uid)
                local chat_plain="$AUDIO_DIR/chat_${_cid}.tmp"
                local chat_enc="$AUDIO_DIR/chat_enc_${_cid}.tmp"
                echo -n "$chat_msg" > "$chat_plain"
                encrypt_file "$chat_plain" "$chat_enc" 2>/dev/null
                if [ -s "$chat_enc" ]; then
                    local chat_b64
                    chat_b64=$(base64 < "$chat_enc" | tr -d '\n')
                    proto_send "MSG:${chat_b64}"
                    echo -e "  ${DIM}[you] ${chat_msg}${NC}" >&2
                fi
                rm -f "$chat_plain" "$chat_enc" 2>/dev/null
            fi
            # Switch back to raw mode for PTT
            stty raw -echo -icanon min 0 time 1
            # Restore status bar to Ready
            printf '\033[s' >&2
            printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
            if [ $IS_TERMUX -eq 1 ]; then
                printf '  \033[1;32m Ready \033[0m \033[2m[SPACE]=Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
            else
                printf '  \033[1;32m Ready \033[0m \033[2m[SPACE]=Hold to Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
            fi
            printf '\033[u' >&2

        elif [ "$key" = "s" ] || [ "$key" = "S" ]; then
            # Mid-call settings
            stty "$ORIGINAL_STTY" 2>/dev/null || stty sane
            # Flush any leftover raw mode input
            read -r -t 0.1 -n 10000 2>/dev/null || true
            settings_menu
            # Redraw call header and switch back to raw mode
            local _rd="" _rc=""
            [ -f "$remote_id_file" ] && _rd=$(cat "$remote_id_file" 2>/dev/null)
            [ -z "$_rd" ] && _rd="$known_remote"
            [ -f "$remote_cipher_file" ] && _rc=$(cat "$remote_cipher_file" 2>/dev/null)
            draw_call_header "$_rd" "$_rc"
            stty raw -echo -icanon min 0 time 1
            # Restore status bar to Ready (header was redrawn, STATUS_ROW is fresh)
            printf '\033[s' >&2
            printf '\033[%d;1H\033[K' "$STATUS_ROW" >&2
            if [ $IS_TERMUX -eq 1 ]; then
                printf '  \033[1;32m Ready \033[0m \033[2m[SPACE]=Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
            else
                printf '  \033[1;32m Ready \033[0m \033[2m[SPACE]=Hold to Talk [T]=Chat [S]=Settings [Q]=Hang up\033[0m   ' >&2
            fi
            printf '\033[u' >&2
        fi
    done

    echo -e "\n${BOLD}${RED} CALL ENDED ${NC}\n"
}

#=============================================================================
# AUDIO TEST (LOOPBACK)
#=============================================================================

test_audio() {
    echo -e "\n${BOLD}${CYAN}═══ Audio Loopback Test ═══${NC}\n"

    # Check dependencies first
    local missing=0
    local audio_deps=(opusenc opusdec)
    if [ $IS_TERMUX -eq 1 ]; then
        audio_deps+=(termux-microphone-record ffmpeg)
    elif [ $IS_MACOS -eq 1 ]; then
        audio_deps+=(rec play)
    fi
    for dep in "${audio_deps[@]}"; do
        if ! check_dep "$dep"; then
            log_err "$dep not found — run option 7 to install dependencies first"
            missing=1
        fi
    done
    # Linux needs either the PulseAudio/PipeWire tools (parec/pacat) or ALSA (arecord/aplay)
    if [ $IS_TERMUX -eq 0 ] && [ $IS_MACOS -eq 0 ]; then
        if ! { check_dep parec && check_dep pacat; } && \
           ! { check_dep arecord && check_dep aplay; }; then
            log_err "No audio tools found — install pulseaudio-utils/libpulse or alsa-utils (option 7)"
            missing=1
        fi
    fi
    if [ $missing -eq 1 ]; then
        return 1
    fi

    echo -e "  ${DIM}This will record 3 seconds of audio, encode it with Opus,${NC}"
    echo -e "  ${DIM}and play it back to verify your audio pipeline works.${NC}\n"

    if [ $IS_TERMUX -eq 0 ] && [ $IS_MACOS -eq 0 ]; then
        echo -e "  ${DIM}Audio backend: $(detect_audio_backend)${NC}\n"
    fi

    mkdir -p "$AUDIO_DIR"

    # Step 1: Record
    echo -ne "  ${YELLOW}● Recording for 3 seconds... speak now!${NC} "
    local _tid=$(uid)
    local raw_file="$AUDIO_DIR/test_${_tid}.tmp"
    audio_record "$raw_file" 3
    echo -e "${GREEN}done${NC}"

    if [ ! -s "$raw_file" ]; then
        log_err "Recording failed — check your microphone"
        return 1
    fi

    local raw_size
    raw_size=$(file_size "$raw_file")
    echo -e "  ${DIM}Recorded $raw_size bytes of raw audio${NC}"

    # Step 1b: Play the RAW recording directly (bypasses Opus/encryption).
    # This isolates capture vs. playback: if you hear yourself here but not in
    # the final step, the problem is in the codec path; if you hear nothing here,
    # it's a microphone/capture or speaker/playback issue (see issue #2).
    echo -ne "  ${YELLOW}● Playing raw recording (pre-codec)...${NC} "
    audio_play "$raw_file" "$SAMPLE_RATE"
    echo -e "${GREEN}done${NC}"

    # Step 2: Encode with Opus
    echo -ne "  ${YELLOW}● Encoding with Opus at ${OPUS_BITRATE}kbps...${NC} "
    local opus_file="$AUDIO_DIR/test_o_${_tid}.tmp"
    opusenc --raw --raw-rate "$SAMPLE_RATE" --raw-chan 1 \
        --bitrate "$OPUS_BITRATE" --framesize "$OPUS_FRAMESIZE" \
        --speech --quiet \
        "$raw_file" "$opus_file" 2>/dev/null
    echo -e "${GREEN}done${NC}"

    if [ ! -s "$opus_file" ]; then
        log_err "Opus encoding failed"
        rm -f "$raw_file"
        return 1
    fi

    local opus_size
    opus_size=$(file_size "$opus_file")
    echo -e "  ${DIM}Opus size: $opus_size bytes (compression ratio: $((raw_size / opus_size))x)${NC}"

    # Step 3: Encrypt + Decrypt round-trip (if secret is set)
    if [ -n "$SHARED_SECRET" ]; then
        echo -ne "  ${YELLOW}● Encrypting and decrypting...${NC} "
        local enc_file="$AUDIO_DIR/test_enc_${_tid}.tmp"
        local dec_file="$AUDIO_DIR/test_dec_${_tid}.tmp"
        encrypt_file "$opus_file" "$enc_file"
        decrypt_file "$enc_file" "$dec_file"

        if cmp -s "$opus_file" "$dec_file"; then
            echo -e "${GREEN}encryption round-trip OK${NC}"
        else
            echo -e "${RED}encryption round-trip FAILED${NC}"
        fi
        rm -f "$enc_file"
        opus_file="$dec_file"
    fi

    # Step 4: Decode and play
    echo -ne "  ${YELLOW}● Playing back...${NC} "
    play_chunk "$opus_file"
    echo -e "${GREEN}done${NC}"

    rm -f "$raw_file" "$opus_file" "$AUDIO_DIR/test_dec_${_tid}.tmp" 2>/dev/null

    echo -e "\n  ${GREEN}${BOLD}Audio test complete!${NC}"
    echo -e "  ${DIM}If you heard your voice, the pipeline is working.${NC}\n"
}

#=============================================================================
# SHOW STATUS
#=============================================================================

show_status() {
    echo -e "\n${BOLD}${CYAN}═══ Status ═══${NC}\n"

    # Tor status
    if [ -n "$TOR_PID" ] && kill -0 "$TOR_PID" 2>/dev/null; then
        echo -e "  ${GREEN}●${NC} Tor running (PID $TOR_PID)"
        local onion
        onion=$(get_onion)
        if [ -n "$onion" ]; then
            echo -e "  ${BOLD}${WHITE}  Address: ${onion}${NC}"
        fi
    else
        echo -e "  ${RED}●${NC} Tor not running"
    fi

    # Secret
    if [ -n "$SHARED_SECRET" ]; then
        echo -e "  ${GREEN}●${NC} Shared secret set"
    else
        echo -e "  ${RED}●${NC} No shared secret (set one before calling)"
    fi

    # Audio
    local _audio_ok=0
    if check_dep opusenc; then
        if [ $IS_MACOS -eq 1 ]; then
            check_dep rec && _audio_ok=1
        elif [ $IS_TERMUX -eq 1 ]; then
            check_dep termux-microphone-record && _audio_ok=1
        else
            { check_dep parec && check_dep pacat; } && _audio_ok=1
            { check_dep arecord && check_dep aplay; } && _audio_ok=1
        fi
    fi
    if [ "$_audio_ok" -eq 1 ]; then
        echo -e "  ${GREEN}●${NC} Audio pipeline ready"
    else
        echo -e "  ${RED}●${NC} Audio dependencies missing"
    fi

    # Snowflake
    if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        if check_dep snowflake-client; then
            echo -e "  ${GREEN}●${NC} Snowflake bridge enabled"
        else
            echo -e "  ${YELLOW}●${NC} Snowflake enabled (client not installed)"
        fi
    else
        echo -e "  ${DIM}●${NC} Snowflake bridge disabled"
    fi

    # Config
    echo -e "\n  ${DIM}Listen port:  $LISTEN_PORT${NC}"
    echo -e "  ${DIM}SOCKS port:   $TOR_SOCKS_PORT${NC}"
    echo -e "  ${DIM}Cipher:       $CIPHER${NC}"
    echo -e "  ${DIM}Opus bitrate: ${OPUS_BITRATE}kbps${NC}"
    echo -e "  ${DIM}Opus frame:   ${OPUS_FRAMESIZE}ms${NC}"
    echo -e "  ${DIM}PTT key:      [SPACEBAR]${NC}"
    echo ""
}

#=============================================================================
# PTT CHIME
#=============================================================================

CUSTOM_CHIME_FILE="$DATA_DIR/custom_chime.tmp"

play_chime() {
    case "$PTT_CHIME" in
        tone)   play -qn synth 0.15 sine 880 vol 0.3 2>/dev/null ;;
        double) play -qn synth 0.08 sine 880 vol 0.3 2>/dev/null; play -qn synth 0.08 sine 1100 vol 0.3 2>/dev/null ;;
        chirp)  play -qn synth 0.2 sine 600:1200 vol 0.3 2>/dev/null ;;
        ding)   play -qn synth 0.3 sine 1047 fade l 0 0.3 0.2 vol 0.3 2>/dev/null ;;
        click)  play -qn synth 0.03 noise vol 0.2 2>/dev/null ;;
        custom)
            if [ -f "$CUSTOM_CHIME_FILE" ]; then
                play -q -t raw -r "$SAMPLE_RATE" -e signed -b 16 -c 1 "$CUSTOM_CHIME_FILE" 2>/dev/null
            else
                play -qn synth 0.15 sine 880 vol 0.3 2>/dev/null
            fi
            ;;
    esac
}

settings_chime() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ PTT Chime ═══${NC}\n"
        echo -e "  ${DIM}Plays a notification sound when the remote party starts recording.${NC}\n"

        local current="$PTT_CHIME"
        local custom_status=""
        if [ -f "$CUSTOM_CHIME_FILE" ]; then
            custom_status=" ${GREEN}(recorded)${NC}"
        fi

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Tone        ${DIM}— short beep${NC}$([ "$current" = "tone" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Double      ${DIM}— two quick beeps${NC}$([ "$current" = "double" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Chirp       ${DIM}— ascending sweep${NC}$([ "$current" = "chirp" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Ding        ${DIM}— bell with decay${NC}$([ "$current" = "ding" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Click       ${DIM}— short percussive${NC}$([ "$current" = "click" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}6${NC} ${CYAN}│${NC} Custom${custom_status}$([ "$current" = "custom" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}7${NC} ${CYAN}│${NC} Record custom chime ${DIM}(2 seconds)${NC}"
        echo -e "  ${BOLD}${WHITE}8${NC} ${CYAN}│${NC} ${DIM}Off${NC}$([ "$current" = "off" ] && echo "  ${GREEN}◄${NC}")"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _cc

        case "$_cc" in
            1) PTT_CHIME="tone";   save_config; log_ok "Chime set to: tone";   play_chime; sleep 1 ;;
            2) PTT_CHIME="double"; save_config; log_ok "Chime set to: double"; play_chime; sleep 1 ;;
            3) PTT_CHIME="chirp";  save_config; log_ok "Chime set to: chirp";  play_chime; sleep 1 ;;
            4) PTT_CHIME="ding";   save_config; log_ok "Chime set to: ding";   play_chime; sleep 1 ;;
            5) PTT_CHIME="click";  save_config; log_ok "Chime set to: click";  play_chime; sleep 1 ;;
            6)
                if [ -f "$CUSTOM_CHIME_FILE" ]; then
                    PTT_CHIME="custom"
                    save_config
                    log_ok "Chime set to: custom"
                    play_chime
                    sleep 1
                else
                    echo -e "\n  ${YELLOW}No custom chime recorded. Use option 7 to record one.${NC}"
                    sleep 2
                fi
                ;;
            7)
                echo -e "\n  ${BOLD}Recording a 2-second custom chime...${NC}"
                echo -e "  ${DIM}Play a sound near the microphone after the countdown.${NC}\n"
                sleep 1
                echo -ne "  3..."
                sleep 1
                echo -ne " 2..."
                sleep 1
                echo -e " 1... ${RED}${BOLD}● REC${NC}"
                audio_record "$CUSTOM_CHIME_FILE" 2
                if [ -s "$CUSTOM_CHIME_FILE" ]; then
                    log_ok "Custom chime recorded!"
                    PTT_CHIME="custom"
                    save_config
                    echo -e "  ${DIM}Playing back...${NC}"
                    sleep 0.5
                    play_chime
                else
                    log_err "Recording failed — no audio captured"
                fi
                sleep 2
                ;;
            0|q|Q)
                return
                ;;
            8)
                PTT_CHIME="off"
                save_config
                log_ok "PTT chime disabled"
                sleep 1
                ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

#=============================================================================
# ALSA DEVICE SETTINGS
#=============================================================================

settings_alsa() {
    [ $IS_MACOS -eq 1 ] && return
    [ $IS_TERMUX -eq 1 ] && return

    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ ALSA Device Settings ═══${NC}\n"
        echo -e "  Current Capture Device:  ${GREEN}${ALSA_DEV_CAPTURE:-default}${NC}"
        echo -e "  Current Playback Device: ${GREEN}${ALSA_DEV_PLAYBACK:-default}${NC}\n"

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Select Capture Device (arecord)"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Select Playback Device (aplay)"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Enter Custom Capture Device Name"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Enter Custom Playback Device Name"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Reset to default"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _ac

        case "$_ac" in
            1)
                clear
                echo -e "\n${BOLD}${CYAN}═══ Select ALSA Capture Device ═══${NC}\n"
                local devs=()
                local idx=1
                # Add default first
                devs+=("default")
                echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} default"
                
                # Parse available devices
                while IFS= read -r dev; do
                    if [ "$dev" != "default" ]; then
                        idx=$((idx + 1))
                        devs+=("$dev")
                        echo -e "  ${BOLD}${WHITE}$idx${NC} ${CYAN}│${NC} $dev"
                    fi
                done < <(arecord -L 2>/dev/null | grep -E '^[^[:space:]]+$')

                echo ""
                echo -ne "  ${BOLD}Select device (1-$idx) or 0 to cancel: ${NC}"
                read -r _dev_sel
                if [[ "$_dev_sel" =~ ^[0-9]+$ ]] && [ "$_dev_sel" -ge 1 ] && [ "$_dev_sel" -le "$idx" ]; then
                    ALSA_DEV_CAPTURE="${devs[$((_dev_sel - 1))]}"
                    save_config
                    log_ok "Capture device set to: $ALSA_DEV_CAPTURE"
                    sleep 1.5
                fi
                ;;
            2)
                clear
                echo -e "\n${BOLD}${CYAN}═══ Select ALSA Playback Device ═══${NC}\n"
                local devs=()
                local idx=1
                # Add default first
                devs+=("default")
                echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} default"

                # Parse available devices
                while IFS= read -r dev; do
                    if [ "$dev" != "default" ]; then
                        idx=$((idx + 1))
                        devs+=("$dev")
                        echo -e "  ${BOLD}${WHITE}$idx${NC} ${CYAN}│${NC} $dev"
                    fi
                done < <(aplay -L 2>/dev/null | grep -E '^[^[:space:]]+$')

                echo ""
                echo -ne "  ${BOLD}Select device (1-$idx) or 0 to cancel: ${NC}"
                read -r _dev_sel
                if [[ "$_dev_sel" =~ ^[0-9]+$ ]] && [ "$_dev_sel" -ge 1 ] && [ "$_dev_sel" -le "$idx" ]; then
                    ALSA_DEV_PLAYBACK="${devs[$((_dev_sel - 1))]}"
                    save_config
                    log_ok "Playback device set to: $ALSA_DEV_PLAYBACK"
                    sleep 1.5
                fi
                ;;
            3)
                echo -ne "\n  ${BOLD}Enter ALSA Capture Device name: ${NC}"
                read -r _custom_dev
                if [ -n "$_custom_dev" ]; then
                    ALSA_DEV_CAPTURE="$_custom_dev"
                    save_config
                    log_ok "Capture device set to: $ALSA_DEV_CAPTURE"
                    sleep 1.5
                fi
                ;;
            4)
                echo -ne "\n  ${BOLD}Enter ALSA Playback Device name: ${NC}"
                read -r _custom_dev
                if [ -n "$_custom_dev" ]; then
                    ALSA_DEV_PLAYBACK="$_custom_dev"
                    save_config
                    log_ok "Playback device set to: $ALSA_DEV_PLAYBACK"
                    sleep 1.5
                fi
                ;;
            5)
                ALSA_DEV_CAPTURE="default"
                ALSA_DEV_PLAYBACK="default"
                save_config
                log_ok "ALSA devices reset to default"
                sleep 1.5
                ;;
            0|q|Q)
                return
                ;;
        esac
    done
}

#=============================================================================
# SETTINGS MENU
#=============================================================================

settings_menu() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Settings ═══${NC}\n"
        echo -e "  ${DIM}Current Opus bitrate: ${NC}${WHITE}${OPUS_BITRATE} kbps${NC}"
        echo -e "  ${DIM}Current Opus frame:   ${NC}${WHITE}${OPUS_FRAMESIZE} ms${NC}"

        local al_label="${RED}disabled${NC}"
        if [ "$AUTO_LISTEN" -eq 1 ]; then
            al_label="${GREEN}enabled${NC}"
        fi
        echo -e "  ${DIM}Auto-listen:          ${NC}${al_label}"

        local ptt_display="SPACE"
        [ "$PTT_KEY" != " " ] && ptt_display="$PTT_KEY"
        echo -e "  ${DIM}PTT key:              ${NC}${WHITE}${ptt_display}${NC}"

        local vfx_display="${VOICE_EFFECT}"
        [ "$vfx_display" = "none" ] && vfx_display="off"
        echo -e "  ${DIM}Voice effect:          ${NC}${WHITE}${vfx_display}${NC}"

        if [ $IS_TERMUX -eq 1 ]; then
            local vp_label="${RED}disabled${NC}"
            if [ "$VOL_PTT" -eq 1 ]; then
                vp_label="${GREEN}enabled${NC}"
            fi
            echo -e "  ${DIM}Volume PTT:            ${NC}${vp_label}  ${DIM}(experimental)${NC}"
        fi

        local circ_label="${RED}disabled${NC}"
        if [ "$SHOW_CIRCUIT" -eq 1 ]; then
            circ_label="${GREEN}enabled${NC}"
        fi
        echo -e "  ${DIM}Circuit display:      ${NC}${circ_label}"

        local hmac_label="${RED}disabled${NC}"
        if [ "$HMAC_AUTH" -eq 1 ]; then
            hmac_label="${GREEN}enabled${NC}"
        fi
        echo -e "  ${DIM}HMAC auth:            ${NC}${hmac_label}"

        local chime_label="${RED}off${NC}"
        if [ "$PTT_CHIME" != "off" ]; then
            chime_label="${GREEN}${PTT_CHIME}${NC}"
        fi
        echo -e "  ${DIM}PTT chime:            ${NC}${chime_label}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Change Opus encoding quality"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Auto-listen (listen for calls automatically once Tor starts)"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Change PTT (push-to-talk) key"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Voice changer"
        if [ $IS_TERMUX -eq 1 ]; then
            echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Volume PTT ${DIM}(double-tap Vol Down to talk, experimental)${NC}"
        fi
        echo -e "  ${BOLD}${WHITE}6${NC} ${CYAN}│${NC} PTT chime ${DIM}(notification sound when remote starts recording)${NC}"
        echo -e "  ${BOLD}${WHITE}7${NC} ${CYAN}│${NC} Tor settings"
        echo -e "  ${BOLD}${WHITE}8${NC} ${CYAN}│${NC} Security"
        if [ $IS_MACOS -eq 0 ] && [ $IS_TERMUX -eq 0 ]; then
            echo -e "  ${BOLD}${WHITE}9${NC} ${CYAN}│${NC} ALSA device settings ${DIM}(select microphone/speakers)${NC}"
        fi
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back to main menu${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r schoice

        case "$schoice" in
            1) settings_opus ;;
            2)
                if [ "$AUTO_LISTEN" -eq 1 ]; then
                    AUTO_LISTEN=0
                    stop_auto_listener
                    log_ok "Auto-listen disabled"
                else
                    AUTO_LISTEN=1
                    log_ok "Auto-listen enabled"
                    start_auto_listener
                fi
                save_config
                sleep 1
                ;;
            3)
                local _pd="SPACE"
                [ "$PTT_KEY" != " " ] && _pd="$PTT_KEY"
                echo -e "\n  ${DIM}Current PTT key: ${NC}${WHITE}${_pd}${NC}"
                echo -ne "  ${BOLD}Press the key you want to use for PTT: ${NC}"
                # Read a single character in raw mode
                local _old_stty
                _old_stty=$(stty -g)
                stty raw -echo
                local _newkey
                _newkey=$(dd bs=1 count=1 2>/dev/null) || true
                stty "$_old_stty"
                if [ -n "$_newkey" ]; then
                    PTT_KEY="$_newkey"
                    save_config
                    local _nd="SPACE"
                    [ "$PTT_KEY" != " " ] && _nd="$PTT_KEY"
                    log_ok "PTT key set to: ${_nd}"
                fi
                sleep 1
                ;;
            4) settings_voice ;;
            5)
                if [ $IS_TERMUX -eq 1 ]; then
                    if [ "$VOL_PTT" -eq 1 ]; then
                        VOL_PTT=0
                        log_ok "Volume PTT disabled"
                    else
                        if ! check_dep jq; then
                            echo ""
                            echo -ne "  ${BOLD}jq is required for Volume PTT. Install now? [Y/n]: ${NC}"
                            read -r _jq_confirm
                            if [ "$_jq_confirm" != "n" ] && [ "$_jq_confirm" != "N" ]; then
                                pkg install -y jq 2>/dev/null || true
                                if ! check_dep jq; then
                                    log_err "jq installation failed — Volume PTT not enabled"
                                    sleep 2
                                    continue
                                fi
                            else
                                echo -e "\n  ${YELLOW}Volume PTT not enabled (jq not installed)${NC}"
                                sleep 2
                                continue
                            fi
                        fi
                        VOL_PTT=1
                        log_ok "Volume PTT enabled (double-tap Vol Down to toggle recording)"
                        echo -e "  ${DIM}Note: Each press will lower your device volume.${NC}"
                        echo -e "  ${DIM}You may want to start with volume at max.${NC}"
                    fi
                    save_config
                    sleep 2
                else
                    echo -e "\n  ${RED}Volume PTT is only available in Termux${NC}"
                    sleep 1
                fi
                ;;
            6) settings_chime ;;
            7) settings_tor ;;
            8) settings_security ;;
            9)
                if [ $IS_MACOS -eq 0 ] && [ $IS_TERMUX -eq 0 ]; then
                    settings_alsa
                else
                    echo -e "\n  ${RED}ALSA settings are only available on Linux${NC}"
                    sleep 1
                fi
                ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_cipher() {
    echo -e "\n${BOLD}${CYAN}═══ Select Encryption Cipher ═══${NC}\n"
    echo -e "  ${DIM}Current: ${NC}${GREEN}${CIPHER}${NC}\n"

    # Curated cipher list ranked from strongest to adequate
    # Only includes ciphers verified to work with openssl enc -pbkdf2
    # Excludes: ECB modes (pattern leakage), DES/RC2/RC4/Blowfish (weak), aliases
    local ciphers=(
        # ── 256-bit (Strongest) ──
        "aes-256-ctr"
        "aes-256-cbc"
        "aes-256-cfb"
        "aes-256-ofb"
        "chacha20"
        "camellia-256-ctr"
        "camellia-256-cbc"
        "aria-256-ctr"
        "aria-256-cbc"
        # ── 192-bit (Strong) ──
        "aes-192-ctr"
        "aes-192-cbc"
        "camellia-192-ctr"
        "camellia-192-cbc"
        "aria-192-ctr"
        "aria-192-cbc"
        # ── 128-bit (Adequate) ──
        "aes-128-ctr"
        "aes-128-cbc"
        "camellia-128-ctr"
        "camellia-128-cbc"
        "aria-128-ctr"
        "aria-128-cbc"
    )

    local total=${#ciphers[@]}

    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Available Ciphers ═══${NC}"
        echo -e "  ${DIM}Current: ${NC}${GREEN}${CIPHER}${NC}"
        echo -e "  ${DIM}${total} ciphers, ranked strongest → adequate${NC}\n"

        local tier=""
        for ((i = 0; i < total; i++)); do
            local num=$((i + 1))
            local c="${ciphers[$i]}"

            # Print tier headers
            if [ $i -eq 0 ]; then
                echo -e "  ${GREEN}${BOLD}── 256-bit (Strongest) ──${NC}"
            elif [ $i -eq 9 ]; then
                echo -e "  ${YELLOW}${BOLD}── 192-bit (Strong) ──${NC}"
            elif [ $i -eq 15 ]; then
                echo -e "  ${WHITE}${BOLD}── 128-bit (Adequate) ──${NC}"
            fi

            if [ "$c" = "$CIPHER" ]; then
                printf "  ${GREEN}${BOLD}%4d${NC} ${CYAN}│${NC} ${GREEN}%-30s ◄ current${NC}\n" "$num" "$c"
            else
                printf "  ${WHITE}${BOLD}%4d${NC} ${CYAN}│${NC} %-30s\n" "$num" "$c"
            fi
        done

        echo ""
        echo -e "  ${DIM}[0] cancel${NC}"
        echo -ne "  ${BOLD}Enter cipher number: ${NC}"
        read -r cinput

        case "$cinput" in
            0|q|Q)
                return
                ;;
            '')
                ;;
            *)
                if [[ "$cinput" =~ ^[0-9]+$ ]] && [ "$cinput" -ge 1 ] && [ "$cinput" -le "$total" ]; then
                    local selected="${ciphers[$((cinput - 1))]}"
                    # Validate that openssl can actually use this cipher
                    if echo "test" | openssl enc -"${selected}" -pbkdf2 -pass pass:test 2>/dev/null | openssl enc -d -"${selected}" -pbkdf2 -pass pass:test &>/dev/null; then
                        CIPHER="$selected"
                        save_config
                        # Update runtime file for live mid-call sync
                        [ -f "$CIPHER_RUNTIME_FILE" ] && echo "$CIPHER" > "$CIPHER_RUNTIME_FILE"
                        # Notify remote side if in a call
                        if [ "$CALL_ACTIVE" -eq 1 ]; then
                            proto_send "CIPHER:${CIPHER}"
                        fi
                        echo -e "\n  ${GREEN}${BOLD}✓${NC} Cipher set to ${WHITE}${BOLD}${CIPHER}${NC}"
                    else
                        echo -e "\n  ${RED}${BOLD}✗${NC} Cipher '${selected}' failed validation — not compatible with stream encryption"
                    fi
                    echo -ne "  ${DIM}Press Enter to continue...${NC}"
                    read -r
                    return
                else
                    echo -e "\n  ${RED}Invalid number${NC}"
                    sleep 1
                fi
                ;;
        esac
    done
}

settings_opus() {
    echo -e "\n${BOLD}${CYAN}═══ Opus Encoding Quality ═══${NC}\n"
    echo -e "  ${DIM}Current bitrate: ${NC}${GREEN}${OPUS_BITRATE} kbps${NC}\n"

    local -a presets=(6 8 12 16 24 32 48 64)
    local -a labels=(
        "6 kbps  — Minimum (very low bandwidth)"
        "8 kbps  — Low (narrowband voice)"
        "12 kbps — Medium-Low (clear voice)"
        "16 kbps — Medium (recommended for Tor)"
        "24 kbps — Medium-High (good quality)"
        "32 kbps — High (wideband voice)"
        "48 kbps — Very High (near-studio)"
        "64 kbps — Maximum (best quality)"
    )

    for ((i = 0; i < ${#presets[@]}; i++)); do
        local num=$((i + 1))
        if [ "${presets[$i]}" = "$OPUS_BITRATE" ]; then
            echo -e "  ${GREEN}${BOLD}${num}${NC} ${CYAN}│${NC} ${GREEN}${labels[$i]} ◄ current${NC}"
        else
            echo -e "  ${BOLD}${WHITE}${num}${NC} ${CYAN}│${NC} ${labels[$i]}"
        fi
    done

    echo -e "  ${BOLD}${WHITE}9${NC} ${CYAN}│${NC} Custom bitrate"
    echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Cancel${NC}"
    echo ""
    echo -ne "  ${BOLD}Select: ${NC}"
    read -r oinput

    case "$oinput" in
        [1-8])
            OPUS_BITRATE=${presets[$((oinput - 1))]}
            save_config
            echo -e "\n  ${GREEN}${BOLD}✓${NC} Opus bitrate set to ${WHITE}${BOLD}${OPUS_BITRATE} kbps${NC}"
            ;;
        9)
            echo -ne "\n  ${BOLD}Enter bitrate (6-510 kbps): ${NC}"
            read -r custom_br
            if [[ "$custom_br" =~ ^[0-9]+$ ]] && [ "$custom_br" -ge 6 ] && [ "$custom_br" -le 510 ]; then
                OPUS_BITRATE=$custom_br
                save_config
                echo -e "\n  ${GREEN}${BOLD}✓${NC} Opus bitrate set to ${WHITE}${BOLD}${OPUS_BITRATE} kbps${NC}"
            else
                echo -e "\n  ${RED}Invalid bitrate. Must be 6–510.${NC}"
            fi
            ;;
        0|q|Q)
            return
            ;;
        *)
            echo -e "\n  ${RED}Invalid choice${NC}"
            ;;
    esac
    echo -ne "  ${DIM}Press Enter to continue...${NC}"
    read -r
}

settings_snowflake() {
    clear
    echo -e "\n${BOLD}${CYAN}═══ Snowflake Bridge ═══${NC}\n"
    echo -e "  ${DIM}Snowflake uses WebRTC proxies to help bypass Tor censorship.${NC}"
    echo -e "  ${DIM}Enable this if Tor is blocked in your region.${NC}\n"

    if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        echo -e "  Status: ${GREEN}${BOLD}ENABLED${NC}"
    else
        echo -e "  Status: ${RED}${BOLD}DISABLED${NC}"
    fi

    if check_dep snowflake-client; then
        echo -e "  Binary: ${GREEN}●${NC} snowflake-client installed"
    else
        echo -e "  Binary: ${RED}●${NC} snowflake-client not installed"
    fi

    echo -e "  ${DIM}Tor manages snowflake-client as a pluggable transport.${NC}"

    echo ""
    if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Disable Snowflake"
    else
        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Enable Snowflake"
    fi
    echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
    echo ""
    echo -ne "  ${BOLD}Select: ${NC}"
    read -r sf_choice

    case "$sf_choice" in
        1)
            if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
                SNOWFLAKE_ENABLED=0
                save_config

                echo -e "\n  ${YELLOW}${BOLD}✓${NC} Snowflake disabled"
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
            else
                # Install if not present
                if ! check_dep snowflake-client; then
                    echo ""
                    echo -ne "  ${BOLD}snowflake-client not installed. Install now? [Y/n]: ${NC}"
                    read -r install_confirm
                    if [ "$install_confirm" != "n" ] && [ "$install_confirm" != "N" ]; then
                        install_snowflake || {
                            echo -ne "  ${DIM}Press Enter to continue...${NC}"
                            read -r
                            return
                        }
                    else
                        echo -e "\n  ${YELLOW}Snowflake not enabled (client not installed)${NC}"
                        echo -ne "  ${DIM}Press Enter to continue...${NC}"
                        read -r
                        return
                    fi
                fi
                SNOWFLAKE_ENABLED=1
                save_config
                echo -e "\n  ${GREEN}${BOLD}✓${NC} Snowflake enabled"
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
            fi
            ;;
        0|q|Q) return ;;
        *)
            echo -e "\n  ${RED}Invalid choice${NC}"
            ;;
    esac
    echo -ne "  ${DIM}Press Enter to continue...${NC}"
    read -r
}

settings_ports() {
    clear
    echo -e "\n${BOLD}${CYAN}═══ Configure Ports ═══${NC}\n"
    echo -e "  ${DIM}Change the listen port and Tor SOCKS port. Both must${NC}"
    echo -e "  ${DIM}be unique per instance if running multiple copies of${NC}"
    echo -e "  ${DIM}TerminalPhone on the same device.${NC}"
    echo ""
    echo -e "  ${DIM}Current listen port: ${NC}${WHITE}${LISTEN_PORT}${NC}  ${DIM}(hidden service \u0026 incoming calls)${NC}"
    echo -e "  ${DIM}Current SOCKS port:  ${NC}${WHITE}${TOR_SOCKS_PORT}${NC}  ${DIM}(Tor proxy for outbound calls)${NC}"
    echo ""

    echo -ne "  ${BOLD}New listen port ${DIM}[${LISTEN_PORT}]${NC}${BOLD}: ${NC}"
    read -r _new_listen
    if [ -n "$_new_listen" ]; then
        if [[ "$_new_listen" =~ ^[0-9]+$ ]] && [ "$_new_listen" -ge 1024 ] && [ "$_new_listen" -le 65535 ]; then
            LISTEN_PORT=$_new_listen
        else
            echo -e "  ${RED}Invalid port (must be 1024–65535). Keeping $LISTEN_PORT.${NC}"
        fi
    fi

    echo -ne "  ${BOLD}New SOCKS port  ${DIM}[${TOR_SOCKS_PORT}]${NC}${BOLD}: ${NC}"
    read -r _new_socks
    if [ -n "$_new_socks" ]; then
        if [[ "$_new_socks" =~ ^[0-9]+$ ]] && [ "$_new_socks" -ge 1024 ] && [ "$_new_socks" -le 65535 ]; then
            if [ "$_new_socks" = "$LISTEN_PORT" ]; then
                echo -e "  ${RED}SOCKS port cannot be the same as listen port. Keeping $TOR_SOCKS_PORT.${NC}"
            else
                TOR_SOCKS_PORT=$_new_socks
            fi
        else
            echo -e "  ${RED}Invalid port (must be 1024–65535). Keeping $TOR_SOCKS_PORT.${NC}"
        fi
    fi

    save_config
    echo ""
    echo -e "  ${GREEN}${BOLD}✓${NC} Ports set — listen: ${WHITE}${LISTEN_PORT}${NC}, SOCKS: ${WHITE}${TOR_SOCKS_PORT}${NC}"
    echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
    echo -ne "  ${DIM}Press Enter to continue...${NC}"
    read -r
}

settings_single_hop() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Single-Hop Mode ═══${NC}\n"

        local sh_label="${RED}disabled${NC}"
        if [ "$SINGLE_HOP" -eq 1 ]; then
            sh_label="${YELLOW}enabled${NC}"
        fi
        echo -e "  ${DIM}Status:${NC} ${sh_label}"
        echo ""

        echo -e "  ${DIM}By default, Tor builds a 3-hop circuit for your hidden${NC}"
        echo -e "  ${DIM}service. This protects your identity but adds latency${NC}"
        echo -e "  ${DIM}— each hop means an extra network round-trip.${NC}"
        echo ""
        echo -e "  ${DIM}Single-hop mode reduces this to 1 hop. Your hidden${NC}"
        echo -e "  ${DIM}service connects directly through a single relay to${NC}"
        echo -e "  ${DIM}the rendezvous point, cutting latency significantly.${NC}"
        echo ""
        echo -e "  ${BOLD}${WHITE}Normal:${NC}     ${DIM}Caller → 3 hops → [RP] ← 3 hops ← You  (6 total)${NC}"
        echo -e "  ${BOLD}${WHITE}Single-hop:${NC} ${DIM}Caller → 3 hops → [RP] ← 1 hop  ← You  (4 total)${NC}"
        echo ""
        echo -e "  ${RED}${BOLD}⚠  TRADEOFFS:${NC}"
        echo -e "  ${RED}•${NC} ${DIM}Your server's real IP is visible to the relay you${NC}"
        echo -e "    ${DIM}connect through. Your anonymity as the listener is${NC}"
        echo -e "    ${DIM}completely gone — the relay knows who is hosting${NC}"
        echo -e "    ${DIM}this hidden service.${NC}"
        echo -e "  ${RED}•${NC} ${DIM}The SOCKS proxy is disabled in this mode. You${NC}"
        echo -e "    ${DIM}cannot make outbound calls — only receive them.${NC}"
        echo -e "    ${DIM}To call someone, disable this and restart Tor.${NC}"
        echo ""
        echo -e "  ${GREEN}•${NC} ${DIM}Callers connecting to you are still fully anonymous${NC}"
        echo -e "    ${DIM}(they still use their own 3-hop circuit).${NC}"
        echo -e "  ${GREEN}•${NC} ${DIM}Noticeably lower latency for voice and chat.${NC}"
        echo ""
        echo -e "  ${YELLOW}Best for: hosting a line others call into, where you${NC}"
        echo -e "  ${YELLOW}don't need to hide your server's location.${NC}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Turn on"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Turn off"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _sh_choice

        case "$_sh_choice" in
            1)
                if [ "$SINGLE_HOP" -eq 1 ]; then
                    log_info "Single-hop mode is already enabled"
                else
                    SINGLE_HOP=1
                    save_config
                    log_ok "Single-hop mode enabled"
                    echo -e "  ${YELLOW}SOCKS proxy will be disabled — outbound calls unavailable.${NC}"
                    echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                fi
                sleep 2
                ;;
            2)
                if [ "$SINGLE_HOP" -eq 0 ]; then
                    log_info "Single-hop mode is already disabled"
                else
                    SINGLE_HOP=0
                    save_config
                    log_ok "Single-hop mode disabled (normal 3-hop anonymity restored)"
                    echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                fi
                sleep 2
                ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_voice() {
    echo -e "\n${BOLD}${CYAN}═══ Voice Changer ═══${NC}\n"
    echo -e "  ${DIM}Current effect: ${NC}${GREEN}${VOICE_EFFECT}${NC}\n"

    local effects=("none" "deep" "high" "robot" "echo" "whisper" "custom")
    local descs=(
        "No effect (natural voice)"
        "Deep voice (pitch shifted down)"
        "High voice (pitch shifted up)"
        "Robot (overdrive + flanger)"
        "Echo (delayed reverb)"
        "Whisper (highpass + tremolo)"
        "Custom (configure all parameters)"
    )

    local i
    for i in "${!effects[@]}"; do
        local num=$(( i + 1 ))
        local marker="  "
        if [ "${effects[$i]}" = "$VOICE_EFFECT" ]; then
            marker="${GREEN}> ${NC}"
        fi
        echo -e "  ${marker}${BOLD}${WHITE}${num}${NC} ${CYAN}│${NC} ${descs[$i]}"
    done

    echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
    echo ""
    echo -ne "  ${BOLD}Select: ${NC}"
    read -r vchoice

    case "$vchoice" in
        1) VOICE_EFFECT="none" ;;
        2) VOICE_EFFECT="deep" ;;
        3) VOICE_EFFECT="high" ;;
        4) VOICE_EFFECT="robot" ;;
        5) VOICE_EFFECT="echo" ;;
        6) VOICE_EFFECT="whisper" ;;
        7) VOICE_EFFECT="custom"
           settings_voice_custom
           ;;
        0|q|Q) return ;;
        *)
            echo -e "\n  ${RED}Invalid choice${NC}"
            sleep 1
            return
            ;;
    esac
    save_config
    log_ok "Voice effect set to: ${VOICE_EFFECT}"
    sleep 1
}

settings_voice_custom() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Custom Voice Effect ═══${NC}\n"
        echo -e "  ${DIM}Configure each parameter. Effects are combined into one chain.${NC}"
        echo -e "  ${DIM}Set a value to 0 to disable that effect.${NC}\n"

        local _p_status="${RED}off${NC}"
        [ "$VOICE_PITCH" -ne 0 ] 2>/dev/null && _p_status="${GREEN}${VOICE_PITCH} cents${NC}"
        local _od_status="${RED}off${NC}"
        [ "$VOICE_OVERDRIVE" -gt 0 ] 2>/dev/null && _od_status="${GREEN}${VOICE_OVERDRIVE}${NC}"
        local _fl_status="${RED}off${NC}"
        [ "$VOICE_FLANGER" -eq 1 ] 2>/dev/null && _fl_status="${GREEN}on${NC}"
        local _ed_status="${RED}off${NC}"
        [ "$VOICE_ECHO_DELAY" -gt 0 ] 2>/dev/null && _ed_status="${GREEN}${VOICE_ECHO_DELAY}ms  decay 0.${VOICE_ECHO_DECAY}${NC}"
        local _hp_status="${RED}off${NC}"
        [ "$VOICE_HIGHPASS" -gt 0 ] 2>/dev/null && _hp_status="${GREEN}${VOICE_HIGHPASS} Hz${NC}"
        local _tr_status="${RED}off${NC}"
        [ "$VOICE_TREMOLO" -gt 0 ] 2>/dev/null && _tr_status="${GREEN}${VOICE_TREMOLO} Hz${NC}"

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Pitch shift     ${_p_status}  ${DIM}(-600 to +600 cents)${NC}"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Overdrive       ${_od_status}  ${DIM}(0=off, 5-20)${NC}"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Flanger         ${_fl_status}  ${DIM}(0=off, 1=on)${NC}"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Echo            ${_ed_status}  ${DIM}(delay 0-200ms, decay 1-9)${NC}"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Highpass filter  ${_hp_status}  ${DIM}(0=off, 300-2000 Hz)${NC}"
        echo -e "  ${BOLD}${WHITE}6${NC} ${CYAN}│${NC} Tremolo         ${_tr_status}  ${DIM}(0=off, 5-40 Hz)${NC}"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Done${NC}"
        echo ""
        echo -ne "  ${BOLD}Select parameter: ${NC}"
        read -r pchoice

        case "$pchoice" in
            1)
                echo -ne "  ${BOLD}Pitch shift (cents, -600 to +600, 0=off): ${NC}"
                read -r val
                [[ "$val" =~ ^-?[0-9]+$ ]] && VOICE_PITCH=$val
                ;;
            2)
                echo -ne "  ${BOLD}Overdrive gain (0=off, 5-20): ${NC}"
                read -r val
                [[ "$val" =~ ^[0-9]+$ ]] && VOICE_OVERDRIVE=$val
                ;;
            3)
                echo -ne "  ${BOLD}Flanger (0=off, 1=on): ${NC}"
                read -r val
                [[ "$val" =~ ^[01]$ ]] && VOICE_FLANGER=$val
                ;;
            4)
                echo -ne "  ${BOLD}Echo delay (ms, 0=off, 20-200): ${NC}"
                read -r val
                [[ "$val" =~ ^[0-9]+$ ]] && VOICE_ECHO_DELAY=$val
                if [ "$VOICE_ECHO_DELAY" -gt 0 ] 2>/dev/null; then
                    echo -ne "  ${BOLD}Echo decay (1-9, maps to 0.1-0.9): ${NC}"
                    read -r val
                    [[ "$val" =~ ^[1-9]$ ]] && VOICE_ECHO_DECAY=$val
                fi
                ;;
            5)
                echo -ne "  ${BOLD}Highpass frequency (Hz, 0=off, 300-2000): ${NC}"
                read -r val
                [[ "$val" =~ ^[0-9]+$ ]] && VOICE_HIGHPASS=$val
                ;;
            6)
                echo -ne "  ${BOLD}Tremolo speed (Hz, 0=off, 5-40): ${NC}"
                read -r val
                [[ "$val" =~ ^[0-9]+$ ]] && VOICE_TREMOLO=$val
                ;;
            0|q|Q)
                save_config
                return
                ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_tor() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Tor Settings ═══${NC}\n"

        local circ_label="${RED}disabled${NC}"
        if [ "$SHOW_CIRCUIT" -eq 1 ]; then
            circ_label="${GREEN}enabled${NC}"
        fi
        local excl_label="${DIM}none${NC}"
        if [ -n "$EXCLUDE_NODES" ]; then
            excl_label="${YELLOW}${EXCLUDE_NODES}${NC}"
        fi
        local sf_label="${RED}disabled${NC}"
        if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
            sf_label="${GREEN}enabled${NC}"
        fi
        local sh_label="${RED}disabled${NC}"
        if [ "$SINGLE_HOP" -eq 1 ]; then
            sh_label="${YELLOW}enabled${NC}"
        fi
        echo -e "  ${DIM}Circuit display:  ${NC}${circ_label}"
        echo -e "  ${DIM}Exclude nodes:    ${NC}${excl_label}"
        echo -e "  ${DIM}Snowflake bridge: ${NC}${sf_label}"
        echo -e "  ${DIM}Single-hop mode:  ${NC}${sh_label}"
        echo -e "  ${DIM}Listen port:      ${NC}${WHITE}${LISTEN_PORT}${NC}"
        echo -e "  ${DIM}SOCKS port:       ${NC}${WHITE}${TOR_SOCKS_PORT}${NC}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Toggle circuit hop display in calls"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Exclude countries from circuits"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Snowflake bridge (censorship circumvention)"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Single-hop mode (low latency)"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Configure ports"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _tor_choice

        case "$_tor_choice" in
            1)
                if [ "$SHOW_CIRCUIT" -eq 1 ]; then
                    SHOW_CIRCUIT=0
                    save_config
                    log_ok "Circuit display disabled"
                else
                    SHOW_CIRCUIT=1
                    save_config
                    log_ok "Circuit display enabled"
                fi
                echo -e "  ${DIM}Restart Tor for changes to take effect (Main menu → option 10).${NC}"
                sleep 2
                ;;
            2) settings_exclude_nodes ;;
            3) settings_snowflake ;;
            4) settings_single_hop ;;
            5) settings_ports ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_exclude_nodes() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Exclude Countries ═══${NC}\n"

        if [ -n "$EXCLUDE_NODES" ]; then
            echo -e "  ${DIM}Current:${NC} ${YELLOW}${EXCLUDE_NODES}${NC}"
        else
            echo -e "  ${DIM}Current:${NC} ${DIM}none (all countries allowed)${NC}"
        fi
        echo -e "  ${DIM}Tor will avoid building circuits through excluded countries.${NC}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Five Eyes       ${DIM}(US, GB, CA, AU, NZ)${NC}"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Nine Eyes       ${DIM}(+ DK, FR, NL, NO)${NC}"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Fourteen Eyes   ${DIM}(+ DE, BE, IT, SE, ES)${NC}"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Custom countries"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} ${RED}Clear (allow all)${NC}"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _excl_choice

        case "$_excl_choice" in
            1)
                EXCLUDE_NODES="{US},{GB},{CA},{AU},{NZ}"
                save_config
                log_ok "Excluding Five Eyes countries"
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                sleep 2
                ;;
            2)
                EXCLUDE_NODES="{US},{GB},{CA},{AU},{NZ},{DK},{FR},{NL},{NO}"
                save_config
                log_ok "Excluding Nine Eyes countries"
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                sleep 2
                ;;
            3)
                EXCLUDE_NODES="{US},{GB},{CA},{AU},{NZ},{DK},{FR},{NL},{NO},{DE},{BE},{IT},{SE},{ES}"
                save_config
                log_ok "Excluding Fourteen Eyes countries"
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                sleep 2
                ;;
            4)
                clear
                echo -e "\n${BOLD}${CYAN}═══ Custom Country Exclusion ═══${NC}\n"
                echo -e "  ${DIM}Country code reference:${NC}\n"
                echo -e "  ${WHITE}AF${NC} Afghanistan      ${WHITE}AL${NC} Albania          ${WHITE}DZ${NC} Algeria"
                echo -e "  ${WHITE}AR${NC} Argentina        ${WHITE}AM${NC} Armenia          ${WHITE}AU${NC} Australia"
                echo -e "  ${WHITE}AT${NC} Austria          ${WHITE}AZ${NC} Azerbaijan       ${WHITE}BH${NC} Bahrain"
                echo -e "  ${WHITE}BD${NC} Bangladesh       ${WHITE}BY${NC} Belarus          ${WHITE}BE${NC} Belgium"
                echo -e "  ${WHITE}BR${NC} Brazil           ${WHITE}BG${NC} Bulgaria         ${WHITE}KH${NC} Cambodia"
                echo -e "  ${WHITE}CA${NC} Canada           ${WHITE}CL${NC} Chile            ${WHITE}CN${NC} China"
                echo -e "  ${WHITE}CO${NC} Colombia         ${WHITE}HR${NC} Croatia          ${WHITE}CU${NC} Cuba"
                echo -e "  ${WHITE}CY${NC} Cyprus           ${WHITE}CZ${NC} Czech Republic   ${WHITE}DK${NC} Denmark"
                echo -e "  ${WHITE}EG${NC} Egypt            ${WHITE}EE${NC} Estonia          ${WHITE}ET${NC} Ethiopia"
                echo -e "  ${WHITE}FI${NC} Finland          ${WHITE}FR${NC} France           ${WHITE}GE${NC} Georgia"
                echo -e "  ${WHITE}DE${NC} Germany          ${WHITE}GR${NC} Greece           ${WHITE}HK${NC} Hong Kong"
                echo -e "  ${WHITE}HU${NC} Hungary          ${WHITE}IS${NC} Iceland          ${WHITE}IN${NC} India"
                echo -e "  ${WHITE}ID${NC} Indonesia        ${WHITE}IR${NC} Iran             ${WHITE}IQ${NC} Iraq"
                echo -e "  ${WHITE}IE${NC} Ireland          ${WHITE}IL${NC} Israel           ${WHITE}IT${NC} Italy"
                echo -e "  ${WHITE}JP${NC} Japan            ${WHITE}JO${NC} Jordan           ${WHITE}KZ${NC} Kazakhstan"
                echo -e "  ${WHITE}KE${NC} Kenya            ${WHITE}KP${NC} North Korea      ${WHITE}KR${NC} South Korea"
                echo -e "  ${WHITE}KW${NC} Kuwait           ${WHITE}LV${NC} Latvia           ${WHITE}LB${NC} Lebanon"
                echo -e "  ${WHITE}LT${NC} Lithuania        ${WHITE}LU${NC} Luxembourg       ${WHITE}MY${NC} Malaysia"
                echo -e "  ${WHITE}MX${NC} Mexico           ${WHITE}MD${NC} Moldova          ${WHITE}MA${NC} Morocco"
                echo -e "  ${WHITE}NL${NC} Netherlands      ${WHITE}NZ${NC} New Zealand      ${WHITE}NG${NC} Nigeria"
                echo -e "  ${WHITE}NO${NC} Norway           ${WHITE}PK${NC} Pakistan         ${WHITE}PA${NC} Panama"
                echo -e "  ${WHITE}PH${NC} Philippines      ${WHITE}PL${NC} Poland           ${WHITE}PT${NC} Portugal"
                echo -e "  ${WHITE}QA${NC} Qatar            ${WHITE}RO${NC} Romania          ${WHITE}RU${NC} Russia"
                echo -e "  ${WHITE}SA${NC} Saudi Arabia     ${WHITE}RS${NC} Serbia           ${WHITE}SG${NC} Singapore"
                echo -e "  ${WHITE}SK${NC} Slovakia         ${WHITE}SI${NC} Slovenia         ${WHITE}ZA${NC} South Africa"
                echo -e "  ${WHITE}ES${NC} Spain            ${WHITE}SE${NC} Sweden           ${WHITE}CH${NC} Switzerland"
                echo -e "  ${WHITE}TW${NC} Taiwan           ${WHITE}TH${NC} Thailand         ${WHITE}TR${NC} Turkey"
                echo -e "  ${WHITE}UA${NC} Ukraine          ${WHITE}AE${NC} UAE              ${WHITE}GB${NC} United Kingdom"
                echo -e "  ${WHITE}US${NC} United States    ${WHITE}UZ${NC} Uzbekistan       ${WHITE}VN${NC} Vietnam"
                echo ""
                echo -e "  ${DIM}Enter codes in Tor format, comma-separated.${NC}"
                echo -e "  ${DIM}Example: {US},{GB},{DE},{RU},{CN}${NC}\n"
                echo -ne "  ${BOLD}Countries: ${NC}"
                read -r _custom_nodes
                if [ -n "$_custom_nodes" ]; then
                    EXCLUDE_NODES="$_custom_nodes"
                    save_config
                    log_ok "Excluding: $EXCLUDE_NODES"
                else
                    log_warn "No input — nothing changed"
                fi
                echo -e "  ${DIM}Restart Tor for changes to take effect.${NC}"
                sleep 2
                ;;
            5)
                EXCLUDE_NODES=""
                save_config
                log_ok "All countries allowed"
                sleep 1
                ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_security() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ Security ═══${NC}\n"

        local hmac_label="${RED}disabled${NC}"
        if [ "$HMAC_AUTH" -eq 1 ]; then
            hmac_label="${GREEN}enabled${NC}"
        fi
        local cipher_upper="$(to_upper "$CIPHER")"
        echo -e "  ${DIM}Cipher:     ${NC}${WHITE}${cipher_upper}${NC}"
        echo -e "  ${DIM}HMAC auth:  ${NC}${hmac_label}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Change encryption cipher"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} HMAC authentication"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _sec_choice

        case "$_sec_choice" in
            1) settings_cipher ;;
            2) settings_hmac ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

settings_hmac() {
    while true; do
        clear
        echo -e "\n${BOLD}${CYAN}═══ HMAC Authentication ═══${NC}\n"

        local hmac_label="${RED}disabled${NC}"
        if [ "$HMAC_AUTH" -eq 1 ]; then
            hmac_label="${GREEN}enabled${NC}"
        fi
        echo -e "  ${DIM}Status:${NC} ${hmac_label}"
        echo ""

        echo -e "  ${DIM}When enabled, every message sent during a call (voice,${NC}"
        echo -e "  ${DIM}text, hangup, and all control signals) is signed with${NC}"
        echo -e "  ${DIM}HMAC-SHA256 derived from your shared secret.${NC}"
        echo ""
        echo -e "  ${DIM}A random nonce is included with each message so that${NC}"
        echo -e "  ${DIM}identical commands produce a unique signature every time.${NC}"
        echo -e "  ${DIM}This prevents replay attacks — a captured message cannot${NC}"
        echo -e "  ${DIM}be re-sent to disrupt future calls.${NC}"
        echo ""
        echo -e "  ${DIM}On the receiving end, any message with an invalid or${NC}"
        echo -e "  ${DIM}missing signature is silently dropped. An attacker who${NC}"
        echo -e "  ${DIM}compromises the Tor circuit but does not have the shared${NC}"
        echo -e "  ${DIM}secret cannot inject commands like HANGUP to disconnect${NC}"
        echo -e "  ${DIM}your call or forge audio and text messages.${NC}"
        echo ""
        echo -e "  ${YELLOW}Both parties must have HMAC enabled for calls to work.${NC}"
        echo -e "  ${YELLOW}Not compatible with versions prior to 1.1.3.${NC}"
        echo ""

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Turn on"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Turn off"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${DIM}Back${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"
        read -r _hmac_choice

        case "$_hmac_choice" in
            1)
                if [ "$HMAC_AUTH" -eq 1 ]; then
                    log_info "HMAC authentication is already enabled"
                else
                    HMAC_AUTH=1
                    save_config
                    log_ok "HMAC authentication enabled"
                    if [ "$CALL_ACTIVE" -eq 1 ]; then
                        echo -e "  ${YELLOW}Takes effect on the next call.${NC}"
                    fi
                fi
                sleep 1
                ;;
            2)
                if [ "$HMAC_AUTH" -eq 0 ]; then
                    log_info "HMAC authentication is already disabled"
                else
                    HMAC_AUTH=0
                    save_config
                    log_ok "HMAC authentication disabled"
                    if [ "$CALL_ACTIVE" -eq 1 ]; then
                        echo -e "  ${YELLOW}Takes effect on the next call.${NC}"
                    fi
                fi
                sleep 1
                ;;
            0|q|Q) return ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

#=============================================================================
# MAIN MENU
#=============================================================================

show_banner() {
    clear
    echo ""
    echo -e "${BOLD}${TOR_PURPLE}   ╔╦╗┌─┐┬─┐┌┬┐┬┌┐┌┌─┐┬  ╔═╗┬ ┬┌─┐┌┐┌┌─┐${NC}"
    echo -e "${BOLD}${TOR_PURPLE}    ║ ├┤ ├┬┘│││││││├─┤│  ╠═╝├─┤│ ││││├┤ ${NC}"
    echo -e "${BOLD}${TOR_PURPLE}    ╩ └─┘┴└─┴ ┴┴┘└┘┴ ┴┴─┘╩  ┴ ┴└─┘┘└┘└─┘${NC}"
    echo ""
    echo -e "  ${TOR_PURPLE}───────────────────────────────────────${NC}"
    echo -e "  ${TOR_PURPLE}${BOLD}Encrypted Voice & Chat${NC} ${DIM}over${NC} ${TOR_PURPLE}${BOLD}Tor${NC} ${DIM}Hidden Services${NC}"
    echo -e "  ${TOR_PURPLE}───────────────────────────────────────${NC}"
    local cipher_display="$(to_upper "$CIPHER")"
    echo -e "  ${DIM}v${VERSION} | Push-to-Talk | End-to-End ${cipher_display}${NC}\n"
}

main_menu() {
    while true; do
        show_banner

        # Show quick status line
        local tor_status="${RED}●${NC}"
        if [ -n "$TOR_PID" ] && kill -0 "$TOR_PID" 2>/dev/null; then
            tor_status="${GREEN}●${NC}"
        fi
        local secret_status="${RED}●${NC}"
        if [ -n "$SHARED_SECRET" ]; then
            secret_status="${GREEN}●${NC}"
        fi
        local sf_status="${RED}●${NC}"
        if [ "$SNOWFLAKE_ENABLED" -eq 1 ]; then
            sf_status="${GREEN}●${NC}"
        fi
        local al_status="${RED}●${NC}"
        if [ "$AUTO_LISTEN" -eq 1 ]; then
            al_status="${GREEN}●${NC}"
        fi
        local _ptt_d="SPACE"
        [ "$PTT_KEY" != " " ] && _ptt_d="$PTT_KEY"

        echo -e "  ${DIM}Tor:${NC} $tor_status  ${DIM}Secret:${NC} $secret_status  ${DIM}SF:${NC} $sf_status  ${DIM}AL:${NC} $al_status  ${DIM}PTT:${NC} ${GREEN}[${_ptt_d}]${NC}\n"

        echo -e "  ${BOLD}${WHITE}1${NC} ${CYAN}│${NC} Listen for calls"
        echo -e "  ${BOLD}${WHITE}2${NC} ${CYAN}│${NC} Call an onion address"
        echo -e "  ${BOLD}${WHITE}3${NC} ${CYAN}│${NC} Show my onion address"
        echo -e "  ${BOLD}${WHITE}4${NC} ${CYAN}│${NC} Set shared secret"
        echo -e "  ${BOLD}${WHITE}5${NC} ${CYAN}│${NC} Test audio (loopback)"
        echo -e "  ${BOLD}${WHITE}6${NC} ${CYAN}│${NC} Show status"
        echo -e "  ${BOLD}${WHITE}7${NC} ${CYAN}│${NC} Install dependencies"
        echo -e "  ${BOLD}${WHITE}8${NC} ${CYAN}│${NC} Start Tor"
        echo -e "  ${BOLD}${WHITE}9${NC} ${CYAN}│${NC} Stop Tor"
        echo -e "  ${BOLD}${WHITE}10${NC}${CYAN}│${NC} Restart Tor"
        echo -e "  ${BOLD}${WHITE}11${NC}${CYAN}│${NC} Rotate onion address"
        echo -e "  ${BOLD}${WHITE}12${NC}${CYAN}│${NC} Settings"
        echo -e "  ${BOLD}${WHITE}13${NC}${CYAN}│${NC} Relay mode (group bridge)"
        echo -e "  ${BOLD}${WHITE}0${NC} ${CYAN}│${NC} ${RED}Quit${NC}"
        echo ""
        echo -ne "  ${BOLD}Select: ${NC}"

        # If auto-listen is active, poll for incoming calls without redrawing
        local choice=""
        if [ "$AUTO_LISTEN" -eq 1 ] && [ -n "$AUTO_LISTEN_PID" ]; then
            echo -ne "${DIM}[Auto-listening...]${NC} " >&2
            while true; do
                # Check for incoming call
                if check_auto_listen; then
                    choice=""
                    break
                fi
                # Try to read user input with short timeout
                if read -r -t 1 choice 2>/dev/null; then
                    break  # user typed something
                fi
            done
        else
            read -r choice
        fi

        [ -z "$choice" ] && continue

        case "$choice" in
            1) listen_for_call ;;
            2) call_remote ;;
            3)
                local onion
                onion=$(get_onion)
                if [ -n "$onion" ]; then
                    echo -e "\n  ${BOLD}${GREEN}Your address:${NC} ${WHITE}${BOLD}${onion}${NC}\n"

                    # QR code generation
                    if check_dep qrencode; then
                        echo -ne "  ${BOLD}Show QR code? [Y/n]: ${NC}"
                        read -r _qr_show
                        if [ "$_qr_show" != "n" ] && [ "$_qr_show" != "N" ]; then
                            tput smcup 2>/dev/null || true
                            clear
                            echo -e "\n  ${BOLD}${GREEN}Your address:${NC} ${WHITE}${BOLD}${onion}${NC}\n"
                            qrencode -t ANSIUTF8 "$onion"
                            echo ""
                            echo -e "  ${DIM}Note: Some QR scanners auto-prepend http:// — this will be stripped when dialing.${NC}"
                            echo -ne "  ${DIM}Press Enter to dismiss QR code...${NC}"
                            read -r
                            tput rmcup 2>/dev/null || true
                        fi
                    else
                        echo -ne "  ${BOLD}Install QR code generator (qrencode) to display a scannable QR? [Y/n]: ${NC}"
                        read -r _qr_install
                        if [ "$_qr_install" != "n" ] && [ "$_qr_install" != "N" ]; then
                            local SUDO="sudo"
                            if [ $IS_TERMUX -eq 1 ]; then
                                SUDO=""
                                pkg install -y libqrencode 2>/dev/null
                            elif check_dep brew; then
                                brew install qrencode 2>/dev/null
                            elif check_dep apt-get; then
                                $SUDO apt-get install -y qrencode 2>/dev/null
                            elif check_dep dnf; then
                                $SUDO dnf install -y qrencode 2>/dev/null
                            elif check_dep pacman; then
                                $SUDO pacman -S --noconfirm qrencode 2>/dev/null
                            else
                                log_err "No supported package manager found. Install qrencode manually."
                            fi

                            if check_dep qrencode; then
                                log_ok "qrencode installed successfully!"
                                sleep 1
                                tput smcup 2>/dev/null || true
                                clear
                                echo -e "\n  ${BOLD}${GREEN}Your address:${NC} ${WHITE}${BOLD}${onion}${NC}\n"
                                qrencode -t ANSIUTF8 "$onion"
                                echo ""
                                echo -e "  ${DIM}Note: Some QR scanners auto-prepend http:// — this will be stripped when dialing.${NC}"
                                echo -ne "  ${DIM}Press Enter to dismiss QR code...${NC}"
                                read -r
                                tput rmcup 2>/dev/null || true
                            else
                                log_err "qrencode installation failed."
                            fi
                        fi
                    fi
                else
                    echo -e "\n  ${YELLOW}Tor hidden service not running. Start Tor first (option 8).${NC}\n"
                fi
                echo -ne "  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            4) set_shared_secret ;;
            5) test_audio
               echo -ne "  ${DIM}Press Enter to continue...${NC}"
               read -r
               ;;
            6) show_status
               echo -ne "  ${DIM}Press Enter to continue...${NC}"
               read -r
               ;;
            7) install_deps
               echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
               read -r
               ;;
            8)
                start_tor
                start_auto_listener
                echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            9)
                stop_tor
                echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            10)
                stop_tor
                start_tor
                start_auto_listener
                echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            11)
                rotate_onion
                echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            12)
                settings_menu
                ;;
            13)
                relay_mode
                echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
                read -r
                ;;
            0|q|Q)
                echo -e "\n${GREEN}Goodbye!${NC}"
                stop_tor
                exit 0
                ;;
            *)
                echo -e "\n  ${RED}Invalid choice${NC}"
                sleep 1
                ;;
        esac
    done
}

#=============================================================================
# ENTRY POINT
#=============================================================================

trap cleanup EXIT INT TERM

# Create data directories
mkdir -p "$DATA_DIR" "$AUDIO_DIR" "$PID_DIR" "$DATA_DIR/run"

# Clean any stale run files from previous sessions
rm -f "$DATA_DIR/run/"* 2>/dev/null || true

# Load saved config
load_config

if [ $IS_TERMUX -eq 1 ]; then
    # Ensure PulseAudio is running so play/rec work on Termux
    if check_dep pulseaudio; then
        if ! pulseaudio --check &>/dev/null; then
            pulseaudio --start --exit-idle-time=-1 &>/dev/null || true
        fi
    fi
fi

# Handle command-line arguments
case "${1:-}" in
    install)
        install_deps
        ;;
    test)
        test_audio
        ;;
    status)
        show_status
        ;;
    listen)
        load_config
        listen_for_call
        ;;
    call)
        load_config
        if [ -n "${2:-}" ]; then
            remote_onion="$2"
            remote_onion="${remote_onion#http://}"
            remote_onion="${remote_onion#https://}"
            if [[ "$remote_onion" != *.onion ]]; then
                remote_onion="${remote_onion}.onion"
            fi
            start_tor
            call_remote
        else
            echo "Usage: $0 call <onion-address>"
        fi
        ;;
    relay)
        load_config
        relay_mode
        ;;
    help|-h|--help)
        echo -e "${BOLD}${APP_NAME} v${VERSION}${NC}"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  (none)     Interactive menu"
        echo "  install    Install dependencies"
        echo "  test       Run audio loopback test"
        echo "  status     Show current status"
        echo "  listen     Start listening for calls"
        echo "  call ADDR  Call an onion address"
        echo "  relay      Start relay mode (group bridge)"
        echo "  help       Show this help"
        ;;
    *)
        main_menu
        ;;
esac
