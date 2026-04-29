#!/usr/bin/env bash
###############################################################################
# HomelinkWG - WireGuard VPN + socat port-forwarding deployer
# Version: 3.1 (2026-04-26)
#
# Idempotent:  safe to re-run, converges config.json -> system state.
# Multi-port:  every entry of config.json .ports becomes its own systemd unit.
# Safe reset:  only stops/removes HomelinkWG units, never runs a blind pkill.
###############################################################################

# Guard: this script requires bash, not sh/dash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "[ERROR] This script must be run with bash, not sh."
    echo "  Use: sudo bash deploy.sh   or   sudo ./deploy.sh"
    exit 1
fi

set -Eeuo pipefail

readonly SCRIPT_VERSION="3.1"
readonly SCRIPT_DATE="2026-04-26"

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CONFIG_JSON_DEFAULT="${SCRIPT_DIR}/config.json"
CONFIG_JSON="${CONFIG_JSON_DEFAULT}"
readonly WG_CONFIG_SRC_DEFAULT="${SCRIPT_DIR}/yourconfwg/wg0.conf"
WG_CONFIG_SRC="${WG_CONFIG_SRC_DEFAULT}"
readonly STATE_DIR="/etc/homelinkwg"
readonly SETTINGS_FILE="${STATE_DIR}/settings.conf"
readonly LOG_FILE="/var/log/homelinkwg-deploy.log"
readonly SOCAT_UNIT_PREFIX="homelinkwg-socat-"
readonly DASHBOARD_UNIT="homelinkwg-dashboard.service"
readonly WG_STARTUP_UNIT="homelinkwg-wg-startup.service"
readonly WG_STARTUP_SCRIPT="/usr/local/bin/homelinkwg-wg-startup.sh"
readonly DASHBOARD_USER="homelinkwg"
readonly DASHBOARD_HOME="/opt/homelinkwg"

# Defaults (overridden by config.json / settings file)
WG_INTERFACE="wg0"
ENABLE_AUTOBOOT=false
ENABLE_DASHBOARD=true
ENABLE_ANALYTICS=false
LIGHT_MODE=false
ULTRA_LIGHT=false
DASHBOARD_PORT=5555
INSTALL_TYPE="fresh"
ADMIN_PASSWORD=""
UPDATE_MODE=false
APPLY_CONFIG=false
SKIP_PROMPTS=false

# ---------------------------------------------------------------------------
# Colors / logging
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[1;33m'
    readonly BLUE=$'\033[0;34m'
    readonly NC=$'\033[0m'
else
    readonly RED="" GREEN="" YELLOW="" BLUE="" NC=""
fi

_append_log() {
    local level="$1"; shift
    [[ $EUID -eq 0 ]] || return 0
    mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || return 0
    printf '%s [%s] %s\n' "$(date -Is)" "${level}" "$*" >>"${LOG_FILE}" 2>/dev/null || true
}
log_info()    { printf '%s[INFO]%s %s\n'  "${BLUE}"   "${NC}" "$*"; _append_log "INFO"  "$*"; }
log_success() { printf '%s[ OK ]%s %s\n'  "${GREEN}"  "${NC}" "$*"; _append_log "OK"    "$*"; }
log_warning() { printf '%s[WARN]%s %s\n'  "${YELLOW}" "${NC}" "$*"; _append_log "WARN"  "$*"; }
log_error()   { printf '%s[FAIL]%s %s\n'  "${RED}"    "${NC}" "$*" >&2; _append_log "FAIL" "$*"; }

on_error() {
    local rc=$?
    local line="${BASH_LINENO[0]:-?}"
    log_error "deploy.sh aborted (exit ${rc}) at line ${line}"
    exit "${rc}"
}
trap on_error ERR

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
require_cmd() {
    local cmd="$1" pkg="${2:-$1}"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_info "Installing missing dependency: ${pkg}"
        apt-get install -y "${pkg}" >/dev/null
    fi
}

ask_yes_no() {
    local prompt="$1" default="${2:-n}" ans
    local hint
    if [[ "${default}" == "y" ]]; then
        hint="y/n, Enter=yes"
    else
        hint="y/n, Enter=no"
    fi
    while true; do
        read -r -p "${prompt} [${hint}]: " ans || ans=""
        ans="${ans:-${default}}"
        case "${ans,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *)     echo "Please answer yes or no." ;;
        esac
    done
}

generate_admin_password() {
    # Use python3 (already required for the dashboard) to avoid extra deps.
    python3 -c 'import secrets; print(secrets.token_urlsafe(18))'
}

print_secret() {
    # Print secrets to the console without appending to /var/log/homelinkwg-deploy.log
    printf '%s\n' "$*"
}

json_get() {
    # json_get <jq-filter> [default]
    local filter="$1" default="${2:-}"
    local v
    v=$(jq -r "${filter} // empty" "${CONFIG_JSON}" 2>/dev/null || true)
    if [[ -z "${v}" ]]; then
        printf '%s' "${default}"
    else
        printf '%s' "${v}"
    fi
}

valid_port() {
    local p="$1"
    [[ "${p}" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

valid_host() {
    local h="$1"
    # IPv4 or DNS label-ish
    [[ "${h}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Must be run as root (sudo ./deploy.sh)"
        exit 1
    fi
}

check_prereqs() {
    [[ -f /etc/debian_version ]] || { log_error "Debian/Ubuntu required"; exit 1; }
    [[ -f "${CONFIG_JSON}"   ]]   || { log_error "Missing config.json"; exit 1; }
    [[ -f "${WG_CONFIG_SRC}" ]]   || { log_error "Missing ${WG_CONFIG_SRC}"; exit 1; }
}

ensure_base_tools() {
    # Needed before we can parse config.json or install anything else
    if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
        log_info "Refreshing apt cache..."
        apt-get update -qq
    fi
    require_cmd jq
    require_cmd curl
}

validate_config() {
    if ! jq empty "${CONFIG_JSON}" 2>/dev/null; then
        log_error "config.json is not valid JSON"
        exit 1
    fi

    WG_INTERFACE=$(json_get '.vpn.interface' "wg0")
    DASHBOARD_PORT=$(json_get '.dashboard.port' "5555")
    LIGHT_MODE=$(json_get '.dashboard.light_mode' "false")
    ULTRA_LIGHT=$(json_get '.dashboard.ultra_light' "false")
    valid_port "${DASHBOARD_PORT}" || { log_error "Invalid dashboard port: ${DASHBOARD_PORT}"; exit 1; }

    local n
    n=$(jq '.ports | length' "${CONFIG_JSON}")
    if (( n == 0 )); then
        log_warning "No ports defined in config.json"
    fi

    # Validate each port entry
    local i=0
    while IFS= read -r entry; do
        local lp rh rp name
        lp=$(jq -r '.local_port'  <<<"${entry}")
        rh=$(jq -r '.remote_host' <<<"${entry}")
        rp=$(jq -r '.remote_port' <<<"${entry}")
        name=$(jq -r '.name'      <<<"${entry}")
        valid_port "${lp}" || { log_error "ports[${i}].local_port invalid: ${lp}"; exit 1; }
        valid_port "${rp}" || { log_error "ports[${i}].remote_port invalid: ${rp}"; exit 1; }
        valid_host "${rh}" || { log_error "ports[${i}].remote_host invalid: ${rh}"; exit 1; }
        [[ -n "${name}" && "${name}" != "null" ]] || { log_error "ports[${i}].name missing"; exit 1; }
        i=$((i+1))
    done < <(jq -c '.ports[]' "${CONFIG_JSON}")

    log_success "config.json validated (${n} port(s))"
}

# ---------------------------------------------------------------------------
# WireGuard config parsing
# ---------------------------------------------------------------------------
extract_wg_metadata() {
    VPN_IP=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); split($2,a,"/"); print a[1]; exit}' "${WG_CONFIG_SRC}")
    if [[ -z "${VPN_IP}" ]]; then
        log_error "Could not extract Address from ${WG_CONFIG_SRC}"
        exit 1
    fi
    # Gateway = first usable IP of the VPN /24 (best-effort)
    VPN_GATEWAY="$(echo "${VPN_IP}" | awk -F. '{printf "%s.%s.%s.1", $1,$2,$3}')"

    # Collect AllowedIPs for route insertion
    mapfile -t ALLOWED_CIDRS < <(awk -F'=' '/^[[:space:]]*AllowedIPs[[:space:]]*=/ {
        gsub(/[[:space:]]/,"",$2); n=split($2,a,","); for(i=1;i<=n;i++) print a[i]
    }' "${WG_CONFIG_SRC}")

    log_success "VPN IP: ${VPN_IP} (gw ${VPN_GATEWAY})"
}

# ---------------------------------------------------------------------------
# Settings persistence
# ---------------------------------------------------------------------------
load_settings() {
    if [[ -f "${SETTINGS_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${SETTINGS_FILE}"
        INSTALL_TYPE="maintenance"
        log_info "Loaded previous settings (autoboot=${ENABLE_AUTOBOOT}, dashboard=${ENABLE_DASHBOARD})"
    fi
}

save_settings() {
    mkdir -p "${STATE_DIR}"
    cat >"${SETTINGS_FILE}" <<EOF
# HomelinkWG settings - generated $(date -Is)
ENABLE_AUTOBOOT=${ENABLE_AUTOBOOT}
ENABLE_DASHBOARD=${ENABLE_DASHBOARD}
ENABLE_ANALYTICS=${ENABLE_ANALYTICS}
LIGHT_MODE=${LIGHT_MODE}
ULTRA_LIGHT=${ULTRA_LIGHT}
EOF
    chmod 600 "${SETTINGS_FILE}"
}

set_config_light_mode() {
    # Persist LIGHT_MODE into config.json so reruns stay consistent.
    local tmp
    tmp=$(mktemp --tmpdir="${SCRIPT_DIR}" .config.XXXXXX.json)
    jq --argjson v "$([[ "${LIGHT_MODE}" == "true" ]] && echo true || echo false)" \
       '.dashboard.light_mode = $v' "${CONFIG_JSON}" >"${tmp}"
    mv "${tmp}" "${CONFIG_JSON}"
}

set_config_ultra_light() {
    # Persist ULTRA_LIGHT into config.json so reruns stay consistent.
    local tmp
    tmp=$(mktemp --tmpdir="${SCRIPT_DIR}" .config.XXXXXX.json)
    jq --argjson v "$([[ "${ULTRA_LIGHT}" == "true" ]] && echo true || echo false)" \
       '.dashboard.ultra_light = $v' "${CONFIG_JSON}" >"${tmp}"
    mv "${tmp}" "${CONFIG_JSON}"
}

# ---------------------------------------------------------------------------
# Hardware analysis — suggests a performance mode before prompting
# ---------------------------------------------------------------------------
_HW_RAM_MB=0
_HW_CPU_CORES=0
_HW_IS_PI=false
_HW_PI_MODEL=""
_HW_DISK_MBPS=0
_HW_NET_TYPE="unknown"   # ethernet | wifi | unknown
_HW_SUGGESTED_MODE="normal"   # normal | light | ultra_light
_HW_REASONS=()

analyze_hardware() {
    printf '\n%s════════════════════════════════════════════════════════%s\n' "${BLUE}" "${NC}"
    printf '%s  HomelinkWG — Hardware Analysis%s\n' "${BLUE}" "${NC}"
    printf '%s════════════════════════════════════════════════════════%s\n\n' "${BLUE}" "${NC}"

    # ── RAM ──────────────────────────────────────────────────────────────────
    if [[ -f /proc/meminfo ]]; then
        _HW_RAM_MB=$(awk '/^MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
    fi

    # ── CPU cores ────────────────────────────────────────────────────────────
    _HW_CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)

    # ── Raspberry Pi detection ────────────────────────────────────────────────
    if grep -qi "raspberry\|BCM2\|BCM27\|BCM28" /proc/cpuinfo 2>/dev/null; then
        _HW_IS_PI=true
        _HW_PI_MODEL=$(grep "Model" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || \
                       cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || echo "Pi (unknown model)")
    elif [[ -f /proc/device-tree/model ]]; then
        local model; model=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
        if echo "${model}" | grep -qi raspberry; then
            _HW_IS_PI=true
            _HW_PI_MODEL="${model}"
        fi
    fi

    # ── Disk speed (quick dd write test — 32 MB, ~3 s max) ───────────────────
    local bench_file="/tmp/homelinkwg_hw_bench"
    local dd_out
    dd_out=$(dd if=/dev/zero of="${bench_file}" bs=1M count=32 conv=fdatasync 2>&1 || true)
    rm -f "${bench_file}"
    # Parse "X MB/s" or "X GB/s" from dd stderr
    if echo "${dd_out}" | grep -qE "MB/s|GB/s"; then
        local spd_str; spd_str=$(echo "${dd_out}" | grep -oE "[0-9]+([.,][0-9]+)? (MB|GB)/s" | tail -1)
        local val; val=$(echo "${spd_str}" | grep -oE "[0-9]+([.,][0-9]+)?" | head -1 | tr ',' '.')
        local unit; unit=$(echo "${spd_str}" | grep -oE "(MB|GB)/s" | head -1)
        if [[ -n "${val}" ]]; then
            if [[ "${unit}" == "GB/s" ]]; then
                _HW_DISK_MBPS=$(echo "${val} * 1024" | bc 2>/dev/null | cut -d. -f1 || echo 9999)
            else
                _HW_DISK_MBPS=$(echo "${val}" | cut -d. -f1)
            fi
        fi
    fi

    # ── Network interface type ────────────────────────────────────────────────
    local default_iface
    default_iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
    if [[ -n "${default_iface}" ]]; then
        if [[ "${default_iface}" == eth* || "${default_iface}" == en* ]]; then
            _HW_NET_TYPE="ethernet"
        elif [[ "${default_iface}" == wlan* || "${default_iface}" == wl* ]]; then
            _HW_NET_TYPE="wifi"
        fi
    fi

    # ── Display findings ──────────────────────────────────────────────────────
    printf '  %-22s %s\n' "Machine:"  "$( [[ "${_HW_IS_PI}" == true ]] && echo "${_HW_PI_MODEL}" || uname -m )"
    printf '  %-22s %s MB\n' "RAM:"  "${_HW_RAM_MB}"
    printf '  %-22s %s core(s)\n' "CPU:"  "${_HW_CPU_CORES}"
    if (( _HW_DISK_MBPS > 0 )); then
        printf '  %-22s %s MB/s\n' "Disk speed:"  "${_HW_DISK_MBPS}"
    else
        printf '  %-22s unknown\n' "Disk speed:"
    fi
    printf '  %-22s %s\n' "Network:"  "${_HW_NET_TYPE}"
    echo

    # ── Score & suggestion ────────────────────────────────────────────────────
    local score=0   # 0=normal, 1=light, 2=ultra_light

    if (( _HW_RAM_MB < 256 )); then
        score=2; _HW_REASONS+=("RAM < 256 MB (${_HW_RAM_MB} MB) → ultra-light recommended")
    elif (( _HW_RAM_MB < 600 )); then
        (( score < 1 )) && score=1
        _HW_REASONS+=("RAM < 600 MB (${_HW_RAM_MB} MB) → light recommended")
    fi

    if (( _HW_CPU_CORES <= 1 )); then
        (( score < 2 )) && score=2
        _HW_REASONS+=("Single CPU core → ultra-light recommended")
    elif (( _HW_CPU_CORES <= 2 )) && [[ "${_HW_IS_PI}" == true ]]; then
        (( score < 1 )) && score=1
        _HW_REASONS+=("Pi with ${_HW_CPU_CORES} cores → light recommended")
    fi

    if (( _HW_DISK_MBPS > 0 && _HW_DISK_MBPS < 15 )); then
        (( score < 2 )) && score=2
        _HW_REASONS+=("Very slow disk (${_HW_DISK_MBPS} MB/s) → ultra-light reduces I/O")
    elif (( _HW_DISK_MBPS > 0 && _HW_DISK_MBPS < 40 )); then
        (( score < 1 )) && score=1
        _HW_REASONS+=("Slow disk (${_HW_DISK_MBPS} MB/s) → light reduces writes")
    fi

    if [[ "${_HW_NET_TYPE}" == "wifi" ]]; then
        (( score < 1 )) && score=1
        _HW_REASONS+=("WiFi active → light recommended (Ethernet = better streaming performance)")
    fi

    case "${score}" in
        0) _HW_SUGGESTED_MODE="normal" ;;
        1) _HW_SUGGESTED_MODE="light" ;;
        2) _HW_SUGGESTED_MODE="ultra_light" ;;
    esac

    # ── Display recommendation ────────────────────────────────────────────────
    printf '  %sSuggested mode: %s%s\n' "${GREEN}" "${_HW_SUGGESTED_MODE^^}" "${NC}"
    if (( ${#_HW_REASONS[@]} > 0 )); then
        for reason in "${_HW_REASONS[@]}"; do
            printf '  %s  • %s%s\n' "${YELLOW}" "${reason}" "${NC}"
        done
    else
        printf '  %s  • Hardware sufficient for normal mode%s\n' "${YELLOW}" "${NC}"
    fi
    printf '\n%s════════════════════════════════════════════════════════%s\n\n' "${BLUE}" "${NC}"
}

prompt_initial_settings() {
    if [[ "${INSTALL_TYPE}" == "maintenance" || "${SKIP_PROMPTS}" == "true" ]]; then
        return 0
    fi
    echo
    log_info "Initial configuration"

    # Auto-start
    if ask_yes_no "Enable auto-start on boot?" "y"; then ENABLE_AUTOBOOT=true; else ENABLE_AUTOBOOT=false; fi

    # Dashboard is always enabled — ask only about performance mode
    ENABLE_DASHBOARD=true

    # Performance mode — use hardware analysis suggestion as default
    echo
    echo "  Performance mode:"
    echo "   Normal      : refresh 5s, full CPU/latency metrics, 720 pts graph"
    echo "                 → Server or VPS with 1 GB+ RAM"
    echo "   Light       : refresh 15s, no CPU stats, 300 pts graph"
    echo "                 → Raspberry Pi 3/4, 512 MB VPS, low-power ARM"
    echo "   Ultra-light : refresh 30s, analytics every 5 min, logs off by default"
    echo "                 → Raspberry Pi Zero, embedded, < 256 MB RAM"
    echo

    # Pre-select defaults based on hardware analysis
    local default_ultra="n" default_light="n"
    if [[ "${_HW_SUGGESTED_MODE}" == "ultra_light" ]]; then
        default_ultra="y"
        printf '  %s[Suggestion] Ultra-light recommended for this hardware%s\n\n' "${YELLOW}" "${NC}"
    elif [[ "${_HW_SUGGESTED_MODE}" == "light" ]]; then
        default_light="y"
        printf '  %s[Suggestion] Light recommended for this hardware%s\n\n' "${YELLOW}" "${NC}"
    else
        printf '  %s[Suggestion] Normal — this hardware is powerful enough%s\n\n' "${GREEN}" "${NC}"
    fi

    if ask_yes_no "Enable ultra-light mode?" "${default_ultra}"; then
        ULTRA_LIGHT=true
        LIGHT_MODE=true
    else
        ULTRA_LIGHT=false
        if ask_yes_no "Enable light mode?" "${default_light}"; then LIGHT_MODE=true; else LIGHT_MODE=false; fi
    fi
    set_config_light_mode
    set_config_ultra_light

    # Analytics (default on — powers the Services tab)
    if ask_yes_no "Enable 24h analytics & metrics collection (requires SQLite)?" "y"; then ENABLE_ANALYTICS=true; else ENABLE_ANALYTICS=false; fi

    # Admin password — always required for dashboard admin features
    log_info "Set an admin password (leave empty to auto-generate)"
    while true; do
        read -rsp "Enter admin password: " ADMIN_PASSWORD
        echo
        if [[ -z "${ADMIN_PASSWORD}" ]]; then
            ADMIN_PASSWORD="$(generate_admin_password)"
            print_secret
            print_secret "Generated admin password (store it now): ${ADMIN_PASSWORD}"
            print_secret
            break
        fi
        read -rsp "Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo
        if [[ "${ADMIN_PASSWORD}" == "${ADMIN_PASSWORD_CONFIRM}" ]]; then
            break
        fi
        log_warning "Passwords do not match, please try again"
    done

    save_settings
}

# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------
install_packages() {
    log_info "Installing required packages..."
    local need=()
    command -v wg      >/dev/null 2>&1 || need+=(wireguard wireguard-tools)
    command -v resolvconf >/dev/null 2>&1 || need+=(openresolv)
    command -v socat   >/dev/null 2>&1 || need+=(socat)
    command -v ss      >/dev/null 2>&1 || need+=(iproute2)
    if [[ "${ENABLE_DASHBOARD}" == true ]]; then
        command -v python3 >/dev/null 2>&1 || need+=(python3)
        python3 -c 'import flask' 2>/dev/null || need+=(python3-flask)
        if [[ "${ENABLE_ANALYTICS}" == true ]]; then
            python3 -c 'import bcrypt' 2>/dev/null || need+=(python3-bcrypt)
        fi
    fi
    if (( ${#need[@]} > 0 )); then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need[@]}" >/dev/null
    fi
    # Python packages not available as Debian packages — install via pip
    if [[ "${ENABLE_DASHBOARD}" == true ]]; then
        local pip_need=()
        python3 -c 'import pyotp' 2>/dev/null       || pip_need+=(pyotp)
        python3 -c 'import qrcode; import PIL' 2>/dev/null || pip_need+=("qrcode[pil]")
        if (( ${#pip_need[@]} > 0 )); then
            log_info "Installing Python packages via pip: ${pip_need[*]}"
            # --break-system-packages requis sur pip 23+ (Python 3.11 / Bookworm)
            # Sur Bullseye (Python 3.9 / pip <23) on installe sans ce flag
            if pip install --break-system-packages --quiet "${pip_need[@]}" 2>/dev/null; then
                true
            else
                pip install --quiet "${pip_need[@]}"
            fi
        fi
    fi
    log_success "Packages ready"
}

# ---------------------------------------------------------------------------
# Dashboard user
# ---------------------------------------------------------------------------
ensure_dashboard_user() {
    if ! id -u "${DASHBOARD_USER}" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${DASHBOARD_USER}"
        log_success "Created system user '${DASHBOARD_USER}'"
    fi
}

# Allow dashboard service to restart socat services via polkit
install_restart_helper() {
    # Detect polkit version:
    #   >= 0.106 (Bookworm) : format JavaScript .rules
    #   <  0.106 (Bullseye) : format .pkla
    local polkit_ver
    polkit_ver=$(pkaction --version 2>/dev/null | awk '{print $NF}' || echo "0")
    local polkit_major
    polkit_major=$(echo "${polkit_ver}" | awk -F. '{print $2}')

    if (( polkit_major >= 106 )); then
        # Bookworm and above — JavaScript format
        local polkit_rule="/etc/polkit-1/rules.d/50-homelinkwg.rules"
        mkdir -p "$(dirname "${polkit_rule}")"
        cat > "${polkit_rule}" <<'POLKIT'
// Allow homelinkwg user to restart its socat services and the dashboard itself
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.systemd1.manage-units") == 0 &&
        subject.user == "homelinkwg") {
        var unit = action.lookup("unit");
        if (unit.indexOf("homelinkwg-socat-") == 0 ||
            unit == "homelinkwg-dashboard.service") {
            return polkit.Result.YES;
        }
    }
});
POLKIT
        chmod 644 "${polkit_rule}"
        log_success "Polkit rule (JS) installed at ${polkit_rule}"
    else
        # Bullseye and below — .pkla format
        local polkit_rule="/etc/polkit-1/localauthority/50-local.d/50-homelinkwg.pkla"
        mkdir -p "$(dirname "${polkit_rule}")"
        cat > "${polkit_rule}" <<'PKLA'
[HomelinkWG - allow homelinkwg to manage its units]
Identity=unix-user:homelinkwg
Action=org.freedesktop.systemd1.manage-units
ResultAny=yes
ResultInactive=yes
ResultActive=yes
PKLA
        chmod 644 "${polkit_rule}"
        log_success "Polkit rule (pkla) installed at ${polkit_rule}"
    fi
}

# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
configure_wireguard() {
    install -m 600 -o root -g root "${WG_CONFIG_SRC}" "/etc/wireguard/${WG_INTERFACE}.conf"
    log_success "WireGuard config installed at /etc/wireguard/${WG_INTERFACE}.conf"
}

bring_up_wireguard() {
    if ip link show "${WG_INTERFACE}" >/dev/null 2>&1 \
        && ip link show "${WG_INTERFACE}" | grep -qE 'state (UP|UNKNOWN)'; then
        log_info "${WG_INTERFACE} already up"
        return 0
    fi
    # Prefer wg-quick service so systemd tracks it and brings it on boot
    systemctl enable --now "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || {
        log_warning "wg-quick@${WG_INTERFACE} failed via systemd, trying manual wg-quick up"
        wg-quick up "${WG_INTERFACE}"
    }
    sleep 1
    log_success "WireGuard interface ${WG_INTERFACE} is up"
}

install_wg_startup_service() {
    # Some VPS providers clear routes on reboot; this oneshot re-adds them.
    local routes=""
    for cidr in "${ALLOWED_CIDRS[@]}"; do
        [[ -z "${cidr}" ]] && continue
        routes+=$'\n'"ip route replace ${cidr} dev ${WG_INTERFACE} 2>/dev/null || true"
    done

    cat >"${WG_STARTUP_SCRIPT}" <<EOF
#!/usr/bin/env bash
# Auto-generated by HomelinkWG deploy.sh
set -u
# Wait for the interface to actually exist
for _ in \$(seq 1 20); do
    ip link show ${WG_INTERFACE} >/dev/null 2>&1 && break
    sleep 1
done
ip addr replace ${VPN_IP}/32 dev ${WG_INTERFACE} 2>/dev/null || true${routes}
EOF
    chmod 755 "${WG_STARTUP_SCRIPT}"

    cat >"/etc/systemd/system/${WG_STARTUP_UNIT}" <<EOF
[Unit]
Description=HomelinkWG WireGuard IP & routes
After=wg-quick@${WG_INTERFACE}.service network-online.target
Wants=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
ExecStart=${WG_STARTUP_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "${WG_STARTUP_UNIT}" >/dev/null 2>&1 || true
    log_success "WireGuard startup service installed"
}

# ---------------------------------------------------------------------------
# socat port-forward units (one per config.ports[])
# ---------------------------------------------------------------------------
socat_unit_name() {
    echo "${SOCAT_UNIT_PREFIX}$1.service"
}

write_socat_unit() {
    local local_port="$1" remote_host="$2" remote_port="$3" name="$4"
    local unit_path="/etc/systemd/system/$(socat_unit_name "${local_port}")"
    cat >"${unit_path}" <<EOF
[Unit]
Description=HomelinkWG socat forward ${name} (${local_port} -> ${remote_host}:${remote_port})
After=network-online.target wg-quick@${WG_INTERFACE}.service ${WG_STARTUP_UNIT}
Wants=wg-quick@${WG_INTERFACE}.service network-online.target
Documentation=https://github.com/homelinkwg/homelinkwg

[Service]
Type=simple
ExecStart=/usr/bin/socat -T60 TCP-LISTEN:${local_port},reuseaddr,fork,keepalive TCP:${remote_host}:${remote_port},keepalive
Restart=always
RestartSec=5
# KillMode=control-group kills the parent AND all forks on stop
# prevents orphan process accumulation on restart
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=10
# Hardening
DynamicUser=no
User=root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SyslogIdentifier=homelinkwg-socat-${local_port}

[Install]
WantedBy=multi-user.target
EOF
}

sync_socat_services() {
    log_info "Syncing socat services with config.json..."

    # 1. Collect desired ports from config.json
    local desired=()
    while IFS= read -r lp; do desired+=("${lp}"); done < <(jq -r '.ports[] | select(.enabled // true) | .local_port' "${CONFIG_JSON}")

    # 2. Remove units for ports no longer desired (or with enabled=false)
    local unit existing_port f
    for f in /etc/systemd/system/${SOCAT_UNIT_PREFIX}*.service; do
        [[ -f "${f}" ]] || continue
        unit="$(basename "${f}")"
        existing_port="${unit#${SOCAT_UNIT_PREFIX}}"
        existing_port="${existing_port%.service}"
        local keep=0
        for d in "${desired[@]}"; do
            [[ "${d}" == "${existing_port}" ]] && { keep=1; break; }
        done
        if (( keep == 0 )); then
            log_info "Removing orphan service ${unit}"
            systemctl disable --now "${unit}" >/dev/null 2>&1 || true
            rm -f "${f}"
        fi
    done
    systemctl daemon-reload

    # 3. Create/update units for each desired port
    local entry lp rh rp name enabled
    while IFS= read -r entry; do
        lp=$(jq -r '.local_port'       <<<"${entry}")
        rh=$(jq -r '.remote_host'      <<<"${entry}")
        rp=$(jq -r '.remote_port'      <<<"${entry}")
        name=$(jq -r '.name'           <<<"${entry}")
        enabled=$(jq -r '.enabled // true' <<<"${entry}")
        [[ "${enabled}" == "true" ]] || continue
        write_socat_unit "${lp}" "${rh}" "${rp}" "${name}"
    done < <(jq -c '.ports[]' "${CONFIG_JSON}")

    systemctl daemon-reload

    # 4. Enable/start each — kill residual socat processes before restart
    for lp in "${desired[@]}"; do
        local u; u="$(socat_unit_name "${lp}")"
        # Stop the service cleanly and kill any residual socat processes on this port
        systemctl stop "${u}" 2>/dev/null || true
        pkill -f "socat.*${lp}" 2>/dev/null || true
        sleep 0.3
        if [[ "${ENABLE_AUTOBOOT}" == true ]]; then
            systemctl enable "${u}" >/dev/null 2>&1 || true
        fi
        systemctl restart "${u}"
        if systemctl is-active --quiet "${u}"; then
            log_success "Service ${u} active (port ${lp})"
        else
            log_error  "Service ${u} failed to start"
            systemctl --no-pager status "${u}" || true
        fi
    done
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
install_dashboard() {
    if [[ "${ENABLE_DASHBOARD}" != true ]]; then
        # If dashboard is disabled, make sure any existing unit is stopped
        if [[ -f "/etc/systemd/system/${DASHBOARD_UNIT}" ]]; then
            systemctl disable --now "${DASHBOARD_UNIT}" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${DASHBOARD_UNIT}"
            systemctl daemon-reload
            log_info "Dashboard disabled and removed"
        fi
        return 0
    fi

    ensure_dashboard_user
    install_restart_helper

    # Install the dashboard code + config to /opt/homelinkwg/ so the service
    # does not depend on the (usually 700) permissions of the user's $HOME.
    # The dashboard reads config.json and yourconfwg/wg0.conf relative to its
    # own location, so we mirror the layout inside DASHBOARD_HOME.
    install -d -m 750 -o root -g "${DASHBOARD_USER}" "${DASHBOARD_HOME}"
    install -d -m 750 -o root -g "${DASHBOARD_USER}" "${DASHBOARD_HOME}/yourconfwg"
    # Backup old dashboard payload before updating (safe, non-destructive).
    if [[ "${UPDATE_MODE}" == "true" && -f "${DASHBOARD_HOME}/dashboard.py" ]]; then
        local ts backup_dir
        ts="$(date -Is | tr ':+' '__' | tr -d '.')"
        backup_dir="${DASHBOARD_HOME}/backups/${ts}"
        install -d -m 750 -o root -g "${DASHBOARD_USER}" "${backup_dir}"
        cp -a "${DASHBOARD_HOME}/dashboard.py" "${backup_dir}/dashboard.py" 2>/dev/null || true
        cp -a "${DASHBOARD_HOME}/analytics.conf" "${backup_dir}/analytics.conf" 2>/dev/null || true
        cp -a "${DASHBOARD_HOME}/config.json" "${backup_dir}/config.json" 2>/dev/null || true
        cp -a "${DASHBOARD_HOME}/yourconfwg/wg0.conf" "${backup_dir}/wg0.conf" 2>/dev/null || true
        log_info "Backup created: ${backup_dir}"
    fi

    install -m 640 -o root -g "${DASHBOARD_USER}" "${SCRIPT_DIR}/dashboard.py" "${DASHBOARD_HOME}/dashboard.py"

    # Copy homelinkwg package (modularized Python modules)
    if [[ -d "${SCRIPT_DIR}/homelinkwg" ]]; then
        log_info "Copying homelinkwg package..."
        cp -r -a "${SCRIPT_DIR}/homelinkwg" "${DASHBOARD_HOME}/"
        chown -R "${DASHBOARD_USER}:${DASHBOARD_USER}" "${DASHBOARD_HOME}/homelinkwg"
        find "${DASHBOARD_HOME}/homelinkwg" -type f -exec chmod 640 {} \;
        find "${DASHBOARD_HOME}/homelinkwg" -type d -exec chmod 750 {} \;
    fi

    # Copy requirements.txt for pip dependencies
    if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
        install -m 640 -o root -g "${DASHBOARD_USER}" "${SCRIPT_DIR}/requirements.txt" "${DASHBOARD_HOME}/requirements.txt"
    fi

    # Copy Flask templates and static assets
    if [[ -d "${SCRIPT_DIR}/templates" ]]; then
        log_info "Copying Flask templates..."
        cp -r -a "${SCRIPT_DIR}/templates" "${DASHBOARD_HOME}/"
        chown -R "${DASHBOARD_USER}:${DASHBOARD_USER}" "${DASHBOARD_HOME}/templates"
        find "${DASHBOARD_HOME}/templates" -type f -exec chmod 640 {} \;
        find "${DASHBOARD_HOME}/templates" -type d -exec chmod 750 {} \;
    fi
    if [[ -d "${SCRIPT_DIR}/static" ]]; then
        log_info "Copying static assets..."
        cp -r -a "${SCRIPT_DIR}/static" "${DASHBOARD_HOME}/"
        chown -R "${DASHBOARD_USER}:${DASHBOARD_USER}" "${DASHBOARD_HOME}/static"
        find "${DASHBOARD_HOME}/static" -type f -exec chmod 640 {} \;
        find "${DASHBOARD_HOME}/static" -type d -exec chmod 750 {} \;
    fi

    # Do not overwrite existing config/vpn config on update unless explicitly requested.
    if [[ ! -f "${DASHBOARD_HOME}/config.json" || "${APPLY_CONFIG}" == "true" ]]; then
        install -m 640 -o root -g "${DASHBOARD_USER}" "${CONFIG_JSON}" "${DASHBOARD_HOME}/config.json"
    else
        log_info "Preserving existing dashboard config.json (use --apply-config to overwrite)"
    fi
    if [[ ! -f "${DASHBOARD_HOME}/yourconfwg/wg0.conf" || "${APPLY_CONFIG}" == "true" ]]; then
        install -m 640 -o root -g "${DASHBOARD_USER}" "${WG_CONFIG_SRC}" "${DASHBOARD_HOME}/yourconfwg/wg0.conf"
    else
        log_info "Preserving existing wg0.conf (use --apply-config to overwrite)"
    fi
    install -d -m 750 -o root -g "${DASHBOARD_USER}" "${DASHBOARD_HOME}/images"
    install -m 640 -o root -g "${DASHBOARD_USER}" "${SCRIPT_DIR}/images/web_logo.png" "${DASHBOARD_HOME}/images/web_logo.png"
    # Optional docs used by the dashboard UI (What's new modal).
    [[ -f "${SCRIPT_DIR}/RELEASE_NOTES.md" ]] && install -m 640 -o root -g "${DASHBOARD_USER}" "${SCRIPT_DIR}/RELEASE_NOTES.md" "${DASHBOARD_HOME}/RELEASE_NOTES.md" || true

    # Save analytics setting
    {
        echo "ENABLE_ANALYTICS=${ENABLE_ANALYTICS}"
        echo "LIGHT_MODE=${LIGHT_MODE}"
        echo "ULTRA_LIGHT=${ULTRA_LIGHT}"

        # Hash admin password — always required for dashboard admin features.
        if [[ -z "${ADMIN_PASSWORD}" ]]; then
            ADMIN_PASSWORD="$(generate_admin_password)"
            print_secret
            print_secret "Generated admin password (store it now): ${ADMIN_PASSWORD}"
            print_secret
        fi
        ADMIN_PASSWORD_HASH=$(python3 -c "
import bcrypt
password = '''${ADMIN_PASSWORD}'''
hash_val = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
print(hash_val)
")
        echo "ADMIN_PASSWORD=${ADMIN_PASSWORD_HASH}"
        echo "SESSION_TIMEOUT_MINUTES=60"
    } > "${DASHBOARD_HOME}/analytics.conf"

    chmod 660 "${DASHBOARD_HOME}/analytics.conf"
    chown root:${DASHBOARD_USER} "${DASHBOARD_HOME}/analytics.conf"

    # Initialize metrics database with proper permissions (only if analytics enabled)
    if [[ "${ENABLE_ANALYTICS}" == true ]]; then
        log_info "Initializing metrics database (WAL mode)..."
        python3 -c "
import sys; sys.path.insert(0, '${DASHBOARD_HOME}')
from dashboard import init_db, DB_FILE
init_db()
" || log_warning "Database init failed; will retry on service startup"

        if [[ -f "${DASHBOARD_HOME}/homelinkwg-metrics.db" ]]; then
            chmod 660 "${DASHBOARD_HOME}/homelinkwg-metrics.db"
            chown root:${DASHBOARD_USER} "${DASHBOARD_HOME}/homelinkwg-metrics.db"
        fi
    else
        log_info "Analytics disabled (no metrics database)"
    fi

    # CRITICAL: Directory must be writable by homelinkwg user for database operations
    chmod 770 "${DASHBOARD_HOME}"

    cat >"/etc/systemd/system/${DASHBOARD_UNIT}" <<EOF
[Unit]
Description=HomelinkWG dashboard (Flask)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${DASHBOARD_USER}
Group=${DASHBOARD_USER}
WorkingDirectory=${DASHBOARD_HOME}
Environment="PYTHONPATH=${DASHBOARD_HOME}"
ExecStart=/usr/bin/python3 ${DASHBOARD_HOME}/dashboard.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=${DASHBOARD_HOME}
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
SyslogIdentifier=homelinkwg-dashboard

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    [[ "${ENABLE_AUTOBOOT}" == true ]] && systemctl enable "${DASHBOARD_UNIT}" >/dev/null 2>&1 || true
    systemctl restart "${DASHBOARD_UNIT}"

    # Give Flask a moment, then probe both systemd state AND the listening port.
    local i ok=0
    for i in 1 2 3 4 5 6 7 8; do
        sleep 1
        if systemctl is-active --quiet "${DASHBOARD_UNIT}" \
            && ss -tlnH "sport = :${DASHBOARD_PORT}" 2>/dev/null | grep -q LISTEN; then
            ok=1; break
        fi
    done

    if (( ok == 1 )); then
        log_success "Dashboard listening on :${DASHBOARD_PORT}"
    else
        log_error "Dashboard did not come up on :${DASHBOARD_PORT} after 8s"
        log_info "---- last 20 lines of ${DASHBOARD_UNIT} ----"
        journalctl -u "${DASHBOARD_UNIT}" -n 20 --no-pager 2>/dev/null || true
        log_info "--------------------------------------------"
    fi
}

# ---------------------------------------------------------------------------
# Raspberry Pi optimizations
# Apply performance settings at install time when running on a Pi
# ---------------------------------------------------------------------------
optimize_raspberry_pi() {
    # Detect if running on a Raspberry Pi
    if ! grep -qi "raspberry\|rpi\|bcm" /proc/cpuinfo /proc/device-tree/model 2>/dev/null; then
        log_info "Non-Pi hardware detected — skipping Pi optimizations"
        return 0
    fi
    log_info "Raspberry Pi detected — applying optimizations..."

    # ── 1. GPU memory ─────────────────────────────────────────────────────────
    # 128 MB minimum for video playback / TV usage
    local config_txt="/boot/firmware/config.txt"
    [[ -f "${config_txt}" ]] || config_txt="/boot/config.txt"  # fallback Bullseye
    if [[ -f "${config_txt}" ]]; then
        if grep -q "^gpu_mem=" "${config_txt}"; then
            local current_gpu
            current_gpu=$(grep "^gpu_mem=" "${config_txt}" | tail -1 | cut -d= -f2)
            if (( current_gpu < 128 )); then
                sed -i "s/^gpu_mem=.*/gpu_mem=128/" "${config_txt}"
                log_success "gpu_mem increased to 128 MB (was ${current_gpu} MB) — reboot required"
            else
                log_info "gpu_mem=${current_gpu} MB — ok"
            fi
        else
            echo "gpu_mem=128" >> "${config_txt}"
            log_success "gpu_mem=128 MB added to ${config_txt} — reboot required"
        fi
    fi

    # ── 2. Low swappiness (zram enabled by default on recent Pi OS) ───────────
    local current_swap
    current_swap=$(cat /proc/sys/vm/swappiness)
    if (( current_swap > 10 )); then
        sysctl -w vm.swappiness=10 >/dev/null
        if ! grep -q "vm.swappiness" /etc/sysctl.conf 2>/dev/null; then
            echo "vm.swappiness=10" >> /etc/sysctl.conf
        else
            sed -i "s/^vm.swappiness=.*/vm.swappiness=10/" /etc/sysctl.conf
        fi
        log_success "vm.swappiness lowered to 10 (was ${current_swap})"
    else
        log_info "vm.swappiness=${current_swap} — ok"
    fi

    # ── 3. WiFi warning ───────────────────────────────────────────────────────
    # WiFi is significantly slower and less stable than Ethernet for streaming
    local default_iface
    default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    if [[ "${default_iface}" == wlan* ]]; then
        log_warning "⚠️  Pi is connected via WiFi (${default_iface})."
        log_warning "   For stable video streaming, use an Ethernet connection instead."
        local wifi_rate
        wifi_rate=$(iwconfig "${default_iface}" 2>/dev/null | awk -F'[=\ ]' '/Bit Rate/{print $3 $4}' || echo "?")
        log_info "   Current WiFi rate: ${wifi_rate}"
    else
        log_success "Network connected via ${default_iface} (Ethernet) ✓"
    fi

    # ── 4. TeamViewer warning ─────────────────────────────────────────────────
    if systemctl is-active --quiet teamviewerd 2>/dev/null; then
        log_warning "⚠️  TeamViewer is active and consumes ~13%% CPU continuously."
        log_warning "   Disable it if not needed:"
        log_warning "   sudo systemctl disable --now teamviewerd"
    fi

    log_success "Raspberry Pi optimizations applied"
}

# ---------------------------------------------------------------------------
# Health summary
# ---------------------------------------------------------------------------
post_deploy_summary() {
    echo
    log_info "================ HomelinkWG summary ================"
    log_info "Mode           : ${INSTALL_TYPE}"
    log_info "VPN interface  : ${WG_INTERFACE} (IP ${VPN_IP})"
    log_info "Auto-boot      : ${ENABLE_AUTOBOOT}"
    log_info "Dashboard      : ${ENABLE_DASHBOARD} (port ${DASHBOARD_PORT})"
    log_info "Analytics      : ${ENABLE_ANALYTICS}"
    log_info "Light mode     : ${LIGHT_MODE}"
    log_info "Ultra-light    : ${ULTRA_LIGHT}"
    log_info "Configured ports:"
    jq -r '.ports[] | "  \u2022 \(.name) :: :\(.local_port) -> \(.remote_host):\(.remote_port) (enabled=\(.enabled // true))"' "${CONFIG_JSON}"
    echo
    log_info "Local access URLs (first listening port):"
    local first_port
    first_port=$(jq -r '.ports[0].local_port // empty' "${CONFIG_JSON}")
    if [[ -n "${first_port}" ]]; then
        while read -r ip; do
            [[ -n "${ip}" ]] && log_info "  http://${ip}:${first_port}"
        done < <(hostname -I 2>/dev/null | tr ' ' '\n' | sort -u)
    fi
    log_info "Logs: journalctl -u 'homelinkwg-*' -f"
    log_info "===================================================="
}

# ---------------------------------------------------------------------------
# Reset (safe)
# ---------------------------------------------------------------------------
reset_homelinkwg() {
    check_root
    log_warning "Resetting HomelinkWG (services, units, state will be removed)"

    # Stop + disable known units (glob + legacy names for migration)
    local units=(
        'homelinkwg-socat-*.service'
        'homelinkwg-dashboard.service'
        'homelinkwg-wg-startup.service'
        'inboxjell-socat*.service'
        'inboxjell-dashboard.service'
    )
    for pattern in "${units[@]}"; do
        # Expand pattern via systemctl list-units to be precise (no blind kill)
        while read -r unit; do
            [[ -z "${unit}" ]] && continue
            systemctl disable --now "${unit}" >/dev/null 2>&1 || true
        done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
                  | awk -v p="^${pattern/\*/.*}\$" '$1 ~ p {print $1}')
    done

    # Remove unit files
    rm -f /etc/systemd/system/homelinkwg-socat-*.service
    rm -f /etc/systemd/system/homelinkwg-dashboard.service
    rm -f /etc/systemd/system/homelinkwg-wg-startup.service
    rm -f /etc/systemd/system/inboxjell-socat*.service
    rm -f /etc/systemd/system/inboxjell-dashboard.service
    rm -f "${WG_STARTUP_SCRIPT}"

    # State
    rm -rf /etc/homelinkwg /etc/inboxjell
    rm -rf "${DASHBOARD_HOME}"

    # System user (created by deploy.sh — safe to remove, home dir wasn't created)
    if id -u "${DASHBOARD_USER}" >/dev/null 2>&1; then
        userdel "${DASHBOARD_USER}" 2>/dev/null || true
    fi

    # Logs
    rm -f /var/log/homelinkwg-deploy.log /var/log/inboxjell-deploy.log /var/log/homelinkwg-monitor.log

    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true

    # We intentionally do NOT touch wg-quick@wg0 or /etc/wireguard — the user
    # may still need their VPN for other things. Bring it down explicitly if
    # the user really wants that:
    log_info "WireGuard config at /etc/wireguard/${WG_INTERFACE}.conf kept."
    log_info "Run 'sudo wg-quick down ${WG_INTERFACE}' if you want it stopped."

    log_success "Reset complete. You can now run: sudo ./deploy.sh"
    exit 0
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
show_usage() {
    cat <<EOF
HomelinkWG deploy.sh v${SCRIPT_VERSION} (${SCRIPT_DATE})

Usage:
  sudo ./deploy.sh           Deploy or converge the installation
  sudo ./deploy.sh --update  Upgrade code without overwriting existing config/db
  sudo ./deploy.sh --update --apply-config  Upgrade and overwrite config/wg conf from this folder
  sudo ./deploy.sh reset     Remove HomelinkWG services and state
  sudo ./deploy.sh status    Show service status summary
  sudo ./deploy.sh help      This message

Configuration is entirely driven by ./config.json and ./yourconfwg/wg0.conf.
EOF
}

show_status() {
    check_root
    echo "--- HomelinkWG services ---"
    systemctl list-units --no-pager --type=service --all 'homelinkwg-*' || true
    echo
    echo "--- WireGuard ---"
    if command -v wg >/dev/null 2>&1; then
        wg show 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    check_root
    log_info "HomelinkWG deploy.sh v${SCRIPT_VERSION} starting at $(date -Is)"

    # Flags
    while (( $# > 0 )); do
        case "$1" in
            --update) UPDATE_MODE=true; SKIP_PROMPTS=true ;;
            --apply-config) APPLY_CONFIG=true ;;
            *) ;;
        esac
        shift || true
    done

    if [[ "${UPDATE_MODE}" == "true" ]]; then
        INSTALL_TYPE="maintenance"
        # Prefer currently-installed config files, so updates don't clobber settings.
        if [[ -f "${DASHBOARD_HOME}/config.json" ]]; then
            CONFIG_JSON="${DASHBOARD_HOME}/config.json"
        fi
        if [[ -f "${DASHBOARD_HOME}/yourconfwg/wg0.conf" ]]; then
            WG_CONFIG_SRC="${DASHBOARD_HOME}/yourconfwg/wg0.conf"
        fi
    fi

    check_prereqs
    ensure_base_tools
    validate_config
    extract_wg_metadata
    load_settings
    analyze_hardware
    prompt_initial_settings

    install_packages
    optimize_raspberry_pi
    configure_wireguard
    bring_up_wireguard
    install_wg_startup_service
    sync_socat_services
    install_dashboard

    post_deploy_summary
    log_success "Deployment finished at $(date -Is)"
}

case "${1:-}" in
    reset)         reset_homelinkwg ;;
    status)        show_status ;;
    help|-h|--help) show_usage ;;
    update|--update) shift || true; main --update "$@" ;;
    "")            main ;;
    *)             show_usage; exit 1 ;;
esac
