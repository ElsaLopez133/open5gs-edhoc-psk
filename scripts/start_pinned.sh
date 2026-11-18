#!/usr/bin/env bash
set -euo pipefail

# Starts the Open5GS core + UERANSIM gNB with CPU pinning suited for
# benchmarking. Use together with scripts/benchmark_crypto_cost_both.sh,
# which pins nr-ue itself.
#
# Pinned (timed) processes:
#   open5gs-udmd  -> CPU $UDM_CORE   (default 0)
#   open5gs-ausfd -> CPU $AUSF_CORE  (default 2)
#   open5gs-amfd  -> CPU $AMF_CORE   (default 4)
#   nr-gnb        -> CPU $GNB_CORE   (default 7)
#   nr-ue         -> CPU $UE_CORE    (default 6, applied by the bench script)
#
# Other daemons (nrf, scp, pcf, smf, upf, udr) start un-pinned -- they are
# not in the timed code path.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UERANSIM_ROOT="${UERANSIM_ROOT:-/home/elsa/projects/UERANSIM}"
UERANSIM_BUILD_DIR="${UERANSIM_ROOT}/cmake-build-release"
GNB_CONFIG="${GNB_CONFIG:-${UERANSIM_ROOT}/config/open5gs-gnb.yaml}"

LOG_DIR="${OPEN5GS_ROOT}/run_logs"
BIN_DIR="${OPEN5GS_ROOT}/install/bin"

UDM_CORE="${UDM_CORE:-0}"
AUSF_CORE="${AUSF_CORE:-2}"
AMF_CORE="${AMF_CORE:-4}"
GNB_CORE="${GNB_CORE:-7}"
UE_CORE="${UE_CORE:-6}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <start|stop|status>

Commands:
  start    Set CPU governor=performance, then start Open5GS daemons + nr-gnb
           with the pinned ones bound to dedicated cores.
  stop     Kill all open5gs-*d daemons and nr-gnb / nr-ue.
  status   Show running PIDs and their CPU affinity.

Override cores via env vars:
  UDM_CORE=$UDM_CORE  AUSF_CORE=$AUSF_CORE  AMF_CORE=$AMF_CORE
  GNB_CORE=$GNB_CORE  UE_CORE=$UE_CORE  (UE_CORE is for the bench script)
EOF
}

ensure_governor() {
  if ! command -v cpupower >/dev/null 2>&1; then
    echo "[pin] WARNING: cpupower not found; skipping governor setup" >&2
    return
  fi
  local current
  current=$(cat "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" 2>/dev/null || echo "?")
  if [[ "${current}" != "performance" ]]; then
    echo "[pin] Setting CPU governor to performance (was: ${current})"
    sudo cpupower frequency-set -g performance >/dev/null
  else
    echo "[pin] CPU governor already 'performance'"
  fi
}

stop_all() {
  echo "[pin] Stopping daemons..."
  sudo pkill -f "${UERANSIM_BUILD_DIR}/nr-ue"  2>/dev/null || true
  sudo pkill -f "${UERANSIM_BUILD_DIR}/nr-gnb" 2>/dev/null || true
  for d in upfd smfd pcfd scpd nrfd amfd ausfd udmd udrd bsfd nssfd; do
    sudo pkill -x "open5gs-${d}" 2>/dev/null || true
  done
  sleep 1
}

start_pinned_daemon() {
  local core="$1" name="$2"
  local bin="${BIN_DIR}/${name}"
  if [[ ! -x "${bin}" ]]; then
    echo "[pin] ERROR: ${bin} not found or not executable" >&2
    exit 1
  fi
  local log="${LOG_DIR}/${name}.log"
  sudo bash -c "exec taskset -c '${core}' '${bin}' >'${log}' 2>&1" &
  echo "[pin]   ${name} -> CPU ${core}"
}

start_unpinned_daemon() {
  local name="$1"
  local bin="${BIN_DIR}/${name}"
  if [[ ! -x "${bin}" ]]; then
    echo "[pin]   skip ${name} (binary missing)"
    return
  fi
  local log="${LOG_DIR}/${name}.log"
  sudo bash -c "exec '${bin}' >'${log}' 2>&1" &
  echo "[pin]   ${name} (unpinned)"
}

start_all() {
  mkdir -p "${LOG_DIR}"
  ensure_governor
  stop_all

  echo "[pin] Starting Open5GS daemons..."
  # Start support daemons first so AMF/AUSF can register with NRF.
  start_unpinned_daemon open5gs-nrfd
  sleep 0.3
  start_unpinned_daemon open5gs-scpd
  start_unpinned_daemon open5gs-udrd
  start_pinned_daemon "${UDM_CORE}"  open5gs-udmd
  start_pinned_daemon "${AUSF_CORE}" open5gs-ausfd
  start_unpinned_daemon open5gs-pcfd
  start_unpinned_daemon open5gs-smfd
  start_unpinned_daemon open5gs-upfd
  start_pinned_daemon "${AMF_CORE}" open5gs-amfd
  sleep 1

  echo "[pin] Starting nr-gnb on CPU ${GNB_CORE}..."
  sudo bash -c "exec taskset -c '${GNB_CORE}' '${UERANSIM_BUILD_DIR}/nr-gnb' \
      -c '${GNB_CONFIG}' >'${LOG_DIR}/nr-gnb.log' 2>&1" &
  sleep 1

  status
  echo ""
  echo "[pin] Ready. Run benchmark with:"
  echo "      ./scripts/benchmark_crypto_cost_both.sh edhoc -n 30 -p ${UE_CORE}"
}

status() {
  echo "[pin] Status:"
  for proc in open5gs-udmd open5gs-ausfd open5gs-amfd open5gs-nrfd \
              open5gs-scpd open5gs-smfd open5gs-upfd open5gs-udrd \
              open5gs-pcfd nr-gnb nr-ue; do
    local pid
    pid=$(pgrep -x "${proc}" 2>/dev/null | head -n1 || true)
    if [[ -n "${pid}" ]]; then
      local aff
      aff=$(taskset -pc "${pid}" 2>/dev/null | awk -F': ' '{print $2}')
      printf "  %-20s pid=%-7s cpu=%s\n" "${proc}" "${pid}" "${aff}"
    else
      printf "  %-20s (not running)\n" "${proc}"
    fi
  done
}

case "${1:-}" in
  start)  start_all ;;
  stop)   stop_all ;;
  status) status ;;
  -h|--help|help|"") usage ;;
  *) echo "Unknown command: $1" >&2; usage; exit 1 ;;
esac
