#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${LOG_DIR:-${OPEN5GS_ROOT}/run_logs}"
PID_DIR="${PID_DIR:-${OPEN5GS_ROOT}/run_pids}"

OPEN5GS_BUILD_DIR="${OPEN5GS_ROOT}/build"
OPEN5GS_BIN_DIR="${OPEN5GS_ROOT}/install/bin"

OPEN5GS_DAEMONS=(
  open5gs-nrfd
  open5gs-scpd
  open5gs-ausfd
  open5gs-udmd
  open5gs-pcfd
  open5gs-nssfd
  open5gs-bsfd
  open5gs-udrd
  open5gs-amfd
  open5gs-smfd
)

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  all         Rebuild, stop old processes, reset ogstun, start Open5GS, check
  rebuild     Rebuild Open5GS (ninja + install)
  stop        Stop Open5GS processes
  tun         Reset ogstun and run misc/netconf.sh
  start       Start Open5GS NFs in background
  check       Show process/interface/log status
EOF
}

prepare_dirs() {
  mkdir -p "${LOG_DIR}" "${PID_DIR}"
}

wait_for_log_line() {
  local logfile="$1"
  local pattern="$2"
  local timeout_s="$3"
  local label="$4"
  local waited=0

  while (( waited < timeout_s )); do
    if [[ -f "${logfile}" ]] && grep -qE "${pattern}" "${logfile}"; then
      return 0
    fi
    sleep 1
    ((waited+=1))
  done

  echo "[open5gs] timeout waiting for ${label} in ${logfile}" >&2
  if [[ -f "${logfile}" ]]; then
    tail -n 20 "${logfile}" >&2 || true
  fi
  return 1
}

require_sudo() {
  sudo -v
}

ensure_nrf_log_writable() {
  local nrf_log="${OPEN5GS_ROOT}/install/var/log/open5gs/nrf.log"
  if [[ -e "${nrf_log}" ]] && [[ ! -w "${nrf_log}" ]]; then
    echo "[open5gs] fixing ownership: ${nrf_log}"
    sudo chown "$(id -un):$(id -gn)" "${nrf_log}"
  fi
}

rebuild_open5gs() {
  echo "[open5gs] rebuild"
  ninja -C "${OPEN5GS_BUILD_DIR}"
  ninja -C "${OPEN5GS_BUILD_DIR}" install
}

stop_open5gs() {
  echo "[open5gs] stopping"
  sudo pkill -f '/home/elsa/projects/open5gs/build/src/' || true
  sudo pkill -f '/home/elsa/projects/open5gs/install/bin/open5gs-' || true

  if compgen -G "${PID_DIR}/open5gs-*.pid" >/dev/null; then
    while IFS= read -r pidfile; do
      pid="$(cat "${pidfile}" 2>/dev/null || true)"
      if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        kill "${pid}" || true
      fi
      rm -f "${pidfile}"
    done < <(find "${PID_DIR}" -maxdepth 1 -type f -name 'open5gs-*.pid')
  fi
}

reset_tun() {
  echo "[open5gs] reset ogstun"
  sudo ip link set ogstun down 2>/dev/null || true
  sudo ip addr flush dev ogstun 2>/dev/null || true
  sudo ip tuntap del name ogstun mode tun 2>/dev/null || true
  (cd "${OPEN5GS_ROOT}" && sudo ./misc/netconf.sh)
}

start_one_nf() {
  local nf="$1"
  local bin="${OPEN5GS_BIN_DIR}/${nf}"
  local logfile="${LOG_DIR}/${nf}.log"
  local pidfile="${PID_DIR}/${nf}.pid"
  if [[ ! -x "${bin}" ]]; then
    echo "Missing binary: ${bin}" >&2
    exit 1
  fi
  nohup "${bin}" >"${logfile}" 2>&1 &
  echo "$!" >"${pidfile}"
}

start_open5gs() {
  ensure_nrf_log_writable
  echo "[open5gs] start NRF"
  start_one_nf "open5gs-nrfd"
  wait_for_log_line \
    "${LOG_DIR}/open5gs-nrfd.log" \
    'NF registered|nghttp2_server\(\)' \
    15 \
    "NRF startup"

  echo "[open5gs] start control plane"
  for nf in "${OPEN5GS_DAEMONS[@]}"; do
    [[ "${nf}" == "open5gs-nrfd" ]] && continue
    start_one_nf "${nf}"
  done

  echo "[open5gs] start UPF (sudo)"
  local upf_log="${LOG_DIR}/open5gs-upfd.log"
  local upf_pid="${PID_DIR}/open5gs-upfd.pid"
  sudo bash -c "nohup '${OPEN5GS_BIN_DIR}/open5gs-upfd' >'${upf_log}' 2>&1 & echo \$! >'${upf_pid}'"

  wait_for_log_line \
    "${LOG_DIR}/open5gs-amfd.log" \
    'ngap_server\(\)' \
    15 \
    "AMF NGAP listener"
  wait_for_log_line \
    "${LOG_DIR}/open5gs-ausfd.log" \
    'NF registered' \
    15 \
    "AUSF NRF registration"
  wait_for_log_line \
    "${LOG_DIR}/open5gs-udmd.log" \
    'NF registered' \
    15 \
    "UDM NRF registration"
  wait_for_log_line \
    "${LOG_DIR}/open5gs-smfd.log" \
    'NF registered' \
    15 \
    "SMF NRF registration"
}

check_open5gs() {
  echo "[open5gs] process status"
  ps -eo pid,cmd | grep -E 'open5gs-(nrfd|scpd|ausfd|udmd|pcfd|nssfd|bsfd|udrd|amfd|smfd|upfd)' | grep -v grep || true

  echo
  echo "[open5gs] ogstun status"
  ip -br addr show ogstun || true

  echo
  echo "[open5gs] key logs"
  for f in "${LOG_DIR}/open5gs-amfd.log" "${LOG_DIR}/open5gs-ausfd.log" "${LOG_DIR}/open5gs-udmd.log" "${LOG_DIR}/open5gs-smfd.log" "${LOG_DIR}/open5gs-upfd.log"; do
    if [[ -f "${f}" ]]; then
      echo "--- ${f}"
      tail -n 8 "${f}" || true
    fi
  done
}

main() {
  prepare_dirs
  local cmd="${1:-all}"
  shift || true

  case "${cmd}" in
    all)
      require_sudo
      rebuild_open5gs
      stop_open5gs
      reset_tun
      start_open5gs
      check_open5gs
      ;;
    rebuild)
      rebuild_open5gs
      ;;
    stop)
      stop_open5gs
      ;;
    tun)
      require_sudo
      reset_tun
      ;;
    start)
      require_sudo
      start_open5gs
      ;;
    check)
      check_open5gs
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Unknown command: ${cmd}" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
