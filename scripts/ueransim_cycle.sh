#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UERANSIM_ROOT="${UERANSIM_ROOT:-/home/elsa/projects/UERANSIM}"
LOG_DIR="${LOG_DIR:-${OPEN5GS_ROOT}/run_logs}"
PID_DIR="${PID_DIR:-${OPEN5GS_ROOT}/run_pids}"
UERANSIM_BUILD_DIR="${UERANSIM_ROOT}/cmake-build-release"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [--no-gnb] [--no-ue]

Commands:
  all       Rebuild, stop old processes, start gNB + UE, check
  rebuild   Rebuild UERANSIM
  stop      Stop gNB/UE processes
  start     Start gNB/UE in background
  check     Show process/log status
EOF
}

prepare_dirs() {
  mkdir -p "${LOG_DIR}" "${PID_DIR}"
}

require_sudo() {
  sudo -v
}

rebuild_ueransim() {
  echo "[ueransim] rebuild"
  cmake --build "${UERANSIM_BUILD_DIR}"
}

stop_ueransim() {
  echo "[ueransim] stopping"
  sudo pkill -f '/home/elsa/projects/UERANSIM/cmake-build-release/nr-ue' || true
  pkill -f '/home/elsa/projects/UERANSIM/cmake-build-release/nr-gnb' || true

  if compgen -G "${PID_DIR}/nr-*.pid" >/dev/null; then
    while IFS= read -r pidfile; do
      pid="$(cat "${pidfile}" 2>/dev/null || true)"
      if [[ -n "${pid}" ]] && sudo kill -0 "${pid}" 2>/dev/null; then
        sudo kill "${pid}" || true
      fi
      rm -f "${pidfile}"
    done < <(find "${PID_DIR}" -maxdepth 1 -type f -name 'nr-*.pid')
  fi
}

start_ueransim() {
  local start_gnb=1
  local start_ue=1

  for arg in "$@"; do
    case "${arg}" in
      --no-gnb) start_gnb=0 ;;
      --no-ue) start_ue=0 ;;
      *)
        echo "Unknown option for start: ${arg}" >&2
        exit 1
        ;;
    esac
  done

  if [[ "${start_gnb}" -eq 1 ]]; then
    echo "[ueransim] start gNB"
    nohup "${UERANSIM_BUILD_DIR}/nr-gnb" -c "${UERANSIM_ROOT}/config/open5gs-gnb.yaml" \
      >"${LOG_DIR}/nr-gnb.log" 2>&1 &
    echo "$!" >"${PID_DIR}/nr-gnb.pid"
  fi

  if [[ "${start_ue}" -eq 1 ]]; then
    echo "[ueransim] start UE (sudo)"
    sudo bash -c "nohup '${UERANSIM_BUILD_DIR}/nr-ue' -c '${UERANSIM_ROOT}/config/open5gs-ue.yaml' >'${LOG_DIR}/nr-ue.log' 2>&1 & echo \$! >'${PID_DIR}/nr-ue.pid'"
  fi
}

check_ueransim() {
  echo "[ueransim] process status"
  ps -eo pid,cmd | grep -E 'nr-gnb|nr-ue' | grep -v grep || true

  local ue_count
  ue_count="$(ps -eo cmd | grep -E '/UERANSIM/cmake-build-release/nr-ue ' | grep -v grep | wc -l | tr -d ' ')"
  if [[ "${ue_count}" -gt 1 ]]; then
    echo "[ueransim] warning: ${ue_count} nr-ue processes are running (expected 1)"
  fi

  echo
  echo "[ueransim] key logs"
  for f in "${LOG_DIR}/nr-gnb.log" "${LOG_DIR}/nr-ue.log"; do
    if [[ -f "${f}" ]]; then
      echo "--- ${f}"
      tail -n 12 "${f}" || true
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
      rebuild_ueransim
      stop_ueransim
      start_ueransim "$@"
      check_ueransim
      ;;
    rebuild)
      rebuild_ueransim
      ;;
    stop)
      require_sudo
      stop_ueransim
      ;;
    start)
      require_sudo
      start_ueransim "$@"
      ;;
    check)
      check_ueransim
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
