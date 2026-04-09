#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [--no-gnb] [--no-ue]

Commands:
  all         open5gs_cycle all + ueransim_cycle all
  rebuild     rebuild Open5GS + UERANSIM
  stop        stop Open5GS + UERANSIM
  tun         reset ogstun only
  start-core  start Open5GS only
  start-ran   start UERANSIM only [--no-gnb|--no-ue]
  check       check Open5GS + UERANSIM
EOF
}

OPEN5GS_SCRIPT="${SCRIPT_DIR}/open5gs_cycle.sh"
UERANSIM_SCRIPT="${SCRIPT_DIR}/ueransim_cycle.sh"

main() {
  if [[ ! -x "${OPEN5GS_SCRIPT}" ]] || [[ ! -x "${UERANSIM_SCRIPT}" ]]; then
    echo "Missing required executable scripts under ${SCRIPT_DIR}" >&2
    echo "Run: chmod +x ${SCRIPT_DIR}/open5gs_cycle.sh ${SCRIPT_DIR}/ueransim_cycle.sh" >&2
    exit 1
  fi

  local cmd="${1:-all}"
  shift || true

  case "${cmd}" in
    all)
      "${OPEN5GS_SCRIPT}" all
      "${UERANSIM_SCRIPT}" all "$@"
      ;;
    rebuild)
      "${OPEN5GS_SCRIPT}" rebuild
      "${UERANSIM_SCRIPT}" rebuild
      ;;
    stop)
      "${UERANSIM_SCRIPT}" stop
      "${OPEN5GS_SCRIPT}" stop
      ;;
    tun)
      "${OPEN5GS_SCRIPT}" tun
      ;;
    start-core)
      "${OPEN5GS_SCRIPT}" start
      ;;
    start-ran)
      "${UERANSIM_SCRIPT}" start "$@"
      ;;
    check)
      "${OPEN5GS_SCRIPT}" check
      "${UERANSIM_SCRIPT}" check
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
