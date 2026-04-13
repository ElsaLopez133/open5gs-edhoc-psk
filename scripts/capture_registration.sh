#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BENCH_DIR="${BENCH_DIR:-${OPEN5GS_ROOT}/benchmarks}"
LOG_DIR="${LOG_DIR:-${OPEN5GS_ROOT}/run_logs}"
DEFAULT_INTERFACE="${CAPTURE_INTERFACE:-lo}"
DEFAULT_SBI_PORT="${SBI_PORT:-7777}"
WAIT_TIMEOUT=30
METHOD=""
OUTPUT_FILE=""
TEARDOWN=0

usage() {
  cat <<EOF
Usage: $(basename "$0") <edhoc|aka> [options]

Capture one full UE registration into a pcap for EDHOC or 5G-AKA.

Options:
  -o <file>       Output pcap path (default: benchmarks/<method>_registration_<timestamp>.pcap)
  -i <iface>      Capture interface (default: ${DEFAULT_INTERFACE})
  -p <port>       AUSF SBI TCP port in capture filter (default: ${DEFAULT_SBI_PORT})
  -t <seconds>    Timeout waiting for UE registration (default: ${WAIT_TIMEOUT})
  --teardown      Stop Open5GS and UERANSIM after capture completes
  -h, --help      Show this help

Examples:
  $(basename "$0") edhoc
  $(basename "$0") aka -o benchmarks/aka_registration.pcap
EOF
}

INTERFACE="${DEFAULT_INTERFACE}"
SBI_PORT="${DEFAULT_SBI_PORT}"
TEMP_PCAP=""
TSHARK_PID=""
TSHARK_LOG=""
REGISTRATION_DONE=0

parse_args() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    edhoc|EDHOC) METHOD="EDHOC_PSK" ;;
    aka|AKA|5g-aka|5G-AKA) METHOD="5G_AKA" ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "[capture] Unknown method: $1 (use 'edhoc' or 'aka')" >&2
      exit 1
      ;;
  esac
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o)
        OUTPUT_FILE="${2:?missing output file}"
        shift 2
        ;;
      -i)
        INTERFACE="${2:?missing interface}"
        shift 2
        ;;
      -p)
        SBI_PORT="${2:?missing port}"
        shift 2
        ;;
      -t)
        WAIT_TIMEOUT="${2:?missing timeout}"
        shift 2
        ;;
      --teardown)
        TEARDOWN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "[capture] Unknown option: $1" >&2
        exit 1
        ;;
    esac
  done
}

set_auth_method() {
  local method="$1"

  if [[ "${method}" == "EDHOC_PSK" ]]; then
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$set: {"authentication_method": "EDHOC_PSK"}}
      )' open5gs >/dev/null
    echo "[capture] Set authentication_method=EDHOC_PSK"
  else
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$unset: {"authentication_method": ""}}
      )' open5gs >/dev/null
    echo "[capture] Removed authentication_method (default=5G-AKA)"
  fi
}

wait_for_registration() {
  local ue_log="${LOG_DIR}/nr-ue.log"
  local waited=0

  while (( waited < WAIT_TIMEOUT )); do
    if [[ -f "${ue_log}" ]] && grep -q 'Initial Registration is successful' "${ue_log}" 2>/dev/null; then
      return 0
    fi
    sleep 1
    ((waited+=1))
  done

  return 1
}

stop_capture() {
  if [[ -n "${TSHARK_PID}" ]] && sudo kill -0 "${TSHARK_PID}" 2>/dev/null; then
    sudo kill "${TSHARK_PID}" 2>/dev/null || true
    wait "${TSHARK_PID}" 2>/dev/null || true
  fi
}

cleanup() {
  local status=$?

  stop_capture

  if [[ "${TEARDOWN}" -eq 1 ]]; then
    "${SCRIPT_DIR}/ueransim_cycle.sh" stop >/dev/null 2>&1 || true
    "${SCRIPT_DIR}/open5gs_cycle.sh" stop >/dev/null 2>&1 || true
  fi

  if [[ ${status} -ne 0 ]]; then
    echo "[capture] FAILED" >&2
    if [[ -n "${TSHARK_LOG}" && -f "${TSHARK_LOG}" ]]; then
      echo "[capture] tshark log: ${TSHARK_LOG}" >&2
      tail -n 20 "${TSHARK_LOG}" >&2 || true
    fi
  fi
}

start_capture() {
  local tshark_bin
  tshark_bin="$(command -v tshark || true)"
  if [[ -z "${tshark_bin}" ]]; then
    echo "[capture] ERROR: tshark not found in PATH" >&2
    exit 1
  fi

  TEMP_PCAP="/tmp/$(basename "${OUTPUT_FILE}")"
  TSHARK_LOG="/tmp/$(basename "${OUTPUT_FILE}" .pcap).log"

  sudo rm -f "${TEMP_PCAP}" "${TSHARK_LOG}"

  sudo "${tshark_bin}" -i "${INTERFACE}" \
    -w "${TEMP_PCAP}" \
    -f "sctp or (tcp port ${SBI_PORT})" >"${TSHARK_LOG}" 2>&1 &
  TSHARK_PID=$!

  sleep 1
  if ! ps -p "${TSHARK_PID}" >/dev/null 2>&1; then
    echo "[capture] ERROR: tshark exited early" >&2
    cat "${TSHARK_LOG}" >&2 || true
    exit 1
  fi

  echo "[capture] Started tshark on ${INTERFACE} (pid=${TSHARK_PID})"
  echo "[capture] Temporary capture: ${TEMP_PCAP}"
}

save_capture() {
  mkdir -p "$(dirname "${OUTPUT_FILE}")"
  sudo cp "${TEMP_PCAP}" "${OUTPUT_FILE}"
  sudo chown "$(id -un):$(id -gn)" "${OUTPUT_FILE}"
  echo "[capture] Saved pcap to ${OUTPUT_FILE}"
}

run_registration_cycle() {
  echo "[capture] Restarting Open5GS and UERANSIM"
  "${SCRIPT_DIR}/open5gs_cycle.sh" stop
  "${SCRIPT_DIR}/ueransim_cycle.sh" stop
  "${SCRIPT_DIR}/open5gs_cycle.sh" all
  "${SCRIPT_DIR}/ueransim_cycle.sh" all

  echo "[capture] Waiting for UE registration"
  if ! wait_for_registration; then
    echo "[capture] ERROR: UE registration did not complete within ${WAIT_TIMEOUT}s" >&2
    exit 1
  fi

  REGISTRATION_DONE=1
  echo "[capture] UE registration completed"
}

main() {
  parse_args "$@"

  local timestamp method_tag
  timestamp="$(date +%Y%m%d-%H%M%S)"
  method_tag="$(echo "${METHOD}" | tr '[:upper:]' '[:lower:]')"

  if [[ -z "${OUTPUT_FILE}" ]]; then
    OUTPUT_FILE="${BENCH_DIR}/${method_tag}_registration_${timestamp}.pcap"
  elif [[ "${OUTPUT_FILE}" != /* ]]; then
    OUTPUT_FILE="${OPEN5GS_ROOT}/${OUTPUT_FILE}"
  fi

  echo "[capture] Method: ${METHOD}"
  echo "[capture] Interface: ${INTERFACE}"
  echo "[capture] SBI port filter: ${SBI_PORT}"
  echo "[capture] Output: ${OUTPUT_FILE}"

  sudo -v
  mkdir -p "${BENCH_DIR}"

  set_auth_method "${METHOD}"
  trap cleanup EXIT

  start_capture
  run_registration_cycle
  stop_capture
  save_capture

  echo "[capture] Complete"
}

main "$@"
