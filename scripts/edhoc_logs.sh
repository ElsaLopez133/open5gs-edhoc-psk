#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${LOG_DIR:-${OPEN5GS_ROOT}/run_logs}"

MODE="print"
PATTERN='EDHOC|edhoc'
LINES=200
COMPONENTS=()

usage() {
  cat <<EOF
Usage: $(basename "$0") [print|follow|save] [options] [components...]

Components:
  ue amf ausf udm smf upf gnb nrf nssf scp all

Options:
  --pattern <regex>   Filter pattern (default: ${PATTERN})
  --lines <n>         Lines to read from each file in print/save (default: ${LINES})
  -h, --help          Show this help

Examples:
  $(basename "$0") print ue amf ausf udm
  $(basename "$0") follow --pattern 'EDHOC|Authentication' ue amf ausf udm
  $(basename "$0") save all
EOF
}

component_file() {
  case "$1" in
    ue) echo "${LOG_DIR}/nr-ue.log" ;;
    amf) echo "${LOG_DIR}/open5gs-amfd.log" ;;
    ausf) echo "${LOG_DIR}/open5gs-ausfd.log" ;;
    udm) echo "${LOG_DIR}/open5gs-udmd.log" ;;
    smf) echo "${LOG_DIR}/open5gs-smfd.log" ;;
    upf) echo "${LOG_DIR}/open5gs-upfd.log" ;;
    gnb) echo "${LOG_DIR}/nr-gnb.log" ;;
    nrf) echo "${LOG_DIR}/open5gs-nrfd.log" ;;
    nssf) echo "${LOG_DIR}/open5gs-nssfd.log" ;;
    scp) echo "${LOG_DIR}/open5gs-scpd.log" ;;
    *)
      echo "Unknown component: $1" >&2
      exit 1
      ;;
  esac
}

parse_args() {
  if [[ $# -gt 0 ]]; then
    case "$1" in
      print|follow|save)
        MODE="$1"
        shift
        ;;
    esac
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pattern)
        PATTERN="${2:-}"
        shift 2
        ;;
      --lines)
        LINES="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        COMPONENTS+=("$1")
        shift
        ;;
    esac
  done

  if [[ ${#COMPONENTS[@]} -eq 0 ]]; then
    COMPONENTS=(ue amf ausf udm)
  fi

  if [[ " ${COMPONENTS[*]} " == *" all "* ]]; then
    COMPONENTS=(ue amf ausf udm smf upf gnb nrf nssf scp)
  fi
}

strip_ansi() {
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'
}

print_mode() {
  local comp f
  for comp in "${COMPONENTS[@]}"; do
    f="$(component_file "${comp}")"
    echo "===== ${comp^^} (${f}) ====="
    if [[ ! -f "${f}" ]]; then
      echo "missing log file"
      echo
      continue
    fi
    tail -n "${LINES}" "${f}" | strip_ansi | grep -Ei "${PATTERN}" || true
    echo
  done
}

follow_mode() {
  local files=()
  local comp f
  for comp in "${COMPONENTS[@]}"; do
    f="$(component_file "${comp}")"
    if [[ -f "${f}" ]]; then
      files+=("${f}")
    fi
  done

  if [[ ${#files[@]} -eq 0 ]]; then
    echo "No log files found under ${LOG_DIR}" >&2
    exit 1
  fi

  echo "Following ${#files[@]} logs with pattern: ${PATTERN}"
  tail -F "${files[@]}" | strip_ansi | grep --line-buffered -Ei "${PATTERN}"
}

save_mode() {
  local out
  out="${LOG_DIR}/edhoc-filtered-$(date +%Y%m%d-%H%M%S).log"
  {
    echo "# Pattern: ${PATTERN}"
    echo "# Components: ${COMPONENTS[*]}"
    echo "# Generated: $(date --iso-8601=seconds)"
    echo
  } >"${out}"

  local comp f
  for comp in "${COMPONENTS[@]}"; do
    f="$(component_file "${comp}")"
    {
      echo "===== ${comp^^} (${f}) ====="
      if [[ -f "${f}" ]]; then
        tail -n "${LINES}" "${f}" | strip_ansi | grep -Ei "${PATTERN}" || true
      else
        echo "missing log file"
      fi
      echo
    } >>"${out}"
  done

  echo "Saved filtered output to: ${out}"
}

main() {
  parse_args "$@"
  case "${MODE}" in
    print) print_mode ;;
    follow) follow_mode ;;
    save) save_mode ;;
    *) echo "Unknown mode: ${MODE}" >&2; exit 1 ;;
  esac
}

main "$@"
