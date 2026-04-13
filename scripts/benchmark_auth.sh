#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN5GS_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UERANSIM_ROOT="${UERANSIM_ROOT:-/home/elsa/projects/UERANSIM}"
UERANSIM_BUILD_DIR="${UERANSIM_ROOT}/cmake-build-release"
UE_CONFIG="${UERANSIM_ROOT}/config/open5gs-ue.yaml"
LOG_DIR="${OPEN5GS_ROOT}/run_logs"
BENCH_DIR="${OPEN5GS_ROOT}/benchmarks"

RUNS=30
METHOD=""
WAIT_TIMEOUT=15
COOLDOWN=2

require_latency_instrumentation() {
  local amf_bin="${OPEN5GS_ROOT}/install/bin/open5gs-amfd"
  local ausf_bin="${OPEN5GS_ROOT}/install/bin/open5gs-ausfd"

  if ! grep -aq 'AUTH_LATENCY:' "${amf_bin}"; then
    echo "[bench] ERROR: ${amf_bin} does not contain AUTH_LATENCY instrumentation" >&2
    echo "[bench] Rebuild and install Open5GS, then restart the core." >&2
    echo "[bench] Suggested sequence: ./scripts/open5gs_ueransim_cycle.sh rebuild && ./scripts/open5gs_ueransim_cycle.sh stop && ./scripts/open5gs_ueransim_cycle.sh start-core" >&2
    exit 1
  fi

  if [[ "${METHOD}" == "EDHOC_PSK" ]] && ! grep -aq 'EDHOC_TIMING:' "${ausf_bin}"; then
    echo "[bench] ERROR: ${ausf_bin} does not contain EDHOC_TIMING instrumentation" >&2
    echo "[bench] Rebuild and install Open5GS, then restart the core." >&2
    echo "[bench] Suggested sequence: ./scripts/open5gs_ueransim_cycle.sh rebuild && ./scripts/open5gs_ueransim_cycle.sh stop && ./scripts/open5gs_ueransim_cycle.sh start-core" >&2
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <edhoc|aka> [options]

Runs N UE registrations and collects AUTH_LATENCY and EDHOC_TIMING from logs.

Options:
  -n <runs>       Number of registration runs (default: ${RUNS})
  -t <seconds>    Timeout waiting for registration (default: ${WAIT_TIMEOUT})
  -c <seconds>    Cooldown between runs (default: ${COOLDOWN})
  -h, --help      Show this help

Prerequisites:
  - Open5GS core must be running (use open5gs_ueransim_cycle.sh start-core)
  - UERANSIM gNB must be running (use open5gs_ueransim_cycle.sh start-ran --no-ue)
  - The subscriber must exist in MongoDB

Example:
  $(basename "$0") edhoc -n 30
  $(basename "$0") aka -n 30
EOF
}

parse_args() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    edhoc|EDHOC) METHOD="EDHOC_PSK" ;;
    aka|AKA|5g-aka) METHOD="5G_AKA" ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown method: $1 (use 'edhoc' or 'aka')" >&2
      exit 1
      ;;
  esac
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -n) RUNS="${2:?missing count}"; shift 2 ;;
      -t) WAIT_TIMEOUT="${2:?missing timeout}"; shift 2 ;;
      -c) COOLDOWN="${2:?missing cooldown}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
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
    echo "[bench] Set authentication_method=EDHOC_PSK in MongoDB"
  else
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$unset: {"authentication_method": ""}}
      )' open5gs >/dev/null
    echo "[bench] Removed authentication_method from MongoDB (default=5G-AKA)"
  fi
}

wait_for_registration() {
  local ue_log="$1"
  local timeout_s="$2"
  local waited=0

  while (( waited < timeout_s )); do
    if [[ -f "${ue_log}" ]] && grep -q 'Initial Registration is successful' "${ue_log}" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
    waited=$((waited + 1))
  done

  echo "[bench] WARNING: registration did not complete within ${timeout_s}s" >&2
  return 1
}

record_amf_line_count() {
  local amf_log="${LOG_DIR}/open5gs-amfd.log"
  if [[ -f "${amf_log}" ]]; then
    wc -l < "${amf_log}"
  else
    echo 0
  fi
}

record_ausf_line_count() {
  local ausf_log="${LOG_DIR}/open5gs-ausfd.log"
  if [[ -f "${ausf_log}" ]]; then
    wc -l < "${ausf_log}"
  else
    echo 0
  fi
}

run_single() {
  local run_id="$1"
  local ue_log="${LOG_DIR}/bench-ue-${run_id}.log"

  local amf_before ausf_before
  amf_before=$(record_amf_line_count)
  ausf_before=$(record_ausf_line_count)

  # Start UE
  local ue_pid
  ue_pid=$(sudo bash -c "'${UERANSIM_BUILD_DIR}/nr-ue' \
    -c '${UE_CONFIG}' \
    >'${ue_log}' 2>&1 & echo \$!")

  local reg_ok=0
  if wait_for_registration "${ue_log}" "${WAIT_TIMEOUT}"; then
    reg_ok=1
  fi

  # Stop UE
  sudo kill "${ue_pid}" 2>/dev/null || true
  sleep 0.5
  sudo kill -9 "${ue_pid}" 2>/dev/null || true

  # Extract new lines from AMF and AUSF logs
  local amf_log="${LOG_DIR}/open5gs-amfd.log"
  local ausf_log="${LOG_DIR}/open5gs-ausfd.log"

  local auth_latency="TIMEOUT"
  if [[ "${reg_ok}" -eq 1 ]] && [[ -f "${amf_log}" ]]; then
    auth_latency=$(tail -n +"$((amf_before + 1))" "${amf_log}" \
      | grep -o 'AUTH_LATENCY: [^ ]* [0-9]* us' \
      | tail -1 \
      | awk '{print $3}' || echo "PARSE_ERROR")
  fi

  local leg1_us="N/A" leg2_us="N/A"
  if [[ "${METHOD}" == "EDHOC_PSK" ]] && [[ -f "${ausf_log}" ]]; then
    leg1_us=$(tail -n +"$((ausf_before + 1))" "${ausf_log}" \
      | grep -o 'leg1_m1_m2 [0-9]* us' \
      | tail -1 \
      | awk '{print $2}' || echo "N/A")
    leg2_us=$(tail -n +"$((ausf_before + 1))" "${ausf_log}" \
      | grep -o 'leg2_m3_m4_kausf [0-9]* us' \
      | tail -1 \
      | awk '{print $2}' || echo "N/A")
  fi

  echo "${run_id},${METHOD},${auth_latency},${leg1_us},${leg2_us}"

  # Clean up per-run UE log
  rm -f "${ue_log}"
}

main() {
  parse_args "$@"

  mkdir -p "${BENCH_DIR}"
  local timestamp
  timestamp=$(date +%Y%m%d-%H%M%S)
  local method_tag
  method_tag=$(echo "${METHOD}" | tr '[:upper:]' '[:lower:]')
  local results_file="${BENCH_DIR}/auth_latency_${method_tag}_${timestamp}.csv"

  echo "[bench] Method: ${METHOD}"
  echo "[bench] Runs: ${RUNS}"
  echo "[bench] Results: ${results_file}"
  echo ""

  # Set auth method in MongoDB
  set_auth_method "${METHOD}"

  # Write CSV header
  echo "run,method,auth_latency_us,ausf_leg1_us,ausf_leg2_us" > "${results_file}"

  # Check prerequisites
  require_latency_instrumentation

  if ! pgrep -f 'open5gs-amfd' >/dev/null; then
    echo "[bench] ERROR: open5gs-amfd is not running" >&2
    exit 1
  fi
  if ! pgrep -f 'nr-gnb' >/dev/null; then
    echo "[bench] ERROR: nr-gnb is not running" >&2
    exit 1
  fi
  if pgrep -f 'nr-ue' >/dev/null; then
    echo "[bench] WARNING: nr-ue is already running, stopping it first" >&2
    sudo pkill -f "${UERANSIM_BUILD_DIR}/nr-ue" || true
    sleep 1
  fi

  sudo -v

  local failed=0
  for i in $(seq 1 "${RUNS}"); do
    printf "[bench] Run %d/%d ... " "${i}" "${RUNS}"
    local line
    line=$(run_single "${i}")
    echo "${line}" >> "${results_file}"

    local latency
    latency=$(echo "${line}" | cut -d',' -f3)
    if [[ "${latency}" == "TIMEOUT" || "${latency}" == "PARSE_ERROR" ]]; then
      printf "TIMEOUT\n"
      ((failed++))
    else
      printf "%s us\n" "${latency}"
    fi

    # Cooldown between runs
    if [[ "${i}" -lt "${RUNS}" ]]; then
      sleep "${COOLDOWN}"
    fi
  done

  echo ""
  echo "[bench] Complete: $((RUNS - failed))/${RUNS} successful"
  echo "[bench] Results saved to: ${results_file}"
  echo ""

  # Print summary statistics
  if command -v awk >/dev/null; then
    echo "[bench] Summary (auth_latency_us):"
    awk -F',' 'NR>1 && $3 != "TIMEOUT" && $3 != "PARSE_ERROR" {
      n++; sum+=$3; vals[n]=$3
      if(n==1 || $3<min) min=$3
      if(n==1 || $3>max) max=$3
    }
    END {
      if(n==0) { print "  No successful runs"; exit }
      mean=sum/n
      for(i=1;i<=n;i++) sumsq+=($3-mean)^2
      # Sort for median
      for(i=1;i<=n;i++) for(j=i+1;j<=n;j++) if(vals[i]>vals[j]) {t=vals[i];vals[i]=vals[j];vals[j]=t}
      if(n%2==1) median=vals[int(n/2)+1]; else median=(vals[n/2]+vals[n/2+1])/2
      printf "  n=%d  mean=%.0f  median=%.0f  min=%d  max=%d\n", n, mean, median, min, max
    }' "${results_file}"
  fi
}

main "$@"
