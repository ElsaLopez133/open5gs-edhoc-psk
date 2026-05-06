#!/usr/bin/env bash
set -euo pipefail

# Measures UE-side crypto cost during 5G registration.
# Mirrors scripts/benchmark_crypto_cost.sh but parses the UE log instead of
# the AUSF/UDM logs. Requires a UERANSIM nr-ue built with AKA_CRYPTO /
# EDHOC_CRYPTO instrumentation in src/ue/nas/mm/auth.cpp.

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

usage() {
  cat <<EOF
Usage: $(basename "$0") <edhoc|aka> [options]

Runs N UE registrations and collects UE-side crypto timing logs.

Options:
  -n <runs>       Number of registration runs (default: ${RUNS})
  -t <seconds>    Timeout waiting for registration (default: ${WAIT_TIMEOUT})
  -c <seconds>    Cooldown between runs (default: ${COOLDOWN})
  -h, --help      Show this help
EOF
}

parse_args() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    edhoc|EDHOC) METHOD="EDHOC_PSK" ;;
    aka|AKA|5g-aka|5G_AKA|5G-AKA) METHOD="5G_AKA" ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown method: $1 (use 'edhoc' or 'aka')" >&2; exit 1 ;;
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
    echo "[bench-ue] Set authentication_method=EDHOC_PSK in MongoDB"
  else
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$unset: {"authentication_method": ""}}
      )' open5gs >/dev/null
    echo "[bench-ue] Removed authentication_method from MongoDB (default=5G-AKA)"
  fi
}

require_ue_instrumentation() {
  local ue_bin="${UERANSIM_BUILD_DIR}/nr-ue"
  if [[ ! -x "${ue_bin}" ]]; then
    echo "[bench-ue] ERROR: ${ue_bin} is missing or not executable" >&2
    exit 1
  fi
  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    if ! grep -aq 'EDHOC_CRYPTO:' "${ue_bin}"; then
      echo "[bench-ue] ERROR: ${ue_bin} lacks EDHOC_CRYPTO instrumentation" >&2
      exit 1
    fi
  else
    if ! grep -aq 'AKA_CRYPTO:' "${ue_bin}"; then
      echo "[bench-ue] ERROR: ${ue_bin} lacks AKA_CRYPTO instrumentation" >&2
      exit 1
    fi
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
  echo "[bench-ue] WARNING: registration did not complete within ${timeout_s}s" >&2
  return 1
}

extract_metric() {
  local logfile="$1"
  local label="$2"
  local unit="$3"

  if [[ ! -f "${logfile}" ]]; then
    echo "N/A"
    return
  fi

  awk -v label="${label}" -v unit="${unit}" '
    index($0, label) {
      for (i = 1; i <= NF; i++) {
        if ($i == label) {
          if (unit == "ns" && (i + 2) <= NF && $(i + 2) == "ns")
            value = $(i + 1);
          if (unit == "cycles" && (i + 4) <= NF && $(i + 4) == "cycles")
            value = $(i + 3);
        }
      }
    }
    END {
      if (value == "" || value == "N/A") print "N/A";
      else print value;
    }' "${logfile}"
}

sum_metrics() {
  awk '
    BEGIN {
      sum=0;
      for (i = 1; i < ARGC; i++) {
        if (ARGV[i] == "N/A" || ARGV[i] == "TIMEOUT" || ARGV[i] == "") {
          print "N/A"; exit;
        }
        sum += ARGV[i];
      }
      print sum;
    }' "$@"
}

run_single() {
  local run_id="$1"
  local ue_log="${LOG_DIR}/bench-crypto-ue-${run_id}.log"

  local ue_pid
  ue_pid=$(sudo bash -c "'${UERANSIM_BUILD_DIR}/nr-ue' -c '${UE_CONFIG}' >'${ue_log}' 2>&1 & echo \$!")

  local reg_ok=0
  if wait_for_registration "${ue_log}" "${WAIT_TIMEOUT}"; then
    reg_ok=1
  fi

  sudo kill "${ue_pid}" 2>/dev/null || true
  sleep 0.5
  sudo kill -9 "${ue_pid}" 2>/dev/null || true

  if [[ "${reg_ok}" -ne 1 ]]; then
    if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
      echo "${run_id},${METHOD},TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT"
    else
      echo "${run_id},${METHOD},TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT,TIMEOUT"
    fi
    return
  fi

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    local m1_prepare_ns m2_parse_ns m2_verify_ns m3_prepare_ns m4_process_ns exporter_ns total_ns
    local m1_prepare_cycles m2_parse_cycles m2_verify_cycles m3_prepare_cycles m4_process_cycles exporter_cycles total_cycles
    m1_prepare_ns=$(extract_metric "${ue_log}" 'initiator_prepare_message_1' ns)
    m2_parse_ns=$(extract_metric "${ue_log}" 'initiator_parse_message_2' ns)
    m2_verify_ns=$(extract_metric "${ue_log}" 'initiator_verify_message_2' ns)
    m3_prepare_ns=$(extract_metric "${ue_log}" 'initiator_prepare_message_3' ns)
    m4_process_ns=$(extract_metric "${ue_log}" 'initiator_process_message_4' ns)
    exporter_ns=$(extract_metric "${ue_log}" 'initiator_edhoc_exporter' ns)
    m1_prepare_cycles=$(extract_metric "${ue_log}" 'initiator_prepare_message_1' cycles)
    m2_parse_cycles=$(extract_metric "${ue_log}" 'initiator_parse_message_2' cycles)
    m2_verify_cycles=$(extract_metric "${ue_log}" 'initiator_verify_message_2' cycles)
    m3_prepare_cycles=$(extract_metric "${ue_log}" 'initiator_prepare_message_3' cycles)
    m4_process_cycles=$(extract_metric "${ue_log}" 'initiator_process_message_4' cycles)
    exporter_cycles=$(extract_metric "${ue_log}" 'initiator_edhoc_exporter' cycles)

    total_ns=$(sum_metrics "${m1_prepare_ns}" "${m2_parse_ns}" "${m2_verify_ns}" "${m3_prepare_ns}" "${m4_process_ns}" "${exporter_ns}")
    total_cycles=$(sum_metrics "${m1_prepare_cycles}" "${m2_parse_cycles}" "${m2_verify_cycles}" "${m3_prepare_cycles}" "${m4_process_cycles}" "${exporter_cycles}")

    echo "${run_id},${METHOD},${m1_prepare_ns},${m2_parse_ns},${m2_verify_ns},${m3_prepare_ns},${m4_process_ns},${exporter_ns},${total_ns},${m1_prepare_cycles},${m2_parse_cycles},${m2_verify_cycles},${m3_prepare_cycles},${m4_process_cycles},${exporter_cycles},${total_cycles}"
  else
    local milenage_ns kausf_ns res_star_ns total_ns
    local milenage_cycles kausf_cycles res_star_cycles total_cycles
    milenage_ns=$(extract_metric "${ue_log}" 'milenage_generate' ns)
    kausf_ns=$(extract_metric "${ue_log}" 'kdf_kausf' ns)
    res_star_ns=$(extract_metric "${ue_log}" 'res_star' ns)
    milenage_cycles=$(extract_metric "${ue_log}" 'milenage_generate' cycles)
    kausf_cycles=$(extract_metric "${ue_log}" 'kdf_kausf' cycles)
    res_star_cycles=$(extract_metric "${ue_log}" 'res_star' cycles)

    total_ns=$(sum_metrics "${milenage_ns}" "${kausf_ns}" "${res_star_ns}")
    total_cycles=$(sum_metrics "${milenage_cycles}" "${kausf_cycles}" "${res_star_cycles}")

    echo "${run_id},${METHOD},${milenage_ns},${kausf_ns},${res_star_ns},${total_ns},${milenage_cycles},${kausf_cycles},${res_star_cycles},${total_cycles}"
  fi

  rm -f "${ue_log}"
}

print_summary() {
  local results_file="$1"

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    echo "[bench-ue] Summary (ns):"
    awk -F',' '
      NR == 1 { next }
      $3 != "TIMEOUT" && $3 != "N/A" {
        labels[1]="m1_prepare"; labels[2]="m2_parse"; labels[3]="m2_verify";
        labels[4]="m3_prepare"; labels[5]="m4_process"; labels[6]="exporter";
        labels[7]="total";
        for (i = 3; i <= 9; i++) {
          idx = i - 2;
          n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= 7; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", labels[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"
    echo "[bench-ue] Summary (cycles):"
    awk -F',' '
      NR == 1 { next }
      $10 != "TIMEOUT" && $10 != "N/A" {
        labels[1]="m1_prepare"; labels[2]="m2_parse"; labels[3]="m2_verify";
        labels[4]="m3_prepare"; labels[5]="m4_process"; labels[6]="exporter";
        labels[7]="total";
        for (i = 10; i <= 16; i++) {
          idx = i - 9;
          n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= 7; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", labels[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"
  else
    echo "[bench-ue] Summary (ns):"
    awk -F',' '
      NR == 1 { next }
      $3 != "TIMEOUT" && $3 != "N/A" {
        labels[1]="milenage"; labels[2]="kdf_kausf"; labels[3]="res_star"; labels[4]="total";
        for (i = 3; i <= 6; i++) {
          idx = i - 2;
          n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= 4; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", labels[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"
    echo "[bench-ue] Summary (cycles):"
    awk -F',' '
      NR == 1 { next }
      $7 != "TIMEOUT" && $7 != "N/A" {
        labels[1]="milenage"; labels[2]="kdf_kausf"; labels[3]="res_star"; labels[4]="total";
        for (i = 7; i <= 10; i++) {
          idx = i - 6;
          n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= 4; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", labels[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"
  fi
}

main() {
  parse_args "$@"

  mkdir -p "${BENCH_DIR}" "${LOG_DIR}"
  local timestamp method_tag results_file failed line total
  timestamp=$(date +%Y%m%d-%H%M%S)
  method_tag=$(echo "${METHOD}" | tr '[:upper:]' '[:lower:]')
  results_file="${BENCH_DIR}/crypto_ue_${method_tag}_${timestamp}.csv"

  echo "[bench-ue] Method: ${METHOD}"
  echo "[bench-ue] Runs: ${RUNS}"
  echo "[bench-ue] Results: ${results_file}"
  echo ""

  set_auth_method "${METHOD}"
  require_ue_instrumentation

  if ! pgrep -f 'open5gs-amfd' >/dev/null; then
    echo "[bench-ue] ERROR: open5gs-amfd is not running" >&2
    exit 1
  fi
  if ! pgrep -f 'nr-gnb' >/dev/null; then
    echo "[bench-ue] ERROR: nr-gnb is not running" >&2
    exit 1
  fi
  if pgrep -f 'nr-ue' >/dev/null; then
    echo "[bench-ue] WARNING: nr-ue is already running, stopping it first" >&2
    sudo pkill -f "${UERANSIM_BUILD_DIR}/nr-ue" || true
    sleep 1
  fi

  sudo -v

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    echo "run,method,m1_prepare_ns,m2_parse_ns,m2_verify_ns,m3_prepare_ns,m4_process_ns,exporter_ns,total_ns,m1_prepare_cycles,m2_parse_cycles,m2_verify_cycles,m3_prepare_cycles,m4_process_cycles,exporter_cycles,total_cycles" > "${results_file}"
  else
    echo "run,method,milenage_ns,kdf_kausf_ns,res_star_ns,total_ns,milenage_cycles,kdf_kausf_cycles,res_star_cycles,total_cycles" > "${results_file}"
  fi

  failed=0
  for i in $(seq 1 "${RUNS}"); do
    printf "[bench-ue] Run %d/%d ... " "${i}" "${RUNS}"
    line=$(run_single "${i}")
    echo "${line}" >> "${results_file}"
    total=$(echo "${line}" | awk -F',' '{print $NF}')
    if [[ "${total}" == "TIMEOUT" || "${total}" == "N/A" ]]; then
      printf "TIMEOUT\n"
      ((failed++))
    else
      printf "%s ns\n" "${total}"
    fi

    if [[ "${i}" -lt "${RUNS}" ]]; then
      sleep "${COOLDOWN}"
    fi
  done

  echo ""
  echo "[bench-ue] Complete: $((RUNS - failed))/${RUNS} successful"
  echo "[bench-ue] Results saved to: ${results_file}"
  echo ""
  print_summary "${results_file}"
}

main "$@"