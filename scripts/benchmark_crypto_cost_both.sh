#!/usr/bin/env bash
set -euo pipefail
umask 002

# Measures crypto cost on both the network side (AUSF/UDM) and the UE side
# (UERANSIM nr-ue) from the SAME registration. Each row of the CSV holds the
# per-message timings for both endpoints, so per-run scatter plots / paired
# comparisons are possible.
#
# Requires:
#   - Open5GS built with AKA_CRYPTO/EDHOC_CRYPTO instrumentation (UDM/AUSF)
#   - UERANSIM nr-ue built with AKA_CRYPTO/EDHOC_CRYPTO instrumentation
#     (src/ue/nas/mm/auth.cpp)

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
OUTPUT_TAG=""

# CPU pinning. Override via env vars or -p / -P flags.
# Default to non-sibling P-cores on a hybrid Intel layout.
UE_CORE="${UE_CORE:-6}"
PIN_UE=1

usage() {
  cat <<EOF
Usage: $(basename "$0") <edhoc|aka> [options]

Runs N UE registrations and collects crypto timing logs from BOTH the network
side (AUSF/UDM) and the UE side (nr-ue) for each run.

Options:
  -n <runs>       Number of registration runs (default: ${RUNS})
  -t <seconds>    Timeout waiting for registration (default: ${WAIT_TIMEOUT})
  -c <seconds>    Cooldown between runs (default: ${COOLDOWN})
  -o <name>       Add name to output file before timestamp
  -p <core>       CPU core to pin nr-ue to via taskset (default: ${UE_CORE})
  -P              Disable CPU pinning of nr-ue
  -h, --help      Show this help
EOF
}

set_output_tag() {
  local tag="$1"
  if [[ ! "${tag}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Invalid output name: ${tag} (use only letters, digits, '.', '_' or '-')" >&2
    exit 1
  fi
  OUTPUT_TAG="${tag}"
}

parse_args() {
  if [[ $# -lt 1 ]]; then usage; exit 1; fi
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
      -o) set_output_tag "${2:?missing output name}"; shift 2 ;;
      -p) UE_CORE="${2:?missing core}"; PIN_UE=1; shift 2 ;;
      -P) PIN_UE=0; shift 1 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done
}

set_auth_method() {
  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$set: {"authentication_method": "EDHOC_PSK"}}
      )' open5gs >/dev/null
    echo "[bench-both] Set authentication_method=EDHOC_PSK in MongoDB"
  else
    mongosh --quiet --eval '
      db.subscribers.updateOne(
        {"imsi":"001010000000001"},
        {$unset: {"authentication_method": ""}}
      )' open5gs >/dev/null
    echo "[bench-both] Removed authentication_method from MongoDB (default=5G-AKA)"
  fi
}

require_instrumentation() {
  local ausf_bin="${OPEN5GS_ROOT}/install/bin/open5gs-ausfd"
  local udm_bin="${OPEN5GS_ROOT}/install/bin/open5gs-udmd"
  local ue_bin="${UERANSIM_BUILD_DIR}/nr-ue"

  if [[ ! -x "${ue_bin}" ]]; then
    echo "[bench-both] ERROR: ${ue_bin} is missing or not executable" >&2
    exit 1
  fi

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    grep -aq 'EDHOC_CRYPTO:' "${ausf_bin}" || { echo "[bench-both] ERROR: ${ausf_bin} lacks EDHOC_CRYPTO instrumentation" >&2; exit 1; }
    grep -aq 'EDHOC_CRYPTO:' "${ue_bin}"   || { echo "[bench-both] ERROR: ${ue_bin} lacks EDHOC_CRYPTO instrumentation" >&2; exit 1; }
  else
    grep -aq 'AKA_CRYPTO:' "${udm_bin}" || { echo "[bench-both] ERROR: ${udm_bin} lacks AKA_CRYPTO instrumentation" >&2; exit 1; }
    grep -aq 'AKA_CRYPTO:' "${ue_bin}"  || { echo "[bench-both] ERROR: ${ue_bin} lacks AKA_CRYPTO instrumentation" >&2; exit 1; }
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
  echo "[bench-both] WARNING: registration did not complete within ${timeout_s}s" >&2
  return 1
}

record_line_count() {
  local logfile="$1"
  if [[ -f "${logfile}" ]]; then wc -l < "${logfile}"; else echo 0; fi
}

# Network-side extractor: tail from `before` line of `logfile`
extract_net_metric() {
  local logfile="$1" before="$2" label="$3" unit="$4"
  if [[ ! -f "${logfile}" ]]; then echo "N/A"; return; fi
  tail -n +"$((before + 1))" "${logfile}" | awk -v label="${label}" -v unit="${unit}" '
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
    END { if (value == "" || value == "N/A") print "N/A"; else print value; }'
}

# UE-side extractor: whole UE log
extract_ue_metric() {
  local logfile="$1" label="$2" unit="$3"
  if [[ ! -f "${logfile}" ]]; then echo "N/A"; return; fi
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
    END { if (value == "" || value == "N/A") print "N/A"; else print value; }' "${logfile}"
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
  local ausf_log="${LOG_DIR}/open5gs-ausfd.log"
  local udm_log="${LOG_DIR}/open5gs-udmd.log"
  local ausf_before udm_before
  ausf_before=$(record_line_count "${ausf_log}")
  udm_before=$(record_line_count "${udm_log}")

  local ue_pid pin_prefix=""
  if [[ "${PIN_UE}" -eq 1 ]]; then
    pin_prefix="taskset -c ${UE_CORE} "
  fi
  ue_pid=$(sudo bash -c "${pin_prefix}'${UERANSIM_BUILD_DIR}/nr-ue' -c '${UE_CONFIG}' >'${ue_log}' 2>&1 & echo \$!")

  local reg_ok=0
  if wait_for_registration "${ue_log}" "${WAIT_TIMEOUT}"; then
    reg_ok=1
  fi

  sudo kill "${ue_pid}" 2>/dev/null || true
  sleep 0.5
  sudo kill -9 "${ue_pid}" 2>/dev/null || true

  if [[ "${reg_ok}" -ne 1 ]]; then
    rm -f "${ue_log}"
    if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
      # 2 + 6 net_ns + 1 net_total_ns + 6 net_cyc + 1 net_total_cyc + 6 ue_ns + 1 ue_total_ns + 6 ue_cyc + 1 ue_total_cyc = 30
      local n_timeout=28
      local row="${run_id},${METHOD}"
      for ((i=0;i<n_timeout;i++)); do row+=",TIMEOUT"; done
      echo "${row}"
    else
      # 2 + 3 net_ns + 1 + 3 net_cyc + 1 + 3 ue_ns + 1 + 3 ue_cyc + 1 = 16
      local n_timeout=14
      local row="${run_id},${METHOD}"
      for ((i=0;i<n_timeout;i++)); do row+=",TIMEOUT"; done
      echo "${row}"
    fi
    return
  fi

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    # ----- network (AUSF responder) -----
    local n_m1_ns n_m2_ns n_m3p_ns n_m3v_ns n_m4_ns n_exp_ns n_total_ns
    local n_m1_c  n_m2_c  n_m3p_c  n_m3v_c  n_m4_c  n_exp_c  n_total_c
    n_m1_ns=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_process_message_1' ns)
    n_m2_ns=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_prepare_message_2' ns)
    n_m3p_ns=$(extract_net_metric "${ausf_log}" "${ausf_before}" 'responder_parse_message_3'   ns)
    n_m3v_ns=$(extract_net_metric "${ausf_log}" "${ausf_before}" 'responder_verify_message_3'  ns)
    n_m4_ns=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_prepare_message_4' ns)
    n_exp_ns=$(extract_net_metric "${ausf_log}" "${ausf_before}" 'responder_edhoc_exporter'    ns)
    n_m1_c=$(extract_net_metric   "${ausf_log}" "${ausf_before}" 'responder_process_message_1' cycles)
    n_m2_c=$(extract_net_metric   "${ausf_log}" "${ausf_before}" 'responder_prepare_message_2' cycles)
    n_m3p_c=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_parse_message_3'   cycles)
    n_m3v_c=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_verify_message_3'  cycles)
    n_m4_c=$(extract_net_metric   "${ausf_log}" "${ausf_before}" 'responder_prepare_message_4' cycles)
    n_exp_c=$(extract_net_metric  "${ausf_log}" "${ausf_before}" 'responder_edhoc_exporter'    cycles)
    n_total_ns=$(sum_metrics "${n_m1_ns}" "${n_m2_ns}" "${n_m3p_ns}" "${n_m3v_ns}" "${n_m4_ns}" "${n_exp_ns}")
    n_total_c=$(sum_metrics  "${n_m1_c}"  "${n_m2_c}"  "${n_m3p_c}"  "${n_m3v_c}"  "${n_m4_c}"  "${n_exp_c}")

    # ----- UE (initiator) -----
    local u_m1_ns u_m2p_ns u_m2v_ns u_m3_ns u_m4_ns u_exp_ns u_total_ns
    local u_m1_c  u_m2p_c  u_m2v_c  u_m3_c  u_m4_c  u_exp_c  u_total_c
    u_m1_ns=$(extract_ue_metric  "${ue_log}" 'initiator_prepare_message_1' ns)
    u_m2p_ns=$(extract_ue_metric "${ue_log}" 'initiator_parse_message_2'   ns)
    u_m2v_ns=$(extract_ue_metric "${ue_log}" 'initiator_verify_message_2'  ns)
    u_m3_ns=$(extract_ue_metric  "${ue_log}" 'initiator_prepare_message_3' ns)
    u_m4_ns=$(extract_ue_metric  "${ue_log}" 'initiator_process_message_4' ns)
    u_exp_ns=$(extract_ue_metric "${ue_log}" 'initiator_edhoc_exporter'    ns)
    u_m1_c=$(extract_ue_metric   "${ue_log}" 'initiator_prepare_message_1' cycles)
    u_m2p_c=$(extract_ue_metric  "${ue_log}" 'initiator_parse_message_2'   cycles)
    u_m2v_c=$(extract_ue_metric  "${ue_log}" 'initiator_verify_message_2'  cycles)
    u_m3_c=$(extract_ue_metric   "${ue_log}" 'initiator_prepare_message_3' cycles)
    u_m4_c=$(extract_ue_metric   "${ue_log}" 'initiator_process_message_4' cycles)
    u_exp_c=$(extract_ue_metric  "${ue_log}" 'initiator_edhoc_exporter'    cycles)
    u_total_ns=$(sum_metrics "${u_m1_ns}" "${u_m2p_ns}" "${u_m2v_ns}" "${u_m3_ns}" "${u_m4_ns}" "${u_exp_ns}")
    u_total_c=$(sum_metrics  "${u_m1_c}"  "${u_m2p_c}"  "${u_m2v_c}"  "${u_m3_c}"  "${u_m4_c}"  "${u_exp_c}")

    echo "${run_id},${METHOD},${n_m1_ns},${n_m2_ns},${n_m3p_ns},${n_m3v_ns},${n_m4_ns},${n_exp_ns},${n_total_ns},${n_m1_c},${n_m2_c},${n_m3p_c},${n_m3v_c},${n_m4_c},${n_exp_c},${n_total_c},${u_m1_ns},${u_m2p_ns},${u_m2v_ns},${u_m3_ns},${u_m4_ns},${u_exp_ns},${u_total_ns},${u_m1_c},${u_m2p_c},${u_m2v_c},${u_m3_c},${u_m4_c},${u_exp_c},${u_total_c}"
  else
    # ----- network (UDM) -----
    local n_mil_ns n_kausf_ns n_xres_ns n_total_ns
    local n_mil_c  n_kausf_c  n_xres_c  n_total_c
    n_mil_ns=$(extract_net_metric   "${udm_log}" "${udm_before}" 'milenage_generate' ns)
    n_kausf_ns=$(extract_net_metric "${udm_log}" "${udm_before}" 'kdf_kausf'         ns)
    n_xres_ns=$(extract_net_metric  "${udm_log}" "${udm_before}" 'kdf_xres_star'     ns)
    n_mil_c=$(extract_net_metric    "${udm_log}" "${udm_before}" 'milenage_generate' cycles)
    n_kausf_c=$(extract_net_metric  "${udm_log}" "${udm_before}" 'kdf_kausf'         cycles)
    n_xres_c=$(extract_net_metric   "${udm_log}" "${udm_before}" 'kdf_xres_star'     cycles)
    n_total_ns=$(sum_metrics "${n_mil_ns}" "${n_kausf_ns}" "${n_xres_ns}")
    n_total_c=$(sum_metrics  "${n_mil_c}"  "${n_kausf_c}"  "${n_xres_c}")

    # ----- UE -----
    local u_mil_ns u_kausf_ns u_res_ns u_total_ns
    local u_mil_c  u_kausf_c  u_res_c  u_total_c
    u_mil_ns=$(extract_ue_metric   "${ue_log}" 'milenage_generate' ns)
    u_kausf_ns=$(extract_ue_metric "${ue_log}" 'kdf_kausf'         ns)
    u_res_ns=$(extract_ue_metric   "${ue_log}" 'res_star'          ns)
    u_mil_c=$(extract_ue_metric    "${ue_log}" 'milenage_generate' cycles)
    u_kausf_c=$(extract_ue_metric  "${ue_log}" 'kdf_kausf'         cycles)
    u_res_c=$(extract_ue_metric    "${ue_log}" 'res_star'          cycles)
    u_total_ns=$(sum_metrics "${u_mil_ns}" "${u_kausf_ns}" "${u_res_ns}")
    u_total_c=$(sum_metrics  "${u_mil_c}"  "${u_kausf_c}"  "${u_res_c}")

    echo "${run_id},${METHOD},${n_mil_ns},${n_kausf_ns},${n_xres_ns},${n_total_ns},${n_mil_c},${n_kausf_c},${n_xres_c},${n_total_c},${u_mil_ns},${u_kausf_ns},${u_res_ns},${u_total_ns},${u_mil_c},${u_kausf_c},${u_res_c},${u_total_c}"
  fi

  rm -f "${ue_log}"
}

print_summary() {
  local results_file="$1"

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    # EDHOC layout (1-based CSV columns):
    #   1=run 2=method
    #   3..9   net_*_ns           (6 ops + total)
    #   10..16 net_*_cycles       (6 ops + total)
    #   17..23 ue_*_ns            (6 ops + total)
    #   24..30 ue_*_cycles        (6 ops + total)
    local net_labels='m1_parse m2_prepare m3_parse m3_verify m4_prepare exporter total'
    local ue_labels='m1_prepare m2_parse m2_verify m3_prepare m4_process exporter total'

    echo "[bench-both] Summary Network (ns):"
    awk -F',' -v labels="${net_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $3 != "TIMEOUT" && $3 != "N/A" {
        for (i = 3; i <= 9; i++) {
          idx = i - 2; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary Network (cycles):"
    awk -F',' -v labels="${net_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $10 != "TIMEOUT" && $10 != "N/A" {
        for (i = 10; i <= 16; i++) {
          idx = i - 9; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary UE (ns):"
    awk -F',' -v labels="${ue_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $17 != "TIMEOUT" && $17 != "N/A" {
        for (i = 17; i <= 23; i++) {
          idx = i - 16; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary UE (cycles):"
    awk -F',' -v labels="${ue_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $24 != "TIMEOUT" && $24 != "N/A" {
        for (i = 24; i <= 30; i++) {
          idx = i - 23; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-12s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

  else
    # 5G-AKA layout:
    #   1=run 2=method
    #   3..6   net_*_ns       (3 ops + total)
    #   7..10  net_*_cycles
    #   11..14 ue_*_ns
    #   15..18 ue_*_cycles
    local net_labels='milenage kdf_kausf kdf_xres_star total'
    local ue_labels='milenage kdf_kausf res_star total'

    echo "[bench-both] Summary Network (ns):"
    awk -F',' -v labels="${net_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $3 != "TIMEOUT" && $3 != "N/A" {
        for (i = 3; i <= 6; i++) {
          idx = i - 2; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-14s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary Network (cycles):"
    awk -F',' -v labels="${net_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $7 != "TIMEOUT" && $7 != "N/A" {
        for (i = 7; i <= 10; i++) {
          idx = i - 6; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-14s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary UE (ns):"
    awk -F',' -v labels="${ue_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $11 != "TIMEOUT" && $11 != "N/A" {
        for (i = 11; i <= 14; i++) {
          idx = i - 10; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-14s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"

    echo "[bench-both] Summary UE (cycles):"
    awk -F',' -v labels="${ue_labels}" '
      BEGIN { n_lbl = split(labels, L, " ") }
      NR == 1 { next }
      $15 != "TIMEOUT" && $15 != "N/A" {
        for (i = 15; i <= 18; i++) {
          idx = i - 14; n[idx]++; sum[idx] += $i;
          if (min[idx] == "" || $i < min[idx]) min[idx] = $i;
          if (max[idx] == "" || $i > max[idx]) max[idx] = $i;
        }
      }
      END {
        for (i = 1; i <= n_lbl; i++)
          if (n[i] > 0)
            printf "  %-14s mean=%.0f  min=%d  max=%d\n", L[i], sum[i]/n[i], min[i], max[i];
      }' "${results_file}"
  fi
}

main() {
  parse_args "$@"

  mkdir -p "${BENCH_DIR}" "${LOG_DIR}"
  local timestamp method_tag output_tag_part results_file failed line total
  timestamp=$(date +%Y%m%d-%H%M%S)
  method_tag=$(echo "${METHOD}" | tr '[:upper:]' '[:lower:]')
  output_tag_part=""
  if [[ -n "${OUTPUT_TAG}" ]]; then
    output_tag_part="_${OUTPUT_TAG}"
  fi
  results_file="${BENCH_DIR}/crypto_both_${method_tag}${output_tag_part}_${timestamp}.csv"

  echo "[bench-both] Method: ${METHOD}"
  echo "[bench-both] Runs: ${RUNS}"
  echo "[bench-both] Results: ${results_file}"
  if [[ "${PIN_UE}" -eq 1 ]]; then
    echo "[bench-both] nr-ue pinned to CPU ${UE_CORE} (taskset)"
  else
    echo "[bench-both] nr-ue pinning DISABLED"
  fi

  # Governor sanity check on the UE core (warn-only).
  local gov_file="/sys/devices/system/cpu/cpu${UE_CORE}/cpufreq/scaling_governor"
  if [[ -r "${gov_file}" ]]; then
    local gov; gov="$(cat "${gov_file}")"
    if [[ "${gov}" != "performance" ]]; then
      echo "[bench-both] WARNING: cpu${UE_CORE} governor is '${gov}' (recommended: performance)" >&2
      echo "[bench-both]   sudo cpupower frequency-set -g performance" >&2
    fi
  fi

  # Report what cores AUSF/AMF/UDM are pinned to (informational).
  for proc in open5gs-ausfd open5gs-amfd open5gs-udmd; do
    local pid; pid=$(pgrep -x "${proc}" | head -n1 || true)
    if [[ -n "${pid}" ]]; then
      local aff; aff=$(taskset -pc "${pid}" 2>/dev/null | awk -F': ' '{print $2}')
      echo "[bench-both] ${proc} (pid ${pid}) affinity: ${aff}"
    fi
  done
  echo ""

  set_auth_method
  require_instrumentation

  if ! pgrep -f 'open5gs-amfd' >/dev/null; then
    echo "[bench-both] ERROR: open5gs-amfd is not running" >&2; exit 1
  fi
  if ! pgrep -f 'nr-gnb' >/dev/null; then
    echo "[bench-both] ERROR: nr-gnb is not running" >&2; exit 1
  fi
  if pgrep -f 'nr-ue' >/dev/null; then
    echo "[bench-both] WARNING: nr-ue is already running, stopping it first" >&2
    sudo pkill -f "${UERANSIM_BUILD_DIR}/nr-ue" || true
    sleep 1
  fi

  sudo -v

  if [[ "${METHOD}" == "EDHOC_PSK" ]]; then
    echo "run,method,\
net_m1_parse_ns,net_m2_prepare_ns,net_m3_parse_ns,net_m3_verify_ns,net_m4_prepare_ns,net_exporter_ns,net_total_ns,\
net_m1_parse_cycles,net_m2_prepare_cycles,net_m3_parse_cycles,net_m3_verify_cycles,net_m4_prepare_cycles,net_exporter_cycles,net_total_cycles,\
ue_m1_prepare_ns,ue_m2_parse_ns,ue_m2_verify_ns,ue_m3_prepare_ns,ue_m4_process_ns,ue_exporter_ns,ue_total_ns,\
ue_m1_prepare_cycles,ue_m2_parse_cycles,ue_m2_verify_cycles,ue_m3_prepare_cycles,ue_m4_process_cycles,ue_exporter_cycles,ue_total_cycles" \
      > "${results_file}"
  else
    echo "run,method,\
net_milenage_ns,net_kdf_kausf_ns,net_kdf_xres_star_ns,net_total_ns,\
net_milenage_cycles,net_kdf_kausf_cycles,net_kdf_xres_star_cycles,net_total_cycles,\
ue_milenage_ns,ue_kdf_kausf_ns,ue_res_star_ns,ue_total_ns,\
ue_milenage_cycles,ue_kdf_kausf_cycles,ue_res_star_cycles,ue_total_cycles" \
      > "${results_file}"
  fi

  failed=0
  for i in $(seq 1 "${RUNS}"); do
    printf "[bench-both] Run %d/%d ... " "${i}" "${RUNS}"
    line=$(run_single "${i}")
    echo "${line}" >> "${results_file}"
    total=$(echo "${line}" | awk -F',' '{print $NF}')
    if [[ "${total}" == "TIMEOUT" || "${total}" == "N/A" ]]; then
      printf "TIMEOUT\n"
      ((failed++))
    else
      printf "ue_total=%s ns\n" "${total}"
    fi

    if [[ "${i}" -lt "${RUNS}" ]]; then
      sleep "${COOLDOWN}"
    fi
  done

  echo ""
  echo "[bench-both] Complete: $((RUNS - failed))/${RUNS} successful"
  echo "[bench-both] Results saved to: ${results_file}"
  echo ""
  print_summary "${results_file}"
}

main "$@"
