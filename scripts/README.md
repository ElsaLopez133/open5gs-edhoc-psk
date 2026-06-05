# Scripts

Helper scripts for running, capturing, and benchmarking the EDHOC-PSK vs. 5G-AKA
authentication flows on this Open5GS fork (used together with the companion
UERANSIM fork).

All scripts print `-h` / `--help`. Most assume the layout:

- Open5GS at the repository root (`install/bin/open5gs-*d`, build via the cycle scripts).
- UERANSIM at `/home/elsa/projects/UERANSIM` — override with `UERANSIM_ROOT=...`.
- A subscriber provisioned in the local MongoDB `open5gs` database
  (default test IMSI `001010000000001`).

Logs are written to `run_logs/`, benchmark CSVs to `benchmarks/`.

---

## Quick start

```bash
# 1. Build + start the whole stack (core + gNB + UE)
./scripts/open5gs_ueransim_cycle.sh all

# 2. Start core + gNB only (no UE) — the layout the benchmarks expect
./scripts/open5gs_ueransim_cycle.sh start-core
./scripts/open5gs_ueransim_cycle.sh start-ran --no-ue

# 3. Run a benchmark (each run spawns/kills one nr-ue)
./scripts/benchmark_auth.sh edhoc -n 30
```

Every benchmark/capture script takes `edhoc` or `aka` as its first argument and
flips `authentication_method` in MongoDB for the test IMSI accordingly
(`EDHOC_PSK`, or unset = default 5G-AKA).

---

## Measurement Helper Scripts

### `open5gs_ueransim_cycle.sh`
Top-level driver that combines the Open5GS and UERANSIM cycle scripts.

```
all         open5gs_cycle all + ueransim_cycle all (rebuild, stop, start, check)
rebuild     rebuild Open5GS + UERANSIM
stop        stop Open5GS + UERANSIM
tun         reset ogstun only
start-core  start Open5GS NFs only
start-ran   start UERANSIM only      [--no-gnb | --no-ue]
check       status of Open5GS + UERANSIM
```

Example — the standard benchmarking setup (core + gNB, no UE):
```bash
./scripts/open5gs_ueransim_cycle.sh start-core
./scripts/open5gs_ueransim_cycle.sh start-ran --no-ue
```

### `open5gs_cycle.sh`
Open5GS only.

```
all       rebuild, stop, reset ogstun, start, check
rebuild   ninja build + install
stop      stop Open5GS processes
tun       reset ogstun + run misc/netconf.sh
start     start Open5GS NFs in background
check     process / interface / log status
```

### `ueransim_cycle.sh`
UERANSIM only.

```
all       rebuild, stop, start gNB + UE, check
rebuild   rebuild UERANSIM
stop      stop gNB / UE
start     start gNB / UE in background   [--no-gnb | --no-ue]
check     process / log status
```

### `start_pinned.sh`
Starts the core + gNB with **CPU pinning** for low-noise crypto benchmarking.
The timed NFs are bound to dedicated cores; the rest start un-pinned. Pairs with
`benchmark_crypto_cost_both.sh`, which pins `nr-ue` itself.

```
start    set CPU governor=performance, start daemons pinned
stop     kill all open5gs-*d + nr-gnb / nr-ue
status   show running PIDs and their CPU affinity
```

Default core assignment (override via env vars):

| Process         | Env var     | Default core |
|-----------------|-------------|--------------|
| `open5gs-udmd`  | `UDM_CORE`  | 0 |
| `open5gs-ausfd` | `AUSF_CORE` | 2 |
| `open5gs-amfd`  | `AMF_CORE`  | 4 |
| `nr-gnb`        | `GNB_CORE`  | 7 |
| `nr-ue`         | `UE_CORE`   | 6 (applied by the bench script) |

```bash
AUSF_CORE=3 ./scripts/start_pinned.sh start
./scripts/start_pinned.sh status
```

---

## Logs

### `edhoc_logs.sh`
Print, follow, or save filtered log output across NF components.

```
Usage: edhoc_logs.sh [print|follow|save] [options] [components...]

Components: ue amf ausf udm smf upf gnb nrf nssf scp all
Options:
  --pattern <regex>   filter pattern
  --lines <n>         lines per file for print/save
```

```bash
./scripts/edhoc_logs.sh print ue amf ausf udm
./scripts/edhoc_logs.sh follow --pattern 'EDHOC|Authentication' ue amf ausf
./scripts/edhoc_logs.sh save all
```

---

## Packet capture

### `capture_registration.sh`
Capture one full UE registration to a pcap (NAS over N1, SBI over N12).

```
Usage: capture_registration.sh <edhoc|aka> [options]
  -o <file>     output pcap (default: benchmarks/<method>_registration_<ts>.pcap)
  -i <iface>    capture interface
  -p <port>     AUSF SBI TCP port in the capture filter
  -t <seconds>  registration timeout
  --teardown    stop Open5GS + UERANSIM after capture
```

```bash
./scripts/capture_registration.sh edhoc
./scripts/capture_registration.sh aka -o benchmarks/aka_registration.pcap
```

---

## Benchmarks

All four take `edhoc|aka` first, then share these options:

```
-n <runs>     number of registration runs (default 30)
-t <seconds>  per-run registration timeout
-c <seconds>  cooldown between runs
-o <name>     tag inserted into the output filename
```

Each run spawns a fresh `nr-ue`, waits for *"Initial Registration is
successful"*, then kills it. Results land in `benchmarks/` as timestamped CSVs.

**Prerequisites (all benchmarks):** core + gNB running, subscriber in MongoDB,
and the relevant log instrumentation compiled in (the scripts check for it and
abort with a rebuild hint if missing).

### `benchmark_auth.sh` — authentication and registration latency
Measures authentication and registration **latency** from AMF logs
(`AUTH_LATENCY`, `REG_LATENCY`), plus the AUSF EDHOC leg timings
(`leg1_m1_m2`, `leg2_m3_m4_kausf`) for the EDHOC method. Prints mean / median /
min / max summaries.
*Needs:* `AUTH_LATENCY` + `REG_LATENCY` (AMF), and `EDHOC_TIMING` (AUSF) for edhoc.
Output: `benchmarks/auth_latency_<method>[_<tag>]_<ts>.csv`.

```bash
./scripts/benchmark_auth.sh edhoc -n 30
./scripts/benchmark_auth.sh aka   -n 30 -o baseline
```

### `benchmark_crypto_cost.sh` — network-side crypto cost
Per-operation **crypto timings** (ns + CPU cycles) from the AUSF/UDM side.
*Needs:* `AKA_CRYPTO` / `EDHOC_CRYPTO` instrumentation.
Output: `benchmarks/crypto_<method>[_<tag>]_<ts>.csv`.
- EDHOC columns: `m1_parse, m2_prepare, m3_parse, m3_verify, m4_prepare, exporter, total` (×ns and ×cycles).
- AKA columns: `milenage, kdf_kausf, kdf_xres_star, total`.

```bash
./scripts/benchmark_crypto_cost.sh edhoc -n 30
```

### `benchmark_crypto_cost_ue.sh` — UE-side crypto cost
Same idea, measured on `nr-ue`.
Output: `benchmarks/crypto_ue_<method>[_<tag>]_<ts>.csv`.
- EDHOC columns: `m1_prepare, m2_parse, m2_verify, m3_prepare, m4_process, exporter, total`.
- AKA columns: `milenage, kdf_kausf, res_star, total`.

```bash
./scripts/benchmark_crypto_cost_ue.sh edhoc -n 30
```

### `benchmark_crypto_cost_both.sh` — UE + network crypto cost
Collects both sides in a single run and merges them. Adds CPU pinning of
`nr-ue`:

```
-p <core>   pin nr-ue to this core via taskset (default 6)
-P          disable nr-ue pinning
```

Output: `benchmarks/crypto_both_<method>[_<tag>]_<ts>.csv`.
Best paired with `start_pinned.sh` so the network NFs are pinned too:

```bash
./scripts/start_pinned.sh start
./scripts/benchmark_crypto_cost_both.sh edhoc -n 30 -p 6
```

---

## Notes

- The benchmark/capture scripts use `sudo` to start/stop `nr-ue` (it needs raw
  socket / TUN privileges); you may be prompted for your password.
- `edhoc` ⇒ sets `authentication_method = EDHOC_PSK` in MongoDB; `aka` ⇒ unsets
  it (Open5GS then defaults to 5G-AKA). The scripts leave the field as last set,
  so re-run the desired method before a manual test if unsure.
- EDHOC subscriber credentials live in the `edhoc_credentials` array of the
  subscriber document (`kid` + `cred_i`).