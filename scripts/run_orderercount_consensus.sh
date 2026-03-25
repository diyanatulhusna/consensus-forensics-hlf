#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# run_orderercount_consensus.sh
#
# PURPOSE
#   Run committee-size experiment for Fabric Raft vs SmartBFT
#   using ONE active working directory that is manually switched
#   by the experimenter before each run (4 / 7 / 10 orderers).
#
# DESIGN
#   - Single working directory (same style as previous experiments)
#   - User manually prepares the active network/config for:
#       4, 7, or 10 orderers
#   - Script only:
#       * resets network
#       * deploys network
#       * verifies active orderer containers
#       * captures channel/config snapshot for consenters
#       * runs SUBMIT then RETRIEVE
#       * stores summary/resource CSV + audit files
#
# IMPORTANT
#   ORDERER_COUNT is a LABEL + validation target.
#   The actual network content must already be prepared manually
#   in the current working directory before execution.
#
# USAGE
#   ./run_orderercount_consensus.sh [CONSENSUS] [BATCH] [TPS] [TOTAL_REPETITIONS] [ORDERER_COUNT]
#
# EXAMPLES
#   ./run_orderercount_consensus.sh Raft 100 100 5 4
#   ./run_orderercount_consensus.sh SmartBFT 100 100 5 7
#   ./run_orderercount_consensus.sh Raft 100 100 5 10
# ==========================================================

CONSENSUS="${1:-SmartBFT}"      # Raft | SmartBFT
BATCH="${2:-100}"               # recommended fixed point: 100
TPS="${3:-100}"                 # recommended fixed point: 100
TOTAL_REPETITIONS="${4:-5}"     # default 5
ORDERER_COUNT="${5:-4}"         # expected active orderer count: 4 | 7 | 10

# ==========================================================
# STATIC CONFIG
# ==========================================================
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"
STATE_DB="${STATE_DB:-couchdb}"
CC_NAME="${CC_NAME:-forensicContract}"
CC_PATH="${CC_PATH:-../forensic/chaincode-javascript}"
CC_LANG="${CC_LANG:-javascript}"

BENCH_SUBMIT_SRC="${BENCH_SUBMIT_SRC:-benchmarks/benchmark-consensus-submit.yaml}"
BENCH_RETRIEVE_SRC="${BENCH_RETRIEVE_SRC:-benchmarks/benchmark-consensus-retrieve.yaml}"

NET_SUBMIT_SRC="${NET_SUBMIT_SRC:-networks/network-consensus-submit.yaml}"
NET_RETRIEVE_SRC="${NET_RETRIEVE_SRC:-networks/network-consensus-retrieve.yaml}"
NET_SUBMIT_TMP="${NET_SUBMIT_TMP:-networks/_tmp_network-consensus-submit.yaml}"
NET_RETRIEVE_TMP="${NET_RETRIEVE_TMP:-networks/_tmp_network-consensus-retrieve.yaml}"

RECEIPTS_BASE="${RECEIPTS_BASE:-$(pwd)/data/receipts}"

ORG1_GW_KEYSTORE="${ORG1_GW_KEYSTORE:-$(pwd)/organizations/peerOrganizations/org1.example.com/users/GatewayCollector@org1.example.com/msp/keystore}"
ORG2_JUDGE_KEYSTORE="${ORG2_JUDGE_KEYSTORE:-$(pwd)/organizations/peerOrganizations/org2.example.com/users/Judge@org2.example.com/msp/keystore}"

SUBMIT_ROUND_LABEL="${SUBMIT_ROUND_LABEL:-submitEvidence}"
RETRIEVE_ROUND_LABEL="${RETRIEVE_ROUND_LABEL:-retrieveEvidenceAndLog}"

COOLDOWN_AFTER_SUBMIT_SEC="${COOLDOWN_AFTER_SUBMIT_SEC:-10}"
COOLDOWN_AFTER_RETRIEVE_SEC="${COOLDOWN_AFTER_RETRIEVE_SEC:-60}"
REST_BETWEEN_REPS_SEC="${REST_BETWEEN_REPS_SEC:-15}"

NET_DOWN_WAIT_SEC="${NET_DOWN_WAIT_SEC:-15}"
NET_UP_WAIT_SEC="${NET_UP_WAIT_SEC:-20}"
POST_VERIFY_WAIT_SEC="${POST_VERIFY_WAIT_SEC:-5}"

ORDERER_READY_TIMEOUT_SEC="${ORDERER_READY_TIMEOUT_SEC:-60}"

RESULT_ROOT="${RESULT_ROOT:-research-results-orderercount}"

# Pattern for real orderer containers
ORDERER_NAME_REGEX="${ORDERER_NAME_REGEX:-^orderer([0-9]+)?\.example\.com$}"

# ==========================================================
# HELPERS
# ==========================================================
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: command not found: $1" >&2
    exit 1
  }
}

require_file() {
  [ -f "$1" ] || {
    echo "ERROR: file not found: $1" >&2
    exit 1
  }
}

require_dir() {
  [ -d "$1" ] || {
    echo "ERROR: directory not found: $1" >&2
    exit 1
  }
}

log() {
  echo "[$(date -Iseconds)] $*" | tee -a "$EXEC_LOG"
}

pick_sk_file_latest() {
  local keystore_dir="$1"
  local sk
  sk="$(find "$keystore_dir" -maxdepth 1 -type f \( -name '*_sk' -o -name 'priv_sk' \) -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)"
  if [ -z "$sk" ] || [ ! -f "$sk" ]; then
    echo "ERROR: no *_sk / priv_sk found in ${keystore_dir}" >&2
    return 1
  fi
  echo "$sk"
}

escape_sed_repl() {
  echo "$1" | sed -e 's/[&]/\\&/g'
}

patch_network_yaml_keys() {
  local gw_sk="$1"
  local judge_sk="$2"
  local gw_esc judge_esc
  gw_esc="$(escape_sed_repl "$gw_sk")"
  judge_esc="$(escape_sed_repl "$judge_sk")"

  sed "s|__GW_PRIVATE_KEY__|${gw_esc}|g" "$NET_SUBMIT_SRC" > "$NET_SUBMIT_TMP"
  sed "s|__JUDGE_PRIVATE_KEY__|${judge_esc}|g" "$NET_RETRIEVE_SRC" > "$NET_RETRIEVE_TMP"
}

# ==========================================================
# BENCH PATCHER
# ==========================================================
patch_bench_yaml() {
  local mode="$1"
  local src="$2"
  local dst="$3"
  local receipts_rep="$4"
  local tps_real="$5"
  local receipts_warmup="${receipts_rep}/warmup"

  python3 - "$mode" "$src" "$dst" "$receipts_rep" "$receipts_warmup" "$tps_real" "$SUBMIT_ROUND_LABEL" "$RETRIEVE_ROUND_LABEL" <<'PY'
import sys, re

mode, src, dst, receipts_rep, receipts_warmup, tps_real, submit_label, retrieve_label = sys.argv[1:]
lines = open(src, encoding="utf-8").read().splitlines(True)
cur_label = None

def repl_line(line, key, value):
    m = re.match(r'^(\s*' + re.escape(key) + r')\s*.*$', line)
    if not m:
        return line
    return f"{m.group(1)} {value}\n"

def repl_tps(line, value):
    m = re.match(r'^(\s*tps:\s*)\d+(\s*#.*)?\s*$', line)
    if not m:
        return line
    tail = m.group(2) or ""
    return f"{m.group(1)}{value}{tail}\n"

for i, line in enumerate(lines):
    m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_.-]+)\s*$', line)
    if m:
        cur_label = m.group(1)

    if cur_label in (submit_label, retrieve_label) and re.match(r'^\s*tps:\s*\d+', line):
        lines[i] = repl_tps(line, tps_real)

    if mode == "submit":
        if re.match(r'^\s*receiptsDir:\s*', line):
            if cur_label == "submit-warmup":
                lines[i] = repl_line(line, "receiptsDir:", receipts_warmup)
            elif cur_label == submit_label:
                lines[i] = repl_line(line, "receiptsDir:", receipts_rep)

    elif mode == "retrieve":
        if re.match(r'^\s*receiptsPath:\s*', line):
            lines[i] = repl_line(line, "receiptsPath:", receipts_rep)

        if re.match(r'^\s*readOnly:\s*(true|false)\s*$', line, re.I):
            lines[i] = repl_line(line, "readOnly:", "false")

        if re.match(r'^\s*funcRetrieve:\s*', line):
            lines[i] = repl_line(line, "funcRetrieve:", "retrieveEvidenceAndLog")

open(dst, "w", encoding="utf-8").write("".join(lines))
PY
}

# ==========================================================
# RESET NETWORK
# ==========================================================
reset_network() {
  log "Reset network (${CONSENSUS}) from current working directory: $(pwd)"

  ./network.sh down || true

  if [ -n "$(docker ps -q 2>/dev/null || true)" ]; then
    docker kill $(docker ps -q) >/dev/null 2>&1 || true
  fi
  if [ -n "$(docker ps -aq 2>/dev/null || true)" ]; then
    docker rm -f $(docker ps -aq) >/dev/null 2>&1 || true
  fi

  docker network prune -f >/dev/null 2>&1 || true
  docker volume prune -f >/dev/null 2>&1 || true

  sleep "$NET_DOWN_WAIT_SEC"

  if [ "$CONSENSUS" = "SmartBFT" ]; then
    ./network.sh up createChannel -bft -c "$CHANNEL_NAME" -s "$STATE_DB"
  else
    ./network.sh up createChannel -c "$CHANNEL_NAME" -s "$STATE_DB"
  fi

  sleep "$NET_UP_WAIT_SEC"

  ./network.sh deployCC \
    -ccn "$CC_NAME" \
    -ccp "$CC_PATH" \
    -ccl "$CC_LANG" \
    -c "$CHANNEL_NAME"
}

# ==========================================================
# ORDERER CONTAINER CHECK
# ==========================================================
list_active_orderer_containers() {
  docker ps --format '{{.Names}}' | grep -E "$ORDERER_NAME_REGEX" | sort -V || true
}

verify_active_orderer_count() {
  local rep="$1"
  local out_file="${RESULT_DIR}/verification_rep${rep}_active_orderers.txt"

  local deadline=$(( $(date +%s) + ORDERER_READY_TIMEOUT_SEC ))
  local current_count=0

  while true; do
    mapfile -t active_nodes < <(list_active_orderer_containers)
    current_count="${#active_nodes[@]}"

    if [ "$current_count" -eq "$ORDERER_COUNT" ]; then
      break
    fi

    if [ "$(date +%s)" -ge "$deadline" ]; then
      break
    fi
    sleep 2
  done

  {
    echo "EXPECTED_ORDERER_COUNT=${ORDERER_COUNT}"
    echo "OBSERVED_ACTIVE_ORDERER_COUNT=${current_count}"
    echo "ACTIVE_ORDERERS_BEGIN"
    printf '%s\n' "${active_nodes[@]:-}"
    echo "ACTIVE_ORDERERS_END"
  } > "$out_file"

  if [ "$current_count" -ne "$ORDERER_COUNT" ]; then
    log "WARNING: active orderer container count mismatch for rep=${rep}: expected=${ORDERER_COUNT}, observed=${current_count}"
    return 1
  fi

  log "Active orderer container count OK for rep=${rep}: ${current_count}"
  return 0
}

# ==========================================================
# CHANNEL / CONSENTER CHECK
# NOTE:
# This captures available evidence for later audit.
# Exact parsing depends on Fabric version and config tooling.
# ==========================================================
set_peer_env_org1_admin() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:7051
}

snapshot_channel_consenter_info() {
  local rep="$1"

  local base="${RESULT_DIR}/verification_rep${rep}_channel_config"
  local fetch_pb="${base}.pb"
  local fetch_json="${base}.json"
  local summary_txt="${base}_summary.txt"

  set_peer_env_org1_admin || true

  {
    echo "EXPECTED_ORDERER_COUNT=${ORDERER_COUNT}"
    echo "CHANNEL_NAME=${CHANNEL_NAME}"
    echo "CONSENSUS=${CONSENSUS}"
    echo "SNAPSHOT_TIME=$(date -Iseconds)"
    echo ""
  } > "$summary_txt"

  # Try fetching config block
  if peer channel fetch config "$fetch_pb" -o localhost:7050 -c "$CHANNEL_NAME" --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" >/dev/null 2>&1; then
    echo "FETCH_CONFIG_BLOCK=OK" >> "$summary_txt"
  else
    echo "FETCH_CONFIG_BLOCK=FAIL" >> "$summary_txt"
  fi

  # Try configtxlator decode if available
  if [ -f "$fetch_pb" ] && command -v configtxlator >/dev/null 2>&1; then
    if configtxlator proto_decode --input "$fetch_pb" --type common.Block > "$fetch_json" 2>/dev/null; then
      echo "DECODE_BLOCK_JSON=OK" >> "$summary_txt"

      python3 - "$fetch_json" "$summary_txt" <<'PY'
import json, sys

json_path, summary_path = sys.argv[1:]
try:
    doc = json.load(open(json_path, encoding="utf-8"))
except Exception as e:
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(f"JSON_PARSE=FAIL ({e})\n")
    raise SystemExit(0)

def append(msg):
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

append("JSON_PARSE=OK")

try:
    groups = doc["data"]["data"][0]["payload"]["data"]["config"]["channel_group"]["groups"]
    orderer_group = groups["Orderer"]
except Exception as e:
    append(f"ORDERER_GROUP_PARSE=FAIL ({e})")
    raise SystemExit(0)

append("ORDERER_GROUP_PARSE=OK")

# Try orderer org count
try:
    org_names = list(orderer_group.get("groups", {}).keys())
    append(f"ORDERER_ORG_COUNT={len(org_names)}")
    append("ORDERER_ORGS_BEGIN")
    for x in org_names:
        append(str(x))
    append("ORDERER_ORGS_END")
except Exception as e:
    append(f"ORDERER_ORG_ENUM_FAIL ({e})")

# Try consenter list (etcdraft) if present
try:
    values = orderer_group.get("values", {})
    consensus_type = values.get("ConsensusType", {})
    metadata = consensus_type.get("value", {}).get("metadata", {})
    consenters = metadata.get("consenters", [])

    append(f"CONSENTERS_FOUND={len(consenters)}")
    append("CONSENTERS_BEGIN")
    for c in consenters:
        host = c.get("host", "")
        port = c.get("port", "")
        append(f"{host}:{port}")
    append("CONSENTERS_END")
except Exception as e:
    append(f"CONSENTERS_PARSE_FAIL ({e})")

# Try smartbft if present
try:
    values = orderer_group.get("values", {})
    ctype = values.get("ConsensusType", {}).get("value", {}).get("type", "")
    append(f"CONSENSUS_TYPE_FIELD={ctype}")
except Exception as e:
    append(f"CONSENSUS_TYPE_PARSE_FAIL ({e})")
PY
    else
      echo "DECODE_BLOCK_JSON=FAIL" >> "$summary_txt"
    fi
  else
    echo "CONFIGTXLATOR_OR_FETCH_UNAVAILABLE=YES" >> "$summary_txt"
  fi

  # Also store current running orderer containers again for cross-check
  {
    echo ""
    echo "ACTIVE_ORDERERS_RUNTIME_BEGIN"
    list_active_orderer_containers
    echo "ACTIVE_ORDERERS_RUNTIME_END"
  } >> "$summary_txt"

  log "Stored channel/consenter snapshot for rep=${rep}: ${summary_txt}"
}

run_preflight_verification() {
  local rep="$1"
  verify_active_orderer_count "$rep" || true
  snapshot_channel_consenter_info "$rep" || true
  sleep "$POST_VERIFY_WAIT_SEC"
}

# ==========================================================
# PARSE SUMMARY
# ==========================================================
append_summary_row() {
  local rep="$1"
  local phase="$2"
  local html="$3"
  local target_round="$4"

  python3 - "$SCENARIO_ID" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$ORDERER_COUNT" "$html" "$target_round" >> "$SUMMARY_CSV" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, orderer_count, path, target = sys.argv[1:]

def strip_tags(x: str) -> str:
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0', ' ').strip()

s = open(path, encoding="utf-8", errors="ignore").read()
m = re.search(r'id=\"benchmarksummary\".*?<table[^>]*>(.*?)</table>', s, re.S | re.I)
if not m:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{orderer_count},{target},ERROR_NO_BENCHMARKSUMMARY,0,0,,,,")
    raise SystemExit(0)

rows = re.findall(r'<tr[^>]*>(.*?)</tr>', m.group(1), re.S | re.I)
parsed = []
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S | re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

if len(parsed) < 2:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{orderer_count},{target},ERROR_EMPTY_SUMMARY,0,0,,,,")
    raise SystemExit(0)

headers = parsed[0]
row_dict = None
for r in parsed[1:]:
    if r and r[0] == target:
        row_dict = dict(zip(headers, r))
        break

if not row_dict:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{orderer_count},{target},ERROR_TARGET_NOT_FOUND,0,0,,,,")
    raise SystemExit(0)

def g(k): return row_dict.get(k, "")

print(",".join([
    scenario, rep, phase, cons, batch, tps, orderer_count, target,
    g("Name") or target,
    g("Succ") or "0",
    g("Fail") or "0",
    g("Send Rate (TPS)"),
    g("Max Latency (s)"),
    g("Min Latency (s)"),
    g("Avg Latency (s)"),
    g("Throughput (TPS)"),
]))
PY
}

# ==========================================================
# PARSE RESOURCE
# ==========================================================
append_resource_rows() {
  local rep="$1"
  local phase="$2"
  local html="$3"
  local target_round="$4"

  python3 - "$SCENARIO_ID" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$ORDERER_COUNT" "$html" "$target_round" >> "$RESOURCE_CSV" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, orderer_count, path, target = sys.argv[1:]

def strip_tags(x: str) -> str:
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0', ' ').strip()

def to_float(x: str):
    try:
        m = re.findall(r'[-]?\d+(?:\.\d+)?', x or "")
        return float(m[0]) if m else None
    except:
        return None

s = open(path, encoding="utf-8", errors="ignore").read()
start = s.lower().find(f"resource utilization for {target}".lower())
if start == -1:
    raise SystemExit(0)

tail = s[start:]
m_end = re.search(r'<div[^>]*id=\"[^\"]+\"[^>]*>\s*<h2[^>]*>\s*Benchmark round:', tail, re.I | re.S)
end = start + (m_end.start() if m_end else len(tail))
seg = s[start:end]

rows = re.findall(r'<tr[^>]*>(.*?)</tr>', seg, re.S | re.I)
parsed = []
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S | re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

header_idx = None
for i, r in enumerate(parsed):
    if "CPU%(max)" in r and "CPU%(avg)" in r and "Traffic In [MB]" in r:
        header_idx = i
        break
if header_idx is None:
    raise SystemExit(0)

headers = parsed[header_idx]
idx = {h:i for i, h in enumerate(headers)}

def cell(row, h):
    j = idx.get(h, None)
    return row[j] if j is not None and j < len(row) else ""

orderer_rows = []

for r in parsed[header_idx+1:]:
    if len(r) < len(headers):
        continue

    name = cell(r, "Name")
    if not name:
        continue

    cpu_max = cell(r, "CPU%(max)")
    cpu_avg = cell(r, "CPU%(avg)")
    mem_max = cell(r, "Memory(max) [MB]")
    mem_avg = cell(r, "Memory(avg) [MB]")
    tin = cell(r, "Traffic In [MB]")
    tout = cell(r, "Traffic Out [MB]")
    dwrite = cell(r, "Disc Write [MB]")
    dread = cell(r, "Disc Read [B]")

    print(",".join([
        scenario, rep, phase, cons, batch, tps, orderer_count, target,
        name,
        cpu_avg, cpu_max, mem_avg, mem_max,
        tin, tout, dread, dwrite
    ]))

    n = name.lower()
    if "orderer" in n and "ca_" not in n and "caorderer" not in n and "ca_orderer" not in n:
        orderer_rows.append((cpu_avg, cpu_max, mem_avg, mem_max, tin, tout, dread, dwrite))

if orderer_rows:
    cpu_avgs = [to_float(x[0]) for x in orderer_rows if to_float(x[0]) is not None]
    cpu_maxs = [to_float(x[1]) for x in orderer_rows if to_float(x[1]) is not None]
    mem_avgs = [to_float(x[2]) for x in orderer_rows if to_float(x[2]) is not None]
    mem_maxs = [to_float(x[3]) for x in orderer_rows if to_float(x[3]) is not None]
    tins = [to_float(x[4]) for x in orderer_rows if to_float(x[4]) is not None]
    touts = [to_float(x[5]) for x in orderer_rows if to_float(x[5]) is not None]
    dwrites = [to_float(x[7]) for x in orderer_rows if to_float(x[7]) is not None]

    def mean(xs): return (sum(xs) / len(xs)) if xs else None
    def summ(xs): return sum(xs) if xs else None

    print(",".join([
        scenario, rep, phase, cons, batch, tps, orderer_count, target,
        "ORDERERS_AGG",
        f"{mean(cpu_avgs):.6f}" if mean(cpu_avgs) is not None else "",
        f"{mean(cpu_maxs):.6f}" if mean(cpu_maxs) is not None else "",
        f"{mean(mem_avgs):.6f}" if mean(mem_avgs) is not None else "",
        f"{mean(mem_maxs):.6f}" if mean(mem_maxs) is not None else "",
        f"{summ(tins):.6f}" if summ(tins) is not None else "",
        f"{summ(touts):.6f}" if summ(touts) is not None else "",
        "",
        f"{summ(dwrites):.6f}" if summ(dwrites) is not None else "",
    ]))
PY
}

# ==========================================================
# RUN PHASE
# ==========================================================
run_phase() {
  local rep="$1"
  local phase="$2"
  local bench_yaml="$3"
  local net_yaml="$4"
  local target_round="$5"

  rm -f report.html report.json 2>/dev/null || true
  rm -rf wallet/ 2>/dev/null || true

  log "Caliper ${phase} | rep=${rep} | expected_orderers=${ORDERER_COUNT} | consensus=${CONSENSUS}"

  npx caliper launch manager \
    --caliper-workspace ./ \
    --caliper-benchconfig "$bench_yaml" \
    --caliper-networkconfig "$net_yaml" \
    --caliper-flow-only-test

  if [ -f report.html ]; then
    local prefix="${SCENARIO_ID}_rep${rep}_${phase}"
    append_summary_row "$rep" "$phase" "report.html" "$target_round"
    append_resource_rows "$rep" "$phase" "report.html" "$target_round"

    mv "report.html" "${RESULT_DIR}/${prefix}.html"
    [ -f "report.json" ] && mv "report.json" "${RESULT_DIR}/${prefix}.json" || true

    echo "$(date -Iseconds) rep=${rep} phase=${phase} OK" >> "$EXEC_LOG"
    return 0
  else
    echo "$(date -Iseconds) rep=${rep} phase=${phase} FAIL" >> "$EXEC_LOG"
    return 1
  fi
}

# ==========================================================
# REQUIREMENTS
# ==========================================================
require_cmd docker
require_cmd python3
require_cmd npx
require_cmd peer

require_file "$BENCH_SUBMIT_SRC"
require_file "$BENCH_RETRIEVE_SRC"
require_file "$NET_SUBMIT_SRC"
require_file "$NET_RETRIEVE_SRC"
require_dir "$ORG1_GW_KEYSTORE"
require_dir "$ORG2_JUDGE_KEYSTORE"

mkdir -p "$RESULT_ROOT"
mkdir -p "$RECEIPTS_BASE"

case "$ORDERER_COUNT" in
  4|7|10) ;;
  *)
    echo "ERROR: ORDERER_COUNT must be one of: 4, 7, 10" >&2
    exit 1
    ;;
esac

SCENARIO_ID="${CONSENSUS}_b${BATCH}_tps${TPS}_ord${ORDERER_COUNT}"
RESULT_DIR="${RESULT_ROOT}/${SCENARIO_ID}"
mkdir -p "$RESULT_DIR"

SUMMARY_CSV="${RESULT_DIR}/${SCENARIO_ID}_summary_metrics.csv"
RESOURCE_CSV="${RESULT_DIR}/${SCENARIO_ID}_resource_metrics.csv"
EXEC_LOG="${RESULT_DIR}/${SCENARIO_ID}_execution_log.txt"
touch "$EXEC_LOG"

if [ ! -s "$SUMMARY_CSV" ]; then
  echo "scenario,rep,phase,consensus,batch,tps,orderer_count,round_label,name,succ,fail,send_rate_tps,max_latency_s,min_latency_s,avg_latency_s,throughput_tps" > "$SUMMARY_CSV"
fi

if [ ! -s "$RESOURCE_CSV" ]; then
  echo "scenario,rep,phase,consensus,batch,tps,orderer_count,round_label,container,cpu_avg,cpu_max,mem_avg_mb,mem_max_mb,traffic_in_mb,traffic_out_mb,disc_read_b,disc_write_mb" > "$RESOURCE_CSV"
fi

log "=========================================================="
log "START: ${SCENARIO_ID}"
log "WORKDIR      : $(pwd)"
log "SUMMARY_CSV  : ${SUMMARY_CSV}"
log "RESOURCE_CSV : ${RESOURCE_CSV}"
log "=========================================================="

for (( rep=1; rep<=TOTAL_REPETITIONS; rep++ )); do
  log "##########################################################"
  log "REPETITION ${rep}/${TOTAL_REPETITIONS} | ${SCENARIO_ID}"
  log "##########################################################"

  reset_network

  GW_SK="$(pick_sk_file_latest "$ORG1_GW_KEYSTORE")"
  JUDGE_SK="$(pick_sk_file_latest "$ORG2_JUDGE_KEYSTORE")"
  patch_network_yaml_keys "$GW_SK" "$JUDGE_SK"

  # verification after network is up and CC deployed
  run_preflight_verification "$rep"

  RECEIPTS_REP_DIR="${RECEIPTS_BASE}/${SCENARIO_ID}/rep${rep}"
  rm -rf "$RECEIPTS_REP_DIR" 2>/dev/null || true
  mkdir -p "$RECEIPTS_REP_DIR"

  PATCH_SUBMIT="${RESULT_DIR}/patched_submit_rep${rep}.yaml"
  PATCH_RETRIEVE="${RESULT_DIR}/patched_retrieve_rep${rep}.yaml"

  patch_bench_yaml "submit" "$BENCH_SUBMIT_SRC" "$PATCH_SUBMIT" "$RECEIPTS_REP_DIR" "$TPS"
  patch_bench_yaml "retrieve" "$BENCH_RETRIEVE_SRC" "$PATCH_RETRIEVE" "$RECEIPTS_REP_DIR" "$TPS"

  run_phase "$rep" "SUBMIT" "$PATCH_SUBMIT" "$NET_SUBMIT_TMP" "$SUBMIT_ROUND_LABEL" || true
  log "Cooldown after SUBMIT: ${COOLDOWN_AFTER_SUBMIT_SEC}s"
  sleep "$COOLDOWN_AFTER_SUBMIT_SEC"

  run_phase "$rep" "RETRIEVE" "$PATCH_RETRIEVE" "$NET_RETRIEVE_TMP" "$RETRIEVE_ROUND_LABEL" || true
  log "Cooldown after RETRIEVE: ${COOLDOWN_AFTER_RETRIEVE_SEC}s"
  sleep "$COOLDOWN_AFTER_RETRIEVE_SEC"

  if [ "$rep" -lt "$TOTAL_REPETITIONS" ]; then
    sleep "$REST_BETWEEN_REPS_SEC"
  fi
done

log "=========================================================="
log "DONE: ${SCENARIO_ID}"
log "Summary CSV : ${SUMMARY_CSV}"
log "Resource CSV: ${RESOURCE_CSV}"
log "Reports dir : ${RESULT_DIR}"
log "=========================================================="