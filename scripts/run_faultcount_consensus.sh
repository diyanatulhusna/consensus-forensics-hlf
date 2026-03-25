#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# run_faultcount_consensus.sh
#
# PURPOSE
#   Fault-count experiment runner for Hyperledger Fabric v3
#   Raft vs SmartBFT, runtime orderer crash injection
#
# DESIGN (fixed for the new subsection)
#   - batch size fixed at user input (recommended: 100)
#   - offered load fixed at user input (recommended: 100 TPS)
#   - mode fixed to UNSPLIT
#   - nested HIGH-IMPACT family only:
#       k=0 : {}
#       k=1 : {orderer.example.com}
#       k=2 : {orderer.example.com, orderer9.example.com}
#       k=3 : {orderer.example.com, orderer9.example.com, orderer10.example.com}
#
# SEMANTICS
#   - SUBMIT:
#       reset network -> run submitEvidence -> inject runtime fault in real round
#   - RETRIEVE:
#       reset network -> preload submit (no fault) on fresh ledger
#                    -> run retrieveEvidenceAndLog -> inject runtime fault in real round
#
# OUTPUT
#   One scenario folder per k under research-results-faultcount/
#
# USAGE
#   ./run_faultcount_consensus.sh [CONSENSUS] [BATCH] [TPS] [TOTAL_REPETITIONS] [K_SET_CSV]
#
# EXAMPLES
#   ./run_faultcount_consensus.sh Raft 100 100 5 0,1,2,3
#   ./run_faultcount_consensus.sh SmartBFT 100 100 5 0,1,2,3
# ==========================================================

# ----------------------------------------------------------
# Positional args
# ----------------------------------------------------------
CONSENSUS="${1:-SmartBFT}"          # Raft | SmartBFT
BATCH="${2:-100}"                   # recommended 100
TPS="${3:-100}"                     # recommended 100
TOTAL_REPETITIONS="${4:-5}"         # recommended 5
K_SET_CSV="${5:-0,1,2,3}"           # nested fault counts

# ----------------------------------------------------------
# Fixed experiment design
# ----------------------------------------------------------
MODE="unsplit"
FAULT_FAMILY_NAME="${FAULT_FAMILY_NAME:-highimpact-nested}"
HIGH_IMPACT_FAMILY_CSV="${HIGH_IMPACT_FAMILY_CSV:-orderer.example.com,orderer9.example.com,orderer10.example.com}"

# ----------------------------------------------------------
# Static config
# ----------------------------------------------------------
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"
STATE_DB="${STATE_DB:-couchdb}"
CC_NAME="${CC_NAME:-forensicContract}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CC_PATH="${CC_PATH:-../forensic/chaincode-javascript}"
CC_LANG="${CC_LANG:-javascript}"

BENCH_SUBMIT_SRC="${BENCH_SUBMIT_SRC:-benchmarks/benchmark-consensus-submit.yaml}"
BENCH_RETRIEVE_SRC="${BENCH_RETRIEVE_SRC:-benchmarks/benchmark-consensus-retrieve.yaml}"

NET_SUBMIT_SRC="${NET_SUBMIT_SRC:-networks/network-consensus-submit.yaml}"
NET_RETRIEVE_SRC="${NET_RETRIEVE_SRC:-networks/network-consensus-retrieve.yaml}"
NET_SUBMIT_TMP="${NET_SUBMIT_TMP:-networks/_tmp_network-consensus-submit.yaml}"
NET_RETRIEVE_TMP="${NET_RETRIEVE_TMP:-networks/_tmp_network-consensus-retrieve.yaml}"

RECEIPTS_BASE="${RECEIPTS_BASE:-/home/labnuc/2labforensic/fabric-samples/test-network/data/receipts}"

ORG1_GW_KEYSTORE="${ORG1_GW_KEYSTORE:-/home/labnuc/2labforensic/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/GatewayCollector@org1.example.com/msp/keystore}"
ORG2_JUDGE_KEYSTORE="${ORG2_JUDGE_KEYSTORE:-/home/labnuc/2labforensic/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/Judge@org2.example.com/msp/keystore}"

# ----------------------------------------------------------
# Timing knobs
# ----------------------------------------------------------
WARMUP_SEC="${WARMUP_SEC:-30}"
UNSPLIT_REAL_SEC="${UNSPLIT_REAL_SEC:-60}"
FAULT_AFTER_REAL_START_SEC="${FAULT_AFTER_REAL_START_SEC:-10}"

COOLDOWN_AFTER_SUBMIT_SEC="${COOLDOWN_AFTER_SUBMIT_SEC:-10}"
COOLDOWN_AFTER_RETRIEVE_SEC="${COOLDOWN_AFTER_RETRIEVE_SEC:-20}"
REST_BETWEEN_REPS_SEC="${REST_BETWEEN_REPS_SEC:-15}"

NET_DOWN_WAIT_SEC="${NET_DOWN_WAIT_SEC:-15}"
NET_UP_WAIT_SEC="${NET_UP_WAIT_SEC:-20}"
POST_DEPLOY_WAIT_SEC="${POST_DEPLOY_WAIT_SEC:-8}"
ORDERER_READY_TIMEOUT_SEC="${ORDERER_READY_TIMEOUT_SEC:-60}"

# ----------------------------------------------------------
# Fault injection knobs
# ----------------------------------------------------------
FAULT_CMD="${FAULT_CMD:-stop0}"   # stop0 | stop | kill
ORDERER_REGEX="${ORDERER_REGEX:-^orderer([0-9]+)?\.example\.com$}"
EXPECTED_ORDERERS="${EXPECTED_ORDERERS:-10}"

# ----------------------------------------------------------
# Retrieve preload knobs
# ----------------------------------------------------------
PRELOAD_REAL_SEC="${PRELOAD_REAL_SEC:-60}"
PRELOAD_TPS="${PRELOAD_TPS:-$TPS}"
PRELOAD_WARMUP_SEC="${PRELOAD_WARMUP_SEC:-10}"
PRELOAD_WARMUP_TPS="${PRELOAD_WARMUP_TPS:-20}"
MIN_SUCCESS_RECEIPTS="${MIN_SUCCESS_RECEIPTS:-100}"

# ----------------------------------------------------------
# Caliper / monitor knobs
# ----------------------------------------------------------
WORKERS="${WORKERS:-5}"
WARMUP_TPS="${WARMUP_TPS:-50}"
MONITOR_INTERVAL_SEC="${MONITOR_INTERVAL_SEC:-1}"
ROUND_MARKER_TIMEOUT_SEC="${ROUND_MARKER_TIMEOUT_SEC:-180}"

ENABLE_CALIPER_RESOURCE_MONITOR="${ENABLE_CALIPER_RESOURCE_MONITOR:-false}"
EXTERNAL_RESOURCE_INTERVAL_SEC="${EXTERNAL_RESOURCE_INTERVAL_SEC:-1}"

SUBMIT_TIMEOUT_SEC="${SUBMIT_TIMEOUT_SEC:-600}"
RETRIEVE_TIMEOUT_SEC="${RETRIEVE_TIMEOUT_SEC:-600}"

# ----------------------------------------------------------
# Seeds / labels
# ----------------------------------------------------------
SUBMIT_WARMUP_SEED="${SUBMIT_WARMUP_SEED:-999}"
SUBMIT_REAL_SEED="${SUBMIT_REAL_SEED:-301}"
PRELOAD_REAL_SEED="${PRELOAD_REAL_SEED:-431}"

SUBMIT_REAL_LABEL="${SUBMIT_REAL_LABEL:-submitEvidence}"
RETRIEVE_REAL_LABEL="${RETRIEVE_REAL_LABEL:-retrieveEvidenceAndLog}"

# ----------------------------------------------------------
# Failure policy
# ----------------------------------------------------------
CONTINUE_ON_PHASE_ERROR="${CONTINUE_ON_PHASE_ERROR:-false}"

# ----------------------------------------------------------
# Runtime globals (scenario-specific; set by init_scenario_outputs)
# ----------------------------------------------------------
CURRENT_K_FAULT=""
SCENARIO_ID=""
RESULT_DIR=""
SUMMARY_CSV=""
RESOURCE_CSV=""
FAULT_CSV=""
EXEC_LOG=""
MANIFEST_TXT=""

PRELOAD_RECEIPTS_DIR=""
ACTUAL_FAULT_NODES_CSV=""
PHASE_RESOURCE_RAW=""
PHASE_RESOURCE_STOPFILE=""
PHASE_RESOURCE_PID=""

# ----------------------------------------------------------
# Helpers
# ----------------------------------------------------------
log() {
  echo "[$(date -Iseconds)] $*" | tee -a "$EXEC_LOG" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: command not found: $1" >&2; exit 1; }
}

require_file() {
  [ -f "$1" ] || { echo "ERROR: file not found: $1" >&2; exit 1; }
}

abspath() {
  python3 - "$1" <<'PY'
import os, sys
print(os.path.realpath(sys.argv[1]))
PY
}

check_python_yaml() {
  python3 - <<'PY' >/dev/null 2>&1
import yaml
PY
}

should_continue_after_error() {
  [ "$CONTINUE_ON_PHASE_ERROR" = "true" ]
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

init_scenario_outputs() {
  local k="$1"

  CURRENT_K_FAULT="$k"
  SCENARIO_ID="${CONSENSUS}_b${BATCH}_tps${TPS}_k${CURRENT_K_FAULT}_${MODE}_${FAULT_FAMILY_NAME}"
  RESULT_DIR="research-results-faultcount/${SCENARIO_ID}"
  mkdir -p "$RESULT_DIR"

  SUMMARY_CSV="${RESULT_DIR}/${SCENARIO_ID}_summary_metrics.csv"
  RESOURCE_CSV="${RESULT_DIR}/${SCENARIO_ID}_resource_metrics.csv"
  FAULT_CSV="${RESULT_DIR}/${SCENARIO_ID}_fault_schedule.csv"
  EXEC_LOG="${RESULT_DIR}/${SCENARIO_ID}_execution_log.txt"
  MANIFEST_TXT="${RESULT_DIR}/${SCENARIO_ID}_manifest.txt"
  touch "$EXEC_LOG"

  if [ ! -s "$SUMMARY_CSV" ]; then
    echo "scenario,rep,scope,phase,mode,consensus,batch,tps,k_fault,fault_family,fault_nodes,round_label,name,succ,fail,send_rate_tps,max_latency_s,min_latency_s,avg_latency_s,throughput_tps" > "$SUMMARY_CSV"
  fi

  if [ ! -s "$RESOURCE_CSV" ]; then
    echo "scenario,rep,scope,phase,mode,consensus,batch,tps,k_fault,fault_family,fault_nodes,round_label,container,cpu_avg,cpu_max,mem_avg_mb,mem_max_mb,traffic_in_mb,traffic_out_mb,disc_read_b,disc_write_mb" > "$RESOURCE_CSV"
  fi

  if [ ! -s "$FAULT_CSV" ]; then
    echo "scenario,rep,scope,phase,mode,consensus,batch,tps,k_fault,fault_family,fault_nodes,fault_cmd,inject_epoch_s,inject_iso" > "$FAULT_CSV"
  fi

  cat > "$MANIFEST_TXT" <<EOF
SCENARIO_ID=${SCENARIO_ID}
CONSENSUS=${CONSENSUS}
BATCH_LABEL=${BATCH}
TPS=${TPS}
K_FAULT=${CURRENT_K_FAULT}
MODE=${MODE}
FAULT_FAMILY_NAME=${FAULT_FAMILY_NAME}
HIGH_IMPACT_FAMILY_CSV=${HIGH_IMPACT_FAMILY_CSV}
CC_NAME=${CC_NAME}
CC_VERSION=${CC_VERSION}
CC_SEQUENCE=${CC_SEQUENCE}
FAULT_CMD=${FAULT_CMD}
EXPECTED_ORDERERS=${EXPECTED_ORDERERS}
WARMUP_SEC=${WARMUP_SEC}
UNSPLIT_REAL_SEC=${UNSPLIT_REAL_SEC}
FAULT_AFTER_REAL_START_SEC=${FAULT_AFTER_REAL_START_SEC}
PRELOAD_REAL_SEC=${PRELOAD_REAL_SEC}
PRELOAD_TPS=${PRELOAD_TPS}
MIN_SUCCESS_RECEIPTS=${MIN_SUCCESS_RECEIPTS}
WORKERS=${WORKERS}
MONITOR_INTERVAL_SEC=${MONITOR_INTERVAL_SEC}
ENABLE_CALIPER_RESOURCE_MONITOR=${ENABLE_CALIPER_RESOURCE_MONITOR}
EXTERNAL_RESOURCE_INTERVAL_SEC=${EXTERNAL_RESOURCE_INTERVAL_SEC}
ROUND_MARKER_TIMEOUT_SEC=${ROUND_MARKER_TIMEOUT_SEC}
SUBMIT_TIMEOUT_SEC=${SUBMIT_TIMEOUT_SEC}
RETRIEVE_TIMEOUT_SEC=${RETRIEVE_TIMEOUT_SEC}
CONTINUE_ON_PHASE_ERROR=${CONTINUE_ON_PHASE_ERROR}
EOF
}

# ----------------------------------------------------------
# Network reset + readiness
# ----------------------------------------------------------
reset_network() {
  log "Resetting network (${CONSENSUS})..."

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

  ./network.sh deployCC -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl "$CC_LANG" -c "$CHANNEL_NAME"

  sleep "$POST_DEPLOY_WAIT_SEC"
}

list_real_orderers() {
  docker ps --format '{{.Names}}' | grep -E "$ORDERER_REGEX" | sort -V || true
}

wait_for_orderers_ready() {
  local deadline=$(( $(date +%s) + ORDERER_READY_TIMEOUT_SEC ))
  while true; do
    local count
    count="$(list_real_orderers | wc -l | tr -d ' ')"
    if [ "$count" -ge "$EXPECTED_ORDERERS" ]; then
      log "Orderer readiness OK: found ${count}/${EXPECTED_ORDERERS}"
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "ERROR: expected ${EXPECTED_ORDERERS} orderers, found ${count}" >&2
      list_real_orderers >&2 || true
      return 1
    fi
    sleep 2
  done
}

set_peer_env_org1_admin() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:7051

  export FABRIC_LOGGING_SPEC=ERROR
  export GRPC_GO_LOG_SEVERITY_LEVEL=error
  export GRPC_GO_LOG_VERBOSITY_LEVEL=0
}

verify_peer_target_ready() {
  set_peer_env_org1_admin
  log "Peer target readiness OK on ${CORE_PEER_ADDRESS}"
}

verify_chaincode_lifecycle_committed() {
  local expected_version="${1:-1.0}"
  local expected_sequence="${2:-1}"

  local qc_out qc_rc
  local qc_log="${RESULT_DIR}/last_querycommitted.log"

  set +e
  qc_out="$(
    peer lifecycle chaincode querycommitted \
      -C "$CHANNEL_NAME" \
      -n "$CC_NAME" \
      2>&1
  )"
  qc_rc=$?
  set -e

  printf '%s\n' "$qc_out" > "$qc_log"

  if [ "$qc_rc" -ne 0 ]; then
    echo "--- querycommitted combined output ---" >&2
    cat "$qc_log" >&2 || true
    echo "ERROR: peer lifecycle chaincode querycommitted failed" >&2
    return 1
  fi

  if ! grep -Fq "Committed chaincode definition for chaincode '$CC_NAME' on channel '$CHANNEL_NAME':" "$qc_log"; then
    echo "--- querycommitted combined output ---" >&2
    cat "$qc_log" >&2 || true
    echo "ERROR: committed definition marker not found for $CC_NAME on $CHANNEL_NAME" >&2
    return 1
  fi

  if ! grep -Eq "Version:[[:space:]]*${expected_version}([[:space:]]*,|$)" "$qc_log"; then
    echo "--- querycommitted combined output ---" >&2
    cat "$qc_log" >&2 || true
    echo "ERROR: expected chaincode version ${expected_version} not found" >&2
    return 1
  fi

  if ! grep -Eq "Sequence:[[:space:]]*${expected_sequence}([[:space:]]*,|$)" "$qc_log"; then
    echo "--- querycommitted combined output ---" >&2
    cat "$qc_log" >&2 || true
    echo "ERROR: expected chaincode sequence ${expected_sequence} not found" >&2
    return 1
  fi

  log "Lifecycle committed verification OK: chaincode=${CC_NAME}, channel=${CHANNEL_NAME}, version=${expected_version}, sequence=${expected_sequence}"
}

verify_chaincode_queryable() {
  local out rc
  local qlog="${RESULT_DIR}/last_chaincode_query.log"

  set +e
  out="$(
    peer chaincode query \
      -C "$CHANNEL_NAME" \
      -n "$CC_NAME" \
      -c '{"Args":["getSystemStatus"]}' \
      2>&1
  )"
  rc=$?
  set -e

  printf '%s\n' "$out" > "$qlog"

  if [ "$rc" -ne 0 ]; then
    echo "--- chaincode query output ---" >&2
    cat "$qlog" >&2 || true
    echo "ERROR: chaincode ${CC_NAME} is not queryable" >&2
    return 1
  fi

  log "Application query verification OK for ${CC_NAME}"
}

verify_network_ready() {
  wait_for_orderers_ready
  verify_peer_target_ready
  verify_chaincode_lifecycle_committed "$CC_VERSION" "$CC_SEQUENCE"
  verify_chaincode_queryable
  log "Network and chaincode verified ready"
}

# ----------------------------------------------------------
# Fault-set logic (nested high-impact family)
# ----------------------------------------------------------
calc_fault_set_for_k() {
  local k="$1"
  local family_csv="${HIGH_IMPACT_FAMILY_CSV}"

  if [ "$k" -eq 0 ]; then
    return 0
  fi

  mapfile -t family_nodes < <(echo "$family_csv" | tr ',' '\n' | sed '/^$/d')
  local family_n="${#family_nodes[@]}"

  if [ "$k" -gt "$family_n" ]; then
    echo "ERROR: requested k=${k} exceeds nested family size=${family_n}" >&2
    return 1
  fi

  local i
  for (( i=0; i<k; i++ )); do
    local node="${family_nodes[$i]}"
    if ! list_real_orderers | grep -Fxq "$node"; then
      echo "ERROR: fault target not found in running orderers: ${node}" >&2
      return 1
    fi
    echo "$node"
  done
}

format_fault_nodes_csv() {
  local k="$1"
  local nodes
  nodes="$(calc_fault_set_for_k "$k" | paste -sd'|' -)"
  echo "$nodes"
}

verify_injected_faults_stopped() {
  local nodes=("$@")
  local failed=0

  for n in "${nodes[@]}"; do
    local status
    status="$(docker inspect -f '{{.State.Status}}' "$n" 2>/dev/null || echo missing)"
    log "Post-injection status: ${n} => ${status}"
    if [ "$status" = "running" ]; then
      failed=$((failed + 1))
    fi
  done

  if [ "$failed" -gt 0 ]; then
    echo "ERROR: ${failed} injected fault target(s) still running after fault injection" >&2
    return 1
  fi

  return 0
}

inject_faults_now() {
  local rep="$1"
  local scope="$2"
  local phase="$3"
  local k="$4"

  if [ "$k" -eq 0 ]; then
    ACTUAL_FAULT_NODES_CSV=""
    log "No fault injection for rep=${rep} scope=${scope} phase=${phase} (k=0)"
    return 0
  fi

  mapfile -t nodes < <(calc_fault_set_for_k "$k")
  [ "${#nodes[@]}" -gt 0 ] || { echo "ERROR: empty fault-set" >&2; return 1; }

  ACTUAL_FAULT_NODES_CSV="$(printf '%s|' "${nodes[@]}" | sed 's/|$//')"
  log "Injecting nested high-impact faults: rep=${rep} scope=${scope} phase=${phase} k=${k} nodes=${ACTUAL_FAULT_NODES_CSV} cmd=${FAULT_CMD}"

  case "$FAULT_CMD" in
    stop0) docker stop -t 0 "${nodes[@]}" >/dev/null ;;
    stop)  docker stop "${nodes[@]}" >/dev/null ;;
    kill)  docker kill "${nodes[@]}" >/dev/null ;;
    *) echo "ERROR: unsupported FAULT_CMD=${FAULT_CMD}" >&2; return 1 ;;
  esac

  verify_injected_faults_stopped "${nodes[@]}"

  local epoch iso
  epoch="$(date +%s)"
  iso="$(date -Iseconds)"
  echo "${SCENARIO_ID},${rep},${scope},${phase},${MODE},${CONSENSUS},${BATCH},${TPS},${CURRENT_K_FAULT},${FAULT_FAMILY_NAME},${ACTUAL_FAULT_NODES_CSV},${FAULT_CMD},${epoch},${iso}" >> "$FAULT_CSV"
}

wait_for_round_start_marker() {
  local phase_log="$1"
  local marker="$2"
  local timeout_sec="$3"

  local deadline=$(( $(date +%s) + timeout_sec ))
  while true; do
    if grep -Fq "$marker" "$phase_log" 2>/dev/null; then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      return 1
    fi
    sleep 1
  done
}

# ----------------------------------------------------------
# External docker stats sampler
# ----------------------------------------------------------
start_external_resource_sampler() {
  local raw_csv="$1"
  local stopfile="$2"
  local interval="$3"
  local orderer_regex="$4"

  rm -f "$stopfile" 2>/dev/null || true
  PHASE_RESOURCE_RAW="$raw_csv"
  PHASE_RESOURCE_STOPFILE="$stopfile"

  python3 - "$raw_csv" "$stopfile" "$interval" "$orderer_regex" <<'PY' &
import csv, json, os, re, subprocess, sys, time

raw_csv, stopfile, interval, orderer_regex = sys.argv[1:]
interval = float(interval)
orderer_re = re.compile(orderer_regex)

peer_re = re.compile(r"^peer\d+\.org\d+\.example\.com$")
couch_re = re.compile(r"^couchdb\d+$")
ca_re = re.compile(r"^ca_")
cc_re = re.compile(r"^dev-peer.*forensicContract_")

def sh(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""

def parse_size_to_bytes(s):
    if s is None:
        return 0.0
    s = str(s).strip()
    if not s or s.lower() in {"0", "0b", "n/a", "-"}:
        return 0.0
    m = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*([A-Za-z]+)?\s*$", s)
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = (m.group(2) or "B").upper()
    factor = {
        "B": 1.0,
        "KB": 1000.0, "KIB": 1024.0,
        "MB": 1000.0**2, "MIB": 1024.0**2,
        "GB": 1000.0**3, "GIB": 1024.0**3,
        "TB": 1000.0**4, "TIB": 1024.0**4,
    }.get(unit, 1.0)
    return val * factor

def split_pair(s):
    parts = [p.strip() for p in str(s).split("/")]
    if len(parts) >= 2:
        return parts[0], parts[1]
    if len(parts) == 1:
        return parts[0], "0B"
    return "0B", "0B"

def interesting(name):
    return (
        orderer_re.match(name)
        or peer_re.match(name)
        or couch_re.match(name)
        or ca_re.match(name)
        or cc_re.match(name)
    )

with open(raw_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow([
        "epoch_s","iso_ts","container","status",
        "cpu_pct","mem_usage_mb","mem_limit_mb",
        "net_in_mb_total","net_out_mb_total",
        "disc_read_b_total","disc_write_mb_total"
    ])
    f.flush()

    while True:
        if os.path.exists(stopfile):
            break

        epoch_s = time.time()
        iso_ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch_s))

        running_names = [x.strip() for x in sh(["docker","ps","--format","{{.Names}}"]).splitlines() if x.strip()]
        all_names = [x.strip() for x in sh(["docker","ps","-a","--format","{{.Names}}"]).splitlines() if x.strip()]

        observed = {}

        if running_names:
            out = sh(["docker","stats","--no-stream","--format","{{json .}}"] + running_names)
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                name = obj.get("Name","").strip()
                if not name or not interesting(name):
                    continue

                cpu_s = str(obj.get("CPUPerc","0")).replace("%","").strip() or "0"
                try:
                    cpu_pct = float(cpu_s)
                except Exception:
                    cpu_pct = 0.0

                mem_used_s, mem_lim_s = split_pair(obj.get("MemUsage", "0B / 0B"))
                mem_usage_mb = parse_size_to_bytes(mem_used_s) / (1000.0**2)
                mem_limit_mb = parse_size_to_bytes(mem_lim_s) / (1000.0**2)

                net_in_s, net_out_s = split_pair(obj.get("NetIO", "0B / 0B"))
                net_in_mb_total = parse_size_to_bytes(net_in_s) / (1000.0**2)
                net_out_mb_total = parse_size_to_bytes(net_out_s) / (1000.0**2)

                disc_read_s, disc_write_s = split_pair(obj.get("BlockIO", "0B / 0B"))
                disc_read_b_total = parse_size_to_bytes(disc_read_s)
                disc_write_mb_total = parse_size_to_bytes(disc_write_s) / (1000.0**2)

                observed[name] = {
                    "status": "running",
                    "cpu_pct": cpu_pct,
                    "mem_usage_mb": mem_usage_mb,
                    "mem_limit_mb": mem_limit_mb,
                    "net_in_mb_total": net_in_mb_total,
                    "net_out_mb_total": net_out_mb_total,
                    "disc_read_b_total": disc_read_b_total,
                    "disc_write_mb_total": disc_write_mb_total,
                }

        final_names = set(name for name in observed if interesting(name))
        for name in all_names:
            if orderer_re.match(name):
                final_names.add(name)

        with open(raw_csv, "a", newline="", encoding="utf-8") as fa:
            wa = csv.writer(fa)
            for name in sorted(final_names):
                if name in observed:
                    row = observed[name]
                    wa.writerow([
                        f"{epoch_s:.3f}", iso_ts, name, row["status"],
                        f"{row['cpu_pct']:.6f}",
                        f"{row['mem_usage_mb']:.6f}",
                        f"{row['mem_limit_mb']:.6f}",
                        f"{row['net_in_mb_total']:.6f}",
                        f"{row['net_out_mb_total']:.6f}",
                        f"{row['disc_read_b_total']:.6f}",
                        f"{row['disc_write_mb_total']:.6f}",
                    ])
                else:
                    if orderer_re.match(name):
                        wa.writerow([
                            f"{epoch_s:.3f}", iso_ts, name, "stopped",
                            "0.000000", "0.000000", "0.000000",
                            "", "", "", ""
                        ])
            fa.flush()

        time.sleep(interval)
PY
  PHASE_RESOURCE_PID="$!"
}

stop_external_resource_sampler() {
  local stopfile="$1"
  local pid="$2"

  touch "$stopfile" 2>/dev/null || true
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    wait "$pid" 2>/dev/null || true
  fi
}

append_resource_rows_from_external_sampler() {
  local rep="$1" scope="$2" phase="$3" raw_csv="$4" target_round="$5" fault_nodes="$6"

  python3 - "$SCENARIO_ID" "$rep" "$scope" "$phase" "$MODE" "$CONSENSUS" "$BATCH" "$TPS" "$CURRENT_K_FAULT" "$FAULT_FAMILY_NAME" "$fault_nodes" "$raw_csv" "$target_round" >> "$RESOURCE_CSV" <<'PY'
import csv, sys
from collections import defaultdict

scenario, rep, scope, phase, mode, cons, batch, tps, k_fault, fault_family, fault_nodes, raw_csv, target = sys.argv[1:]

rows = []
with open(raw_csv, encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for r in reader:
        rows.append(r)

if not rows:
    raise SystemExit(0)

by_container = defaultdict(list)
for r in rows:
    by_container[r["container"]].append(r)

def f(x):
    s = str(x).strip()
    if s == "":
        return None
    try:
        return float(s)
    except Exception:
        return None

def mean(xs):
    return (sum(xs) / len(xs)) if xs else None

orderer_summary = []

for container, arr in sorted(by_container.items()):
    cpu_vals = [f(r["cpu_pct"]) for r in arr if f(r["cpu_pct"]) is not None]
    mem_vals = [f(r["mem_usage_mb"]) for r in arr if f(r["mem_usage_mb"]) is not None]
    net_in_series = [f(r["net_in_mb_total"]) for r in arr if f(r["net_in_mb_total"]) is not None]
    net_out_series = [f(r["net_out_mb_total"]) for r in arr if f(r["net_out_mb_total"]) is not None]
    disc_read_series = [f(r["disc_read_b_total"]) for r in arr if f(r["disc_read_b_total"]) is not None]
    disc_write_series = [f(r["disc_write_mb_total"]) for r in arr if f(r["disc_write_mb_total"]) is not None]

    cpu_avg = mean(cpu_vals)
    cpu_max = max(cpu_vals) if cpu_vals else None
    mem_avg = mean(mem_vals)
    mem_max = max(mem_vals) if mem_vals else None
    traffic_in_mb = (max(net_in_series) - min(net_in_series)) if len(net_in_series) >= 2 else (net_in_series[-1] if len(net_in_series) == 1 else None)
    traffic_out_mb = (max(net_out_series) - min(net_out_series)) if len(net_out_series) >= 2 else (net_out_series[-1] if len(net_out_series) == 1 else None)
    disc_read_b = (max(disc_read_series) - min(disc_read_series)) if len(disc_read_series) >= 2 else (disc_read_series[-1] if len(disc_read_series) == 1 else None)
    disc_write_mb = (max(disc_write_series) - min(disc_write_series)) if len(disc_write_series) >= 2 else (disc_write_series[-1] if len(disc_write_series) == 1 else None)

    print(",".join([
        scenario, rep, scope, phase, mode, cons, batch, tps, k_fault, fault_family, fault_nodes,
        target, container,
        f"{cpu_avg:.6f}" if cpu_avg is not None else "",
        f"{cpu_max:.6f}" if cpu_max is not None else "",
        f"{mem_avg:.6f}" if mem_avg is not None else "",
        f"{mem_max:.6f}" if mem_max is not None else "",
        f"{traffic_in_mb:.6f}" if traffic_in_mb is not None else "",
        f"{traffic_out_mb:.6f}" if traffic_out_mb is not None else "",
        f"{disc_read_b:.6f}" if disc_read_b is not None else "",
        f"{disc_write_mb:.6f}" if disc_write_mb is not None else "",
    ]))

    if container.startswith("orderer") and container.endswith(".example.com"):
        orderer_summary.append((cpu_avg, cpu_max, mem_avg, mem_max, traffic_in_mb, traffic_out_mb, disc_read_b, disc_write_mb))

if orderer_summary:
    def nn(i):
        return [x[i] for x in orderer_summary if x[i] is not None]

    cpu_avgs = nn(0)
    cpu_maxs = nn(1)
    mem_avgs = nn(2)
    mem_maxs = nn(3)
    tins = nn(4)
    touts = nn(5)
    dre = nn(6)
    dwr = nn(7)

    print(",".join([
        scenario, rep, scope, phase, mode, cons, batch, tps, k_fault, fault_family, fault_nodes,
        target, "ORDERERS_AGG",
        f"{mean(cpu_avgs):.6f}" if cpu_avgs else "",
        f"{mean(cpu_maxs):.6f}" if cpu_maxs else "",
        f"{mean(mem_avgs):.6f}" if mem_avgs else "",
        f"{mean(mem_maxs):.6f}" if mem_maxs else "",
        f"{sum(tins):.6f}" if tins else "",
        f"{sum(touts):.6f}" if touts else "",
        f"{sum(dre):.6f}" if dre else "",
        f"{sum(dwr):.6f}" if dwr else "",
    ]))
PY
}

# ----------------------------------------------------------
# Benchmark YAML generators (unsplit + preload only)
# ----------------------------------------------------------
build_submit_bench() {
  local src="$1" dst="$2" variant="$3" tps_real="$4" receipts_real="$5" receipts_warmup="$6" interval="$7"

  python3 - "$src" "$dst" "$variant" "$tps_real" "$receipts_real" "$receipts_warmup" "$interval" \
    "$WARMUP_SEC" "$WARMUP_TPS" "$UNSPLIT_REAL_SEC" \
    "$PRELOAD_REAL_SEC" "$PRELOAD_TPS" "$PRELOAD_WARMUP_SEC" "$PRELOAD_WARMUP_TPS" \
    "$SUBMIT_REAL_LABEL" "$WORKERS" "$SUBMIT_WARMUP_SEED" "$SUBMIT_REAL_SEED" "$PRELOAD_REAL_SEED" \
    "$SUBMIT_TIMEOUT_SEC" "$ENABLE_CALIPER_RESOURCE_MONITOR" <<'PY'
import sys, copy, yaml

(src, dst, variant, tps_real, receipts_real, receipts_warmup, interval,
 warmup_sec, warmup_tps, unsplit_real_sec,
 preload_real_sec, preload_tps, preload_warmup_sec, preload_warmup_tps,
 submit_real_label, workers, submit_warmup_seed, submit_real_seed, preload_real_seed,
 submit_timeout_sec, enable_monitor) = sys.argv[1:]

enable_monitor = (str(enable_monitor).lower() == "true")

doc = yaml.safe_load(open(src, encoding='utf-8'))
rounds = doc['test']['rounds']
warmup = next(r for r in rounds if r['label'] == 'submit-warmup')
real = next(r for r in rounds if r['label'] == submit_real_label)

warm = copy.deepcopy(warmup)
rl = copy.deepcopy(real)

if 'workers' in doc['test'] and isinstance(doc['test']['workers'], dict):
    doc['test']['workers']['number'] = int(workers)

if enable_monitor:
    res = doc.get('monitors', {}).get('resource', [])
    if res:
        res[0].setdefault('options', {})['interval'] = int(interval)
else:
    doc['monitors'] = {}

def set_submit_round(rt, label, dur, tps, receipts_dir, seed):
    rt['label'] = label
    rt['txDuration'] = int(dur)
    rt.setdefault('rateControl', {}).setdefault('opts', {})['tps'] = int(tps)
    args = rt.setdefault('workload', {}).setdefault('arguments', {})
    args['receiptsDir'] = receipts_dir
    args['seed'] = int(seed)
    args['txTimeoutSec'] = int(submit_timeout_sec)
    args['strictSuccess'] = True
    return rt

if variant == 'unsplit':
    new_rounds = [
        set_submit_round(warm, 'submit-warmup', warmup_sec, warmup_tps, receipts_warmup, submit_warmup_seed),
        set_submit_round(rl, submit_real_label, unsplit_real_sec, tps_real, receipts_real, submit_real_seed),
    ]
elif variant == 'preload':
    new_rounds = [
        set_submit_round(warm, 'submit-preload-warmup', preload_warmup_sec, preload_warmup_tps, receipts_warmup, submit_warmup_seed),
        set_submit_round(rl, 'submit-preload', preload_real_sec, preload_tps, receipts_real, preload_real_seed),
    ]
else:
    raise ValueError(f'Unsupported submit variant: {variant}')

doc['test']['rounds'] = new_rounds

with open(dst, 'w', encoding='utf-8') as f:
    yaml.safe_dump(doc, f, sort_keys=False)
PY
}

build_retrieve_bench() {
  local src="$1" dst="$2" tps_real="$3" receipts_path="$4" interval="$5"

  python3 - "$src" "$dst" "$tps_real" "$receipts_path" "$interval" \
    "$WARMUP_SEC" "$WARMUP_TPS" "$UNSPLIT_REAL_SEC" \
    "$RETRIEVE_REAL_LABEL" "$WORKERS" "$RETRIEVE_TIMEOUT_SEC" "$ENABLE_CALIPER_RESOURCE_MONITOR" <<'PY'
import sys, copy, yaml

(src, dst, tps_real, receipts_path, interval,
 warmup_sec, warmup_tps, unsplit_real_sec,
 retrieve_real_label, workers, retrieve_timeout_sec, enable_monitor) = sys.argv[1:]

enable_monitor = (str(enable_monitor).lower() == "true")

doc = yaml.safe_load(open(src, encoding='utf-8'))
rounds = doc['test']['rounds']
warmup = next(r for r in rounds if r['label'] == 'retrieve-warmup')
real = next(r for r in rounds if r['label'] == retrieve_real_label)

warm = copy.deepcopy(warmup)
rl = copy.deepcopy(real)

if 'workers' in doc['test'] and isinstance(doc['test']['workers'], dict):
    doc['test']['workers']['number'] = int(workers)

if enable_monitor:
    res = doc.get('monitors', {}).get('resource', [])
    if res:
        res[0].setdefault('options', {})['interval'] = int(interval)
else:
    doc['monitors'] = {}

def set_retrieve_round(rt, label, dur, tps, receipts_dir):
    rt['label'] = label
    rt['txDuration'] = int(dur)
    rt.setdefault('rateControl', {}).setdefault('opts', {})['tps'] = int(tps)
    args = rt.setdefault('workload', {}).setdefault('arguments', {})
    args['receiptsPath'] = receipts_dir
    args['readOnly'] = False
    args['funcRetrieve'] = 'retrieveEvidenceAndLog'
    args['requireSuccess'] = True
    args['strict'] = True
    args['txTimeoutSec'] = int(retrieve_timeout_sec)
    return rt

new_rounds = [
    set_retrieve_round(warm, 'retrieve-warmup', warmup_sec, warmup_tps, receipts_path),
    set_retrieve_round(rl, retrieve_real_label, unsplit_real_sec, tps_real, receipts_path),
]

doc['test']['rounds'] = new_rounds

with open(dst, 'w', encoding='utf-8') as f:
    yaml.safe_dump(doc, f, sort_keys=False)
PY
}

# ----------------------------------------------------------
# Performance report parser
# ----------------------------------------------------------
append_summary_row() {
  local rep="$1" scope="$2" phase="$3" html="$4" target_round="$5" fault_nodes="$6"

  python3 - "$SCENARIO_ID" "$rep" "$scope" "$phase" "$MODE" "$CONSENSUS" "$BATCH" "$TPS" "$CURRENT_K_FAULT" "$FAULT_FAMILY_NAME" "$fault_nodes" "$html" "$target_round" >> "$SUMMARY_CSV" <<'PY'
import sys, re
from html import unescape

scenario, rep, scope, phase, mode, cons, batch, tps, k_fault, fault_family, fault_nodes, path, target = sys.argv[1:]

def strip_tags(x):
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0', ' ').strip()

s = open(path, encoding='utf-8', errors='ignore').read()
m = re.search(r'id=\"benchmarksummary\".*?<table[^>]*>(.*?)</table>', s, re.S | re.I)
if not m:
    print(f"{scenario},{rep},{scope},{phase},{mode},{cons},{batch},{tps},{k_fault},{fault_family},{fault_nodes},{target},ERROR_NO_BENCHMARKSUMMARY,0,0,,,,")
    raise SystemExit(0)

rows = re.findall(r'<tr[^>]*>(.*?)</tr>', m.group(1), re.S | re.I)
parsed = []
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S | re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

headers = parsed[0]
row_dict = None
for r in parsed[1:]:
    if r and r[0] == target:
        row_dict = dict(zip(headers, r))
        break

if not row_dict:
    print(f"{scenario},{rep},{scope},{phase},{mode},{cons},{batch},{tps},{k_fault},{fault_family},{fault_nodes},{target},ERROR_TARGET_NOT_FOUND,0,0,,,,")
    raise SystemExit(0)

def g(k): return row_dict.get(k, '')
print(','.join([
    scenario, rep, scope, phase, mode, cons, batch, tps, k_fault, fault_family, fault_nodes,
    target, g('Name') or target, g('Succ') or '0', g('Fail') or '0',
    g('Send Rate (TPS)'), g('Max Latency (s)'), g('Min Latency (s)'),
    g('Avg Latency (s)'), g('Throughput (TPS)')
]))
PY
}

# ----------------------------------------------------------
# Caliper launchers
# ----------------------------------------------------------
run_phase_raw() {
  local rep="$1" scope="$2" phase="$3" bench_yaml="$4" net_yaml="$5" file_prefix="$6"

  rm -f report.html report.json 2>/dev/null || true
  rm -rf wallet/ 2>/dev/null || true

  local helper_log="${RESULT_DIR}/${file_prefix}.live.log"
  log "Launching helper Caliper run: rep=${rep} scope=${scope} phase=${phase}"

  if ! (
    set -o pipefail
    npx caliper launch manager \
      --caliper-workspace ./ \
      --caliper-benchconfig "$bench_yaml" \
      --caliper-networkconfig "$net_yaml" \
      --caliper-flow-only-test 2>&1 | tee "$helper_log"
  ); then
    log "Helper Caliper FAIL(exec): rep=${rep} scope=${scope} phase=${phase}"
    return 1
  fi

  if [ -f report.html ]; then
    mv report.html "${RESULT_DIR}/${file_prefix}.html"
    [ -f report.json ] && mv report.json "${RESULT_DIR}/${file_prefix}.json" || true
    log "Helper Caliper OK: rep=${rep} scope=${scope} phase=${phase}"
    return 0
  fi

  log "Helper Caliper FAIL(no report): rep=${rep} scope=${scope} phase=${phase}"
  return 1
}

run_phase_with_runtime_injection() {
  local rep="$1" scope="$2" phase="$3" bench_yaml="$4" net_yaml="$5" target_round="$6" fault_nodes="$7"

  rm -f report.html report.json 2>/dev/null || true
  rm -rf wallet/ 2>/dev/null || true

  ACTUAL_FAULT_NODES_CSV="$fault_nodes"

  local prefix="${SCENARIO_ID}_rep${rep}_${scope}_${phase}"
  local phase_log="${RESULT_DIR}/${prefix}.live.log"
  local raw_resource_csv="${RESULT_DIR}/${prefix}.dockerstats.csv"
  local stopfile="${RESULT_DIR}/${prefix}.dockerstats.stop"
  rm -f "$phase_log" 2>/dev/null || true

  start_external_resource_sampler "$raw_resource_csv" "$stopfile" "$EXTERNAL_RESOURCE_INTERVAL_SEC" "$ORDERER_REGEX"

  log "Launching Caliper with runtime injector: rep=${rep} scope=${scope} phase=${phase} planned_fault_nodes=${fault_nodes}"

  (
    set -o pipefail
    npx caliper launch manager \
      --caliper-workspace ./ \
      --caliper-benchconfig "$bench_yaml" \
      --caliper-networkconfig "$net_yaml" \
      --caliper-flow-only-test 2>&1 | tee "$phase_log"
  ) &
  local caliper_pid=$!

  local marker="Started round 2 (${target_round})"
  if wait_for_round_start_marker "$phase_log" "$marker" "$ROUND_MARKER_TIMEOUT_SEC"; then
    log "Detected real-round marker: ${marker}"
    sleep "$FAULT_AFTER_REAL_START_SEC"
    if kill -0 "$caliper_pid" >/dev/null 2>&1; then
      inject_faults_now "$rep" "$scope" "$phase" "$CURRENT_K_FAULT"
    else
      log "WARNING: Caliper exited before fault injection for rep=${rep} scope=${scope} phase=${phase}"
    fi
  else
    log "WARNING: Failed to detect real-round marker within timeout: ${marker}"
  fi

  set +e
  wait "$caliper_pid"
  local rc=$?
  set -e

  stop_external_resource_sampler "$PHASE_RESOURCE_STOPFILE" "$PHASE_RESOURCE_PID"

  if [ "$rc" -ne 0 ]; then
    log "Caliper exited with rc=${rc}: rep=${rep} scope=${scope} phase=${phase}"
  fi

  if [ -f report.html ]; then
    append_summary_row "$rep" "$scope" "$phase" "report.html" "$target_round" "$ACTUAL_FAULT_NODES_CSV"
    [ -f "$PHASE_RESOURCE_RAW" ] && append_resource_rows_from_external_sampler "$rep" "$scope" "$phase" "$PHASE_RESOURCE_RAW" "$target_round" "$ACTUAL_FAULT_NODES_CSV"
    mv report.html "${RESULT_DIR}/${prefix}.html"
    [ -f report.json ] && mv report.json "${RESULT_DIR}/${prefix}.json" || true
    log "Caliper OK(with runtime injector): rep=${rep} scope=${scope} phase=${phase}"
    return 0
  fi

  log "Caliper FAIL(no report, with runtime injector): rep=${rep} scope=${scope} phase=${phase}"
  return 1
}

# ----------------------------------------------------------
# Receipt helpers
# ----------------------------------------------------------
count_success_receipts() {
  local dir="$1"
  python3 - "$dir" <<'PY'
import os, sys, json
root = sys.argv[1]
ok = 0
if not os.path.isdir(root):
    print(0)
    raise SystemExit
for fn in os.listdir(root):
    if not fn.endswith('.ndjson'):
        continue
    p = os.path.join(root, fn)
    try:
        with open(p, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get('mode') == 'hybrid' and obj.get('evidenceId') and obj.get('failed') is not True:
                    ok += 1
    except Exception:
        pass
print(ok)
PY
}

validate_receipts_dir() {
  local dir="$1"
  [ -d "$dir" ] || { echo "ERROR: receipts dir not found: $dir" >&2; return 1; }
  find "$dir" -maxdepth 1 -type f -name '*.ndjson' | grep -q . || { echo "ERROR: no .ndjson receipts found in: $dir" >&2; return 1; }
}

# ----------------------------------------------------------
# Experiment workflows
# ----------------------------------------------------------
run_submit_experiment() {
  local rep="$1"

  local submit_root="${RESULT_DIR}/rep${rep}/submit"
  local submit_unsplit_dir="${submit_root}/receipts_unsplit"
  mkdir -p "$submit_unsplit_dir"

  reset_network
  verify_network_ready

  local gw_sk judge_sk
  gw_sk="$(pick_sk_file_latest "$ORG1_GW_KEYSTORE")"
  judge_sk="$(pick_sk_file_latest "$ORG2_JUDGE_KEYSTORE")"
  patch_network_yaml_keys "$gw_sk" "$judge_sk"

  local fault_nodes
  fault_nodes="$(format_fault_nodes_csv "$CURRENT_K_FAULT")"
  log "Submit fault set (nested high-impact): ${fault_nodes:-<none>}"

  local bench_unsplit="${RESULT_DIR}/patched_submit_rep${rep}_unsplit.yaml"
  build_submit_bench "$BENCH_SUBMIT_SRC" "$bench_unsplit" "unsplit" "$TPS" "$submit_unsplit_dir" "${submit_unsplit_dir}/warmup" "$MONITOR_INTERVAL_SEC"

  if ! run_phase_with_runtime_injection "$rep" "SUBMIT" "UNSPLIT" "$bench_unsplit" "$NET_SUBMIT_TMP" "$SUBMIT_REAL_LABEL" "$fault_nodes"; then
    should_continue_after_error || return 1
    log "WARNING: continuing after failed phase SUBMIT UNSPLIT rep=${rep}"
  fi

  sleep "$COOLDOWN_AFTER_SUBMIT_SEC"
}

prepare_retrieve_receipts_pool() {
  local rep="$1"

  local preload_root="${RESULT_DIR}/rep${rep}/retrieve_preload"
  local preload_real_dir="${preload_root}/receipts"
  mkdir -p "$preload_real_dir"
  preload_real_dir="$(abspath "$preload_real_dir")"

  local bench_preload="${RESULT_DIR}/patched_submit_rep${rep}_preload.yaml"
  build_submit_bench "$BENCH_SUBMIT_SRC" "$bench_preload" "preload" "$PRELOAD_TPS" "$preload_real_dir" "${preload_real_dir}/warmup" "$MONITOR_INTERVAL_SEC"

  run_phase_raw "$rep" "RETRIEVE-PRELOAD" "NOFAULT" "$bench_preload" "$NET_SUBMIT_TMP" "${SCENARIO_ID}_rep${rep}_RETRIEVE_PRELOAD_NOFAULT"

  validate_receipts_dir "$preload_real_dir"

  local ok_count
  ok_count="$(count_success_receipts "$preload_real_dir")"
  log "Retrieve preload receipts: rep=${rep} success_receipts=${ok_count} path=${preload_real_dir}"

  if [ "$ok_count" -lt "$MIN_SUCCESS_RECEIPTS" ]; then
    echo "ERROR: preload success receipts too few (${ok_count} < ${MIN_SUCCESS_RECEIPTS}) for rep=${rep}" >&2
    return 1
  fi

  PRELOAD_RECEIPTS_DIR="$preload_real_dir"
}

run_retrieve_experiment() {
  local rep="$1"

  reset_network
  verify_network_ready

  local gw_sk judge_sk
  gw_sk="$(pick_sk_file_latest "$ORG1_GW_KEYSTORE")"
  judge_sk="$(pick_sk_file_latest "$ORG2_JUDGE_KEYSTORE")"
  patch_network_yaml_keys "$gw_sk" "$judge_sk"

  local fault_nodes
  fault_nodes="$(format_fault_nodes_csv "$CURRENT_K_FAULT")"
  log "Retrieve fault set (nested high-impact): ${fault_nodes:-<none>}"

  PRELOAD_RECEIPTS_DIR=""
  prepare_retrieve_receipts_pool "$rep"

  [ -n "$PRELOAD_RECEIPTS_DIR" ] || { echo "ERROR: PRELOAD_RECEIPTS_DIR is empty" >&2; return 1; }
  validate_receipts_dir "$PRELOAD_RECEIPTS_DIR"
  log "Using retrieve preload receipts dir: ${PRELOAD_RECEIPTS_DIR}"

  local bench_unsplit="${RESULT_DIR}/patched_retrieve_rep${rep}_unsplit.yaml"
  build_retrieve_bench "$BENCH_RETRIEVE_SRC" "$bench_unsplit" "$TPS" "$PRELOAD_RECEIPTS_DIR" "$MONITOR_INTERVAL_SEC"

  if ! run_phase_with_runtime_injection "$rep" "RETRIEVE" "UNSPLIT" "$bench_unsplit" "$NET_RETRIEVE_TMP" "$RETRIEVE_REAL_LABEL" "$fault_nodes"; then
    should_continue_after_error || return 1
    log "WARNING: continuing after failed phase RETRIEVE UNSPLIT rep=${rep}"
  fi

  sleep "$COOLDOWN_AFTER_RETRIEVE_SEC"
}

# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
require_cmd docker
require_cmd python3
require_cmd npx
require_cmd peer
require_file "$BENCH_SUBMIT_SRC"
require_file "$BENCH_RETRIEVE_SRC"
require_file "$NET_SUBMIT_SRC"
require_file "$NET_RETRIEVE_SRC"
check_python_yaml || { echo "ERROR: python3 module 'yaml' is required." >&2; exit 1; }

mkdir -p "$RECEIPTS_BASE"

IFS=',' read -r -a K_SET <<< "$K_SET_CSV"

for k in "${K_SET[@]}"; do
  case "$k" in
    0|1|2|3) ;;
    *) echo "ERROR: unsupported k in K_SET_CSV: ${k}. Allowed: 0,1,2,3" >&2; exit 1 ;;
  esac

  init_scenario_outputs "$k"

  log "=========================================================="
  log "START: ${SCENARIO_ID}"
  log "Summary CSV : ${SUMMARY_CSV}"
  log "Resource CSV: ${RESOURCE_CSV}"
  log "Fault CSV   : ${FAULT_CSV}"
  log "Manifest    : ${MANIFEST_TXT}"
  log "=========================================================="

  for (( rep=1; rep<=TOTAL_REPETITIONS; rep++ )); do
    log "##########################################################"
    log "REPETITION ${rep}/${TOTAL_REPETITIONS} | ${SCENARIO_ID}"
    log "Fault family: ${FAULT_FAMILY_NAME}"
    log "Nested set  : ${HIGH_IMPACT_FAMILY_CSV}"
    log "K fault     : ${CURRENT_K_FAULT}"
    log "##########################################################"

    run_submit_experiment "$rep"
    run_retrieve_experiment "$rep"

    if [ "$rep" -lt "$TOTAL_REPETITIONS" ]; then
      sleep "$REST_BETWEEN_REPS_SEC"
    fi
  done

  log "=========================================================="
  log "DONE: ${SCENARIO_ID}"
  log "Summary CSV : ${SUMMARY_CSV}"
  log "Resource CSV: ${RESOURCE_CSV}"
  log "Fault CSV   : ${FAULT_CSV}"
  log "Reports dir : ${RESULT_DIR}"
  log "Log         : ${EXEC_LOG}"
  log "=========================================================="
done