#!/usr/bin/env bash
set -euo pipefail

# ==========================================================
# run_fault_orderer_changes_10orderers.sh (FINAL FIXED)
#
# GOAL:
#  Measure throughput/latency/resource under injected orderer crashes (docker stop)
#  - Baseline: 10 orderers running
#  - Consensus: Raft / SmartBFT
#  - Modes:
#      unsplit: warmup(30s) + real(60s), crash at warmup+10s
#      split  : warmup(30s) + pre(30s) + post(30s), crash at boundary pre->post
#
# FIXES vs previous fault script:
#  1) TPS patching outputs valid YAML: "tps: 100" (space after colon)
#  2) Keystore discovery supports "*_sk" and "priv_sk"
#  3) Orderer aggregation restricted to real orderer containers only
#  4) FORCE=1 overwrite protection
# ==========================================================

cd "$(dirname "$0")"

log() { echo -e "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
require_file() { [ -f "$1" ] || die "file tidak ditemukan: $1"; }

# -----------------------------
# Defaults (override via env)
# -----------------------------
CONSENSUS="${CONSENSUS:-SmartBFT}"          # SmartBFT / Raft
MODE="${MODE:-unsplit}"                    # unsplit / split
BATCH="${BATCH:-100}"                      # label only (Fabric config defines actual batch)
TPS="${TPS:-100}"                          # fixed-rate TPS for real rounds
TOTAL_REPETITIONS="${TOTAL_REPETITIONS:-5}"

# K sweep (fault nodes)
K_LIST="${K_LIST:-"1 2 3 4 5"}"

# Timing
WARMUP_SEC="${WARMUP_SEC:-30}"
REAL_SEC_UNSPLIT="${REAL_SEC_UNSPLIT:-60}"

PREFAULT_SEC="${PREFAULT_SEC:-30}"
POSTFAULT_SEC="${POSTFAULT_SEC:-30}"
SPLIT_GAP_SEC="${SPLIT_GAP_SEC:-2}"

FAULT_DELAY_AFTER_REAL_START="${FAULT_DELAY_AFTER_REAL_START:-10}"  # Yang et al style

# Cooldowns
COOLDOWN_AFTER_SUBMIT_SEC="${COOLDOWN_AFTER_SUBMIT_SEC:-10}"
COOLDOWN_AFTER_RETRIEVE_SEC="${COOLDOWN_AFTER_RETRIEVE_SEC:-60}"
REST_BETWEEN_REPS_SEC="${REST_BETWEEN_REPS_SEC:-15}"
REST_BETWEEN_SCENARIOS_SEC="${REST_BETWEEN_SCENARIOS_SEC:-30}"

# Network setup
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"
STATE_DB="${STATE_DB:-couchdb}"
CC_NAME="${CC_NAME:-forensicContract}"
CC_PATH="${CC_PATH:-../forensic/chaincode-javascript}"
CC_LANG="${CC_LANG:-javascript}"

# Bench + network configs
BENCH_SUBMIT_SRC="${BENCH_SUBMIT_SRC:-benchmarks/benchmark-consensus-submit.yaml}"
BENCH_RETRIEVE_SRC="${BENCH_RETRIEVE_SRC:-benchmarks/benchmark-consensus-retrieve.yaml}"

NET_SUBMIT_SRC="${NET_SUBMIT_SRC:-networks/network-consensus-submit.yaml}"
NET_RETRIEVE_SRC="${NET_RETRIEVE_SRC:-networks/network-consensus-retrieve.yaml}"
NET_SUBMIT_TMP="${NET_SUBMIT_TMP:-networks/_tmp_network-consensus-submit.yaml}"
NET_RETRIEVE_TMP="${NET_RETRIEVE_TMP:-networks/_tmp_network-consensus-retrieve.yaml}"

# Keys
ORG1_GW_KEYSTORE="${ORG1_GW_KEYSTORE:-$(pwd)/organizations/peerOrganizations/org1.example.com/users/GatewayCollector@org1.example.com/msp/keystore}"
ORG2_JUDGE_KEYSTORE="${ORG2_JUDGE_KEYSTORE:-$(pwd)/organizations/peerOrganizations/org2.example.com/users/Judge@org2.example.com/msp/keystore}"

# Receipts base
RECEIPTS_BASE="${RECEIPTS_BASE:-$(pwd)/data/receipts-fault}"

# Safety overwrite
FORCE="${FORCE:-0}"

# Orderer crash selection safety
ALLOW_STOP_ORDERER1="${ALLOW_STOP_ORDERER1:-false}"   # false: don't stop orderer.example.com
ORDERER_RECOVERY_WAIT_SEC="${ORDERER_RECOVERY_WAIT_SEC:-20}"

require_file "$BENCH_SUBMIT_SRC"
require_file "$BENCH_RETRIEVE_SRC"
require_file "$NET_SUBMIT_SRC"
require_file "$NET_RETRIEVE_SRC"

validate() {
  [[ "$MODE" == "unsplit" || "$MODE" == "split" ]] || die "MODE must be unsplit|split (got: $MODE)"
  [[ "$CONSENSUS" == "Raft" || "$CONSENSUS" == "SmartBFT" ]] || die "CONSENSUS must be Raft|SmartBFT (got: $CONSENSUS)"
}

# FIX: support *_sk and priv_sk
pick_sk_file_latest() {
  local keystore_dir="$1"
  local sk
  sk="$(ls -t "${keystore_dir}"/*_sk "${keystore_dir}/priv_sk" 2>/dev/null | head -n 1 || true)"
  [ -n "$sk" ] && [ -f "$sk" ] || die "tidak menemukan *_sk atau priv_sk di ${keystore_dir}"
  echo "$sk"
}

patch_network_yaml_keys() {
  local gw_sk="$1"
  local judge_sk="$2"
  sed "s|__GW_PRIVATE_KEY__|${gw_sk}|g" "$NET_SUBMIT_SRC" > "$NET_SUBMIT_TMP"
  sed "s|__JUDGE_PRIVATE_KEY__|${judge_sk}|g" "$NET_RETRIEVE_SRC" > "$NET_RETRIEVE_TMP"
}

# List only orderer containers (running), deterministic order
list_orderers_sorted() {
  docker ps --format '{{.Names}}' \
    | grep -E '^orderer(\.example\.com|[0-9]+\.example\.com)$' \
    | sort -V
}

# Select K orderers deterministically:
# - default: exclude orderer.example.com, then take highest-numbered orderers (orderer10..)
select_k_orderers_to_stop() {
  local k="$1"
  mapfile -t all < <(list_orderers_sorted)

  [ "${#all[@]}" -ge 10 ] || die "expected ~10 orderers running, found ${#all[@]}: ${all[*]}"

  local candidates=("${all[@]}")
  if [ "$ALLOW_STOP_ORDERER1" != "true" ]; then
    candidates=()
    for o in "${all[@]}"; do
      [ "$o" != "orderer.example.com" ] && candidates+=("$o")
    done
  fi

  if [ "$k" -le 0 ]; then
    return 0
  fi
  [ "${#candidates[@]}" -ge "$k" ] || die "candidates orderer kurang. candidates=${#candidates[@]} k=${k}"

  local start=$(( ${#candidates[@]} - k ))
  printf "%s\n" "${candidates[@]:$start:$k}"
}

start_all_orderers() {
  mapfile -t all < <(docker ps -a --format '{{.Names}}' | grep -E '^orderer(\.example\.com|[0-9]+\.example\.com)$' | sort -V || true)
  [ "${#all[@]}" -gt 0 ] || { log "WARN: no orderer containers found"; return 0; }
  docker start "${all[@]}" >/dev/null 2>&1 || true
  log "⏳ Waiting ${ORDERER_RECOVERY_WAIT_SEC}s for orderer cluster recovery..."
  sleep "$ORDERER_RECOVERY_WAIT_SEC"
}

reset_network() {
  local consensus="$1"
  log "🧱 Reset network (${consensus})..."
  ./network.sh down || true

  if [ "$consensus" = "SmartBFT" ]; then
    ./network.sh up createChannel -bft -c "$CHANNEL_NAME" -s "$STATE_DB"
  else
    ./network.sh up createChannel -c "$CHANNEL_NAME" -s "$STATE_DB"
  fi

  ./network.sh deployCC -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl "$CC_LANG" -c "$CHANNEL_NAME"
}

# ----------------------------------------------------------
# Patch bench YAML
#   - unsplit: patch TPS for base label only
#   - split  : duplicate base label into pre/post and patch durations and TPS
# IMPORTANT FIX: TPS line patched as "tps: 100" (valid YAML)
# ----------------------------------------------------------
patch_bench_yaml() {
  local mode="$1"          # submit|retrieve
  local src="$2"
  local dst="$3"
  local receipts_rep="$4"
  local tps_real="$5"
  local split_mode="$6"    # unsplit|split
  local receipts_warmup="${receipts_rep}/warmup"

  python3 - "$mode" "$src" "$dst" "$receipts_rep" "$receipts_warmup" "$tps_real" "$split_mode" \
    "$WARMUP_SEC" "$REAL_SEC_UNSPLIT" "$PREFAULT_SEC" "$POSTFAULT_SEC" <<'PY'
import sys, re
mode, src, dst, receipts_rep, receipts_warmup, tps_real, split_mode, warmup_sec, real_sec, pre_sec, post_sec = sys.argv[1:]
tps_real = int(tps_real)
warmup_sec = int(warmup_sec)
real_sec = int(real_sec)
pre_sec = int(pre_sec)
post_sec = int(post_sec)

SUBMIT_LABEL = "submitEvidence"
RETRIEVE_LABEL = "retrieveEvidenceAndLog"

lines = open(src, encoding="utf-8").read().splitlines(True)

def repl_line(line, key, value):
    m = re.match(r'^(\s*' + re.escape(key) + r')\s*.*$', line)
    if not m:
        return line
    return f"{m.group(1)} {value}\n"

# FIX: enforce space after colon
def repl_int_after_colon_space(line, key, value_int):
    # e.g. "tps:" or "txDuration:" -> "tps: 100"
    m = re.match(r'^(\s*' + re.escape(key) + r'\s*)\d+(\s*#.*)?\s*$', line)
    if not m:
        return line
    tail = m.group(2) or ""
    return f"{m.group(1)}{value_int}{tail}\n"

def find_block(label):
    pat = re.compile(r'^(\s*)-\s*label:\s*' + re.escape(label) + r'\s*$')
    start = None
    indent = None
    for i, ln in enumerate(lines):
        m = pat.match(ln)
        if m:
            start = i
            indent = m.group(1)
            break
    if start is None:
        return None
    end = None
    for j in range(start+1, len(lines)):
        if re.match(r'^\s*report:\s*$', lines[j]):
            end = j
            break
        if re.match(r'^' + re.escape(indent) + r'-\s*label:\s*', lines[j]):
            end = j
            break
    if end is None:
        end = len(lines)
    return start, end

def replace_label(block_lines, old, new):
    out=[]
    for ln in block_lines:
        if re.match(r'^\s*-\s*label:\s*' + re.escape(old) + r'\s*$', ln):
            ln = re.sub(re.escape(old), new, ln)
        out.append(ln)
    return out

def patch_block_common(block_lines):
    cur = None
    out=[]
    for ln in block_lines:
        m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_-]+)\s*$', ln)
        if m:
            cur = m.group(1)

        # receipts
        if mode == "submit":
            if re.match(r'^\s*receiptsDir:\s*', ln):
                if cur == "submit-warmup":
                    ln = repl_line(ln, "receiptsDir:", receipts_warmup)
                elif cur in (SUBMIT_LABEL, f"{SUBMIT_LABEL}_preFault", f"{SUBMIT_LABEL}_postFault"):
                    ln = repl_line(ln, "receiptsDir:", receipts_rep)

        if mode == "retrieve":
            if re.match(r'^\s*receiptsPath:\s*', ln):
                ln = repl_line(ln, "receiptsPath:", receipts_rep)
            if re.match(r'^\s*readOnly:\s*(true|false)\s*$', ln, re.I):
                ln = repl_line(ln, "readOnly:", "false")
            if re.match(r'^\s*funcRetrieve:\s*', ln):
                ln = repl_line(ln, "funcRetrieve:", RETRIEVE_LABEL)

        out.append(ln)
    return out

def patch_tps_for_label(block_lines, target_label, tps_value):
    cur=None
    out=[]
    for ln in block_lines:
        m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_-]+)\s*$', ln)
        if m:
            cur=m.group(1)
        if cur == target_label and re.match(r'^\s*tps:\s*\d+', ln):
            ln = repl_int_after_colon_space(ln, "tps:", tps_value)
        out.append(ln)
    return out

def patch_duration_for_label(block_lines, target_label, sec):
    cur=None
    out=[]
    for ln in block_lines:
        m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_-]+)\s*$', ln)
        if m:
            cur=m.group(1)
        if cur == target_label and re.match(r'^\s*txDuration:\s*\d+', ln):
            ln = repl_int_after_colon_space(ln, "txDuration:", sec)
        out.append(ln)
    return out

# Build new YAML
if split_mode == "split":
    base = SUBMIT_LABEL if mode=="submit" else RETRIEVE_LABEL
    blk = find_block(base)
    if not blk:
        raise SystemExit(f"ERROR: cannot find block label={base} in {src}")
    s,e = blk
    base_block = lines[s:e]

    pre_label = f"{base}_preFault"
    post_label = f"{base}_postFault"

    pre_block = replace_label(base_block, base, pre_label)
    post_block = replace_label(base_block, base, post_label)

    pre_block = patch_duration_for_label(pre_block, pre_label, pre_sec)
    post_block = patch_duration_for_label(post_block, post_label, post_sec)

    pre_block = patch_tps_for_label(pre_block, pre_label, tps_real)
    post_block = patch_tps_for_label(post_block, post_label, tps_real)

    pre_block = patch_block_common(pre_block)
    post_block = patch_block_common(post_block)

    head = patch_block_common(lines[:s])
    tail = patch_block_common(lines[e:])
    new_lines = head + pre_block + post_block + tail

else:
    # unsplit: patch TPS only for base real label
    cur=None
    out=[]
    for ln in lines:
        m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_-]+)\s*$', ln)
        if m:
            cur=m.group(1)

        if mode=="submit" and cur==SUBMIT_LABEL and re.match(r'^\s*tps:\s*\d+', ln):
            ln = repl_int_after_colon_space(ln, "tps:", tps_real)
        if mode=="retrieve" and cur==RETRIEVE_LABEL and re.match(r'^\s*tps:\s*\d+', ln):
            ln = repl_int_after_colon_space(ln, "tps:", tps_real)

        out.append(ln)

    new_lines = patch_block_common(out)

open(dst, "w", encoding="utf-8").write("".join(new_lines))
PY
}

# ----------------------------------------------------------
# Fault injection scheduling
# ----------------------------------------------------------
schedule_fault_stop() {
  local delay_sec="$1"
  local k="$2"
  local phase="$3"
  local rep="$4"
  local exec_log="$5"

  mapfile -t to_stop < <(select_k_orderers_to_stop "$k" || true)
  if [ "${#to_stop[@]}" -eq 0 ]; then
    echo "$(date -Iseconds) schedule fault: rep=${rep} phase=${phase} K=${k} (no stop targets)" >> "$exec_log"
    return 0
  fi

  echo "$(date -Iseconds) schedule fault: rep=${rep} phase=${phase} K=${k} delay=${delay_sec}s stop=[${to_stop[*]}]" >> "$exec_log"

  (
    sleep "$delay_sec"
    echo "$(date -Iseconds) INJECT fault: rep=${rep} phase=${phase} K=${k} docker stop [${to_stop[*]}]" >> "$exec_log"
    docker stop "${to_stop[@]}" >/dev/null 2>&1 || true
    sleep 2
    echo "$(date -Iseconds) orderers still running:" >> "$exec_log"
    list_orderers_sorted >> "$exec_log" || true
  ) &
  echo $!
}

# ----------------------------------------------------------
# HTML parser: summary (multi-round supported)
# ----------------------------------------------------------
append_summary_rows_multi() {
  local scenario="$1"
  local rep="$2"
  local phase="$3"
  local html="$4"
  shift 4
  local rounds=("$@")

  python3 - "$scenario" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$html" "${rounds[@]}" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, path = sys.argv[1:8]
targets = sys.argv[8:]

def strip_tags(x: str) -> str:
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0',' ').strip()

s = open(path, encoding="utf-8", errors="ignore").read()
m = re.search(r'id=\"benchmarksummary\".*?<table[^>]*>(.*?)</table>', s, re.S|re.I)
if not m:
    for target in targets:
        print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_NO_BENCHMARKSUMMARY,0,0,,,,")
    raise SystemExit(0)

tbl = m.group(1)
rows = re.findall(r'<tr[^>]*>(.*?)</tr>', tbl, re.S|re.I)

parsed=[]
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S|re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

if len(parsed) < 2:
    for target in targets:
        print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_EMPTY_SUMMARY,0,0,,,,")
    raise SystemExit(0)

headers = parsed[0]
table = [dict(zip(headers, r)) for r in parsed[1:] if len(r)==len(headers)]

def pick_row(label):
    for row in table:
        if row.get("Name","")==label:
            return row
    # fallback: first header col is usually Name
    h0 = headers[0]
    for row in table:
        if row.get(h0,"")==label:
            return row
    return None

for target in targets:
    d = pick_row(target)
    if not d:
        print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_TARGET_NOT_FOUND,0,0,,,,")
        continue

    def g(k): return d.get(k,"")
    print(",".join([
      scenario, rep, phase, cons, batch, tps, target,
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

# ----------------------------------------------------------
# HTML parser: resource rows + ORDERERS_AGG (real orderers only)
# ----------------------------------------------------------
append_resource_rows_one_round() {
  local scenario="$1"
  local rep="$2"
  local phase="$3"
  local html="$4"
  local target_round="$5"

  python3 - "$scenario" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$html" "$target_round" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, path, target = sys.argv[1:]

def strip_tags(x: str) -> str:
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0',' ').strip()

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
m_end = re.search(r'<div[^>]*id=\"[^\"]+\"[^>]*>\s*<h2[^>]*>\s*Benchmark round:', tail, re.I|re.S)
end = start + (m_end.start() if m_end else len(tail))
seg = s[start:end]

rows = re.findall(r"<tr[^>]*>(.*?)</tr>", seg, re.S|re.I)

parsed=[]
for r in rows:
    cells = re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", r, re.S|re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

header_idx=None
for i,r in enumerate(parsed):
    if "CPU%(max)" in r and "CPU%(avg)" in r and "Traffic In [MB]" in r and "Disc Write [MB]" in r:
        header_idx=i; break
if header_idx is None:
    raise SystemExit(0)

headers = parsed[header_idx]
idx = {h:i for i,h in enumerate(headers)}
def cell(row,h):
    j=idx.get(h,None)
    return row[j] if j is not None and j < len(row) else ""

orderer_rows=[]

for r in parsed[header_idx+1:]:
    if len(r) < len(headers):
        continue
    name = cell(r,"Name")
    if not name:
        continue

    cpu_avg = cell(r,"CPU%(avg)")
    cpu_max = cell(r,"CPU%(max)")
    mem_avg = cell(r,"Memory(avg) [MB]")
    mem_max = cell(r,"Memory(max) [MB]")
    tin = cell(r,"Traffic In [MB]")
    tout = cell(r,"Traffic Out [MB]")
    dread = cell(r,"Disc Read [B]")
    dwrite = cell(r,"Disc Write [MB]")

    print(",".join([
        scenario, rep, phase, cons, batch, tps, target,
        name,
        cpu_avg, cpu_max, mem_avg, mem_max,
        tin, tout, dread, dwrite
    ]))

    # FIX: only real orderer containers
    if re.match(r'^orderer(\d*)\.example\.com$', (name or "").strip(), re.I):
        orderer_rows.append((cpu_avg, cpu_max, mem_avg, mem_max, tin, tout, dread, dwrite))

if orderer_rows:
    cpu_avgs=[to_float(x[0]) for x in orderer_rows if to_float(x[0]) is not None]
    cpu_maxs=[to_float(x[1]) for x in orderer_rows if to_float(x[1]) is not None]
    mem_avgs=[to_float(x[2]) for x in orderer_rows if to_float(x[2]) is not None]
    mem_maxs=[to_float(x[3]) for x in orderer_rows if to_float(x[3]) is not None]
    tins=[to_float(x[4]) for x in orderer_rows if to_float(x[4]) is not None]
    touts=[to_float(x[5]) for x in orderer_rows if to_float(x[5]) is not None]
    dwrites=[to_float(x[7]) for x in orderer_rows if to_float(x[7]) is not None]

    def mean(xs): return (sum(xs)/len(xs)) if xs else None
    def summ(xs): return sum(xs) if xs else None

    print(",".join([
        scenario, rep, phase, cons, batch, tps, target,
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

run_phase() {
  local scenario="$1"
  local rep="$2"
  local phase="$3"        # SUBMIT / RETRIEVE
  local bench_yaml="$4"
  local net_yaml="$5"
  shift 5
  local real_rounds=("$@")

  rm -f report.html report.json 2>/dev/null || true

  log "▶️  Caliper ${phase} (rep ${rep})..."
  set +e
  npx caliper launch manager \
    --caliper-workspace ./ \
    --caliper-benchconfig "$bench_yaml" \
    --caliper-networkconfig "$net_yaml" \
    --caliper-flow-only-test
  local rc=$?
  set -e

  if [ $rc -ne 0 ]; then
    log "❌ Caliper FAILED rc=$rc (${phase} rep=${rep})"
    return 1
  fi
  [ -f "report.html" ] || { log "❌ report.html tidak ditemukan (${phase} rep=${rep})"; return 1; }

  local prefix="${scenario}_rep${rep}_${phase}"

  append_summary_rows_multi "$scenario" "$rep" "$phase" "report.html" "${real_rounds[@]}" >> "$SUMMARY_CSV"
  for r in "${real_rounds[@]}"; do
    append_resource_rows_one_round "$scenario" "$rep" "$phase" "report.html" "$r" >> "$RESOURCE_CSV"
  done

  mv "report.html" "${RESULT_DIR}/${prefix}.html"
  [ -f "report.json" ] && mv "report.json" "${RESULT_DIR}/${prefix}.json" || true

  return 0
}

prepare_scenario_dir() {
  local scenario_id="$1"
  local dir="research-results-fault/${scenario_id}"
  local sum="${dir}/${scenario_id}_summary_metrics.csv"

  if [ -d "$dir" ] && [ -s "$sum" ] && [ "$FORCE" != "1" ]; then
    die "folder scenario sudah ada dan summary CSV sudah terisi: ${dir}. Set FORCE=1 untuk overwrite."
  fi

  if [ "$FORCE" = "1" ]; then
    rm -rf "$dir" 2>/dev/null || true
  fi

  mkdir -p "$dir"
  echo "$dir"
}

run_one_scenario() {
  local consensus="$1"
  local mode="$2"
  local k="$3"

  local scenario_id="${consensus}_b${BATCH}_tps${TPS}_k${k}_${mode}"
  RESULT_DIR="$(prepare_scenario_dir "$scenario_id")"

  SUMMARY_CSV="${RESULT_DIR}/${scenario_id}_summary_metrics.csv"
  RESOURCE_CSV="${RESULT_DIR}/${scenario_id}_resource_metrics.csv"
  EXEC_LOG="${RESULT_DIR}/${scenario_id}_execution_log.txt"
  touch "$EXEC_LOG"

  if [ ! -s "$SUMMARY_CSV" ]; then
    echo "scenario,rep,phase,consensus,batch,tps,round_label,name,succ,fail,send_rate_tps,max_latency_s,min_latency_s,avg_latency_s,throughput_tps" > "$SUMMARY_CSV"
  fi
  if [ ! -s "$RESOURCE_CSV" ]; then
    echo "scenario,rep,phase,consensus,batch,tps,round_label,container,cpu_avg,cpu_max,mem_avg_mb,mem_max_mb,traffic_in_mb,traffic_out_mb,disc_read_b,disc_write_mb" > "$RESOURCE_CSV"
  fi

  mkdir -p "$RECEIPTS_BASE"

  log "=========================================================="
  log "SCENARIO: ${scenario_id}"
  log "Consensus : ${consensus}"
  log "Mode      : ${mode}"
  log "K faults  : ${k} (docker stop)"
  log "Batch/TPS : ${BATCH}/${TPS}"
  log "Reps      : ${TOTAL_REPETITIONS}"
  log "Output    : ${RESULT_DIR}"
  log "=========================================================="

  for (( REP=1; REP<=TOTAL_REPETITIONS; REP++ )); do
    log ""
    log "##########################################################"
    log "REP ${REP}/${TOTAL_REPETITIONS} | ${scenario_id}"
    log "##########################################################"
    echo "---- $(date -Iseconds) SCENARIO=${scenario_id} REP=${REP} ----" >> "$EXEC_LOG"

    # 1) Reset network
    reset_network "$consensus"

    # 2) Patch keys after reset
    local gw_sk judge_sk
    gw_sk="$(pick_sk_file_latest "$ORG1_GW_KEYSTORE")"
    judge_sk="$(pick_sk_file_latest "$ORG2_JUDGE_KEYSTORE")"
    patch_network_yaml_keys "$gw_sk" "$judge_sk"

    # 3) Receipts per rep
    local receipts_rep_dir
    receipts_rep_dir="${RECEIPTS_BASE}/${scenario_id}/rep${REP}"
    rm -rf "$receipts_rep_dir" 2>/dev/null || true
    mkdir -p "$receipts_rep_dir"

    # 4) Patch bench YAML per rep
    local patch_submit patch_retrieve
    patch_submit="${RESULT_DIR}/patched_submit_rep${REP}.yaml"
    patch_retrieve="${RESULT_DIR}/patched_retrieve_rep${REP}.yaml"
    patch_bench_yaml "submit" "$BENCH_SUBMIT_SRC" "$patch_submit" "$receipts_rep_dir" "$TPS" "$mode"
    patch_bench_yaml "retrieve" "$BENCH_RETRIEVE_SRC" "$patch_retrieve" "$receipts_rep_dir" "$TPS" "$mode"

    # 5) Determine real rounds + fault injection delay
    local SUBMIT_ROUNDS RETRIEVE_ROUNDS
    local submit_delay retrieve_delay

    if [ "$mode" = "unsplit" ]; then
      SUBMIT_ROUNDS=("submitEvidence")
      RETRIEVE_ROUNDS=("retrieveEvidenceAndLog")
      submit_delay=$((WARMUP_SEC + FAULT_DELAY_AFTER_REAL_START))
      retrieve_delay=$((WARMUP_SEC + FAULT_DELAY_AFTER_REAL_START))
    else
      SUBMIT_ROUNDS=("submitEvidence_preFault" "submitEvidence_postFault")
      RETRIEVE_ROUNDS=("retrieveEvidenceAndLog_preFault" "retrieveEvidenceAndLog_postFault")
      submit_delay=$((WARMUP_SEC + PREFAULT_SEC + SPLIT_GAP_SEC))
      retrieve_delay=$((WARMUP_SEC + PREFAULT_SEC + SPLIT_GAP_SEC))
    fi

    # Ensure orderers up before SUBMIT scheduling
    start_all_orderers

    # 6) Schedule fault during SUBMIT (background)
    local pid_submit=""
    pid_submit="$(schedule_fault_stop "$submit_delay" "$k" "SUBMIT" "$REP" "$EXEC_LOG" || true)"

    rm -rf wallet/ 2>/dev/null || true
    if run_phase "$scenario_id" "$REP" "SUBMIT" "$patch_submit" "$NET_SUBMIT_TMP" "${SUBMIT_ROUNDS[@]}"; then
      echo "$(date -Iseconds) rep=${REP} phase=SUBMIT OK" >> "$EXEC_LOG"
    else
      echo "$(date -Iseconds) rep=${REP} phase=SUBMIT FAIL" >> "$EXEC_LOG"
    fi

    [ -n "${pid_submit:-}" ] && wait "$pid_submit" 2>/dev/null || true

    sleep "$COOLDOWN_AFTER_SUBMIT_SEC"

    # Ensure orderers up again before RETRIEVE
    start_all_orderers

    # 7) Schedule fault during RETRIEVE
    local pid_retrieve=""
    pid_retrieve="$(schedule_fault_stop "$retrieve_delay" "$k" "RETRIEVE" "$REP" "$EXEC_LOG" || true)"

    rm -rf wallet/ 2>/dev/null || true
    if run_phase "$scenario_id" "$REP" "RETRIEVE" "$patch_retrieve" "$NET_RETRIEVE_TMP" "${RETRIEVE_ROUNDS[@]}"; then
      echo "$(date -Iseconds) rep=${REP} phase=RETRIEVE OK" >> "$EXEC_LOG"
    else
      echo "$(date -Iseconds) rep=${REP} phase=RETRIEVE FAIL" >> "$EXEC_LOG"
    fi

    [ -n "${pid_retrieve:-}" ] && wait "$pid_retrieve" 2>/dev/null || true

    sleep "$COOLDOWN_AFTER_RETRIEVE_SEC"
    [ "$REP" -lt "$TOTAL_REPETITIONS" ] && sleep "$REST_BETWEEN_REPS_SEC"
  done

  log ""
  log "✅ DONE SCENARIO: ${scenario_id}"
  log " - Summary : ${SUMMARY_CSV}"
  log " - Resource: ${RESOURCE_CSV}"
  log " - Log     : ${EXEC_LOG}"
  log "=========================================================="
}

usage() {
  cat <<EOF
Usage:
  Single:
    ./run_fault_orderer_changes_10orderers.sh single <Raft|SmartBFT> <unsplit|split> <K>

  All (sweep K_LIST for a given consensus/mode):
    ./run_fault_orderer_changes_10orderers.sh all <Raft|SmartBFT> <unsplit|split>

Env overrides:
  BATCH=100 TPS=100 TOTAL_REPETITIONS=5
  K_LIST="1 2 3 4 5"
  WARMUP_SEC=30 REAL_SEC_UNSPLIT=60
  PREFAULT_SEC=30 POSTFAULT_SEC=30 SPLIT_GAP_SEC=2
  FAULT_DELAY_AFTER_REAL_START=10
  FORCE=1 (overwrite scenario folder)
EOF
}

main() {
  validate

  local cmd="${1:-}"
  case "$cmd" in
    single)
      local consensus="${2:-}"
      local mode="${3:-}"
      local k="${4:-}"
      [ -n "$consensus" ] || die "single butuh consensus"
      [ -n "$mode" ] || die "single butuh mode"
      [ -n "$k" ] || die "single butuh K"
      CONSENSUS="$consensus"
      MODE="$mode"
      run_one_scenario "$consensus" "$mode" "$k"
      ;;
    all)
      local consensus="${2:-}"
      local mode="${3:-}"
      [ -n "$consensus" ] || die "all butuh consensus"
      [ -n "$mode" ] || die "all butuh mode"
      CONSENSUS="$consensus"
      MODE="$mode"
      for k in $K_LIST; do
        run_one_scenario "$consensus" "$mode" "$k"
        sleep "$REST_BETWEEN_SCENARIOS_SEC"
      done
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      die "unknown command: $cmd"
      ;;
  esac
}

main "$@"