#!/bin/bash
set -euo pipefail

# ==========================================================
# 5 REPS, RESET NETWORK EACH REP (ONE SCENARIO) + ANALYTICS CSV
# - CSV gabungan untuk seluruh repetisi (rep1..rep5)
# - Hanya ambil metrik round REAL (submitEvidence / retrieveEvidenceAndLog)
# - Tetap simpan report.html/json per phase untuk audit trail
# ==========================================================

CONSENSUS="${1:-SmartBFT}"   # "Raft" / "SmartBFT"
BATCH="${2:-10}"             # label untuk folder hasil (batch Anda set manual)
TPS="${3:-150}"              # 50/100/150/200
TOTAL_REPETITIONS="${4:-5}"

CHANNEL_NAME="forensic-channel"
STATE_DB="couchdb"
CC_NAME="forensicContract"
CC_PATH="../forensic/chaincode-javascript"
CC_LANG="javascript"

# --------------------------
# Cooldowns (override via env)
# --------------------------
COOLDOWN_AFTER_SUBMIT_SEC="${COOLDOWN_AFTER_SUBMIT_SEC:-10}"
# dukung env lama COOLDOWN_AFTER_AUDITED_SEC kalau ada
COOLDOWN_AFTER_RETRIEVE_SEC="${COOLDOWN_AFTER_RETRIEVE_SEC:-${COOLDOWN_AFTER_AUDITED_SEC:-60}}"

REST_BETWEEN_REPS_SEC="${REST_BETWEEN_REPS_SEC:-15}"

BENCH_SUBMIT_SRC="benchmarks/benchmark-consensus-submit.yaml"
BENCH_RETRIEVE_SRC="benchmarks/benchmark-consensus-retrieve.yaml"

NET_SUBMIT_SRC="networks/network-consensus-submit.yaml"
NET_RETRIEVE_SRC="networks/network-consensus-retrieve.yaml"
NET_SUBMIT_TMP="networks/_tmp_network-consensus-submit.yaml"
NET_RETRIEVE_TMP="networks/_tmp_network-consensus-retrieve.yaml"

RECEIPTS_BASE="/home/labnuc/2labforensic/fabric-samples/test-network/data/receipts"

ORG1_GW_KEYSTORE="/home/labnuc/2labforensic/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/GatewayCollector@org1.example.com/msp/keystore"
ORG2_JUDGE_KEYSTORE="/home/labnuc/2labforensic/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/users/Judge@org2.example.com/msp/keystore"

# --------------------------
# Network reset waits (UPDATED FOR STABILITY)
# --------------------------
NET_DOWN_WAIT_SEC="${NET_DOWN_WAIT_SEC:-15}" # Was 5
NET_UP_WAIT_SEC="${NET_UP_WAIT_SEC:-20}"     # Was 10

# ====== ROUND LABELS (UPDATED) ======
SUBMIT_ROUND_LABEL="${SUBMIT_ROUND_LABEL:-submitEvidence}"
RETRIEVE_ROUND_LABEL="${RETRIEVE_ROUND_LABEL:-retrieveEvidenceAndLog}"  # chaincode terbaru

SCENARIO_ID="${CONSENSUS}_b${BATCH}_tps${TPS}"
RESULT_DIR="research-results/${SCENARIO_ID}"
mkdir -p "$RESULT_DIR"

# ========= ANALYTICS CSV (gabungan semua repetisi) =========
# Nama file sesuai format yang kamu minta
SUMMARY_CSV="${RESULT_DIR}/${CONSENSUS}_b${BATCH}_tps${TPS}_summary_metrics.csv"
RESOURCE_CSV="${RESULT_DIR}/${CONSENSUS}_b${BATCH}_tps${TPS}_resource_metrics.csv"
EXEC_LOG="${RESULT_DIR}/${SCENARIO_ID}_execution_log.txt"
touch "$EXEC_LOG"

# Header: satu baris = 1 phase (SUBMIT/RETRIEVE) pada 1 repetisi
if [ ! -s "$SUMMARY_CSV" ]; then
  echo "scenario,rep,phase,consensus,batch,tps,round_label,name,succ,fail,send_rate_tps,max_latency_s,min_latency_s,avg_latency_s,throughput_tps" > "$SUMMARY_CSV"
fi

# Header: per container + agregat ORDERERS_AGG
# (tetap copy angka mentah dari report.html; Traffic In/Out tetap MB)
if [ ! -s "$RESOURCE_CSV" ]; then
  echo "scenario,rep,phase,consensus,batch,tps,round_label,container,cpu_avg,cpu_max,mem_avg_mb,mem_max_mb,traffic_in_mb,traffic_out_mb,disc_read_b,disc_write_mb" > "$RESOURCE_CSV"
fi

require_file() { [ -f "$1" ] || { echo "ERROR: file tidak ditemukan: $1" >&2; exit 1; }; }
require_file "$BENCH_SUBMIT_SRC"
require_file "$BENCH_RETRIEVE_SRC"
require_file "$NET_SUBMIT_SRC"
require_file "$NET_RETRIEVE_SRC"

pick_sk_file_latest() {
  local keystore_dir="$1"
  local sk
  sk="$(ls -t "${keystore_dir}"/*_sk 2>/dev/null | head -n 1 || true)"
  if [ -z "$sk" ] || [ ! -f "$sk" ]; then
    echo "ERROR: tidak menemukan *_sk di ${keystore_dir}" >&2
    return 1
  fi
  echo "$sk"
}

escape_sed_repl() { echo "$1" | sed -e 's/[&]/\\&/g'; }

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
# ROBUST RESET NETWORK FUNCTION (as requested)
# ==========================================================
reset_network() {
  echo "🧱 Reset network (${CONSENSUS})..."

  # 1) Polite shutdown
  ./network.sh down || true

  # 2) Aggressive cleanup
  echo "🧹 Cleaning up residual containers and networks..."
  if [ -n "$(docker ps -q 2>/dev/null || true)" ]; then
    docker kill $(docker ps -q) >/dev/null 2>&1 || true
  fi
  if [ -n "$(docker ps -aq 2>/dev/null || true)" ]; then
    docker rm -f $(docker ps -aq) >/dev/null 2>&1 || true
  fi
  docker network prune -f >/dev/null 2>&1 || true
  docker volume prune -f >/dev/null 2>&1 || true

  # 3) Wait for OS settle
  echo "⏳ Waiting ${NET_DOWN_WAIT_SEC}s for system settle..."
  sleep "$NET_DOWN_WAIT_SEC"

  # 4) Start fresh
  if [ "$CONSENSUS" = "SmartBFT" ]; then
    ./network.sh up createChannel -bft -c "$CHANNEL_NAME" -s "$STATE_DB"
  else
    ./network.sh up createChannel -c "$CHANNEL_NAME" -s "$STATE_DB"
  fi

  echo "⏳ Waiting ${NET_UP_WAIT_SEC}s before deploying CC..."
  sleep "$NET_UP_WAIT_SEC"

  ./network.sh deployCC -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl "$CC_LANG" -c "$CHANNEL_NAME"
}

# Patch bench YAML per rep:
# - receipts path/dir
# - TPS for REAL rounds (submitEvidence + retrieveEvidenceAndLog)
# - retrieve readOnly=false
# - (optional) force funcRetrieve=retrieveEvidenceAndLog (if field exists)
patch_bench_yaml() {
  local mode="$1"          # submit|retrieve
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
    m = re.match(r'^\s*-\s*label:\s*([A-Za-z0-9_-]+)\s*$', line)
    if m:
        cur_label = m.group(1)

    # Patch TPS hanya real rounds
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

        # ensure ordered tx
        if re.match(r'^\s*readOnly:\s*(true|false)\s*$', line, re.I):
            lines[i] = repl_line(line, "readOnly:", "false")

        # if funcRetrieve field exists, force audited function
        if re.match(r'^\s*funcRetrieve:\s*', line):
            lines[i] = repl_line(line, "funcRetrieve:", "retrieveEvidenceAndLog")

open(dst, "w", encoding="utf-8").write("".join(lines))
PY
}

# ====== Parsers: tulis 1 baris ringkasan (REAL round) ======
append_summary_row() {
  local rep="$1"
  local phase="$2"
  local html="$3"
  local target_round="$4"

  python3 - "$SCENARIO_ID" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$html" "$target_round" >> "$SUMMARY_CSV" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, path, target = sys.argv[1:]

def strip_tags(x: str) -> str:
    x = re.sub(r'<[^>]+>', '', x)
    return unescape(x).replace('\xa0', ' ').strip()

s = open(path, encoding="utf-8", errors="ignore").read()
m = re.search(r'id=\"benchmarksummary\".*?<table[^>]*>(.*?)</table>', s, re.S|re.I)
if not m:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_NO_BENCHMARKSUMMARY,0,0,,,,")
    raise SystemExit(0)

tbl = m.group(1)
rows = re.findall(r'<tr[^>]*>(.*?)</tr>', tbl, re.S|re.I)

parsed = []
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S|re.I)
    if cells:
        parsed.append([strip_tags(c) for c in cells])

if len(parsed) < 2:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_EMPTY_SUMMARY,0,0,,,,")
    raise SystemExit(0)

headers = parsed[0]
row_dict = None
for r in parsed[1:]:
    if r and r[0] == target:
        row_dict = dict(zip(headers, r))
        break

if not row_dict:
    print(f"{scenario},{rep},{phase},{cons},{batch},{tps},{target},ERROR_TARGET_NOT_FOUND,0,0,,,,")
    raise SystemExit(0)

def g(k): return row_dict.get(k, "")

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

# ====== Parsers: resource -> multirow + ORDERERS_AGG ======
append_resource_rows() {
  local rep="$1"
  local phase="$2"
  local html="$3"
  local target_round="$4"

  python3 - "$SCENARIO_ID" "$rep" "$phase" "$CONSENSUS" "$BATCH" "$TPS" "$html" "$target_round" >> "$RESOURCE_CSV" <<'PY'
import sys, re
from html import unescape

scenario, rep, phase, cons, batch, tps, path, target = sys.argv[1:]

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
m_end = re.search(r'<div[^>]*id=\"[^\"]+\"[^>]*>\s*<h2[^>]*>\s*Benchmark round:', tail, re.I|re.S)
end = start + (m_end.start() if m_end else len(tail))
seg = s[start:end]

rows = re.findall(r'<tr[^>]*>(.*?)</tr>', seg, re.S|re.I)

parsed = []
for r in rows:
    cells = re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', r, re.S|re.I)
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
idx = {h:i for i,h in enumerate(headers)}

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

    # CSV order follows header you defined:
    # cpu_avg,cpu_max,mem_avg,mem_max,traffic_in,traffic_out,disc_read_b,disc_write_mb
    print(",".join([
        scenario, rep, phase, cons, batch, tps, target,
        name,
        cpu_avg, cpu_max, mem_avg, mem_max,
        tin, tout, dread, dwrite
    ]))

    if "orderer" in name.lower():
        orderer_rows.append((cpu_avg, cpu_max, mem_avg, mem_max, tin, tout, dread, dwrite))

# ORDERERS_AGG: mean cpu/mem, sum traffic/write (raw values from report.html)
if orderer_rows:
    cpu_avgs = [to_float(x[0]) for x in orderer_rows if to_float(x[0]) is not None]
    cpu_maxs = [to_float(x[1]) for x in orderer_rows if to_float(x[1]) is not None]
    mem_avgs = [to_float(x[2]) for x in orderer_rows if to_float(x[2]) is not None]
    mem_maxs = [to_float(x[3]) for x in orderer_rows if to_float(x[3]) is not None]
    tins = [to_float(x[4]) for x in orderer_rows if to_float(x[4]) is not None]
    touts = [to_float(x[5]) for x in orderer_rows if to_float(x[5]) is not None]
    dwrites = [to_float(x[7]) for x in orderer_rows if to_float(x[7]) is not None]

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
        "",  # disc_read_b aggregated is often meaningless here; keep blank
        f"{summ(dwrites):.6f}" if summ(dwrites) is not None else "",
    ]))
PY
}

run_phase() {
  local rep="$1"
  local phase="$2"          # SUBMIT / RETRIEVE
  local bench_yaml="$3"
  local net_yaml="$4"
  local target_round="$5"   # submitEvidence / retrieveEvidenceAndLog

  rm -f report.html report.json 2>/dev/null || true

  echo "▶️  Caliper ${phase} (rep ${rep})..."
  npx caliper launch manager \
    --caliper-workspace ./ \
    --caliper-benchconfig "$bench_yaml" \
    --caliper-networkconfig "$net_yaml" \
    --caliper-flow-only-test

  if [ -f "report.html" ]; then
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

mkdir -p "$RECEIPTS_BASE"

echo "=========================================================="
echo "START: $SCENARIO_ID"
echo "CSV  : $SUMMARY_CSV"
echo "CSV  : $RESOURCE_CSV"
echo "=========================================================="

for (( i=1; i<=TOTAL_REPETITIONS; i++ )); do
  echo ""
  echo "##########################################################"
  echo "   REPETITION $i / $TOTAL_REPETITIONS  |  $SCENARIO_ID"
  echo "##########################################################"

  reset_network

  GW_SK="$(pick_sk_file_latest "$ORG1_GW_KEYSTORE")"
  JUDGE_SK="$(pick_sk_file_latest "$ORG2_JUDGE_KEYSTORE")"
  patch_network_yaml_keys "$GW_SK" "$JUDGE_SK"

  RECEIPTS_REP_DIR="${RECEIPTS_BASE}/${SCENARIO_ID}/rep${i}"
  rm -rf "$RECEIPTS_REP_DIR" 2>/dev/null || true
  mkdir -p "$RECEIPTS_REP_DIR"

  PATCH_SUBMIT="${RESULT_DIR}/patched_submit_rep${i}.yaml"
  PATCH_RETRIEVE="${RESULT_DIR}/patched_retrieve_rep${i}.yaml"
  patch_bench_yaml "submit" "$BENCH_SUBMIT_SRC" "$PATCH_SUBMIT" "$RECEIPTS_REP_DIR" "$TPS"
  patch_bench_yaml "retrieve" "$BENCH_RETRIEVE_SRC" "$PATCH_RETRIEVE" "$RECEIPTS_REP_DIR" "$TPS"

  rm -rf wallet/ 2>/dev/null || true
  run_phase "$i" "SUBMIT" "$PATCH_SUBMIT" "$NET_SUBMIT_TMP" "$SUBMIT_ROUND_LABEL" || true

  echo "⏳ Cooldown after submit: ${COOLDOWN_AFTER_SUBMIT_SEC}s"
  sleep "$COOLDOWN_AFTER_SUBMIT_SEC"

  rm -rf wallet/ 2>/dev/null || true
  run_phase "$i" "RETRIEVE" "$PATCH_RETRIEVE" "$NET_RETRIEVE_TMP" "$RETRIEVE_ROUND_LABEL" || true

  echo "⏳ Cooldown after retrieve: ${COOLDOWN_AFTER_RETRIEVE_SEC}s"
  sleep "$COOLDOWN_AFTER_RETRIEVE_SEC"

  if [ $i -lt $TOTAL_REPETITIONS ]; then
    sleep "$REST_BETWEEN_REPS_SEC"
  fi
done

echo ""
echo "=========================================================="
echo "DONE: $SCENARIO_ID"
echo "Summary CSV : $SUMMARY_CSV"
echo "Resource CSV: $RESOURCE_CSV"
echo "Reports dir : $RESULT_DIR"
echo "Log         : $EXEC_LOG"
echo "=========================================================="