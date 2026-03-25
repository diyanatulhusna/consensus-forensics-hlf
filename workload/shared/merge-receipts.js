'use strict';

const fs = require('fs');
const path = require('path');

function mergeWorkerReceipts(receiptsPath, totalWorkers = 5) {
  const full = path.isAbsolute(receiptsPath) ? receiptsPath : path.join(process.cwd(), receiptsPath);
  const dir = path.dirname(full);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  console.log('\n╔════════════════════════════════════════════════════════════');
  console.log('║ MERGING WORKER RECEIPT FILES');
  console.log('╚════════════════════════════════════════════════════════════');

  let all = [];
  let filesFound = 0;

  for (let i = 0; i < totalWorkers; i++) {
    const wfile = `${full}.worker${i}.tmp`;
    if (fs.existsSync(wfile)) {
      try {
        const data = JSON.parse(fs.readFileSync(wfile, 'utf8'));
        const count = Array.isArray(data) ? data.length : 0;
        console.log(`  • Worker ${i}: ${count} receipts`);
        if (Array.isArray(data)) all = all.concat(data);
        filesFound++;
      } catch (e) {
        console.error(`  ✗ Worker ${i}: parse error: ${e.message}`);
      } finally {
        try { fs.unlinkSync(wfile); } catch {}
      }
    } else {
      console.log(`  • Worker ${i}: no file`);
    }
  }

  // de-dup by (mode|evidenceId)
  const seen = new Set();
  all = all.filter(r => {
    const k = `${r.mode}|${r.evidenceId}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  // sort by time
  all.sort((a, b) => (a.time || 0) - (b.time || 0));

  if (all.length > 0) {
    fs.writeFileSync(full, JSON.stringify(all, null, 2));
    console.log('\n╔════════════════════════════════════════════════════════════');
    console.log('║ ✅ MERGE COMPLETE');
    console.log('╠════════════════════════════════════════════════════════════');
    console.log(`║ Files merged   : ${filesFound}/${totalWorkers}`);
    console.log(`║ Total receipts : ${all.length}`);
    console.log(`║ Output         : ${full}`);
    console.log('╚════════════════════════════════════════════════════════════\n');
  } else {
    console.error('\n❌ No receipts found from any worker!\n');
  }
  return all.length;
}

if (require.main === module) {
  const receiptsPath = process.argv[2] || './data/submit_receipts.json';
  const totalWorkers = parseInt(process.argv[3] || '5', 10);
  mergeWorkerReceipts(receiptsPath, totalWorkers);
}

module.exports = { mergeWorkerReceipts };