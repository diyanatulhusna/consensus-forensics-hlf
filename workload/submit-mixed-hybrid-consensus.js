'use strict';

/**
 * submit-mixed-hybrid-consensus.js (FINAL)
 * - evidenceId ALWAYS <= 64 and regex-safe
 * - receipt marks failed:false ONLY if chaincode returned success:true
 * - receipt marks failed:true on any error / non-success response
 * - store returned on-chain/audit sizes when available
 * - timeout bump on DEADLINE_EXCEEDED
 */

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const EvidenceLoader = require('./shared/evidence-loader');
const MixedEvidenceSelector = require('./shared/mixed-evidence-selector');
const DummyCIDGenerator = require('./shared/dummy-cid');
const PayloadBuilder = require('./shared/payload-builders');
const fs = require('fs');
const path = require('path');

const receiptsDirState = Object.create(null);

function percentile(sorted, p) {
  if (!sorted || sorted.length === 0) return NaN;
  const idx = Math.ceil(p * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
}

function decodeCaliperResult(res) {
  let asString = '';
  try {
    const item = Array.isArray(res) ? res[0] : res;
    if (!item) return {};

    const txId =
      (typeof item.GetID === 'function' && item.GetID()) ||
      (typeof item.getId === 'function' && item.getId()) ||
      item.txId || item.id || null;

    let raw =
      (typeof item.GetResult === 'function' && item.GetResult()) ||
      (typeof item.getResult === 'function' && item.getResult()) ||
      item.result || item.payload || null;

    if (raw == null && typeof item === 'string') raw = item;
    if (raw == null && typeof item === 'object') raw = item.data || item.body || null;

    if (Buffer.isBuffer(raw)) {
      asString = raw.toString('utf8');
    } else if (raw && typeof raw === 'object' && raw['0'] !== undefined && !raw.evidenceId) {
      try { asString = Buffer.from(Object.values(raw)).toString('utf8'); }
      catch { asString = JSON.stringify(raw); }
    } else if (typeof raw === 'string') {
      asString = raw;
    } else if (raw != null) {
      asString = JSON.stringify(raw);
    }

    let parsed = {};
    if (asString) {
      try { parsed = JSON.parse(asString); } catch (_) { /* ignore */ }
    }

    const obj = parsed && typeof parsed === 'object' ? parsed : {};
    const inner = (obj.result && typeof obj.result === 'object') ? obj.result : obj;
    return { txId, _raw: asString, ...inner };
  } catch (_) {
    return { _raw: asString };
  }
}

class SubmitMixedHybridWorkload extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.totalWorkers = totalWorkers;

    this.role = roundArguments.role || 'GatewayCollector';
    this.indexPath = roundArguments.indexPath || './data/evidence_index.json';
    this.seed = Number(roundArguments.seed) || Date.now();

    this.txTimeoutSec = Number(roundArguments.txTimeoutSec) || 180;
    this.maxTimeoutSec = Number(roundArguments.maxTimeoutSec) || Math.max(this.txTimeoutSec, 600);
    this.timeoutStepSec = Number(roundArguments.timeoutStepSec) || 60;

    this.contractId = roundArguments.contractId || 'forensicContract';
    this.funcHybrid = roundArguments.funcHybrid || 'submitEvidence';

    // IMPORTANT: strictSuccess default true => only write success receipts if out.success===true
    this.strictSuccess = (roundArguments.strictSuccess === undefined) ? true : !!roundArguments.strictSuccess;

    this.txSeq = 0;

    const receiptsDirArg = roundArguments.receiptsDir || './data/receipts';
    const absDir = path.resolve(receiptsDirArg);
    if (!receiptsDirState[absDir]) {
      fs.mkdirSync(absDir, { recursive: true });
      receiptsDirState[absDir] = true;
      console.log(`[INIT] ensured receipts dir: ${absDir}`);
    }

    this.receiptsPath = path.join(absDir, `receipt_hybrid_worker_${this.workerIndex}.ndjson`);
    if (fs.existsSync(this.receiptsPath)) {
      try { fs.unlinkSync(this.receiptsPath); } catch (_) {}
    }

    const distWeights =
      roundArguments.weights ||
      roundArguments.distribution ||
      { tiny: 20, small: 35, medium: 45, large: 10 };

    this.weights = {
      tiny: Number(distWeights.tiny || 0),
      small: Number(distWeights.small || 0),
      medium: Number(distWeights.medium || 0),
      large: Number(distWeights.large || 0),
    };

    this.evidenceLoader = new EvidenceLoader(this.indexPath, {
      strict: true,
      workspaceRoot: process.cwd(),
    });
    this.evidenceLoader.loadIndex();

    this.selector = new MixedEvidenceSelector(this.evidenceLoader, this.weights, this.seed + this.workerIndex);

    this.stats = { submitted: 0, failed: 0 };
    this.requestBytesArr = [];

    const st = (typeof this.evidenceLoader.getIndexStats === 'function') ? this.evidenceLoader.getIndexStats() : null;
    console.log(`[HYBRID Submit] Worker ${workerIndex}/${totalWorkers} ready`);
    console.log(`  Receipts      : ${this.receiptsPath}`);
    console.log(`  Weights       : ${JSON.stringify(this.weights)}`);
    if (st) console.log(`  Index         : ${JSON.stringify(st)}`);
    console.log(`  Timeout       : base=${this.txTimeoutSec}s max=${this.maxTimeoutSec}s step=${this.timeoutStepSec}s`);
    console.log(`  strictSuccess : ${this.strictSuccess}`);
  }

  _isDeadlineExceeded(err) {
    const msg = String(err && (err.message || err)).toLowerCase();
    return msg.includes('deadline_exceeded') || msg.includes('deadline exceeded');
  }

  _increaseTimeoutTemporarily() {
    const next = Math.min(this.maxTimeoutSec, this.txTimeoutSec + this.timeoutStepSec);
    if (next !== this.txTimeoutSec) {
      this.txTimeoutSec = next;
      console.warn(`[TIMEOUT] bumped to ${this.txTimeoutSec}s (worker ${this.workerIndex})`);
    }
  }

  /**
   * evidenceId regex-safe and <= 64:
   * EV-<cat>-<seed36>-<w>-<seq>
   */
  _makeEvidenceId(category) {
    const cat = String(category || 'x').substring(0, 1).toLowerCase(); // t/s/m/l
    const seed36 = (Math.abs(this.seed) >>> 0).toString(36);
    const seq = (this.txSeq++ >>> 0).toString(36);
    return `EV-${cat}-${seed36}-${this.workerIndex}-${seq}`;
  }

  _writeReceipt(obj) {
    fs.appendFileSync(this.receiptsPath, JSON.stringify(obj) + '\n');
  }

  async submitTransaction() {
    let argStr = '';
    let requestBytes = 0;

    // request fields for fail receipt
    let requestEvidenceId = null;
    let requestIntegrityHash = null;
    let requestIpfsRef = null;
    let category = null;

    try {
      const ev = await this.selector.getNextEvidenceWithFile();
      if (!ev) {
        this.stats.failed++;
        console.error(`❌ selector returned null (no evidence)`);
        return;
      }

      const { entry, fileBuffer, category: cat } = ev;
      category = cat;

      const legacyLike = PayloadBuilder.buildLegacyPayload({
        entry,
        fileBuffer,
        submittedBy: this.role,
      });

      const minimalEvidence = PayloadBuilder.stripHeavyFields(legacyLike);
      minimalEvidence.evidenceId = this._makeEvidenceId(category);

      const dummyCID = DummyCIDGenerator.generate({
        version: 'v0',
        seed: `${this.seed}-${Date.now()}-${this.workerIndex}`,
      });

      const wrapper = {
        evidence: minimalEvidence,
        storageMode: 'hybrid',
        storageVersion: '2.0',
        masterCID: dummyCID,
        ipfsReference: dummyCID,
        offChain: {
          provider: 'ipfs',
          cid: dummyCID,
          size: fileBuffer.length,
          mime: 'application/octet-stream',
          sha256: legacyLike.integrityHash,
        },
      };

      requestEvidenceId = minimalEvidence.evidenceId;
      requestIntegrityHash = legacyLike.integrityHash;
      requestIpfsRef = `ipfs://${String(dummyCID).replace('ipfs://', '')}`;

      argStr = JSON.stringify(wrapper);
      requestBytes = Buffer.byteLength(argStr, 'utf8');
      this.requestBytesArr.push(requestBytes);

      const request = {
        contractId: this.contractId,
        contractFunction: this.funcHybrid,
        contractArguments: [argStr],
        invokerIdentity: this.role,
        timeout: this.txTimeoutSec,
      };

      const res = await this.sutAdapter.sendRequests(request);
      const out = decodeCaliperResult(res);

      // STRICT SUCCESS CHECK:
      // chaincode submitEvidence returns JSON with { success:true, ... }
      // If decode fails or success!=true, treat as failure to keep receipts "committed-only"
      if (this.strictSuccess) {
        if (!out || out.success !== true) {
          const msg = (out && (out.message || out.error)) ? String(out.message || out.error) : 'non-success response';
          throw new Error(`Chaincode submitEvidence not success: ${msg} | raw=${out && out._raw ? out._raw : 'n/a'}`);
        }
      }

      const evidenceId =
        (out && typeof out.evidenceId === 'string' && out.evidenceId) ? out.evidenceId : requestEvidenceId;

      const txId = out.txId || undefined;

      // sizes returned by chaincode (if present)
      const onChainSizeBytes = (typeof out.onChainSizeBytes === 'number') ? out.onChainSizeBytes : undefined;
      const stateEvidenceBytes = (typeof out.stateEvidenceBytes === 'number') ? out.stateEvidenceBytes : undefined;
      const stateAuditBytes = (typeof out.stateAuditBytes === 'number') ? out.stateAuditBytes : undefined;
      const stateTotalWriteBytes = (typeof out.stateTotalWriteBytes === 'number') ? out.stateTotalWriteBytes : undefined;
      const stateWriteCount = (typeof out.stateWriteCount === 'number') ? out.stateWriteCount : undefined;

      const receipt = {
        mode: 'hybrid',
        size: category,
        time: Date.now(),
        evidenceId,
        integrityHash: out.integrityHash || requestIntegrityHash || undefined,
        ipfsReference: requestIpfsRef,
        txId,

        // request payload size (client->gateway)
        requestBytes,

        // chaincode return (optional but useful)
        onChainSizeBytes,
        stateEvidenceBytes,
        stateAuditBytes,
        stateTotalWriteBytes,
        stateWriteCount,

        failed: false,
      };

      this._writeReceipt(receipt);
      this.stats.submitted++;
    } catch (e) {
      this.stats.failed++;
      if (this._isDeadlineExceeded(e)) this._increaseTimeoutTemporarily();

      // write failed receipt (best-effort)
      if (requestEvidenceId) {
        try {
          const failReceipt = {
            mode: 'hybrid',
            size: category || undefined,
            time: Date.now(),
            evidenceId: requestEvidenceId,
            integrityHash: requestIntegrityHash || undefined,
            ipfsReference: requestIpfsRef || undefined,
            requestBytes,
            failed: true,
            error: String(e && (e.message || e)),
          };
          this._writeReceipt(failReceipt);
        } catch (_) {}
      }

      console.error(`❌ [HYBRID Submit] Worker ${this.workerIndex} failed: ${e && e.message ? e.message : e}`);
    }
  }

  summarizeBytes(arr) {
    if (!arr || arr.length === 0) return { count: 0 };
    const sorted = [...arr].sort((a, b) => a - b);
    const count = sorted.length;
    const sum = sorted.reduce((a, b) => a + b, 0);
    const avg = sum / count;
    return {
      count,
      min: sorted[0],
      p50_median: percentile(sorted, 0.50),
      p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
      max: sorted[count - 1],
      avg,
    };
  }

  async cleanupWorkloadModule() {
    console.log(`\n--- [HYBRID-MIXED Cleanup] Worker ${this.workerIndex} ---`);
    console.log(`  > Successful Transactions : ${this.stats.submitted}`);
    console.log(`  > Failed Transactions     : ${this.stats.failed}`);

    const sizeStats = this.summarizeBytes(this.requestBytesArr);
    if (sizeStats.count > 0) {
      console.log('  > Request Payload Size Stats (BYTES):');
      console.log(`    - Count : ${sizeStats.count}`);
      console.log(`    - Avg   : ${sizeStats.avg.toFixed(2)} (~${(sizeStats.avg / 1024).toFixed(2)} KB)`);
      console.log(`    - Median: ${sizeStats.p50_median}`);
      console.log(`    - p95   : ${sizeStats.p95}`);
      console.log(`    - p99   : ${sizeStats.p99}`);
      console.log(`    - Min   : ${sizeStats.min}`);
      console.log(`    - Max   : ${sizeStats.max} (~${(sizeStats.max / 1024).toFixed(2)} KB)`);
    }
    console.log('-----------------------------------------------------\n');
  }
}

function createWorkloadModule() {
  return new SubmitMixedHybridWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;