'use strict';

/**
 * retrieve-mixed-consensus.js (FINAL for chaincode split)
 * - default func: readOnly=true -> retrieveEvidence, readOnly=false -> retrieveEvidenceAndLog
 * - filter receipts by mode + evidenceId + (requireSuccess => failed!=true)
 * - isPublic parsing safe (handles "false" string)
 * - INFINITE wrap-around
 */

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const fs = require('fs');
const path = require('path');

function loadAllReceiptsFromDir(dirPath) {
  const absPath = path.resolve(dirPath);

  if (!fs.existsSync(absPath)) {
    throw new Error(`[RETRIEVE] receiptsPath tidak ditemukan: ${absPath}`);
  }
  if (!fs.lstatSync(absPath).isDirectory()) {
    throw new Error(`[RETRIEVE] receiptsPath bukan direktori: ${absPath}`);
  }

  const allReceipts = [];
  const files = fs.readdirSync(absPath);

  for (const file of files) {
    if (!file.endsWith('.ndjson')) continue;
    const filePath = path.join(absPath, file);

    let content = '';
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      console.warn(`[RETRIEVE] skip unreadable file ${file}: ${e.message}`);
      continue;
    }

    const lines = content.split('\n').filter(line => line.trim() !== '');
    for (const line of lines) {
      try { allReceipts.push(JSON.parse(line)); } catch (_) {}
    }
  }
  return allReceipts;
}

class RetrieveMixedWorkload extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.totalWorkers = Math.max(1, Number(totalWorkers) || 1);

    this.role = roundArguments.role || 'Judge';

    this.storageFilter = String(roundArguments.storageFilter || '').trim(); // legacy|hybrid
    if (!this.storageFilter) throw new Error('Argument "storageFilter" (legacy|hybrid) wajib ada.');
    if (this.storageFilter !== 'legacy' && this.storageFilter !== 'hybrid') {
      throw new Error('Argument "storageFilter" harus "legacy" atau "hybrid".');
    }

    // SAFE boolean parse: handles YAML boolean or string "false"
    this.isPublic = String(roundArguments.isPublic) === 'true';

    this.txTimeoutSec = Number(roundArguments.txTimeoutSec) || 45;

    // default query (readOnly=true)
    this.readOnly = (roundArguments.readOnly === undefined) ? true : !!roundArguments.readOnly;

    // require committed/success receipts only (default true)
    this.requireSuccess = (roundArguments.requireSuccess === undefined) ? true : !!roundArguments.requireSuccess;

    this.contractId = roundArguments.contractId || 'forensicContract';

    // default function based on readOnly mode
    this.funcRetrieve = roundArguments.funcRetrieve
      || (this.readOnly ? 'retrieveEvidence' : 'retrieveEvidenceAndLog');

    // allow requestPRE override (default false)
    this.requestPRE = String(roundArguments.requestPRE) === 'true';

    const receiptsDir = roundArguments.receiptsPath;
    if (!receiptsDir) throw new Error('Argument "receiptsPath" (direktori receipts) wajib ada.');
    this.receiptsPath = path.resolve(receiptsDir);

    this.strict = (roundArguments.strict === undefined) ? true : !!roundArguments.strict;

    const all = loadAllReceiptsFromDir(this.receiptsPath);
    if (all.length === 0) {
      const msg =
        `❌ TIDAK ADA RECEIPTS DITEMUKAN\n` +
        `   Path: ${this.receiptsPath}\n` +
        `   Pastikan SUBMIT sudah jalan & receiptsDir sama.\n`;
      if (this.strict) throw new Error(msg);
      console.warn(msg);
    }

    // filter: mode + evidenceId + (optional) success only
    // NOTE: treat failed===true as failed; missing failed field considered success
    const filtered = all.filter(r => {
      if (!r) return false;
      if (r.mode !== this.storageFilter) return false;
      if (!r.evidenceId) return false;
      if (this.requireSuccess && r.failed === true) return false;
      return true;
    });

    if (filtered.length === 0) {
      const msg =
        `❌ TIDAK ADA RECEIPTS SESUAI FILTER\n` +
        `   Mode: ${this.storageFilter}\n` +
        `   requireSuccess: ${this.requireSuccess}\n` +
        `   Path: ${this.receiptsPath}\n`;
      if (this.strict) throw new Error(msg);
      console.warn(msg);
    }

    // assigned slice per worker
    const start = Math.floor(filtered.length * this.workerIndex / this.totalWorkers);
    const end = Math.floor(filtered.length * (this.workerIndex + 1) / this.totalWorkers);
    const assigned = filtered.slice(start, end);

    this.pool = (assigned.length > 0) ? assigned : filtered;
    this.poolOffset = (assigned.length > 0) ? 0 : (this.workerIndex % Math.max(1, this.pool.length));
    this.txIndex = 0;

    console.log(
      `[RETRIEVE-MIXED] Worker ${workerIndex}/${this.totalWorkers} init | Mode='${this.storageFilter}' | ` +
      `Access=${this.isPublic ? 'PUBLIC' : 'PRIVATE'} | readOnly=${this.readOnly} | func=${this.funcRetrieve} | ` +
      `requireSuccess=${this.requireSuccess} | pool=${this.pool.length} (assigned=${assigned.length}, filtered=${filtered.length}) | ` +
      `receiptsDir=${this.receiptsPath}`
    );
  }

  async _doRequest(funcName, args, readOnlyOverride) {
    const request = {
      contractId: this.contractId,
      contractFunction: funcName,
      contractArguments: args,
      invokerIdentity: this.role,
      readOnly: (readOnlyOverride === undefined) ? this.readOnly : !!readOnlyOverride,
      timeout: this.txTimeoutSec
    };
    return this.sutAdapter.sendRequests(request);
  }

  async submitTransaction() {
    if (!this.pool || this.pool.length === 0) return;

    const idx = (this.poolOffset + (this.txIndex++)) % this.pool.length;
    const r = this.pool[idx];

    const evidenceId = r.evidenceId;
    const isPublicStr = String(this.isPublic);
    const requestPREStr = String(this.requestPRE);

    await this._doRequest(this.funcRetrieve, [evidenceId, isPublicStr, requestPREStr], undefined);
  }
}

function createWorkloadModule() {
  return new RetrieveMixedWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;