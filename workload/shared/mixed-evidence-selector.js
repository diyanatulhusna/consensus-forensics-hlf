'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_ORDER = ['tiny', 'small', 'medium', 'large'];

function xfnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function seedToInt(seed) {
  if (seed === undefined || seed === null) return 0xC0FFEE;
  if (typeof seed === 'number' && Number.isFinite(seed)) return (seed >>> 0);
  return xfnv1a(String(seed));
}

function mulberry32(a) {
  return function () {
    let t = a += 0x6D2B79F5;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function normalizeWeightSpec(weights, order) {
  const out = [];
  let sum = 0;
  for (const k of order) {
    const w = Number(weights?.[k] ?? 0);
    if (w > 0) {
      out.push({ key: k, w });
      sum += w;
    }
  }
  if (sum <= 0) {
    for (const k of order) out.push({ key: k, w: 1 });
    sum = out.length;
  }
  for (const it of out) it.p = it.w / sum;
  return out;
}

function weightedPick(rng, items) {
  const r = rng();
  let acc = 0;
  for (const it of items) {
    acc += it.p;
    if (r <= acc) return it.key;
  }
  return items[items.length - 1].key;
}

function shuffleInPlace(arr, rng) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

class MixedEvidenceSelector {
  /**
   * loader must provide getNextFromCategory(category) -> item
   * mixSpec:
   *  - {weights:{tiny,small,medium,large}}  => weighted random (infinite stream)
   *  - {distribution:{...}} or direct object => fixed plan (finite shuffled)
   */
  constructor(loader, mixSpec, seed, options = {}) {
    this.loader = loader;
    this.order = options.order || DEFAULT_ORDER;
    this.rng = mulberry32(seedToInt(seed));

    let weights = null;
    let distribution = null;

    if (mixSpec && (mixSpec.weights || mixSpec.distribution)) {
      weights = mixSpec.weights || null;
      distribution = mixSpec.distribution || null;
    } else {
      distribution = mixSpec;
    }

    if (weights) {
      this.mode = 'weights';
      this.weights = normalizeWeightSpec(weights, this.order);
      this.plan = null;
    } else {
      this.mode = 'distribution';
      this.weights = null;
      this.plan = this._buildPlan(distribution || {});
    }

    this.txIndex = 0;
    this.picked = Object.fromEntries(this.order.map(k => [k, 0]));
    this.baseDir = options.baseDir || null;
  }

  _buildPlan(distribution) {
    const plan = [];
    for (const k of this.order) {
      const c = Number(distribution?.[k] ?? 0);
      for (let i = 0; i < c; i++) plan.push(k);
    }
    if (plan.length === 0) for (const k of this.order) plan.push(k);
    return shuffleInPlace(plan, this.rng);
  }

  getNextEvidence() {
    const category = (this.mode === 'weights')
      ? weightedPick(this.rng, this.weights)
      : this.plan[this.txIndex % this.plan.length];

    this.txIndex++;
    this.picked[category] = (this.picked[category] || 0) + 1;

    const entry = this.loader.getNextFromCategory(category);
    return { category, entry };
  }

  _resolveFilePath(entry) {
    const p = entry?.filePath || entry?.filepath || entry?.path || entry?.file || entry?.sourcePath;
    if (!p || typeof p !== 'string') return null;
    if (path.isAbsolute(p)) return p;
    return this.baseDir ? path.join(this.baseDir, p) : p;
  }

  getNextEvidenceWithFile() {
    const { category, entry } = this.getNextEvidence();
    const fp = this._resolveFilePath(entry);

    let fileBuffer;
    if (fp && fs.existsSync(fp)) {
      fileBuffer = fs.readFileSync(fp);
    } else {
      const inlineB64 = entry?.payloadBase64;
      const inline = entry?.payload ?? entry?.data;
      if (typeof inlineB64 === 'string') fileBuffer = Buffer.from(inlineB64, 'base64');
      else if (typeof inline === 'string') fileBuffer = Buffer.from(inline, 'utf8');
      else fileBuffer = Buffer.from(JSON.stringify(entry || {}), 'utf8');
    }

    const fileHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    return {
      category,
      entry,
      fileBuffer,
      fileHash,
      fileSizeBytes: fileBuffer.length,
      filePath: fp
    };
  }

  getStats() {
    return {
      mode: this.mode,
      picked: this.picked,
      total: Object.values(this.picked).reduce((a, b) => a + b, 0)
    };
  }
}

module.exports = MixedEvidenceSelector;
