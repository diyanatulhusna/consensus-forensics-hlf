'use strict';

const crypto = require('crypto');

// Optional dependency (fallback to internal merkle if not available)
let MerkleTreeLib = null;
try {
  // eslint-disable-next-line global-require
  MerkleTreeLib = require('merkletreejs');
} catch (_) {
  MerkleTreeLib = null;
}

// =============================================================================
// Deterministic helpers
// =============================================================================

function stableStringify(x) {
  if (x === null || x === undefined) return 'null';
  if (typeof x !== 'object') return JSON.stringify(x);

  if (Array.isArray(x)) {
    return '[' + x.map(stableStringify).join(',') + ']';
  }

  const keys = Object.keys(x).sort();
  const parts = keys.map(k => JSON.stringify(k) + ':' + stableStringify(x[k]));
  return '{' + parts.join(',') + '}';
}

function sha256Buf(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function byteLenUtf8(s) {
  return Buffer.byteLength(String(s), 'utf8');
}

// =============================================================================
// Storage Optimizer (HADES-compatible)
// =============================================================================

/**
 * Storage Optimizer for Hybrid Storage System
 * Version: 2.0 - Deterministic, minimal on-chain baseline (HADES-compatible)
 *
 * Hybrid (v2.0) principle:
 * - On-chain: minimal baseline + ipfsReference (masterCID) + integrityHash
 * - Off-chain (master object at masterCID): metadata + (optional) encryption envelope + CoC + ZKP refs
 */
class StorageOptimizer {
  static STORAGE_VERSION = '2.0';
  static MAX_ONCHAIN_SIZE = 800; // bytes (must match your contract ceiling)
  static IPFS_PREFIX = 'ipfs://';

  // Off-chain master object schema marker
  static MASTER_SCHEMA = 'hades-master-v1';
  static DEFAULT_ENC_ALG = 'AES-256-GCM';

  /**
   * Strict denylist: MUST NOT appear in on-chain HYBRID baseline.
   * (Typical bloat culprits / accidental blobs.)
   */
  static DENY_FIELDS = new Set([
    'data', 'payload', 'content', 'raw', 'blob', 'file', 'bytes',
    'evidenceData', 'evidencePayload', 'evidenceContent',
    'pcap', 'video', 'image', 'dump',
    'chunks', 'chunkList',
    'chainOfCustody', 'actions', 'logs',
    'analysis', 'findings', 'report', 'reportData', 'fullReport',
    // v2 design: single master CID, avoid carrying multi-CID maps on-chain
    'ipfsReferences'
  ]);

  /**
   * Deterministic trimming order if somehow over budget.
   * (Hybrid baseline here is already minimal; this is a safety net.)
   */
  static TRIM_ORDER = [
    'collectorType',
    'submittedBy',
    'incidentId',
    'evidenceType',
    'metadata'
  ];

  // ---------------------------------------------------------------------------
  // CID utilities (align with your contract: ipfs://<CID>)
  // ---------------------------------------------------------------------------

  static normalizeCID(cid) {
    if (!cid) return '';
    const s = String(cid).trim();
    const raw = s.replace(/^ipfs:\/\//i, '');
    // Strip any path suffix
    return raw.split('/')[0].trim();
  }

  static ensureIpfsUri(cid) {
    const base = StorageOptimizer.normalizeCID(cid);
    return base ? `${StorageOptimizer.IPFS_PREFIX}${base}` : '';
  }

  static isNonEmptyString(x) {
    return typeof x === 'string' && x.trim().length > 0;
  }

  /**
   * Validate IPFS CID format (supports both v0 and v1).
   */
  static isValidCID(cidString) {
    if (!cidString || typeof cidString !== 'string') return false;
    const cid = StorageOptimizer.normalizeCID(cidString);

    // CIDv0: Base58btc, starts with Qm, length 46
    const v0Pattern = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
    // CIDv1 (common): bafy...
    const v1Pattern = /^bafy[a-z2-7]{20,}$/;

    return v0Pattern.test(cid) || v1Pattern.test(cid);
  }

  // ---------------------------------------------------------------------------
  // Compact / guard utilities
  // ---------------------------------------------------------------------------

  static _compactInPlace(obj) {
    if (!obj || typeof obj !== 'object') return;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      const emptyObj = v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0;
      const emptyArr = Array.isArray(v) && v.length === 0;
      if (v === undefined || v === null || v === '' || emptyObj || emptyArr) delete obj[k];
    }
  }

  static _assertNoDenyFields(obj) {
    const walk = (x) => {
      if (!x || typeof x !== 'object') return;
      for (const k of Object.keys(x)) {
        if (StorageOptimizer.DENY_FIELDS.has(k)) {
          throw new Error(`Hybrid baseline contains denylisted field: ${k}`);
        }
        walk(x[k]);
      }
    };
    walk(obj);
  }

  static estimateOnChainBytes(obj) {
    return byteLenUtf8(JSON.stringify(obj));
  }

  static _trimToFit(obj, maxBytes) {
    const out = JSON.parse(JSON.stringify(obj));
    let bytes = StorageOptimizer.estimateOnChainBytes(out);
    if (bytes <= maxBytes) return out;

    for (const field of StorageOptimizer.TRIM_ORDER) {
      if (out[field] !== undefined) {
        delete out[field];
        StorageOptimizer._compactInPlace(out);
        bytes = StorageOptimizer.estimateOnChainBytes(out);
        if (bytes <= maxBytes) return out;
      }
    }
    return out; // caller will hard-fail if still > maxBytes
  }

  // ---------------------------------------------------------------------------
  // Encryption envelope (Option-2, off-chain master object only)
  // ---------------------------------------------------------------------------

  /**
   * Extract encryption envelope from fullEvidence in a tolerant way.
   * Recommended:
   *   fullEvidence.encryption = { cipherCID, iv, tag, encAlg }
   * Also accepts:
   *   fullEvidence.encryptionEnvelope / fullEvidence.cryptoEnvelope
   * Legacy fallbacks (tolerated):
   *   fullEvidence.encryptionIV / fullEvidence.encryptionAuthTag / fullEvidence.cipherCID
   */
  static extractEncryptionEnvelope(fullEvidence) {
    const src =
      fullEvidence?.encryptionEnvelope ||
      fullEvidence?.cryptoEnvelope ||
      fullEvidence?.encryption ||
      {};

    const cipherCID =
      src.cipherCID ||
      src.cipherCid ||
      fullEvidence?.cipherCID ||
      fullEvidence?.cipherCid ||
      '';

    const iv =
      src.iv ||
      src.encryptionIV ||
      fullEvidence?.encryptionIV ||
      '';

    const tag =
      src.tag ||
      src.authTag ||
      src.encryptionAuthTag ||
      fullEvidence?.encryptionAuthTag ||
      '';

    const encAlg =
      src.encAlg ||
      src.encAlgorithm ||
      src.algorithm ||
      fullEvidence?.encAlg ||
      fullEvidence?.encAlgId ||
      StorageOptimizer.DEFAULT_ENC_ALG;

    const enabled = StorageOptimizer.isNonEmptyString(cipherCID);

    if (!enabled) {
      return {
        enabled: false,
        encAlg: StorageOptimizer.DEFAULT_ENC_ALG,
        cipherCID: '',
        iv: '',
        tag: ''
      };
    }

    if (!StorageOptimizer.isNonEmptyString(iv) || !StorageOptimizer.isNonEmptyString(tag)) {
      throw new Error(
        'Encryption envelope incomplete: cipherCID present but iv/tag missing. ' +
        'For Option-2, store {cipherCID, iv, tag, encAlg} in the master object.'
      );
    }

    const normCipher = StorageOptimizer.normalizeCID(cipherCID);
    if (normCipher && !StorageOptimizer.isValidCID(normCipher)) {
      throw new Error(`Invalid cipherCID format: ${cipherCID}`);
    }

    return {
      enabled: true,
      encAlg: String(encAlg),
      cipherCID: normCipher,
      iv: String(iv),
      tag: String(tag)
    };
  }

  /**
   * Prevent accidental storage of sensitive cryptographic material in master object.
   * Keep only policy flags + ZKP descriptors; drop keys.
   */
  static sanitizeCryptographicMetadataForMaster(meta) {
    if (!meta || typeof meta !== 'object') return {};

    const safe = JSON.parse(JSON.stringify(meta));

    // Remove common key materials / sensitive fields if present
    const SENSITIVE_KEYS = [
      'aesKey', 'aesKeyEncrypted', 'symmetricKey', 'secretKey',
      'privateKey', 'kmsKeyId', 'keyId',
      'encryptionIV', 'encryptionAuthTag', 'iv', 'tag'
    ];

    for (const k of SENSITIVE_KEYS) {
      if (k in safe) delete safe[k];
    }

    // If zkp proofs are huge, your design should store proof CIDs, not full blobs.
    // We keep structure but do not enforce here (off-chain), just avoid accidental blobs if any.
    StorageOptimizer._compactInPlace(safe);
    return safe;
  }

  // ---------------------------------------------------------------------------
  // On-chain preparation (minimal trust record)
  // ---------------------------------------------------------------------------

  /**
   * Prepare hybrid evidence baseline (minimal + deterministic).
   * This MUST stay <= MAX_ONCHAIN_SIZE in normal conditions.
   *
   * IMPORTANT alignment with your contract:
   * - ipfsReference is stored as `ipfs://<CID>`
   * - collectionTimestamp preferred (because your _sanitizeForPublic checks it)
   */
  static prepareHybridEvidence(fullEvidence, masterCID, txMetadata = {}) {
    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('prepareHybridEvidence: fullEvidence must be an object');
    }
    if (!fullEvidence.evidenceId) throw new Error('prepareHybridEvidence: evidenceId is required');
    if (!fullEvidence.integrityHash && !fullEvidence.fileHash) {
      throw new Error('prepareHybridEvidence: integrityHash (or fileHash) is required');
    }
    if (!masterCID) throw new Error('prepareHybridEvidence: masterCID is required');

    const masterBase = StorageOptimizer.normalizeCID(masterCID);
    if (!StorageOptimizer.isValidCID(masterBase)) {
      throw new Error(`prepareHybridEvidence: invalid masterCID: ${masterCID}`);
    }
    const masterUri = StorageOptimizer.ensureIpfsUri(masterBase);

    // Deterministic meta (contract already passes deterministic createdAt)
    const createdAt =
      fullEvidence.collectionTimestamp ||
      fullEvidence.createdAt ||
      txMetadata.createdAt ||
      '1970-01-01T00:00:00.000Z';

    const baseline = {
      evidenceId: String(fullEvidence.evidenceId),
      incidentId: fullEvidence.incidentId ? String(fullEvidence.incidentId) : 'EVIDENCE_ONLY',
      evidenceType: fullEvidence.evidenceType ? String(fullEvidence.evidenceType) : undefined,

      integrityHash: String(fullEvidence.integrityHash || fullEvidence.fileHash),

      // prefer collectionTimestamp (your contract uses it widely)
      collectionTimestamp: String(fullEvidence.collectionTimestamp || createdAt),

      // ownership is set by contract; keep short identifier only
      submittedBy: fullEvidence.submittedBy ? String(fullEvidence.submittedBy) : undefined,
      collectorType: fullEvidence.collectorType ? String(fullEvidence.collectorType) : undefined,

      storageMode: 'hybrid',
      storageVersion: StorageOptimizer.STORAGE_VERSION,
      ipfsReference: masterUri,

      // Keep compliance flags inside cryptographicMetadata (matches your queryCrossBorderEvidence logic)
      cryptographicMetadata: {
        gdprCompliant: !!(fullEvidence.cryptographicMetadata?.gdprCompliant || fullEvidence.gdprCompliant),
        crossBorderShareable: !!(fullEvidence.cryptographicMetadata?.crossBorderShareable || fullEvidence.crossBorderShareable)
      },

      // keep tx metadata grouped (small & deterministic)
      metadata: {
        version: StorageOptimizer.STORAGE_VERSION,
        schema: 'HADES-HYBRID-BASELINE',
        createdAt: String(createdAt),
        createdBy: txMetadata.createdBy ? String(txMetadata.createdBy) : undefined,
        mspId: txMetadata.mspId ? String(txMetadata.mspId) : undefined,
        txId: txMetadata.txId ? String(txMetadata.txId) : undefined
      }
    };

    StorageOptimizer._compactInPlace(baseline);
    StorageOptimizer._assertNoDenyFields(baseline);

    const trimmed = StorageOptimizer._trimToFit(baseline, StorageOptimizer.MAX_ONCHAIN_SIZE);
    StorageOptimizer._compactInPlace(trimmed);

    const bytes = StorageOptimizer.estimateOnChainBytes(trimmed);
    if (bytes > StorageOptimizer.MAX_ONCHAIN_SIZE) {
      throw new Error(`Hybrid baseline exceeds MAX_ONCHAIN_SIZE: ${bytes} > ${StorageOptimizer.MAX_ONCHAIN_SIZE}`);
    }

    return trimmed;
  }

  // ---------------------------------------------------------------------------
  // Off-chain master object (Option 2)
  // ---------------------------------------------------------------------------

  /**
   * Create master IPFS object (deterministic fields; no secret key).
   * - masterCID points to this JSON object
   * - offChain.encryption references ciphertext CID + iv/tag/alg (no key)
   */
  static createMasterIPFSObject(fullEvidence) {
    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('createMasterIPFSObject: fullEvidence must be an object');
    }
    if (!fullEvidence.evidenceId) throw new Error('createMasterIPFSObject: evidenceId required');

    const envelope = StorageOptimizer.extractEncryptionEnvelope(fullEvidence);

    // Minimal evidence fields (no bytes)
    const evidenceCore = {
      evidenceId: fullEvidence.evidenceId,
      incidentId: fullEvidence.incidentId || 'EVIDENCE_ONLY',
      submittedBy: fullEvidence.submittedBy,
      collectionTimestamp: fullEvidence.collectionTimestamp,
      evidenceType: fullEvidence.evidenceType,
      evidenceTitle: fullEvidence.evidenceTitle,
      evidenceDescription: fullEvidence.evidenceDescription
    };

    StorageOptimizer._compactInPlace(evidenceCore);

    const masterObject = {
      schema: StorageOptimizer.MASTER_SCHEMA,

      evidence: evidenceCore,

      offChain: {
        byteStore: 'ipfs',
        encryption: {
          enabled: envelope.enabled,
          encAlg: envelope.encAlg,
          cipherCID: envelope.cipherCID, // ciphertext blob CID (base CID)
          iv: envelope.iv,
          tag: envelope.tag
        }
      },

      // ZKP proofs (could be objects or refs; recommended store refs/CIDs)
      zkpProofs: {
        integrity: fullEvidence.cryptographicMetadata?.zkpMetadata?.integrityProof,
        compliance: fullEvidence.cryptographicMetadata?.zkpMetadata?.complianceProof,
        fazkp: fullEvidence.cryptographicMetadata?.zkpMetadata?.fazkp
      },

      // CoC off-chain is allowed (may be large)
      chainOfCustody: fullEvidence.chainOfCustody || [],

      metadata: {
        toolsUsed: fullEvidence.toolsUsed,
        deviceContext: fullEvidence.deviceContext,
        collectorInfo: fullEvidence.collectorInfo,
        tags: fullEvidence.tags,
        location: fullEvidence.location,
        fileSize: fullEvidence.fileSize
      },

      // IMPORTANT: sanitize cryptographicMetadata to avoid key material
      cryptographicMetadata: StorageOptimizer.sanitizeCryptographicMetadataForMaster(fullEvidence.cryptographicMetadata),

      storageInfo: {
        // deterministic size metric (stable stringify)
        originalSize: stableStringify(fullEvidence).length,
        timestamp:
          fullEvidence.createdAt ||
          fullEvidence.timestamp ||
          fullEvidence.collectionTimestamp ||
          '1970-01-01T00:00:00.000Z',
        version: StorageOptimizer.STORAGE_VERSION,
        singleMasterCID: true,
        option: 'ledger-minimal-master-offchain'
      }
    };

    // Compact non-critical empties
    StorageOptimizer._compactInPlace(masterObject.metadata);
    StorageOptimizer._compactInPlace(masterObject.zkpProofs);
    StorageOptimizer._compactInPlace(masterObject);

    return masterObject;
  }

  // ---------------------------------------------------------------------------
  // Metrics & size accounting
  // ---------------------------------------------------------------------------

  /**
   * Calculate on-chain size for evidence (world-state write payload size).
   */
  static calculateOnChainSize(evidenceData, masterCID = null, txMetadata = null) {
    if (masterCID) {
      const meta =
        txMetadata || {
          createdAt:
            evidenceData.collectionTimestamp ||
            evidenceData.createdAt ||
            '1970-01-01T00:00:00.000Z',
          createdBy: evidenceData.submittedBy || '',
          mspId: evidenceData.mspId || '',
          txId: ''
        };

      const onChainData = StorageOptimizer.prepareHybridEvidence(evidenceData, masterCID, meta);
      return byteLenUtf8(JSON.stringify(onChainData));
    }
    return byteLenUtf8(JSON.stringify(evidenceData));
  }

  /**
   * Reconstruct full evidence from hybrid storage.
   * Returns envelope (cipherCID/iv/tag) but does not decrypt (key external).
   */
  static async reconstructEvidence(onChainData, offChainData) {
    if (!offChainData) {
      return {
        ...onChainData,
        offChainWarning: 'Off-chain data unavailable'
      };
    }

    const envelope =
      offChainData?.offChain?.encryption ||
      offChainData?.encryption ||
      null;

    return {
      // on-chain essentials
      evidenceId: onChainData.evidenceId,
      incidentId: onChainData.incidentId || 'EVIDENCE_ONLY',
      integrityHash: onChainData.integrityHash,
      submittedBy: onChainData.submittedBy,
      collectionTimestamp: onChainData.collectionTimestamp || onChainData.timestamp,

      // off-chain details
      ...(offChainData.evidence || {}),
      zkpProofs: offChainData.zkpProofs || {},
      chainOfCustody: offChainData.chainOfCustody || [],
      metadata: offChainData.metadata || {},
      cryptographicMetadata: offChainData.cryptographicMetadata || {},

      encryptionEnvelope: envelope,

      storageMode: onChainData.storageMode,
      storageVersion: onChainData.storageVersion,
      ipfsReference: onChainData.ipfsReference
    };
  }

  static generateStorageMetrics(originalSize, onChainSize, masterCID = null, createdAt = null) {
    return {
      originalSize,
      onChainSize,
      storageReduction: originalSize > 0 ? Math.round((1 - onChainSize / originalSize) * 100) : 0,
      hasMasterCID: !!masterCID,
      timestamp: createdAt || '1970-01-01T00:00:00.000Z',
      version: StorageOptimizer.STORAGE_VERSION
    };
  }

  // ---------------------------------------------------------------------------
  // Strategy selection
  // ---------------------------------------------------------------------------

  /**
   * Determine storage strategy based on evidence size.
   * NOTE: Strategy is heuristic; your pipeline can override explicitly via storageMode/CID.
   */
  static determineStorageStrategy(evidenceData) {
    const fullSize = byteLenUtf8(JSON.stringify(evidenceData));

    // Small enough: legacy on-chain (if you still support it)
    if (fullSize <= StorageOptimizer.MAX_ONCHAIN_SIZE * 2) {
      return {
        mode: 'legacy',
        reason: 'Evidence small enough for on-chain storage',
        fullSize,
        onChainSize: fullSize
      };
    }

    // Large: hybrid (estimate with valid dummy CIDv0)
    const dummyCID = `Qm${'a'.repeat(44)}`; // valid-shape CIDv0
    const onChainSize = StorageOptimizer.calculateOnChainSize(evidenceData, dummyCID);

    return {
      mode: 'hybrid',
      reason: 'Evidence requires off-chain storage',
      fullSize,
      onChainSize,
      reduction: Math.round((1 - onChainSize / fullSize) * 100)
    };
  }
}

// =============================================================================
// MerkleTreeManager (CoC integrity)
// - Deterministic leaves + supports fallback when merkletreejs unavailable
// =============================================================================

class MerkleTreeManager {
  static _leafHash(entry) {
    // Fixed-key object => deterministic
    const canonical = {
      timestamp: entry?.timestamp || '',
      actor: entry?.actor || entry?.actorId || '',
      action: entry?.action || '',
      location: entry?.location || '',
      condition: entry?.condition || '',
      txId: entry?.txId || entry?.transactionId || ''
    };
    return sha256Buf(stableStringify(canonical));
  }

  static generateMerkleRoot(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
      return sha256Hex('empty');
    }

    const leaves = entries.map(e => MerkleTreeManager._leafHash(e));

    // If merkletreejs exists, use it (sortPairs + duplicateOdd for determinism)
    if (MerkleTreeLib?.MerkleTree) {
      const { MerkleTree } = MerkleTreeLib;
      const tree = new MerkleTree(leaves, sha256Buf, { sortPairs: true, duplicateOdd: true });
      return tree.getRoot().toString('hex');
    }

    // Fallback: manual merkle (pairwise hash, duplicate odd)
    let layer = leaves.map(b => b.toString('hex'));
    while (layer.length > 1) {
      const next = [];
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = (i + 1 < layer.length) ? layer[i + 1] : layer[i];
        next.push(sha256Hex(left + right));
      }
      layer = next;
    }
    return layer[0];
  }

  static generateProof(entries, index) {
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new Error('Invalid entries for proof generation');
    }
    if (index < 0 || index >= entries.length) {
      throw new Error('Invalid index for proof generation');
    }

    const leaves = entries.map(e => MerkleTreeManager._leafHash(e));
    const leaf = leaves[index].toString('hex');
    const root = MerkleTreeManager.generateMerkleRoot(entries);

    if (MerkleTreeLib?.MerkleTree) {
      const { MerkleTree } = MerkleTreeLib;
      const tree = new MerkleTree(leaves, sha256Buf, { sortPairs: true, duplicateOdd: true });

      const proof = tree.getProof(leaves[index]).map(p => ({
        position: p.position,
        data: p.data.toString('hex')
      }));

      return { proof, root, leaf };
    }

    // Fallback proof (manual): store sibling hashes + position
    let idx = index;
    let layer = leaves.map(b => b.toString('hex'));
    const proof = [];

    while (layer.length > 1) {
      const isRight = (idx % 2) === 1;
      const pairIdx = isRight ? idx - 1 : idx + 1;
      const sibling = layer[pairIdx] ?? layer[idx];

      proof.push({
        position: isRight ? 'left' : 'right',
        data: sibling
      });

      const next = [];
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = (i + 1 < layer.length) ? layer[i + 1] : layer[i];
        next.push(sha256Hex(left + right));
      }

      layer = next;
      idx = Math.floor(idx / 2);
    }

    return { proof, root, leaf };
  }

  static verifyProof(leafHex, proof, rootHex) {
    if (!leafHex || !rootHex) return false;

    // merkletreejs path
    if (MerkleTreeLib?.MerkleTree && Array.isArray(proof)) {
      try {
        const { MerkleTree } = MerkleTreeLib;
        const leafBuffer = Buffer.from(leafHex, 'hex');
        const rootBuffer = Buffer.from(rootHex, 'hex');
        const proofBuffers = proof.map(p => ({
          position: p.position,
          data: Buffer.from(p.data, 'hex')
        }));

        const tree = new MerkleTree([], sha256Buf, { sortPairs: true, duplicateOdd: true });
        return tree.verify(proofBuffers, leafBuffer, rootBuffer);
      } catch (_) {
        return false;
      }
    }

    // manual verify fallback
    if (!Array.isArray(proof)) return false;

    let h = String(leafHex).toLowerCase();
    for (const step of proof) {
      if (!step || !step.data || !step.position) return false;
      const sib = String(step.data).toLowerCase();

      h = (step.position === 'left')
        ? sha256Hex(sib + h)
        : sha256Hex(h + sib);
    }
    return h === String(rootHex).toLowerCase();
  }
}

module.exports = { StorageOptimizer, MerkleTreeManager };
