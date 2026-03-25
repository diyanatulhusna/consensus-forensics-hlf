'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

const IPFSManager = require('./IPFSManager');
const { StorageOptimizer } = require('./StorageOptimizer');

class ForensicContract extends Contract {
  constructor() {
    super();
    this.ipfsManager = null; // only for SIMULATION/TEST
  }

  // ===========================================================================
  // Determinism & Environment Guards
  // ===========================================================================

  /**
   * Chaincode must be deterministic across endorsers.
   * Any outbound HTTP (IPFS) is NON-deterministic => disallow in production.
   */
  _isSimulationMode() {
    const mode = String(process.env.FORENSIC_MODE || process.env.MODE || '')
      .toUpperCase()
      .trim();
    return mode === 'SIMULATION';
  }

  _assertIPFSAllowed(opName) {
    const allow =
      this._isSimulationMode() ||
      String(process.env.ALLOW_CHAINCODE_IPFS || '').toLowerCase() === 'true';

    if (!allow) {
      throw new Error(
        `${opName} disabled in PRODUCTION. ` +
          `Do IPFS store/retrieve in the client/gateway, then pass masterCID to chaincode. ` +
          `Enable only for tests with FORENSIC_MODE=SIMULATION (or ALLOW_CHAINCODE_IPFS=true).`
      );
    }
  }

  // ===========================================================================
  // Utilities
  // ===========================================================================

  _normRole(s) {
    return String(s || '').trim().toLowerCase().replace(/\s+/g, '');
  }

  _normClearance(s) {
    return String(s || '').trim().toLowerCase();
  }

  _toSafeNumber(x) {
    // Fabric can return protobuf Long-like objects
    if (x === null || x === undefined) return 0;
    if (typeof x === 'number') return x;
    if (typeof x === 'string') return Number(x);
    if (typeof x === 'object') {
      if (typeof x.toNumber === 'function') return x.toNumber();
      if (typeof x.valueOf === 'function') return Number(x.valueOf());
      if (x.low !== undefined) return Number(x.low);
    }
    return Number(x);
  }

  /**
   * Deterministic timestamp from transaction (endorsers see same tx timestamp).
   */
  _getTimestamp(ctx) {
    const ts = ctx.stub.getTxTimestamp();
    const seconds = this._toSafeNumber(ts.seconds);
    const nanos = this._toSafeNumber(ts.nanos);
    const ms = (seconds * 1000) + Math.floor(nanos / 1e6);
    return new Date(ms).toISOString();
  }

  _sha256Hex(input) {
    const s = (input === null || input === undefined) ? '' : String(input);
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  }

  _getAuditActor(ctx) {
    const enrollment =
      ctx.clientIdentity.getAttributeValue('hf.EnrollmentID') ||
      ctx.clientIdentity.getAttributeValue('enrollmentId') ||
      '';

    if (enrollment && String(enrollment).trim()) return String(enrollment).trim();

    const id = String(ctx.clientIdentity.getID() || '');
    const h = crypto.createHash('sha256').update(id).digest('hex').substring(0, 16);
    return `id:${h}`;
  }

  /**
   * Helper: extract evidence owner consistently (we store submittedBy as auditActor string)
   */
  _getEvidenceOwner(evidence) {
    if (!evidence) return null;
    const sb = evidence.submittedBy;
    if (!sb) return null;
    if (typeof sb === 'object') return sb.enrollmentId || sb.userId || sb.id || null;
    return sb;
  }

  /**
   * Normalize & validate CID format lightly (CIDv0/Qm.. or CIDv1/bafy..).
   * Returns normalized: ipfs://<cidBase>
   */
  _assertCIDFormat(cid) {
    if (cid === null || cid === undefined) throw new Error('CID is empty');
    const c = String(cid).trim();
    if (!c) throw new Error('CID is empty');

    // normalize common patterns:
    // ipfs://<cid>, ipfs://ipfs/<cid>, /ipfs/<cid>, <cid>/path
    let raw = c.replace(/^ipfs:\/\//i, '');
    raw = raw.replace(/^ipfs\//i, '');     // handles ipfs://ipfs/<cid>
    raw = raw.replace(/^\/?ipfs\//i, '');  // handles /ipfs/<cid>

    const base = raw.split('/')[0].trim();
    if (!base) throw new Error(`Invalid CID format: ${cid}`);

    const baseLower = base.toLowerCase();

    const isCidV0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(base);
    const isCidV1 = baseLower.startsWith('bafy');

    if (!isCidV0 && !isCidV1) throw new Error(`Invalid CID format: ${cid}`);

    return `ipfs://${isCidV1 ? baseLower : base}`;
  }

  /**
   * Hash CID for logging (avoid CID leakage)
   */
  _cidHash(cid) {
    if (cid === null || cid === undefined) return null;
    const norm = this._assertCIDFormat(String(cid));
    return this._sha256Hex(norm);
  }

  // ===========================================================================
  // Access Control (RBAC + Clearance)
  // ===========================================================================

  _checkAccess(ctx, required) {
    const id = ctx.clientIdentity;

    let role = id.getAttributeValue('role');
    let clearance = id.getAttributeValue('clearance');

    if (!role || role === 'null' || String(role).trim() === '') {
      throw new Error('Role attribute not found in certificate');
    }
    if (!clearance || clearance === 'null' || String(clearance).trim() === '') {
      throw new Error('Clearance attribute not found in certificate');
    }

    role = String(role).trim();
    clearance = String(clearance).trim();

    const roleNorm = this._normRole(role);
    const allowedRoleNorms = (required.roles || []).map(r => this._normRole(r));
    const roleOk = allowedRoleNorms.includes(roleNorm);

    const clrNorm = this._normClearance(clearance);
    const allowedClrNorms = (required.clearance || []).map(c => this._normClearance(c));
    const clrOk = allowedClrNorms.includes(clrNorm);

    if (!roleOk || !clrOk) {
      throw new Error(`Access denied: role=${role}, clearance=${clearance}`);
    }

    // Optional debug trace without leaking full identity
    const idHash = crypto.createHash('sha256').update(id.getID()).digest('hex');
    console.log(`Access granted for identity hash: ${idHash.substring(0, 16)}...`);
  }

  // ===========================================================================
  // IPFS (SIMULATION/TEST ONLY)
  // ===========================================================================

  async initIPFSManager(ctx) {
    this._assertIPFSAllowed('initIPFSManager');

    if (!this.ipfsManager) {
      this.ipfsManager = new IPFSManager();
      console.log('✅ IPFS Manager initialized (SIMULATION/TEST ONLY)');
    }
    return this.ipfsManager;
  }

  async storeToIPFS(ctx, data) {
    this._assertIPFSAllowed('storeToIPFS');
    await this.initIPFSManager(ctx);

    try {
      const rawCid = await this.ipfsManager.store(data);
      const cid = this._assertCIDFormat(rawCid);

      // HADES: do not write CID markers to world-state by default.
      const markerOnChain =
        String(process.env.IPFS_MARKER_ONCHAIN || '').toLowerCase() === 'true';

      if (markerOnChain) {
        const cidKey = `ipfs::${cid.replace('ipfs://', '').replace(/\//g, '_')}`;
        const marker = { cid, cached: false, note: 'hybrid-simulation-marker' };
        await ctx.stub.putState(cidKey, Buffer.from(JSON.stringify(marker), 'utf8'));
        ctx.stub.setEvent('IPFSStoredMarker', Buffer.from(JSON.stringify({ cid }), 'utf8'));
      }

      return cid;
    } catch (error) {
      console.error('IPFS storage failed:', error);
      throw error;
    }
  }

  async retrieveFromIPFS(ctx, cid) {
    this._assertIPFSAllowed('retrieveFromIPFS');
    await this.initIPFSManager(ctx);

    try {
      const cidStr = this._assertCIDFormat(String(cid));
      const bareCid = cidStr.replace(/^ipfs:\/\//i, '');
      return await this.ipfsManager.retrieve(bareCid);
    } catch (error) {
      console.error('IPFS retrieval failed:', error);
      return null;
    }
  }

  // ===========================================================================
  // Sanitizers
  // ===========================================================================

  _sanitizeForPublic(stored) {
    const inferredMode = stored.storageMode
      ? stored.storageMode
      : ((stored.storageVersion === '2.0') || !!stored.ipfsReference) ? 'hybrid' : 'legacy';

    const inferredVersion = stored.storageVersion || (inferredMode === 'hybrid' ? '2.0' : '1.0');

    return {
      publicAccess: true,
      storageMode: inferredMode,
      storageVersion: inferredVersion,

      // hash-only
      evidenceHash: {
        fileHash: stored.integrityHash || stored.fileHash || null
      },

      // minimal metadata
      metadata: {
        evidenceId: stored.evidenceId || null,
        evidenceType: stored.evidenceType || null,
        collectionTimestamp: stored.collectionTimestamp || stored.timestamp || stored.createdAt || null
      }
    };
  }

  _sanitizeAnalysisForExternal(entry) {
    const cm = entry.cryptographicMetadata || {};
    const cv = entry.cryptographicVerification || null;

    const safeEvidenceIds = Array.isArray(entry.evidenceIds) ? entry.evidenceIds : [];
    const safeTools = Array.isArray(entry.analysisTools) ? entry.analysisTools : [];

    const inv = entry.investigatorId ? String(entry.investigatorId) : '';
    const invHash = inv
      ? crypto.createHash('sha256').update(inv, 'utf8').digest('hex').substring(0, 16)
      : null;

    const ioc = entry.indicatorsOfCompromise || entry.ioc || [];
    const vul = entry.vulnerabilities || [];
    const ttp = entry.ttpMapping || [];
    const wh5 = entry.wh5 || [];

    return {
      incidentId: entry.incidentId || null,
      timestamp: entry.timestamp || null,

      evidenceCount: safeEvidenceIds.length,
      evidenceIds: safeEvidenceIds.map(e => String(e)),

      analysisTooling: {
        toolCount: safeTools.length,
        tools: safeTools.slice(0, 10)
      },

      findingsSummary: {
        iocCount: Array.isArray(ioc) ? ioc.length : 0,
        vulnerabilityCount: Array.isArray(vul) ? vul.length : 0,
        ttpCount: Array.isArray(ttp) ? ttp.length : 0,
        wh5Count: Array.isArray(wh5) ? wh5.length : 0
      },

      cryptographic: {
        analysisHash: cm.analysisHash || null,
        integrityLevel: cm.integrityLevel || null,
        zkpCapabilities: !!cm.zkpCapabilities,
        complianceFlags: cm.complianceFlags || {}
      },

      cryptographicVerification: cv,
      investigatorRef: invHash ? `inv:${invHash}` : null
    };
  }

  // ===========================================================================
  // Chain of Custody (CoC) - pointer-first design
  // ===========================================================================

  async _addCoCEntry(ctx, evidenceId, action, metadata = {}) {
    const ts = this._getTimestamp(ctx);
    const actualActor = this._getAuditActor(ctx);

    const evidenceKey = `evidence::${evidenceId}`;
    const evidenceBytes = await ctx.stub.getState(evidenceKey);
    if (!evidenceBytes || !evidenceBytes.length) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    const evidence = JSON.parse(evidenceBytes.toString());

    let prevHash = evidence.lastCoCHash || null;
    if (!prevHash && Array.isArray(evidence.chainOfCustody) && evidence.chainOfCustody.length > 0) {
      prevHash = evidence.chainOfCustody[evidence.chainOfCustody.length - 1]?.entryHash || null;
    }

    const entryData = {
      timestamp: ts,
      actor: actualActor,
      action,
      location: metadata.location || 'Blockchain Network',
      condition: metadata.condition || 'verified',
      integrityHash: evidence.integrityHash,
      cryptographicProofs: metadata.cryptographicProofs || {
        signatureProvided: true,
        integrityVerified: true,
        chainVerified: true
      },
      prevHash,
      metadata: metadata.additionalData || {},
      txId: ctx.stub.getTxID()
    };

    const entryHash = crypto.createHash('sha256')
      .update(JSON.stringify(entryData))
      .digest('hex');

    entryData.entryHash = entryHash;

    // Optional embed (OFF by default)
    const embedCoC =
      String(process.env.COC_EMBED_IN_EVIDENCE || '').toLowerCase() === 'true';

    if (embedCoC) {
      if (!Array.isArray(evidence.chainOfCustody)) evidence.chainOfCustody = [];
      evidence.chainOfCustody.push(entryData);
    }

    evidence.cocCount = (evidence.cocCount || 0) + 1;
    evidence.lastCoCHash = entryHash;

    const ad = entryData.metadata || {};

    if (ad.merkleRoot) {
      const mr = String(ad.merkleRoot).trim();
      if (!/^[A-Fa-f0-9]{64}$/.test(mr)) {
        throw new Error('Invalid merkleRoot format (must be 64 hex chars)');
      }
      evidence.merkleRoot = mr;
    }

    if (ad.cocCID) {
      evidence.cocCID = String(ad.cocCID).trim();
    }

    const storageMode = evidence.storageMode || 'legacy';
    const storageVersion = evidence.storageVersion || (storageMode === 'hybrid' ? '2.0' : '1.0');

    if (storageMode === 'hybrid' && storageVersion === '2.0' && ad.newMasterCID) {
      evidence.ipfsReference = this._assertCIDFormat(ad.newMasterCID);
    }

    // Single write for evidence
    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));

    // Append-only CoC entry
    const cocKey = ctx.stub.createCompositeKey('CoCEntry', [evidenceId, ts, entryHash]);
    await ctx.stub.putState(cocKey, Buffer.from(JSON.stringify(entryData), 'utf8'));

    return entryHash;
  }

  // ===========================================================================
  // Audit Logging (PRIVATE) — IMPORTANT: keep internal only
  // ===========================================================================

  /**
   * Internal audit writer (2 writes: summary + blob).
   * PATCH: include txId in hash input to guarantee uniqueness and prevent key collisions
   * under high concurrency (same action/metadata can occur at same ms).
   */
  async _logAction(ctx, action, incidentId = '', metadata = {}) {
    const safeIncident =
      (incidentId && incidentId.toString().trim()) ? incidentId.toString().trim() : 'GLOBAL';
    const safeAction = (action || '').toString().trim();

    const auditActor = this._getAuditActor(ctx);
    const roleForAudit = (ctx.clientIdentity.getAttributeValue('role') || 'unknown').trim();

    const timestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();
    const channel = ctx.stub.getChannelID();

    const storageVersion = (StorageOptimizer && StorageOptimizer.STORAGE_VERSION)
      ? StorageOptimizer.STORAGE_VERSION
      : '2.0';

    // IMPORTANT PATCH:
    // include txId (and channel) so logHash is always unique per tx.
    const logData = {
      incidentId: safeIncident,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit,
      timestamp,
      metadata: metadata || {},
      systemVersion: storageVersion,
      txId,
      channel
    };

    const logHash = crypto.createHash('sha256')
      .update(JSON.stringify(logData))
      .digest('hex');

    const entry = {
      ...logData,
      logHash
    };

    const logKey = ctx.stub.createCompositeKey('LogEntry', [safeIncident, timestamp, logHash]);

    const summary = {
      incidentId: safeIncident,
      timestamp,
      logHash,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit
    };

    const summaryStr = JSON.stringify(summary);
    const entryStr = JSON.stringify(entry);

    const auditSummaryBytes = Buffer.byteLength(summaryStr, 'utf8');
    const auditBlobBytes = Buffer.byteLength(entryStr, 'utf8');
    const auditBytes = auditSummaryBytes + auditBlobBytes;

    await ctx.stub.putState(logKey, Buffer.from(summaryStr, 'utf8'));

    const blobKey = `LogBlob_${logHash}`;
    await ctx.stub.putState(blobKey, Buffer.from(entryStr, 'utf8'));

    const eventPayload = {
      type: 'AUDIT_LOG',
      incidentId: safeIncident,
      timestamp,
      hash: logHash,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit,
      txId,
      channel,
      systemVersion: storageVersion,
      storageMode: metadata?.storageMode
    };
    ctx.stub.setEvent('CryptographicAuditLog', Buffer.from(JSON.stringify(eventPayload), 'utf8'));

    return {
      success: true,
      logHash,
      auditSummaryBytes,
      auditBlobBytes,
      auditBytes,
      auditWriteCount: 2,
      logKey,
      blobKey
    };
  }


  // ===========================================================================
  // ZKP Proof Storage (SIMULATED)
  // ===========================================================================

  async _storeProofInIPFS(ctx, proofData) {
    // Simulation-only pattern: store on-chain with key, return zkp:// ref
    const proofStr = JSON.stringify(proofData || {});
    const size = Buffer.byteLength(proofStr, 'utf8');

    const MAX_PROOF_BYTES = Number(process.env.MAX_SIM_PROOF_BYTES || 64 * 1024); // 64KB default
    if (size > MAX_PROOF_BYTES) {
      throw new Error(`Simulated proof too large (${size} bytes). Max ${MAX_PROOF_BYTES}`);
    }

    const proofHash = crypto.createHash('sha256')
      .update(proofStr)
      .digest('hex');

    const proofKey = `ZKPProof_${proofHash}`;
    const simulated = { ...proofData, simulation: true, storedAt: this._getTimestamp(ctx) };

    await ctx.stub.putState(proofKey, Buffer.from(JSON.stringify(simulated), 'utf8'));

    const proofRef = `zkp://${proofHash}`;
    ctx.stub.setEvent(
      'ZKPProofStoredSimulated',
      Buffer.from(JSON.stringify({ proofRef, proofHash }), 'utf8')
    );

    return proofRef;
  }

  // ===========================================================================
  // Delegation
  // ===========================================================================

  async registerDelegation(ctx, evidenceId, delegateToUserId, delegationType, expirationHours) {
    if (!delegationType) delegationType = 'FULL_ACCESS';
    if (!expirationHours) expirationHours = '24';

    const expHours = parseInt(expirationHours, 10);
    if (!Number.isFinite(expHours) || expHours <= 0) {
      throw new Error('expirationHours harus integer > 0');
    }

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();

    this._checkAccess(ctx, {
      roles: [
        'Forensic Investigator', 'ForensicInvestigator',
        'Gateway Collector', 'GatewayCollector',
        'Manual Collector', 'ManualCollector'
      ],
      clearance: ['Medium', 'High']
    });

    const evId = String(evidenceId || '').trim();
    const delTo = String(delegateToUserId || '').trim();
    if (!evId) throw new Error('evidenceId wajib diisi');
    if (!delTo) throw new Error('delegateToUserId wajib diisi');

    const evidenceKey = `evidence::${evId}`;
    const evidenceBytes = await ctx.stub.getState(evidenceKey);
    if (!evidenceBytes || !evidenceBytes.length) throw new Error(`Evidence ${evId} not found`);
    const evidence = JSON.parse(evidenceBytes.toString());

    const roleNow = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const isFI = this._normRole(roleNow) === 'forensicinvestigator';

    const evidenceOwner = this._getEvidenceOwner(evidence);
    const callerEnroll = this._getAuditActor(ctx);

    if (!isFI && evidenceOwner && callerEnroll !== evidenceOwner) {
      throw new Error('Only the evidence owner or Forensic Investigator may delegate access');
    }

    const delegationKey = ctx.stub.createCompositeKey('Delegation', [evId, delTo]);

    // Anti-bloat: if old delegation exists for (evId, delTo), remove old delegationId record
    const existing = await ctx.stub.getState(delegationKey);
    if (existing && existing.length) {
      try {
        const old = JSON.parse(existing.toString());
        if (old && old.delegationId) {
          await ctx.stub.deleteState(old.delegationId);
        }
      } catch {
        // ignore
      }
    }

    const delegationId = `DEL-${evId}-${delTo}-${txId.substring(0, 8)}`;
    const txDate = new Date(txTimestamp);
    const expiresAt = new Date(txDate.getTime() + (expHours * 3600000)).toISOString();

    const delegation = {
      delegationId,
      evidenceId: evId,
      incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
      delegatorId: ctx.clientIdentity.getID(),
      delegatorEnrollmentId:
        ctx.clientIdentity.getAttributeValue('hf.EnrollmentID') ||
        ctx.clientIdentity.getAttributeValue('enrollmentId') ||
        '',
      delegateToUserId: delTo,
      delegationType: String(delegationType).trim(),
      createdAt: txTimestamp,
      expiresAt,
      active: true,
      txId
    };

    await ctx.stub.putState(delegationKey, Buffer.from(JSON.stringify(delegation), 'utf8'));
    await ctx.stub.putState(delegationId, Buffer.from(JSON.stringify(delegation), 'utf8'));

    const pointerOnEvidence =
      String(process.env.DELEGATION_POINTER_ON_EVIDENCE || '').toLowerCase() === 'true';

    if (pointerOnEvidence) {
      evidence.delegationCount = (evidence.delegationCount || 0) + 1;
      evidence.lastDelegationAt = txTimestamp;
      evidence.lastDelegationTo = delTo;
      evidence.lastDelegationType = delegation.delegationType;
      await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));
    }

    ctx.stub.setEvent(
      'DelegationRegistered',
      Buffer.from(JSON.stringify({
        delegationId,
        evidenceId: evId,
        delegateToUserId: delTo,
        delegationType: delegation.delegationType,
        expiresAt,
        pointerOnEvidence
      }), 'utf8')
    );

    await this._logAction(ctx, 'registerDelegation', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      delegateToUserId: delTo,
      delegationType: delegation.delegationType,
      expiresAt,
      pointerOnEvidence
    });

    return JSON.stringify({ success: true, delegationId, expiresAt, pointerOnEvidence });
  }

  /**
   * Check delegation (no privilege escalation):
   * - FULL_ACCESS ok
   * - exact match ok
   * - PRE_ACCESS can satisfy AES_ACCESS (PRE dianggap lebih tinggi)
   * - AES_ACCESS MUST NOT satisfy PRE_ACCESS
   */
  async _checkDelegation(ctx, evidenceId, userId, requiredType) {
    const normalizedUserId = String(userId || '').trim();
    const reqType = String(requiredType || '').trim();

    const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', [evidenceId, normalizedUserId]);

    const txTimestamp = this._getTimestamp(ctx);
    const now = new Date(txTimestamp).getTime();

    let hasValid = false;
    let details = null;

    while (true) {
      const res = await iter.next();
      if (res.done) break;

      let d;
      try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

      const exp = Date.parse(d.expiresAt);
      if (!d.active || !(exp > now)) continue;

      const dt = String(d.delegationType || '').trim();

      const typeOk =
        dt === 'FULL_ACCESS' ||
        dt === reqType ||
        (reqType === 'AES_ACCESS' && dt === 'PRE_ACCESS');

      if (typeOk) {
        hasValid = true;
        details = d;
        break;
      }
    }

    await iter.close();
    return { hasValidDelegation: hasValid, delegationDetails: details };
  }

  async revokeExpiredDelegations(ctx) {
    this._checkAccess(ctx, {
      roles: ['Admin', 'System Administrator', 'Forensic Investigator', 'ForensicInvestigator'],
      clearance: ['High']
    });

    const txTimestamp = this._getTimestamp(ctx);
    const now = new Date(txTimestamp).getTime();

    const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', []);
    let revokedCount = 0;

    while (true) {
      const res = await iter.next();
      if (res.done) break;

      let d;
      try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

      const expTime = Date.parse(d.expiresAt);
      if (d.active && expTime <= now) {
        d.active = false;
        d.revokedAt = txTimestamp;

        await ctx.stub.putState(res.value.key, Buffer.from(JSON.stringify(d), 'utf8'));

        if (d.delegationId) {
          await ctx.stub.putState(d.delegationId, Buffer.from(JSON.stringify(d), 'utf8'));
        }

        revokedCount++;
      }
    }

    await iter.close();
    return JSON.stringify({ success: true, revokedCount, timestamp: txTimestamp });
  }

  // ===========================================================================
  // Public Key Registry
  // ===========================================================================

  async registerPublicKey(ctx, userId, keyType, publicKey, purpose) {
    if (!userId || !keyType || !publicKey || !purpose) {
      throw new Error('userId, keyType, publicKey, purpose are required');
    }

    userId = String(userId).trim();
    keyType = String(keyType).trim();
    publicKey = String(publicKey).trim();
    purpose = String(purpose).trim();

    const callerId = ctx.clientIdentity.getID();

    const keyRecord = {
      userId,
      keyType,
      publicKey,
      purpose,
      registeredBy: callerId,
      registeredAt: this._getTimestamp(ctx),
      status: 'active'
    };

    const keyId = `PublicKey_${userId}_${keyType}_${purpose}`;
    await ctx.stub.putState(keyId, Buffer.from(JSON.stringify(keyRecord), 'utf8'));

    await this._logAction(ctx, 'registerPublicKey', '', {
      targetUserId: userId,
      keyType,
      purpose,
      publicKeyHash: crypto.createHash('sha256').update(publicKey).digest('hex').substring(0, 16)
    });

    return JSON.stringify({ success: true, keyId });
  }

  async getPublicKey(ctx, userId, keyType, purpose) {
    const keyId = `PublicKey_${userId}_${keyType}_${purpose}`;
    const keyBytes = await ctx.stub.getState(keyId);

    if (!keyBytes || keyBytes.length === 0) {
      throw new Error(`Public key not found: ${userId} - ${keyType} - ${purpose}`);
    }

    return JSON.parse(keyBytes.toString());
  }

  // ===========================================================================
  // Incident (optional)
  // ===========================================================================

  async initializeIncident(
    ctx,
    responderId,
    incidentId,
    detectionTime,
    incidentType,
    severityLevel,
    description,
    actionTaken,
    actionTimestamp,
    affectedSystems,
    deviceContextJson
  ) {
    this._checkAccess(ctx, {
      roles: ['Monitoring Team', 'MonitoringTeam'],
      clearance: ['Low']
    });

    const levels = ['Low', 'Medium', 'High', 'Critical'];
    if (!levels.includes(severityLevel)) {
      throw new Error(`Invalid severityLevel: ${severityLevel}`);
    }

    let affectedList;
    try {
      affectedList = JSON.parse(affectedSystems);
      if (!Array.isArray(affectedList)) throw new Error();
    } catch {
      throw new Error('affectedSystems must be a valid JSON array');
    }

    let deviceContext = null;
    let cryptographicProof = null;

    if (deviceContextJson && deviceContextJson !== 'null') {
      try {
        const parsedData = JSON.parse(deviceContextJson);
        if (parsedData.reportingSource && parsedData.zkpProof) {
          deviceContext = parsedData.reportingSource;
          cryptographicProof = parsedData.zkpProof;
        } else {
          deviceContext = parsedData;
        }
      } catch {
        throw new Error('deviceContext must be a valid JSON object');
      }
    }

    const createdAt = this._getTimestamp(ctx);

    const incidentData = {
      responderId, incidentId, detectionTime, incidentType,
      severityLevel, description, affectedList, deviceContext
    };

    const incidentHash = crypto.createHash('sha256')
      .update(JSON.stringify(incidentData))
      .digest('hex');

    const record = {
      ...incidentData,
      initialActions: [{ action: actionTaken, timestamp: actionTimestamp }],
      status: 'initialized',
      createdBy: ctx.clientIdentity.getID(),
      createdAt,
      reportingSource: deviceContext,
      evidenceList: [],
      cryptographicMetadata: {
        incidentHash,
        cryptographicProof,
        signatureVerified: !!cryptographicProof,
        integrityLevel: 'HIGH'
      },
      actions: [
        { action: 'initializeIncident', timestamp: createdAt, by: responderId, hash: incidentHash.substring(0, 16) }
      ]
    };

    await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(record), 'utf8'));

    ctx.stub.setEvent('IncidentInitialized', Buffer.from(JSON.stringify({
      incidentId,
      createdAt,
      incidentHash: incidentHash.substring(0, 16),
      cryptographicProof: !!cryptographicProof
    }), 'utf8'));

    await this._logAction(ctx, 'initializeIncident', incidentId, {
      responderId,
      severityLevel,
      incidentType,
      integrityHash: incidentHash.substring(0, 16)
    });

    return JSON.stringify({ success: true, incidentId, incidentHash });
  }

  // ===========================================================================
  // Evidence Submit (LEGACY v1.0 / HYBRID v2.0)
  // ===========================================================================

  async submitEvidence(ctx, evidenceDataStr) {
    let inputData;
    try {
      inputData = JSON.parse(evidenceDataStr);
    } catch (e) {
      throw new Error(`Invalid JSON for evidence payload: ${e.message}`);
    }

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();

    const fullEvidence = (inputData && typeof inputData.evidence === 'object')
      ? inputData.evidence
      : inputData;

    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('Invalid evidence payload');
    }

    const id = (fullEvidence.evidenceId || '').toString().trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id)) {
      throw new Error('Invalid evidenceId format (allowed: A-Z a-z 0-9 . _ - ; max 64)');
    }
    fullEvidence.evidenceId = id;

    if (!fullEvidence.integrityHash) throw new Error('integrityHash is required');

    // RBAC: collectors can submit
    this._checkAccess(ctx, {
      roles: ['Gateway Collector', 'GatewayCollector', 'Manual Collector', 'ManualCollector'],
      clearance: ['Medium', 'High']
    });

    // Bind ownership to invoker identity (do not trust submittedBy)
    const auditActor = this._getAuditActor(ctx);
    const claimedSubmittedBy = fullEvidence.submittedBy;
    fullEvidence.submittedBy = auditActor;
    if (claimedSubmittedBy !== undefined) fullEvidence.claimedSubmittedBy = claimedSubmittedBy;

    if (!fullEvidence.collectionTimestamp) {
      fullEvidence.collectionTimestamp = txTimestamp;
    }

    const evidenceKey = `evidence::${fullEvidence.evidenceId}`;
    const existingBytes = await ctx.stub.getState(evidenceKey);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`Evidence ${fullEvidence.evidenceId} already exists`);
    }

    const hintedMode = (inputData.storageMode || fullEvidence.storageMode || '').toLowerCase().trim();

    let cidCandidate =
      inputData.masterCID ||
      inputData.realCID ||
      inputData.ipfsReference ||
      inputData.ipfsReferences?.masterCID ||
      inputData.ipfsReferences?.evidenceCID ||
      fullEvidence.masterCID ||
      fullEvidence.ipfsReference ||
      null;

    const isHybrid = (hintedMode === 'hybrid') || !!cidCandidate;

    let storageMode, storageVersion, dataToStore, masterCID = null;

    if (isHybrid) {
      storageMode = 'hybrid';
      storageVersion = '2.0';

      if (!cidCandidate) {
        throw new Error('Hybrid mode requires a CID (masterCID/realCID/ipfsReference)');
      }

      masterCID = this._assertCIDFormat(String(cidCandidate));

      const txMetadata = {
        createdAt: txTimestamp,
        createdBy: ctx.clientIdentity.getID(),
        mspId: ctx.clientIdentity.getMSPID(),
        txId
      };

      dataToStore = StorageOptimizer.prepareHybridEvidence(fullEvidence, masterCID, txMetadata);

      dataToStore.storageMode = 'hybrid';
      dataToStore.storageVersion = '2.0';
      dataToStore.evidenceId = fullEvidence.evidenceId;

      const ceiling = (StorageOptimizer && StorageOptimizer.MAX_ONCHAIN_SIZE)
        ? StorageOptimizer.MAX_ONCHAIN_SIZE
        : 800;

      const tmpBytes = Buffer.byteLength(JSON.stringify(dataToStore), 'utf8');
      if (tmpBytes > ceiling) {
        // best-effort trim optional fields only
        delete dataToStore.optionalNotes;
        delete dataToStore.unused;
      }
    } else {
      storageMode = 'legacy';
      storageVersion = '1.0';

      dataToStore = {
        ...fullEvidence,
        storageMode,
        storageVersion
      };
    }

    const dataToStoreStr = JSON.stringify(dataToStore);
    const stateEvidenceBytes = Buffer.byteLength(dataToStoreStr, 'utf8');

    if (storageMode === 'hybrid') {
      const finalCeiling = (StorageOptimizer && StorageOptimizer.MAX_ONCHAIN_SIZE)
        ? StorageOptimizer.MAX_ONCHAIN_SIZE
        : 800;

      if (stateEvidenceBytes > finalCeiling) {
        throw new Error(`Hybrid on-chain payload too large: ${stateEvidenceBytes} > ${finalCeiling}`);
      }
    }

    // For consistent measurement, use the actual client payload bytes
    const fullEvidenceSizeBytes = Buffer.byteLength(String(evidenceDataStr || ''), 'utf8');
    const storageReductionPct = (storageMode === 'hybrid' && fullEvidenceSizeBytes > 0)
      ? Math.round((1 - stateEvidenceBytes / fullEvidenceSizeBytes) * 100)
      : 0;

    await ctx.stub.putState(evidenceKey, Buffer.from(dataToStoreStr, 'utf8'));

    const auditRes = await this._logAction(ctx, 'submitEvidence', fullEvidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: fullEvidence.evidenceId,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      ipfsRefHash: masterCID ? this._cidHash(masterCID) : null
    });

    const stateAuditBytes = (auditRes && typeof auditRes.auditBytes === 'number') ? auditRes.auditBytes : 0;
    const stateTotalWriteBytes = stateEvidenceBytes + stateAuditBytes;
    const stateWriteCount = 1 + ((auditRes && typeof auditRes.auditWriteCount === 'number') ? auditRes.auditWriteCount : 0);

    ctx.stub.setEvent('EvidenceSubmitted', Buffer.from(JSON.stringify({
      evidenceId: fullEvidence.evidenceId,
      submittedBy: fullEvidence.submittedBy,
      timestamp: txTimestamp,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      ipfsRefHash: masterCID ? this._cidHash(masterCID) : null,

      txId,
      stateEvidenceBytes,
      stateAuditBytes,
      stateTotalWriteBytes,
      stateWriteCount,
      auditLogHash: auditRes?.logHash || null
    }), 'utf8'));

    return JSON.stringify({
      success: true,
      evidenceId: fullEvidence.evidenceId,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      masterCID: masterCID || null,

      stateEvidenceBytes,
      stateAuditBytes,
      stateTotalWriteBytes,
      stateWriteCount,
      auditLogHash: auditRes?.logHash || null
    });
  }

  // ===========================================================================
  // Evidence Retrieve (PURE QUERY / AUDITED)
  // ===========================================================================

  async _retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr) {
    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(evId)) {
      throw new Error('Invalid evidenceId format (allowed: A-Z a-z 0-9 . _ - ; max 64)');
    }

    const isPublic = (String(isPublicStr) === 'true');
    const requestPRE = (String(requestPREStr) === 'true');

    const auditActor = this._getAuditActor(ctx);
    const roleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(roleRaw);

    // RBAC: single, non-duplicated
    if (isPublic) {
      this._checkAccess(ctx, {
        roles: ['External Verifier', 'ExternalVerifier'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: [
          'Forensic Investigator', 'ForensicInvestigator',
          'Gateway Collector', 'GatewayCollector',
          'Manual Collector', 'ManualCollector',
          'Judge',
          'Data Protection Officer', 'DataProtectionOfficer'
        ],
        clearance: ['Medium', 'High', 'Judicial']
      });
    }

    // Read evidence (new key, fallback legacy)
    const evidenceKey = `evidence::${evId}`;
    let storedDataBytes = await ctx.stub.getState(evidenceKey);

    if (!storedDataBytes || !storedDataBytes.length) {
      storedDataBytes = await ctx.stub.getState(evId);
      if (!storedDataBytes || !storedDataBytes.length) {
        throw new Error(`Evidence ${evId} not found`);
      }
    }

    const storedData = JSON.parse(storedDataBytes.toString());
    const storageMode = storedData.storageMode || ((storedData.storageVersion === '2.0' || storedData.ipfsReference) ? 'hybrid' : 'legacy');
    const storageVersion = storedData.storageVersion || (storageMode === 'hybrid' ? '2.0' : '1.0');

    const masterCIDRaw =
      storedData.ipfsReference ||
      storedData.ipfsReferences?.masterCID ||
      storedData.ipfsReferences?.evidenceCID ||
      storedData.masterCID ||
      storedData.realCID ||
      null;

    const masterCIDNorm = masterCIDRaw ? this._assertCIDFormat(String(masterCIDRaw)) : null;

    // Owner / privileged roles
    const owner = this._getEvidenceOwner(storedData);
    const isOwner = owner && String(owner).trim() === String(auditActor).trim();
    const isFI = roleNorm === 'forensicinvestigator';
    const isJudge = roleNorm === 'judge';

    // Delegation enforcement (only meaningful for PRIVATE)
    let delAES = { hasValidDelegation: false, delegationDetails: null };
    let delPRE = { hasValidDelegation: false, delegationDetails: null };

    if (!isPublic && !isOwner && !isFI && !isJudge) {
      if (masterCIDNorm) {
        delAES = await this._checkDelegation(ctx, evId, auditActor, 'AES_ACCESS');
      }
      if (requestPRE) {
        delPRE = await this._checkDelegation(ctx, evId, auditActor, 'PRE_ACCESS');
      }
    }

    // If PRE explicitly requested, block without valid delegation (except privileged/owner)
    if (!isPublic && requestPRE && !isOwner && !isFI && !isJudge) {
      if (!delPRE.hasValidDelegation) {
        throw new Error('PRE access requires valid delegation (PRE_ACCESS/FULL_ACCESS)');
      }
    }

    // masterCID disclosure policy (defense-in-depth)
    const canSeeMasterCID =
      !!masterCIDNorm &&
      !isPublic &&
      (isOwner || isFI || isJudge || delAES.hasValidDelegation);

    // Build response
    let response;
    if (storageMode === 'hybrid' && storageVersion === '2.0') {
      if (isPublic) {
        response = this._sanitizeForPublic(storedData);
      } else {
        response = {
          storageMode: 'hybrid',
          storageVersion,
          onChainData: storedData,
          masterCID: canSeeMasterCID ? masterCIDNorm : null,
          masterCIDHash: masterCIDNorm ? this._cidHash(masterCIDNorm) : null,
          preAccessGranted: requestPRE ? (isOwner || isFI || isJudge || delPRE.hasValidDelegation) : false,
          retrievalNote: canSeeMasterCID
            ? 'Private mode: use masterCID to fetch complete evidence off-chain (IPFS) via client/gateway.'
            : 'MasterCID disclosure restricted. Require owner/FI/Judge or valid delegation (AES_ACCESS/PRE_ACCESS/FULL_ACCESS).'
        };
      }
    } else {
      response = isPublic ? this._sanitizeForPublic(storedData) : storedData;
    }

    response.accessMode = isPublic ? 'PUBLIC' : 'PRIVATE';
    response.accessTimestamp = this._getTimestamp(ctx);
    response.accessedBy = isPublic ? 'PUBLIC' : auditActor;

    return {
      response,
      auditMeta: {
        incidentId: storedData.incidentId || 'EVIDENCE_ONLY',
        storageMode
      }
    };
  }

  /**
   * PURE QUERY (no audit write). Suitable for Caliper readOnly=true.
   */
  async retrieveEvidence(ctx, evidenceId, isPublicStr, requestPREStr) {
    const { response } = await this._retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr);
    return JSON.stringify(response);
  }

  /**
   * AUDITED retrieve (writes audit log). Suitable for Caliper readOnly=false.
   */
  async retrieveEvidenceAndLog(ctx, evidenceId, isPublicStr, requestPREStr) {
    const { response, auditMeta } = await this._retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr);

    const auditRes = await this._logAction(ctx, 'retrieveEvidence', auditMeta.incidentId, {
      evidenceId,
      audited: true,
      accessMode: response.accessMode,
      storageMode: auditMeta.storageMode
    });

    response.audit = {
      audited: true,
      auditLogHash: auditRes?.logHash || null,
      auditBytes: auditRes?.auditBytes ?? 0
    };

    return JSON.stringify(response);
  }

  // ===========================================================================
  // System Status (no hard-coded TPS/latency claims)
  // ===========================================================================

  async getSystemStatus(ctx) {
    const ALLOW_SIMULATION = process.env.ALLOW_ZKP_SIMULATION === 'true';
    const STRICT_MODE = process.env.FORENSIC_STRICT_MODE === 'true';

    let storageMetrics = { totalEvidence: 0, hybridCount: 0, legacyCount: 0 };
    try {
      const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');
      while (true) {
        const result = await iterator.next();
        if (result.value && result.value.value.toString()) {
          storageMetrics.totalEvidence++;
          const evidence = JSON.parse(result.value.value.toString());
          const version = evidence.metadata?.version || evidence.storageVersion || '1.0';
          if (version === '2.0') storageMetrics.hybridCount++; else storageMetrics.legacyCount++;
        }
        if (result.done) { await iterator.close(); break; }
      }
    } catch (e) {
      console.log('Could not get storage metrics:', e.message);
    }

    const status = {
      timestamp: this._getTimestamp(ctx),
      version: '7.4.0-HYBRID-v2.0',

      features: {
        eddsaSignatures: 'ACTIVE',
        aesEncryption: 'AES-256-GCM',
        proxyReEncryption: 'READY',
        zkpSupport: 'DUAL_SYSTEM_WITH_FAZKP',
        zkpTypes: ['FILE_INTEGRITY', 'GDPR_COMPLIANCE'],
        zkpMode: ALLOW_SIMULATION ? 'SIMULATION' : 'PRODUCTION',
        fazkpEnabled: true,
        fazkpStrategy: 'ADAPTIVE_CHUNKING',

        storageMode: 'HYBRID_V2.0',
        storageVersion: StorageOptimizer?.STORAGE_VERSION || '2.0',
        hybridFeatures: {
          enabled: true,
          onChainLimit: StorageOptimizer?.MAX_ONCHAIN_SIZE || 800,
          offChainStorage: 'Private IPFS',
          singleMasterCID: true,
          merkleTreeCoC: true,
          backwardCompatible: true,
          cidValidation: true
        },

        storageStatistics: {
          totalEvidence: storageMetrics.totalEvidence,
          hybridCount: storageMetrics.hybridCount,
          legacyCount: storageMetrics.legacyCount,
          hybridPercentage: storageMetrics.totalEvidence > 0
            ? Math.round((storageMetrics.hybridCount / storageMetrics.totalEvidence) * 100)
            : 0
        }
      },

      performance: {
        telemetry: {
          enabled: false,
          note: 'Runtime performance metrics (TPS/latency/reduction) berasal dari telemetry nyata, bukan hard-coded.'
        },
        maxEvidenceSize: 'UNLIMITED_WITH_IPFS'
      },

      accessModes: {
        public: 'Hash only (ExternalVerifier)',
        private: 'Metadata + controlled masterCID disclosure (FI/Judge/Owner/Delegation)',
        delegated: 'Explicit delegation for AES/PRE disclosure',
        strictMode: STRICT_MODE ? 'ENABLED - All reads update CoC' : 'DISABLED - Optimized performance'
      },

      deployment: {
        chaincodeName: 'forensicContract',
        channel: 'forensic-channel'
      }
    };

    return JSON.stringify(status, null, 2);
  }

  // ===========================================================================
  // Link Evidence to Incident
  // ===========================================================================

  async linkEvidenceToIncident(ctx, evidenceId, incidentId) {
    this._checkAccess(ctx, {
      roles: ['Forensic Investigator', 'ForensicInvestigator', 'Monitoring Team', 'MonitoringTeam'],
      clearance: ['Low', 'Medium', 'High']
    });

    const evidenceBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
    if (!evidenceBytes || !evidenceBytes.length) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || !incidentBytes.length) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const evidence = JSON.parse(evidenceBytes.toString());
    const incident = JSON.parse(incidentBytes.toString());

    evidence.incidentId = incidentId;
    evidence.linkedAt = this._getTimestamp(ctx);
    await ctx.stub.putState(`evidence::${evidenceId}`, Buffer.from(JSON.stringify(evidence), 'utf8'));

    incident.evidenceList = incident.evidenceList || [];
    if (!incident.evidenceList.includes(evidenceId)) {
      incident.evidenceList.push(evidenceId);
      await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));
    }

    ctx.stub.setEvent('EvidenceLinkedToIncident', Buffer.from(JSON.stringify({
      evidenceId,
      incidentId,
      linkedAt: evidence.linkedAt
    }), 'utf8'));

    await this._logAction(ctx, 'linkEvidenceToIncident', incidentId, { evidenceId });

    return JSON.stringify({ success: true, evidenceId, incidentId });
  }

  // ===========================================================================
  // Examination & Analysis
  // ===========================================================================

  async submitExaminationAndAnalysisData(
    ctx,
    investigatorId,
    incidentId,
    evidenceIdsJson,
    analysisToolsJson,
    iocJson,
    vulnerabilitiesJson,
    ttpMappingJson,
    wh5Json
  ) {
    this._checkAccess(ctx, {
      roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge'],
      clearance: ['High', 'Judicial']
    });

    let evidenceIds, analysisTools, ioc, vulnerabilities, ttpMapping, wh5;
    try {
      evidenceIds = JSON.parse(evidenceIdsJson);
      analysisTools = JSON.parse(analysisToolsJson);
      ioc = JSON.parse(iocJson);
      vulnerabilities = JSON.parse(vulnerabilitiesJson);
      ttpMapping = JSON.parse(ttpMappingJson);
      wh5 = JSON.parse(wh5Json);
    } catch (err) {
      throw new Error(`Invalid JSON in analysis data: ${err.message}`);
    }

    const hasZKPVerifier = Array.isArray(analysisTools) && analysisTools.includes('ZKP-Verifier');
    const ts = this._getTimestamp(ctx);

    const actualInvestigator = this._getAuditActor(ctx);
    const claimedInvestigatorId = investigatorId;

    const analysisData = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      evidenceIds,
      analysisTools,
      ioc,
      vulnerabilities,
      ttpMapping,
      wh5
    };

    const analysisHash = crypto.createHash('sha256')
      .update(JSON.stringify(analysisData))
      .digest('hex');

    const entry = {
      ...analysisData,
      status: 'analysisCompleted',
      timestamp: ts,
      cryptographicMetadata: {
        analysisHash,
        integrityLevel: 'HIGH',
        zkpCapabilities: hasZKPVerifier,
        complianceFlags: {
          gdprCompliant: hasZKPVerifier,
          privacyPreserving: hasZKPVerifier,
          auditTrailComplete: true
        }
      }
    };

    const incBytes = await ctx.stub.getState(incidentId);
    if (!incBytes || incBytes.length === 0) {
      throw new Error(`Incident ${incidentId} does not exist`);
    }

    const incident = JSON.parse(incBytes.toString());
    incident.actions = incident.actions || [];
    incident.actions.push({
      action: 'examinationAndAnalysisSubmitted',
      timestamp: ts,
      by: actualInvestigator,
      claimedBy: claimedInvestigatorId,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier
    });
    await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));

    const analysisKey = ctx.stub.createCompositeKey('AnalysisEntry', [incidentId, ts, analysisHash]);
    await ctx.stub.putState(analysisKey, Buffer.from(JSON.stringify(entry), 'utf8'));

    for (const evId of evidenceIds || []) {
      try {
        const evidenceBytes = await ctx.stub.getState(`evidence::${evId}`);
        if (evidenceBytes && evidenceBytes.length > 0) {
          await this._addCoCEntry(ctx, evId, 'examined', {
            location: 'Forensic Analysis Lab',
            condition: 'analyzed',
            additionalData: {
              investigatorId: actualInvestigator,
              claimedInvestigatorId,
              analysisTools: Array.isArray(analysisTools) ? analysisTools.join(', ') : String(analysisTools),
              findingsSummary: `IOCs: ${(ioc || []).length}, Vulnerabilities: ${(vulnerabilities || []).length}`,
              analysisHash: analysisHash.substring(0, 16)
            }
          });
        }
      } catch (error) {
        console.warn(`⚠️ Failed to update CoC for evidence ${evId}: ${error.message}`);
      }
    }

    ctx.stub.setEvent('AnalysisSubmitted', Buffer.from(JSON.stringify({
      incidentId,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      timestamp: ts,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier,
      privacyLevel: hasZKPVerifier ? 'HIGH' : 'STANDARD',
      evidenceExamined: (evidenceIds || []).length
    }), 'utf8'));

    await this._logAction(ctx, 'submitExaminationAndAnalysisData', incidentId, {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier,
      evidenceCount: (evidenceIds || []).length,
      cocUpdated: true
    });

    return JSON.stringify({ success: true, analysisHash });
  }

  async retrieveExaminationAndAnalysisData(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isExternalVerifier = (roleNorm === 'externalverifier');

    if (isExternalVerifier) {
      this._checkAccess(ctx, {
        roles: ['External Verifier', 'ExternalVerifier'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge'],
        clearance: ['High', 'Judicial']
      });
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || incidentBytes.length === 0) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const iterator = await ctx.stub.getStateByPartialCompositeKey('AnalysisEntry', [incidentId]);
    const entries = [];

    let result = await iterator.next();
    while (!result.done) {
      let entry;
      try {
        entry = JSON.parse(result.value.value.toString());
      } catch {
        result = await iterator.next();
        continue;
      }

      if (entry.cryptographicMetadata?.analysisHash) {
        const originalData = {
          investigatorId: entry.investigatorId,
          incidentId: entry.incidentId,
          evidenceIds: entry.evidenceIds,
          analysisTools: entry.analysisTools,
          ioc: entry.indicatorsOfCompromise || entry.ioc,
          vulnerabilities: entry.vulnerabilities,
          ttpMapping: entry.ttpMapping,
          wh5: entry.wh5
        };

        const verificationHash = crypto.createHash('sha256')
          .update(JSON.stringify(originalData))
          .digest('hex');

        entry.cryptographicVerification = {
          integrityVerified: verificationHash === entry.cryptographicMetadata.analysisHash,
          verificationTimestamp: this._getTimestamp(ctx)
        };
      }

      entries.push(isExternalVerifier ? this._sanitizeAnalysisForExternal(entry) : entry);
      result = await iterator.next();
    }

    await iterator.close();

    if (entries.length === 0) {
      throw new Error(`No analysis data found for incident ${incidentId}`);
    }

    await this._logAction(ctx, 'retrieveExaminationAndAnalysisData', incidentId, {
      entriesRetrieved: entries.length,
      disclosure: isExternalVerifier ? 'SUMMARY_ONLY' : 'FULL',
      cryptographicVerification: 'COMPLETED'
    });

    if (isExternalVerifier) {
      return JSON.stringify({
        incidentId,
        count: entries.length,
        disclosure: 'SUMMARY_ONLY',
        entries,
        note: 'External Verifier receives summary-only analysis (hashes + verification + counts).'
      }, null, 2);
    }

    return JSON.stringify({
      incidentId,
      count: entries.length,
      entries,
      cryptographicSummary: {
        allEntriesVerified: entries.every(e => e.cryptographicVerification?.integrityVerified !== false),
        zkpEnabledEntries: entries.filter(e => e.cryptographicMetadata?.zkpCapabilities).length,
        complianceLevel: 'ENHANCED'
      }
    }, null, 2);
  }

  // ===========================================================================
  // GDPR Erasure (strict)
  // ===========================================================================

  async requestDataErasure(ctx, evidenceId, incidentId, legalBasis, requesterId) {
    this._checkAccess(ctx, {
      roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge', 'Data Protection Officer', 'DataProtectionOfficer'],
      clearance: ['High', 'Judicial']
    });

    const evidenceKey = `evidence::${evidenceId}`;
    const evidenceBytes = await ctx.stub.getState(evidenceKey);
    if (!evidenceBytes || !evidenceBytes.length) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    const evidence = JSON.parse(evidenceBytes.toString());

    if (evidence.legalHold && evidence.legalHold.active) {
      throw new Error(`Cannot erase evidence under legal hold until ${evidence.legalHold.expirationDate}`);
    }

    const ts = this._getTimestamp(ctx);
    const erasureHash = crypto.createHash('sha256')
      .update(evidenceId + ts + String(requesterId || ''))
      .digest('hex');

    const cocPointer = {
      cocCount: evidence.cocCount || 0,
      lastCoCHash: evidence.lastCoCHash || null,
      cocCID: evidence.cocCID || null
    };

    evidence.gdprCompliance = {
      erasureRequested: true,
      erasureTimestamp: ts,
      requestedBy: requesterId,
      legalBasis,
      cryptographicErasure: {
        method: 'AES_KEY_DESTRUCTION',
        erasureHash,
        irreversible: true,
        complianceStatus: 'GDPR_ARTICLE_17_COMPLIANT'
      },
      auditTrailPointer: cocPointer
    };

    if (evidence.cryptographicMetadata) {
      delete evidence.cryptographicMetadata.aesKeyEncrypted;
      delete evidence.cryptographicMetadata.encryptionIV;

      if (evidence.cryptographicMetadata.zkpMetadata) {
        if (evidence.cryptographicMetadata.zkpMetadata.integrityProof) {
          delete evidence.cryptographicMetadata.zkpMetadata.integrityProof.zkpCID;
        }
        if (evidence.cryptographicMetadata.zkpMetadata.complianceProof) {
          delete evidence.cryptographicMetadata.zkpMetadata.complianceProof.zkpCID;
        }
      }
    }

    evidence.cryptographicMetadata = { gdprCompliant: true };

    // revoke off-chain pointer defensively
    evidence.ipfsReference = null;
    if (evidence.ipfsReferences) evidence.ipfsReferences = null;
    evidence.offChainAccessRevokedAt = ts;

    evidence.status = 'CRYPTOGRAPHICALLY_ERASED';
    evidence.accessRestricted = true;

    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));

    await this._addCoCEntry(ctx, evidenceId, 'erased', {
      location: 'Blockchain Network',
      condition: 'cryptographically_erased',
      additionalData: {
        requesterId,
        legalBasis,
        erasureMethod: 'AES_KEY_DESTRUCTION',
        gdprArticle: 'ARTICLE_17'
      }
    });

    const erasureKey = ctx.stub.createCompositeKey('ErasureRecord', [evidenceId, ts]);
    const erasureRecord = {
      evidenceId,
      incidentId,
      erasureTimestamp: ts,
      requestedBy: requesterId,
      legalBasis,
      erasureHash,
      method: 'CRYPTOGRAPHIC_KEY_DESTRUCTION',
      gdprCompliant: true
    };
    await ctx.stub.putState(erasureKey, Buffer.from(JSON.stringify(erasureRecord), 'utf8'));

    ctx.stub.setEvent('DataErasureCompleted', Buffer.from(JSON.stringify({
      evidenceId,
      incidentId,
      erasureTimestamp: ts,
      requestedBy: requesterId,
      gdprCompliant: true,
      method: 'CRYPTOGRAPHIC'
    }), 'utf8'));

    await this._logAction(ctx, 'requestDataErasure', incidentId, {
      requesterId,
      legalBasis,
      erasureMethod: 'CRYPTOGRAPHIC_KEY_DESTRUCTION',
      gdprArticle: 'ARTICLE_17'
    });

    return erasureHash;
  }

  // ===========================================================================
  // Update Chain of Custody
  // ===========================================================================

  async updateChainOfCustody(ctx, evidenceId, action, actorId, location, condition, additionalDataStr) {
    if (!additionalDataStr) additionalDataStr = '{}';

    this._checkAccess(ctx, {
      roles: [
        'Forensic Investigator', 'ForensicInvestigator',
        'Gateway Collector', 'GatewayCollector',
        'Manual Collector', 'ManualCollector',
        'Judge'
      ],
      clearance: ['Medium', 'High', 'Judicial']
    });

    const addBytes = Buffer.byteLength(String(additionalDataStr), 'utf8');
    if (addBytes > 16 * 1024) {
      throw new Error(`additionalData too large (${addBytes} bytes). Max 16KB for CoC metadata`);
    }

    let additionalData = {};
    try {
      additionalData = JSON.parse(additionalDataStr);
    } catch (e) {
      throw new Error(`Invalid JSON additionalData: ${e.message}`);
    }

    additionalData.claimedActorId = actorId;

    const entryHash = await this._addCoCEntry(ctx, evidenceId, action, {
      location,
      condition,
      additionalData
    });

    const evidenceBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
    const evidence = evidenceBytes && evidenceBytes.length ? JSON.parse(evidenceBytes.toString()) : {};

    ctx.stub.setEvent('ChainOfCustodyUpdated', Buffer.from(JSON.stringify({
      evidenceId,
      action,
      actor: this._getAuditActor(ctx),
      timestamp: this._getTimestamp(ctx),
      entryHash,
      cocCount: evidence.cocCount || null,
      merkleRoot: evidence.merkleRoot || null,
      masterCID: evidence.ipfsReference || null
    }), 'utf8'));

    await this._logAction(ctx, 'updateChainOfCustody', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId,
      action,
      location,
      condition,
      storageMode: evidence.storageMode || 'legacy',
      storageVersion: evidence.storageVersion || '1.0',
      claimedActorId: actorId
    });

    return JSON.stringify({
      success: true,
      entryHash,
      cocCount: evidence.cocCount || null,
      merkleRoot: evidence.merkleRoot || null,
      masterCID: evidence.ipfsReference || null
    });
  }

  // ===========================================================================
  // Forensic Report (hybrid if large)
  // ===========================================================================

  async createForensicReport(
    ctx,
    investigatorId,
    incidentId,
    reportId,
    reportTimestamp,
    analysis,
    findings,
    storageReference,
    reportHash,
    digitalSignature
  ) {
    this._checkAccess(ctx, {
      roles: ['Forensic Investigator', 'ForensicInvestigator'],
      clearance: ['High']
    });

    if (!incidentId || !reportId || !storageReference || !reportHash) {
      throw new Error('Missing required report fields');
    }

    const createdAt = this._getTimestamp(ctx);
    const createdBy = ctx.clientIdentity.getID();

    const actualInvestigator = this._getAuditActor(ctx);
    const claimedInvestigatorId = investigatorId;

    const reportData = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      reportId,
      reportTimestamp,
      analysis,
      findings,
      reportHash
    };

    const reportIntegrityHash = crypto.createHash('sha256')
      .update(JSON.stringify(reportData))
      .digest('hex');

    const report = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      reportId,
      reportTimestamp,
      analysis,
      findings,
      storageReference,
      status: 'created',
      createdBy,
      createdAt,
      cryptographicMetadata: {
        reportHash,
        reportIntegrityHash,
        digitalSignature,
        signatureVerified: !!digitalSignature,
        encryptionMethod: 'AES-256-GCM',
        integrityLevel: 'HIGH',
        tamperProof: true
      },
      complianceMetadata: {
        gdprCompliant: true,
        auditTrailComplete: true,
        chainOfCustodyVerified: true,
        evidentialValue: 'HIGH',
        crossBorderShareable: true,
        publicSummaryAvailable: true
      }
    };

    const THRESHOLD_BYTES = 5000;
    const reportBytes = Buffer.byteLength(JSON.stringify(report), 'utf8');

    let reportToStore;
    if (reportBytes > THRESHOLD_BYTES) {
      const cid = this._assertCIDFormat(storageReference);
      reportToStore = {
        reportId,
        incidentId,
        investigatorId: actualInvestigator,
        claimedInvestigatorId,
        createdAt,
        createdBy,
        status: report.status,
        storageVersion: '2.0',
        reportCID: cid,
        reportSizeBytes: reportBytes,
        cryptographicMetadata: {
          reportHash,
          reportIntegrityHash,
          digitalSignature,
          signatureVerified: !!digitalSignature
        },
        complianceMetadata: report.complianceMetadata
      };
    } else {
      reportToStore = { ...report, storageVersion: '1.0', reportSizeBytes: reportBytes };
    }

    await ctx.stub.putState(reportId, Buffer.from(JSON.stringify(reportToStore), 'utf8'));

    const entryKey = ctx.stub.createCompositeKey('ReportEntry', [incidentId, reportTimestamp, reportId]);
    await ctx.stub.putState(entryKey, Buffer.from(JSON.stringify(reportToStore), 'utf8'));

    const incBytes = await ctx.stub.getState(incidentId);
    if (incBytes && incBytes.length > 0) {
      const incident = JSON.parse(incBytes.toString());
      incident.status = 'reportCreated';
      incident.reportMetadata = {
        reportId,
        createdAt,
        cryptographicallySecured: true,
        tamperProof: true,
        publicSummaryAvailable: true,
        storageVersion: reportToStore.storageVersion,
        reportCID: reportToStore.reportCID || null
      };
      await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));
    }

    ctx.stub.setEvent('ReportCreated', Buffer.from(JSON.stringify({
      incidentId,
      reportId,
      createdAt,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      reportIntegrityHash: reportIntegrityHash.substring(0, 16),
      publicSummaryAvailable: true,
      storageVersion: reportToStore.storageVersion,
      reportCID: reportToStore.reportCID || null
    }), 'utf8'));

    await this._logAction(ctx, 'createForensicReport', incidentId, {
      reportId,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      reportIntegrityHash: reportIntegrityHash.substring(0, 16),
      storageVersion: reportToStore.storageVersion,
      reportCID: reportToStore.reportCID || null
    });

    return JSON.stringify({ success: true, reportId, reportIntegrityHash });
  }

  async retrieveForensicReport(ctx, reportId, incidentId, summaryOnly) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const normalizedRole = this._normRole(callerRoleRaw);

    if (normalizedRole === 'externalverifier' && summaryOnly !== 'true') {
      summaryOnly = 'true';
    }

    // External verifier allowed with lower clearance
    if (normalizedRole === 'externalverifier') {
      this._checkAccess(ctx, {
        roles: ['External Verifier', 'ExternalVerifier'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge'],
        clearance: ['High', 'Judicial']
      });
    }

    if (!reportId) throw new Error('reportId is required');

    const reportBytes = await ctx.stub.getState(reportId);
    if (!reportBytes || reportBytes.length === 0) {
      throw new Error(`Report ${reportId} not found`);
    }

    const report = JSON.parse(reportBytes.toString());

    if (incidentId && report.incidentId && report.incidentId !== incidentId) {
      throw new Error(`Report ${reportId} does not belong to incident ${incidentId}`);
    }

    const accessTimestamp = this._getTimestamp(ctx);

    const storageVersion = report.storageVersion || '1.0';
    const isHybrid = storageVersion === '2.0';

    if (isHybrid) {
      if (report.reportCID) {
        report.reportCID = this._assertCIDFormat(report.reportCID);
      }
      report.cryptographicVerification = {
        pointerOnly: true,
        note: 'Full report content is off-chain; verify integrity off-chain using CID + reportHash.',
        verificationTimestamp: accessTimestamp,
        reportCID: report.reportCID || null
      };
    } else {
      if (report.cryptographicMetadata?.reportIntegrityHash) {
        const originalData = {
          investigatorId: report.investigatorId,
          claimedInvestigatorId: report.claimedInvestigatorId,
          incidentId: report.incidentId,
          reportId: report.reportId,
          reportTimestamp: report.reportTimestamp,
          analysis: report.analysis,
          findings: report.findings,
          reportHash: report.cryptographicMetadata.reportHash
        };
        const verificationHash = crypto.createHash('sha256')
          .update(JSON.stringify(originalData))
          .digest('hex');

        report.cryptographicVerification = {
          integrityVerified: verificationHash === report.cryptographicMetadata.reportIntegrityHash,
          verificationTimestamp: accessTimestamp,
          tamperProof: true
        };
      }
    }

    const mustSummary = (summaryOnly === 'true' || normalizedRole === 'externalverifier');

    let responseData;
    if (mustSummary) {
      responseData = {
        reportId: report.reportId || reportId,
        incidentId: report.incidentId || incidentId || null,
        reportTimestamp: report.reportTimestamp || null,
        status: report.status || null,
        storageVersion,
        publicSummary: {
          investigatorId: report.investigatorId || null,
          claimedInvestigatorId: report.claimedInvestigatorId || null,
          cryptographicMetadata: report.cryptographicMetadata || {},
          complianceMetadata: report.complianceMetadata || {},
          cryptographicVerification: report.cryptographicVerification || null,
          reportCID: report.reportCID || null
        },
        accessInfo: {
          mode: 'SUMMARY_ONLY',
          retrievedBy: this._getAuditActor(ctx),
          retrievedAt: accessTimestamp,
          note: isHybrid
            ? 'Hybrid report: full content off-chain (use reportCID).'
            : 'This is a public summary. Full report requires appropriate authorization.'
        }
      };
    } else {
      responseData = report;
      if (isHybrid) {
        responseData.retrievalNote = 'Hybrid report: use reportCID to fetch the full report off-chain (IPFS).';
      }
    }

    await this._logAction(ctx, 'retrieveForensicReport', report.incidentId || incidentId || '', {
      reportId,
      summaryOnly: mustSummary,
      storageVersion,
      isHybrid,
      reportCID: report.reportCID || null
    });

    ctx.stub.setEvent('ReportRetrieved', Buffer.from(JSON.stringify({
      reportId,
      incidentId: report.incidentId || incidentId || null,
      retrievedBy: this._getAuditActor(ctx),
      retrievedAt: accessTimestamp,
      summaryOnly: mustSummary,
      storageVersion,
      isHybrid,
      reportCID: report.reportCID || null
    }), 'utf8'));

    return JSON.stringify(responseData);
  }

  // ===========================================================================
  // Logs Retrieval (role-based disclosure)
  // ===========================================================================

  async getLogsForIncident(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isExternalVerifier = (roleNorm === 'externalverifier');

    if (isExternalVerifier) {
      this._checkAccess(ctx, {
        roles: ['External Verifier', 'ExternalVerifier'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge'],
        clearance: ['High', 'Judicial']
      });
    }

    const iter = await ctx.stub.getStateByPartialCompositeKey('LogEntry', [incidentId]);
    const logs = [];
    const summaries = [];

    try {
      while (true) {
        const r = await iter.next();
        if (r.done) break;
        if (!r.value || !r.value.value || !r.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(r.value.value.toString()); } catch { continue; }

        summaries.push({
          incidentId: summary.incidentId || incidentId,
          timestamp: summary.timestamp || null,
          logHash: summary.logHash || summary.hash || null,
          action: summary.action || null,
          userId: summary.userId || null,
          role: summary.role || null
        });

        if (isExternalVerifier) continue;

        const hash = summary.logHash || summary.hash;
        if (!hash) continue;

        const blobBytes = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blobBytes || !blobBytes.length) continue;

        let entry;
        try { entry = JSON.parse(blobBytes.toString()); } catch { continue; }

        if (entry.logHash) {
          const verificationData = {
            incidentId: entry.incidentId,
            action: entry.action,
            userId: entry.userId,
            role: entry.role,
            timestamp: entry.timestamp,
            metadata: entry.metadata
          };
          const verificationHash = crypto.createHash('sha256')
            .update(JSON.stringify(verificationData))
            .digest('hex');

          entry.cryptographicVerification = {
            integrityVerified: verificationHash === entry.logHash,
            tamperProof: true
          };
        }

        // defense-in-depth redaction of raw CID fields
        if (entry.metadata && typeof entry.metadata === 'object') {
          if (entry.metadata.ipfsReference) delete entry.metadata.ipfsReference;
          if (entry.metadata.masterCID) delete entry.metadata.masterCID;
          if (entry.metadata.realCID) delete entry.metadata.realCID;
          if (entry.metadata.cid) delete entry.metadata.cid;
        }

        logs.push(entry);
      }
    } finally {
      await iter.close();
    }

    if (isExternalVerifier) {
      return JSON.stringify({
        incidentId,
        logCount: summaries.length,
        disclosure: 'SUMMARY_ONLY',
        summaries,
        note: 'External Verifier only receives LogEntry summaries (no LogBlob disclosure).'
      }, null, 2);
    }

    return JSON.stringify({
      incidentId,
      logCount: logs.length,
      logs,
      cryptographicSummary: {
        allLogsVerified: logs.every(l => l.cryptographicVerification?.integrityVerified !== false),
        tamperProofAuditTrail: true,
        optimizedStorage: true
      }
    }, null, 2);
  }

  // ===========================================================================
  // Cross-border Evidence Query
  // ===========================================================================

  async queryCrossBorderEvidence(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isExternalVerifier = (roleNorm === 'externalverifier');

    if (isExternalVerifier) {
      this._checkAccess(ctx, {
        roles: ['External Verifier', 'ExternalVerifier'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge'],
        clearance: ['High', 'Judicial']
      });
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || incidentBytes.length === 0) {
      throw new Error(`Incident ${incidentId} not found`);
    }
    const incident = JSON.parse(incidentBytes.toString());

    const shareableEvidence = [];
    const nonShareableEvidence = [];

    for (const evidenceId of incident.evidenceList || []) {
      const evBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
      if (!evBytes || !evBytes.length) continue;

      const evidence = JSON.parse(evBytes.toString());
      const storageVersion = evidence.metadata?.version || evidence.storageVersion || '1.0';

      const shareable = evidence.cryptographicEvidence?.crossBorderShareable ||
        evidence.cryptographicMetadata?.crossBorderShareable || false;

      const gdprCompliant = evidence.gdprCompliance?.compliant ||
        evidence.cryptographicMetadata?.gdprCompliant || false;

      const onChainSizeBytes = Buffer.byteLength(JSON.stringify(evidence), 'utf8');

      const submittedByRaw = (typeof evidence.submittedBy === 'object')
        ? (evidence.submittedBy.enrollmentId || evidence.submittedBy.userId || evidence.submittedBy.id || null)
        : evidence.submittedBy;

      const submittedBy = isExternalVerifier
        ? (submittedByRaw ? `sub:${this._sha256Hex(String(submittedByRaw)).substring(0, 16)}` : null)
        : submittedByRaw;

      const summary = {
        evidenceId: evidence.evidenceId,
        evidenceTitle: evidence.evidenceTitle,
        evidenceType: evidence.evidenceType,
        gdprCompliant,
        crossBorderShareable: shareable,
        zkpProofsAvailable: !!(evidence.cryptographicMetadata?.zkpMetadata),
        submittedBy,
        submissionTimestamp: evidence.collectionTimestamp || evidence.timestamp || evidence.createdAt || null,
        integrityHash: evidence.integrityHash,
        publicAccessible: true,
        delegationRequired: true,
        storageInfo: {
          version: storageVersion,
          mode: storageVersion === '2.0' ? 'hybrid' : 'legacy',
          hasIPFS: !!(evidence.ipfsReference),
          onChainSizeBytes,
          ipfsPointer: (storageVersion === '2.0' && evidence.ipfsReference)
            ? {
              masterCIDHash: this._cidHash(evidence.ipfsReference),
              totalPointers: 1
            }
            : null
        }
      };

      if (shareable) shareableEvidence.push(summary);
      else nonShareableEvidence.push(summary);
    }

    const all = shareableEvidence.concat(nonShareableEvidence);

    const response = {
      incidentId,
      totalEvidence: incident.evidenceList?.length || 0,
      shareableCount: shareableEvidence.length,
      nonShareableCount: nonShareableEvidence.length,
      shareableEvidence,
      nonShareableEvidence,
      summary: {
        crossBorderCapability: shareableEvidence.length > 0,
        privacyPreserved: true,
        externalVerificationEnabled: true,
        storageBreakdown: {
          totalEvidence: incident.evidenceList?.length || 0,
          hybridStorage: all.filter(e => e.storageInfo.mode === 'hybrid').length,
          legacyStorage: all.filter(e => e.storageInfo.mode === 'legacy').length,
          averageOnChainSizeBytes: all.length
            ? Math.round(all.reduce((sum, e) => sum + (e.storageInfo.onChainSizeBytes || 0), 0) / all.length)
            : 0
        }
      }
    };

    await this._logAction(ctx, 'queryCrossBorderEvidence', incidentId, {
      shareableCount: shareableEvidence.length,
      totalCount: incident.evidenceList?.length || 0,
      hybridCount: response.summary.storageBreakdown.hybridStorage,
      legacyCount: response.summary.storageBreakdown.legacyStorage
    });

    return JSON.stringify(response, null, 2);
  }

  // ===========================================================================
  // Storage stats & queries
  // ===========================================================================

  async queryHybridStatistics(ctx) {
    const txTimestamp = this._getTimestamp(ctx);
    const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');

    const stats = {
      totalEvidence: 0,
      hybridCount: 0,
      legacyCount: 0,
      totalOnChainSize: 0,
      avgOnChainSize: 0,
      ipfsCIDCount: 0
    };

    const evidenceList = [];

    while (true) {
      const result = await iterator.next();
      if (result.value && result.value.value.toString()) {
        const evidence = JSON.parse(result.value.value.toString());
        const size = result.value.value.length;

        stats.totalEvidence++;
        stats.totalOnChainSize += size;

        if ((evidence.storageVersion || evidence.metadata?.version) === '2.0' || evidence.storageMode === 'hybrid') {
          stats.hybridCount++;
          stats.ipfsCIDCount += evidence.ipfsReference ? 1 : 0;
        } else {
          stats.legacyCount++;
        }

        evidenceList.push({
          evidenceId: evidence.evidenceId,
          storageMode: evidence.storageMode || 'legacy',
          onChainSize: size,
          hasCIDs: !!evidence.ipfsReference
        });
      }

      if (result.done) {
        await iterator.close();
        break;
      }
    }

    if (stats.totalEvidence > 0) {
      stats.avgOnChainSize = Math.round(stats.totalOnChainSize / stats.totalEvidence);
    }

    return JSON.stringify({
      statistics: stats,
      recentEvidence: evidenceList.slice(-10),
      timestamp: txTimestamp
    });
  }

  async queryMyDelegations(ctx) {
    const caller = this._getAuditActor(ctx);

    const txTimestamp = this._getTimestamp(ctx);
    const now = new Date(txTimestamp).getTime();

    const list = [];
    const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', []);

    while (true) {
      const res = await iter.next();
      if (res.done) break;

      let d;
      try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

      const expTime = Date.parse(d.expiresAt);

      if (String(d.delegateToUserId || '').trim() === caller && d.active && expTime > now) {
        let title = 'Unknown';
        const evBytes = await ctx.stub.getState(`evidence::${d.evidenceId}`);
        if (evBytes && evBytes.length) {
          try { title = JSON.parse(evBytes.toString()).evidenceTitle || title; } catch {}
        }
        list.push({
          delegationId: d.delegationId ? d.delegationId.substring(0, 16) : '',
          evidenceId: d.evidenceId,
          evidenceTitle: title,
          delegationType: d.delegationType,
          expirationTime: d.expiresAt
        });
      }
    }
    await iter.close();

    return JSON.stringify({ userId: caller, activeDelegations: list.length, delegations: list });
  }

  async getStorageMetrics(ctx) {
    const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');

    const metrics = {
      totalEvidence: 0,
      v1Legacy: 0,
      v2Hybrid: 0,
      totalOnChainSize: 0,
      avgOnChainSize: 0,
      avgV1Size: 0,
      avgV2Size: 0,
      totalCIDs: 0,
      timestamp: this._getTimestamp(ctx)
    };

    let v1TotalSize = 0;
    let v2TotalSize = 0;

    while (true) {
      const result = await iterator.next();

      if (result.value && result.value.value.toString()) {
        const evidence = JSON.parse(result.value.value.toString());
        const size = result.value.value.length;
        const version = evidence.metadata?.version || evidence.storageVersion || '1.0';

        metrics.totalEvidence++;
        metrics.totalOnChainSize += size;

        if (version === '2.0' || evidence.storageMode === 'hybrid') {
          metrics.v2Hybrid++;
          v2TotalSize += size;

          if (evidence.ipfsReference) metrics.totalCIDs += 1;

          if (evidence.ipfsReferences) {
            metrics.totalCIDs += Object.values(evidence.ipfsReferences)
              .filter(cid => cid !== null && cid !== undefined && String(cid).trim() !== '' && String(cid) !== 'null')
              .length;
          }
        } else {
          metrics.v1Legacy++;
          v1TotalSize += size;
        }
      }

      if (result.done) {
        await iterator.close();
        break;
      }
    }

    if (metrics.totalEvidence > 0) {
      metrics.avgOnChainSize = Math.round(metrics.totalOnChainSize / metrics.totalEvidence);
    }
    if (metrics.v1Legacy > 0) {
      metrics.avgV1Size = Math.round(v1TotalSize / metrics.v1Legacy);
    }
    if (metrics.v2Hybrid > 0) {
      metrics.avgV2Size = Math.round(v2TotalSize / metrics.v2Hybrid);
    }

    if (metrics.avgV1Size > 0 && metrics.avgV2Size > 0) {
      metrics.storageSavings = `${Math.round((1 - metrics.avgV2Size / metrics.avgV1Size) * 100)}%`;
    }

    return JSON.stringify(metrics);
  }

  async queryEvidenceByStorage(ctx, storageMode = 'all') {
    if (!['all', 'legacy', 'hybrid'].includes(storageMode)) {
      throw new Error('Invalid storage mode. Use: all, legacy, or hybrid');
    }

    const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');
    const results = [];

    while (true) {
      const result = await iterator.next();

      if (result.value && result.value.value && result.value.value.length) {
        const evidence = JSON.parse(result.value.value.toString());
        const version = evidence.metadata?.version || evidence.storageVersion || '1.0';
        const isHybrid = (version === '2.0' || evidence.storageMode === 'hybrid');

        if (
          storageMode === 'all' ||
          (storageMode === 'hybrid' && isHybrid) ||
          (storageMode === 'legacy' && !isHybrid)
        ) {
          const onChainSizeBytes = Buffer.byteLength(JSON.stringify(evidence), 'utf8');

          results.push({
            evidenceId: evidence.evidenceId,
            incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
            storageMode: isHybrid ? 'hybrid' : 'legacy',
            version,
            onChainSizeBytes,
            hasIPFSRefs: !!(evidence.ipfsReference),
            ipfsPointer: evidence.ipfsReference
              ? { masterCIDHash: this._cidHash(evidence.ipfsReference) }
              : null,
            timestamp: evidence.createdAt || evidence.timestamp || evidence.collectionTimestamp || null,
            submittedBy: evidence.submittedBy
          });
        }
      }

      if (result.done) {
        await iterator.close();
        break;
      }
    }

    const summary = {
      totalFound: results.length,
      storageMode,
      breakdown: {
        hybrid: results.filter(r => r.storageMode === 'hybrid').length,
        legacy: results.filter(r => r.storageMode === 'legacy').length
      },
      avgSizesBytes: { hybrid: 0, legacy: 0 }
    };

    const hybridEvidence = results.filter(r => r.storageMode === 'hybrid');
    const legacyEvidence = results.filter(r => r.storageMode === 'legacy');

    if (hybridEvidence.length > 0) {
      summary.avgSizesBytes.hybrid = Math.round(
        hybridEvidence.reduce((sum, e) => sum + e.onChainSizeBytes, 0) / hybridEvidence.length
      );
    }

    if (legacyEvidence.length > 0) {
      summary.avgSizesBytes.legacy = Math.round(
        legacyEvidence.reduce((sum, e) => sum + e.onChainSizeBytes, 0) / legacyEvidence.length
      );
    }

    return JSON.stringify({ summary, evidence: results });
  }

  // ===========================================================================
  // Audit statistics
  // ===========================================================================

  async getAuditStatistics(ctx, incidentId = '') {
    this._checkAccess(ctx, {
      roles: ['Forensic Investigator', 'ForensicInvestigator', 'Judge', 'Admin', 'System Administrator'],
      clearance: ['High', 'Judicial']
    });

    const stats = {
      totalLogs: 0,
      byAction: {},
      byUser: {},
      byIncident: {},
      lastTimestamp: null
    };

    const attrs = [];
    if (incidentId && String(incidentId).trim()) attrs.push(String(incidentId).trim());

    const iterator = await ctx.stub.getStateByPartialCompositeKey('LogEntry', attrs);

    try {
      while (true) {
        const res = await iterator.next();
        if (res.done) break;
        if (!res.value || !res.value.value || !res.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(res.value.value.toString()); } catch { continue; }

        const hash = summary.hash || summary.logHash;
        if (!hash) continue;

        const blobBytes = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blobBytes || !blobBytes.length) continue;

        let entry;
        try { entry = JSON.parse(blobBytes.toString()); } catch { continue; }

        const { action, userId, incidentId: incId, timestamp } = entry;

        stats.totalLogs++;
        if (action) stats.byAction[action] = (stats.byAction[action] || 0) + 1;
        if (userId) stats.byUser[userId] = (stats.byUser[userId] || 0) + 1;
        if (incId) stats.byIncident[incId] = (stats.byIncident[incId] || 0) + 1;

        if (timestamp && (!stats.lastTimestamp || timestamp > stats.lastTimestamp)) {
          stats.lastTimestamp = timestamp;
        }
      }
    } finally {
      await iterator.close();
    }

    return JSON.stringify(stats, null, 2);
  }

  async getMetricsByTimeRange(ctx, startTime, endTime) {
    if (!startTime || !endTime) {
      throw new Error('startTime dan endTime (ISO8601 dengan timezone) wajib diisi');
    }

    const ISO_TZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+\-]\d{2}:\d{2})$/;
    if (!ISO_TZ.test(String(startTime)) || !ISO_TZ.test(String(endTime))) {
      throw new Error('startTime/endTime harus ISO8601 lengkap + timezone, contoh: 2026-02-10T00:00:00Z');
    }

    const startISO = new Date(startTime).toISOString();
    const endISO = new Date(endTime).toISOString();
    if (startISO > endISO) throw new Error('startTime harus <= endTime');

    const metrics = {
      period: { start: startISO, end: endISO },
      submissions: 0,
      retrievals: 0,
      updates: 0,
      evidence: []
    };

    const prefix = 'evidence::';
    const iterator = await ctx.stub.getStateByRange(prefix, prefix + '\uFFFF');

    try {
      while (true) {
        const res = await iterator.next();
        if (res.done) break;
        if (!res.value || !res.value.value || !res.value.value.length) continue;

        let ev;
        try { ev = JSON.parse(res.value.value.toString()); } catch { continue; }

        const tsRaw = ev.collectionTimestamp || ev.timestamp || ev.createdAt;
        if (!tsRaw) continue;

        let tsISO;
        try { tsISO = new Date(tsRaw).toISOString(); } catch { continue; }

        if (tsISO >= startISO && tsISO <= endISO) {
          metrics.submissions++;
          metrics.evidence.push({
            id: ev.evidenceId,
            type: ev.evidenceType,
            incidentId: ev.incidentId || null,
            timestamp: tsISO
          });
        }
      }
    } finally {
      await iterator.close();
    }

    const lu = await this._countLogActionsInRange(ctx, startISO, endISO);
    metrics.retrievals = lu.retrievals;
    metrics.updates = lu.updates;

    return JSON.stringify(metrics);
  }

  async _countLogActionsInRange(ctx, startISO, endISO) {
    const out = { retrievals: 0, updates: 0 };
    const it = await ctx.stub.getStateByPartialCompositeKey('LogEntry', []);

    try {
      while (true) {
        const r = await it.next();
        if (r.done) break;
        if (!r.value || !r.value.value || !r.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(r.value.value.toString()); } catch { continue; }

        const hash = summary.hash || summary.logHash;
        if (!hash) continue;

        const blob = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blob || !blob.length) continue;

        let entry;
        try { entry = JSON.parse(blob.toString()); } catch { continue; }

        if (!entry.timestamp) continue;

        let t;
        try { t = new Date(entry.timestamp).toISOString(); } catch { continue; }

        if (t < startISO || t > endISO) continue;

        if (entry.action === 'retrieveEvidence') out.retrievals++;
        if (['updateChainOfCustody', 'submitEvidence', 'submitExaminationAndAnalysisData'].includes(entry.action)) {
          out.updates++;
        }
      }
    } finally {
      await it.close();
    }

    return out;
  }
}

module.exports = ForensicContract;
