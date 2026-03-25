'use strict';

const crypto = require('crypto');

/**
 * Payload Builder Utility for Evidence Submission
 * v2.2 — Compatible with ForensicContract (hybrid/direct v2.0)
 */
class PayloadBuilder {

    // Field "berat" yang harus dihapus dari payload on-chain
    static HEAVY_KEYS = [
        'evidence', 'evidenceBase64', 'payload', 'raw', 'rawBytes',
        'bytes', 'file', 'fileContent', 'blob', 'content', 'data',
        'artefak', 'artefact', 'artifact', 'fileData', 'binaryData'
    ];

    // =========================
    // Helpers
    // =========================

    static _sha256(bufOrStr) {
        return crypto.createHash('sha256').update(bufOrStr).digest('hex');
    }

    static _nowISO() {
        return new Date().toISOString();
    }

    static _id(prefix) {
        return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
    }

    static _isHex(str, len) {
        return typeof str === 'string'
            && (!len || str.length === len)
            && /^[0-9a-f]+$/i.test(str);
    }

    static _trimToString(v) {
        return (v ?? '').toString().trim();
    }

    static _normalizeCategory(category) {
        const c = (category || '').toString().toLowerCase();
        if (['tiny', 'small', 'medium', 'large'].includes(c)) return c;
        return 'tiny';
    }

    static _getEvidenceClass(category) {
        const c = this._normalizeCategory(category);
        const map = { tiny: 'sensor-data', small: 'log-file', medium: 'system-dump', large: 'memory-image' };
        return map[c] || 'unknown';
    }

    static _getPriority(category) {
        const c = this._normalizeCategory(category);
        const map = { tiny: 'low', small: 'medium', medium: 'high', large: 'critical' };
        return map[c] || 'medium';
    }

    static _getToolsByCategory(category) {
        const c = this._normalizeCategory(category);
        const map = {
            tiny: ['sensor-collector', 'mqtt-broker'],
            small: ['syslog', 'filebeat'],
            medium: ['tcpdump', 'wireshark'],
            large: ['volatility', 'dd', 'ftk-imager']
        };
        return map[c] || ['manual-upload'];
    }

    static canonicalStringify(obj) {
        if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
        if (Array.isArray(obj)) return '[' + obj.map(i => this.canonicalStringify(i)).join(',') + ']';
        const keys = Object.keys(obj).sort();
        const pairs = keys.map(k => JSON.stringify(k) + ':' + this.canonicalStringify(obj[k]));
        return '{' + pairs.join(',') + '}';
    }

    static stripHeavyFields(obj) {
        if (obj == null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(it => this.stripHeavyFields(it));
        const out = {};
        for (const [k, v] of Object.entries(obj)) {
            if (this.HEAVY_KEYS.includes(k)) continue;
            out[k] = (v && typeof v === 'object') ? this.stripHeavyFields(v) : v;
        }
        return out;
    }

    static _normalizeCid(cid) {
        if (!cid || typeof cid !== 'string') return cid;
        const c = cid.trim();
        // Chaincode terima 'Qm*'/'bafy*' atau 'ipfs://*'. Kita normalkan ke 'ipfs://*' biar konsisten.
        if (c.startsWith('ipfs://')) return c;
        return `ipfs://${c}`;
    }

    // =========================
    // Legacy builder (full on-chain)
    // =========================

    static buildLegacyPayload({ entry, fileBuffer, submittedBy, metadata = {} }) {
        const timestamp = this._nowISO();
        const fileBase64 = fileBuffer.toString('base64');
        const integrityHash = this._sha256(fileBuffer);
        const category = this._normalizeCategory(entry?.category);

        const sb = this._trimToString(submittedBy) || 'GatewayCollector';

        const payload = {
            evidenceId: this._id('EVID'),
            incidentId: metadata.incidentId || 'INC-BENCHMARK-001',
            submissionType: metadata.submissionType || 'manual',
            submittedBy: sb,
            evidenceTitle: entry?.filename || entry?.title || 'Evidence File',
            collectionTimestamp: timestamp,
            evidenceType: entry?.evidenceType || entry?.type || 'file',

            // FULL artefact on-chain (legacy)
            artefak: fileBase64,
            fileSize: fileBuffer.length,
            fileHash: integrityHash,
            integrityHash,

            toolsUsed: metadata.toolsUsed || ['manual-upload'],
            deviceContext: metadata.deviceContext || {
                platform: 'test-environment',
                source: 'caliper-benchmark'
            },

            category,
            hasPII: !!entry?.hasPII,

            chainOfCustody: [{
                timestamp,
                actor: sb,
                action: 'SUBMITTED',
                location: 'Blockchain Network',
                integrityHash
            }],

            forensicMetadata: {
                collectionMethod: 'manual',
                preservationStatus: 'preserved',
                evidenceClass: this._getEvidenceClass(category),
                priority: this._getPriority(category)
            },

            storageMode: 'legacy',
            storageVersion: '1.0'
        };

        if (metadata.includeZKP) {
            payload.cryptographicMetadata = {
                zkpProofs: {
                    type: 'simulated',
                    proof: crypto.randomBytes(32).toString('hex'),
                    publicInputs: [integrityHash.substring(0, 16)]
                },
                gdprCompliant: !entry?.hasPII,
                crossBorderShareable: !entry?.hasPII
            };
        }

        return payload;
    }

    // =========================
    // HYBRID v2.0 builder (minimal on-chain + IPFS ref)
    // =========================

    /**
     * Build hybrid wrapper with minimal on-chain data + off-chain CID
     * Selalu menulis: storageMode='hybrid', masterCID, ipfsReference, ipfsReferences.evidenceCID
     */
    static buildHybridWrapper({ evidencePayload, dummyCID, evidenceMeta = {}, storageVersion = '2.0' }) {
        const base = this.stripHeavyFields(evidencePayload || {});
        const submittedAt = this._nowISO();

        // Gunakan evidenceId dari payload bila ada; kalau tidak, generate baru
        const evidenceId = this._trimToString(base.evidenceId) || this._id('EVID');
        const incidentId = this._trimToString(base.incidentId) || 'INC-BENCHMARK-001';
        const submittedBy = this._trimToString(base.submittedBy) || 'GatewayCollector';
        const collectionTimestamp = this._trimToString(base.collectionTimestamp) || submittedAt;
        const evidenceType = this._trimToString(base.evidenceType) || this._trimToString(base.type) || 'file';
        const category = this._normalizeCategory(base.category);
        const hasPII = !!base.hasPII;

        // Pastikan integrityHash ada & valid
        let integrityHash = this._trimToString(base.integrityHash);
        if (!this._isHex(integrityHash, 64) && base.fileHash && this._isHex(base.fileHash, 64)) {
            integrityHash = base.fileHash;
        }
        if (!this._isHex(integrityHash, 64)) {
            // fallback terakhir
            integrityHash = this._sha256(evidenceId + collectionTimestamp);
        }

        // Forensic metadata minimal
        const forensicMetadata = {
            collectionMethod: base?.forensicMetadata?.collectionMethod || 'manual',
            preservationStatus: base?.forensicMetadata?.preservationStatus || 'preserved',
            evidenceClass: base?.forensicMetadata?.evidenceClass || this._getEvidenceClass(category),
            priority: base?.forensicMetadata?.priority || this._getPriority(category)
        };

        // Off-chain ref — sha256 harus sama dengan integrityHash
        const cid = this._normalizeCid(this._trimToString(dummyCID));
        const offChain = {
            provider: 'ipfs',
            cid,
            size: Number.isFinite(evidenceMeta.size) ? evidenceMeta.size : 0,
            mime: evidenceMeta.mime || 'application/octet-stream',
            sha256: (this._isHex(evidenceMeta.sha256, 64) ? evidenceMeta.sha256 : integrityHash)
        };

        // Wrapper hybrid — tambahkan semua alias CID agar chaincode pasti mendeteksi HYBRID
        const wrapper = {
            evidence: {
                evidenceId,
                incidentId,
                submittedBy,                // tidak boleh kosong
                collectionTimestamp,
                evidenceType,
                integrityHash,
                category,
                hasPII,
                forensicMetadata
            },
            offChain,
            masterCID: cid,                // detector #1 (inputData.masterCID)
            ipfsReference: cid,            // detector #2 (inputData.ipfsReference)
            ipfsReferences: {              // detector #3 (inputData.ipfsReferences.evidenceCID)
                evidenceCID: cid
            },
            storageMode: 'hybrid',
            storageVersion: storageVersion || '2.0',
            submittedAt
        };

        this.validatePayload(wrapper, 'hybrid');
        return wrapper;
    }

    // =========================
    // Size estimation (approx.)
    // =========================

    static calculateOnChainSize(payload, mode = 'legacy') {
        if (mode === 'legacy') {
            return Buffer.byteLength(JSON.stringify(payload), 'utf8');
        }
        if (mode === 'hybrid') {
            const minimal = {
                evidenceId: payload?.evidence?.evidenceId || payload?.evidenceId,
                incidentId: payload?.evidence?.incidentId || payload?.incidentId,
                integrityHash: payload?.evidence?.integrityHash || payload?.integrityHash,
                submittedBy: payload?.evidence?.submittedBy || payload?.submittedBy,
                collectionTimestamp: payload?.evidence?.collectionTimestamp || payload?.collectionTimestamp,
                evidenceType: payload?.evidence?.evidenceType || payload?.evidenceType,

                ipfsReference: payload?.ipfsReference || payload?.masterCID || payload?.offChain?.cid,
                offChainProvider: payload?.offChain?.provider || 'ipfs',
                offChainSize: payload?.offChain?.size || 0,

                storageMode: (payload?.storageMode || 'hybrid'),
                storageVersion: payload?.storageVersion || '2.0',
                submittedAt: payload?.submittedAt || this._nowISO(),

                category: payload?.evidence?.category,
                hasPII: !!payload?.evidence?.hasPII,
                priority: payload?.evidence?.forensicMetadata?.priority
            };
            return Buffer.byteLength(JSON.stringify(minimal), 'utf8');
        }
        return 0;
    }

    // =========================
    // Metadata generator (optional)
    // =========================

    static generateMetadata(category, includeOptional = false) {
        const c = this._normalizeCategory(category);
        const meta = {
            incidentId: `INC-${c.toUpperCase()}-${Date.now()}`,
            submissionType: c === 'tiny' ? 'automated' : 'manual',
            toolsUsed: this._getToolsByCategory(c),
            deviceContext: {
                platform: 'industrial-iot',
                source: `sensor-${c}`,
                location: 'test-facility'
            }
        };
        if (includeOptional) {
            meta.includeZKP = true;
            meta.additionalTags = ['benchmark', 'phase1a', c];
        }
        return meta;
    }

    // =========================
    // Validation
    // =========================

    static validatePayload(payload, mode = 'legacy') {
        if (mode === 'legacy') {
            const req = ['evidenceId', 'integrityHash', 'submittedBy', 'artefak'];
            for (const f of req) {
                if (!payload[f]) throw new Error(`Missing required field: ${f}`);
            }
            if (!this._isHex(payload.integrityHash, 64)) {
                throw new Error('Invalid integrityHash for legacy payload (must be 64-char hex)');
            }
            return true;
        }

        if (mode === 'hybrid') {
            if (!payload || typeof payload !== 'object') throw new Error('Hybrid payload must be an object');
            if (payload.storageMode !== 'hybrid') throw new Error('Hybrid payload storageMode must be "hybrid" (lowercase)');

            // Harus ada salah satu alias CID — kita mewajibkan semuanya sudah ada
            if (!payload.masterCID) throw new Error('Hybrid payload missing masterCID');
            if (!payload.ipfsReference) throw new Error('Hybrid payload missing ipfsReference');
            if (!payload.offChain || !payload.offChain.cid) throw new Error('Hybrid payload missing offChain.cid');

            if (!payload.evidence || typeof payload.evidence !== 'object') {
                throw new Error('Hybrid payload missing evidence object');
            }

            const e = payload.evidence;
            const reqE = [
                'evidenceId', 'incidentId', 'submittedBy',
                'collectionTimestamp', 'evidenceType', 'integrityHash',
                'category', 'hasPII', 'forensicMetadata'
            ];
            for (const f of reqE) {
                if (e[f] === undefined || e[f] === null || e[f] === '') {
                    throw new Error(`Hybrid evidence missing field: evidence.${f}`);
                }
            }

            // Hash harus valid & sama
            if (!this._isHex(e.integrityHash, 64)) {
                throw new Error('Hybrid evidence.integrityHash must be 64-char hex');
            }
            if (!payload.offChain.sha256 || payload.offChain.sha256.toLowerCase() !== e.integrityHash.toLowerCase()) {
                throw new Error('offChain.sha256 must equal evidence.integrityHash');
            }

            // Normalisasi kategori/prioritas
            const catNorm = this._normalizeCategory(e.category);
            if (catNorm !== e.category) e.category = catNorm;

            const pri = (e.forensicMetadata?.priority || '').toString().toLowerCase();
            if (!['low', 'medium', 'high', 'critical'].includes(pri)) {
                e.forensicMetadata.priority = this._getPriority(e.category);
            }

            if (typeof e.evidenceType !== 'string' || e.evidenceType.trim() === '') {
                e.evidenceType = 'file';
            }

            return true;
        }

        throw new Error(`Unknown validation mode: ${mode}`);
    }
}

module.exports = PayloadBuilder;
