'use strict';

const crypto = require('crypto');

/**
 * Dummy CID Generator for HLF-only Testing
 * Generates valid CID-like strings without actual IPFS integration
 * FIXED: Consistent API and better validation
 */
class DummyCIDGenerator {
    
    /**
     * Generate CIDv0 format (Qm... base58, 46 chars total)
     */
    static generateV0(seed = null) {
        const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        let cid = 'Qm';
        
        if (seed) {
            const hash = crypto.createHash('sha256').update(seed).digest();
            for (let i = 0; i < 44; i++) {
                const index = hash[i % hash.length] % base58Alphabet.length;
                cid += base58Alphabet[index];
            }
        } else {
            // Generate random CID
            for (let i = 0; i < 44; i++) {
                const randomIndex = Math.floor(Math.random() * base58Alphabet.length);
                cid += base58Alphabet[randomIndex];
            }
        }
        
        return cid;
    }
    
    /**
     * Generate CIDv1 format (bafy... base32, variable length)
     */
    static generateV1(seed = null) {
        const base32Alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
        let cid = 'bafy';
        const length = 52 + Math.floor(Math.random() * 8); // 52-59 chars
        
        if (seed) {
            const hash = crypto.createHash('sha256').update(seed).digest();
            for (let i = 0; i < length; i++) {
                const index = hash[i % hash.length] % base32Alphabet.length;
                cid += base32Alphabet[index];
            }
        } else {
            for (let i = 0; i < length; i++) {
                const randomIndex = Math.floor(Math.random() * base32Alphabet.length);
                cid += base32Alphabet[randomIndex];
            }
        }
        
        return cid;
    }
    
    /**
     * General CID generation API
     */
    static generate(options = {}) {
        const { version = 'v0', seed = null } = options;
        if (version === 'v1') {
            return this.generateV1(seed);
        }
        return this.generateV0(seed);
    }
    
    /**
     * Validate CID format
     */
    static isValidFormat(cid) {
        if (!cid || typeof cid !== 'string') return false;
        
        // CIDv0: Qm followed by 44 base58 chars (total 46)
        const v0Pattern = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
        
        // CIDv1: ba followed by base32 chars (minimum 50)
        const v1Pattern = /^ba[a-z][a-z2-7]{50,}$/;
        
        return v0Pattern.test(cid) || v1Pattern.test(cid);
    }
    
    /**
     * Generate CID from evidence object
     * Uses evidence properties to create deterministic CID
     */
    static fromEvidence(evidence) {
        const seed = `${evidence.evidenceId}-${evidence.integrityHash || ''}-${evidence.submittedBy || ''}`;
        return this.generateV0(seed);
    }
    
    /**
     * Generate component CIDs for complex evidence
     */
    static generateComponentCIDs(evidenceId) {
        return {
            masterCID: this.generateV0(`master-${evidenceId}`),
            evidenceCID: this.generateV0(`evidence-${evidenceId}`),
            zkpCID: this.generateV0(`zkp-${evidenceId}`),
            metadataCID: this.generateV0(`metadata-${evidenceId}`)
        };
    }
    
    /**
     * Generate test CID - FIXED to always return valid CID
     * @param {Object} options
     * @returns {Object} Test CID information
     */
    static generateTestCID(options = {}) {
        const {
            version = 'v0',
            seed = 'test-seed-' + Date.now(),
            returnObject = true  // Changed default to true for better debugging
        } = options;
        
        const cid = this.generate({ version, seed });
        
        if (!returnObject) {
            return cid;
        }
        
        return {
            cid: cid,
            valid: this.isValidFormat(cid),
            version: version,
            length: cid.length,
            prefix: cid.substring(0, 2)
        };
    }
    
    /**
     * Create dummy CID from buffer/data
     * Simulates IPFS hashing behavior
     */
    static fromBuffer(buffer) {
        const hash = crypto.createHash('sha256').update(buffer).digest('hex');
        return this.generateV0(hash);
    }
    
    /**
     * Generate batch of CIDs for testing
     */
    static generateBatch(count = 10, version = 'v0') {
        const cids = [];
        for (let i = 0; i < count; i++) {
            cids.push(this.generate({ 
                version, 
                seed: `batch-${i}-${Date.now()}` 
            }));
        }
        return cids;
    }
}

module.exports = DummyCIDGenerator;