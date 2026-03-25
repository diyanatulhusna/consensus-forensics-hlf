/**
 * IPFSManager.js - ROBUST VERSION v2.6 (HADES-aligned)
 *
 * Key updates:
 * - CID normalization supports ipfs:// and path suffix
 * - Strict statusCode checks
 * - retrieve() supports binary-safe Buffer output
 * - maxBytes guard to prevent huge cat responses
 * - stable JSON stringify for deterministic object CIDs (if ever used in endorsement path)
 * - optional env guard to disable IPFS IO inside chaincode
 */

'use strict';

const http = require('http');

class IPFSManager {
  constructor() {
    this.nodes = [
      { host: 'forensic-ipfs-node1', port: 5001, priority: 1 },
      { host: '172.20.0.11', port: 5001, priority: 2 },
      { host: 'localhost', port: 5001, priority: 3 }
    ];

    this.requestTimeoutMs = 30000;
    this.maxRetries = 3;

    // Safety defaults
    this.defaultMaxCatBytes = 2 * 1024 * 1024; // 2MB: enough for master object / metadata
    this.defaultCidVersion = 0; // keep backward-compatible (Qm...). You can set to 1 if you want bafy...
    this.keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });

    // If this code runs inside endorsing peers, strongly consider disabling IO:
    // export ALLOW_IPFS_IO=false (default false)
    this.allowIo = (process.env.ALLOW_IPFS_IO || 'false').toLowerCase() === 'true';
  }

  // ------------------------------
  // Deterministic stringify
  // ------------------------------
  static stableStringify(x) {
    if (x === null || x === undefined) return 'null';
    if (typeof x !== 'object') return JSON.stringify(x);
    if (Array.isArray(x)) return '[' + x.map(IPFSManager.stableStringify).join(',') + ']';

    const keys = Object.keys(x).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + IPFSManager.stableStringify(x[k]));
    return '{' + parts.join(',') + '}';
  }

  // ------------------------------
  // CID normalize + validate
  // ------------------------------
  static normalizeCID(cid) {
    if (!cid) return '';
    const s = String(cid).trim();
    const raw = s.replace(/^ipfs:\/\//i, '');
    // strip path: bafy.../something -> bafy...
    return raw.split('/')[0].trim();
  }

  static isValidCID(cid) {
    if (!cid) return false;
    const c = IPFSManager.normalizeCID(cid);
    // CIDv0
    const v0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
    // CIDv1 common
    const v1 = /^bafy[a-z2-7]{20,}$/;
    return v0.test(c) || v1.test(c);
  }

  // ------------------------------
  // Public API
  // ------------------------------

  /**
   * Store data to IPFS with retry + pin
   * @param {Object|String|Buffer} data
   * @param {Object} opts
   * @param {number} opts.cidVersion 0 or 1
   * @returns {Promise<string>} CID (bare, without ipfs://)
   */
  async store(data, opts = {}) {
    if (!this.allowIo) {
      throw new Error('IPFS IO disabled (ALLOW_IPFS_IO=false). Store via off-chain gateway/service.');
    }

    const cidVersion = Number.isInteger(opts.cidVersion) ? opts.cidVersion : this.defaultCidVersion;

    let dataBuf;
    if (Buffer.isBuffer(data)) {
      dataBuf = data;
    } else if (typeof data === 'string') {
      dataBuf = Buffer.from(data, 'utf8');
    } else if (typeof data === 'object') {
      // deterministic for objects (important if CID is later anchored on-chain)
      dataBuf = Buffer.from(IPFSManager.stableStringify(data), 'utf8');
    } else {
      dataBuf = Buffer.from(String(data), 'utf8');
    }

    for (const node of this.nodes) {
      for (let retry = 0; retry < this.maxRetries; retry++) {
        try {
          const cid = await this._storeToNode(node, dataBuf, { cidVersion });
          const norm = IPFSManager.normalizeCID(cid);

          if (norm && IPFSManager.isValidCID(norm)) {
            console.log(`   ✅ Stored to IPFS via ${node.host}: ${norm}`);
            return norm;
          }
          throw new Error(`Invalid CID returned: ${cid}`);
        } catch (err) {
          console.warn(`   ⚠️ Attempt ${retry + 1}/${this.maxRetries} failed for ${node.host}: ${err.message}`);
          if (retry < this.maxRetries - 1) {
            await new Promise(r => setTimeout(r, Math.pow(2, retry) * 1000));
          }
        }
      }
    }

    throw new Error('Failed to store to any IPFS node after all retries');
  }

  /**
   * Retrieve from IPFS with failover
   * @param {string} cid (accepts ipfs://CID too)
   * @param {Object} opts
   * @param {boolean} opts.asBuffer return Buffer (binary-safe)
   * @param {boolean} opts.parseJson try JSON.parse if not asBuffer
   * @param {number} opts.maxBytes limit response size
   * @returns {Promise<any|Buffer|string>}
   */
  async retrieve(cid, opts = {}) {
    if (!this.allowIo) {
      throw new Error('IPFS IO disabled (ALLOW_IPFS_IO=false). Retrieve via off-chain gateway/service.');
    }

    const norm = IPFSManager.normalizeCID(cid);
    if (!IPFSManager.isValidCID(norm)) {
      throw new Error(`Invalid CID format: ${cid}`);
    }

    const asBuffer = opts.asBuffer === true;
    const parseJson = opts.parseJson !== false; // default true
    const maxBytes = Number.isInteger(opts.maxBytes) ? opts.maxBytes : this.defaultMaxCatBytes;

    for (const node of this.nodes) {
      try {
        const out = await this._retrieveFromNode(node, norm, { asBuffer, parseJson, maxBytes });
        console.log(`   ✅ Retrieved from IPFS via ${node.host}`);
        return out;
      } catch (err) {
        console.warn(`   ⚠️ Failed to retrieve from ${node.host}: ${err.message}`);
      }
    }

    throw new Error(`Failed to retrieve CID ${norm} from any node`);
  }

  async pin(cid) {
    if (!this.allowIo) {
      throw new Error('IPFS IO disabled (ALLOW_IPFS_IO=false). Pin via off-chain gateway/service.');
    }

    const norm = IPFSManager.normalizeCID(cid);
    if (!IPFSManager.isValidCID(norm)) throw new Error(`Invalid CID format: ${cid}`);

    for (const node of this.nodes) {
      try {
        await this._pinOnNode(node, norm);
        console.log(`   📌 Pinned ${norm} on ${node.host}`);
        return true;
      } catch (err) {
        console.warn(`   ⚠️ Failed to pin on ${node.host}: ${err.message}`);
      }
    }
    return false;
  }

  // ------------------------------
  // Internal: store / retrieve / pin
  // ------------------------------

  async _storeToNode(node, dataBuf, { cidVersion }) {
    return new Promise((resolve, reject) => {
      const boundary = '----FormBoundary' + Math.random().toString(36).slice(2);
      const formData = this._createFormData(dataBuf, boundary);

      const path =
        `/api/v0/add?pin=true&wrap-with-directory=false&cid-version=${encodeURIComponent(String(cidVersion))}`;

      const options = {
        hostname: node.host,
        port: node.port,
        path,
        method: 'POST',
        agent: this.keepAliveAgent,
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': formData.length,
          'Accept': 'application/json'
        }
      };

      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk.toString('utf8'); });
        res.on('end', () => {
          if (res.statusCode !== 200) {
            return reject(new Error(`IPFS add failed (HTTP ${res.statusCode}): ${body}`));
          }

          try {
            // NDJSON: take last line
            const lines = body.trim().split(/\r?\n/).filter(Boolean);
            if (!lines.length) return reject(new Error('Empty response from IPFS add'));

            const last = JSON.parse(lines[lines.length - 1]);
            const cid = last.Hash || last.Cid || last.cid || null;

            const finalCid = (typeof cid === 'string') ? cid : (cid && cid['/']) || null;
            if (!finalCid) return reject(new Error(`No CID in response: ${body}`));

            resolve(finalCid);
          } catch (e) {
            reject(new Error(`Failed to parse IPFS add response: ${e.message}\nBody: ${body}`));
          }
        });
      });

      req.on('error', (e) => reject(new Error(`Request error: ${e.message}`)));
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        reject(new Error(`IPFS add request timeout after ${this.requestTimeoutMs}ms`));
      });

      req.write(formData);
      req.end();
    });
  }

  async _retrieveFromNode(node, cid, { asBuffer, parseJson, maxBytes }) {
    return new Promise((resolve, reject) => {
      const path = `/api/v0/cat?arg=${encodeURIComponent(cid)}`;

      const options = {
        hostname: node.host,
        port: node.port,
        path,
        method: 'POST',
        agent: this.keepAliveAgent
      };

      const req = http.request(options, (res) => {
        if (res.statusCode !== 200) {
          let body = '';
          res.on('data', (c) => { body += c.toString('utf8'); });
          res.on('end', () => reject(new Error(`IPFS cat failed (HTTP ${res.statusCode}): ${body}`)));
          return;
        }

        const chunks = [];
        let total = 0;

        res.on('data', (chunk) => {
          total += chunk.length;
          if (total > maxBytes) {
            req.destroy();
            return reject(new Error(`IPFS cat exceeded maxBytes (${total} > ${maxBytes})`));
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          const buf = Buffer.concat(chunks);

          if (asBuffer) return resolve(buf);

          const text = buf.toString('utf8');
          if (parseJson) {
            try { return resolve(JSON.parse(text)); } catch { /* fallthrough */ }
          }
          return resolve(text);
        });
      });

      req.on('error', (e) => reject(new Error(`Retrieve error: ${e.message}`)));
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        reject(new Error(`IPFS cat request timeout after ${this.requestTimeoutMs}ms`));
      });

      req.end();
    });
  }

  _createFormData(dataBuf, boundary) {
    const eol = '\r\n';
    const prefix = `--${boundary}${eol}`;
    const suffix = `${eol}--${boundary}--${eol}`;

    const contentDisposition = `Content-Disposition: form-data; name="file"; filename="data"${eol}`;
    const contentType = `Content-Type: application/octet-stream${eol}${eol}`;

    const header = Buffer.from(prefix + contentDisposition + contentType, 'utf8');
    const footer = Buffer.from(suffix, 'utf8');

    const data = Buffer.isBuffer(dataBuf) ? dataBuf : Buffer.from(dataBuf);
    return Buffer.concat([header, data, footer]);
  }

  async _pinOnNode(node, cid) {
    return new Promise((resolve, reject) => {
      const path = `/api/v0/pin/add?arg=${encodeURIComponent(cid)}`;

      const options = {
        hostname: node.host,
        port: node.port,
        path,
        method: 'POST',
        agent: this.keepAliveAgent
      };

      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk.toString('utf8'); });
        res.on('end', () => {
          if (res.statusCode === 200) return resolve(true);
          reject(new Error(`Pin failed (HTTP ${res.statusCode}): ${body}`));
        });
      });

      req.on('error', (e) => reject(new Error(`Pin error: ${e.message}`)));
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        reject(new Error(`Pin request timeout after ${this.requestTimeoutMs}ms`));
      });
      req.end();
    });
  }
}

module.exports = IPFSManager;
