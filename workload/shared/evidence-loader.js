'use strict';

const fs = require('fs');
const path = require('path');

/**
 * EvidenceLoader (FINAL)
 * - Backward compatible (Phase 1A): next(), readFile*, getStats()
 * - Phase 1B: getNextFromCategory(), loadFileBuffer()
 * - Wrap-around per kategori (infinite stream)
 * - Path resolution lebih robust (baseDir + workspace fallback)
 * - Validasi bucket + optional strict mode
 */
class EvidenceLoader {
    /**
     * @param {string} indexPath absolute / relative
     * @param {{strict?: boolean, workspaceRoot?: string}} opts
     */
    constructor(indexPath, opts = {}) {
        this.indexPath = indexPath;
        this.opts = {
            strict: Boolean(opts.strict ?? false),
            workspaceRoot: opts.workspaceRoot || process.cwd(), // caliper-workspace root
        };

        this.index = null; // {tiny:[], small:[], medium:[], large:[]}
        this.cursors = { tiny: 0, small: 0, medium: 0, large: 0 };

        this.baseDir = null;      // dir tempat index.json berada
        this._loaded = false;
        this._keys = ['tiny', 'small', 'medium', 'large'];
    }

    // ---------------------------
    // Load + Normalize index.json
    // ---------------------------
    loadIndex() {
        const absolutePath = this._resolveIndexPath(this.indexPath);
        if (!fs.existsSync(absolutePath)) {
            throw new Error(`Evidence index not found: ${absolutePath}`);
        }

        this.baseDir = path.dirname(absolutePath);

        const raw = fs.readFileSync(absolutePath, 'utf8');
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            throw new Error(`Invalid JSON (${absolutePath}): ${e.message}`);
        }

        // Accept shapes:
        // 1) { files:[...] }
        // 2) { benchmarkAssignments:{...} }
        // 3) { tiny:[], small:[], medium:[], large:[] }
        if (parsed.files && Array.isArray(parsed.files)) {
            this.index = this._organizeByCategory(parsed.files);
        } else if (parsed.benchmarkAssignments) {
            this.index = this._extractFromAssignments(parsed.benchmarkAssignments);
        } else {
            this.index = this._normalizeBuckets(parsed);
        }

        // Ensure all keys exist
        for (const k of this._keys) this.index[k] = Array.isArray(this.index[k]) ? this.index[k] : [];

        // Minimal health check (agar masalah cepat ketahuan)
        const stats = this.getIndexStats();
        console.log('[EvidenceLoader] Index loaded:');
        console.log(`  baseDir: ${this.baseDir}`);
        console.log(`  stats : ${JSON.stringify(stats)}`);

        if (this.opts.strict) {
            // strict: kalau total 0 atau ada bucket kosong -> fail fast (buat riset lebih bersih)
            if (stats.total === 0) {
                throw new Error('EvidenceLoader strict: index total=0 (no entries)');
            }
        }

        this._loaded = true;
        return stats;
    }

    _resolveIndexPath(p) {
        if (path.isAbsolute(p)) return p;

        // 1) relative to workspace root
        const c1 = path.resolve(this.opts.workspaceRoot, p);
        if (fs.existsSync(c1)) return c1;

        // 2) relative to current working dir (backup)
        const c2 = path.resolve(process.cwd(), p);
        if (fs.existsSync(c2)) return c2;

        // 3) relative to this file (legacy fallback)
        const c3 = path.resolve(__dirname, '../../../../', p);
        return c3;
    }

    _organizeByCategory(files) {
        const out = { tiny: [], small: [], medium: [], large: [] };
        for (const f of files) {
            const cat = String((f.category || this.inferCategory(f.size || 0))).toLowerCase();
            if (!out[cat]) continue;
            out[cat].push(this._normalizeEntry(f, cat));
        }
        return out;
    }

    _extractFromAssignments(assignments) {
        const out = { tiny: [], small: [], medium: [], large: [] };
        const seen = new Set();

        for (const files of Object.values(assignments || {})) {
            if (!Array.isArray(files)) continue;
            for (const f of files) {
                const cat = String((f.category || this.inferCategory(f.size || 0))).toLowerCase();
                const fn = f.filename || f.name || f.fileName || path.basename(f.path || f.filePath || f.absolutePath || '');
                const id = `${cat}:${fn}`;
                if (seen.has(id)) continue;
                seen.add(id);
                if (!out[cat]) continue;
                out[cat].push(this._normalizeEntry({ ...f, filename: fn }, cat));
            }
        }
        return out;
    }

    _normalizeBuckets(src) {
        const out = { tiny: [], small: [], medium: [], large: [] };
        for (const k of this._keys) {
            const arr = Array.isArray(src?.[k]) ? src[k] : [];
            for (const e of arr) out[k].push(this._normalizeEntry(e, k));
        }
        return out;
    }

    _normalizeEntry(entry, categoryHint = null) {
        const e = { ...(entry || {}) };

        // category
        e.category = String(e.category || categoryHint || this.inferCategory(Number(e.size || 0))).toLowerCase();
        if (!this._keys.includes(e.category)) e.category = 'tiny';

        // filename
        if (!e.filename) {
            e.filename = e.name || e.fileName || path.basename(e.path || e.filePath || e.absolutePath || '');
        }

        // size
        e.size = Number(e.size) || 0;

        // absolutePath (best-effort resolve now; still re-checked in loadFileBuffer)
        e.absolutePath = e.absolutePath || this._resolveEntryPath(e);

        return e;
    }

    _resolveEntryPath(e) {
        const cands = this._buildCandidates(e);
        for (const p of cands) {
            if (p && fs.existsSync(p)) return p;
        }
        return null;
    }

    _buildCandidates(e) {
        const cands = [];

        // already absolute
        if (e.absolutePath) cands.push(e.absolutePath);

        // path/filePath relative to baseDir first, then workspace
        if (e.path) {
            cands.push(path.isAbsolute(e.path) ? e.path : path.resolve(this.baseDir || this.opts.workspaceRoot, e.path));
            cands.push(path.isAbsolute(e.path) ? e.path : path.resolve(this.opts.workspaceRoot, e.path));
        }
        if (e.filePath) {
            cands.push(path.isAbsolute(e.filePath) ? e.filePath : path.resolve(this.baseDir || this.opts.workspaceRoot, e.filePath));
            cands.push(path.isAbsolute(e.filePath) ? e.filePath : path.resolve(this.opts.workspaceRoot, e.filePath));
        }

        // conventional layout: <baseDir>/evidence/<category>/<filename>
        if (e.filename && e.category) {
            cands.push(path.resolve(this.baseDir || this.opts.workspaceRoot, 'evidence', e.category, e.filename));
            cands.push(path.resolve(this.opts.workspaceRoot, 'evidence', e.category, e.filename));
        }

        return cands.filter(Boolean);
    }

    // ---------------
    // Category helpers
    // ---------------
    inferCategory(bytes) {
        const b = Number(bytes) || 0;
        if (b < 1 * 1024) return 'tiny';
        if (b < 10 * 1024) return 'small';
        if (b < 1 * 1024 * 1024) return 'medium';
        return 'large';
    }

    // ----------
    // Statistics
    // ----------
    getIndexStats() {
        const t = this.index?.tiny?.length || 0;
        const s = this.index?.small?.length || 0;
        const m = this.index?.medium?.length || 0;
        const l = this.index?.large?.length || 0;
        return { tiny: t, small: s, medium: m, large: l, total: t + s + m + l };
    }

    getStats() {
        return this.getIndexStats();
    }

    // --------------------------
    // Core cursored next() (wrap)
    // --------------------------
    next(sizeProfile) {
        if (!this._loaded || !this.index) throw new Error('Evidence index not loaded. Call loadIndex() first.');

        const k = String(sizeProfile || 'tiny').toLowerCase();
        const key = this._keys.includes(k) ? k : 'tiny';

        const arr = this.index[key];
        if (!Array.isArray(arr)) throw new Error(`Unknown size profile: ${key}`);
        if (arr.length === 0) return null; // benar-benar kosong

        const cur = this.cursors[key] || 0;
        const i = cur % arr.length;           // wrap-around
        this.cursors[key] = (cur + 1) >>> 0;  // safe overflow

        return { ...arr[i] }; // avoid mutation downstream
    }

    // Phase 1B API
    getNextFromCategory(category) {
        return this.next(category);
    }

    // -----------------------
    // File load (robust)
    // -----------------------
    async loadFileBuffer(entry) {
        if (!entry) throw new Error('loadFileBuffer: entry is required');

        const cands = this._buildCandidates(entry);

        for (const p of cands) {
            try {
                if (p && fs.existsSync(p)) {
                    return fs.readFileSync(p);
                }
            } catch (_) {
                // try next
            }
        }

        // strict: fail noisy biar cepat ketahuan path salah
        const msg =
            `File not found for "${entry.filename || '(unknown)'}" ` +
            `cat="${entry.category || '?'}". Tried: ${cands.slice(0, 6).join(' | ')}${cands.length > 6 ? ' | ...' : ''}`;

        throw new Error(msg);
    }

    // ----------
    // Utilities
    // ----------
    resetCursors() {
        this.cursors = { tiny: 0, small: 0, medium: 0, large: 0 };
    }
}

module.exports = EvidenceLoader;