/**
 * Centralized CSV metrics logger for off-chain measurements (Schema v2)
 * - Safe for multi-worker Caliper: header-once using lock file
 * - Atomic per-row append to avoid interleaving between processes
 * - Backward compatible base columns + optional ZKP microbench columns
 */

'use strict';

const fs = require('fs');
const path = require('path');

class MetricsLogger {
  constructor() {
    // Tag unik per run; bisa diisi dari luar: RUN_TAG="stage4-YYYYmmdd-HHMMSS"
    this.runTag = process.env.RUN_TAG || `run-${Date.now()}`;

    // logs dir relatif ke repo caliper-benchmarks
    this.logDir = path.join(__dirname, '../../../../logs');
    this.csvFile = path.join(this.logDir, `offchain-metrics-${this.runTag}.csv`);
    this.headerLock = `${this.csvFile}.hdr.lock`;

    this.isInitialized = false;

    // ===== BASE COLUMNS (jangan ubah urutan) =====
    this.baseHeaders = [
      'ts','round','txLabel','worker','sizeProfile',
      'isPublic','fazkp','zkp_gen_ms','zkp_verify_ms',
      'ipfs_add_ms','ipfs_cat_ms','cid_count','onchain_bytes',
      'size_saving_pct','delegation_check_ms','note'
    ];

    // ===== OPTIONAL ZKP MICROBENCH COLUMNS (kosong untuk run lama) =====
    // Disimpan di akhir agar kompatibel dengan parser lama yang hanya baca prefix kolom.
    this.extraHeaders = [
      'zkp_mode',        // 'direct' | 'chunked' | 'merkle' | 'none'
      'zkp_phase',       // 'gen-only' | 'verify-only' | 'gen-verify' | ''
      'proof_bytes',     // total ukuran proof (jika ada)
      'chunks'           // jumlah chunks (jika ada)
    ];

    this.headers = [...this.baseHeaders, ...this.extraHeaders];
  }

  // ---------- init & header-once ----------
  init() {
    if (this.isInitialized) return;

    if (!fs.existsSync(this.logDir)) {
      fs.mkdirSync(this.logDir, { recursive: true });
    }

    // Tulis header SEKALI saja secara aman lintas worker:
    // - coba buat lock file dengan 'wx' (gagal jika sudah ada)
    // - pemenang menulis header jika file CSV belum ada/masih kosong
    let winner = false;
    try {
      const fd = fs.openSync(this.headerLock, 'wx'); // succeed once
      fs.closeSync(fd);
      winner = true;
    } catch (_) {
      winner = false;
    }

    const needHeader =
      !fs.existsSync(this.csvFile) || fs.statSync(this.csvFile).size === 0;

    if (winner && needHeader) {
      fs.appendFileSync(this.csvFile, this.headers.join(',') + '\n', { encoding: 'utf8', mode: 0o600 });
    } else if (needHeader && !winner) {
      // Balapan sangat cepat: kecil kemungkinan. Jika masih kosong tapi bukan pemenang,
      // tunggu sangat singkat & cek lagi, lalu tulis header jika tetap kosong.
      try {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5); // sleep ~5ms (no-op fallback di Node lama)
      } catch {}
      if (fs.statSync(this.csvFile).size === 0) {
        fs.appendFileSync(this.csvFile, this.headers.join(',') + '\n', { encoding: 'utf8', mode: 0o600 });
      }
    }

    this.isInitialized = true;
    console.log(`[MetricsLogger] Initialized: ${this.csvFile}`);
  }

  // ---------- CSV helpers ----------
  _csvEscape(val) {
    if (val === null || val === undefined) return '';
    const s = String(val);
    // quote jika mengandung , " atau \n
    if (/[",\n]/.test(s)) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  }

  _defaults() {
    return {
      ts: Date.now(),
      round: '',
      txLabel: '',
      worker: 0,
      sizeProfile: '',
      isPublic: '',
      fazkp: 0,
      zkp_gen_ms: '',
      zkp_verify_ms: '',
      ipfs_add_ms: '',
      ipfs_cat_ms: '',
      cid_count: '',
      onchain_bytes: '',
      size_saving_pct: '',
      delegation_check_ms: '',
      note: '',
      // extra (opsional)
      zkp_mode: '',
      zkp_phase: '',
      proof_bytes: '',
      chunks: ''
    };
  }

  // ---------- public API ----------
  /**
   * Log satu baris metrik (akan otomatis init & append atomik)
   * Field yang tidak diisi akan dikosongkan.
   */
  logMetric(metric) {
    if (!this.isInitialized) this.init();

    const entry = Object.assign(this._defaults(), metric || {});
    const row = this.headers.map(h => this._csvEscape(entry[h])).join(',');
    // append per-row atomic
    fs.appendFileSync(this.csvFile, row + '\n', { encoding: 'utf8' });
  }

  /** Log banyak sekaligus */
  logBatch(metrics) {
    if (!Array.isArray(metrics) || metrics.length === 0) return;
    metrics.forEach(m => this.logMetric(m));
  }

  /** Tutup (no-op; pakai appendFileSync) */
  close() {
    // tidak perlu apa-apa; disediakan untuk API kompatibel
  }

  /** Path file log aktif */
  getLogPath() {
    return this.csvFile;
  }
}

// Singleton
let instance = null;

module.exports = {
  getInstance: () => {
    if (!instance) {
      instance = new MetricsLogger();
      instance.init();
    }
    return instance;
  },
  MetricsLogger
};
