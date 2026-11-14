if (typeof module !== 'undefined') { Object.assign(globalThis, require('./core.js')); }
/*FCORE_START*/
// ===== ファイル解析 =====
const u16be = (b, o) => (b[o] << 8) | b[o + 1];
const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u16le = (b, o) => b[o] | (b[o + 1] << 8);
const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const asc = (b, o, n) => latin1(b.subarray(o, o + n));
function startsHex(b, o, h) { if (o + h.length / 2 > b.length) return false; for (let i = 0; i < h.length / 2; i++) if (b[o + i] !== parseInt(h.substr(i * 2, 2), 16)) return false; return true; }

const SIGS = [
  ['PNG画像', 'png', '89504e470d0a1a0a'], ['JPEG画像', 'jpg jpeg jfif', 'ffd8ff'], ['GIF画像', 'gif', '474946383961'], ['GIF画像', 'gif', '474946383761'],
  ['PDF', 'pdf', '255044462d'], ['ZIP圧縮', 'zip docx xlsx pptx jar apk odt epub', '504b0304'], ['ZIP圧縮（空）', 'zip', '504b0506'],
  ['GZIP圧縮', 'gz tgz', '1f8b08'], ['7z圧縮', '7z', '377abcaf271c'], ['RAR圧縮', 'rar', '526172211a07'], ['XZ圧縮', 'xz', 'fd377a585a00'],
  ['BZIP2圧縮', 'bz2', '425a6839'], ['ELF実行ファイル（Linuxのプログラム）', ' elf so o out bin', '7f454c46'], ['Javaクラス', 'class', 'cafebabe'],
  ['pcap（通信の記録）', 'pcap cap', 'd4c3b2a1'], ['pcap（通信の記録）', 'pcap cap', 'a1b2c3d4'], ['pcapng（通信の記録）', 'pcapng', '0a0d0d0a'],
  ['SQLiteデータベース', 'db sqlite sqlite3', '53514c69746520666f726d6174203300'], ['OGG音声', 'ogg', '4f676753'], ['FLAC音声', 'flac', '664c6143'],
  ['MP3音声', 'mp3', '494433'], ['MIDI音楽', 'mid midi', '4d546864'], ['Photoshop画像', 'psd', '38425053'], ['BMP画像', 'bmp', '424d'],
  ['EXE実行ファイル（Windowsのプログラム）', 'exe dll', '4d5a'],
];
function detectType(b) {
  if (asc(b, 0, 4) === 'RIFF') { const k = asc(b, 8, 4); if (k === 'WAVE') return { n: 'WAV音声', ext: ['wav'] }; if (k === 'WEBP') return { n: 'WebP画像', ext: ['webp'] }; if (k === 'AVI ') return { n: 'AVI動画', ext: ['avi'] }; }
  if (asc(b, 4, 4) === 'ftyp') return { n: 'MP4/MOV動画', ext: ['mp4', 'mov', 'm4a', 'heic'] };
  if (asc(b, 257, 5) === 'ustar') return { n: 'TARまとめファイル', ext: ['tar'] };
  for (const [n, e, h] of SIGS) if (startsHex(b, 0, h)) return { n, ext: e.split(' ') };
  if (b.length && printableRatio(latin1(b.subarray(0, 4096))) > 0.95) return { n: 'テキスト（文字だけのファイル）', ext: ['txt', 'md', 'csv', 'py', 'c', 'js', 'html', 'json', 'log', 'xml', 'sh', ''], text: true };
  return null;
}
const EMBED = [['PNG画像', '89504e470d0a1a0a'], ['JPEG画像', 'ffd8ffe0'], ['JPEG画像', 'ffd8ffe1'], ['JPEG画像', 'ffd8ffdb'], ['JPEG画像', 'ffd8ffee'], ['GIF画像', '474946383961'], ['PDF', '255044462d312e'], ['ZIP圧縮', '504b0304'], ['7z圧縮', '377abcaf271c'], ['RAR圧縮', '526172211a07'], ['GZIP圧縮', '1f8b0800'], ['ELF実行ファイル', '7f454c4602'], ['ELF実行ファイル', '7f454c4601'], ['SQLiteデータベース', '53514c69746520666f726d617420'], ['OGG音声', '4f67675300'], ['FLAC音声', '664c614300']];
function scanEmbedded(b, selfType) {
  const hits = [];
  for (const [n, h] of EMBED) {
    const f = parseInt(h.substr(0, 2), 16);
    for (let i = 1; i < b.length && hits.length < 60; i++) {
      if (b[i] !== f || !startsHex(b, i, h)) continue;
      hits.push({ off: i, n });
      if (n === 'ZIP圧縮') break; // ZIPは最初の1つだけ（中のファイルごとに見つかるため）
    }
  }
  if (selfType && selfType.n === 'ZIP圧縮') return hits.filter(h => h.n !== 'ZIP圧縮');
  return hits.sort((a, c) => a.off - c.off);
}

// CRC32（PNGのチェック用の数）
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(b) { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

function parsePNG(b) {
  const r = { chunks: [], texts: [], ztxt: [], ihdr: null, end: null, exif: null };
  let off = 8;
  while (off + 12 <= b.length) {
    const len = u32be(b, off), type = asc(b, off + 4, 4), ds = off + 8;
    if (!/^[A-Za-z]{4}$/.test(type)) break;
    if (ds + len + 4 > b.length) { r.chunks.push({ type, len, off, broken: true }); break; }
    const crcOk = u32be(b, ds + len) === crc32(b.subarray(off + 4, ds + len));
    r.chunks.push({ type, len, off, crcOk });
    const d = b.subarray(ds, ds + len);
    if (type === 'IHDR') r.ihdr = { w: u32be(d, 0), h: u32be(d, 4), crcOk, off };
    if (type === 'tEXt') { const z = d.indexOf(0); r.texts.push({ key: asc(d, 0, z), val: latin1(d.subarray(z + 1)) }); }
    if (type === 'zTXt') { const z = d.indexOf(0); r.ztxt.push({ key: asc(d, 0, z), data: d.subarray(z + 2) }); }
    if (type === 'iTXt') {
      const z = d.indexOf(0), comp = d[z + 1]; let p = d.indexOf(0, z + 3); p = d.indexOf(0, p + 1);
      if (comp) r.ztxt.push({ key: asc(d, 0, z), data: d.subarray(p + 1) }); else r.texts.push({ key: asc(d, 0, z), val: bytesToText(d.subarray(p + 1)) });
    }
    if (type === 'eXIf') r.exif = parseTIFF(b, ds, ds + len);
    off = ds + len + 4;
    if (type === 'IEND') { r.end = off; break; }
  }
  return r;
}
// IHDRのCRCが合わない → 幅や高さが書き換えられている問題。正しい値を探す
function fixIHDR(b, ihdr) {
  const body = b.slice(ihdr.off + 4, ihdr.off + 21), want = u32be(b, ihdr.off + 21);
  const tryWH = (w, h) => { body[5] = w >>> 16 & 255; body[6] = w >>> 8 & 255; body[7] = w & 255; body[4] = w >>> 24; body[9] = h >>> 16 & 255; body[10] = h >>> 8 & 255; body[11] = h & 255; body[8] = h >>> 24; return crc32(body) === want; };
  let found = null;
  for (let h = 1; h <= 10000 && !found; h++) if (tryWH(ihdr.w, h)) found = [ihdr.w, h];
  for (let w = 1; w <= 10000 && !found; w++) if (tryWH(w, ihdr.h)) found = [w, ihdr.h];
  for (let w = 1; w <= 2000 && !found; w++) for (let h = 1; h <= 2000; h++) if (tryWH(w, h)) { found = [w, h]; break; }
  if (!found) return null;
  const out = b.slice(); tryWH(found[0], found[1]); out.set(body, ihdr.off + 4);
  return { w: found[0], h: found[1], bytes: out };
}

const TIFF_TAGS = { 0x010e: '画像の説明 (ImageDescription)', 0x010f: 'カメラのメーカー (Make)', 0x0110: 'カメラの機種 (Model)', 0x0131: 'ソフト (Software)', 0x0132: '更新日時 (DateTime)', 0x013b: '作者 (Artist)', 0x8298: '著作権 (Copyright)', 0x9003: '撮影日時 (DateTimeOriginal)', 0x9286: 'コメント (UserComment)', 0x9c9b: 'タイトル (XPTitle)', 0x9c9c: 'コメント (XPComment)', 0x9c9d: '作者 (XPAuthor)', 0x9c9e: 'キーワード (XPKeywords)', 0x9c9f: '件名 (XPSubject)', 0xa430: 'カメラの持ち主 (CameraOwnerName)', 0xa431: 'カメラの製造番号 (BodySerialNumber)', 0xa420: '画像ID (ImageUniqueID)', 0x010d: 'ドキュメント名 (DocumentName)' };
function parseTIFF(b, base, limit) {
  const tags = [], gps = {};
  try {
    const le = b[base] === 0x49, r16 = o => le ? u16le(b, o) : u16be(b, o), r32 = o => le ? u32le(b, o) : u32be(b, o);
    const SZ = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
    const seen = new Set();
    const walk = (ifd, kind) => {
      if (!ifd || seen.has(ifd) || base + ifd + 2 > limit) return; seen.add(ifd);
      const p = base + ifd, n = r16(p);
      for (let i = 0; i < n && i < 300; i++) {
        const e = p + 2 + i * 12, tag = r16(e), type = r16(e + 2), cnt = r32(e + 4), tot = (SZ[type] || 1) * cnt;
        const doff = tot <= 4 ? e + 8 : base + r32(e + 8);
        if (doff + tot > limit) continue;
        const d = b.subarray(doff, doff + tot);
        if (kind === 'gps') {
          if (tag === 1 || tag === 3) gps[tag] = asc(d, 0, 1);
          if ((tag === 2 || tag === 4) && type === 5) { const v = [0, 1, 2].map(k => r32(doff + k * 8) / (r32(doff + k * 8 + 4) || 1)); gps[tag] = v[0] + v[1] / 60 + v[2] / 3600; }
          continue;
        }
        if (tag === 0x8769) { walk(r32(e + 8), 'exif'); continue; }
        if (tag === 0x8825) { walk(r32(e + 8), 'gps'); continue; }
        let val = null;
        if (type === 2) val = latin1(d).replace(/\0+$/, '');
        else if (tag >= 0x9c9b && tag <= 0x9c9f) val = new TextDecoder('utf-16le').decode(d).replace(/\0+$/, '');
        else if (tag === 0x9286) val = (asc(d, 0, 7) === 'UNICODE' ? new TextDecoder(le ? 'utf-16le' : 'utf-16be').decode(d.subarray(8)) : bytesToText(d.subarray(8))).replace(/\0+$/, '');
        else if (type === 7 && cnt > 4 && cnt < 2000 && printableRatio(latin1(d)) > 0.9) val = latin1(d);
        if (val && val.trim()) tags.push({ name: TIFF_TAGS[tag] || 'タグ 0x' + tag.toString(16), val: val.trim() });
      }
      if (kind === 'ifd0') walk(r32(p + 2 + n * 12), 'ifd1');
    };
    walk(r32(base + 4), 'ifd0');
  } catch (e) { }
  let pos = null;
  if (gps[2] != null && gps[4] != null) pos = { lat: gps[2] * (gps[1] === 'S' ? -1 : 1), lon: gps[4] * (gps[3] === 'W' ? -1 : 1) };
  return { tags, gps: pos };
}
function parseJPEG(b) {
  const r = { comments: [], exif: null, xmp: null, end: null };
  let off = 2;
  while (off + 4 <= b.length) {
    if (b[off] !== 0xff) break;
    const m = b[off + 1];
    if (m === 0xff) { off++; continue; }
    if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { off += 2; continue; }
    if (m === 0xd9) { r.end = off + 2; break; }
    const len = u16be(b, off + 2), s = off + 4, e = off + 2 + len;
    if (e > b.length) break;
    if (m === 0xfe) r.comments.push(bytesToText(b.subarray(s, e)));
    if (m === 0xe1 && asc(b, s, 6) === 'Exif\0\0') r.exif = parseTIFF(b, s + 6, e);
    else if (m === 0xe1 && asc(b, s, 20).startsWith('http://ns.adobe.com/')) r.xmp = bytesToText(b.subarray(s, e));
    off = e;
    if (m === 0xda) {
      let p = off;
      while (p + 1 < b.length) { if (b[p] === 0xff) { const n = b[p + 1]; if (n === 0 || (n >= 0xd0 && n <= 0xd7)) { p += 2; continue; } if (n === 0xff) { p++; continue; } break; } p++; }
      off = p;
    }
  }
  return r;
}
function parseZip(b) {
  const r = { entries: [], comment: '', end: null };
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (b[i] === 0x50 && u32le(b, i) === 0x06054b50) { eocd = i; break; }
  if (eocd >= 0) {
    const n = u16le(b, eocd + 10), cd = u32le(b, eocd + 16), cl = u16le(b, eocd + 20);
    r.comment = bytesToText(b.subarray(eocd + 22, eocd + 22 + cl)); r.end = eocd + 22 + cl;
    let p = cd;
    for (let k = 0; k < n && p + 46 <= b.length && u32le(b, p) === 0x02014b50; k++) {
      const nl = u16le(b, p + 28), el = u16le(b, p + 30), cml = u16le(b, p + 32), lho = u32le(b, p + 42);
      const ent = { name: bytesToText(b.subarray(p + 46, p + 46 + nl)), flags: u16le(b, p + 8), method: u16le(b, p + 10), csize: u32le(b, p + 20), usize: u32le(b, p + 24), comment: bytesToText(b.subarray(p + 46 + nl + el, p + 46 + nl + el + cml)) };
      if (lho + 30 <= b.length && u32le(b, lho) === 0x04034b50) ent.dataOff = lho + 30 + u16le(b, lho + 26) + u16le(b, lho + 28);
      r.entries.push(ent); p += 46 + nl + el + cml;
    }
  }
  if (!r.entries.length || r.entries.some(e => e.dataOff == null)) {
    r.entries = []; let p = 0;
    while (p + 30 <= b.length && u32le(b, p) === 0x04034b50 && r.entries.length < 500) {
      const nl = u16le(b, p + 26), el = u16le(b, p + 28);
      const ent = { name: bytesToText(b.subarray(p + 30, p + 30 + nl)), flags: u16le(b, p + 6), method: u16le(b, p + 8), csize: u32le(b, p + 18), usize: u32le(b, p + 22), dataOff: p + 30 + nl + el, comment: '' };
      r.entries.push(ent);
      if ((ent.flags & 8) && !ent.csize) break;
      p = ent.dataOff + ent.csize;
    }
  }
  r.entries.forEach(e => { e.encrypted = !!(e.flags & 1); e.dir = e.name.endsWith('/'); });
  return r;
}
async function inflate(data, fmt) {
  if (typeof DecompressionStream === 'undefined') return null;
  const ds = new DecompressionStream(fmt), w = ds.writable.getWriter();
  w.write(data).catch(() => { }); w.close().catch(() => { });
  const rd = ds.readable.getReader(), parts = []; let tot = 0;
  try { for (; ;) { const { done, value } = await rd.read(); if (done) break; parts.push(value); tot += value.length; if (tot > 50e6) { rd.cancel().catch(() => { }); break; } } }
  catch (e) { if (!parts.length) return null; }
  const out = new Uint8Array(tot); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function zipExtract(b, e) {
  if (e.encrypted || e.dir || e.dataOff == null) return null;
  const d = b.subarray(e.dataOff, e.dataOff + e.csize);
  if (e.method === 0) return d;
  if (e.method === 8) return inflate(d, 'deflate-raw');
  return null;
}
function typeEnd(b, t) {
  if (!t) return null;
  if (t.n === 'PNG画像') return parsePNG(b).end;
  if (t.n === 'JPEG画像') return parseJPEG(b).end;
  if (t.n.startsWith('ZIP')) return parseZip(b).end;
  if (t.n === 'PDF') { const s = latin1(b.subarray(Math.max(0, b.length - 4096))); const i = s.lastIndexOf('%%EOF'); if (i < 0) return null; let e = b.length - s.length + i + 5; while (e < b.length && (b[e] === 10 || b[e] === 13)) e++; return e; }
  return null;
}
async function pdfStreams(b) {
  const s = latin1(b), out = []; const re = /stream\r?\n/g; let m;
  while ((m = re.exec(s)) && out.length < 300) {
    const st = m.index + m[0].length, en = s.indexOf('endstream', st); if (en < 0) break;
    const dict = s.slice(Math.max(0, m.index - 300), m.index);
    const raw = b.subarray(st, en);
    const d = /FlateDecode/.test(dict.slice(dict.lastIndexOf('<<'))) ? await inflate(raw, 'deflate') : raw;
    if (d && d.length) out.push(d);
    re.lastIndex = en;
  }
  return out;
}
function extractStrings(b, min = 4, cap = 20000) {
  const out = []; let st = -1;
  for (let i = 0; i <= b.length; i++) {
    const c = b[i], ok = i < b.length && ((c >= 32 && c < 127) || c === 9);
    if (ok) { if (st < 0) st = i; } else { if (st >= 0 && i - st >= min) { out.push({ off: st, s: latin1(b.subarray(st, i)) }); if (out.length >= cap) break; } st = -1; }
  }
  // UTF-16（Windowsでよく使う文字の形）
  st = -1;
  for (let i = 0; i + 1 <= b.length && out.length < cap; i += 2) {
    const ok = i + 1 < b.length && b[i + 1] === 0 && b[i] >= 32 && b[i] < 127;
    if (ok) { if (st < 0) st = i; } else { if (st >= 0 && (i - st) / 2 >= min) out.push({ off: st, s: new TextDecoder('utf-16le').decode(b.subarray(st, i)), u16: true }); st = -1; }
  }
  return out;
}
function xorPrefixScan(b, extra) {
  const pre = ['flag{', 'FLAG{', 'ctf{', 'CTF{', 'picoCTF{', 'ctf4b{', 'Flag{']; if (extra) pre.push(extra + '{');
  const found = [], seen = new Set();
  for (const p of pre) {
    const pb = toBytes(p);
    for (let i = 0; i + pb.length < b.length && found.length < 20; i++) {
      const k = b[i] ^ pb[0]; if (!k) continue;
      let j = 1; while (j < pb.length && (b[i + j] ^ k) === pb[j]) j++;
      if (j < pb.length) continue;
      let e = i + j; while (e < b.length && e - i < 300 && (b[e] ^ k) !== 0x7d) e++;
      if (e >= b.length || (b[e] ^ k) !== 0x7d) continue;
      const f = latin1(Uint8Array.from(b.subarray(i, e + 1), x => x ^ k));
      if (printableRatio(f) < 1 || seen.has(f)) continue;
      seen.add(f); found.push({ flag: f, key: k });
    }
  }
  return found;
}
function lsbVariants(px, w, h, maxBytes = 1 << 18) {
  let alphaUsed = false; for (let i = 3; i < px.length; i += 4) if (px[i] !== 255) { alphaUsed = true; break; }
  const CH = { RGB: [0, 1, 2], BGR: [2, 1, 0], R: [0], G: [1], B: [2] };
  if (alphaUsed) { CH.RGBA = [0, 1, 2, 3]; CH.A = [3]; }
  const res = [], N = w * h;
  for (const name in CH) for (const bit of [0, 1]) for (const msb of [true, false]) {
    const ch = CH[name], nb = Math.min(maxBytes, Math.floor(N * ch.length / 8)), out = new Uint8Array(nb);
    let idx = 0, cur = 0, bi = 0;
    outer: for (let p = 0; p < N; p++) for (const c of ch) {
      const v = (px[p * 4 + c] >> bit) & 1;
      if (msb) cur = (cur << 1) | v; else cur |= v << bi;
      if (++bi === 8) { out[idx++] = cur; cur = 0; bi = 0; if (idx >= nb) break outer; }
    }
    res.push({ name: `${name} の 第${bit}ビット（${msb ? '上の桁から' : '下の桁から'}）`, bytes: out });
  }
  return res;
}
function hexdump(b, start = 0, len = 512) {
  const lines = [];
  for (let o = start; o < Math.min(b.length, start + len); o += 16) {
    const row = b.subarray(o, Math.min(o + 16, b.length));
    const hx = [...row].map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    lines.push(o.toString(16).padStart(8, '0') + '  ' + hx + '  |' + [...row].map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join('') + '|');
  }
  return lines.join('\n');
}
function hintsFor(t, rep) {
  const H = [];
  const n = t ? t.n : '';
  if (n.startsWith('ZIP') && rep.zip && rep.zip.entries.some(e => e.encrypted)) H.push('パスワード付きZIPです。John the Ripper（パスワードを総当たりするツール）の zip2john や、fcrackzip で辞書攻撃（よくあるパスワードを順番に試すこと）をしてみよう。問題文や画像の中にパスワードのヒントがあることも多いです。');
  if (n === 'JPEG画像') H.push('JPEGは steghide（画像にデータを隠すツール）がよく使われます。パソコンで「steghide extract -sf ファイル名」を実行して、パスワードを聞かれたら何も入れずにEnterを押してみよう。');
  if (n === 'PNG画像' || n === 'BMP画像') H.push('下の「ビットプレーン」で R/G/B の0ビット目を順番に見てみよう。文字やQRコードが浮かんでくることがあります。パソコンなら zsteg（PNGの隠しデータを探すツール）も便利です。');
  if (/画像/.test(n)) H.push('画像の明るさやコントラストを極端に変えると、うっすら書かれた文字が見えることがあります。');
  if (/音声/.test(n)) H.push('音声ファイルは Audacity や Sonic Visualiser で「スペクトログラム」（音を色の絵として表示する方法）を見てみよう。文字が描かれていたり、モールス信号やSSTV（音で画像を送る方式）のことがあります。');
  if (/pcap/.test(n)) H.push('通信の記録です。Wireshark（通信を見るツール）で開いて、「統計 → プロトコル階層」で何の通信が多いか見よう。「ファイル → オブジェクトをエクスポート → HTTP」で送られたファイルを取り出せます。');
  if (/実行ファイル|Java/.test(n)) H.push('プログラムのファイルです。Ghidra（機械語を読める形に戻すツール）で開いて main 関数を読もう。Linuxなら ltrace / strace で、動かしながら何をしているか見る方法もあります。');
  if (n === 'PDF') H.push('PDFは黒塗りの下に文字が残っていることがあります。全部選択してコピーし、メモ帳に貼ってみよう。');
  if (n === 'SQLiteデータベース') H.push('DB Browser for SQLite で開いて、全部のテーブル（表）を見てみよう。');
  if (!t) H.push('種類がわかりませんでした。ファイルの先頭のマジックナンバー（ファイルの種類を表す最初の数バイト）が壊されているか、XORなどで全体が暗号化されているかもしれません。下の16進ダンプで先頭を見てみよう。');
  if (rep.extMismatch) H.push('拡張子（ファイル名の最後の .png など）と中身がちがいます。拡張子を正しいものに変えると開けるかもしれません。');
  return H;
}

// ---- 全体の解析 ----
const STR_CAND = /^[A-Za-z0-9+/=_\-]{12,4000}$|^[01\s]{16,}$|%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#\d+;|^[.\-\s\/]{10,}$/;
const TWEAKS = [...Array.from({ length: 25 }, (_, i) => ['シーザー+' + (i + 1) + (i === 12 ? '(ROT13)' : ''), s => caesar(s, i + 1)]), ['ROT47', rot47], ['逆順', reverse], ['Atbash', atbash]];

function addFlag(ctx, flag, where, how) {
  flag = flag.trim(); if (!flag) return;
  let f = ctx.flags.get(flag); if (!f) { f = { flag, ways: [] }; ctx.flags.set(flag, f); }
  const w = where + ' ／ ' + how; if (!f.ways.includes(w) && f.ways.length < 6) f.ways.push(w);
}
function searchText(ctx, text, where, how) {
  const re = knownRe(ctx.extra, 'gi'); re.lastIndex = 0;
  const reFull = new RegExp(re.source + '[^{}\\n\\r]{0,300}\\}', 'gi');
  for (const m of text.matchAll(reFull)) addFlag(ctx, m[0], where, how);
  if (ctx.like.size < 30) for (const m of text.matchAll(new RegExp(FLAG_SHAPE.source, 'g'))) { if (!knownRe(ctx.extra).test(m[0]) && printableRatio(m[0]) === 1) ctx.like.set(m[0], where); if (ctx.like.size >= 30) break; }
}
function deepText(ctx, s, where, label) {
  // 1つの文字列を、そのまま・ずらし・自動解析でチェック
  searchText(ctx, s, where, label);
  const kr = knownRe(ctx.extra);
  if (s.includes('{') && s.includes('}')) for (const [nm, f] of TWEAKS) { const t = f(s); if (kr.test(t)) searchText(ctx, t, where, label + ' → ' + nm); }
  const c = s.trim();
  if (c.length >= 8 && c.length <= 6000 && STR_CAND.test(c) && ctx.magicCount++ < 1500) {
    for (const r of magic(c, 3, ctx.extra)) if (r.flag === 2 && r.path.length) searchText(ctx, r.text, where, label + ' → ' + r.path.join(' → '));
  }
}
const tick = () => new Promise(r => setTimeout(r, 0));

async function analyzeBytes(b, name, ctx, depth = 0, where = '', quiet = false) {
  where = where || name;
  const rep = { name, where, size: b.length, bytes: b, depth };
  if (!quiet) ctx.reports.push(rep);
  ctx.progress && ctx.progress(`${where} を調べています…`); await tick();
  const t = rep.type = detectType(b);
  const ext = (name.match(/\.([A-Za-z0-9]+)$/) || [, ''])[1].toLowerCase();
  if (t && !t.text && ext && !t.ext.includes(ext)) rep.extMismatch = `拡張子は .${ext} なのに、中身は「${t.n}」です`;

  // 1. そのまま・UTF-16・逆さま
  const raw = latin1(b);
  searchText(ctx, raw, where, 'ファイルにそのまま書いてあった');
  searchText(ctx, new TextDecoder('utf-16le').decode(b), where, 'UTF-16（2バイトずつの文字）で書いてあった');
  searchText(ctx, raw.split('').reverse().join(''), where, '逆さまに書いてあった');
  if (t && t.text) searchText(ctx, bytesToText(b), where, 'テキストとして読んだ');
  // 2. strings
  rep.strings = extractStrings(b);
  for (const s of rep.strings) deepText(ctx, s.s, where, `文字列（${s.off.toString(16)}番地）`);
  if (t && t.text && b.length < 200000) deepText(ctx, bytesToText(b).trim(), where, 'ファイル全体');
  await tick();
  // 3. XOR
  if (b.length <= 4e6) for (const x of xorPrefixScan(b, ctx.extra)) addFlag(ctx, x.flag, where, `全体が XOR されていた（鍵 0x${x.key.toString(16).padStart(2, '0')}）`);

  const nested = new Map(); // off -> {bytes, label}
  const texts = [];
  // 4. 種類ごと
  if (t && t.n === 'PNG画像') {
    const p = rep.png = parsePNG(b);
    p.texts.forEach(x => texts.push([x.key + ' (PNGのテキスト)', x.val]));
    for (const z of p.ztxt) { const d = await inflate(z.data, 'deflate'); if (d) { const v = bytesToText(d); p.texts.push({ key: z.key + '（圧縮されていた）', val: v }); texts.push([z.key + ' (PNGの圧縮テキスト)', v]); } }
    if (p.exif) { rep.exif = p.exif; p.exif.tags.forEach(x => texts.push([x.name, x.val])); }
    if (p.ihdr && !p.ihdr.crcOk) { ctx.progress && ctx.progress('画像の正しい大きさを計算しています…'); await tick(); rep.ihdrFix = fixIHDR(b, p.ihdr); }
    if (p.chunks.some(c => c.type === 'IDAT')) rep.image = 'image/png';
  }
  if (t && t.n === 'JPEG画像') {
    const j = rep.jpeg = parseJPEG(b);
    j.comments.forEach(c => texts.push(['JPEGのコメント', c]));
    if (j.exif) { rep.exif = j.exif; j.exif.tags.forEach(x => texts.push([x.name, x.val])); }
    if (j.xmp) texts.push(['XMP（画像の追加情報）', j.xmp]);
    rep.image = 'image/jpeg';
  }
  if (t && /GIF|BMP|WebP/.test(t.n)) rep.image = t.n.startsWith('GIF') ? 'image/gif' : t.n.startsWith('BMP') ? 'image/bmp' : 'image/webp';
  // 先頭が壊れたPNG/JPEGを直す
  if (!t || !/画像/.test(t.n)) {
    if (asc(b, 12, 4) === 'IHDR' && !startsHex(b, 0, '89504e470d0a1a0a')) { const f = b.slice(); f.set(hexDec('89504e470d0a1a0a'), 0); rep.headerFix = 'PNG'; nested.set(-1, { bytes: f, label: '先頭を直したPNG画像', name: 'fixed.png' }); }
    else if (/JFIF|Exif/.test(asc(b, 6, 4)) && !startsHex(b, 0, 'ffd8')) { const f = b.slice(); f[0] = 0xff; f[1] = 0xd8; rep.headerFix = 'JPEG'; nested.set(-1, { bytes: f, label: '先頭を直したJPEG画像', name: 'fixed.jpg' }); }
  }
  if (t && t.n.startsWith('ZIP')) {
    const z = rep.zip = parseZip(b);
    if (z.comment) texts.push(['ZIPのコメント', z.comment]);
    z.entries.forEach(e => { if (e.comment) texts.push([e.name + ' のコメント', e.comment]); });
    if (depth < 4) for (const e of z.entries.slice(0, 80)) {
      if (e.encrypted) continue;
      const d = await zipExtract(b, e); e.ok = !!d;
      if (d && d.length) nested.set('zip:' + e.name, { bytes: d, label: 'ZIPの中の ' + e.name, name: e.name.split('/').pop() });
    }
  }
  if (t && t.n === 'GZIP圧縮' && depth < 4) { const d = await inflate(b, 'gzip'); if (d) { const fn = name.replace(/\.t?gz$/i, '') || 'gunzip'; nested.set('gz', { bytes: d, label: 'GZIPを解凍した中身', name: /\.tgz$/i.test(name) ? fn + '.tar' : fn }); } }
  if (t && t.n === 'TARまとめファイル' && depth < 4) {
    let p = 0; rep.tar = [];
    while (p + 512 <= b.length && b[p]) { const nm = asc(b, p, 100).replace(/\0.*$/, ''), sz = parseInt(asc(b, p + 124, 12).replace(/\0.*$/, '').trim() || '0', 8) || 0; rep.tar.push({ name: nm, size: sz }); if (sz && asc(b, p + 156, 1) !== '5') nested.set('tar:' + nm, { bytes: b.subarray(p + 512, p + 512 + sz), label: 'TARの中の ' + nm, name: nm.split('/').pop() }); p += 512 + Math.ceil(sz / 512) * 512; if (rep.tar.length > 200) break; }
  }
  if (t && t.n === 'PDF') {
    const st = await pdfStreams(b); rep.pdfStreams = st.length;
    for (let i = 0; i < st.length; i++) await analyzeBytes(st[i], `stream${i}`, ctx, depth + 1, `${where} の中のデータ${i + 1}`, true);
  }
  for (const [k, v] of texts) deepText(ctx, v, where, k);
  rep.texts = texts;
  // 5. 後ろにくっついたデータ・中に隠れたファイル
  const end = typeEnd(b, t);
  if (end && end < b.length) { rep.trailing = { off: end, len: b.length - end }; if (depth < 4) nested.set(end, { bytes: b.subarray(end), label: `ファイルの後ろにくっついていたデータ（${end.toString(16)}番地から）`, name: 'trailing.bin' }); }
  rep.embedded = scanEmbedded(b, t).filter(h => !(t && t.n === 'JPEG画像' && h.n === 'JPEG画像' && rep.jpeg && rep.jpeg.end && h.off < rep.jpeg.end));
  if (depth < 4) for (const h of rep.embedded.slice(0, 20)) {
    if (nested.has(h.off)) { nested.get(h.off).label += `（${h.n}）`; continue; }
    const sub = b.subarray(h.off), e2 = typeEnd(sub, { n: h.n });
    nested.set(h.off, { bytes: e2 ? sub.subarray(0, e2) : sub, label: `${h.off.toString(16)}番地に隠れていた${h.n}`, name: 'hidden.' + ({ 'PNG画像': 'png', 'JPEG画像': 'jpg', 'ZIP圧縮': 'zip', 'GIF画像': 'gif', 'PDF': 'pdf', 'GZIP圧縮': 'gz' }[h.n] || 'bin') });
  }
  if (rep.ihdrFix) nested.set('ihdr', { bytes: rep.ihdrFix.bytes, label: `大きさを直したPNG（${rep.ihdrFix.w}×${rep.ihdrFix.h}）`, name: 'fixed.png' });
  rep.hints = hintsFor(t, rep);
  for (const [, v] of nested) {
    if (ctx.reports.length > 60 || ctx.total > 200e6) break;
    ctx.total += v.bytes.length;
    await analyzeBytes(v.bytes, v.name, ctx, depth + 1, `${where} → ${v.label}`);
  }
  return rep;
}
function lsbCheck(ctx, rep, px, w, h) {
  const out = [];
  for (const v of lsbVariants(px, w, h)) {
    const s = latin1(v.bytes);
    searchText(ctx, s, rep.where, 'LSB（色の一番下のビットに隠す方法）: ' + v.name);
    const head = s.match(/^[\x20-\x7e\t\r\n]{8,}/);
    if (head) { out.push({ name: v.name, text: head[0].slice(0, 2000) }); deepText(ctx, head[0].slice(0, 6000), rep.where, 'LSB: ' + v.name); }
  }
  return out;
}
function cleanLike(ctx) {
  const kr = knownRe(ctx.extra);
  for (const k of [...ctx.like.keys()]) if (TWEAKS.some(([, f]) => kr.test(f(k)))) ctx.like.delete(k);
}
async function analyzeFile(b, name, extra, progress) {
  const ctx = { flags: new Map(), like: new Map(), reports: [], extra, progress, magicCount: 0, total: b.length };
  await analyzeBytes(b, name, ctx);
  return ctx;
}
/*FCORE_END*/
if (typeof module !== 'undefined') module.exports = { cleanLike, analyzeFile, lsbCheck, lsbVariants, parsePNG, parseJPEG, parseZip, crc32, fixIHDR, hexdump, extractStrings, xorPrefixScan, detectType };
