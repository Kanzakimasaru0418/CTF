/*CORE_START*/
const TE = new TextEncoder();
const TD = new TextDecoder('utf-8', { fatal: true });

function toBytes(s) { return TE.encode(s); }
function latin1(b) { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return s; }
function bytesToText(b) { try { return TD.decode(b); } catch (e) { return latin1(b); } }
function asBytes(x) { return typeof x === 'string' ? toBytes(x) : x; }
function asText(x) { return typeof x === 'string' ? x : bytesToText(x); }

function isGood(c) {
  return (c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 ||
    (c >= 0x3000 && c <= 0x9fff) || (c >= 0xff00 && c <= 0xffef);
}
function printableRatio(s) {
  if (!s.length) return 0;
  let g = 0; for (const ch of s) if (isGood(ch.codePointAt(0))) g++;
  return g / [...s].length;
}
function showable(s) {
  let o = '';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (isGood(c) || c > 0x9fff) o += ch;
    else o += '\\x' + c.toString(16).padStart(2, '0');
  }
  return o;
}

// ---- hex ----
function hexClean(s) { return s.replace(/0x|\\x|[\s:,]/gi, ''); }
function hexDec(s) {
  const h = hexClean(s);
  if (!/^[0-9a-f]*$/i.test(h) || h.length % 2) throw new Error('16進数として読めません');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function hexEnc(x) { return [...asBytes(x)].map(b => b.toString(16).padStart(2, '0')).join(''); }

// ---- base64 ----
function b64Dec(s) {
  let t = s.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(t) || t.length % 4 === 1) throw new Error('Base64として読めません');
  while (t.length % 4) t += '=';
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64Enc(x) {
  const b = asBytes(x); let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

// ---- base32 ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32Dec(s) {
  const t = s.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0, val = 0; const out = [];
  for (const ch of t) {
    const i = B32.indexOf(ch); if (i < 0) throw new Error('Base32として読めません');
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; val &= (1 << bits) - 1; }
  }
  return Uint8Array.from(out);
}
function b32Enc(x) {
  const b = asBytes(x); let bits = 0, val = 0, out = '';
  for (const byte of b) {
    val = (val << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    val &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  while (out.length % 8) out += '=';
  return out;
}

// ---- bigint / base58 ----
function bigToBytes(n) {
  if (n === 0n) return new Uint8Array([0]);
  let h = n.toString(16); if (h.length % 2) h = '0' + h;
  return hexDec(h);
}
function bytesToBig(b) { return b.length ? BigInt('0x' + hexEnc(b)) : 0n; }
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58Dec(s) {
  const t = s.trim(); let n = 0n;
  for (const ch of t) { const i = B58.indexOf(ch); if (i < 0) throw new Error('Base58として読めません'); n = n * 58n + BigInt(i); }
  let lead = 0; while (lead < t.length && t[lead] === '1') lead++;
  const body = n === 0n ? new Uint8Array(0) : bigToBytes(n);
  const out = new Uint8Array(lead + body.length); out.set(body, lead); return out;
}
function b58Enc(x) {
  const b = asBytes(x); let n = bytesToBig(b), out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (let i = 0; i < b.length && b[i] === 0; i++) out = '1' + out;
  return out;
}

// ---- 2進 / 8進 / 10進 ----
function binDec(s) {
  const t = s.trim();
  let groups = /\s/.test(t) ? t.split(/\s+/) : (t.length % 8 === 0 ? t.match(/.{8}/g) : null);
  if (!groups || !groups.every(g => /^[01]{1,8}$/.test(g))) throw new Error('2進数として読めません（8桁ずつ）');
  return Uint8Array.from(groups.map(g => parseInt(g, 2)));
}
function binEnc(x) { return [...asBytes(x)].map(b => b.toString(2).padStart(8, '0')).join(' '); }
function octDec(s) {
  const g = s.trim().split(/[\s,]+/);
  if (!g.every(v => /^[0-7]{1,3}$/.test(v) && parseInt(v, 8) < 256)) throw new Error('8進数として読めません');
  return Uint8Array.from(g.map(v => parseInt(v, 8)));
}
function octEnc(x) { return [...asBytes(x)].map(b => b.toString(8).padStart(3, '0')).join(' '); }
function decDec(s) {
  const g = s.trim().split(/[\s,]+/);
  if (!g.every(v => /^\d+$/.test(v) && +v <= 0x10ffff)) throw new Error('10進数（文字コード）として読めません');
  return g.map(v => String.fromCodePoint(+v)).join('');
}
function decEnc(x) { return [...asText(x)].map(c => c.codePointAt(0)).join(' '); }

// ---- URL / HTML / Unicode ----
function urlDec(s) {
  const out = [];
  const b = toBytes(s);
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 37 && i + 2 < b.length && /^[0-9a-f]{2}$/i.test(String.fromCharCode(b[i + 1], b[i + 2]))) {
      out.push(parseInt(String.fromCharCode(b[i + 1], b[i + 2]), 16)); i += 2;
    } else out.push(b[i]);
  }
  return Uint8Array.from(out);
}
function urlEnc(x) { return [...asBytes(x)].map(b => /[A-Za-z0-9\-_.~]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0')).join(''); }
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' };
function htmlDec(s) {
  return s.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
    .replace(/&(lt|gt|amp|quot|apos|nbsp);/g, (_, n) => ENT[n]);
}
function htmlEnc(x) { return [...asText(x)].map(c => '&#' + c.codePointAt(0) + ';').join(''); }
function uniDec(s) {
  return s.replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
function uniEnc(x) { return [...asText(x)].map(c => { const n = c.codePointAt(0); return n > 0xffff ? '\\u{' + n.toString(16) + '}' : '\\u' + n.toString(16).padStart(4, '0'); }).join(''); }

// ---- モールス ----
const MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..', 0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.', '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--', '/': '-..-.', '(': '-.--.', ')': '-.--.-', ':': '---...', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '@': '.--.-.', '{': '-.--.', '}': '-.--.-' };
const MORSE_R = {}; for (const k in MORSE) if (!(MORSE[k] in MORSE_R)) MORSE_R[MORSE[k]] = k;
function morseDec(s) {
  const t = s.replace(/_/g, '-').replace(/[•·]/g, '.').trim();
  return t.split(/\s*[\/|]\s*|\s{3,}/).map(w => w.trim().split(/\s+/).map(c => c ? (MORSE_R[c] || '?') : '').join('')).join(' ');
}
function morseEnc(x) { return [...asText(x).toUpperCase()].map(c => c === ' ' ? '/' : (MORSE[c] || '?')).join(' '); }

// ---- 換字（文字の置きかえ） ----
function caesar(s, k) {
  k = ((k % 26) + 26) % 26;
  return s.replace(/[a-z]/g, c => String.fromCharCode((c.charCodeAt(0) - 97 + k) % 26 + 97))
    .replace(/[A-Z]/g, c => String.fromCharCode((c.charCodeAt(0) - 65 + k) % 26 + 65));
}
function rot13(x) { return caesar(asText(x), 13); }
function rot47(x) { return [...asText(x)].map(c => { const n = c.charCodeAt(0); return n >= 33 && n <= 126 ? String.fromCharCode(33 + (n - 33 + 47) % 94) : c; }).join(''); }
function atbash(x) {
  return asText(x).replace(/[a-z]/g, c => String.fromCharCode(219 - c.charCodeAt(0)))
    .replace(/[A-Z]/g, c => String.fromCharCode(155 - c.charCodeAt(0)));
}
function reverse(x) { return [...asText(x)].reverse().join(''); }

function vigenere(s, key, decrypt) {
  const k = key.toLowerCase().replace(/[^a-z]/g, '');
  if (!k) throw new Error('鍵はアルファベットで入れてね');
  let j = 0;
  return s.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    const sh = k.charCodeAt(j++ % k.length) - 97;
    return String.fromCharCode((c.charCodeAt(0) - base + (decrypt ? 26 - sh : sh)) % 26 + base);
  });
}

// 英語らしさ（カイ二乗：小さいほど英語っぽい）
const EN = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9, 0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074];
function englishScore(s) {
  const cnt = new Array(26).fill(0); let n = 0;
  for (const c of s.toLowerCase()) { const i = c.charCodeAt(0) - 97; if (i >= 0 && i < 26) { cnt[i]++; n++; } }
  if (!n) return Infinity;
  let chi = 0; for (let i = 0; i < 26; i++) { const e = EN[i] / 100 * n; chi += (cnt[i] - e) ** 2 / e; }
  let bonus = 0;
  const words = s.toLowerCase().match(/[a-z]+/g) || [];
  for (const w of words) if (COMMON_WORDS.has(w)) bonus += w.length;
  return chi / n - bonus / Math.max(1, n) * 10;
}
const COMMON_WORDS = new Set('the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were flag ctf quick brown fox jumps lazy dog hello world secret key password answer here'.split(' '));
function letterFreq(s) {
  const cnt = new Array(26).fill(0);
  for (const c of s.toLowerCase()) { const i = c.charCodeAt(0) - 97; if (i >= 0 && i < 26) cnt[i]++; }
  return cnt;
}

// ---- XOR ----
function xorBytes(data, key) {
  if (!key.length) throw new Error('鍵が空です');
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ key[i % key.length];
  return out;
}
function parseByInput(s, fmt) {
  if (fmt === 'hex') return hexDec(s);
  if (fmt === 'b64') return b64Dec(s);
  if (fmt === 'dec') return Uint8Array.from(s.trim().split(/[\s,]+/).map(v => { const n = +v; if (!(n >= 0 && n < 256)) throw new Error('0〜255の数を入れてね'); return n; }));
  return toBytes(s);
}

// ---- MD5（ブラウザに標準でないので自前） ----
function md5(input) {
  const bytes = asBytes(input);
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const K = new Uint32Array(64); for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296);
  const len = bytes.length, nb = ((len + 8) >> 6) + 1;
  const buf = new Uint8Array(nb * 64); buf.set(bytes); buf[len] = 0x80;
  const dv = new DataView(buf.buffer); const bl = len * 8;
  dv.setUint32(buf.length - 8, bl >>> 0, true); dv.setUint32(buf.length - 4, Math.floor(bl / 4294967296), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < buf.length; off += 64) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + dv.getUint32(off + g * 4, true)) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << S[i]) | (F >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const o = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((v, i) => o.setUint32(i * 4, v, true));
  return hexEnc(new Uint8Array(o.buffer));
}
async function shaHex(alg, input) {
  const d = await crypto.subtle.digest(alg, asBytes(input));
  return hexEnc(new Uint8Array(d));
}
function identifyHash(h) {
  const t = h.trim();
  if (/^\$2[abxy]?\$\d\d\$/.test(t)) return ['bcrypt（ブルートフォースにとても強い）'];
  if (/^\$1\$/.test(t)) return ['md5crypt（Linuxの古いパスワード形式）'];
  if (/^\$5\$/.test(t)) return ['sha256crypt（Linuxのパスワード形式）'];
  if (/^\$6\$/.test(t)) return ['sha512crypt（今のLinuxで多いパスワード形式）'];
  if (/^\$argon2/.test(t)) return ['Argon2（最新のパスワード用ハッシュ）'];
  if (/^\$y\$/.test(t)) return ['yescrypt（新しいLinuxのパスワード形式）'];
  if (!/^[0-9a-f]+$/i.test(t)) return [];
  const m = { 8: ['CRC32'], 16: ['MySQL3 / CRC64'], 32: ['MD5', 'NTLM（Windowsのパスワード）', 'MD4'], 40: ['SHA-1', 'RIPEMD-160'], 56: ['SHA-224', 'SHA3-224'], 64: ['SHA-256', 'SHA3-256'], 96: ['SHA-384', 'SHA3-384'], 128: ['SHA-512', 'SHA3-512', 'Whirlpool'] };
  return m[t.length] || [];
}
const COMMON_PW = ['password', '123456', '12345678', '123456789', '1234', '12345', 'qwerty', 'abc123', 'password1', 'admin', 'root', 'toor', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'iloveyou', 'sunshine', 'princess', 'football', 'baseball', 'shadow', 'superman', 'michael', 'secret', 'test', 'guest', 'hello', 'flag', 'ctf', 'pass', 'pass123', 'admin123', 'qwerty123', '111111', '000000', '654321', '666666', '123123', '1q2w3e4r', 'zaq12wsx', 'passw0rd', 'p@ssw0rd', 'trustno1', 'starwars', 'pokemon', 'hacker', 'hunter2', 'changeme', 'default', 'user', 'login', 'access', 'love', 'a', 'abc', 'abcdef', 'apple', 'banana', 'cat', 'dog', 'nara', 'kosen', 'japan', 'tokyo', 'osaka', 'yes', 'no', 'ok', '0', '1', '2', 'hogehoge', 'hoge', 'fuga', 'piyo', 'foo', 'bar', 'foobar', 'helloworld', 'hello world', ''];

// ---- 自動解析（Magic） ----
const DECODERS = [
  { name: 'Base64', test: s => /^[A-Za-z0-9+/_\-\s]+=*\s*$/.test(s) && s.replace(/\s/g, '').length >= 4, fn: b64Dec },
  { name: 'Base32', test: s => /^[A-Z2-7\s]+=*\s*$/i.test(s) && s.replace(/\s/g, '').length >= 8, fn: b32Dec },
  { name: 'Base58', test: s => /^[1-9A-HJ-NP-Za-km-z]{6,}$/.test(s.trim()), fn: b58Dec },
  { name: '16進数(Hex)', test: s => { const h = hexClean(s); return h.length >= 4 && h.length % 2 === 0 && /^[0-9a-f]+$/i.test(h); }, fn: hexDec },
  { name: '2進数', test: s => /^[01\s]+$/.test(s) && s.replace(/\s/g, '').length >= 8, fn: binDec },
  { name: '8進数', test: s => /^[0-7]{2,3}([\s,]+[0-7]{2,3})+\s*$/.test(s.trim()), fn: octDec },
  { name: '10進数(文字コード)', test: s => /^\d{2,6}([\s,]+\d{2,6})+$/.test(s.trim()), fn: decDec },
  { name: 'URLデコード', test: s => /%[0-9a-f]{2}/i.test(s), fn: urlDec },
  { name: 'HTMLエンティティ', test: s => /&(#\d+|#x[0-9a-f]+|lt|gt|amp|quot);/i.test(s), fn: htmlDec },
  { name: 'Unicodeエスケープ', test: s => /\\u[0-9a-f]{4}|\\x[0-9a-f]{2}|\\u\{/i.test(s), fn: uniDec },
  { name: 'モールス信号', test: s => /^[.\-_\s\/|•·]+$/.test(s.trim()) && /[.\-_]/.test(s), fn: morseDec },
];
const FLAG_PREFIXES = ['flag', 'ctf', 'picoctf', 'ctf4b', 'ductf', 'htb', 'thm', 'seccon', 'tsgctf', 'wanictf', 'ricerca', 'kosenctf', 'nitic', 'cpctf', 'tkbctf', 'alpacahack', 'lactf', 'uiuctf', 'csawctf', 'hkcert', 'actf', 'dice', 'hsctf', 'idek', 'sekai', 'irisctf', 'bctf', 'osu'];
function escRe(t) { return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function knownRe(extra, flags = 'i') { const p = FLAG_PREFIXES.slice(); if (extra) p.unshift(escRe(extra)); return new RegExp('(?:' + p.join('|') + ')\\{', flags); }
const FLAG_KNOWN = knownRe('');
const FLAG_SHAPE = /[A-Za-z0-9_]{2,24}\{[^{}\n]{1,300}\}/;

function magic(input, maxDepth = 3, extraFlag) {
  const known = knownRe(extraFlag);
  const start = { text: input, path: [], score: printableRatio(input) };
  const all = [start], seen = new Set([input]), queue = [start];
  while (queue.length && all.length < 300) {
    const it = queue.shift();
    if (it.path.length >= maxDepth) continue;
    for (const d of DECODERS) {
      if (!d.test(it.text)) continue;
      let out; try { out = asText(d.fn(it.text)); } catch (e) { continue; }
      if (!out || seen.has(out) || out === it.text) continue;
      seen.add(out);
      const score = printableRatio(out);
      if (score < 0.85) continue;
      const node = { text: out, path: [...it.path, d.name], score };
      all.push(node); queue.push(node);
    }
  }
  const tweaks = [];
  for (let k = 1; k < 26; k++) tweaks.push(['シーザー+' + k + (k === 13 ? '(ROT13)' : ''), s => caesar(s, k)]);
  tweaks.push(['ROT47', rot47], ['逆順', reverse], ['Atbash', atbash]);
  const results = [];
  for (const n of all) {
    const isFlag = known.test(n.text) ? 2 : (FLAG_SHAPE.test(n.text) ? 1 : 0);
    if (n.path.length) results.push({ ...n, flag: isFlag });
    else if (isFlag) results.push({ ...n, flag: isFlag });
    for (const [nm, f] of tweaks) {
      const t = f(n.text);
      if (t !== n.text && known.test(t)) results.push({ text: t, path: [...n.path, nm], score: printableRatio(t), flag: 2 });
    }
  }
  const uniq = new Map();
  for (const r of results) if (!uniq.has(r.text) || uniq.get(r.text).path.length > r.path.length) uniq.set(r.text, r);
  return [...uniq.values()].sort((a, b) => b.flag - a.flag || b.score - a.score || a.path.length - b.path.length);
}
/*CORE_END*/
if (typeof module !== 'undefined') module.exports = { toBytes, bytesToText, hexDec, hexEnc, b64Dec, b64Enc, b32Dec, b32Enc, b58Dec, b58Enc, binDec, binEnc, octDec, octEnc, decDec, decEnc, urlDec, urlEnc, htmlDec, htmlEnc, uniDec, uniEnc, morseDec, morseEnc, caesar, rot13, rot47, atbash, reverse, vigenere, englishScore, xorBytes, md5, shaHex, identifyHash, magic, bigToBytes, asText, knownRe, FLAG_SHAPE, latin1, printableRatio };
