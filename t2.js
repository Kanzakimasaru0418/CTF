const c=require('./core.js');
for (const p of ['The quick brown fox','Hello world this is a secret message','attack at dawn','flag is caesar']) {
 for (const k of [3,7,19]){ const e=c.caesar(p,k); let best=null; for(let j=1;j<26;j++){const t=c.caesar(e,j);const sc=c.englishScore(t); if(!best||sc<best.sc)best={t,sc};} console.log(best.t===p?'OK':'NG',k,best.t);}
}
// xor
const d=c.xorBytes(c.toBytes('flag{xor_is_fun}'),[0x42]);console.log(c.hexEnc(d));
