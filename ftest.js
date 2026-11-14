const fs=require('fs');const F=require('./fcore.js');
const {PNG}=(()=>{try{return require('pngjs')}catch(e){return {}}})();
(async()=>{
for (const f of fs.readdirSync('samples').sort()){
  const b=new Uint8Array(fs.readFileSync('samples/'+f));
  const t0=Date.now();const ctx=await F.analyzeFile(b,f,'');
  console.log('\n##',f,Date.now()-t0+'ms','reports:',ctx.reports.length, 'type:',ctx.reports[0].type&&ctx.reports[0].type.n, ctx.reports[0].extMismatch||'');
  for(const [k,v] of ctx.flags) console.log('  FLAG',k,'|',v.ways[0]);
  if(ctx.reports[0].ihdrFix) console.log('  IHDR fix',ctx.reports[0].ihdrFix.w,ctx.reports[0].ihdrFix.h);
  if(ctx.reports[0].zip) console.log('  zip',ctx.reports[0].zip.entries.map(e=>e.name+(e.encrypted?'(鍵)':'')));
  console.log('  hints',ctx.reports[0].hints.length, 'like',[...ctx.like.keys()].slice(0,3));
}})();
