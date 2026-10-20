// Parse untrusted adapter text as syntax only. Never require/evaluate the adapter.
const fs = require('node:fs');
const path = require('node:path');
const acorn = require('../flare-scan/contracts/firelight-core/node_modules/acorn');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const ast = acorn.parse(input.source, {ecmaVersion:2020, sourceType:'script', locations:true, allowReturnOutsideFunction:true});
const definitions = new Map();
function walk(node, fn) {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) { for (const n of node) walk(n,fn); return; }
  if (node.type) fn(node);
  for (const [k,v] of Object.entries(node)) if (!['loc','start','end'].includes(k)) walk(v,fn);
}
walk(ast,n=>{
  if (n.type==='VariableDeclarator' && n.id.type==='Identifier') definitions.set(n.id.name,n.init);
  if (n.type==='FunctionDeclaration' && n.id) definitions.set(n.id.name,n.body);
});
const key=n=>n?.type==='Identifier'?n.name:n?.type==='Literal'?String(n.value):null;
const roots=[];
walk(ast,n=>{if (n.type==='Property' && input.chainKeys.includes(key(n.key))) roots.push(n.value);});
// Single-chain adapters may keep all addresses in file-level declarations.
// Only traverse identifiers actually referenced by the matched chain subtree.
const out=[], visited=new Set();
function collect(n, trail=[], depth=0) {
  if (!n || depth>40) return;
  if (Array.isArray(n)) {for(const v of n) collect(v,trail,depth+1);return;}
  if (typeof n!=='object') return;
  if(n.type==='Identifier' && definitions.has(n.name) && !visited.has(n.name)) {
    visited.add(n.name);collect(definitions.get(n.name),[...trail,n.name],depth+1);return;
  }
  if(n.type==='Property') {collect(n.value,[...trail,key(n.key)||'?'],depth+1);return;}
  if(n.type==='Literal' && typeof n.value==='string' && /^0x[0-9a-fA-F]{40}$/.test(n.value)) {
    if (trail.some(p=>/blacklist|exclude|tokens?$|tokenaddress|assetaddress|stakingToken|rewardToken/i.test(p))) return;
    out.push({address:n.value, line:n.loc.start.line, context:trail.join('.'), association:'adapter chain-scoped reference; business role requires review'});return;
  }
  if(n.type==='MemberExpression') {collect(n.object,trail,depth+1);return;}
  for(const [k,v] of Object.entries(n)) if(!['loc','start','end','key','id'].includes(k)) collect(v,trail,depth+1);
}
for(const root of roots) collect(root);
const seen=new Set();
process.stdout.write(JSON.stringify({matchedChainScopes:roots.length, addresses:out.filter(x=>!seen.has(x.address.toLowerCase())&&seen.add(x.address.toLowerCase()))}));
