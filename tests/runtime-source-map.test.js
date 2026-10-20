import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const {runtimeLocations,effectSiteId}=createRequire(import.meta.url)('../scripts/evm-source-map.cjs');
test('runtime source maps skip PUSH operands and preserve UTF8 byte spans',()=>{
  const text='// 中文\nfunction f() {}';
  const start=Buffer.byteLength('// 中文\n');
  const m=runtimeLocations('60ff5f5561000155',`0:0:-1;${start}:8:7;;:10:`,{'Vault.sol':{id:7}},{'Vault.sol':{content:text}});
  assert.equal(m.has(1),false);assert.equal(m.has(5),false);assert.equal(m.has(6),false);
  assert.equal(m.get(2).lineStart,2);assert.equal(m.get(3).start,start);assert.equal(m.get(4).length,10);
});
test('runtime source maps omit generated and invalid spans',()=>{
  const sources={'V.sol':{id:0}},contents={'V.sol':{content:'abc'}};
  const m=runtimeLocations('555555','0:1:-1;9:2:0;1:1:0',sources,contents);
  assert.equal(m.size,1);assert.equal(m.get(2).start,1);
  assert.throws(()=>runtimeLocations('__$unlinked$__','',sources,contents),/malformed/);
});
test('runtime source maps preserve compressed fields and ignore large tails beyond decoded instructions',()=>{
  const sources={'V.sol':{id:0}},contents={'V.sol':{content:'abcde'}};
  const sourceMap=`0:1:0;2:2${';invalid:map:entry'.repeat(50000)}`;
  const m=runtimeLocations('5555',sourceMap,sources,contents);
  assert.equal(m.size,2);
  assert.deepEqual([...m].map(([pc,location])=>[pc,location.start,location.length]),[[0,0,1],[1,2,2]]);
});
test('runtime source maps preserve empty trailing entries as compressed repeats',()=>{
  const m=runtimeLocations('5555','0:1:0;',{'V.sol':{id:0}},{'V.sol':{content:'abc'}});
  assert.deepEqual([...m].map(([pc,location])=>[pc,location.start,location.length]),[[0,0,1],[1,0,1]]);
});
test('source spans use an exclusive end and ignore zero-width compiler markers',()=>{
  const m=runtimeLocations('555555','0:2:0;2:0:0;2:1:0',{'V.sol':{id:0}},{'V.sol':{content:'x\ny'}});
  assert.equal(m.get(0).lineEnd,1);assert.equal(m.has(1),false);assert.equal(m.get(2).lineStart,2);
});
test('effect-site ids are deterministic across the exact source hash and UTF8 byte span',()=>{
  const crypto=createRequire(import.meta.url)('node:crypto');
  const input={bytecode:'5555',sourceMap:'0:2:0',sources:{'V.sol':{id:0}},contents:{'V.sol':{content:'ab'}}};
  const first=runtimeLocations(input.bytecode,input.sourceMap,input.sources,input.contents).get(0);
  const second=runtimeLocations(input.bytecode,input.sourceMap,input.sources,input.contents).get(0);
  assert.deepEqual(first,second);
  assert.equal(first.start,0);assert.equal(first.length,2);
  assert.equal(first.sourceSha256,crypto.createHash('sha256').update('ab','utf8').digest('hex'));
  const id=effectSiteId(first,'state_write');
  const expected=crypto.createHash('sha256').update([
    first.sourceSha256,first.file,String(first.start),String(first.length),'state_write',
  ].join('\0'),'utf8').digest('hex');
  assert.equal(id,expected);
  const changed=runtimeLocations(input.bytecode,input.sourceMap,input.sources,{'V.sol':{content:'ac'}}).get(0);
  assert.notEqual(changed.sourceSha256,first.sourceSha256);
  assert.notEqual(effectSiteId(changed,'state_write'),id);
  assert.notEqual(effectSiteId(first,'state_write'),effectSiteId(first,'external_call'));
  assert.notEqual(effectSiteId(first,'state_write'),effectSiteId(first,'selfdestruct'));
  assert.throws(()=>effectSiteId(first,'unknown'),/effect site requires/);
});
