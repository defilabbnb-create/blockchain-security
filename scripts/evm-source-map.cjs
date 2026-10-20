const crypto = require('node:crypto');

// Solidity source-map spans use UTF-8 byte offsets, not JavaScript characters.
function runtimeLocations(bytecode, sourceMap, sources, contents) {
  const code=String(bytecode||'').replace(/^0x/,'');
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(code)) throw Error('Unlinked or malformed runtime bytecode');
  const files=new Map(Object.entries(sources||{}).map(([file,data])=>[data.id,file]));
  const raw=Buffer.from(code,'hex');
  const fileInfo=new Map();
  for(const [file,source] of Object.entries(contents||{})){
    if(typeof source?.content!=='string')continue;
    const bytes=Buffer.from(source.content,'utf8'),lineStarts=[0];
    for(let i=0;i<bytes.length;i++)if(bytes[i]===10)lineStarts.push(i+1);
    fileInfo.set(file,{bytes,lineStarts,sourceSha256:crypto.createHash('sha256').update(bytes).digest('hex')});
  }
  const lineAt=(starts,offset)=>{let lo=0,hi=starts.length;while(lo<hi){const mid=(lo+hi)>>>1;if(starts[mid]<=offset)lo=mid+1;else hi=mid;}return lo;};
  const result=new Map();let previous=[0,0,-1,'',0];
  const sourceMapText=String(sourceMap||'');
  let entryStart=0;
  for(let pc=0;pc<raw.length;){
    const instructionPc=pc,op=raw[pc];pc+=1+(op>=0x60&&op<=0x7f?op-0x5f:0);
    const entryEnd=sourceMapText.indexOf(';',entryStart);
    const entry=entryEnd<0?sourceMapText.slice(entryStart):sourceMapText.slice(entryStart,entryEnd);
    const fields=entry.split(':');previous=previous.map((old,index)=>fields[index]===undefined||fields[index]===''?old:index===3?fields[index]:Number(fields[index]));
    const [start,length,id]=previous,file=files.get(id),info=fileInfo.get(file);
    if(info&&Number.isSafeInteger(start)&&Number.isSafeInteger(length)&&start>=0&&length>0&&start+length<=info.bytes.length){
      result.set(instructionPc,{file,start,length,lineStart:lineAt(info.lineStarts,start),lineEnd:lineAt(info.lineStarts,start+length-1),sourceSha256:info.sourceSha256});
    }
    if(entryEnd<0)break;
    entryStart=entryEnd+1;
  }
  return result;
}

function effectSiteId(location, kind) {
  if (!location || typeof location !== 'object' ||
      typeof location.sourceSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(location.sourceSha256) ||
      typeof location.file !== 'string' || !location.file ||
      !Number.isSafeInteger(location.start) || location.start < 0 ||
      !Number.isSafeInteger(location.length) || location.length < 1 ||
      !['state_write', 'external_call', 'contract_creation', 'selfdestruct'].includes(kind)) {
    throw Error('effect site requires a source hash, file, byte span, and supported kind');
  }
  return crypto.createHash('sha256')
    .update([location.sourceSha256, location.file, String(location.start), String(location.length), kind].join('\0'), 'utf8')
    .digest('hex');
}

module.exports={runtimeLocations,effectSiteId};
