#!/usr/bin/env python3
"""Validate the local analyzer against deliberately broken copies; no RPC use."""
import argparse
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT=Path(__file__).resolve().parent.parent
MUTATIONS=[
    ('share_accounting','totalSupply += shares;', 'totalSupply += shares + 1;', 'idle-vault-state-sequence-'),
    ('redemption_authorization','if (msg.sender != onBehalf) {','if (false) {','idle-vault-unauthorized-redemption-and-allowance'),
    ('mint_rounding','return shares.mulDivUp(newTotalAssets + 1, newTotalSupply + virtualShares);','return shares.mulDivDown(newTotalAssets + 1, newTotalSupply + virtualShares);','idle-vault-rounding-and-roundtrip'),
    ('redemption_receiver','SafeERC20Lib.safeTransfer(asset, receiver, assets);','SafeERC20Lib.safeTransfer(asset, onBehalf, assets);','idle-vault-unauthorized-redemption-and-allowance'),
    ('redemption_to_caller','SafeERC20Lib.safeTransfer(asset, receiver, assets);','SafeERC20Lib.safeTransfer(asset, msg.sender, assets);','idle-vault-role-separated-redemption-revocation'),
    ('vault-v2-infinite-allowance','if (_allowance != type(uint256).max) {','if (true) {','idle-vault-share-transferFrom-allowance-ledger'),
    ('vault-v2-finite-allowance-not-consumed','if (_allowance != type(uint256).max) {','if (false) {','idle-vault-share-transferFrom-allowance-ledger'),
    ('vault-v2-self-transferFrom-allowance','if (msg.sender != from) {','if (true) {','idle-vault-share-transferFrom-allowance-ledger'),
    ('donation_rate_cap_bypass','uint256 newTotalAssets = MathLib.min(realAssets, maxTotalAssets);','uint256 newTotalAssets = realAssets;','idle-vault-donation-zero-rate-consistency'),
]

def check(input_path,output):
    original=json.loads(input_path.read_text())
    target='lib/vault-v2/src/VaultV2.sol'
    source=original['sources'][target]['content']
    output.mkdir(parents=True,exist_ok=False)
    jobs=[('baseline',original,None)]
    for name,before,after,test in MUTATIONS:
        if source.count(before)!=1:raise ValueError(f'{name}: mutation anchor must occur exactly once')
        data=copy.deepcopy(original);data['sources'][target]['content']=source.replace(before,after)
        jobs.append((name,data,test))
    def execute(job):
        name,data,expected=job
        folder=output/name;folder.mkdir();request=folder/'input.json';request.write_text(json.dumps(data))
        env=dict(os.environ,CAMPAIGN_SOLJSON=str(ROOT/'flare-scan/tools/solc-0828/node_modules/solc/soljson.js'))
        start=time.monotonic()
        proc=subprocess.Popen(['node',str(ROOT/'scripts/test-vault.cjs'),str(request),target,'--contract','VaultV2'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,env=env,cwd=ROOT)
        try:stdout,stderr=proc.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate()
            (folder/'stdout.log').write_text(stdout);(folder/'stderr.log').write_text(stderr)
            return {'name':name,'state':'failed','reason':'harness_timeout','durationMs':round((time.monotonic()-start)*1000)}
        (folder/'stdout.log').write_text(stdout);(folder/'stderr.log').write_text(stderr)
        try:result=json.loads(stdout)
        except ValueError:return {'name':name,'state':'failed','reason':'invalid_harness_output','exitCode':proc.returncode}
        (folder/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
        failed=[r['id'] for r in result.get('results',[]) if r.get('state')=='failed']
        valid=(proc.returncode==0 and result.get('state')=='passed') if name=='baseline' else (proc.returncode!=0 and result.get('state')=='failed' and any(x.startswith(expected) for x in failed))
        targeted=sorted({p for row in result.get('results',[]) if row.get('state')=='failed' for p in row.get('targetPropertyIds',[])})
        return {'name':name,'state':'passed' if valid else 'failed','expected':'unmodified baseline passes' if name=='baseline' else 'deliberate local mutation detected','harnessState':result.get('state'),'failedProperties':failed,'failedTestTargetPropertyIds':targeted,'validatedPropertyIds':result.get('propertyIds',[]),'sourceHash':result.get('sourceHash'),'harnessHash':result.get('harnessHash'),'evidence':str(folder/'result.json'),'durationMs':round((time.monotonic()-start)*1000)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(execute,jobs))
    report={'state':'passed' if all(r['state']=='passed' for r in results) else 'failed','scope':'detector effectiveness check using isolated modified copies, not live vulnerability confirmation','inputSha256':hashlib.sha256(input_path.read_bytes()).hexdigest(),'results':results,'externalTransactions':False,'confirmedVulnerabilities':0}
    (output/'detector-validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    report=check(args.input.resolve(),args.output.resolve());print(json.dumps(report,ensure_ascii=False));raise SystemExit(0 if report['state']=='passed' else 1)
