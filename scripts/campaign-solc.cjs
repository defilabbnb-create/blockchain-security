#!/usr/bin/env node
const fs=require('node:fs');
const solcBase=require('../flare-scan/tools/solc-0828/node_modules/solc');
const solc=solcBase.setupMethods(require(process.env.CAMPAIGN_SOLJSON));
if(process.argv.includes('--version')) console.log(`solc, the solidity compiler commandline interface\nVersion: ${solc.version()}`);
else if(process.argv.includes('--standard-json')) process.stdout.write(solc.compile(fs.readFileSync(0,'utf8')));
else throw Error('Only --version and --standard-json are supported');
