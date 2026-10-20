#!/usr/bin/env node
// Local solc-js adapter for crytic-compile's combined-json protocol.
const fs = require('node:fs');
const path = require('node:path');
const semver = require('./solc-0828/node_modules/semver');
const argv = process.argv.slice(2);
const versions = { '0.8.19': '0819', '0.8.23': '0823', '0.8.28': '0828' };
const load = v => require(path.join(__dirname, `solc-${versions[v]}`, 'node_modules/solc'));
function select(contents) {
  if (process.env.SOLC_VERSION) {
    if (!versions[process.env.SOLC_VERSION]) throw new Error('SOLC_VERSION must be 0.8.19, 0.8.23 or 0.8.28');
    return load(process.env.SOLC_VERSION);
  }
  const clean = contents.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
  const ranges = [...clean.matchAll(/pragma\s+solidity\s+([^;]+);/g)].map(m => m[1].trim());
  const version = Object.keys(versions).reverse().find(v => ranges.every(r => semver.satisfies(v, r)));
  if (!version) throw new Error('No installed compiler satisfies the source pragmas; set up the required compiler');
  return load(version);
}
function compile(solc, input, base) {
  return JSON.parse(solc.compile(JSON.stringify(input), { import: name => {
    const candidates = [path.resolve(base, name), path.resolve(base, 'node_modules', name)];
    for (const candidate of candidates) {
      try { if (fs.statSync(candidate).isFile()) return { contents: fs.readFileSync(candidate, 'utf8') }; } catch {}
    }
    return { error: `Import not found: ${name}` };
  } }));
}
function main() {
  if (argv.includes('--version')) {
    console.log(`solc, the solidity compiler commandline interface\nVersion: ${select('').version()}`);
    return;
  }
  if (argv.includes('--standard-json')) {
    const input = JSON.parse(fs.readFileSync(0, 'utf8'));
    const contents = Object.values(input.sources || {}).map(s => s.content || '').join('\n');
    const out = compile(select(contents), input, process.cwd());
    process.stdout.write(JSON.stringify(out));
    if ((out.errors || []).some(e => e.severity === 'error')) process.exitCode = 1;
    return;
  }
  let base = process.cwd(), evmVersion = 'paris', optimize = false, runs = 200, viaIR = false;
  const files = [], remappings = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => { if (argv[i + 1] === undefined) throw new Error(`Missing value for ${a}`); return argv[++i]; };
    if (a === '--base-path') base = path.resolve(value());
    else if (a === '--combined-json' || a === '--allow-paths') value();
    else if (a === '--remappings' || a === '--remap') remappings.push(...value().split(',').filter(Boolean));
    else if (a === '--evm-version') evmVersion = value();
    else if (a === '--via-ir') viaIR = true;
    else if (a === '--optimize') optimize = true;
    else if (a === '--optimize-runs') { runs = Number(value()); if (!Number.isInteger(runs) || runs < 0) throw new Error('Invalid optimizer runs'); }
    else if (a.includes('=') && !a.startsWith('--')) remappings.push(a);
    else if (a.endsWith('.sol')) files.push(a);
    else throw new Error(`Unsupported compiler option: ${a}`);
  }
  if (!files.length) throw new Error('No Solidity source files supplied');
  if (process.env.SOLC_REMAPPINGS) remappings.push(...process.env.SOLC_REMAPPINGS.split(',').filter(Boolean));
  const sources = Object.fromEntries(files.map(file => [path.resolve(base, file), { content: fs.readFileSync(path.resolve(base, file), 'utf8') }]));
  const solc = select(Object.values(sources).map(s => s.content).join('\n'));
  const input = { language: 'Solidity', sources, settings: {
    remappings, evmVersion, viaIR, optimizer: { enabled: optimize, runs },
    outputSelection: { '*': { '': ['ast'], '*': ['abi', 'evm.bytecode', 'evm.deployedBytecode', 'evm.methodIdentifiers', 'metadata', 'userdoc', 'devdoc'] } },
  } };
  const out = compile(solc, input, base);
  for (const error of out.errors || []) console.error(error.formattedMessage || error.message);
  if ((out.errors || []).some(e => e.severity === 'error')) { process.exitCode = 1; return; }
  const contracts = {};
  for (const [file, entries] of Object.entries(out.contracts || {})) {
    for (const [name, c] of Object.entries(entries)) contracts[`${file}:${name}`] = {
      abi: c.abi, bin: c.evm.bytecode.object, 'bin-runtime': c.evm.deployedBytecode.object,
      srcmap: c.evm.bytecode.sourceMap, 'srcmap-runtime': c.evm.deployedBytecode.sourceMap,
      hashes: c.evm.methodIdentifiers, metadata: c.metadata, userdoc: c.userdoc, devdoc: c.devdoc,
    };
  }
  if (!Object.keys(contracts).length || !Object.keys(out.sources || {}).length) throw new Error('Compiler produced no contracts/AST');
  process.stdout.write(JSON.stringify({ contracts,
    sources: Object.fromEntries(Object.entries(out.sources).map(([file, s]) => [file, { id: s.id, AST: s.ast }])),
    sourceList: Object.entries(out.sources).sort((a, b) => a[1].id - b[1].id).map(([file]) => file), version: solc.version(),
  }));
}
try { main(); } catch (error) { console.error(`Compiler failed: ${error.message}`); process.exitCode = 1; }
