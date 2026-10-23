import { readFile } from 'node:fs/promises';
import { createSeverityResolver } from '../src/severity-resolver.js';

const root = process.argv[2] || process.cwd();
const index = JSON.parse(await readFile(`${root}/work/finding-index.json`, 'utf8'));
const resolver = await createSeverityResolver(root);

const counts = {};
const basis = {};
const rows = [];
for (const finding of index.findings) {
  // 模拟 status-store 的接线方式：raw severity 来自来源，派生结果单独写回。
  const raw = finding.severity === 'medium' && finding.kind === 'risk_hypothesis' ? null : finding.severity;
  const input = { ...finding };
  if (raw === null) delete input.severity; else input.statedSeverity = raw;
  const out = resolver.resolve(input);
  counts[out.severity] = (counts[out.severity] || 0) + 1;
  basis[out.severityBasis] = (basis[out.severityBasis] || 0) + 1;
  rows.push({ finding, out });
}
console.log('severity', counts);
console.log('basis', basis);
console.log();
for (const { finding, out } of rows) {
  if (finding.kind === 'runtime_bytecode_analysis' || finding.kind === 'dependency_trace') continue;
  if (finding.kind !== 'risk_hypothesis' && finding.kind !== 'campaign_review_observation') continue;
  const f = out.severityFactors;
  console.log([finding.severity.padEnd(6), '->', out.severity.padEnd(8), `(${out.severityBasis})`.padEnd(18),
    (f.category || '-').padEnd(22), (f.libraryEntryId || '-').padEnd(34), `w=${f.categoryWeight}`,
    `d=${f.triggerDifficulty}`, (out.severityDowngrade || '-').padEnd(24),
    `mit=[${(f.visibleMitigations || []).join(',')}]`.padEnd(46),
    `cand=[${(f.categoryCandidates || []).join(',')}]`].join(' '), '::', finding.title.slice(0, 50));
}