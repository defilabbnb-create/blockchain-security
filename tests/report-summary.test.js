import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const appSource = await readFile(new URL('../web/app.js', import.meta.url), 'utf8');
const summarySource = appSource.match(/function renderArchivedReportSummary\(report\) \{[\s\S]*?\n\}(?=\n\nasync function renderTaskDetailWorkspace)/)?.[0];
assert.ok(summarySource, 'task detail should include the tested archive report summary renderer');
const renderArchivedReportSummary = new Function('escapeHTML', 'report', `${summarySource}; return renderArchivedReportSummary(report);`);
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

test('archived report summary only counts explicit stored findings and confirmation flags', () => {
  const html = renderArchivedReportSummary(escapeHTML, {
    state: 'completed',
    findings: [
      { id: 'a', confirmed: true },
      { id: 'b', status: 'hypothesis' },
      { id: 'c', confirmed: false },
    ],
    dynamicAnalysis: { tests: 4 },
  });
  assert.match(html, /报告状态：已完成/);
  assert.match(html, /风险记录：3 条/);
  assert.match(html, /明确标记已确认：1 条/);
  assert.match(html, /其他记录不会自动视为已确认/);
  assert.match(html, /已运行 4 项/);
});

test('missing report fields remain unrecorded instead of becoming zero', () => {
  const html = renderArchivedReportSummary(escapeHTML, { state: 'custom-state' });
  assert.match(html, /报告状态：custom-state/);
  assert.match(html, /风险记录：未记录/);
  assert.match(html, /明确标记已确认：未记录/);
  assert.match(html, /动态检查：未记录/);
});

test('untrusted archived report text is escaped before rendering', () => {
  const html = renderArchivedReportSummary(escapeHTML, {
    state: '<script>alert(1)</script>',
    findings: [{ confirmed: true }],
  });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});
