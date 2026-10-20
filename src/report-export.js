import { createHash } from 'node:crypto';

const SEVERITY_LEVELS = new Map([
  ['Critical', 'error'],
  ['High', 'error'],
  ['Medium', 'warning'],
  ['Low', 'note'],
  ['Informational', 'note'],
]);

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function stableId(value) {
  return `finding-${createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16)}`;
}

function findings(report) {
  return Array.isArray(report?.findings) ? report.findings.filter((item) => item && typeof item === 'object' && !Array.isArray(item)) : [];
}

function severity(finding) {
  return finding.severity || finding.impact || 'Informational';
}

function sourceLocation(source) {
  if (typeof source !== 'string' || !source) return null;
  const match = source.match(/^(.*?)(?:#L(\d+)(?:-L?(\d+))?)?$/);
  if (!match || !match[1]) return null;
  const startLine = match[2] ? Number(match[2]) : null;
  const endLine = match[3] ? Number(match[3]) : startLine;
  return { uri: match[1], ...(Number.isSafeInteger(startLine) ? { startLine } : {}), ...(Number.isSafeInteger(endLine) ? { endLine } : {}) };
}

function findingRuleId(finding) {
  return String(finding.ruleId || finding.id || stableId({ check: finding.check, target: finding.target, source: finding.source }));
}

function sarifResult(finding) {
  const level = SEVERITY_LEVELS.get(severity(finding)) || 'note';
  const result = {
    ruleId: findingRuleId(finding),
    level,
    message: { text: `${finding.check || '未命名检查'}：${finding.target || finding.contract || '未知目标'}` },
    properties: {
      severity: severity(finding),
      status: finding.evidenceStatus || finding.status || 'hypothesis',
      confirmed: finding.confirmed === true,
    },
  };
  const location = sourceLocation(finding.source || finding.location);
  if (location) result.locations = [{ physicalLocation: { artifactLocation: { uri: location.uri }, ...(location.startLine ? { region: { startLine: location.startLine, ...(location.endLine ? { endLine: location.endLine } : {}) } } : {}) } }];
  return result;
}

export function toSarif(report, { taskId = null, sourceSha256 = null } = {}) {
  const rows = findings(report);
  const rules = [];
  const seen = new Set();
  for (const finding of rows) {
    const id = findingRuleId(finding);
    if (seen.has(id)) continue;
    seen.add(id);
    rules.push({ id, name: String(finding.check || id), shortDescription: { text: String(finding.check || '未命名检查') } });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'defi-scan', informationUri: 'https://github.com/oasisprotocol', rules } },
      results: rows.map(sarifResult),
      properties: {
        reportState: report?.state || null,
        taskId,
        sourceReportSha256: sourceSha256,
        interpretation: 'SARIF 仅转发已保存的检查结果；候选结果不等于确认漏洞。',
      },
    }],
  };
}

function htmlEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

export function toHtml(report, { taskId = null, sourceSha256 = null } = {}) {
  const rows = findings(report);
  const rowMarkup = rows.length ? rows.map((finding) => `<tr><td>${htmlEscape(severity(finding))}</td><td>${htmlEscape(finding.check || '未命名检查')}</td><td>${htmlEscape(finding.target || finding.contract || '未知目标')}</td><td>${htmlEscape(finding.source || '未提供')}</td><td>${htmlEscape(finding.evidenceStatus || finding.status || 'hypothesis')}</td></tr>`).join('') : '<tr><td colspan="5">未提供检查结果</td></tr>';
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>分析报告 ${htmlEscape(taskId || '')}</title><style>body{font:15px system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#18212b}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d8dee6;padding:8px;text-align:left}th{background:#f3f6f8}.meta{color:#536273}.notice{background:#fff6df;padding:12px;border-left:4px solid #e0a323}</style><h1>分析报告</h1><p class="meta">任务：${htmlEscape(taskId || '未提供')} · 状态：${htmlEscape(report?.state || '未提供')} · 来源指纹：${htmlEscape(sourceSha256 || '未提供')}</p><p class="notice">页面中的结果来自已保存的检查记录。候选结果不等于确认漏洞，请结合证据状态和复现材料判断。</p><h2>检查结果（${rows.length}）</h2><table><thead><tr><th>级别</th><th>检查</th><th>目标</th><th>来源</th><th>证据状态</th></tr></thead><tbody>${rowMarkup}</tbody></table></html>`;
}

export function exportReport(report, format, options = {}) {
  const normalized = String(format || 'json').toLowerCase();
  if (normalized === 'json') return { format: 'json', contentType: 'application/json; charset=utf-8', body: `${JSON.stringify(clone(report), null, 2)}\n` };
  if (normalized === 'sarif') return { format: 'sarif', contentType: 'application/sarif+json; charset=utf-8', body: `${JSON.stringify(toSarif(report, options), null, 2)}\n` };
  if (normalized === 'html') return { format: 'html', contentType: 'text/html; charset=utf-8', body: toHtml(report, options) };
  const error = new Error('format 必须是 json、sarif 或 html');
  error.code = 'invalid_format';
  error.status = 422;
  throw error;
}
