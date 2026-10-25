// 置信度分级：只回答“这条记录被验证到了哪一步”，与严重度（severity.js）互相独立。
//
// 规则：
// 1. 红色（confirmed）只认后端已绑定的 PoC 字段对：status === 'poc_confirmed' 且 confirmedVulnerability === true。
//    前端不会从 violated / invariant_violated 之类的状态推导出“已确认”。
// 2. 字段缺失、取值无法识别、或确认类字段互相矛盾，一律落到 indeterminate，并在 reason 里写明原因。
//    不允许悄悄落进某个默认等级。
// 3. “已提交赏金平台”一级没有后端数据源，故意不在此定义；等后端有字段再加。
// 4. unconfirmed_observation 只是采集代码里的默认 status（makeCampaignFinding 的默认参数），
//    里面混着假设和不构成漏洞声明的记录，所以按 kind 区分，未知 kind 不猜。

export const CONFIDENCE_TIERS = Object.freeze({
  confirmed: Object.freeze({ rank: 0, label: '已确认', glyph: 'check', tone: 'red', meaning: '有绑定的 PoC 证据，攻击可复现' }),
  anomaly: Object.freeze({ rank: 1, label: '异常待确认', glyph: 'exclamation', tone: 'yellow', meaning: '断言或 PoC 出现异常，尚未被 PoC 确认' }),
  unverified: Object.freeze({ rank: 2, label: '待验证', glyph: 'question', tone: 'gray', meaning: '静态假设，还没有动态验证结果' }),
  indeterminate: Object.freeze({ rank: 3, label: '无法判定', glyph: 'dash', tone: 'dashed', meaning: '字段缺失、无法识别或互相矛盾，不给出等级' }),
  not_applicable: Object.freeze({ rank: 4, label: '非漏洞声明', glyph: 'record', tone: 'none', meaning: '采集记录或覆盖说明，不在置信度刻度上' }),
});

// 只收后端确实写进 finding.status 的值：status-store.js 在 dynamic-result 为 violated 时写 invariant_violated。
// poc_failed 只出现在 report_builder / 基准脚本里，finding 不带这个值，所以不在此处认定，遇到会落到 indeterminate。
const ANOMALY_STATUSES = new Set(['invariant_violated']);
const UNVERIFIED_STATUSES = new Set(['hypothesis', 'static_signal']);
// 只有 risk_hypothesis 是通过引用校验、对潜在风险的陈述。
const OBSERVATION_CLAIM_KINDS = new Set(['risk_hypothesis']);
// 这两个 kind 是“没分类”的占位值，不能当候选：
// - campaign_review_observation：status-store.js:144 在 observation.kind 缺失时的默认值，全仓库没有其它写入点。
// - unclassified_observation：defi-campaign.py:728 对不在白名单内的 kind 的兜底值。
const OBSERVATION_UNCLASSIFIED_KINDS = new Set(['campaign_review_observation', 'unclassified_observation']);
// 这四类 kind 是采集产物、覆盖缺口或安全控制，本身不声称存在漏洞。
const OBSERVATION_RECORD_KINDS = new Set(['runtime_bytecode_analysis', 'dependency_trace', 'coverage_gap', 'security_control']);
const CONFIRMATION_STATUSES = new Set(['poc_confirmed', 'confirmed', 'reproduced']);

function result(tier, reason, basis) {
  return Object.freeze({ tier, label: CONFIDENCE_TIERS[tier].label, reason, basis: Object.freeze({ ...basis }) });
}

export function confidenceTier(finding) {
  if (finding === null || typeof finding !== 'object' || Array.isArray(finding)) {
    return result('indeterminate', 'finding_missing', {});
  }
  const status = typeof finding.status === 'string' && finding.status ? finding.status : null;
  const kind = typeof finding.kind === 'string' && finding.kind ? finding.kind : null;
  const basis = { status, kind, confirmedVulnerability: finding.confirmedVulnerability, confirmed: finding.confirmed, pocState: finding.pocState };

  const pocPair = status === 'poc_confirmed' && finding.confirmedVulnerability === true
    && (finding.pocState === undefined || finding.pocState === 'confirmed');
  if (pocPair) return result('confirmed', 'poc_confirmed_pair', basis);

  const claimsConfirmation = CONFIRMATION_STATUSES.has(status) || finding.confirmed === true || finding.confirmedVulnerability === true;
  if (claimsConfirmation) return result('indeterminate', 'confirmation_fields_conflict', basis);

  if (status === null) return result('indeterminate', 'status_missing', basis);
  if (ANOMALY_STATUSES.has(status)) return result('anomaly', `status:${status}`, basis);
  if (UNVERIFIED_STATUSES.has(status)) return result('unverified', `status:${status}`, basis);
  if (status === 'unconfirmed_observation') {
    if (OBSERVATION_CLAIM_KINDS.has(kind)) return result('unverified', `observation_kind:${kind}`, basis);
    if (OBSERVATION_RECORD_KINDS.has(kind)) return result('not_applicable', `observation_kind:${kind}`, basis);
    if (OBSERVATION_UNCLASSIFIED_KINDS.has(kind)) return result('indeterminate', 'observation_kind_unclassified', basis);
    return result('indeterminate', 'observation_kind_unknown', basis);
  }
  return result('indeterminate', 'status_unrecognized', basis);
}

export function compareByConfidence(a, b) {
  return CONFIDENCE_TIERS[confidenceTier(a).tier].rank - CONFIDENCE_TIERS[confidenceTier(b).tier].rank;
}
