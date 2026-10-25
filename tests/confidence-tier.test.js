import test from 'node:test';
import assert from 'node:assert/strict';
import { CONFIDENCE_TIERS, confidenceTier, compareByConfidence } from '../web/lib/confidence.js';

const tierOf = (finding) => confidenceTier(finding).tier;

test('表驱动：状态与 kind 到等级的映射', () => {
  const rows = [
    [{ status: 'poc_confirmed', confirmedVulnerability: true }, 'confirmed'],
    [{ status: 'poc_confirmed', confirmedVulnerability: true, pocState: 'confirmed' }, 'confirmed'],
    [{ status: 'invariant_violated' }, 'anomaly'],
    // finding 上不会出现 poc_failed，遇到时不猜
    [{ status: 'poc_failed' }, 'indeterminate'],
    [{ status: 'invariant_violated', pocState: 'unconfirmed' }, 'anomaly'],
    [{ status: 'invariant_violated', pocState: 'error' }, 'anomaly'],
    [{ status: 'hypothesis' }, 'unverified'],
    [{ status: 'static_signal' }, 'unverified'],
    [{ status: 'static_signal', kind: 'source_bytecode_divergence' }, 'unverified'],
    [{ status: 'unconfirmed_observation', kind: 'risk_hypothesis' }, 'unverified'],
    // 无分类的占位 kind 不当候选
    [{ status: 'unconfirmed_observation', kind: 'campaign_review_observation' }, 'indeterminate'],
    [{ status: 'unconfirmed_observation', kind: 'unclassified_observation' }, 'indeterminate'],
    [{ status: 'unconfirmed_observation', kind: 'runtime_bytecode_analysis' }, 'not_applicable'],
    [{ status: 'unconfirmed_observation', kind: 'dependency_trace' }, 'not_applicable'],
    [{ status: 'unconfirmed_observation', kind: 'coverage_gap' }, 'not_applicable'],
    [{ status: 'unconfirmed_observation', kind: 'security_control' }, 'not_applicable'],
    // 未知 kind 不猜
    [{ status: 'unconfirmed_observation', kind: 'invariant_observation' }, 'indeterminate'],
    [{ status: 'unconfirmed_observation' }, 'indeterminate'],
    // 字段缺失或无法识别
    [{}, 'indeterminate'],
    [{ status: '' }, 'indeterminate'],
    [{ status: 42 }, 'indeterminate'],
    [{ status: 'rejected' }, 'indeterminate'],
    [{ status: 'something_new' }, 'indeterminate'],
    [null, 'indeterminate'],
    [undefined, 'indeterminate'],
    ['poc_confirmed', 'indeterminate'],
    [[], 'indeterminate'],
  ];
  for (const [input, expected] of rows) {
    assert.equal(tierOf(input), expected, JSON.stringify(input));
  }
});

test('红色只来自 status=poc_confirmed 与 confirmedVulnerability=true 的成对字段', () => {
  const statuses = [undefined, null, '', 'hypothesis', 'static_signal', 'unconfirmed_observation', 'invariant_violated',
    'poc_failed', 'poc_confirmed', 'confirmed', 'reproduced', 'observed', 'rejected', 'insufficient'];
  const flags = [undefined, null, false, true, 'true', 1];
  const pocStates = [undefined, 'confirmed', 'unconfirmed', 'error'];
  let confirmedCount = 0;
  for (const status of statuses) for (const confirmedVulnerability of flags) for (const confirmed of flags) for (const pocState of pocStates) {
    const finding = { status, confirmedVulnerability, confirmed, pocState };
    const expected = status === 'poc_confirmed' && confirmedVulnerability === true && (pocState === undefined || pocState === 'confirmed');
    assert.equal(tierOf(finding) === 'confirmed', expected, JSON.stringify(finding));
    if (expected) confirmedCount += 1;
  }
  assert.ok(confirmedCount > 0);
});

test('任何一侧声称已确认但字段不成对，落到无法判定而不是红色或灰色', () => {
  const rows = [
    { status: 'poc_confirmed' },
    { status: 'poc_confirmed', confirmedVulnerability: false },
    { status: 'poc_confirmed', confirmedVulnerability: true, pocState: 'unconfirmed' },
    { status: 'hypothesis', confirmedVulnerability: true },
    { status: 'invariant_violated', confirmedVulnerability: true },
    { status: 'confirmed' },
    { status: 'reproduced' },
    { status: 'static_signal', confirmed: true },
  ];
  for (const finding of rows) {
    const verdict = confidenceTier(finding);
    assert.equal(verdict.tier, 'indeterminate', JSON.stringify(finding));
    assert.equal(verdict.reason, 'confirmation_fields_conflict');
  }
});

test('无分类占位 kind 的 reason 指向“未分类”，与“未知 kind”区分开', () => {
  for (const kind of ['campaign_review_observation', 'unclassified_observation']) {
    assert.equal(confidenceTier({ status: 'unconfirmed_observation', kind }).reason, 'observation_kind_unclassified');
  }
  assert.equal(confidenceTier({ status: 'unconfirmed_observation', kind: 'brand_new_kind' }).reason, 'observation_kind_unknown');
});

test('v1 接口里 confirmed=false 与 PoC 已确认并存是正常状态，不算矛盾', () => {
  assert.equal(tierOf({ status: 'poc_confirmed', confirmedVulnerability: true, confirmed: false }), 'confirmed');
});

test('严重度与置信度互相独立', () => {
  for (const severity of ['critical', 'High', 'medium', 'low', 'info', undefined, 'garbage']) {
    assert.equal(tierOf({ status: 'hypothesis', severity, impact: severity }), 'unverified');
    assert.equal(tierOf({ status: 'poc_confirmed', confirmedVulnerability: true, severity }), 'confirmed');
  }
});

test('每个结论都带 reason 和读取到的字段，便于界面展示依据', () => {
  const verdict = confidenceTier({ status: 'static_signal', kind: 'source_bytecode_divergence', severity: 'medium' });
  assert.equal(verdict.reason, 'status:static_signal');
  assert.equal(verdict.basis.status, 'static_signal');
  assert.equal(verdict.basis.kind, 'source_bytecode_divergence');
  assert.equal(verdict.label, CONFIDENCE_TIERS.unverified.label);
  assert.ok(Object.isFrozen(verdict) && Object.isFrozen(verdict.basis));
});

test('等级表：没有“已提交”这一级，五项都有标签和图形，且互不重复', () => {
  assert.deepEqual(Object.keys(CONFIDENCE_TIERS), ['confirmed', 'anomaly', 'unverified', 'indeterminate', 'not_applicable']);
  assert.ok(!('submitted' in CONFIDENCE_TIERS));
  for (const key of ['label', 'glyph', 'tone', 'rank']) {
    const values = Object.values(CONFIDENCE_TIERS).map((tier) => tier[key]);
    assert.ok(values.every((value) => value !== undefined && value !== ''), key);
    assert.equal(new Set(values).size, values.length, `${key} 不应重复`);
  }
  assert.ok(Object.isFrozen(CONFIDENCE_TIERS));
});

test('排序：已确认在最前，非漏洞声明在最后', () => {
  const rows = [
    { id: 'n', status: 'unconfirmed_observation', kind: 'coverage_gap' },
    { id: 'i', status: 'something_new' },
    { id: 'u', status: 'hypothesis' },
    { id: 'a', status: 'invariant_violated' },
    { id: 'c', status: 'poc_confirmed', confirmedVulnerability: true },
  ];
  assert.deepEqual([...rows].sort(compareByConfidence).map((row) => row.id), ['c', 'a', 'u', 'i', 'n']);
});
