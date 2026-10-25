import test from 'node:test';
import assert from 'node:assert/strict';
import { CONFIDENCE_TIERS } from '../web/lib/confidence.js';
import { CONFIDENCE_ICONS, confidenceBadge, confidenceLegend, findingSignals, severityMeter, severityReading } from '../web/lib/badges.js';

const tierKeys = Object.keys(CONFIDENCE_TIERS);

test('每个置信度等级都有图标，且形状互不相同（不能只靠颜色区分）', () => {
  assert.deepEqual(Object.keys(CONFIDENCE_ICONS).sort(), [...tierKeys].sort());
  const shapes = tierKeys.map((key) => CONFIDENCE_ICONS[key]);
  assert.equal(new Set(shapes).size, tierKeys.length, '存在两个等级共用同一个图标');
  for (const svg of shapes) assert.match(svg, /aria-hidden="true"/);
});

test('置信度徽章同时带图标、文字标签和 title 说明', () => {
  const html = confidenceBadge({ status: 'hypothesis' });
  assert.match(html, /<svg class="conf-icon"/);
  assert.match(html, /class="conf-label">待验证</);
  assert.match(html, /data-tier="unverified"/);
  assert.match(html, /title="[^"]*依据/);
});

test('置信度徽章不会把静态线索显示成已确认', () => {
  for (const finding of [{ status: 'static_signal' }, { status: 'hypothesis' }, { severity: 'critical' }, { impact: 'High' }, {}]) {
    assert.doesNotMatch(confidenceBadge(finding), /data-tier="confirmed"/);
  }
  assert.match(confidenceBadge({ status: 'poc_confirmed', confirmedVulnerability: true }), /data-tier="confirmed"/);
});

test('严重度读数：缺失或无法识别时是“未分级”，不落到“提示”', () => {
  assert.deepEqual(
    ['critical', 'high', 'medium', 'low', 'info', 'Informational', 'HIGH'].map((value) => severityReading({ severity: value }).bars),
    [4, 3, 2, 1, 0, 0, 3],
  );
  for (const finding of [{}, { severity: '' }, { severity: '  ' }, { severity: 'catastrophic' }, { severity: 3 }, null, undefined]) {
    const reading = severityReading(finding);
    assert.equal(reading.key, 'unrated');
    assert.equal(reading.bars, 0);
  }
  assert.equal(severityReading({}).reason, 'severity_missing');
  assert.equal(severityReading({ severity: 'catastrophic' }).reason, 'severity_unrecognized');
  assert.match(severityMeter({}), /未分级/);
  assert.doesNotMatch(severityMeter({}), />提示</);
});

test('严重度也认 impact 字段（静态报告只带 impact）', () => {
  assert.equal(severityReading({ impact: 'High' }).key, 'high');
  assert.equal(severityReading({ severity: 'low', impact: 'High' }).key, 'low');
});

test('严重度刻度是四格长度条加文字，不带置信度的颜色类或图标', () => {
  const html = severityMeter({ severity: 'medium' });
  assert.equal((html.match(/<i/g) || []).length, 4);
  assert.equal((html.match(/<i class="on">/g) || []).length, 2);
  assert.match(html, /中危/);
  assert.doesNotMatch(html, /conf-|<svg/);
});

test('严重度与置信度并排但分区，各带说明文字', () => {
  const html = findingSignals({ severity: 'high', status: 'hypothesis' });
  const cells = html.match(/<div class="signal-cell">/g) || [];
  assert.equal(cells.length, 2);
  assert.ok(html.indexOf('signal-caption">严重度') < html.indexOf('signal-caption">置信度'));
  const [severityCell, confidenceCell] = html.split('<div class="signal-cell">').slice(1);
  assert.doesNotMatch(severityCell, /conf-badge/);
  assert.doesNotMatch(confidenceCell, /sev-meter/);
});

test('不可信字段进入徽章前被转义', () => {
  const html = findingSignals({ severity: '"><img src=x onerror=alert(1)>', status: '<script>x</script>' });
  assert.doesNotMatch(html, /<img|<script/);
});

test('图例列出全部等级，顺序与 rank 一致', () => {
  const html = confidenceLegend();
  const order = [...html.matchAll(/data-tier="(\w+)"/g)].map((match) => match[1]);
  assert.deepEqual(order, [...tierKeys].sort((a, b) => CONFIDENCE_TIERS[a].rank - CONFIDENCE_TIERS[b].rank));
});
