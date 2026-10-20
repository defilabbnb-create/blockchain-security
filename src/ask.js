import { answerQuestion, createSnapshotStore } from './status-store.js';
import { boundedSingleFlight } from './bounded-work.js';

const question = process.argv.slice(2).join(' ').trim();
const baseUrl = (process.env.DSH_BASE_URL || process.env.UI_BASE_URL || 'http://127.0.0.1:8788').replace(/\/$/, '');
if (!question) {
  console.error('用法：npm run ask -- "当前正在分析什么？"');
  process.exitCode = 1;
} else {
  try {
    let snapshot;
    let source = '实时服务';
    try {
      const response = await fetch(`${baseUrl}/api/status`, { signal: AbortSignal.timeout(7000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      snapshot = await response.json();
      if (!snapshot.syncVersion) throw new Error('缺少状态版本');
    } catch {
      source = '离线读取报告（不覆盖服务同步文件）';
      snapshot = await boundedSingleFlight(createSnapshotStore(null))();
    }
    const result = answerQuestion(snapshot, question);
    console.log(result.answer);
    console.log(`· ${source}；快照 ${snapshot.generatedAt}；版本 ${snapshot.syncVersion}`);
    for (const evidence of result.evidence || []) console.log(`· ${evidence}`);
  } catch (error) {
    console.error(`DSH 状态读取失败：${error.message}`);
    // An OS read can remain blocked after its deadline. This CLI owns no writes.
    process.exit(1);
  }
}
