const { mkdir, writeFile } = require('node:fs/promises');
const { resolve, join } = require('node:path');
let playwright;
try { playwright = require(process.env.PLAYWRIGHT_MODULE || 'playwright'); }
catch { playwright = require('/Users/d288/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright'); }
const output = resolve(process.env.UI_OUTPUT_DIR || 'work/ui');
const baseUrl = process.env.UI_BASE_URL || 'http://127.0.0.1:8788';
const assert = (ok, message) => { if (!ok) throw Error(message); };
async function waitForService(url = `${baseUrl}/api/health`) {
  const deadline = Date.now() + 15000;
  let lastError = 'service unavailable';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000) });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) { lastError = error.message; }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw Error(`等待区块链安全服务超时：${lastError}`);
}
(async () => {
  await mkdir(output, { recursive: true });
  await waitForService();
  const browser = await playwright.chromium.launch({ headless: true, channel: 'chrome', args: ['--no-proxy-server'] });
    const report = { generatedAt: new Date().toISOString(), browser: 'system Chrome', state: 'running', viewports: [], errors: [], failedRequests: [], apiReads: [], checks: [] };
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1100 }, deviceScaleFactor: 1, reducedMotion: 'reduce' });
    let lastAskRequest;
    const workspaceSubmissions = [];
    const taskActions = [];
    const operatorTask = { taskId: 'ui-operator-task', type: 'analysis', state: 'queued', priority: 0, attempts: 0, maxAttempts: 3, checkpointSeq: 0, createdAt: '2026-10-20T00:00:00.000Z', updatedAt: '2026-10-20T00:00:00.000Z', history: [], checkpoint: {}, lease: null, payload: {} };
    let operatorRevision = 10;
    page.on('pageerror', (error) => report.errors.push(error.message));
    page.on('console', (message) => { if (message.type() === 'error') report.errors.push(message.text()); });
    page.on('response', (response) => { if (response.status() >= 400) report.failedRequests.push({ url: response.url(), status: response.status() }); });
    page.on('request', (request) => {
      if (request.method() === 'GET' && new URL(request.url()).pathname.startsWith('/api/')) report.apiReads.push(request.url());
      if (request.url().endsWith('/api/ask') && request.method() === 'POST') {
        try { lastAskRequest = JSON.parse(request.postData() || '{}'); } catch { lastAskRequest = null; }
      }
    });
    await page.route('**/api/v1/**', async (route) => {
      const request = route.request();
      const pathname = new URL(request.url()).pathname;
      const url = new URL(request.url());
      if (request.method() === 'GET' && pathname === '/api/v1/tasks' && url.searchParams.has('limit')) {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, items: [operatorTask], consistency: { revision: operatorRevision, asOf: '2026-10-20T00:00:00.000Z' }, page: { limit: 20, hasMore: false, nextCursor: null } }) });
        return;
      }
      const operatorTaskPath = pathname.match(/^\/api\/v1\/tasks\/ui-operator-task(?:\/(pause|resume|cancel))?$/);
      if (operatorTaskPath && request.method() === 'GET') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, data: operatorTask, consistency: { revision: operatorRevision, asOf: '2026-10-20T00:00:00.000Z' } }) });
        return;
      }
      if (request.method() === 'GET' && pathname === '/api/v1/reports/ui-operator-task') {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, data: { report: {} } }) });
        return;
      }
      if (operatorTaskPath && operatorTaskPath[1] && request.method() === 'POST') {
        const headers = request.headers();
        const match = headers['if-match']?.match(/^W\/"(\d+)"$/);
        const body = JSON.parse(request.postData() || '{}');
        assert(match && Number(match[1]) === operatorRevision, 'task action must send the latest If-Match revision');
        const action = operatorTaskPath[1];
        taskActions.push({ action, revision: Number(match[1]), reason: body.reason });
        operatorTask.state = action === 'pause' ? 'paused' : action === 'resume' ? 'queued' : 'cancelled';
        operatorRevision += 1;
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, data: operatorTask, consistency: { revision: operatorRevision, asOf: '2026-10-20T00:00:00.000Z' } }) });
        return;
      }
      if (request.method() === 'GET' && pathname === '/api/v1/decompile' && url.searchParams.has('limit')) {
        const taskId = 'ui-reverse-artifact';
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
          apiVersion: 'v1', schemaVersion: 1, items: [{ taskId, id: taskId, state: 'succeeded',
            artifacts: [
              { kind: 'solidity-pseudocode', bytes: 40, sha256: 'a'.repeat(64) },
              { kind: 'unified-ir', bytes: 24, sha256: 'b'.repeat(64) },
            ] }], page: { limit: 100, hasMore: false, nextCursor: null },
        }) });
        return;
      }
      const artifactContent = pathname.match(/^\/api\/v1\/tasks\/ui-reverse-artifact\/artifacts\/([0-9a-f]{64})\/content$/);
      if (request.method() === 'GET' && artifactContent) {
        const content = artifactContent[1] === 'a'.repeat(64)
          ? '<img src=x onerror=alert(1)> contract Recovered {}'
          : '{"functions":[]}';
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, data: { content, bytes: content.length, kind: artifactContent[1] === 'a'.repeat(64) ? 'solidity-pseudocode' : 'unified-ir', sha256: artifactContent[1] } }) });
        return;
      }
      if (request.method() === 'POST' && ['/api/v1/tasks', '/api/v1/decompile'].includes(pathname)) {
        const body = JSON.parse(request.postData() || '{}');
        workspaceSubmissions.push({ pathname, body });
        await route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify({ apiVersion: 'v1', schemaVersion: 1, accepted: true, data: { taskId: `ui-check-${workspaceSubmissions.length}` } }) });
        return;
      }
      await route.continue();
    });
    await page.goto(`${baseUrl}/`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#audit-view h1')?.textContent === '协议风险作战地图');
    for (const [hash, title] of [['#map', '协议风险作战地图'], ['#protocols', '协议清单与关系'], ['#discoveries', '发现与证据链'], ['#execution', '执行与复现']]) {
      await page.locator(`.nav-list > .nav-item[href="${hash}"]`).click();
      await page.waitForFunction((expected) => document.querySelector('#audit-view h1')?.textContent === expected, title);
      assert(await page.locator('#audit-view').isVisible(), `${hash} audit view visibility`);
      if (hash === '#protocols') await page.waitForSelector('#audit-view .mermaid svg', { timeout: 10000 });
      if (hash === '#discoveries') {
        assert(await page.locator('#audit-view .audit-finding').count() > 0, 'findings view must render campaign-backed evidence');
        assert((await page.locator('#audit-view .finding-toolbar').innerText()).includes('campaign 证据'), 'findings view shows campaign source count');
      }
    }
    report.checks.push('four audit views switch and findings include campaign evidence');
    await page.locator('.operations-nav').evaluate((element) => { element.open = true; });
    await page.locator('.nav-item[href="#overview"]').click();
    await page.waitForSelector('.lab-step');
    assert(await page.locator('#use-model').count() === 0, 'homepage must not expose local-model query control');
    assert(await page.locator('.stage-card').count() === 4, 'four-stage workflow summary');
    assert((await page.locator('#stage-summary-title').innerText()).includes('采集 → 处理 → 分析 → 结果'), 'stage summary title');
    const stageText = await page.locator('#stage-summary').innerText();
    const stageData = await page.locator('#stage-summary').textContent();
    assert((await page.locator('.stage-card h4').allTextContents()).join('') === '采集处理分析结果', 'stage summary labels');
    assert(stageText.includes('待补') && stageText.includes('更新于'), 'stage summary shows pending work and data freshness');
    assert(stageText.includes('总览更新于') && stageText.includes('采集记录更新于'), 'stage summary distinguishes snapshot and campaign record freshness');
    assert(stageText.includes('待核验线索') && stageText.includes('不等于漏洞已确认'), 'stage summary explains what results mean');
    assert(!stageText.includes('总体证据') && !stageText.includes('代码检查 '), 'stage summary avoids confusing completion percentages');
    assert(stageData.includes('云端复核完成') && stageData.includes('待核验线索不是已确认漏洞'), 'stage summary preserves cloud review evidence boundaries');
    assert(await page.locator('.progress-summary').count() === 0, 'overview must not show incomparable progress percentages');
    assert(await page.locator('.campaign-results details[open]').count() === 0, 'detailed evidence starts collapsed');
    report.checks.push('collection / processing / analysis / result summary');
    assert((await page.locator('#campaign-title').innerText()).includes('采集'), 'campaign status title');
    assert((await page.locator('#campaign-performance').innerText()).includes('云端审查完成'), 'cloud review completion metric');
    const scopeCopy = await page.locator('#active-scope').innerText();
    assert(scopeCopy.includes('已保存记录') && scopeCopy.includes('更新时间'), 'overview must explain that stage counts come from saved records');
    assert(!/\bTVL\b|\bRPC\b|\bEVM\b/.test(scopeCopy), 'overview scope must avoid specialist abbreviations');
    assert(await page.locator('#rpc-summary').innerText().then(x=>x.includes('验证连接')), 'verified connection summary');
    report.checks.push('live campaign metrics / verified RPC summary');
    await page.locator('.nav-item[href="#analysis-tasks"]').click();
    await page.waitForFunction(() => document.querySelector('.nav-item.active')?.hash === '#analysis-tasks');
    assert(await page.locator('#analysis-tasks').isVisible(), 'task queue navigation');
    await page.locator('.nav-item[href="#overview"]').click();
    await page.waitForFunction(() => document.querySelector('.nav-item.active')?.hash === '#overview');
    report.checks.push('task queue navigation and active section');
    await page.locator('#chain-search').fill('Flare');
    assert(await page.locator('#chain-list tr').count() === 1, 'chain search');
    await page.locator('#chain-search').fill('no-such-chain');
    assert((await page.locator('#chain-list').innerText()).includes('暂无'), 'empty search');
    await page.locator('#chain-search').fill('');
    await page.locator('#chain-filter').selectOption('ready');
    assert(await page.locator('#chain-list tr').count() === 4, 'ready filter');
    await page.locator('#chain-filter').selectOption('all');
    report.checks.push('chain search / empty / ready filter');
    for (let i = 0; i < 3; i++) {
      await page.getByRole('tab').nth(i).click();
      assert(await page.getByRole('tab').nth(i).getAttribute('aria-selected') === 'true', 'tab state');
      assert(await page.locator('.lab-step').count() === 4, 'path steps');
    }
    const sourceContexts = page.locator('.lab-source-context');
    assert(await sourceContexts.count() > 0, 'on-page source context');
    await sourceContexts.first().locator('summary').click();
    assert(/^>\s+\d+\s+/m.test(await sourceContexts.first().locator('pre').innerText()), 'source context line numbers and match marker');
    await page.getByText('复现命令与回归输出', { exact: true }).click();
    assert((await page.locator('.lab-path pre').innerText()).length > 20, 'test evidence');
    await page.getByText('复现命令与回归输出', { exact: true }).click();
    await page.getByRole('tab').first().click();
    report.checks.push('three path tabs / line-numbered source context / local test evidence');
    await page.locator('#ask-input').fill('当前有哪些高优先级告警？');
    await page.locator('#ask-form button').click();
    await page.waitForFunction(() => document.querySelectorAll('#ask-messages .assistant').length > 1);
    assert((await page.locator('#ask-messages .assistant').last().innerText()).includes('High'), 'specific question routing');
    assert(lastAskRequest && lastAskRequest.useModel === false, 'homepage status question must request structured facts');
    report.checks.push('structured question through browser');
    await page.locator('.nav-item[href="#ai"]').click();
    await page.waitForFunction(() => document.querySelector('#workspace-view h1')?.textContent === '状态问答与云端审查通道');
    const aiText = await page.locator('#workspace-view').innerText();
    assert(aiText.includes('结构化状态问答'), 'structured status workspace');
    assert(aiText.includes('云端审查通道'), 'cloud review channel status');
    report.checks.push('AI workspace status boundary');
    const workspaces = [
      { hash: '#projects', title: '项目管理', paths: ['/api/v1/projects', '/api/v1/contracts', '/api/v1/capabilities'] },
      { hash: '#collection', title: '创建采集任务', paths: ['/api/v1/collection', '/api/v1/projects', '/api/v1/capabilities'] },
      { hash: '#scan', title: '创建扫描任务', paths: ['/api/v1/analysis', '/api/v1/scans', '/api/v1/capabilities'] },
      { hash: '#tasks', title: '任务中心', paths: ['/api/v1/tasks'] },
      { hash: '#findings-view', title: '漏洞中心', paths: ['/api/v1/findings'] },
      { hash: '#finding', title: '漏洞详情', paths: ['/api/v1/findings'] },
      { hash: '#permissions', title: '权限与业务模型', paths: ['/api/v1/analysis', '/api/v1/rules', '/api/v1/invariants'] },
      { hash: '#replay', title: '调用轨迹和重放', paths: ['/api/v1/replay', '/api/v1/evidence'] },
      { hash: '#dynamic', title: '动态检查', paths: ['/api/campaign'] },
      { hash: '#reverse', title: '代码查看', paths: ['/api/v1/bytecode', '/api/v1/decompile', '/api/campaign'] },
      { hash: '#ai', title: '状态问答与云端审查通道', paths: ['/api/status', '/api/v1/reviews/audit', '/api/health'] },
    ];
    for (const workspace of workspaces) {
      const before = report.apiReads.length;
      await page.locator(`.nav-item[href="${workspace.hash}"]`).click();
      await page.waitForFunction((expected) => document.querySelector('#workspace-view h1')?.textContent === expected, workspace.title);
      assert(await page.locator('#workspace-view').isVisible(), `${workspace.hash} workspace visibility`);
      const reads = report.apiReads.slice(before).map((url) => new URL(url).pathname);
      for (const path of workspace.paths) assert(reads.includes(path), `${workspace.hash} must read ${path}`);
      assert((await page.locator('#workspace-view').innerText()).trim().length > workspace.title.length, `${workspace.hash} must render API state or an explicit empty/error state`);
      if (workspace.hash === '#scan') {
        assert(await page.locator('#workspace-view input[name="sourcePath"]').getAttribute('required') !== null, 'scan source bundle path is required');
        assert(await page.locator('#workspace-view input[name="dependencyPath"]').count() === 1, 'scan dependency bundle is optional');
        assert(await page.locator('#workspace-view input[name="contractId"]').count() === 0, 'scan form must not send unsupported contractId');
      }
    }
    await page.locator('#workspace-view input[name="question"]').fill('当前任务是什么？');
    await page.locator('#workspace-view form[data-ai-form] button[type="submit"]').click();
    await page.waitForFunction(() => document.querySelectorAll('#workspace-ai-messages .assistant').length > 1);
    assert(lastAskRequest && lastAskRequest.useModel === false, 'AI workspace status question must request structured facts');
    report.checks.push('all workspace pages read their backing API and show a real state');
    await page.locator('.nav-item[href="#findings-view"]').click();
    await page.waitForFunction(() => document.querySelector('#workspace-view h1')?.textContent === '漏洞中心');
    assert(await page.locator('#workspace-finding-triage-status').count() === 1, 'finding list includes a separate manual triage filter');
    assert(await page.locator('#workspace-findings-export').count() === 1, 'finding list can export loaded rows');
    const findingLink = page.locator('#workspace-view a[href^="#finding/"]').first();
    if (await findingLink.count()) {
      const before = report.apiReads.length;
      await findingLink.click();
      await page.waitForSelector('#workspace-view .workspace-definition');
      const reads = report.apiReads.slice(before).map((url) => new URL(url).pathname);
      assert(reads.some((path) => /^\/api\/v1\/findings\//.test(path)), 'finding detail must fetch the selected finding');
      assert(reads.includes('/api/v1/evidence'), 'finding detail must fetch evidence');
      assert(await page.locator('#workspace-view form[data-finding-triage]').count() === 1, 'finding detail includes durable triage controls');
      assert(await page.locator('#workspace-view form[data-finding-triage] textarea[name="note"]').count() === 1, 'finding triage can append an auditable note');
      report.checks.push('selected finding detail reads its record and evidence');
    }
    await page.locator('.nav-item[href="#tasks"]').click();
    await page.waitForFunction(() => document.querySelector('#workspace-view h1')?.textContent === '任务中心');
    const beforeTaskDetail = report.apiReads.length;
    const taskDetailLink = page.locator('#workspace-view .workspace-table a[href="#task/ui-operator-task"]');
    assert(await taskDetailLink.count() === 1, 'task list exposes a direct details link');
    await taskDetailLink.click();
    await page.waitForSelector('#workspace-view .workspace-definition');
    assert(report.apiReads.slice(beforeTaskDetail).some((url) => /^\/api\/v1\/tasks\//.test(new URL(url).pathname)), 'task detail must fetch the selected task');
    report.checks.push('task list opens selected task detail and reads its record');
    await page.waitForSelector('#workspace-view .task-operator-actions [data-task-action="pause"]');
    await page.locator('#workspace-view [data-task-action="pause"]').click();
    await page.waitForSelector('#workspace-view .task-operator-actions [data-task-action="resume"]');
    await page.locator('#workspace-view [data-task-action="resume"]').click();
    await page.waitForSelector('#workspace-view .task-operator-actions [data-task-action="cancel"]');
    await page.locator('#workspace-view [data-task-action="cancel"]').click();
    await page.waitForFunction(() => document.querySelector('#workspace-view .workspace-state')?.textContent === '已取消');
    assert(JSON.stringify(taskActions.map(({ action }) => action)) === JSON.stringify(['pause', 'resume', 'cancel']), 'task detail supports pause, resume, then cancel');
    assert(taskActions.every((item, index) => item.revision === 10 + index), 'each task action uses the refreshed revision');
    assert(taskActions.every((item) => item.reason), 'each task action includes an audit reason');
    report.checks.push('task detail pause / resume / cancel controls use current revision');
    for (const [hash, title, boundaryText] of [
      ['#dynamic', '动态检查', '标记为“未执行”'],
      ['#reverse', '代码查看', '生成内容可能不完整'],
    ]) {
      await page.locator(`.nav-item[href="${hash}"]`).click();
      await page.waitForFunction((expected) => document.querySelector('#workspace-view h1')?.textContent === expected, title);
      assert(await page.locator('#workspace-view').isVisible(), `${hash} workspace visibility`);
      assert((await page.locator('.workspace-boundary').innerText()).includes(boundaryText), `${hash} report-only boundary`);
      assert(await page.locator('#workspace-view form[data-resource-form]').count() === 1, `${hash} must expose its supported task form`);
      assert(await page.locator('#workspace-view .workspace-table th').count() > 0 || await page.locator('#workspace-view .workspace-status').count() > 0, `${hash} visible result or empty state`);
      const plainCopy = await page.locator('#workspace-view .workspace-head, #workspace-view .workspace-boundary').allTextContents();
      assert(!/反汇编|反编译|bytecode|decompilation|\bEVM\b|\bRPC\b|\bAPI\b/i.test(plainCopy.join(' ')), `${hash} visible copy should avoid specialist terms`);
      if (hash === '#reverse') assert(!/Heimdall|opcode|高层引擎|伪码|统一 IR|PC 核对/i.test((await page.locator('#workspace-view').innerText())), 'code view should describe validation without specialist tool jargon');
      const evidenceDetails = page.locator('#workspace-view details.workspace-json');
      if (await evidenceDetails.count()) assert(!(await evidenceDetails.first().evaluate((element) => element.open)), `${hash} evidence must start collapsed`);
      if (hash === '#reverse') {
        assert((await page.locator('#workspace-view').innerText()).includes('生成内容可能不完整或不准确'), 'code view source readability boundary');
        const beforeArtifactRead = report.apiReads.length;
        const pseudoButton = page.getByRole('button', { name: '查看还原代码' }).first();
        assert(await pseudoButton.count() === 1, 'registered pseudo-code artifact can be opened');
        await pseudoButton.click();
        const pseudoContent = page.locator('#reverse-artifact-ui-reverse-artifact-0');
        await pseudoContent.waitFor({ state: 'visible' });
        assert((await pseudoContent.innerText()).includes('<img src=x onerror=alert(1)> contract Recovered {}'), 'artifact is rendered as literal text');
        assert(await pseudoContent.locator('img').count() === 0, 'artifact text must not execute as markup');
        const artifactReads = report.apiReads.slice(beforeArtifactRead).map((url) => new URL(url).pathname);
        assert(artifactReads.includes(`/api/v1/tasks/ui-reverse-artifact/artifacts/${'a'.repeat(64)}/content`), 'artifact is fetched only on explicit request');
        assert(!artifactReads.some((path) => path.includes('attempt-') || path.includes('work/')), 'artifact read request does not expose file paths');
        await page.getByRole('button', { name: '查看代码结构' }).first().click();
        const irContent = page.locator('#reverse-artifact-ui-reverse-artifact-1');
        await irContent.waitFor({ state: 'visible' });
        assert((await irContent.innerText()).includes('{"functions":[]}'), 'unified code artifact is readable');
        const form = page.locator('#workspace-view form[data-resource-form="decompile"]');
        await form.locator('textarea[name="runtimeBytecode"]').fill('0x60 00');
        await form.locator('button[type="submit"]').click();
        await page.waitForFunction(() => document.querySelector('#workspace-view [data-form-result]')?.dataset.state === 'ready');
        const submission = workspaceSubmissions.at(-1);
        assert(submission?.pathname === '/api/v1/decompile' && submission.body.runtimeBytecode === '0x6000', 'code form must queue normalized code through the decompile resource');
        report.checks.push('code view submits real bounded decompile task input');
      } else {
        const form = page.locator('#workspace-view form[data-resource-form="scan"]');
        await form.locator('input[name="sourcePath"]').fill('/work/ui-check-source.json');
        await form.locator('button[type="submit"]').click();
        await page.waitForFunction(() => document.querySelector('#workspace-view [data-form-result]')?.dataset.state === 'ready');
        const submission = workspaceSubmissions.at(-1);
        assert(submission?.pathname === '/api/v1/tasks' && submission.body.type === 'local-source-analysis' && submission.body.payload.sourcePath === '/work/ui-check-source.json', 'dynamic form must queue a source analysis that runs a supported local harness');
        report.checks.push('dynamic view submits source analysis and only claims supported local test coverage');
      }
    }
    await page.locator('.nav-item[href="#overview"]').click();
    await page.waitForFunction(() => document.querySelector('.nav-item.active')?.hash === '#overview');
    report.checks.push('dynamic and code views show evidence limits and supported task entry points');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('.operations-nav').evaluate((element) => { element.open = false; });
    for (const workspace of workspaces) {
      await page.evaluate((hash) => { location.hash = hash; }, workspace.hash);
      await page.waitForFunction((expected) => document.querySelector('#workspace-view h1')?.textContent === expected, workspace.title);
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const layout = await page.evaluate(() => ({ route: location.hash, viewport: innerWidth, width: document.documentElement.scrollWidth, navHeight: document.querySelector('.sidebar').getBoundingClientRect().height }));
      report.viewports.push(layout);
      assert(layout.width <= layout.viewport, `workspace overflow at 390: ${workspace.hash}`);
      assert(layout.navHeight < 160, `mobile navigation too tall at ${workspace.hash}`);
    }
    report.checks.push('all data workspaces fit the narrow mobile viewport');
    await page.evaluate(() => { location.hash = '#overview'; });
    await page.waitForFunction(() => document.querySelector('#workspace-view').hidden);
    for (const width of [1440, 768, 390]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 1100 });
      await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
      await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      const layout = await page.evaluate(() => ({ viewport: innerWidth, width: document.documentElement.scrollWidth, navHeight: document.querySelector('.sidebar').getBoundingClientRect().height }));
      report.viewports.push(layout);
      assert(layout.width <= layout.viewport, `page overflow at ${width}`);
      if (width === 390) assert(layout.navHeight < 160, 'mobile navigation too tall');
      assert(await page.locator('.nav-item.active').getAttribute('href') === '#overview', 'navigation must match visible overview');
      if (width === 390) {
        const summary = await page.locator('#stage-summary').boundingBox();
        assert(summary && summary.y + summary.height <= 844, 'mobile workflow summary should fit in the first viewport');
      }
      await page.screenshot({ path: join(output, `web-${width === 1440 ? 'desktop' : width === 390 ? 'mobile' : 'tablet'}.png`), fullPage: width !== 390 });
    }
    assert(!report.errors.length && !report.failedRequests.length, 'browser runtime / request error');
    report.state = 'passed';
  } catch (error) { report.state = 'failed'; report.failure = error.message; process.exitCode = 1; }
  finally {
    await browser.close();
    await writeFile(join(output, 'ui-check.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify(report));
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
