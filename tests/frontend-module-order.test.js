import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

/**
 * 前端模块的顶层求值顺序回归。
 *
 * 背景：ES 模块按书写顺序求值。若文件的顶层「启动代码」调用了一个函数，
 * 而该函数读到的 `const` / `let` 声明写在启动代码之后，启动那一行会撞上
 * 暂时性死区（TDZ）并抛 ReferenceError。模块求值就此中止 —— 页面上所有
 * 交互都失效，但后端接口、单元测试和静态检查全绿，看起来一切正常。
 *
 * 真实踩过的例子：`web/app.js` 的启动段调用 `startCollectionPolling()`，
 * 它读 `COLLECTION_POLL_INTERVAL_MS`（声明在文件更靠后的位置）。结果整个
 * 前端只渲染出静态 HTML，链上采集开关一直显示「读取开关状态失败」，
 * 而后端 `/api/v1/chain-collection/status` 返回 200。
 *
 * 这里用真实求值来钉死它：把模块顶层代码放进一个函数里执行，让
 * ReferenceError 以真实异常的形式冒出来，而不是靠正则猜声明位置。
 */

const appSource = await readFile(new URL('../web/app.js', import.meta.url), 'utf8');

/**
 * app.js 没有 export、没有顶层 await，也没有 import.meta，
 * 因此整个文件可以直接放进一个函数体求值 —— `let` / `const` 的 TDZ
 * 语义与模块完全一致，而 ReferenceError 会以真实异常冒出来。
 *
 * `import` 语句要先剥掉：`new Function` 的函数体不是模块，装不下 import。
 * 被导入的符号通过参数注入，值取不到也无妨 —— 我们要验的是求值顺序，
 * 不是各视图的 DOM 行为。
 */
function evaluateTopLevel(source) {
  const importLines = source.split('\n').filter((line) => !/^\s*import\b/.test(line));
  const body = new Function(
    'overviewView', 'protocolView', 'findingView', 'executionView', 'corpusView', 'getJSON',
    `
    // 顶层的 DOM 依赖用空实现顶住：我们要验的是「求值顺序」，
    // 不是 DOM 行为本身。真实 DOM 行为由浏览器端和 ui-check 覆盖。
    const noop = () => {};
    const fakeElement = new Proxy({}, {
      get(_target, prop) {
        if (prop === 'classList') return { add: noop, remove: noop, toggle: noop, contains: () => false };
        if (prop === 'style') return {};
        if (prop === 'dataset') return {};
        if (prop === 'children') return [];
        if (prop === 'innerHTML' || prop === 'textContent' || prop === 'value' || prop === 'href' || prop === 'download') return '';
        if (prop === 'getAttribute') return () => null;
        if (prop === 'setAttribute') return noop;
        if (prop === 'removeAttribute') return noop;
        if (prop === 'addEventListener') return noop;
        if (prop === 'removeEventListener') return noop;
        if (prop === 'querySelectorAll') return () => [];
        if (prop === 'querySelector') return () => fakeElement;
        if (prop === 'getBoundingClientRect') return () => ({ top: 0, left: 0, width: 0, height: 0 });
        if (prop === 'append' || prop === 'appendChild' || prop === 'remove' || prop === 'replaceChildren'
          || prop === 'insertBefore' || prop === 'click' || prop === 'focus' || prop === 'scrollIntoView') return noop;
        if (prop === 'parentElement' || prop === 'parentNode' || prop === 'closest') return null;
        if (prop === 'offsetWidth' || prop === 'offsetHeight' || prop === 'scrollTop' || prop === 'scrollHeight') return 0;
        return undefined;
      },
      set() { return true; },
    });
    const document = {
      querySelector: () => fakeElement,
      querySelectorAll: () => [],
      getElementById: () => fakeElement,
      createElement: () => fakeElement,
      createDocumentFragment: () => fakeElement,
      addEventListener: noop,
      hidden: false,
    };
    const window = { addEventListener: noop };
    const addEventListener = noop;
    const setInterval = () => 0;
    const clearInterval = noop;
    const setTimeout = () => 0;
    const clearTimeout = noop;
    const requestAnimationFrame = () => 0;
    const fetch = () => Promise.reject(new Error('network disabled in module-eval test'));
    const AbortSignal = { timeout: () => ({}) };
    const location = { href: 'http://127.0.0.1/', hash: '' };
    const history = { replaceState: noop };
    const EventSource = class { addEventListener() {} };
    // 顶层会启动若干异步任务（fetch / EventSource / 定时器）。
    // 这里把它们产生的拒绝就地吞掉，否则未处理的 rejection 会在
    // 测试结束后才冒出来，污染下一个用例的结果。
    const __results = [];
    ${importLines.join('\n')}
    return __results;
  `,
  );
  const emptyModule = {};
  return body(emptyModule, emptyModule, emptyModule, emptyModule, emptyModule, async () => ({}));
}

test('app.js 的顶层求值不会因为暂时性死区中断', async (t) => {
  // 顶层会启动 fetch / EventSource 之类的异步任务，它们的拒绝会在
  // 用例结束后才冒出来，污染后续用例的结果。这里就地吞掉。
  const rejections = [];
  const collect = (reason) => rejections.push(reason);
  process.on('unhandledRejection', collect);
  t.after(() => process.off('unhandledRejection', collect));

  let thrown = null;
  try {
    evaluateTopLevel(appSource);
  } catch (error) {
    thrown = error;
  }
  // 让微任务队列里的拒绝先落定，再恢复默认处理。
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  // 顶层语句里引用了模块内声明的符号（state、$、renderSnapshot 等），
  // 这些在真实模块里是同作用域，整体求值时同样存在。
  // 因此这里不追求整段执行成功，只要求：一旦抛出，
  // 必须是「引用了未声明符号」这类必然的失败，而不是暂时性死区。
  if (thrown) {
    const isTDZ = thrown instanceof ReferenceError
      && /Cannot access '[^']+' before initialization/.test(String(thrown.message));
    assert.equal(
      isTDZ,
      false,
      `app.js 顶层代码在声明之前就读到了变量（暂时性死区）：${thrown.message}\n`
      + '这会让整个模块求值中止，页面只剩静态 HTML，所有交互失效。\n'
      + '顶层声明必须排在顶层启动代码之前。',
    );
  }

  // 顶层调用 async 函数时，函数体里的暂时性死区错误不会同步抛出，
  // 而是变成「被拒绝的 promise」。没人接住就是 unhandledRejection，
  // 在浏览器里表现为 pageerror —— 整个模块交互全失效，但同步求值看着正常。
  const tdzRejections = rejections.filter((reason) => reason instanceof ReferenceError
    && /Cannot access '[^']+' before initialization/.test(String(reason.message)));
  assert.deepEqual(
    tdzRejections.map((reason) => reason.message),
    [],
    'app.js 顶层调用在常量初始化前读到了模块级常量（暂时性死区）：'
    + `${tdzRejections.map((reason) => reason.message).join('；')}\n`
    + '这类错误发生在 async 函数里，会变成未被接住的 promise 拒绝：'
    + '页面只剩静态 HTML，所有交互失效，而后端接口与单元测试全绿。',
  );
});

test('app.js 的链上采集状态变量声明在启动代码之前', () => {
  // 显式钉住这次的直接受害者：startCollectionPolling() 读的常量。
  const declaration = appSource.indexOf('const COLLECTION_POLL_INTERVAL_MS');
  // 只找真正的调用点，不把函数定义算进去：
  // 调用是 `startCollectionPolling();`，定义是 `function startCollectionPolling() {`。
  const call = appSource.search(/^startCollectionPolling\(\);$/m);
  assert.ok(declaration !== -1, '应当声明 COLLECTION_POLL_INTERVAL_MS');
  assert.ok(call !== -1, '应当调用 startCollectionPolling()');
  assert.ok(
    declaration < call,
    `COLLECTION_POLL_INTERVAL_MS 声明在第 ${declaration} 行，`
    + `startCollectionPolling() 调用在第 ${call} 行：声明必须在前，否则启动即撞上暂时性死区。`,
  );
});

test('app.js 的模块级状态变量各只声明一次', () => {
  for (const name of ['COLLECTION_POLL_INTERVAL_MS', 'COLLECTION_STATE_CLASS', 'collectionPollTimer', 'collectionBusy']) {
    const matches = appSource.match(new RegExp(`^(?:const|let|var)\\s+${name}\\b`, 'gm')) || [];
    assert.equal(matches.length, 1, `${name} 应当只声明一次，实际 ${matches.length} 次`);
  }
});

test('工作区常量声明在首次路由渲染之前', () => {
  // 真实踩过的例子：顶层的 `routeWorkspace();` 读到了还没初始化的
  // `WORKSPACE_FLAG_CLASS`（workspaceFrame() 会同步读它），
  // 撞上暂时性死区，模块求值中止 —— 页面只剩静态 HTML。
  // 注意 routeWorkspace() 是 async 函数，所以这个错误不会同步抛出，
  // 只会变成未被接住的 promise 拒绝；必须靠顺序断言 + 上一条用例兜住。
  const call = appSource.search(/^routeWorkspace\(\);$/m);
  assert.ok(call !== -1, '应当有顶层的 routeWorkspace() 首次渲染调用');
  for (const name of [
    'WORKSPACE_FLAG_TEXT',
    'WORKSPACE_FLAG_CLASS',
    'WORKSPACE_FLAG_ICON',
    'WORKSPACE_STATE_KIND',
    'WORKSPACE_EVIDENCE_LABELS',
    'WORKSPACE_SEVERITY_KEYS',
    'WORKSPACE_SEVERITY_TEXT',
    'WORKSPACE_OFFLINE_HINT',
  ]) {
    const declaration = appSource.search(new RegExp(`^(?:const|let|var)\\s+${name}\\b`, 'm'));
    assert.ok(declaration !== -1, `应当声明 ${name}`);
    assert.ok(
      declaration < call,
      `${name} 声明在第 ${declaration} 行，routeWorkspace() 调用在第 ${call} 行：`
      + '声明必须在前，否则首次渲染就撞上暂时性死区。',
    );
  }
});
