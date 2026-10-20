import { createHash, randomUUID } from 'node:crypto';

export const REVIEW_MANIFEST_SCHEMA_VERSION = 1;
export const REVIEW_SEVERITIES = Object.freeze(['P0', 'P1', 'P2', 'P3']);

const SECRET_KEY = /(?:api[_-]?key|access[_-]?token|authorization|auth|password|passwd|private[_-]?key|mnemonic|secret|rpc[_-]?url|bearer)(?:$|[_-])/i;
const SECRET_ASSIGNMENT = /((?:api[_-]?key|access[_-]?token|authorization|password|passwd|private[_-]?key|mnemonic|secret|rpc[_-]?url)\s*[:=]\s*)([^\s,;&]+)/gi;
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~-]+/gi;
// Redact credential formats that can appear in an otherwise ordinary diff
// without a sensitive field name. Keep this list deliberately format-bound so
// Solidity addresses, hashes and ordinary prose are not blanket-redacted.
const PEM_PRIVATE_KEY = /-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/gi;
const JWT_TOKEN = /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const KNOWN_TOKEN = /\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b/g;
const URL_USERINFO = /(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi;
const MAX_TEXT = 200_000;

function isSecretKey(key) {
  if (typeof key !== 'string' || key.length === 0) return false;
  // Normalize camelCase boundaries so compound fields such as clientApiKey
  // and accessTokenValue receive the same treatment as snake_case fields.
  const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2');
  return SECRET_KEY.test(normalized);
}

function fail(message, Type = TypeError) {
  throw new Type(message);
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
}

function assertText(value, label, { optional = false, max = MAX_TEXT } = {}) {
  if (value === undefined && optional) return undefined;
  if (typeof value !== 'string' || value.length < 1 || value.length > max) fail(`${label} must be a non-empty string of at most ${max} characters`);
  return value;
}

function assertInteger(value, label, { optional = false, min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (value === undefined && optional) return undefined;
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(`${label} must be a safe integer in ${min}..${max}`);
  return value;
}

function cloneAndRedact(value, key = '', state = { count: 0 }, seen = new WeakSet()) {
  if (typeof value === 'string') {
    if (isSecretKey(key)) {
      state.count += 1;
      return '[REDACTED]';
    }
    let result = value;
    result = result.replace(BEARER_TOKEN, () => { state.count += 1; return 'Bearer [REDACTED]'; });
    result = result.replace(SECRET_ASSIGNMENT, (_match, prefix) => { state.count += 1; return `${prefix}[REDACTED]`; });
    result = result.replace(PEM_PRIVATE_KEY, () => { state.count += 1; return '[REDACTED PRIVATE KEY]'; });
    result = result.replace(JWT_TOKEN, () => { state.count += 1; return '[REDACTED JWT]'; });
    result = result.replace(KNOWN_TOKEN, () => { state.count += 1; return '[REDACTED TOKEN]'; });
    result = result.replace(URL_USERINFO, (_match, scheme) => { state.count += 1; return `${scheme}[REDACTED]@`; });
    return result;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('manifest data numbers must be finite');
    return value;
  }
  if (typeof value !== 'object') fail('manifest data must contain only JSON values');
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) if (!Object.hasOwn(value, index)) fail('manifest data must not contain sparse arrays');
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail('manifest data must contain only plain JSON objects');
    if (Reflect.ownKeys(value).some((property) => typeof property !== 'string')) fail('manifest data must not contain symbol keys');
  }
  if (seen.has(value)) fail('manifest data must not contain cycles');
  seen.add(value);
  let result;
  if (Array.isArray(value)) result = value.map((item) => cloneAndRedact(item, key, state, seen));
  else {
    result = {};
    for (const [childKey, childValue] of Object.entries(value)) result[childKey] = cloneAndRedact(childValue, childKey, state, seen);
  }
  seen.delete(value);
  return result;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  return value;
}

function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(canonicalize(value))).digest('hex');
}

function freezeDeep(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) freezeDeep(child, seen);
  return Object.freeze(value);
}

function repoPath(value, label) {
  const path = assertText(value, label, { max: 500 });
  if (path.startsWith('/') || path.includes('\\') || /^[A-Za-z]:/.test(path) || path.split('/').includes('..')) fail(`${label} must be a repository-relative path`);
  return path;
}

function normalizeChangedFiles(files) {
  if (!Array.isArray(files)) fail('changedFiles must be an array');
  return files.map((file, index) => {
    assertObject(file, `changedFiles[${index}]`);
    const normalized = { path: repoPath(file.path, `changedFiles[${index}].path`) };
    if (file.status !== undefined) normalized.status = assertText(file.status, `changedFiles[${index}].status`, { max: 40 });
    for (const key of ['additions', 'deletions']) if (file[key] !== undefined) normalized[key] = assertInteger(file[key], `changedFiles[${index}].${key}`);
    if (file.contentSha256 !== undefined) {
      normalized.contentSha256 = assertText(file.contentSha256, `changedFiles[${index}].contentSha256`, { max: 128 });
    }
    return normalized;
  });
}

function normalizeTests(tests) {
  if (!Array.isArray(tests)) fail('tests must be an array');
  return tests.map((test, index) => {
    assertObject(test, `tests[${index}]`);
    const normalized = { name: assertText(test.name, `tests[${index}].name`, { max: 300 }), status: assertText(test.status, `tests[${index}].status`, { max: 30 }) };
    if (test.command !== undefined) normalized.command = assertText(test.command, `tests[${index}].command`, { max: 2000 });
    if (test.required !== undefined) {
      if (typeof test.required !== 'boolean') fail(`tests[${index}].required must be boolean`);
      normalized.required = test.required;
    }
    if (test.output !== undefined) normalized.output = assertText(test.output, `tests[${index}].output`);
    return normalized;
  });
}

function normalizeDependencies(dependencies) {
  if (!Array.isArray(dependencies)) fail('dependencies must be an array');
  return dependencies.map((dependency, index) => {
    assertObject(dependency, `dependencies[${index}]`);
    const normalized = { name: assertText(dependency.name, `dependencies[${index}].name`, { max: 300 }) };
    for (const key of ['from', 'to', 'reason']) if (dependency[key] !== undefined) normalized[key] = assertText(dependency[key], `dependencies[${index}].${key}`, { max: 2000 });
    if (dependency.changed !== undefined) {
      if (typeof dependency.changed !== 'boolean') fail(`dependencies[${index}].changed must be boolean`);
      normalized.changed = dependency.changed;
    }
    return normalized;
  });
}

export function createReviewManifest({
  manifestId = randomUUID(),
  createdAt = new Date().toISOString(),
  baseRevision = null,
  headRevision = null,
  changedFiles = [],
  diff = '',
  tests = [],
  dependencies = [],
  risks = [],
  environment = {},
  localModel = null,
  reviewRound = 0,
} = {}) {
  assertText(manifestId, 'manifestId', { max: 200 });
  assertText(createdAt, 'createdAt', { max: 80 });
  if (!Number.isFinite(Date.parse(createdAt))) fail('createdAt must be an ISO timestamp');
  if (baseRevision !== null) assertText(baseRevision, 'baseRevision', { max: 200 });
  if (headRevision !== null) assertText(headRevision, 'headRevision', { max: 200 });
  if (typeof diff !== 'string' || diff.length > 4_000_000) fail('diff must be a string of at most 4000000 characters');
  if (!Array.isArray(risks)) fail('risks must be an array');
  const state = { count: 0 };
  const safeEnvironment = cloneAndRedact(environment, 'environment', state);
  const safeRisks = cloneAndRedact(risks, 'risks', state);
  const safeLocalModel = localModel === null ? null : cloneAndRedact(localModel, 'localModel', state);
  const safeDiff = cloneAndRedact(diff, 'diff', state);
  const safeTests = cloneAndRedact(tests, 'tests', state);
  const safeDependencies = cloneAndRedact(dependencies, 'dependencies', state);
  const body = {
    schemaVersion: REVIEW_MANIFEST_SCHEMA_VERSION,
    manifestId,
    createdAt,
    baseRevision,
    headRevision,
    changedFiles: normalizeChangedFiles(changedFiles),
    diff: safeDiff,
    diffSha256: sha256(safeDiff),
    tests: normalizeTests(safeTests),
    dependencies: normalizeDependencies(safeDependencies),
    risks: safeRisks,
    environment: safeEnvironment,
    localModel: safeLocalModel,
    reviewRound: assertInteger(reviewRound, 'reviewRound', { max: 100 }),
    privacy: { redacted: state.count > 0, redactionCount: state.count },
  };
  return freezeDeep({ ...body, manifestSha256: sha256(body) });
}

export function verifyReviewManifest(manifest) {
  try {
    assertObject(manifest, 'manifest');
    const allowed = new Set(['schemaVersion', 'manifestId', 'createdAt', 'baseRevision', 'headRevision', 'changedFiles', 'diff', 'diffSha256', 'tests', 'dependencies', 'risks', 'environment', 'localModel', 'reviewRound', 'privacy', 'manifestSha256']);
    if (Reflect.ownKeys(manifest).some((key) => typeof key !== 'string' || !allowed.has(key)) || Object.keys(manifest).length !== allowed.size) return false;
    const { manifestSha256, ...body } = manifest;
    return typeof manifestSha256 === 'string' && /^[a-f0-9]{64}$/.test(manifestSha256) && sha256(body) === manifestSha256 && sha256(manifest.diff) === manifest.diffSha256;
  } catch {
    return false;
  }
}

function changedPathSet(manifest) {
  return new Set(manifest.changedFiles.map((file) => file.path));
}

export function validateCloudReview(review, manifest) {
  assertObject(review, 'review');
  assertObject(manifest, 'manifest');
  if (!verifyReviewManifest(manifest)) fail('review manifest hash is invalid');
  if (review.schemaVersion !== REVIEW_MANIFEST_SCHEMA_VERSION) fail('unsupported cloud review schemaVersion');
  if (review.manifestSha256 !== manifest.manifestSha256) fail('cloud review does not match the review manifest');
  if (!['allow', 'block', 'needs_changes'].includes(review.decision)) fail('cloud review decision is invalid');
  if (!Array.isArray(review.findings)) fail('cloud review findings must be an array');
  const paths = changedPathSet(manifest);
  const findingIds = new Set();
  const reviewRedactions = { count: 0 };
  const findings = review.findings.map((finding, index) => {
    assertObject(finding, `findings[${index}]`);
    const findingId = assertText(finding.findingId, `findings[${index}].findingId`, { max: 200 });
    if (findingIds.has(findingId)) fail(`duplicate findingId: ${findingId}`);
    findingIds.add(findingId);
    if (!REVIEW_SEVERITIES.includes(finding.severity)) fail(`findings[${index}].severity is invalid`);
    const normalized = {
      findingId,
      severity: finding.severity,
      title: cloneAndRedact(assertText(finding.title, `findings[${index}].title`, { max: 500 }), 'title', reviewRedactions),
      summary: cloneAndRedact(assertText(finding.summary, `findings[${index}].summary`, { max: 5000 }), 'summary', reviewRedactions),
    };
    if (finding.file !== undefined) {
      normalized.file = repoPath(finding.file, `findings[${index}].file`);
      if (!paths.has(normalized.file)) fail(`finding references an unchanged file: ${normalized.file}`);
    }
    if (finding.line !== undefined) normalized.line = assertInteger(finding.line, `findings[${index}].line`, { min: 1 });
    if (finding.confidence !== undefined) {
      if (typeof finding.confidence !== 'number' || !Number.isFinite(finding.confidence) || finding.confidence < 0 || finding.confidence > 1) fail(`findings[${index}].confidence must be 0..1`);
      normalized.confidence = finding.confidence;
    }
    if (finding.reproduction !== undefined) normalized.reproduction = cloneAndRedact(assertText(finding.reproduction, `findings[${index}].reproduction`, { max: 5000 }), 'reproduction', reviewRedactions);
    if (finding.requiredTests !== undefined) {
      if (!Array.isArray(finding.requiredTests) || finding.requiredTests.some((item) => typeof item !== 'string' || !item.trim())) fail(`findings[${index}].requiredTests must be non-empty strings`);
      normalized.requiredTests = finding.requiredTests.slice(0, 50).map((item) => cloneAndRedact(item.trim(), 'requiredTests', reviewRedactions));
    }
    if (finding.evidenceComplete !== undefined) {
      if (typeof finding.evidenceComplete !== 'boolean') fail(`findings[${index}].evidenceComplete must be boolean`);
      normalized.evidenceComplete = finding.evidenceComplete;
    }
    if (finding.blocking !== undefined) {
      if (typeof finding.blocking !== 'boolean') fail(`findings[${index}].blocking must be boolean`);
      normalized.blocking = finding.blocking;
    }
    if (finding.confidence === undefined) fail(`findings[${index}].confidence is required`);
    if (finding.file !== undefined && finding.line === undefined) fail(`findings[${index}].line is required when file is present`);
    if (finding.evidenceComplete === undefined) fail(`findings[${index}].evidenceComplete is required`);
    return normalized;
  });
  if (typeof review.evidenceComplete !== 'boolean') fail('cloud review evidenceComplete must be boolean');
  return freezeDeep({ schemaVersion: review.schemaVersion, manifestSha256: review.manifestSha256, decision: review.decision, evidenceComplete: review.evidenceComplete, findings, privacy: { redacted: reviewRedactions.count > 0, redactionCount: reviewRedactions.count } });
}

export function evaluateMergeGate({ manifest, review, checks = [] } = {}) {
  const normalizedReview = validateCloudReview(review, manifest);
  if (!Array.isArray(checks)) fail('checks must be an array');
  const reasons = [];
  if (normalizedReview.decision !== 'allow') reasons.push({ code: 'cloud_review_not_approved', decision: normalizedReview.decision });
  if (!manifest.tests.some((test) => test.required !== false)) reasons.push({ code: 'required_test_evidence_missing' });
  for (const test of manifest.tests) {
    if (test.required !== false && test.status !== 'passed') reasons.push({ code: 'required_test_failed', name: test.name, status: test.status });
  }
  for (const check of checks) {
    assertObject(check, 'check');
    const name = assertText(check.name, 'check.name', { max: 300 });
    if (check.required !== false && check.status !== 'passed') reasons.push({ code: 'required_check_failed', name, status: check.status || 'missing' });
  }
  if (!normalizedReview.evidenceComplete) reasons.push({ code: 'evidence_incomplete' });
  for (const finding of normalizedReview.findings) {
    if (finding.severity === 'P0' || finding.severity === 'P1' || finding.blocking === true) reasons.push({ code: 'blocking_finding', findingId: finding.findingId, severity: finding.severity });
    if (finding.evidenceComplete === false) reasons.push({ code: 'finding_evidence_incomplete', findingId: finding.findingId });
  }
  for (const dependency of manifest.dependencies) {
    if (dependency.changed === true && !dependency.reason) reasons.push({ code: 'unexplained_dependency_change', name: dependency.name });
  }
  return { allowed: reasons.length === 0, status: reasons.length === 0 ? 'allowed' : 'blocked', reasons, manifestSha256: manifest.manifestSha256 };
}
