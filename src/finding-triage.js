export const FINDING_TRIAGE_STATUSES = Object.freeze([
  'unreviewed', 'in_review', 'false_positive', 'fixed', 'accepted_risk',
]);

const PATCH_FIELDS = new Set(['triageStatus', 'assignee', 'tags', 'note']);
const REASON_REQUIRED_STATUSES = new Set(['false_positive', 'fixed', 'accepted_risk']);

export function normalizeFindingTriagePatch(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('处置内容必须是对象');
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError('处置内容必须是普通对象');

  const keys = Object.keys(input);
  if (!keys.length) throw new TypeError('处置内容不能为空');
  for (const key of keys) if (!PATCH_FIELDS.has(key)) throw new TypeError(`不支持的处置字段：${key}`);

  const patch = {};
  if (Object.hasOwn(input, 'triageStatus')) {
    if (!FINDING_TRIAGE_STATUSES.includes(input.triageStatus)) throw new TypeError('处置状态无效');
    patch.triageStatus = input.triageStatus;
  }
  if (Object.hasOwn(input, 'assignee')) {
    if (input.assignee !== null && typeof input.assignee !== 'string') throw new TypeError('指派人必须是字符串或 null');
    if (input.assignee === null) patch.assignee = null;
    else {
      const assignee = input.assignee.trim();
      if (!assignee || assignee.length > 200) throw new TypeError('指派人长度必须为 1..200');
      patch.assignee = assignee;
    }
  }
  if (Object.hasOwn(input, 'tags')) {
    if (!Array.isArray(input.tags) || input.tags.length > 30) throw new TypeError('标签必须是最多 30 项的数组');
    const tags = [];
    const seen = new Set();
    for (const value of input.tags) {
      if (typeof value !== 'string') throw new TypeError('标签必须是字符串');
      const tag = value.trim();
      if (!tag || tag.length > 64) throw new TypeError('标签长度必须为 1..64');
      if (!seen.has(tag)) { seen.add(tag); tags.push(tag); }
    }
    patch.tags = tags;
  }
  if (Object.hasOwn(input, 'note')) {
    if (typeof input.note !== 'string') throw new TypeError('备注必须是字符串');
    const note = input.note.trim();
    if (!note || note.length > 4000) throw new TypeError('备注长度必须为 1..4000');
    patch.note = note;
  }
  if (REASON_REQUIRED_STATUSES.has(patch.triageStatus) && !patch.note) {
    throw new TypeError('此处置状态需要同时填写原因');
  }
  return patch;
}
