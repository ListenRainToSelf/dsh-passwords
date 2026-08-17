// F-25 回归测试：会话归属（sessionId 提取 / 枚举源清理 / 会话列表过滤）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SESSION_SCOPED_RE,
  extractSessionId,
  stripArchivedSessionIds,
  filterSessionItems,
} from '../src/permissions.js';

test('F-25：SESSION_SCOPED_RE 命中会读取/写入会话的 RPC，但不命中 create/list', () => {
  for (const m of ['history', 'prompt', 'respond', 'archive', 'delete', 'rename', 'retitle', 'title', 'resume', 'fork', 'truncate', 'export']) {
    assert.equal(SESSION_SCOPED_RE.test(`/api/session.${m}`), true, `session.${m} 应归属校验`);
    assert.equal(SESSION_SCOPED_RE.test(`/api/session/${m}`), true, `session/${m} 应归属校验`);
  }
  assert.equal(SESSION_SCOPED_RE.test('/api/session.create'), false, 'create 无源会话');
  assert.equal(SESSION_SCOPED_RE.test('/api/session.list'), false, 'list 单独过滤');
});

test('F-25：extractSessionId 提取顶层与嵌套 sessionId', () => {
  assert.equal(extractSessionId({ sessionId: 'session-1', prompt: {} }), 'session-1');
  assert.equal(extractSessionId({ args: { request: { sessionId: 's-2' } } }), 's-2');
  assert.equal(extractSessionId({ id: 'x' }), null, '无 sessionId 返回 null');
});

test('F-25：stripArchivedSessionIds 清空 archivedSessionIds 数组', () => {
  const obj = {
    workspaces: [{ id: 'w1', archivedSessionIds: ['s1', 's2'] }],
    keep: 'x',
  };
  const changed = stripArchivedSessionIds(obj);
  assert.equal(changed, true);
  assert.deepEqual(obj.workspaces[0].archivedSessionIds, []);
  assert.equal(obj.keep, 'x');
});

test('F-25：filterSessionItems 只保留自己拥有的会话（sessionId+cwd 条目）', () => {
  const owned = new Set(['s-own']);
  const tree = {
    result: {
      value: [
        { sessionId: 's-own', cwd: '/root/11', title: 'mine' },
        { sessionId: 's-other', cwd: '/root/21', title: 'theirs' },
        { sessionId: 's-admin', cwd: '/root/21', title: 'admin' },
      ],
    },
  };
  const out = filterSessionItems(tree, (id) => owned.has(id)) as typeof tree;
  const items = out.result.value as Array<{ sessionId: string }>;
  assert.deepEqual(items.map((i) => i.sessionId), ['s-own'], '只留下自己拥有的会话');
});
