// dsh-passwords 设置卡片：可折叠（与官方 PluginCard 同形态：header 按钮 +
// aria-expanded + 展开才渲染 body）。内容：
//   - 远程设置补丁：状态 + "重载补丁"按钮（任何登录用户可触发；补丁强制启用）
//   - 用户管理：改密/改名/子用户分配（主用户 admin 可管理所有，子用户只能改自己）
// 数据面：/api/dsh-passwords/*（网关注入的 JWT cookie 鉴权）。
import { createElement as h, useEffect, useState } from 'react';

export interface UserInfo {
  id: number;
  username: string;
  role: 'admin' | 'user';
  created_at: string;
  last_login_at: string | null;
}

export interface StateData {
  me: { username: string; role: 'admin' | 'user' };
  users: UserInfo[];
}

export interface PatchState {
  settingsHostMode: boolean;
  whitelist: boolean;
}

/** 与 host 侧一致的最小密码策略（本机提示用，最终以服务端校验为准） */
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;

function api<T>(path: string, body?: unknown): Promise<T> {
  return fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(async (res) => {
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new Error(data.error || `请求失败 (HTTP ${res.status})`);
    return data as T;
  });
}

function errText(error: unknown): string {
  return error instanceof Error ? error.message : '操作失败';
}

function Chevron(props: { open: boolean }) {
  return h(
    'svg',
    {
      className: 'dshpw-chevron' + (props.open ? ' open' : ''),
      width: 14,
      height: 14,
      viewBox: '0 0 24 24',
      fill: 'none',
      'aria-hidden': 'true',
    },
    h('path', {
      d: 'M6 9l6 6 6-6',
      stroke: 'currentColor',
      strokeWidth: 2,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
    }),
  );
}

export function DshPasswordsCard(_props: object) {
  // 折叠状态（与官方 PluginCard 一致：默认收起，展开状态为卡片本地状态）
  const [open, setOpen] = useState(false);

  const [data, setData] = useState<StateData | null>(null);
  const [patchState, setPatchState] = useState<PatchState | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  // 改密表单
  const [pwTarget, setPwTarget] = useState('');
  const [pwNew, setPwNew] = useState('');
  const [pwConfirm, setPwConfirm] = useState('');
  // 改名表单
  const [nameTarget, setNameTarget] = useState('');
  const [nameNew, setNameNew] = useState('');
  // 新增子用户表单
  const [addName, setAddName] = useState('');
  const [addPw, setAddPw] = useState('');

  const refresh = () => {
    api<StateData>('/api/dsh-passwords/state')
      .then((d) => {
        setData(d);
        setError('');
      })
      .catch((e) => setError(errText(e)));
    api<{ status: PatchState | null }>('/api/dsh-passwords/patch/status')
      .then((r) => setPatchState(r.status))
      .catch(() => setPatchState(null));
  };

  useEffect(() => {
    refresh();
  }, []);

  const isAdmin = data?.me?.role === 'admin';
  const me = data?.me?.username ?? '';

  const run = async (fn: () => Promise<void>, okMessage: string) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await fn();
      setNotice(okMessage);
      refresh();
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  };

  /** 重载补丁：任何登录用户可触发；网关重打补丁并重启 dsh 网页服务，页面稍后自动刷新 */
  const reloadPatch = () => {
    void run(async () => {
      await api('/api/dsh-passwords/patch/reload', {});
      // 给网关留出应用补丁 + 重启 dsh 的时间，再刷新页面拿到新代码
      window.setTimeout(() => {
        window.location.reload();
      }, 6000);
    }, '正在重载：网页服务即将重启，页面将自动刷新');
  };

  const changePassword = () => {
    if (pwNew !== pwConfirm) return setError('两次输入的密码不一致');
    if (!PASSWORD_RE.test(pwNew)) return setError('密码需至少 12 位，且同时包含大写字母、小写字母、数字、符号');
    void run(
      () => api('/api/dsh-passwords/password', { target: pwTarget || me, password: pwNew }),
      '密码已修改（若改的是自己，其他设备上的会话已全部失效）',
    );
  };

  const rename = () => {
    if (!USERNAME_RE.test(nameNew)) return setError('用户名需为 3-32 位字母、数字、下划线或连字符');
    void run(
      () => api('/api/dsh-passwords/username', { target: nameTarget || me, username: nameNew }),
      '用户名已修改。若改的是自己，请用新用户名重新登录。',
    );
  };

  const addSubUser = () => {
    if (!USERNAME_RE.test(addName)) return setError('用户名需为 3-32 位字母、数字、下划线或连字符');
    if (!PASSWORD_RE.test(addPw)) return setError('密码需至少 12 位，且同时包含大写字母、小写字母、数字、符号');
    void run(() => api('/api/dsh-passwords/users', { username: addName, password: addPw }), '子用户已创建');
  };

  const removeUser = (username: string) => {
    if (!window.confirm(`确定删除子用户 ${username} 吗？该操作不可撤销。`)) return;
    void run(() => api('/api/dsh-passwords/users/remove', { target: username }), '子用户已删除');
  };

  // 管理员的目标用户下拉：列出全部用户（默认自己，即当前账号在列表中的那一项）
  const targetSelect = (value: string, onChange: (v: string) => void) =>
    isAdmin
      ? h(
          'select',
          {
            className: 'dshpw-input',
            value: value || me,
            onChange: (e: { target: { value: string } }) => onChange(e.target.value),
          },
          ...(data?.users ?? []).map((u) =>
            h(
              'option',
              { key: u.id, value: u.username },
              `${u.username}（${u.role === 'admin' ? '主用户' : '子用户'}）`,
            ),
          ),
        )
      : null;

  const patchOk = patchState !== null && patchState.settingsHostMode && patchState.whitelist;
  const patchText =
    patchState === null ? '状态未知' : patchOk ? '已启用 · 远程连接可用' : '异常：部分功能不可用';

  const header = h(
    'button',
    {
      type: 'button',
      className: 'dshpw-header',
      'aria-expanded': open,
      'aria-label': (open ? '收起' : '展开') + '：dsh-passwords · 密码门',
      onClick: () => setOpen(!open),
    },
    h(
      'span',
      { className: 'dshpw-head' },
      h('span', { className: 'dshpw-title' }, 'dsh-passwords · 密码门'),
      h(
        'span',
        { className: 'dshpw-desc' },
        '登录网关的账号管理。当前身份：',
        h('strong', null, me || '—'),
        isAdmin
          ? h('span', { className: 'dshpw-badge admin' }, '主用户')
          : h('span', { className: 'dshpw-badge' }, '子用户'),
      ),
    ),
    h(Chevron, { open }),
  );

  const body = h(
    'div',
    { className: 'dshpw-body' },
    // ── 远程设置：状态 + 重载 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h('span', { className: 'dshpw-label' }, '远程设置'),
      h(
        'div',
        { className: 'dshpw-row' },
        h('span', { className: patchOk ? 'dshpw-ok' : 'dshpw-error' }, patchText),
        h('button', { className: 'dshpw-btn', disabled: busy, onClick: reloadPatch }, '重载补丁'),
      ),
      h(
        'div',
        { className: 'dshpw-hint' },
        '经密码门登录后，远程浏览器可正常使用 dsh 的全部设置功能。',
        'dsh 升级后若设置页出现异常，点"重载补丁"即可修复（自动重启网页服务并刷新页面）。',
      ),
    ),

    // ── 修改密码 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h('span', { className: 'dshpw-label' }, '修改密码'),
      isAdmin && h('span', { className: 'dshpw-hint' }, '目标用户'),
      targetSelect(pwTarget, setPwTarget),
      h('input', {
        className: 'dshpw-input',
        type: 'password',
        placeholder: '新密码（至少 12 位，含大小写、数字、符号）',
        value: pwNew,
        onChange: (e: { target: { value: string } }) => setPwNew(e.target.value),
      }),
      h('input', {
        className: 'dshpw-input',
        type: 'password',
        placeholder: '再次输入新密码',
        value: pwConfirm,
        onChange: (e: { target: { value: string } }) => setPwConfirm(e.target.value),
      }),
      h(
        'div',
        { className: 'dshpw-row' },
        h('button', { className: 'dshpw-btn', disabled: busy, onClick: changePassword }, '保存密码'),
      ),
    ),

    // ── 修改用户名 ──
    h(
      'div',
      { className: 'dshpw-section' },
      h('span', { className: 'dshpw-label' }, '修改用户名'),
      isAdmin && h('span', { className: 'dshpw-hint' }, '目标用户'),
      targetSelect(nameTarget, setNameTarget),
      h('input', {
        className: 'dshpw-input',
        placeholder: '新用户名（3-32 位字母、数字、下划线或连字符）',
        value: nameNew,
        onChange: (e: { target: { value: string } }) => setNameNew(e.target.value),
      }),
      h(
        'div',
        { className: 'dshpw-row' },
        h('button', { className: 'dshpw-btn', disabled: busy, onClick: rename }, '保存用户名'),
      ),
      h('div', { className: 'dshpw-hint' }, '改名后旧会话立即失效，需要用新用户名重新登录。'),
    ),

    // ── 子用户管理（仅主用户） ──
    isAdmin &&
      h(
        'div',
        { className: 'dshpw-section' },
        h('span', { className: 'dshpw-label' }, '子用户管理'),
        ...(data?.users ?? []).map((u) =>
          h(
            'div',
            { className: 'dshpw-user', key: u.id },
            h(
              'span',
              null,
              u.username,
              u.role === 'admin'
                ? h('span', { className: 'dshpw-badge admin' }, '主用户')
                : h('span', { className: 'dshpw-badge' }, '子用户'),
              u.last_login_at ? h('span', { className: 'dshpw-hint' }, ` 最近登录 ${u.last_login_at}`) : null,
            ),
            u.username !== me &&
              h('button', { className: 'dshpw-btn danger', disabled: busy, onClick: () => removeUser(u.username) }, '删除'),
          ),
        ),
        h('input', {
          className: 'dshpw-input',
          placeholder: '子用户名（3-32 位字母、数字、下划线或连字符）',
          value: addName,
          onChange: (e: { target: { value: string } }) => setAddName(e.target.value),
        }),
        h('input', {
          className: 'dshpw-input',
          type: 'password',
          placeholder: '子用户密码（至少 12 位，含大小写、数字、符号）',
          value: addPw,
          onChange: (e: { target: { value: string } }) => setAddPw(e.target.value),
        }),
        h(
          'div',
          { className: 'dshpw-row' },
          h('button', { className: 'dshpw-btn', disabled: busy, onClick: addSubUser }, '添加子用户'),
        ),
        h('div', { className: 'dshpw-hint' }, '子用户可用同样的登录页进入 dsh，但没有用户管理权限。'),
      ),

    error && h('div', { className: 'dshpw-error' }, error),
    notice && h('div', { className: 'dshpw-ok' }, notice),
  );

  return h('div', { className: 'dshpw-card' + (open ? ' open' : '') }, header, open ? body : null);
}
