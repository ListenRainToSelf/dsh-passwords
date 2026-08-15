// 子用户权限模型 + 网关侧强制执行的纯函数（无 DB/框架依赖，便于复用与测试）。
//
// 权限（主用户在设置卡片里为每个子用户配置）：
//   - allowedFolders    允许打开的工作区/项目文件夹（绝对路径；空数组 = 全部允许）
//   - hourlyTokenLimit  每小时 token 上限（null = 不限）
//   - dailyMinutesLimit 每日使用时长上限，分钟（从当天首次使用起算；null = 不限）
//   - allowUpload       是否允许上传文件
//   - allowGitDownload  是否允许 git 下载（clone/pull 等）
//   - banned            是否封禁（封禁后经密码门的请求全部 403）
//
// 说明：folder / upload / git 的网关层拦截是"尽力而为"（基于 dsh 的 HTTP API
// 路径与请求体字段）。主用户账号不受任何限制。

export interface UserPermissions {
  allowedFolders: string[];
  hourlyTokenLimit: number | null;
  dailyMinutesLimit: number | null;
  allowUpload: boolean;
  allowGitDownload: boolean;
  banned: boolean;
}

export function defaultPermissions(): UserPermissions {
  return {
    allowedFolders: [],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: true,
    allowGitDownload: true,
    banned: false,
  };
}

/** 规范化路径：反斜杠转正斜杠、去尾部斜杠，便于前缀比较 */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/\/+$/, '');
}

/** path 是否命中 allowed 白名单（相等或为某白名单目录的子路径；空白名单 = 全部允许） */
export function folderAllowed(path: string, allowedFolders: string[]): boolean {
  if (allowedFolders.length === 0) return true;
  const p = normalizePath(path);
  return allowedFolders.some((entry) => {
    const base = normalizePath(entry);
    if (base === '') return false;
    return p === base || p.startsWith(base + '/');
  });
}

/**
 * 递归过滤 JSON 里路径字段不在白名单的对象（session.list 用 field='cwd'，workspace.list 用 field='path'）：
 * 只对数组元素中带该路径字段的对象做白名单判定，白名单外的直接丢弃；其余字段原样递归保留。
 * 字段缺失/空串（无工作区）不拦截。
 */
export function filterByPathField(value: unknown, allowedFolders: string[], field: string): unknown {
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) {
      if (
        item !== null &&
        typeof item === 'object' &&
        typeof (item as Record<string, unknown>)[field] === 'string' &&
        !folderAllowed((item as Record<string, unknown>)[field] as string, allowedFolders)
      ) {
        continue;
      }
      out.push(filterByPathField(item, allowedFolders, field));
    }
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = filterByPathField(v, allowedFolders, field);
    }
    return out;
  }
  return value;
}

/** 递归收集 {id, path} 对（workspace.list 响应用，建 workspaceId → 路径 映射） */
export function collectIdPathPairs(value: unknown, out: Map<string, string> = new Map()): Map<string, string> {
  if (Array.isArray(value)) {
    for (const item of value) collectIdPathPairs(item, out);
  } else if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.id === 'string' && typeof obj.path === 'string') out.set(obj.id, obj.path);
    for (const v of Object.values(obj)) collectIdPathPairs(v, out);
  }
  return out;
}

/** 递归查找请求体里的 workspaceId（session.create 可能带 workspaceId 而非 cwd） */
export function extractWorkspaceId(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  if (typeof obj.workspaceId === 'string' && obj.workspaceId.length > 0) return obj.workspaceId;
  for (const key of Object.keys(obj)) {
    const nested = extractWorkspaceId(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/** 沙盒权限级别（dsh SANDBOX_MODES）+ 严重度排序（越靠后越宽松） */
export type SandboxMode = 'read-only' | 'workspace-write' | 'danger-full-access';
export const SANDBOX_RANK: Record<SandboxMode, number> = {
  'read-only': 0,
  'workspace-write': 1,
  'danger-full-access': 2,
};

/** 递归查找某个字符串字段（settings.mutate 里找 defaultPreset 用） */
export function findStringField(value: unknown, field: string, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  const v = obj[field];
  if (typeof v === 'string' && v.length > 0) return v;
  for (const key of Object.keys(obj)) {
    const nested = findStringField(obj[key], field, depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/** preset → 沙盒 rank：按 SANDBOX_RANK 精确映射；未知值按最宽松=2 处理（防止越权切换） */
export function sandboxPresetRank(preset: string): number {
  return SANDBOX_RANK[preset as SandboxMode] ?? 2;
}

/**
 * 从 slash 命令行解析 /permission 的 preset 参数。
 * 例："/permission workspace-write" → "workspace-write"；非该命令或无参数返回 null。
 */
export function permissionPresetFromCommand(line: string): string | null {
  const match = /^\/permission\s+([A-Za-z0-9_-]+)/.exec(line.trim());
  return match ? match[1] : null;
}

/**
 * 从 settings.mutate 请求体里找 permission.defaultPreset 写入。
 * 该字段是 ops[].path 数组里的元素（不是对象字段键），所以不能用 findStringField 找；
 * 递归找到某个带 `path` 数组且含 'defaultPreset' 的对象，返回其 `value` 字符串。
 */
export function presetFromSettingsMutate(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  if (Array.isArray(obj.path) && obj.path.includes('defaultPreset')) {
    const v = obj.value;
    if (typeof v === 'string' && v.length > 0) return v;
  }
  for (const key of Object.keys(obj)) {
    const nested = presetFromSettingsMutate(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * 递归把审批响应里的 outcome 强制改成 'rejected'（受限子用户的 AI 提权一律取消）。
 * /api/respond 的 body 是 ClientResponse 信封：outcome/approvalId 位于 result.value，
 * 因此这里递归找到同时带字符串 approvalId + outcome 的对象并改值；返回是否有实际改动。
 * （ask_user_question 的响应用的是 answer 字段，不会被误伤。）
 */
export function forceRejectApproval(value: unknown, depth = 0): boolean {
  if (depth > 6 || value === null || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  let changed = false;
  if (typeof obj.approvalId === 'string' && typeof obj.outcome === 'string' && obj.outcome !== 'rejected') {
    obj.outcome = 'rejected';
    changed = true;
  }
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v !== null && typeof v === 'object') {
      if (forceRejectApproval(v, depth + 1)) changed = true;
    }
  }
  return changed;
}

// ── 上传 / git 拦截的路径判定（纯路径 + 方法，不读请求体） ──────────────

/** 上传相关端点：dsh-file-uploads 插件 + dsh-file-path 的"复制到工作区"桥 + dsh-ssh 远程上传 */
export function isUploadRequest(method: string, pathname: string): boolean {
  if (method !== 'POST' && method !== 'PUT') return false;
  return (
    pathname === '/api/dsh-uploads' ||
    pathname === '/api/filePathBridge/importFile' ||
    pathname === '/api/dsh-uploads/' ||
    pathname === '/api/dsh-ssh/upload'
  );
}

/**
 * git 相关端点（dsh 内置 git 工具 / git-graph 插件 / aionui-panel 的 git 面板等，尽力匹配）。
 * 同时覆盖“从服务器拿走数据”的其它通道：session.export（会话日志 ZIP）与 dsh-ssh 的远程文件下载。
 */
export function isGitRequest(pathname: string): boolean {
  return (
    /\/api\/[^/]*(git|clone|pull|fetch)[^/]*/i.test(pathname) ||
    /^\/aionui-panel\/git[-.]/.test(pathname) ||
    /^\/api\/session[.\/]export/.test(pathname) ||
    /^\/api\/dsh-ssh[.\/](download|ls)/.test(pathname)
  );
}

/** aionui-panel 文件树：读取/下载文件内容的端点（raw 为 GET 流式传输，read 为 POST JSON） */
export function isAionuiFileRead(method: string, pathname: string): boolean {
  if (pathname === '/aionui-panel/raw') return method === 'GET' || method === 'HEAD';
  return method === 'POST' && pathname === '/aionui-panel/read';
}

/** aionui-panel 文件树：写文件/删除的端点（与上传权限对称） */
export function isAionuiFileWrite(method: string, pathname: string): boolean {
  if (method !== 'POST' && method !== 'PUT' && method !== 'DELETE') return false;
  return (
    pathname === '/aionui-panel/write' ||
    pathname === '/aionui-panel/delete' ||
    pathname === '/aionui-panel/git-stage' ||
    pathname === '/aionui-panel/git-unstage' ||
    pathname === '/aionui-panel/git-discard'
  );
}

/** aionui-panel 文件树：任意端点（用于 allowedFolders 白名单校验 root） */
export function isAionuiPanel(pathname: string): boolean {
  return pathname.startsWith('/aionui-panel/');
}

/** 从 aionui-panel 请求中提取 root（工作区路径）：GET/HEAD 取 query，POST 取 JSON body */
export function aionuiRootFrom(
  method: string,
  pathname: string,
  query: URLSearchParams,
  bodyJson: unknown,
): string | null {
  if (!isAionuiPanel(pathname)) return null;
  if (method === 'GET' || method === 'HEAD') {
    const root = query.get('root');
    return root !== null && root.length > 0 ? root : null;
  }
  if (typeof bodyJson === 'object' && bodyJson !== null) {
    const root = (bodyJson as Record<string, unknown>).root;
    return typeof root === 'string' && root.length > 0 ? root : null;
  }
  return null;
}

/** 工作区创建/删除等写操作（受限子用户直接禁止，防止绕过文件夹白名单） */
export function isWorkspaceWrite(pathname: string): boolean {
  return /^\/api\/workspace[.\/](add|create|import|remove|delete)/.test(pathname);
}

// ── 工作区/会话文件夹限制：需要读 JSON 请求体 ──────────────────────────

/** 涉及创建/切换工作区的 dsh typert RPC（斜杠风格：/api/session/create 等；兼容点号风格） */
export const WORKSPACE_ENDPOINT_RE = /^\/api\/session[.\/](create|fork)/;

/** 请求体里可能携带目标路径的字段名（按优先级） */
const PATH_FIELDS = [
  'cwd',
  'path',
  'directory',
  'dir',
  'folder',
  'workspace',
  'root',
  'workspacePath',
  'absolutePath',
  'target',
  'targetPath',
];

/** 递归查找请求体里第一个字符串路径字段（兼容 typert 的 {args:{request:{...}}} 嵌套） */
export function extractPathFromBody(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  for (const field of PATH_FIELDS) {
    const v = obj[field];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  for (const key of Object.keys(obj)) {
    const nested = extractPathFromBody(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

// ── token 用量识别（尽力而为：扫描 dsh 流式/JSON 响应里的用量字段） ─────

// dsh 的 TokenUsage：{ inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, reasoningTokens }。
// 每个 agent step 上报一次（非累计），因此跨事件求和；input + output 即"两个数据一比对"的总消耗。
const TOKEN_USAGE_RE = /"(?:inputTokens|outputTokens)"\s*:\s*(\d+)/g;

/**
 * 从一段响应文本里累加 token 用量（input + output）。识别不到返回 0（不会误扣）。
 */
export function tokensFromText(text: string): number {
  let total = 0;
  let m: RegExpExecArray | null;
  TOKEN_USAGE_RE.lastIndex = 0;
  while ((m = TOKEN_USAGE_RE.exec(text)) !== null) {
    const n = Number(m[1]);
    if (Number.isFinite(n)) total += n;
  }
  return total;
}

/** 当日日期（本地时区 YYYY-MM-DD，与"每日使用时长"语义一致） */
export function todayLocal(): string {
  const d = new Date();
  const y = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${y}-${mm}-${dd}`;
}

/** 是否应跳过用量计时/扣减的静态资源路径（减少无意义的活跃时间累计） */
export function isStaticAsset(pathname: string): boolean {
  return (
    pathname.startsWith('/assets/') ||
    (pathname.startsWith('/plugins/') && pathname.includes('rev=')) ||
    pathname === '/favicon.ico'
  );
}
