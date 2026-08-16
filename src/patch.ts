// 远程设置补丁：强制启用。
//
// 背景：dsh 把 settings 等特权面设计成 loopback-only——
//   1. 客户端（dsh-client-ui-settings/lib/client.js）：
//      connection.isLoopback ? "host" : "memory" → 远程浏览器走 memory 模式，
//      设置表单不可用
//   2. 主机侧（dsh-host-apiproxy/lib/index.js）：
//      WEB_SETTINGS_NAMESPACES 硬编码白名单，第三方插件命名空间不在其中
// 网关把 Host/Origin 改写为 127.0.0.1:3080，主机侧栅栏对经网关的流量放行，
// 所以只需把客户端持久化强制为 host 模式 + 把插件命名空间加进白名单。
//
// 信任边界：只有通过密码门登录的浏览器能写设置（直连 3080 的局域网浏览器
// 仍会被主机侧栅栏拒绝）。无论本地直连还是远程，强制打此补丁影响都不大，
// 因此不提供开关：网关每次启动自动应用（幂等），dsh 升级覆盖文件后重启
// 网关自动重打，或在设置页点"重载补丁"。
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import path from 'node:path';

const BAK_SUFFIX = '.bak-dshpw';

/** 客户端设置持久化文件（强制 host 模式） */
const SETTINGS_TARGET = path.join(
  'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js',
);
/** 主机侧 settings 白名单文件（补插件命名空间） */
const WHITELIST_TARGET = path.join(
  'node_modules', '@deepseek-ai', 'dsh-host-apiproxy', 'lib', 'index.js',
);

const SETTINGS_FROM = 'connection.isLoopback ? "host" : "memory"';
const SETTINGS_TO = '"host"';

/** 白名单完整列表：dsh 自带 7 个 + dsh-web-ui 插件 6 个 + 本项目 1 个 */
const WL_NAMESPACES = [
  'agent-loop',
  'shell',
  'locale',
  'permission',
  'ui-conversation',
  'ui-theme',
  'web-search-deepseek',
  'task-board',
  'dsh-ssh',
  'pet',
  'live-stats',
  'remote-web-ui',
  'skin-background',
  'dsh-passwords',
];

/** 找到 dsh 安装根目录（@deepseek-ai/dsh），找不到返回 null */
export function findDshRoot(explicit: string): string | null {
  if (explicit) return existsSync(explicit) ? explicit : null;
  try {
    const globalRoot = execSync('npm root -g', { encoding: 'utf8' }).trim();
    const candidate = path.join(globalRoot, '@deepseek-ai', 'dsh');
    if (existsSync(candidate)) return candidate;
  } catch {
    // npm 不可用时走兜底路径
  }
  // 本地依赖：从 cwd 向上找 node_modules/@deepseek-ai/dsh
  // （覆盖 npm i 到项目本地而非全局的场景，如 Windows/开发机/手动部署）
  let dir = process.cwd();
  for (;;) {
    const candidate = path.join(dir, 'node_modules', '@deepseek-ai', 'dsh');
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  for (const candidate of [
    '/usr/local/lib/node_modules/@deepseek-ai/dsh',
    '/usr/lib/node_modules/@deepseek-ai/dsh',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/** 补丁当前状态（用于 status 展示） */
export function patchStatus(dshRoot: string): { settingsHostMode: boolean; whitelist: boolean } {
  const settingsFile = path.join(dshRoot, SETTINGS_TARGET);
  const wlFile = path.join(dshRoot, WHITELIST_TARGET);
  let settingsHostMode = false;
  let whitelist = false;
  try {
    const s = readFileSync(settingsFile, 'utf8');
    settingsHostMode = !s.includes(SETTINGS_FROM) && s.includes(SETTINGS_TO);
  } catch { /* 文件缺失按未打处理 */ }
  try {
    const w = readFileSync(wlFile, 'utf8');
    whitelist = w.includes('"dsh-passwords"');
  } catch { /* 同上 */ }
  return { settingsHostMode, whitelist };
}

/** 应用补丁（幂等）：返回 'applied'（本次有改动）或 'unchanged' 或 'missing'（目标文件不在） */
export function applyRemotePatch(dshRoot: string): 'applied' | 'unchanged' | 'missing' {
  const settingsFile = path.join(dshRoot, SETTINGS_TARGET);
  const wlFile = path.join(dshRoot, WHITELIST_TARGET);
  if (!existsSync(settingsFile) || !existsSync(wlFile)) return 'missing';
  let changed = false;

  // 1) 客户端 settings 强制 host 模式
  const s = readFileSync(settingsFile, 'utf8');
  if (s.includes(SETTINGS_FROM)) {
    if (!existsSync(settingsFile + BAK_SUFFIX)) writeFileSync(settingsFile + BAK_SUFFIX, s);
    writeFileSync(settingsFile, s.replace(SETTINGS_FROM, SETTINGS_TO));
    changed = true;
  }

  // 2) 白名单补齐（整块重建，兼容任意已打过部分补丁的状态）
  const w = readFileSync(wlFile, 'utf8');
  if (!w.includes('"dsh-passwords"')) {
    const block =
      'const WEB_SETTINGS_NAMESPACES = [\n\t' + WL_NAMESPACES.map((n) => `"${n}"`).join(',\n\t') + '\n];';
    const re = /const WEB_SETTINGS_NAMESPACES = \[[\s\S]*?\];/;
    if (!re.test(w)) return 'missing';
    if (!existsSync(wlFile + BAK_SUFFIX)) writeFileSync(wlFile + BAK_SUFFIX, w);
    writeFileSync(wlFile, w.replace(re, block));
    changed = true;
  }

  return changed ? 'applied' : 'unchanged';
}

/**
 * 回滚补丁：从 .bak-dshpw 备份恢复两个目标文件。
 * 备份不存在（从未打过补丁）时返回 'no-backup'。
 */
export function rollbackPatch(dshRoot: string): 'rolled-back' | 'no-backup' | 'missing' {
  const settingsFile = path.join(dshRoot, SETTINGS_TARGET);
  const wlFile = path.join(dshRoot, WHITELIST_TARGET);
  if (!existsSync(settingsFile) || !existsSync(wlFile)) return 'missing';
  let changed = false;
  for (const target of [settingsFile, wlFile]) {
    const bak = target + BAK_SUFFIX;
    if (existsSync(bak)) {
      writeFileSync(target, readFileSync(bak));
      changed = true;
    }
  }
  return changed ? 'rolled-back' : 'no-backup';
}

/** 延迟重启 dsh 网页服务（补丁生效需要 dsh 重新加载模块）；仅适用于常驻进程 */
export function restartDshWeb(service: string, delayMs = 2500): void {
  if (!service) return;
  setTimeout(() => {
    try {
      execSync(`systemctl restart ${service}`, { stdio: 'ignore' });
    } catch (error) {
      console.error(`[dsh-passwords] 重启 ${service} 失败（补丁将在下次 dsh 重启后生效）:`, error);
    }
  }, delayMs).unref();
}
