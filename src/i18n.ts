// 文案集中管理（zh / en 双语）。
//
// 网关页面语言解析顺序（resolveGatewayLang）：
//   1. ?lang= 查询参数（语言切换链接点出来的）
//   2. cookie dshpw_lang（用户手动切换后的持久选择）
//   3. dsh settings.yaml 的 locale.preference —— 跟随 dsh 设置里的语言
//   4. Accept-Language（浏览器语言）
//   5. 默认 zh
//
// CLI 语言（resolveCliLang）：LANG / LC_ALL / LC_MESSAGES 以 en 开头 → en，
// 否则 zh。dsh 设置卡片的语言不经过本模块——卡片词典注册进 dsh 的 locale
// 服务（src/client/locales.ts），直接跟随 dsh 的语言设置。
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export type Lang = 'zh' | 'en';

type Params = Record<string, string | number>;

const DICT: Record<Lang, Record<string, string>> = {
  zh: {
    // ── 认证 / 业务错误（AuthError.code → 文案） ──
    'err.ALREADY_INITIALIZED': '平台已初始化，不能重复配置',
    'err.INVALID_SETUP_KEY': '预设密钥不正确',
    'err.INVALID_USERNAME': '用户名需为 3-32 位字母、数字、下划线或连字符',
    'err.INVALID_PASSWORD': '密码需至少 12 位，且必须同时包含大写字母、小写字母、数字、符号各至少一位',
    'err.SQL_INJECTION_REJECTED': '{field} 包含非法字符，已拒绝',
    'err.ACCOUNT_LOCKED': '账号已锁定，请 {minutes} 分钟后再试',
    'err.ACCOUNT_LOCKED_FRESH': '连续失败 {count} 次，账号已锁定 {minutes} 分钟',
    'err.INVALID_CREDENTIALS': '用户名或密码错误',
    'err.INVALID_TOKEN': '会话无效或已过期',
    'err.NO_SUCH_USER': '目标用户不存在',
    'err.FORBIDDEN_PASSWORD': '只有主用户可以修改他人密码',
    'err.INVALID_CURRENT_PASSWORD': '当前密码不正确',
    'err.FORBIDDEN_USERNAME': '只有主用户可以修改他人用户名',
    'err.FORBIDDEN_ADD_USER': '只有主用户可以分配子用户',
    'err.FORBIDDEN_REMOVE_USER': '只有主用户可以删除用户',
    'err.USERNAME_TAKEN': '该用户名已被使用',
    'err.CANNOT_REMOVE_SELF': '不能删除自己',
    'err.NOT_CONFIGURED': '未配置：请先完成 dsh-passwords 部署（.env 中 SETUP_KEY 等），再重启 dsh',
    'err.NOT_AUTHENTICATED': '未登录或会话已失效',
    'err.FORBIDDEN_CSRF': '请求被拒绝（跨站伪造防护）',
    // ── 网关登录 / 首次配置页 ──
    'gw.titleLogin': '登录 · DeepSeek Harness',
    'gw.loginTitle': '登录 DeepSeek Harness',
    'gw.loginSub1': '访问已受 dsh-passwords 网关保护',
    'gw.loginSub2': '请输入平台账号密码',
    'gw.username': '用户名',
    'gw.password': '密码',
    'gw.usernamePlaceholder': '你的用户名',
    'gw.passwordPlaceholder': '你的密码',
    'gw.login': '登录',
    'gw.loggingIn': '登录中…',
    'gw.dbHint': '注意：数据库当前不可达，登录校验将不可用',
    'gw.titleSetup': '首次配置 · DeepSeek Harness',
    'gw.setupTitle': '首次配置',
    'gw.setupSub1': '输入部署时预设的安装密钥，并创建管理员账号',
    'gw.setupSub2': '此操作只能进行一次',
    'gw.setupKey': '预设密钥',
    'gw.setupKeyPlaceholder': '部署时在 .env 中设置的 SETUP_KEY',
    'gw.usernameRule': '3-32 位字母数字下划线',
    'gw.passwordRule': '至少 12 位，含大写、小写、数字、符号',
    'gw.confirmPassword': '确认密码',
    'gw.confirmPlaceholder': '再次输入密码',
    'gw.initPlatform': '初始化平台',
    'gw.initializing': '正在初始化…',
    'gw.passwordMismatch': '两次输入的密码不一致',
    'gw.ruleLen': '至少 12 位',
    'gw.ruleUp': '含大写字母',
    'gw.ruleLow': '含小写字母',
    'gw.ruleNum': '含数字',
    'gw.ruleSym': '含符号',
    'gw.csrfFailed': '页面安全校验失败，请重新提交',
    'gw.initFailed': '初始化失败',
    'gw.loginFailed': '登录失败',
    'gw.upstreamDown': '上游 dsh 不可达',
    'gw.banned': '账号已被主用户封禁，请联系主用户',
    'gw.noUpload': '你的账号没有上传文件权限',
    'gw.noGit': '你的账号没有 git 下载权限',
    'gw.timeLimit': '今日使用时长已用完',
    'gw.tokenLimit': '每小时 token 用量已达上限',
    'gw.folderDenied': '该文件夹不在你的授权目录内',
    'gw.workspaceDenied': '你的账号无权创建或删除工作区',
    'gw.sandboxDenied': '你的沙盒权限不足，无法切换到该级别',
    // ── CLI ──
    'cli.warnMissingValue': '{name} 缺少值',
    'cli.warnInvalidPort': '无效端口 {value}，已忽略',
    'cli.noAudit': '（暂无审计日志）',
    'cli.noDshRoot': '找不到 dsh 安装目录（可用 MCP_DSH_ROOT 指定 @deepseek-ai/dsh 路径）',
    'cli.dshDir': 'dsh 目录',
    'cli.hostMode': 'settings 强制 host 模式',
    'cli.whitelist': 'WEB_SETTINGS_NAMESPACES 白名单(含 dsh-passwords)',
    'cli.patched': '已打',
    'cli.notPatched': '未打',
    'cli.result': '结果',
    'cli.restarting': '重启 {service} 使补丁立即生效...',
    'cli.restartFailed': '重启失败（补丁将在下次 dsh 重启后生效）',
    'cli.usage': '用法: node dist/cli.js patch [status]',
    'cli.needSetupKey': '请先配置 .env 中的 SETUP_KEY（预设安装密钥），见 .env.example',
    'cli.patchApplied': '远程设置补丁: 已自动应用，dsh 网页服务即将重启',
    'cli.patchTargetMissing': '未找到补丁目标文件（dsh 版本可能变更），跳过补丁应用',
    'cli.dshRootMissing': 'MCP_DSH_ROOT 指定的 dsh 目录不存在，跳过补丁同步',
    'cli.patchSyncFailed': '补丁同步失败（不影响网关启动）',
    'cli.gatewayListening': '登录网关({mode})',
    'cli.upstream': '上游',
    'cli.db': '数据库(SQLite)',
    'cli.redirect': 'HTTP→HTTPS 跳转',
    'cli.startFailed': '启动失败',
    'cli.acmeIssuing': '正在申请 HTTPS 证书（{domain}）…',
    'cli.acmeIssued': 'HTTPS 证书就绪：{domain}，有效期至 {date}',
    'cli.acmeRenewFailed': '证书续期失败（下次再试）',
    'cli.acmeFallbackOld': '证书续期失败，继续使用现有证书（到期前会自动重试）',
    'cli.publicUrl': '访问地址',
    // ── 启动错误码（fail-closed：签发失败/无公网域名绝不降级为明文 HTTP） ──
    'cli.exitCertFailed': '自动 HTTPS 启动失败（错误码 {code}）：证书签发失败：{error}',
    'cli.exitCertHint': '请检查：1) 服务器 80/443 端口是否被占用或未放行（防火墙 + 云安全组都要开）2) 能否连通 Let\'s Encrypt。有域名可在 .env 设置 MCP_GATEWAY_DOMAIN；或运行 scripts/start-http.mjs 改用明文 HTTP（有被嗅探风险）',
    'cli.exitNoDomain': '自动 HTTPS 启动失败（错误码 {code}）：无法确定公网 IP/域名',
    'cli.exitNoDomainHint': '服务器没有公网 IP 或探测失败。有域名请在 .env 设置 MCP_GATEWAY_DOMAIN；或运行 scripts/start-http.mjs 改用明文 HTTP（有被嗅探风险）',
    'cli.exitPortBusy': '端口监听失败（错误码 {code}）：{error}',
    'cli.httpWarning': '⚠ 密码门运行在【明文 HTTP】模式：登录密码与会话 Cookie 将以明文传输，可能被网络中间人嗅探。公网部署请优先使用自动 HTTPS。',
    'cli.watchParent': '跟随宿主 dsh 进程（PID {pid}），宿主退出时自动停止',
    'cli.parentGone': '宿主 dsh 进程已退出，密码门随其停止',
    'cli.installScriptMissing': '找不到一键安装脚本：{path}',
  },
  en: {
    'err.ALREADY_INITIALIZED': 'The platform is already initialized and cannot be set up again',
    'err.INVALID_SETUP_KEY': 'Incorrect setup key',
    'err.INVALID_USERNAME': 'Username must be 3-32 letters, digits, underscores or hyphens',
    'err.INVALID_PASSWORD': 'Password must be at least 12 characters and include uppercase, lowercase, digits and symbols',
    'err.SQL_INJECTION_REJECTED': '{field} contains invalid characters and was rejected',
    'err.ACCOUNT_LOCKED': 'Account locked, try again in {minutes} minutes',
    'err.ACCOUNT_LOCKED_FRESH': '{count} consecutive failures, account locked for {minutes} minutes',
    'err.INVALID_CREDENTIALS': 'Incorrect username or password',
    'err.INVALID_TOKEN': 'Session is invalid or expired',
    'err.NO_SUCH_USER': 'Target user does not exist',
    'err.FORBIDDEN_PASSWORD': "Only the owner can change another user's password",
    'err.INVALID_CURRENT_PASSWORD': 'Current password is incorrect',
    'err.FORBIDDEN_USERNAME': "Only the owner can change another user's username",
    'err.FORBIDDEN_ADD_USER': 'Only the owner can create subusers',
    'err.FORBIDDEN_REMOVE_USER': 'Only the owner can delete users',
    'err.USERNAME_TAKEN': 'That username is already taken',
    'err.CANNOT_REMOVE_SELF': 'You cannot delete yourself',
    'err.NOT_CONFIGURED': 'Not configured: finish the dsh-passwords deployment first (SETUP_KEY etc. in .env), then restart dsh',
    'err.NOT_AUTHENTICATED': 'Not signed in or the session has expired',
    'err.FORBIDDEN_CSRF': 'Request rejected (cross-site forgery protection)',
    'gw.titleLogin': 'Sign in · DeepSeek Harness',
    'gw.loginTitle': 'Sign in to DeepSeek Harness',
    'gw.loginSub1': 'Access is protected by the dsh-passwords gateway',
    'gw.loginSub2': 'Enter your platform username and password',
    'gw.username': 'Username',
    'gw.password': 'Password',
    'gw.usernamePlaceholder': 'Your username',
    'gw.passwordPlaceholder': 'Your password',
    'gw.login': 'Sign in',
    'gw.loggingIn': 'Signing in…',
    'gw.dbHint': 'Note: the database is unreachable, sign-in verification is unavailable',
    'gw.titleSetup': 'First-time setup · DeepSeek Harness',
    'gw.setupTitle': 'First-time setup',
    'gw.setupSub1': 'Enter the setup key preset at deployment and create the owner account',
    'gw.setupSub2': 'This can only be done once',
    'gw.setupKey': 'Setup key',
    'gw.setupKeyPlaceholder': 'The SETUP_KEY set in .env at deployment',
    'gw.usernameRule': '3-32 letters, digits or underscores',
    'gw.passwordRule': 'At least 12 characters with uppercase, lowercase, digits and symbols',
    'gw.confirmPassword': 'Confirm password',
    'gw.confirmPlaceholder': 'Enter the password again',
    'gw.initPlatform': 'Initialize platform',
    'gw.initializing': 'Initializing…',
    'gw.passwordMismatch': 'The two passwords do not match',
    'gw.ruleLen': 'At least 12 characters',
    'gw.ruleUp': 'Has uppercase',
    'gw.ruleLow': 'Has lowercase',
    'gw.ruleNum': 'Has a digit',
    'gw.ruleSym': 'Has a symbol',
    'gw.csrfFailed': 'Page security check failed, please resubmit',
    'gw.initFailed': 'Initialization failed',
    'gw.loginFailed': 'Sign-in failed',
    'gw.upstreamDown': 'Upstream dsh is unreachable',
    'gw.banned': 'This account has been banned by the owner',
    'gw.noUpload': 'Your account has no upload permission',
    'gw.noGit': 'Your account has no git download permission',
    'gw.timeLimit': 'Daily usage time has been used up',
    'gw.tokenLimit': 'Hourly token limit reached',
    'gw.folderDenied': 'That folder is not in your allowed directories',
    'gw.workspaceDenied': 'Your account cannot create or delete workspaces',
    'gw.sandboxDenied': 'Your sandbox permission is too low to switch to that level',
    'cli.warnMissingValue': 'missing value for {name}',
    'cli.warnInvalidPort': 'invalid port {value}, ignored',
    'cli.noAudit': '(no audit logs)',
    'cli.noDshRoot': 'cannot find the dsh install directory (set MCP_DSH_ROOT to the @deepseek-ai/dsh path)',
    'cli.dshDir': 'dsh directory',
    'cli.hostMode': 'settings forced host mode',
    'cli.whitelist': 'WEB_SETTINGS_NAMESPACES whitelist (incl. dsh-passwords)',
    'cli.patched': 'patched',
    'cli.notPatched': 'not patched',
    'cli.result': 'result',
    'cli.restarting': 'restarting {service} to apply the patch immediately...',
    'cli.restartFailed': 'restart failed (patch takes effect on next dsh restart)',
    'cli.usage': 'usage: node dist/cli.js patch [status]',
    'cli.needSetupKey': 'configure SETUP_KEY in .env first (the preset setup key), see .env.example',
    'cli.patchApplied': 'remote settings patch: applied automatically, the dsh web service will restart shortly',
    'cli.patchTargetMissing': 'patch target files not found (dsh version may have changed), skipping patch',
    'cli.dshRootMissing': 'the directory set by MCP_DSH_ROOT does not exist, skipping patch sync',
    'cli.patchSyncFailed': 'patch sync failed (gateway still starts)',
    'cli.gatewayListening': 'login gateway({mode})',
    'cli.upstream': 'upstream',
    'cli.db': 'database(SQLite)',
    'cli.redirect': 'HTTP→HTTPS redirect',
    'cli.startFailed': 'startup failed',
    'cli.acmeIssuing': 'Requesting HTTPS certificate for {domain}…',
    'cli.acmeIssued': 'HTTPS certificate ready: {domain}, valid until {date}',
    'cli.acmeRenewFailed': 'certificate renewal failed (will retry)',
    'cli.acmeFallbackOld': 'certificate renewal failed, keeping the existing certificate (will retry before expiry)',
    'cli.publicUrl': 'Access URL',
    'cli.exitCertFailed': 'auto HTTPS startup failed (error code {code}): certificate issuance failed: {error}',
    'cli.exitCertHint': 'Check: 1) ports 80/443 are free and open (firewall + cloud security group) 2) Let\'s Encrypt is reachable. If you own a domain set MCP_GATEWAY_DOMAIN in .env; or run scripts/start-http.mjs to switch to plain HTTP (sniffing risk)',
    'cli.exitNoDomain': 'auto HTTPS startup failed (error code {code}): cannot determine a public IP or domain',
    'cli.exitNoDomainHint': 'the server has no public IP or detection failed. If you own a domain set MCP_GATEWAY_DOMAIN in .env; or run scripts/start-http.mjs to switch to plain HTTP (sniffing risk)',
    'cli.exitPortBusy': 'failed to listen (error code {code}): {error}',
    'cli.httpWarning': '⚠ The gateway is running in PLAIN HTTP mode: passwords and session cookies travel in cleartext and can be sniffed. Prefer automatic HTTPS for public deployments.',
    'cli.watchParent': 'following the host dsh process (PID {pid}); exits when the host exits',
    'cli.parentGone': 'the host dsh process exited, the gateway stops with it',
    'cli.installScriptMissing': 'one-click install script not found: {path}',
  },
};

/** 按语言取文案：缺 key 回退 zh，再缺返回 key 本身（界面宁可露字也不空白） */
export function t(lang: Lang, key: string, params?: Params): string {
  const template = DICT[lang][key] ?? DICT.zh[key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

/**
 * 读 dsh 的语言偏好：<dsh home>/settings.yaml 的 locale.preference
 * （zh | en，dsh 设置页 General → Language 写入）。读不到返回 null。
 * 与 gateway.ts 里读 ui-theme.preference 用的是同一套候选路径逻辑。
 */
export function readDshLocalePreference(): Lang | null {
  const explicit = process.env.MCP_DSH_SETTINGS_FILE?.trim();
  const dshHome = process.env.DSH_HOME?.trim();
  const candidates: string[] = explicit
    ? [explicit]
    : [
        ...(dshHome ? [path.join(dshHome, 'settings.yaml')] : []),
        path.join(os.homedir(), '.dsh', 'settings.yaml'),
      ];
  for (const file of candidates) {
    try {
      const text = readFileSync(file, 'utf8');
      // settings.yaml 为扁平结构：顶层命名空间键 + 缩进字段（注释可跟在行尾）
      const block = text.match(/^locale\s*:\s*(?:#.*)?$/m);
      if (!block || block.index === undefined) continue;
      const rest = text.slice(block.index);
      const hit = rest.match(/^\s+preference\s*:\s*["']?(zh|en)["']?\s*(?:#.*)?$/m);
      if (hit) return hit[1] as Lang;
    } catch {
      // 文件不存在/不可读：继续尝试下一个候选
    }
  }
  return null;
}

function parseAcceptLanguage(header: string | null | undefined): string | null {
  if (!header) return null;
  const first = header.split(',')[0]?.trim();
  if (!first) return null;
  const primary = first.split('-')[0].toLowerCase();
  return primary === 'zh' || primary === 'en' ? primary : null;
}

/** 解析网关页面语言：?lang → cookie → dsh 设置 → 浏览器语言 → zh */
export function resolveGatewayLang(input: {
  queryLang?: unknown;
  cookieLang?: string | null;
  acceptLanguage?: string | null;
}): Lang {
  const pick = (value: unknown): Lang | null =>
    typeof value === 'string' && (value === 'zh' || value === 'en') ? value : null;
  return (
    pick(input.queryLang) ??
    pick(input.cookieLang) ??
    readDshLocalePreference() ??
    pick(parseAcceptLanguage(input.acceptLanguage)) ??
    'zh'
  );
}

/** 解析 CLI 语言：LANG / LC_ALL / LC_MESSAGES 以 en 开头 → en，否则 zh */
export function resolveCliLang(): Lang {
  // POSIX 优先级：LC_ALL > LC_MESSAGES > LANG
  for (const key of ['LC_ALL', 'LC_MESSAGES', 'LANG']) {
    const value = process.env[key];
    if (typeof value !== 'string' || value === '') continue;
    const lower = value.toLowerCase();
    if (lower.startsWith('en')) return 'en';
    if (lower.startsWith('zh')) return 'zh';
  }
  return 'zh';
}
