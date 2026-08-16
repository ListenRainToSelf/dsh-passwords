// 登录网关：劫持 dsh 访问入口
//   用户访问网关端口 → 未认证则渲染登录页（dsh 风格 + 动画）
//   → 登录成功 Set-Cookie(JWT, HttpOnly) → 302 回到原始 URL（重定向兼容层）
//   → 已认证请求反向代理到上游 dsh（HTTP + WebSocket，Host 改写为上游地址）
import http, { type IncomingMessage } from 'node:http';
import https from 'node:https';
import { createSecureContext } from 'node:tls';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { type Duplex } from 'node:stream';
import zlib from 'node:zlib';
import { URL } from 'node:url';
import express, { type Request, type Response } from 'express';
import type { PlatformConfig } from './config.js';
import { AuthService, AuthError, type RequestMeta } from './auth.js';
import { Database, type UserPermissionsRow, type MessageRow } from './db.js';
import {
  folderAllowed,
  isUploadRequest,
  isGitRequest,
  isAionuiFileRead,
  isAionuiFileWrite,
  isAionuiPanel,
  aionuiRootFrom,
  isWorkspaceWrite,
  isStaticAsset,
  isPollingRequest,
  isUsageAnchorRequest,
  WORKSPACE_ENDPOINT_RE,
  extractPathFromBody,
  filterByPathField,
  collectIdPathPairs,
  extractWorkspaceId,
  findStringField,
  sandboxPresetRank,
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  forceRejectApproval,
  SANDBOX_RANK,
  todayLocal,
} from './permissions.js';
import { findDshRoot, applyRemotePatch, restartDshWeb } from './patch.js';
import { t, resolveGatewayLang, type Lang } from './i18n.js';

/** 网关内部扩展请求：权限执行时把用户/权限附在 req 上，供后续中间件与代理读取 */
type Req = Request & {
  dshpwUser?: number;
  dshpwPerms?: UserPermissionsRow;
};

const COOKIE_NAME = 'dsh_gateway_token';
/** 语言偏好 cookie（用户在登录页手动切换后持久化） */
const LANG_COOKIE = 'dshpw_lang';

/** 解析页面语言：?lang → cookie → dsh 设置(locale.preference) → 浏览器语言 → zh */
function langOf(req: Request): Lang {
  return resolveGatewayLang({
    queryLang: req.query.lang,
    cookieLang: readCookie(req.headers.cookie, LANG_COOKIE),
    acceptLanguage: req.headers['accept-language'],
  });
}

/**
 * 注入 dsh HTML 的兼容脚本：
 * crypto.randomUUID 是 Web Crypto API，只在安全上下文（HTTPS / localhost）
 * 存在；明文 HTTP 部署下 dsh 前端的 RPC id 生成（如加载 Agent 预设）会报
 * "crypto.randomUUID is not a function"。这里用 getRandomValues（HTTP 下
 * 可用）实现 UUID v4 补齐。
 */
const INJECT_SCRIPT = `<script>
(function () {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID !== 'function' && typeof crypto.getRandomValues === 'function') {
    crypto.randomUUID = function () {
      var b = crypto.getRandomValues(new Uint8Array(16));
      b[6] = (b[6] & 15) | 64;
      b[8] = (b[8] & 63) | 128;
      var h = Array.prototype.map.call(b, function (x) {
        return x.toString(16).padStart(2, '0');
      }).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    };
  }
})();
</script>`;

function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name && rest.length > 0) {
      const raw = rest.join('=');
      try {
        return decodeURIComponent(raw);
      } catch {
        // 畸形百分号编码（如 %zz）：返回原值，JWT 校验自然失败，不抛 URIError 500
        return raw;
      }
    }
  }
  return null;
}

/**
 * 防开放重定向：next 只允许站内路径。
 * 拒绝一切浏览器可能解析成跨域的形式：
 *   - 反斜杠（浏览器按 '/' 解析：/\evil.com → //evil.com 协议相对跳转）
 *   - 解码后以 // 开头（%2F%2F 解码后成 //）
 *   - 非 / 开头、控制字符/空白
 */
function safeNext(next: string | undefined): string {
  if (!next) return '/';
  let decoded: string;
  try {
    decoded = decodeURIComponent(next);
  } catch {
    return '/';
  }
  if (decoded.includes('\\')) return '/';
  if (!decoded.startsWith('/') || decoded.startsWith('//')) return '/';
  if (/[\u0000-\u0020\u007f]/.test(decoded)) return '/';
  return decoded;
}

// ── CSRF（double-submit token）────────────────────────────────
// 登录/配置表单：GET 渲染时下发 Cookie + 表单隐藏域同一随机值，
// POST 时恒定时间比对。无服务端会话也能防跨站表单伪造。
const CSRF_COOKIE = 'dsh_csrf';

function newCsrfToken(): string {
  return randomBytes(16).toString('hex');
}

function csrfMatches(cookieValue: string | null, fieldValue: string): boolean {
  if (!cookieValue || cookieValue.length !== fieldValue.length) return false;
  return timingSafeEqual(Buffer.from(cookieValue), Buffer.from(fieldValue));
}

function setCsrfCookie(res: Response, token: string, secure: boolean): void {
  res.setHeader(
    'Set-Cookie',
    `${CSRF_COOKIE}=${token}; Path=/gateway; HttpOnly; SameSite=Lax; Max-Age=3600${
      secure ? '; Secure' : ''
    }`,
  );
}

// ── 主题同步：合理化跟随 dsh 主题 ─────────────────────────────
// dsh 的主题偏好持久化在 <dsh home>/settings.yaml 的 ui-theme.preference
// （light|dark|system，默认 system）。网关在渲染登录/配置页时读取该文件，
// 注入引导脚本在浏览器端解析（system 走 prefers-color-scheme，与 dsh 的
// boot-theme 逻辑一致）。文件不可读时回退 system；可用 MCP_DSH_SETTINGS_FILE
// 显式指定 dsh 设置文件路径（网关与 dsh 不同机时用）。
type ThemePreference = 'light' | 'dark' | 'system';

function readDshThemePreference(): ThemePreference {
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
      const block = text.match(/^ui-theme\s*:\s*(?:#.*)?$/m);
      if (!block || block.index === undefined) continue;
      const rest = text.slice(block.index);
      const hit = rest.match(/^\s+preference\s*:\s*["']?(light|dark|system)["']?\s*(?:#.*)?$/m);
      if (hit) return hit[1] as ThemePreference;
    } catch {
      // 文件不存在/不可读：继续尝试下一个候选，最终回退 system
    }
  }
  return 'system';
}

/** 主题引导脚本：在 <head> 内尽早设置 data-theme 与 color-scheme，避免闪烁 */
function themeBootScript(preference: ThemePreference): string {
  return `<script>(function(){var pref=${JSON.stringify(preference)};var mq=window.matchMedia&&matchMedia('(prefers-color-scheme: dark)');function apply(){var dark=pref==='dark'||(pref==='system'&&mq&&mq.matches);document.documentElement.setAttribute('data-theme',dark?'dark':'light');document.documentElement.style.colorScheme=dark?'dark':'light';}apply();if(pref==='system'&&mq){try{mq.addEventListener('change',apply)}catch(e){mq.addListener(apply)}}})();</script>`;
}

/**
 * 登录/配置页共享样式：完全采用 dsh 设计令牌（design-platform.css）
 * - 浅色为默认（dsh 默认主题 = 简约白色）：bg #fff、主文字 rgb(15,17,21)、
 *   品牌蓝 rgb(65,118,230)（deepseek-500）、边框 rgba(0,0,0,.1) 等
 * - html[data-theme=dark] 覆盖为 dsh 暗色令牌（neutral-bluish-950 等）
 * - 输入框修复：-webkit-autofill 会把输入栏刷成白色/黄色（粘贴触发布局），
 *   用 inset 大阴影 + text-fill-color 回压为当前主题输入底色
 * - 动画只动 transform/opacity/box-shadow，并尊重 prefers-reduced-motion
 */
const PAGE_STYLE = `
:root{
  --bg:rgb(255,255,255);
  --card:rgba(255,255,255,.94);
  --field:rgb(255,255,255);
  --txt:rgb(15,17,21);
  --sub:rgb(97,102,107);
  --muted:rgb(129,133,140);
  --caption:rgb(173,178,184);
  --border:rgba(0,0,0,.1);
  --border-soft:rgba(0,0,0,.06);
  --border-strong:rgba(0,0,0,.16);
  --brand:rgb(65,118,230);
  --brand-hi:rgb(86,134,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.08);
  --danger-border:rgba(242,90,90,.3);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.1);
  --warn-border:rgba(247,173,49,.35);
  --ring:rgba(65,118,230,.16);
  --glow-a:rgba(77,147,248,.18);
  --glow-b:rgba(103,65,217,.09);
  --glow-c:rgba(96,165,250,.11);
  --grid-line:rgba(15,17,21,.03);
  --shadow-card:0 24px 48px -24px rgba(15,23,42,.18),0 2px 8px rgba(15,23,42,.05);
  --shadow-field:0 1px 2px rgba(15,23,42,.05);
  --shadow-btn:0 4px 14px -4px rgba(65,118,230,.5);
}
html[data-theme=dark]{
  --bg:rgb(21,21,23);
  --card:rgba(35,35,36,.92);
  --field:rgb(44,44,46);
  --txt:rgb(249,250,251);
  --sub:rgb(207,211,214);
  --muted:rgb(173,178,184);
  --caption:rgb(129,133,140);
  --border:rgba(255,255,255,.12);
  --border-soft:rgba(255,255,255,.06);
  --border-strong:rgba(255,255,255,.2);
  --brand:rgb(86,134,254);
  --brand-hi:rgb(103,158,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.14);
  --danger-border:rgba(242,90,90,.35);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.12);
  --warn-border:rgba(247,173,49,.4);
  --ring:rgba(86,134,254,.28);
  --glow-a:rgba(86,134,254,.15);
  --glow-b:rgba(103,65,217,.13);
  --glow-c:rgba(96,165,250,.09);
  --grid-line:rgba(255,255,255,.025);
  --shadow-card:0 24px 60px -20px rgba(0,0,0,.6);
  --shadow-field:0 1px 2px rgba(0,0,0,.3);
  --shadow-btn:0 4px 18px -4px rgba(86,134,254,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei','Helvetica Neue',Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;overflow:hidden;-webkit-font-smoothing:antialiased}
.orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.orbs i{position:absolute;border-radius:50%;filter:blur(80px);will-change:transform;animation:drift 22s ease-in-out infinite}
.orbs .a{width:46vw;height:46vw;max-width:520px;max-height:520px;left:-12vw;top:-14vh;background:radial-gradient(circle,var(--glow-a),transparent 68%)}
.orbs .b{width:40vw;height:40vw;max-width:440px;max-height:440px;right:-10vw;bottom:-12vh;background:radial-gradient(circle,var(--glow-b),transparent 68%);animation-delay:-7s}
.orbs .c{width:30vw;height:30vw;max-width:320px;max-height:320px;right:16vw;top:-16vh;background:radial-gradient(circle,var(--glow-c),transparent 68%);animation-delay:-13s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(4vw,3vh) scale(1.08)}66%{transform:translate(-3vw,2vh) scale(.95)}}
.grid{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(var(--grid-line) 1px,transparent 1px),linear-gradient(90deg,var(--grid-line) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%);mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%)}
.card{position:relative;z-index:10;width:100%;max-width:400px;margin:0 16px;background:var(--card);border:1px solid var(--border-soft);border-radius:16px;padding:32px 32px 28px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:var(--shadow-card);animation:enter .55s cubic-bezier(.22,1,.36,1) both}
@keyframes enter{from{opacity:0;transform:translateY(20px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
.logo{width:48px;height:48px;margin:0 auto 16px;border-radius:14px;background:linear-gradient(135deg,var(--brand-hi),var(--brand));display:flex;align-items:center;justify-content:center;box-shadow:0 8px 20px -6px var(--shadow-btn);position:relative}
.logo::after{content:"";position:absolute;inset:-4px;border-radius:18px;border:1px solid var(--ring);opacity:0;animation:ping 4s ease-out infinite}
@keyframes ping{0%{opacity:.7;transform:scale(.92)}55%{opacity:0;transform:scale(1.18)}100%{opacity:0}}
h1{font-size:20px;font-weight:600;letter-spacing:-.01em;text-align:center}
.sub{margin-top:8px;font-size:13px;color:var(--muted);text-align:center;line-height:1.5}
label{display:block;margin-top:14px}
label span{display:block;margin-bottom:6px;font-size:12px;font-weight:500;color:var(--sub)}
input,button{font-family:inherit}
input{width:100%;padding:10px 14px;font-size:14px;line-height:20px;color:var(--txt);background:var(--field);border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-field);transition:border-color .16s,box-shadow .16s;caret-color:var(--brand)}
input::placeholder{color:var(--caption)}
input::selection{background:var(--ring)}
input:hover{border-color:var(--border-strong)}
input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--ring),var(--shadow-field)}
input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus{-webkit-text-fill-color:var(--txt);-webkit-box-shadow:0 0 0 1000px var(--field) inset;box-shadow:0 0 0 1000px var(--field) inset;caret-color:var(--txt);transition:background-color 999999s ease-in-out 0s}
button{margin-top:22px;width:100%;padding:10px 16px;font-size:14px;font-weight:500;color:#fff;background:linear-gradient(135deg,var(--brand-hi),var(--brand));border:none;border-radius:10px;cursor:pointer;box-shadow:var(--shadow-btn);transition:transform .16s,box-shadow .16s,filter .16s}
button:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 6px 22px -4px var(--shadow-btn)}
button:active:not(:disabled){transform:translateY(0) scale(.99);filter:brightness(.96)}
button:disabled{opacity:.7;cursor:default}
.error-bar{display:none;margin-top:14px;padding:8px 12px;font-size:12px;color:var(--danger);background:var(--danger-soft);border:1px solid var(--danger-border);border-radius:8px;animation:shake .4s}
.db-hint{margin-top:14px;padding:8px 12px;font-size:12px;color:var(--warn);background:var(--warn-soft);border:1px solid var(--warn-border);border-radius:8px}
@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-10px)}40%{transform:translateX(10px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}}
.rules{margin-top:12px;display:flex;flex-wrap:wrap;gap:4px 12px;font-size:11px;color:var(--caption)}
.rules span{display:inline-flex;align-items:center;gap:4px}
.rules span.on{color:var(--ok)}
.strength{height:4px;margin-top:10px;border-radius:999px;background:var(--field);border:1px solid var(--border-soft);overflow:hidden}
.strength i{display:block;height:100%;width:0;border-radius:999px;background:var(--danger);transition:width .32s cubic-bezier(.22,1,.36,1),background .32s}
.lang-switch{position:absolute;top:14px;right:16px;display:flex;gap:12px;font-size:12px}
.lang-switch a{color:var(--caption);text-decoration:none;transition:color .15s}
.lang-switch a:hover{color:var(--sub)}
.lang-switch a.on{color:var(--brand);font-weight:600}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

/** 语言切换链接：中文 / English（当前语言高亮，点击带 ?lang= 走同一个登录路径） */
function langSwitch(lang: Lang, next: string): string {
  const query = next === '' ? '' : `?next=${encodeURIComponent(next)}`;
  const mk = (id: Lang, label: string) =>
    `<a${lang === id ? ' class="on"' : ''} href="/gateway/login${query}${query === '' ? '?' : '&'}lang=${id}">${label}</a>`;
  return `<div class="lang-switch">${mk('zh', '中文')}${mk('en', 'English')}</div>`;
}

/** 页面骨架：共享 head（主题引导 + 样式）+ 背景动画层 + 卡片容器 */
function pageShell(params: { lang: Lang; title: string; body: string; script?: string }): string {
  return `<!doctype html>
<html lang="${params.lang === 'en' ? 'en' : 'zh-CN'}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${params.title}</title>
${themeBootScript(readDshThemePreference())}
<style>${PAGE_STYLE}</style>
</head>
<body>
<div class="orbs" aria-hidden="true"><i class="a"></i><i class="b"></i><i class="c"></i></div>
<div class="grid" aria-hidden="true"></div>
<div class="card">${params.body}</div>
${params.script ?? ''}
</body>
</html>`;
}

function renderLoginPage(params: { lang: Lang; next: string; error?: string; dbHealthy: boolean; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const dbHint = params.dbHealthy
    ? ''
    : `<div class="db-hint">${escapeHtml(tr('gw.dbHint'))}</div>`;
  const body = `
  <div class="logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
  ${langSwitch(params.lang, params.next)}
  <h1>${tr('gw.loginTitle')}</h1>
  <p class="sub">${tr('gw.loginSub1')}<br/>${tr('gw.loginSub2')}</p>
  <form method="POST" action="/gateway/login" id="login-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <input type="hidden" name="next" value="${escapeHtml(params.next)}" />
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernamePlaceholder')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" placeholder="${tr('gw.passwordPlaceholder')}" autocomplete="current-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.login')}</button>
  </form>
  ${errorBlock}
  ${dbHint}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleLogin'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  document.getElementById('login-form').addEventListener('submit', () => {
    const btn = document.getElementById('submit-btn');
    btn.textContent = ${JSON.stringify(tr('gw.loggingIn'))};
    btn.disabled = true;
  });
</script>`,
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── 首次配置页（平台未初始化时显示；预设密钥 + 用户名 + 密码） ──
function renderSetupPage(params: { lang: Lang; error?: string; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const body = `
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  ${langSwitch(params.lang, '')}
  <h1>${tr('gw.setupTitle')}</h1>
  <p class="sub">${tr('gw.setupSub1')}<br/>${tr('gw.setupSub2')}</p>
  <form method="POST" action="/gateway/setup" id="setup-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <label><span>${tr('gw.setupKey')}</span><input type="password" name="setupKey" placeholder="${tr('gw.setupKeyPlaceholder')}" required /></label>
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernameRule')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" id="pw" placeholder="${tr('gw.passwordRule')}" autocomplete="new-password" required /></label>
    <div class="strength"><i id="pw-bar"></i></div>
    <div class="rules" id="pw-rules">
      <span data-r="len">○ ${tr('gw.ruleLen')}</span>
      <span data-r="up">○ ${tr('gw.ruleUp')}</span>
      <span data-r="low">○ ${tr('gw.ruleLow')}</span>
      <span data-r="num">○ ${tr('gw.ruleNum')}</span>
      <span data-r="sym">○ ${tr('gw.ruleSym')}</span>
    </div>
    <label><span>${tr('gw.confirmPassword')}</span><input type="password" name="confirm" placeholder="${tr('gw.confirmPlaceholder')}" autocomplete="new-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.initPlatform')}</button>
  </form>
  ${errorBlock}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleSetup'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  const pw = document.getElementById('pw');
  const bar = document.getElementById('pw-bar');
  const COLORS = ['#f25a5a', '#f7ad31', '#f59e0b', '#4d93f8', '#22c55e'];
  pw.addEventListener('input', () => {
    const v = pw.value;
    const rules = {
      len: v.length >= 12, up: /[A-Z]/.test(v), low: /[a-z]/.test(v),
      num: /[0-9]/.test(v), sym: /[^A-Za-z0-9]/.test(v),
    };
    let n = 0;
    document.querySelectorAll('#pw-rules span').forEach((el) => {
      const ok = rules[el.dataset.r];
      if (ok) n++;
      el.className = ok ? 'on' : '';
      el.textContent = (ok ? '✓ ' : '○ ') + el.textContent.replace(/^[✓○] /, '');
    });
    const pct = Math.max(20, (n / 5) * 100);
    bar.style.width = pct + '%';
    bar.style.background = COLORS[Math.max(0, n - 1)];
  });
  document.getElementById('setup-form').addEventListener('submit', (e) => {
    const pwv = pw.value;
    const confirm = document.querySelector('input[name=confirm]').value;
    if (pwv !== confirm) {
      e.preventDefault();
      const err = document.getElementById('error-bar');
      err.textContent = ${JSON.stringify(tr('gw.passwordMismatch'))};
      err.style.display = 'block';
      err.style.animation = 'none';
      void err.offsetWidth;
      err.style.animation = 'shake .4s';
      return;
    }
    const btn = document.getElementById('submit-btn');
    btn.textContent = ${JSON.stringify(tr('gw.initializing'))};
    btn.disabled = true;
  });
</script>`,
  });
}

export function createGatewayServer(
  config: PlatformConfig,
  auth: AuthService,
  db: Database,
): http.Server {
  const app = express();
  // 不泄露框架信息
  app.disable('x-powered-by');
  // 仅解析 /gateway 表单请求；代理请求的 body 必须原样透传给上游
  // （全局 express.json/urlencoded 会消费掉请求流，导致上游收到空 body）
  app.use('/gateway', express.urlencoded({ extended: false }));

  // HTTPS 模式：全站 HSTS（浏览器强制后续走 HTTPS）+ 会话 Cookie 加 Secure
  //（Cookie 标志在登录处理器内按 config.gateway.tls 决定）
  if (config.gateway.tls !== null) {
    app.use((_req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      next();
    });
  }

  // 登录/配置页安全响应头（仅 /gateway/* 自有页面；代理的 dsh 响应不强制
  // CSP，避免破坏 dsh 前端）：禁嗅探、禁嵌入、无 Referrer、禁缓存、禁索引
  app.use('/gateway', (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    // 页面完全自包含（内联 CSS/JS、无外部资源）：可以上严格 CSP
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    next();
  });

  const upstream = new URL(config.gateway.upstream);
  const upstreamHost = upstream.hostname;
  const upstreamPort = Number(upstream.port || 80);

  // 上游连接池：复用与 dsh 的 TCP 连接（keep-alive），
  // 避免每个代理请求都新建一次 TCP 握手
  const upstreamAgent = new http.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 30_000 });

  // workspaceId → 规范路径 映射：从 workspace.list 响应里收集，供 session.create 用 workspaceId 时解析路径
  const workspacePathById = new Map<string, string>();

  /**
   * 从 Cookie 校验会话；返回用户或 null（用户已不存在时旧 token 立即失效）。
   * 性能：同一 token 的验签 + 用户存在性查询结果缓存 30 秒——每个代理
   * 请求（含静态资源）都要走鉴权，缓存后只剩一次 Map 查找，避免逐请求
   * 重复 JWT 验签 + SQLite 查询 + HMAC/AES。
   */
  const sessionCache = new Map<
    string,
    { user: { userId: number; username: string }; expireAt: number }
  >();
  const SESSION_CACHE_TTL_MS = 30_000;

  function sessionOf(req: Request): { userId: number; username: string } | null {
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) return null;
    const now = Date.now();
    const hit = sessionCache.get(token);
    if (hit) {
      if (hit.expireAt > now) return hit.user;
      sessionCache.delete(token);
    }
    try {
      const user = auth.verifyToken(token);
      // 用户被删除/重置/改密后旧会话必须失效（缓存有效期 30 秒内生效）
      const row = db.getUserByUsername(user.username);
      if (row === null) return null;
      if (user.cv !== row.credential_version) return null;
      sessionCache.set(token, { user, expireAt: now + SESSION_CACHE_TTL_MS });
      return user;
    } catch {
      return null;
    }
  }

  /** 子用户权限：缺行时返回默认（全量允许、未封禁） */
  function effectivePermissions(userId: number): UserPermissionsRow {
    return (
      db.getPermissions(userId) ?? {
        user_id: userId,
        allowed_folders: [],
        hourly_token_limit: null,
        daily_minutes_limit: null,
        allow_upload: true,
        allow_git_download: true,
        banned: false,
        sandbox_mode: null,
        updated_at: '',
      }
    );
  }

  /** 从会话 cookie 解析完整用户（含角色）；无会话/失效返回 null */
  function authedUser(req: Request): { userId: number; username: string; role: 'admin' | 'user' } | null {
    const s = sessionOf(req);
    if (!s) return null;
    const row = db.getUserById(s.userId);
    if (!row) return null;
    return { userId: row.id, username: row.username, role: row.role === 'admin' ? 'admin' : 'user' };
  }

  /** 统一 403 页面（封禁 / 权限拒绝） */
  function forbiddenPage(lang: Lang, message: string): string {
    return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title></head><body style="font-family:system-ui;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="margin:0 0 8px">403</h1><p style="margin:0;opacity:.7">${escapeHtml(message)}</p></div></body></html>`;
  }

  /** 用量节流：每 15 秒最多写一次活跃时间，返回当前用量（用于配额判定） */
  const usageThrottle = new Map<number, number>();
  function touchUsageThrottled(userId: number) {
    const now = Date.now();
    const day = todayLocal();
    const last = usageThrottle.get(userId) ?? 0;
    if (now - last >= 15000) {
      usageThrottle.set(userId, now);
      return db.touchUsage(userId, day, new Date().toISOString());
    }
    return db.getUsage(userId, day);
  }

  // ── 留言 / 聊天（SSE 广播） ────────────────────────────────
  // 订阅者带 userId，广播时按收件人过滤（与 GET /gateway/api/messages 的
  // 列表语义一致）：定向消息只推给收件人与发件人，公开消息推给所有人。
  const chatClients = new Set<{ res: Response; userId: number }>();
  function broadcastMessage(msg: MessageRow): void {
    const payload = `data: ${JSON.stringify(msg)}\n\n`;
    for (const client of chatClients) {
      const visible =
        msg.recipient_id === null || msg.recipient_id === client.userId || msg.sender_id === client.userId;
      if (!visible) continue;
      try {
        client.res.write(payload);
      } catch {
        chatClients.delete(client);
      }
    }
  }

  // ── 登录页（GET）：平台未初始化时显示首次配置页 ─────────────
  app.get('/gateway/login', async (req, res) => {
    const next = safeNext(typeof req.query.next === 'string' ? req.query.next : undefined);
    const lang = langOf(req);
    const queryLang = typeof req.query.lang === 'string' ? req.query.lang : null;
    const [initialized, dbHealthy] = await Promise.all([
      auth.isInitialized().catch(() => false),
      db.health().catch(() => false),
    ]);
    // 每次渲染下发新 CSRF token（Cookie + 表单隐藏域）
    const csrf = newCsrfToken();
    setCsrfCookie(res, csrf, config.gateway.tls !== null);
    // 显式 ?lang= 选择持久化到 cookie（语言切换链接点出来的）。
    // 注意 Set-Cookie 头已由 CSRF 占用，这里用数组追加而不是 setHeader 覆盖。
    if (queryLang === 'zh' || queryLang === 'en') {
      const langCookie = `${LANG_COOKIE}=${queryLang}; Path=/gateway; SameSite=Lax; Max-Age=31536000${
        config.gateway.tls !== null ? '; Secure' : ''
      }`;
      const existing = res.getHeader('Set-Cookie');
      const prev: string[] = Array.isArray(existing)
        ? existing.map((value) => String(value))
        : existing
          ? [String(existing)]
          : [];
      res.setHeader('Set-Cookie', [...prev, langCookie]);
    }
    if (!initialized) {
      res.type('html').send(renderSetupPage({ lang, csrf }));
      return;
    }
    res.type('html').send(renderLoginPage({ lang, next, dbHealthy, csrf }));
  });

  // ── 首次配置提交（POST）→ 302 回登录页 ────────────────────────
  app.post('/gateway/setup', async (req, res) => {
    const setupKey = typeof req.body?.setupKey === 'string' ? req.body.setupKey : '';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const csrf = newCsrfToken();
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res
        .status(403)
        .type('html')
        .send(renderSetupPage({ lang: langOf(req), error: t(langOf(req), 'gw.csrfFailed'), csrf }));
      return;
    }

    try {
      await auth.setup({ setupKey, username, password }, meta);
      res.redirect(302, '/gateway/login');
    } catch (error) {
      // 真实状态码：409 已初始化 / 401 密钥错误 / 400 参数错误
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.initFailed');
      const csrf = newCsrfToken();
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res.status(status).type('html').send(renderSetupPage({ lang, error: message, csrf }));
    }
  });

  // ── 登录提交（POST） → Set-Cookie + 302 重定向兼容层 ────────
  app.post('/gateway/login', async (req, res) => {
    const next = safeNext(typeof req.body?.next === 'string' ? req.body.next : undefined);
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken();
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res
        .status(403)
        .type('html')
        .send(
          renderLoginPage({ lang: langOf(req), next, error: t(langOf(req), 'gw.csrfFailed'), dbHealthy, csrf }),
        );
      return;
    }

    try {
      const { token } = await auth.login({ username, password }, meta);
      res.setHeader(
        'Set-Cookie',
        `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${
          config.gateway.tls !== null ? '; Secure' : ''
        }`,
      );
      // 中文/非 ASCII 路径需重新编码（Node 的 Location 头只接受 latin1，
      // 直接 setHeader 会抛 ERR_INVALID_CHAR → 500）
      res.redirect(302, encodeURI(next));
    } catch (error) {
      // 真实状态码：429 锁定 / 401 凭据错误 / 400 其他
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.loginFailed');
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken();
      setCsrfCookie(res, csrf, config.gateway.tls !== null);
      res.status(status).type('html').send(renderLoginPage({ lang, next, error: message, dbHealthy, csrf }));
    }
  });

  // ── 登出 ─────────────────────────────────────────────────────
  app.get('/gateway/logout', (_req, res) => {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0`);
    res.redirect(302, '/gateway/login');
  });

  // ── 内部接口：dsh 插件通知网关重载远程设置补丁 ───────────────
  // 仅限本机 dsh 插件调用：要求回环地址 + 恒定时间比对内部密钥
  // （密钥由 SETUP_KEY 派生，泄漏面与安装密钥一致）。响应立即返回，
  // 补丁应用与 dsh 重启异步进行，让设置页的响应先刷给浏览器。
  app.post('/gateway/internal/patch', express.json({ limit: '4kb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(secret);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    res.status(202).json({ ok: true });
    setTimeout(() => {
      try {
        const root = findDshRoot(config.patch.dshRoot);
        if (!root) return;
        const result = applyRemotePatch(root);
        if (result === 'applied' && config.patch.restartService) {
          restartDshWeb(config.patch.restartService, 2500);
        }
      } catch (error) {
        console.error('[dsh-passwords] 补丁重载失败:', error);
      }
    }, 500);
  });

  // ── 内部辅助：API 路由的输入清洗 ───────────────────────────
  const nullableInt = (v: unknown): number | null => {
    const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
    if (!Number.isInteger(n) || n < 0) return null;
    return n;
  };
  const stringArray = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, 64) : [];

  // 统一 API 鉴权：跨站拒绝 + 会话校验 + 可选主用户门控
  const apiAuth = (req: Request, res: Response, requireAdmin = false) => {
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      res.status(403).json({ ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
      return null;
    }
    const user = authedUser(req);
    if (!user) {
      res.status(401).json({ ok: false, code: 'NOT_AUTHENTICATED', error: '未登录或会话已失效' });
      return null;
    }
    if (requireAdmin && user.role !== 'admin') {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
      return null;
    }
    return user;
  };

  const jsonBody = express.json({ limit: '256kb' });

  // ── 概览（仅主用户）：所有用户 + 权限 + 当日用量 ─────────────
  app.get('/gateway/api/overview', (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const day = todayLocal();
    const users = db.listUsers().map((u) => {
      const perms = effectivePermissions(u.id);
      const usage = db.getUsage(u.id, day);
      return {
        id: u.id,
        username: u.username,
        role: u.role,
        permissions: {
          allowedFolders: perms.allowed_folders,
          hourlyTokenLimit: perms.hourly_token_limit,
          dailyMinutesLimit: perms.daily_minutes_limit,
          allowUpload: perms.allow_upload,
          allowGitDownload: perms.allow_git_download,
          banned: perms.banned,
          sandboxMode: perms.sandbox_mode,
        },
        usage: usage
          ? {
              day: usage.day,
              activeSeconds: usage.active_seconds,
              hourlyTokens: usage.hourly_tokens,
              firstSeenAt: usage.first_seen_at,
              lastActiveAt: usage.last_active_at,
            }
          : null,
      };
    });
    res.json({ ok: true, me: { id: me.userId, username: me.username, role: me.role }, users });
  });

  // ── 更新某子用户权限（仅主用户） ─────────────────────────────
  app.post('/gateway/api/permissions', jsonBody, (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const userId = Number(body.userId);
    if (!Number.isInteger(userId) || userId <= 0) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'userId 无效' });
      return;
    }
    const target = db.getUserById(userId);
    if (!target) {
      res.status(404).json({ ok: false, code: 'NO_SUCH_USER', error: '用户不存在' });
      return;
    }
    if (target.role === 'admin') {
      res.status(400).json({ ok: false, code: 'FORBIDDEN', error: '不能修改主用户权限' });
      return;
    }
    const allowedFolders = stringArray(body.allowedFolders);
    // 0 归一为 null（=不限）：避免"每日 0 分钟"被误当作"首次使用即封禁"
    const rawToken = nullableInt(body.hourlyTokenLimit);
    const rawMinutes = nullableInt(body.dailyMinutesLimit);
    const hourlyTokenLimit = rawToken === 0 ? null : rawToken;
    const dailyMinutesLimit = rawMinutes === 0 ? null : rawMinutes;
    const allowUpload = body.allowUpload !== false;
    const allowGitDownload = body.allowGitDownload !== false;
    const banned = body.banned === true;
    const rawSandbox = typeof body.sandboxMode === 'string' ? body.sandboxMode : '';
    const sandboxMode =
      rawSandbox === 'read-only' || rawSandbox === 'workspace-write' || rawSandbox === 'danger-full-access'
        ? rawSandbox
        : null;
    db.setPermissions(userId, {
      allowedFolders,
      hourlyTokenLimit,
      dailyMinutesLimit,
      allowUpload,
      allowGitDownload,
      banned,
      sandboxMode,
    });
    db.audit('permissions_changed', {
      username: target.username,
      detail: JSON.stringify({
        allowedFolders,
        hourlyTokenLimit,
        dailyMinutesLimit,
        allowUpload,
        allowGitDownload,
        banned,
        sandboxMode,
      }),
    });
    res.json({ ok: true });
  });

  // ── token 用量上报（客户端 liveTokenUsage 投影增量，所有登录用户） ──
  // 替代旧的 HTTP 响应正则计量：客户端复用 dsh 的 tokenUsage 投影（与
  // dsh-web-ui 同源），只上报「增量」，服务端按小时窗口累计并用于配额判定。
  // 客户端 15 秒 flush 一次；这里再加 5 秒最小间隔节流，防止被高频自刷。
  const usageReportThrottle = new Map<number, number>();
  app.post('/gateway/api/usage/report', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const now = Date.now();
    const last = usageReportThrottle.get(me.userId) ?? 0;
    if (now - last < 5000) {
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '上报过于频繁' });
      return;
    }
    usageReportThrottle.set(me.userId, now);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const tokens = Number(body.tokens);
    if (!Number.isFinite(tokens) || tokens < 0 || tokens > 100_000_000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'tokens 无效' });
      return;
    }
    const rounded = Math.round(tokens);
    if (rounded <= 0) {
      res.json({ ok: true });
      return;
    }
    db.addTokens(me.userId, todayLocal(), rounded, new Date().toISOString());
    res.json({ ok: true });
  });

  // ── 留言列表（所有登录用户；按收件人过滤） ─────────────────────
  app.get('/gateway/api/messages', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const all = db.listMessages(300);
    const mine = all.filter(
      (m) => m.recipient_id === null || m.recipient_id === me.userId || m.sender_id === me.userId,
    );
    res.json({ ok: true, me: { id: me.userId, username: me.username, role: me.role }, messages: mine });
  });

  // ── 发送留言（所有登录用户） ─────────────────────────────────
  app.post('/gateway/api/messages', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const content = typeof body.content === 'string' ? body.content.trim() : '';
    if (content === '') {
      res.status(400).json({ ok: false, code: 'INVALID', error: '内容不能为空' });
      return;
    }
    if (content.length > 4000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '内容过长' });
      return;
    }
    const recipientId = nullableInt(body.recipientId);
    const tags = stringArray(body.tags).slice(0, 8);
    const msg = db.addMessage(me.userId, recipientId, content, tags);
    broadcastMessage(msg);
    res.json({ ok: true, message: msg });
  });

  // ── SSE 实时推送（所有登录用户） ─────────────────────────────
  app.get('/gateway/api/messages/stream', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    res.write(`data: ${JSON.stringify({ type: 'init', me: { id: me.userId, username: me.username, role: me.role } })}\n\n`);
    const client = { res, userId: me.userId };
    chatClients.add(client);
    req.on('close', () => chatClients.delete(client));
  });

  // ── 认证门卫：非 /gateway 请求必须带有效会话 ─────────────────
  // 路径先用 WHATWG URL 规范化（. / .. / %2e%2e 均被归一），再做前缀判断——
  // 否则 /gateway/../api/xxx 会绕过前缀检查直达上游（dsh 侧 new URL 同样
  // 会归一化该路径，等于未认证调用任意 RPC）。解析失败一律按未认证处理，绝不 500。
  app.use((req, res, next) => {
    try {
      const parsed = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      // /gateway 精确路径与 /gateway/* 都视为网关自有前缀（未注册子路径由
      // 后续中间件处理，避免透传到上游 dsh）
      if (parsed.pathname === '/gateway' || parsed.pathname.startsWith('/gateway/')) return next();
      const user = sessionOf(req);
      if (!user) {
        // 重定向兼容层：记录原始 URL，登录后跳回
        const nextUrl = encodeURIComponent(req.originalUrl);
        res.redirect(302, `/gateway/login?next=${nextUrl}`);
        return;
      }
      const row = db.getUserById(user.userId);
      if (!row) {
        res.redirect(302, `/gateway/login?next=${encodeURIComponent(req.originalUrl)}`);
        return;
      }
      if (row.role !== 'admin') {
        const perms = effectivePermissions(user.userId);
        const lang = langOf(req);
        if (perms.banned) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.banned')));
          return;
        }
        if (!perms.allow_upload && isUploadRequest(req.method, parsed.pathname)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noUpload')));
          return;
        }
        if (!perms.allow_git_download && (isGitRequest(parsed.pathname) || isAionuiFileRead(req.method, parsed.pathname))) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noGit')));
          return;
        }
        if (!perms.allow_upload && isAionuiFileWrite(req.method, parsed.pathname)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noUpload')));
          return;
        }
        if (perms.allowed_folders.length > 0 && isWorkspaceWrite(parsed.pathname)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
          return;
        }
        // aionui-panel 文件树：GET/HEAD 的 root 在 query 里，直接校验白名单（拦截目录浏览/下载）
        if (perms.allowed_folders.length > 0 && (req.method === 'GET' || req.method === 'HEAD')) {
          const aionuiRoot = aionuiRootFrom(req.method, parsed.pathname, parsed.searchParams, null);
          if (aionuiRoot !== null && !folderAllowed(aionuiRoot, perms.allowed_folders)) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        if (!isStaticAsset(parsed.pathname) && !isPollingRequest(parsed.pathname)) {
          // 配额计时从子用户“说第一句话”（发消息锚点）才开始：
          // 未使用过的子用户（无当日记录且非锚点请求）不创建记录、不受配额限制
          const day = todayLocal();
          if (db.getUsage(user.userId, day) !== null || isUsageAnchorRequest(parsed.pathname)) {
            const usage = touchUsageThrottled(user.userId);
            if (usage) {
              if (perms.daily_minutes_limit !== null && usage.active_seconds >= perms.daily_minutes_limit * 60) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.timeLimit')));
                return;
              }
              if (perms.hourly_token_limit !== null && usage.hourly_tokens >= perms.hourly_token_limit) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.tokenLimit')));
                return;
              }
            }
          }
        }
        // 附上权限与用户，供后续文件夹限制中间件 / 代理 token 计量使用
        (req as Req).dshpwUser = user.userId;
        (req as Req).dshpwPerms = perms;
      }
      return next();
    } catch {
      res.redirect(302, '/gateway/login');
    }
  });

  // ── 反向代理（HTTP）→ 上游 dsh ──────────────────────────────
  app.use((req, res) => {
    const headers: Record<string, string | string[] | undefined> = { ...req.headers };
    // 改写 Host 为上游地址（过 dsh 的 browser-trust fence 第 1 道：Host 检查）
    headers.host = `${upstreamHost}:${upstreamPort}`;
    // 改写 Origin 为上游地址（过第 3 道：Origin 必须与 Host 同 host——
    // 浏览器发来的是网关地址 origin，与改写后的 Host 不一致会被 403）
    if (typeof headers.origin === 'string') {
      headers.origin = `http://${upstreamHost}:${upstreamPort}`;
    }
    delete headers['content-length'];
    // 缓冲/改写路径用 end(body) 重写 content-length，chunked 的 transfer-encoding
    // 若保留会造成 Node 的 ERR_HTTP_CONTENT_LENGTH_MISMATCH
    delete headers['transfer-encoding'];
    // 只允许 gzip/identity：HTML 注入与 workspace/session 过滤只处理 gzip，
    // 上游若返回 br 会损坏页面/导致过滤静默失效（brotli 不走代理缓冲）
    headers['accept-encoding'] = 'gzip';

    const parsedUrl = new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`);
    // 请求上挂的用户/权限（子用户才有）
    const reqAs = req as Req;
    // 请求上挂的用户/权限（子用户才有）
    const upstreamReq = http.request(
      {
        hostname: upstreamHost,
        port: upstreamPort,
        // 规范化路径转发（与 dsh 的 new URL 解析行为一致，杜绝 ../ 混入上游）
        path: parsedUrl.pathname + parsedUrl.search,
        method: req.method,
        headers,
        agent: upstreamAgent,
      },
      (upstreamRes) => {
        const contentType = String(upstreamRes.headers['content-type'] ?? '');
        const encoding = String(upstreamRes.headers['content-encoding'] ?? '');

        // ── HTML 响应：缓冲 + 注入兼容脚本（crypto.randomUUID polyfill 等） ──
        if (contentType.includes('text/html')) {
          const chunks: Buffer[] = [];
          upstreamRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          upstreamRes.on('end', () => {
            try {
              let body = Buffer.concat(chunks);
              if (encoding.includes('gzip')) body = zlib.gunzipSync(body);
              const html = body.toString('utf8');
              const injected = html.replace(/<head[^>]*>/i, (match) => match + INJECT_SCRIPT);
              let out = Buffer.from(injected, 'utf8');
              const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
              delete respHeaders['content-length'];
              delete respHeaders['content-encoding'];
              // 代理层补齐防嵌框头（dsh 应用自身未设置）：
              // 允许同源内嵌（dsh 内部如有同源 iframe 不受影响），禁止跨站嵌框。
              // 仅在上游未提供 CSP 时补充 frame-ancestors，避免冲掉上游更严的策略。
              respHeaders['x-frame-options'] = 'SAMEORIGIN';
              const upstreamCsp = String(upstreamRes.headers['content-security-policy'] ?? '');
              if (!upstreamCsp.includes('frame-ancestors')) {
                respHeaders['content-security-policy'] = upstreamCsp
                  ? `${upstreamCsp}; frame-ancestors 'self'`
                  : "frame-ancestors 'self'";
              }
              if (encoding.includes('gzip')) {
                out = zlib.gzipSync(out);
                respHeaders['content-encoding'] = 'gzip';
              }
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              res.destroy();
            }
          });
          upstreamRes.on('error', () => {
            res.destroy();
          });
          return;
        }

        // ── workspace.list 响应：收集 id→path 缓存 + 受限子用户过滤白名单外的工作区 ──
        if (req.method === 'POST' && /^\/api\/workspace[.\/]list$/.test(parsedUrl.pathname)) {
          const chunks: Buffer[] = [];
          upstreamRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          upstreamRes.on('end', () => {
            try {
              let body = Buffer.concat(chunks);
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = zlib.gunzipSync(body);
              const parsed = JSON.parse(body.toString('utf8'));
              // 先缓存全量 id→path（供 session.create 用 workspaceId 时解析路径）
              collectIdPathPairs(parsed, workspacePathById);
              const restricted =
                reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.allowed_folders.length > 0;
              const outBody = restricted
                ? filterByPathField(parsed, reqAs.dshpwPerms!.allowed_folders, 'path')
                : parsed;
              const out = Buffer.from(JSON.stringify(outBody), 'utf8');
              const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
              delete respHeaders['content-length'];
              delete respHeaders['content-encoding'];
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(Buffer.concat(chunks));
            }
          });
          upstreamRes.on('error', () => res.destroy());
          return;
        }

        // ── session.list 响应过滤：受限子用户只看得到白名单内工作区的会话 ──
        if (
          reqAs.dshpwPerms !== undefined &&
          reqAs.dshpwPerms.allowed_folders.length > 0 &&
          req.method === 'POST' &&
          /^\/api\/session[.\/]list$/.test(parsedUrl.pathname)
        ) {
          const chunks: Buffer[] = [];
          upstreamRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          upstreamRes.on('end', () => {
            try {
              let body = Buffer.concat(chunks);
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = zlib.gunzipSync(body);
              const parsed = JSON.parse(body.toString('utf8'));
              const filtered = filterByPathField(parsed, reqAs.dshpwPerms!.allowed_folders, 'cwd');
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
              delete respHeaders['content-length'];
              delete respHeaders['content-encoding'];
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(Buffer.concat(chunks));
            }
          });
          upstreamRes.on('error', () => res.destroy());
          return;
        }

        // ── 非 HTML：原样流式转发 ───────────────────────────────────
        const respHeaders: Record<string, string | string[] | undefined> = { ...upstreamRes.headers };
        // dsh 对插件/静态资源返回 no-cache（或不给缓存头），浏览器每次
        // 进页面都要重新下载全部 ~30 个插件文件，导致卡在 "Loading plugins…"。
        // rev 参数/文件名都是内容哈希（换内容即换新 URL），可安全长缓存：
        const isHashedStatic =
          parsedUrl.pathname.startsWith('/assets/') ||
          (parsedUrl.pathname.startsWith('/plugins/') && parsedUrl.searchParams.has('rev'));
        if (isHashedStatic) {
          respHeaders['cache-control'] = 'public, max-age=31536000, immutable';
        }
        if (res.headersSent) {
          // 响应已被 fail-closed 分支发送（上游仍返回了响应）：不再重复写头
          res.destroy();
          return;
        }
        res.writeHead(upstreamRes.statusCode ?? 502, respHeaders);
        upstreamRes.pipe(res);
        // 上游响应流中途断开：客户端侧直接中断（头已发，不能再写错误页）
        upstreamRes.on('error', () => {
          res.destroy();
        });
      },
    );
    upstreamReq.on('error', (error) => {
      if (res.headersSent) {
        // 响应已开始转发：只能中断连接，避免 ERR_HTTP_HEADERS_SENT 崩溃
        res.destroy();
        return;
      }
      res
        .status(502)
        .type('html')
        .send(`<h3>${escapeHtml(t(langOf(req), 'gw.upstreamDown'))}</h3><p>${escapeHtml(error.message)}</p>`);
    });
    // 客户端中途断开：中止上游请求，避免悬挂连接
    res.on('close', () => {
      if (!res.writableEnded) upstreamReq.destroy();
    });
    // 受限子用户的请求体缓冲检查（尽力而为）：
    //   1) 文件夹白名单：session.create/fork 的 cwd/workspaceId 必须在授权目录内
    //   2) 沙盒权限：settings.mutate 试图把 defaultPreset 切到高于授权级别 → 403
    const needsFolderCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.allowed_folders.length > 0 &&
      (req.method === 'POST' || req.method === 'PUT' || (req.method === 'DELETE' && isAionuiPanel(parsedUrl.pathname))) &&
      (WORKSPACE_ENDPOINT_RE.test(parsedUrl.pathname) || isAionuiPanel(parsedUrl.pathname));
    const needsSandboxCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/settings[.\/]/.test(parsedUrl.pathname);
    // 沙盒切换的实际主路径是 /permission slash 命令：经 commands/execute RPC
    // （body { agentId, line }，line 形如 "/permission workspace-write"），
    // 而不是 settings.mutate。这里对受限子用户同样做越权预设检查。
    const needsCommandCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/commands[.\/]execute$/.test(parsedUrl.pathname);
    // AI 提权审批：沙盒升级经 /api/respond（body { sessionId, approvalId, outcome }）。
    // 受限子用户（sandbox_mode 非空）即使点了“允许”，也强制改成 rejected，把 AI 的
    // 越权提权直接取消。ask_user_question 用的是 answer 字段，不会被这里误伤。
    const needsApprovalCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/respond$/.test(parsedUrl.pathname);

    if (needsFolderCheck || needsSandboxCheck || needsCommandCheck || needsApprovalCheck) {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      const MAX_BODY = 64 * 1024;
      // aionui-panel 写文件（/write）可能携带大 JSON，单独放宽上限并完整检查；
      // 其余需要检查的端点 body 天然很小（session.create/settings.mutate/respond），
      // 超限即 fail-closed，防止“超限透传”绕过权限检查。
      const isAionuiWrite =
        reqAs.dshpwPerms !== undefined && isAionuiPanel(parsedUrl.pathname) && req.method === 'POST';
      const bodyLimit = isAionuiWrite ? 4 * 1024 * 1024 : MAX_BODY;
      req.on('data', (chunk: Buffer) => {
        if (settled) return;
        size += chunk.length;
        if (size > bodyLimit) {
          // 超大且非 aionui 写端点：拒绝，不透传（防止绕过白名单/审批检查）
          if (!isAionuiWrite) {
            settled = true;
            const lang = langOf(req);
            // 先中止上游请求，否则上游响应到达时会对已发送的响应再 writeHead
            upstreamReq.destroy();
            res.status(413).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          settled = true;
          upstreamReq.write(Buffer.concat(chunks));
          upstreamReq.write(chunk);
          req.pipe(upstreamReq);
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (settled) return;
        settled = true;
        const lang = langOf(req);
        let bodyObj: unknown = null;
        try {
          bodyObj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        } catch {
          bodyObj = null;
        }
        // 需要检查的端点 body 必须是可解析的 JSON。解析失败（gzip/非 JSON 编码
        // 构造）一律 fail-closed：直接拒绝，防止绕过文件夹白名单、沙盒越权、
        // 命令越权与 AI 提权审批（之前会静默透传到上游）。
        if (bodyObj === null) {
          upstreamReq.destroy();
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
          return;
        }

        if (needsFolderCheck) {
          let targetPath: string | null = null;
          if (isAionuiPanel(parsedUrl.pathname)) {
            // aionui-panel 文件树：root 是工作区路径，path 是 root 下的相对文件路径
            targetPath = aionuiRootFrom(req.method, parsedUrl.pathname, parsedUrl.searchParams, bodyObj);
          } else {
            targetPath = extractPathFromBody(bodyObj);
            if (targetPath === null) {
              const wid = extractWorkspaceId(bodyObj);
              if (wid !== null) targetPath = workspacePathById.get(wid) ?? null;
              // 缓存里没有该 workspaceId 的映射（进程重启后/从未有 workspace.list
              // 经过网关）：无法确认目标目录在白名单内，fail-closed 拒绝
              if (wid !== null && targetPath === null) {
                upstreamReq.destroy();
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
                return;
              }
            }
          }
          if (targetPath !== null && !folderAllowed(targetPath, reqAs.dshpwPerms!.allowed_folders)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }

        if (needsSandboxCheck && bodyObj !== null) {
          const preset = presetFromSettingsMutate(bodyObj);
          const assignedRank =
            SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
          const targetRank = preset === null ? assignedRank : sandboxPresetRank(preset);
          if (targetRank > assignedRank) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
            return;
          }
        }

        if (needsCommandCheck && bodyObj !== null) {
          const line = findStringField(bodyObj, 'line');
          const preset = line === null ? null : permissionPresetFromCommand(line);
          if (preset !== null) {
            const assignedRank =
              SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
            const targetRank = sandboxPresetRank(preset);
            if (targetRank > assignedRank) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
              return;
            }
          }
        }

        // 审批响应改写：受限子用户的 AI 提权审批一律强制 rejected（返回取消）
        let forwardBody = Buffer.concat(chunks);
        if (needsApprovalCheck && bodyObj !== null && typeof bodyObj === 'object') {
          if (forceRejectApproval(bodyObj)) {
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
          }
        }

        upstreamReq.end(forwardBody);
      });
      req.on('error', () => {
        if (!settled) {
          settled = true;
          upstreamReq.destroy();
        }
      });
    } else {
      req.pipe(upstreamReq);
    }
  });

  const hasTls = config.gateway.tls !== null;
  const server = hasTls
    ? https.createServer(
        {
          // 默认证书（启动时读一次）：不带 SNI 的客户端（如 https://127.0.0.1
          // 直连、插件→网关内部回环调用）不会触发 SNICallback，必须要有默认
          // cert/key 才能完成握手
          cert: readFileSync(config.gateway.tls!.cert),
          key: readFileSync(config.gateway.tls!.key),
          // 证书每次 TLS 握手时从文件动态读取：自动续期写入新文件后
          // 下一个连接即用新证书，无需重启进程
          SNICallback: (_servername, callback) => {
            try {
              callback(
                null,
                createSecureContext({
                  cert: readFileSync(config.gateway.tls!.cert),
                  key: readFileSync(config.gateway.tls!.key),
                  minVersion: 'TLSv1.2',
                }),
              );
            } catch (error) {
              callback(error as Error);
            }
          },
          // 仅允许 TLS 1.2+，拒绝老旧协议与弱套件协商
          minVersion: 'TLSv1.2',
        },
        app,
      )
    : http.createServer(app);

  // ── WebSocket 升级代理（dsh 前端依赖 WS 通信） ──────────────
  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    if (url.pathname.startsWith('/gateway/')) {
      socket.destroy();
      return;
    }
    // 认证检查（复用 Cookie；与 HTTP 侧一致：校验 cv + banned）
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    let authed = false;
    if (token) {
      try {
        const user = auth.verifyToken(token);
        const row = db.getUserByUsername(user.username);
        if (row !== null && user.cv === row.credential_version) {
          const perms = effectivePermissions(row.id);
          if (!perms.banned) authed = true;
        }
      } catch {
        authed = false;
      }
    }
    if (!authed) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // 转发升级请求（Host/Origin 改写，同 HTTP 路径；路径已规范化）
    const upstreamSocket = net.connect(upstreamPort, upstreamHost, () => {
      const lines: string[] = [
        `${req.method ?? 'GET'} ${url.pathname + url.search} HTTP/1.1`,
      ];
      for (const [key, value] of Object.entries(req.headers)) {
        if (key.toLowerCase() === 'host') {
          lines.push(`Host: ${upstreamHost}:${upstreamPort}`);
        } else if (key.toLowerCase() === 'origin' && typeof value === 'string') {
          lines.push(`Origin: http://${upstreamHost}:${upstreamPort}`);
        } else if (value !== undefined) {
          lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
        }
      }
      lines.push('', '');
      upstreamSocket.write(lines.join('\r\n'));
      if (head && head.length > 0) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
    });
    upstreamSocket.on('error', () => socket.destroy());
    socket.on('error', () => upstreamSocket.destroy());
    socket.on('close', () => upstreamSocket.destroy());
    upstreamSocket.on('close', () => socket.destroy());
  });

  return server;
}

/**
 * HTTP→HTTPS 301 跳转服务器（仅 TLS 模式且配置了 redirectPort 时创建）。
 * 解决“网关裸奔在 80 明文”问题：80 不再提供任何页面内容，只做跳转。
 * 自动 HTTPS 模式下同时承载 ACME HTTP-01 挑战应答（/.well-known/acme-challenge/*）。
 */
export function createRedirectServer(
  config: PlatformConfig,
  challengeStore?: Map<string, string>,
): http.Server | null {
  if (config.gateway.tls === null || config.gateway.redirectPort === null) return null;
  return http.createServer((req, res) => {
    // ACME HTTP-01 挑战应答：优先于跳转处理（Let's Encrypt 校验走这里）
    if (challengeStore) {
      const pathname = (() => {
        try {
          return new URL(req.url ?? '/', 'http://localhost').pathname;
        } catch {
          return '/';
        }
      })();
      const prefix = '/.well-known/acme-challenge/';
      if (pathname.startsWith(prefix)) {
        const token = pathname.slice(prefix.length).split('/')[0];
        const keyAuthz =
          token !== '' && /^[A-Za-z0-9_-]{1,128}$/.test(token)
            ? challengeStore.get(token)
            : undefined;
        if (keyAuthz !== undefined) {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': String(Buffer.byteLength(keyAuthz)),
            'Cache-Control': 'no-store',
            Connection: 'close',
          });
          res.end(keyAuthz);
          return;
        }
        res.writeHead(404, { 'Content-Length': '0', Connection: 'close' });
        res.end();
        return;
      }
    }
    // Host 头部可能带跳转端口或 :80 后缀，跳转目标去掉它们；空 Host 回退主端口
    const strip = new RegExp(`:(${config.gateway.redirectPort}|80)$`);
    const rawHost = (req.headers.host ?? '').replace(strip, '');
    // 防 Host 反射（HTTP/1.0 可伪造 Host: evil.com → Location: https://evil.com/）：
    // 自动 HTTPS 固定用证书域名；否则用配置的公网主机；再否则严格校验请求 Host 格式
    const candidate = config.gateway.domain || config.gateway.publicHost || rawHost;
    const host =
      /^[A-Za-z0-9.\-[\]:]+$/.test(candidate) && candidate !== ''
        ? candidate
        : `127.0.0.1:${config.gateway.port}`;
    const target = `https://${host}${req.url ?? '/'}`;
    res.writeHead(301, {
      Location: target,
      'Content-Length': '0',
      Connection: 'close',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    res.end();
  });
}
