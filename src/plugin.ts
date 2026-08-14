// dsh 主机侧插件：dsh-passwords 在 dsh 里的"席位"
//   1. /api/dsh-passwords/* 用户管理路由：改密码、改用户名、
//      主用户分配/删除子用户。走网关 JWT cookie 鉴权。
//   2. /api/dsh-passwords/patch/* 远程设置补丁路由：
//      - GET  /patch/status → 补丁当前状态（任何登录用户可看）
//      - POST /patch/reload → 通知网关重载补丁并重启 dsh 网页服务
//        （任何登录用户可触发；补丁强制启用，无开关）
//      dsh 升级覆盖补丁后，用户在设置页点"重载补丁"即可，无需登录服务器。
import type { Context } from '@deepseek-ai/cordis';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver';
import http from 'node:http';
import https from 'node:https';
import jwt from 'jsonwebtoken';
import { loadConfig, type PlatformConfig } from './config.js';
import { Database, type UserListRow } from './db.js';
import { createFieldCrypto } from './encrypt.js';
import { AuthService, AuthError, assertNoSqlInjection, type AuthedUser, type RequestMeta } from './auth.js';
import { findDshRoot, patchStatus } from './patch.js';

/** 稳定 cordis 插件名（insert 进 cordis.yml 时用同一个名字） */
export const name = 'dsh-passwords';

/** 依赖 dsh 主机侧的 webServer 服务（路由挂载点） */
export const inject = ['webServer'];

/** 网关会话 cookie 名（与 gateway.ts 保持一致） */
const COOKIE_NAME = 'dsh_gateway_token';
/** 请求体上限（用户管理 JSON 都很小） */
const MAX_BODY = 4096;

function readCookie(cookieHeader: string | undefined, cookieName: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === cookieName && rest.length > 0) {
      const raw = rest.join('=');
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return null;
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(text);
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

/** 通知网关进程：重载补丁 + 延迟重启 dsh-web（fire-and-forget） */
function notifyGateway(cfg: PlatformConfig): void {
  const mod = cfg.gateway.tls !== null ? https : http;
  const url = `${cfg.gateway.tls !== null ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/patch`;
  const body = JSON.stringify({ action: 'apply' });
  const req = mod.request(
    url,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-internal-secret': cfg.internalSecret,
        'content-length': String(Buffer.byteLength(body)),
      },
      // 网关可能用自签证书，内部回环调用豁免校验
      rejectUnauthorized: false,
      timeout: 4000,
    },
    (res) => {
      res.resume();
    },
  );
  req.on('error', () => {
    // 网关没起来时静默：下次网关启动会自动应用补丁
  });
  req.end(body);
}

export function apply(ctx: Context): void {
  let cfg: PlatformConfig;
  try {
    cfg = loadConfig();
  } catch {
    return;
  }

  // 未配置 .env（SETUP_KEY 为空）时不初始化数据库，用户管理路由返回 503 提示
  const configured =
    cfg.setupKey !== '' && cfg.setupKey !== 'change-me-to-a-strong-random-key';
  let db: Database | null = null;
  let auth: AuthService | null = null;
  if (configured) {
    try {
      db = new Database(cfg.dbPath, createFieldCrypto(cfg.dbEncKey, cfg.setupKey));
      db.init();
      auth = new AuthService(cfg, db);
    } catch (error) {
      console.error('[dsh-passwords] 网关数据库初始化失败:', error);
      db = null;
      auth = null;
    }
  }

  /** 从网关 JWT cookie 解析调用方身份（含凭据版本校验） */
  const callerOf = (req: IncomingMessage): AuthedUser | null => {
    if (db === null || auth === null) return null;
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) return null;
    try {
      const payload = jwt.verify(token, cfg.jwtSecret) as jwt.JwtPayload;
      const row = db.getUserById(Number(payload.sub));
      if (!row) return null;
      const cv = typeof payload.cv === 'number' ? payload.cv : 0;
      if (cv !== row.credential_version) return null;
      return { userId: row.id, username: row.username, role: row.role };
    } catch {
      return null;
    }
  };

  /** 统一守卫：跨站拒绝 + 配置检查 + 会话校验 */
  const guard = (req: IncomingMessage, res: ServerResponse): AuthedUser | null => {
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      writeJson(res, 403, { ok: false, error: 'forbidden' });
      return null;
    }
    if (db === null || auth === null) {
      writeJson(res, 503, {
        ok: false,
        error: '未配置：请先完成 dsh-passwords 部署（.env 中 SETUP_KEY 等），再重启 dsh',
      });
      return null;
    }
    const caller = callerOf(req);
    if (!caller) {
      writeJson(res, 401, { ok: false, error: '未登录或会话已失效' });
      return null;
    }
    return caller;
  };

  const metaOf = (req: IncomingMessage): RequestMeta => ({
    ip: 'gateway',
    userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
  });

  const failJson = (res: ServerResponse, error: unknown): void => {
    if (error instanceof AuthError) {
      writeJson(res, error.status, { ok: false, error: error.message });
      return;
    }
    writeJson(res, 500, { ok: false, error: error instanceof Error ? error.message : '内部错误' });
  };

  // ── /api/dsh-passwords/* 路由（exact 路由先于连接插件的 /api 前缀命中） ──
  const routes: WebRoute[] = [
    {
      kind: 'exact',
      path: '/api/dsh-passwords/state',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        const users: UserListRow[] = db!.listUsers();
        writeJson(res, 200, {
          ok: true,
          me: { username: caller.username, role: caller.role },
          users,
        });
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/password',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        try {
          const body = await readJsonBody(req);
          const target = typeof body.target === 'string' && body.target !== '' ? body.target : caller.username;
          const password = typeof body.password === 'string' ? body.password : '';
          await auth!.changePassword(caller, target, password, metaOf(req));
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/username',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        try {
          const body = await readJsonBody(req);
          const target = typeof body.target === 'string' && body.target !== '' ? body.target : caller.username;
          const username = typeof body.username === 'string' ? body.username : '';
          assertNoSqlInjection(username, 'username');
          await auth!.renameUser(caller, target, username, metaOf(req));
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/users',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        try {
          const body = await readJsonBody(req);
          const username = typeof body.username === 'string' ? body.username : '';
          const password = typeof body.password === 'string' ? body.password : '';
          assertNoSqlInjection(username, 'username');
          await auth!.addSubUser(caller, username, password, metaOf(req));
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/users/remove',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        try {
          const body = await readJsonBody(req);
          const target = typeof body.target === 'string' ? body.target : '';
          assertNoSqlInjection(target, 'target');
          await auth!.removeUser(caller, target, metaOf(req));
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/patch/status',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        try {
          const root = findDshRoot(cfg.patch.dshRoot);
          const status = root ? patchStatus(root) : null;
          writeJson(res, 200, { ok: true, status });
        } catch {
          writeJson(res, 200, { ok: true, status: null });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/patch/reload',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        // 任何登录用户都可触发（补丁强制启用，重载只是重新应用 + 重启 dsh 网页服务）
        notifyGateway(cfg);
        writeJson(res, 202, { ok: true, message: '补丁重载中：dsh 网页服务即将重启（约 3-5 秒）' });
      },
    },
  ];

  ctx.effect(
    () => {
      const disposers = routes.map((route) => ctx.webServer.register(route));
      return () => {
        for (const dispose of disposers) dispose();
      };
    },
    'dsh-passwords: user management routes',
  );
}
