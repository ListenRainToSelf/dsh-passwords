// 认证服务：首次配置（预设密钥+用户名+密码）、登录（JWT）
// 安全强化：
//   1. 密码策略：≥12 位，大写/小写/数字/符号各至少一位
//   2. 反 SQL 注入：全链参数化查询（根本防线）+ 输入特征检测（纵深防御）
//   3. 网络安全审查：审计日志（登录成功/失败/锁定/配置）+ 防暴力破解（5 次失败锁 15 分钟）
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { PlatformConfig } from './config.js';
import { Database } from './db.js';

const BCRYPT_ROUNDS = 10;
const TOKEN_TTL = '12h';
const MAX_FAILED = 5;
const LOCK_MINUTES = 15;
/** 时序均衡用空跑哈希：用户不存在时也执行一次 bcrypt，抹平“快=不存在”的枚举差异 */
const DUMMY_HASH = bcrypt.hashSync('dsh-passwords-timing-equalizer', BCRYPT_ROUNDS);

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly status = 400,
  ) {
    super(message);
  }
}

const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;

/** 密码策略：≥12 位，且大写、小写、数字、符号各至少一位 */
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/;

/**
 * SQL 注入特征（纵深防御层）。
 * 所有数据库查询均已参数化（占位符 + 值绑定），此检测针对会进入
 * 请求解析的字符串字段（password 除外——密码必须允许符号，且经 bcrypt
 * 哈希 + 参数化写入，无注入面）。
 */
const SQLI_PATTERN =
  /('|"|;|--|\/\*|\*\/|\bunion\b|\bselect\b|\binsert\b|\bdrop\b|\bdelete\b|\bupdate\b|\btruncate\b|\bsleep\b|\bbenchmark\b)/i;

export function assertNoSqlInjection(value: unknown, field: string): void {
  if (typeof value !== 'string' || value === '') return;
  if (SQLI_PATTERN.test(value)) {
    throw new AuthError(`${field} 包含非法字符，已拒绝`, 'SQL_INJECTION_REJECTED', 400);
  }
}

function assertUsername(username: unknown): string {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new AuthError(
      '用户名需为 3-32 位字母、数字、下划线或连字符',
      'INVALID_USERNAME',
    );
  }
  return username;
}

function assertPassword(password: unknown): string {
  if (typeof password !== 'string' || !PASSWORD_RE.test(password)) {
    throw new AuthError(
      '密码需至少 12 位，且必须同时包含大写字母、小写字母、数字、符号各至少一位',
      'INVALID_PASSWORD',
    );
  }
  return password;
}

export interface RequestMeta {
  ip?: string | null;
  userAgent?: string | null;
}

export class AuthService {
  constructor(
    private config: PlatformConfig,
    private db: Database,
  ) {}

  /** 平台是否已初始化（存在至少一个用户） */
  async isInitialized(): Promise<boolean> {
    return (await this.db.countUsers()) > 0;
  }

  /**
   * 首次配置：校验预设密钥 + 创建首个用户。
   * 已初始化后再次调用会失败（单次初始化语义）。
   */
  async setup(
    input: { setupKey: string; username: string; password: string },
    meta: RequestMeta = {},
  ): Promise<void> {
    if (await this.isInitialized()) {
      throw new AuthError('平台已初始化，不能重复配置', 'ALREADY_INITIALIZED', 409);
    }
    // 注入特征拦截（setupKey 与 username 进系统前先查）
    assertNoSqlInjection(input.setupKey, 'setupKey');
    if (input.setupKey !== this.config.setupKey) {
      await this.db.audit('setup_failure', {
        username: input.username || null,
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: '预设密钥错误',
      });
      throw new AuthError('预设密钥不正确', 'INVALID_SETUP_KEY', 401);
    }
    const username = assertUsername(input.username);
    const password = assertPassword(input.password);

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await this.db.createUser(username, hash);
    await this.db.setSetting('installed_at', new Date().toISOString());
    await this.db.audit('setup_success', {
      username,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail: '平台初始化完成',
    });
  }

  /** 登录：用户名 + 密码 → JWT（含防暴力破解与审计） */
  async login(
    input: { username: string; password: string },
    meta: RequestMeta = {},
  ): Promise<{ token: string; username: string }> {
    const username = input.username.trim();
    const ip = meta.ip ?? 'unknown';

    // 1) 锁定检查（防暴力破解）
    const attempt = await this.db.getLoginAttempt(username, ip);
    if (attempt?.locked_until && attempt.locked_until.getTime() > Date.now()) {
      const remainMin = Math.ceil((attempt.locked_until.getTime() - Date.now()) / 60000);
      await this.db.audit('account_locked_blocked', {
        username,
        ip,
        userAgent: meta.userAgent,
        detail: `锁定期间拒绝登录，剩余 ${remainMin} 分钟`,
      });
      throw new AuthError(`账号已锁定，请 ${remainMin} 分钟后再试`, 'ACCOUNT_LOCKED', 429);
    }

    // 2) 凭据校验（统一错误信息，避免用户名枚举；时序上用户不存在也空跑 bcrypt）
    const user = await this.db.getUserByUsername(username);
    let valid = false;
    if (user) {
      valid = await bcrypt.compare(input.password, user.password_hash);
    } else {
      await bcrypt.compare(input.password, DUMMY_HASH); // 空跑一次，抹平时序差异
    }
    if (!user || !valid) {
      const count = await this.db.recordLoginFailure(username, ip);
      if (count >= MAX_FAILED) {
        const until = new Date(Date.now() + LOCK_MINUTES * 60000);
        await this.db.lockLoginAttempt(username, ip, until);
        await this.db.audit('account_locked', {
          username,
          ip,
          userAgent: meta.userAgent,
          detail: `连续失败 ${count} 次，锁定 ${LOCK_MINUTES} 分钟`,
        });
        throw new AuthError(
          `连续失败 ${count} 次，账号已锁定 ${LOCK_MINUTES} 分钟`,
          'ACCOUNT_LOCKED',
          429,
        );
      }
      await this.db.audit('login_failure', {
        username,
        ip,
        userAgent: meta.userAgent,
        detail: `第 ${count} 次失败（${MAX_FAILED} 次锁定）`,
      });
      throw new AuthError('用户名或密码错误', 'INVALID_CREDENTIALS', 401);
    }

    // 3) 成功：清除失败计数 + 记录审计
    await this.db.resetLoginAttempts(username, ip);
    await this.db.touchLogin(user.id);
    await this.db.audit('login_success', { username, ip, userAgent: meta.userAgent });

    const token = jwt.sign(
      { sub: String(user.id), username: user.username },
      this.config.jwtSecret,
      { expiresIn: TOKEN_TTL },
    );
    return { token, username: user.username };
  }

  /** 校验 JWT（Web 中间件用） */
  verifyToken(token: string): { userId: number; username: string } {
    try {
      const payload = jwt.verify(token, this.config.jwtSecret) as jwt.JwtPayload;
      return { userId: Number(payload.sub), username: String(payload.username) };
    } catch {
      throw new AuthError('会话无效或已过期', 'INVALID_TOKEN', 401);
    }
  }

  /** MCP 侧登录（agent 调用）：用户名+密码 → 认证结果（同样受限流+审计保护） */
  async mcpLogin(input: { username: string; password: string }): Promise<{ ok: boolean }> {
    try {
      await this.login(input, { ip: 'stdio', userAgent: 'mcp-agent' });
      return { ok: true };
    } catch {
      return { ok: false };
    }
  }
}
