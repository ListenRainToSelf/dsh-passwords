// SQLite 数据层：Node 内置 node:sqlite（零外部数据库依赖）
// 表结构：users / platform_settings / audit_logs / login_attempts
//
// 静态加密（见 src/encrypt.ts）：
//   - users.username         → AES-256-GCM 密文存储；username_hash（HMAC）做等值索引
//   - audit_logs 的 username/ip/user_agent/detail → AES-256-GCM 密文存储
//   - login_attempts         → 只存 username_hash/ip_hash（HMAC，不可逆）
//   密码始终只存 bcrypt 哈希（不可逆，无明文，无需加密）。
//   旧明文数据在 init() 时一次性自动迁移为密文（幂等，检测 v1:/h1: 前缀）。
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import type { FieldCrypto } from './encrypt.js';

export interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  created_at: string;
  last_login_at: string | null;
}

export interface AuditLogRow {
  id: number;
  event_type: string;
  username: string | null;
  ip: string | null;
  user_agent: string | null;
  detail: string | null;
  created_at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT    NOT NULL,
  username_hash TEXT,
  password_hash TEXT    NOT NULL,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS platform_settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  username   TEXT,
  ip         TEXT,
  user_agent TEXT,
  detail     TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username_hash TEXT NOT NULL,
  ip_hash       TEXT NOT NULL,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(username_hash, ip_hash)
);
`;

export class Database {
  private db: DatabaseSync;
  private crypto: FieldCrypto;

  constructor(dbPath: string, crypto: FieldCrypto) {
    mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.crypto = crypto;
  }

  /** 建表（幂等）+ 旧明文数据一次性迁移为密文 */
  init(): void {
    // 删除内容清零，防止已删除的明文残留在空闲页可被文件扫描恢复
    this.db.exec('PRAGMA secure_delete = ON');
    this.db.exec(SCHEMA);
    const changedUsers = this.migrateUsers();
    const changedAudit = this.migrateAuditLogs();
    const changedAttempts = this.migrateLoginAttempts();
    const changed = changedUsers || changedAudit || changedAttempts;
    // 密文比明文长：UPDATE 会写新页，旧页上的明文留在空闲页里。
    // VACUUM 重写整个文件，彻底清除可被 raw 扫描恢复的残留明文。
    // 用 platform_settings 标记确保每个库只执行一次（旧库即使本次
    // 迁移无变化也会补一次 VACUUM）。
    const vacuumed = this.getSetting('enc_migrated_v1') === '1';
    if (changed || !vacuumed) {
      this.db.exec('VACUUM');
      this.setSetting('enc_migrated_v1', '1');
    }
  }

  // ── 迁移：users.username 明文 → 密文 + username_hash ──────────
  private migrateUsers(): boolean {
    const cols = this.db.prepare('PRAGMA table_info(users)').all() as { name: string }[];
    if (!cols.some((c) => c.name === 'username_hash')) {
      this.db.exec('ALTER TABLE users ADD COLUMN username_hash TEXT');
    }
    // 索引必须在列存在之后创建（旧库无此列时不能在建表阶段引用它）
    this.db.exec(
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_hash ON users(username_hash) WHERE username_hash IS NOT NULL',
    );
    const rows = this.db
      .prepare('SELECT id, username, username_hash FROM users')
      .all() as { id: number; username: string; username_hash: string | null }[];
    const upd = this.db.prepare('UPDATE users SET username = ?, username_hash = ? WHERE id = ?');
    let changed = false;
    for (const row of rows) {
      const plain = row.username.startsWith('v1:') ? this.crypto.decrypt(row.username) : row.username;
      if (!row.username.startsWith('v1:') || !row.username_hash) {
        this.db.exec('BEGIN');
        try {
          upd.run(this.crypto.encrypt(plain!), this.crypto.lookupHash(plain!), row.id);
          this.db.exec('COMMIT');
          changed = true;
        } catch (error) {
          this.db.exec('ROLLBACK');
          throw error;
        }
      }
    }
    return changed;
  }

  // ── 迁移：audit_logs 敏感列明文 → 密文 ─────────────────────────
  private migrateAuditLogs(): boolean {
    const rows = this.db
      .prepare('SELECT id, username, ip, user_agent, detail FROM audit_logs')
      .all() as { id: number; username: string | null; ip: string | null; user_agent: string | null; detail: string | null }[];
    const upd = this.db.prepare(
      'UPDATE audit_logs SET username = ?, ip = ?, user_agent = ?, detail = ? WHERE id = ?',
    );
    let changed = false;
    for (const row of rows) {
      const needs = (v: string | null) => v !== null && !v.startsWith('v1:');
      if (needs(row.username) || needs(row.ip) || needs(row.user_agent) || needs(row.detail)) {
        this.db.exec('BEGIN');
        try {
          upd.run(
            this.crypto.encrypt(row.username),
            this.crypto.encrypt(row.ip),
            this.crypto.encrypt(row.user_agent),
            this.crypto.encrypt(row.detail),
            row.id,
          );
          this.db.exec('COMMIT');
          changed = true;
        } catch (error) {
          this.db.exec('ROLLBACK');
          throw error;
        }
      }
    }
    return changed;
  }

  // ── 迁移：login_attempts 明文 username/ip → HMAC 散列 ─────────
  private migrateLoginAttempts(): boolean {
    const cols = this.db.prepare('PRAGMA table_info(login_attempts)').all() as { name: string }[];
    if (cols.some((c) => c.name === 'username_hash')) return false; // 已迁移
    const rows = this.db
      .prepare('SELECT username, ip, failed_count, locked_until, updated_at FROM login_attempts')
      .all() as { username: string; ip: string | null; failed_count: number; locked_until: string | null; updated_at: string }[];
    this.db.exec('BEGIN');
    try {
      this.db.exec(`
        CREATE TABLE login_attempts_new (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          username_hash TEXT NOT NULL,
          ip_hash       TEXT NOT NULL,
          failed_count INTEGER NOT NULL DEFAULT 0,
          locked_until TEXT,
          updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
          UNIQUE(username_hash, ip_hash)
        );
      `);
      const ins = this.db.prepare(
        'INSERT INTO login_attempts_new (username_hash, ip_hash, failed_count, locked_until, updated_at) VALUES (?, ?, ?, ?, ?)',
      );
      for (const row of rows) {
        ins.run(
          this.crypto.lookupHash(row.username),
          this.crypto.lookupHash(row.ip ?? ''),
          Number(row.failed_count),
          row.locked_until,
          row.updated_at,
        );
      }
      this.db.exec('DROP TABLE login_attempts');
      this.db.exec('ALTER TABLE login_attempts_new RENAME TO login_attempts');
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  async health(): Promise<boolean> {
    try {
      this.db.prepare('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  getUserByUsername(username: string): UserRow | null {
    const hash = this.crypto.lookupHash(username);
    const row = this.db
      .prepare(
        'SELECT id, username, password_hash, created_at, last_login_at FROM users WHERE username_hash = ?',
      )
      .get(hash) as Omit<UserRow, 'username'> & { username: string } | undefined;
    if (!row) return null;
    return { ...row, username: this.crypto.decrypt(row.username) ?? username };
  }

  countUsers(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
    return Number(row?.n ?? 0);
  }

  createUser(username: string, passwordHash: string): UserRow {
    const result = this.db
      .prepare('INSERT INTO users (username, username_hash, password_hash) VALUES (?, ?, ?)')
      .run(this.crypto.encrypt(username), this.crypto.lookupHash(username), passwordHash);
    return {
      id: Number(result.lastInsertRowid),
      username,
      password_hash: passwordHash,
      created_at: new Date().toISOString(),
      last_login_at: null,
    };
  }

  touchLogin(userId: number): void {
    this.db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(userId);
  }

  getSetting(key: string): string | null {
    const row = this.db.prepare('SELECT v FROM platform_settings WHERE k = ?').get(key) as
      | { v: string }
      | undefined;
    return row ? String(row.v) : null;
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare('INSERT INTO platform_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v')
      .run(key, value);
  }

  // ── 网络安全审查：审计日志（敏感字段静态加密） ────────────────
  audit(
    eventType: string,
    opts: { username?: string | null; ip?: string | null; userAgent?: string | null; detail?: string | null } = {},
  ): void {
    try {
      this.db
        .prepare('INSERT INTO audit_logs (event_type, username, ip, user_agent, detail) VALUES (?, ?, ?, ?, ?)')
        .run(
          eventType,
          this.crypto.encrypt(opts.username ?? null),
          this.crypto.encrypt(opts.ip ?? null),
          this.crypto.encrypt(opts.userAgent ?? null),
          this.crypto.encrypt(opts.detail ?? null),
        );
    } catch {
      // 审计写入失败不阻断主流程
    }
  }

  listAuditLogs(limit = 30): AuditLogRow[] {
    const rows = this.db
      .prepare(
        'SELECT id, event_type, username, ip, user_agent, detail, created_at FROM audit_logs ORDER BY id DESC LIMIT ?',
      )
      .all(Math.min(Math.max(limit, 1), 100)) as unknown as AuditLogRow[];
    return rows.map((row) => ({
      ...row,
      username: this.crypto.decrypt(row.username),
      ip: this.crypto.decrypt(row.ip),
      user_agent: this.crypto.decrypt(row.user_agent),
      detail: this.crypto.decrypt(row.detail),
    }));
  }

  // ── 网络安全审查：防暴力破解（仅存 HMAC 散列，不含明文） ────────
  getLoginAttempt(username: string, ip: string): { failed_count: number; locked_until: Date | null } | null {
    const row = this.db
      .prepare(
        'SELECT failed_count, locked_until FROM login_attempts WHERE username_hash = ? AND ip_hash = ?',
      )
      .get(this.crypto.lookupHash(username), this.crypto.lookupHash(ip)) as
      | { failed_count: number; locked_until: string | null }
      | undefined;
    return row
      ? { failed_count: Number(row.failed_count), locked_until: row.locked_until ? new Date(row.locked_until) : null }
      : null;
  }

  recordLoginFailure(username: string, ip: string): number {
    this.db
      .prepare(
        `INSERT INTO login_attempts (username_hash, ip_hash, failed_count) VALUES (?, ?, 1)
         ON CONFLICT(username_hash, ip_hash) DO UPDATE SET failed_count = failed_count + 1`,
      )
      .run(this.crypto.lookupHash(username), this.crypto.lookupHash(ip));
    return this.getLoginAttempt(username, ip)?.failed_count ?? 1;
  }

  lockLoginAttempt(username: string, ip: string, until: Date): void {
    this.db
      .prepare(
        `INSERT INTO login_attempts (username_hash, ip_hash, failed_count, locked_until) VALUES (?, ?, 0, ?)
         ON CONFLICT(username_hash, ip_hash) DO UPDATE SET locked_until = excluded.locked_until`,
      )
      .run(this.crypto.lookupHash(username), this.crypto.lookupHash(ip), until.toISOString());
  }

  resetLoginAttempts(username: string, ip: string): void {
    this.db
      .prepare('DELETE FROM login_attempts WHERE username_hash = ? AND ip_hash = ?')
      .run(this.crypto.lookupHash(username), this.crypto.lookupHash(ip));
  }
}
