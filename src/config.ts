// .env 加载：相对模块位置（而不是进程 cwd）解析项目根目录 .env。
// 这样无论从哪个目录运行（systemd WorkingDirectory、npm start、
// 任意目录下的 audit CLI）都读到同一份配置与同一把密钥。
import { config as loadEnv } from 'dotenv';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import path from 'node:path';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
loadEnv({ path: path.join(moduleDir, '..', '.env'), quiet: true });

function readEnv(name: string, fallback: string): string {
  return (process.env[name] ?? '').trim() || fallback;
}

export interface PlatformConfig {
  setupKey: string;
  /** SQLite 数据库文件路径（Node 内置 node:sqlite，无需外部数据库） */
  dbPath: string;
  /** 数据静态加密密钥（可选，留空则从 SETUP_KEY 派生） */
  dbEncKey: string;
  /** 登录网关（dsh 访问门卫）：对外端口 + 上游 dsh 地址 */
  gateway: {
    host: string;
    port: number;
    upstream: string;
    /** HTTPS 证书/密钥文件路径（都配置时网关启用 TLS） */
    tls: { cert: string; key: string } | null;
    /** HTTP→HTTPS 301 跳转端口（TLS 开启时可选；空/0 = 关闭） */
    redirectPort: number | null;
  };
  jwtSecret: string;
}

export function loadConfig(): PlatformConfig {
  // JWT 密钥：留空则用 setupKey 做稳定派生，重启不失效
  const jwtSecret =
    readEnv('MCP_JWT_SECRET', '') ||
    createHash('sha256').update(readEnv('SETUP_KEY', 'dev')).digest('hex');

  const dbPath = readEnv(
    'MCP_DB_PATH',
    path.resolve(process.cwd(), 'data', 'platform.db'),
  );

  return {
    setupKey: readEnv('SETUP_KEY', ''),
    dbPath,
    dbEncKey: readEnv('MCP_DB_ENC_KEY', ''),
    gateway: {
      host: readEnv('MCP_GATEWAY_HOST', '0.0.0.0'),
      port: Number(readEnv('MCP_GATEWAY_PORT', '8080')),
      upstream: readEnv('MCP_GATEWAY_UPSTREAM', 'http://127.0.0.1:3080'),
      tls: (() => {
        const cert = readEnv('MCP_GATEWAY_TLS_CERT', '');
        const key = readEnv('MCP_GATEWAY_TLS_KEY', '');
        return cert && key ? { cert, key } : null;
      })(),
      // HTTP→HTTPS 跳转端口：TLS 开启时在 80 提供 301，避免明文服务
      redirectPort: (() => {
        const raw = readEnv('MCP_GATEWAY_REDIRECT_PORT', '');
        const n = Number(raw);
        return raw !== '' && Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
      })(),
    },
    jwtSecret,
  };
}
