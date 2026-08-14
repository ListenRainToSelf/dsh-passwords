#!/usr/bin/env node
// 入口：serve-gateway（登录网关，唯一模式；serve 为其别名）
//
// 端口/主机/上游三层配置（优先级从高到低）：
//   1. 启动参数:  node dist/cli.js serve-gateway --port 9000 --host 0.0.0.0
//   2. 环境变量:  MCP_GATEWAY_PORT=9000 node dist/cli.js serve-gateway
//   3. .env 文件: MCP_GATEWAY_PORT=9000
// 云服务器上 HTTP 端口未必开放 8080，部署时用以上任一方式指定实际端口。
//
// 远程设置补丁：强制启用，网关启动时自动应用（幂等）——
// dsh 升级覆盖文件后，重启网关就会自动重打，无需手动操作。
// 也可手动：node dist/cli.js patch [status]
import { loadConfig } from './config.js';
import { Database } from './db.js';
import { AuthService } from './auth.js';
import { createGatewayServer, createRedirectServer } from './gateway.js';
import { createFieldCrypto } from './encrypt.js';
import { execSync } from 'node:child_process';
import {
  findDshRoot,
  applyRemotePatch,
  restartDshWeb,
  patchStatus,
} from './patch.js';

interface CliOverrides {
  port?: number;
  host?: string;
  upstream?: string;
}

/** 解析 --port/--host/--upstream 参数（支持 --k=v 与 --k v 两种写法） */
function parseCliOverrides(argv: string[]): CliOverrides {
  const out: CliOverrides = {};
  const take = (index: number, name: string): string | null => {
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      console.error(`[dsh-passwords] 警告: ${name} 缺少值`);
      return null;
    }
    return next;
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--port' || arg === '--host' || arg === '--upstream') {
      const value = take(i, arg);
      if (value === null) continue;
      if (arg === '--port') {
        const port = Number(value);
        if (!Number.isInteger(port) || port < 0 || port > 65535) {
          console.error(`[dsh-passwords] 警告: 无效端口 ${value}，已忽略`);
        } else {
          out.port = port;
        }
      } else if (arg === '--host') {
        out.host = value;
      } else {
        out.upstream = value;
      }
      i++;
    } else if (arg.startsWith('--port=')) {
      const port = Number(arg.slice('--port='.length));
      if (Number.isInteger(port) && port >= 0 && port <= 65535) out.port = port;
    } else if (arg.startsWith('--host=')) {
      out.host = arg.slice('--host='.length);
    } else if (arg.startsWith('--upstream=')) {
      out.upstream = arg.slice('--upstream='.length);
    }
  }
  return out;
}

/** 审计日志查看命令：node dist/cli.js audit [--limit N]（自动解密敏感字段） */
function runAudit(argv: string[]): void {
  const limitArg = argv.indexOf('--limit');
  const limit = limitArg >= 0 && argv[limitArg + 1] ? Number(argv[limitArg + 1]) : 30;
  const config = loadConfig();
  const db = new Database(config.dbPath, createFieldCrypto(config.dbEncKey, config.setupKey));
  db.init();
  const rows = db.listAuditLogs(Number.isFinite(limit) ? limit : 30);
  if (rows.length === 0) {
    console.log('（暂无审计日志）');
    return;
  }
  for (const row of rows) {
    console.log(
      `[${row.created_at}] ${row.event_type}  username=${row.username ?? '-'}  ip=${row.ip ?? '-'}`,
    );
    if (row.user_agent) console.log(`    ua: ${row.user_agent}`);
    if (row.detail) console.log(`    detail: ${row.detail}`);
  }
}

/** 补丁管理命令：node dist/cli.js patch [status]（补丁强制启用；无参数=立即重载） */
function runPatch(argv: string[]): void {
  const action = argv[0];
  const config = loadConfig();
  const root = findDshRoot(config.patch.dshRoot);
  if (!root) {
    console.error('[dsh-passwords] 找不到 dsh 安装目录（可用 MCP_DSH_ROOT 指定 @deepseek-ai/dsh 路径）');
    process.exit(1);
  }
  console.log(`dsh 目录: ${root}`);
  if (action === 'status') {
    const status = patchStatus(root);
    console.log(`  settings 强制 host 模式: ${status.settingsHostMode ? '已打' : '未打'}`);
    console.log(`  WEB_SETTINGS_NAMESPACES 白名单(含 dsh-passwords): ${status.whitelist ? '已打' : '未打'}`);
    return;
  }
  if (action === undefined || action === 'on' || action === 'reload') {
    const result = applyRemotePatch(root);
    console.log(`  结果: ${result}`);
    if (result === 'applied' && config.patch.restartService) {
      console.log(`  重启 ${config.patch.restartService} 使补丁立即生效...`);
      // CLI 进程跑完就退出，不能用延迟定时器（unref 定时器会被丢弃）；直接同步重启
      try {
        execSync(`systemctl restart ${config.patch.restartService}`, { stdio: 'inherit' });
      } catch (error) {
        console.error(`  重启失败（补丁将在下次 dsh 重启后生效）: ${String(error)}`);
      }
    }
    return;
  }
  console.error('用法: node dist/cli.js patch [status]');
  process.exit(1);
}

async function boot() {
  const config = loadConfig();
  if (!config.setupKey || config.setupKey === 'change-me-to-a-strong-random-key') {
    console.error('[dsh-passwords] 请先配置 .env 中的 SETUP_KEY（预设安装密钥），见 .env.example');
    process.exit(1);
  }

  const mode = process.argv[2] ?? 'serve-gateway';
  const cli = parseCliOverrides(process.argv.slice(3));

  // 启动参数覆盖 .env / 环境变量
  if (cli.port !== undefined) config.gateway.port = cli.port;
  if (cli.host !== undefined) config.gateway.host = cli.host;
  if (cli.upstream !== undefined) config.gateway.upstream = cli.upstream;

  // ── 远程设置补丁：强制启用，网关每次启动自动应用（幂等） ──
  try {
    const root = findDshRoot(config.patch.dshRoot);
    if (root) {
      const result = applyRemotePatch(root);
      if (result === 'applied') {
        console.error('[dsh-passwords] 远程设置补丁: 已自动应用，dsh 网页服务即将重启');
        if (config.patch.restartService) restartDshWeb(config.patch.restartService, 2500);
      } else if (result === 'missing') {
        console.error('[dsh-passwords] 未找到补丁目标文件（dsh 版本可能变更），跳过补丁应用');
      }
    } else if (config.patch.dshRoot) {
      console.error('[dsh-passwords] MCP_DSH_ROOT 指定的 dsh 目录不存在，跳过补丁同步');
    }
  } catch (error) {
    console.error('[dsh-passwords] 补丁同步失败（不影响网关启动）:', error);
  }

  const db = new Database(config.dbPath, createFieldCrypto(config.dbEncKey, config.setupKey));
  db.init();

  const auth = new AuthService(config, db);

  const gateway = createGatewayServer(config, auth, db);
  const redirect = createRedirectServer(config);
  const tlsOn = config.gateway.tls !== null;

  gateway.listen(config.gateway.port, config.gateway.host, () => {
    console.error(
      `[dsh-passwords] 登录网关(${tlsOn ? 'HTTPS' : 'HTTP'}): ${tlsOn ? 'https' : 'http'}://${config.gateway.host}:${config.gateway.port} → 上游 ${config.gateway.upstream}`,
    );
    console.error(`[dsh-passwords] 数据库(SQLite): ${config.dbPath}`);
  });
  if (redirect !== null) {
    redirect.listen(config.gateway.redirectPort!, config.gateway.host, () => {
      console.error(
        `[dsh-passwords] HTTP→HTTPS 跳转: http://${config.gateway.host}:${config.gateway.redirectPort} → 301 https://…（不提供页面内容）`,
      );
    });
  }
  process.on('SIGINT', () => {
    gateway.close();
    redirect?.close();
    process.exit(0);
  });
  process.on('SIGTERM', () => {
    gateway.close();
    redirect?.close();
    process.exit(0);
  });
}

// CLI 分发：audit | patch | serve-gateway
if (process.argv[2] === 'audit') {
  runAudit(process.argv.slice(3));
} else if (process.argv[2] === 'patch') {
  runPatch(process.argv.slice(3));
} else {
  boot().catch((error) => {
    console.error('[dsh-passwords] 启动失败:', error);
    process.exit(1);
  });
}
