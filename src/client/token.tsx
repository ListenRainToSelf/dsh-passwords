// 不可见 token 上报组件：挂在 dsh 会话作用域槽 `conversation.composer.dock`。
// 该槽的标准 props 里带有 `useProjection`（dsh 的第五个框架 hook seat），
// 读 `tokenUsage` 投影（宿主 token-meter 计算的"全日志 provider 计费"，字段为
// uncachedInputTokens / outputTokens / cacheReadTokens / cacheWriteTokens）。
//
// 设计要点：投影值是【会话内累计值】而非增量。这里记录"上次观测到的累计值"，
// 只把差值累进 pending，再按固定间隔 POST 到密码门 `/gateway/api/usage/report`，
// 由网关按小时窗口累计后做子用户每小时 token 配额判定。首次观测值只作为基线
// 不计费（避免重开会话/重挂载重复计费）。组件渲染 null，不影响 dsh 界面。
import { useEffect, useRef } from 'react';
import type { UseProjection } from '@deepseek-ai/dsh-client-runtime/client';

interface TokenUsageProjection {
  uncachedInputTokens?: number;
  outputTokens?: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

const REPORT_INTERVAL_MS = 15000;

export function TokenReporter({ useProjection }: { useProjection: UseProjection }) {
  const read = useProjection as unknown as (key: string) => unknown;
  const usage = read('tokenUsage') as TokenUsageProjection | undefined;

  const lastTotal = useRef<number | null>(null);
  const pending = useRef(0);

  // 累计投影增量
  useEffect(() => {
    if (!usage) return;
    const total = (usage.uncachedInputTokens ?? 0) + (usage.outputTokens ?? 0);
    if (lastTotal.current === null) {
      lastTotal.current = total;
      return;
    }
    const delta = total - lastTotal.current;
    if (delta > 0) pending.current += delta;
    lastTotal.current = total;
  }, [usage]);

  // 定时 flush；卸载时做最后一次 flush（会话切换不丢已产生的增量）
  useEffect(() => {
    const flush = () => {
      const n = pending.current;
      if (n <= 0) return;
      pending.current = 0;
      fetch('/gateway/api/usage/report', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokens: n }),
      }).catch(() => {
        pending.current += n; // 上报失败回滚，下个周期重试
      });
    };
    const timer = window.setInterval(flush, REPORT_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
      flush();
    };
  }, []);

  return null;
}
