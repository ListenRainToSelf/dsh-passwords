// 不可见 token 上报组件：挂在 dsh 会话作用域槽 `conversation.composer.dock`。
// 该槽的标准 props 里带有 `useProjection`（dsh 的第五个框架 hook seat），
// 读 `tokenUsage` 投影（宿主 token-meter 计算的"全日志 provider 计费"）。
//
// ⚠️ 计费口径：只计 `uncachedInputTokens + outputTokens`。
// 实测 dsh 的 tokenUsage 投影里 `cacheReadTokens` 是【每个 step 的缓存累计量】
// 而非增量，而投影的 last-sample-replacing 聚合把它当增量逐 step 累加，
// 导致 cacheRead 虚高 60 倍（一个会话报出 1000 万+）。
// 因此 cacheRead/cacheWrite 不计入配额，避免子用户额度被系统性虚耗。
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
  const inFlight = useRef(false);

  // 累计投影增量
  useEffect(() => {
    if (!usage) return;
    // 只计真实消耗（uncached 输入 + 输出）；cacheRead 因 dsh 投影虚高不计入
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
      if (inFlight.current) return; // 上一轮请求未结束：下个周期再试，避免并发重复上报
      const n = pending.current;
      if (n <= 0) return;
      pending.current = 0;
      inFlight.current = true;
      fetch('/gateway/api/usage/report', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tokens: n }),
      })
        .then((res) => {
          // 只有明确成功才算已上报；4xx/5xx 回滚到 pending 下个周期重试
          if (!res.ok) pending.current += n;
        })
        .catch(() => {
          pending.current += n; // 网络失败回滚，下个周期重试
        })
        .finally(() => {
          inFlight.current = false;
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
