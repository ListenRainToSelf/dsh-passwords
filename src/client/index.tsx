// dsh 浏览器侧插件：在设置页"插件"列表里注册 dsh-passwords 卡片。
// 卡片内容：
//   - 远程设置补丁状态 + "重载补丁"按钮（任何登录用户可触发；补丁强制启用）
//   - 用户管理（改密/改名/子用户） → fetch /api/dsh-passwords/*（网关
//     JWT cookie 鉴权）
import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client';
import type {} from '@deepseek-ai/dsh-client-ui-slots/client';
import type {} from '@deepseek-ai/dsh-client-locale/client';
import { DshPasswordsCard } from './card';

/** 卡片样式：全部使用 dsh 设计令牌（--dsw-alias-*），颜色/主题与官方 PluginCard 完全一致 */
const CSS = `
.dshpw-card{display:flex;flex-direction:column;border:1px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-3);transition:border-color .16s,background .16s;font-size:13px;line-height:1.5;overflow:hidden}
.dshpw-card:hover{border-color:var(--dsw-alias-label-dimmed)}
.dshpw-card.open{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-label-dimmed)}
.dshpw-header{display:flex;align-items:center;gap:12px;width:100%;padding:14px 16px;background:none;border:0;border-radius:12px;font:inherit;color:inherit;text-align:left;cursor:pointer}
.dshpw-header:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-2px}
.dshpw-head{flex:1;min-width:0;display:flex;flex-direction:column;gap:4px}
.dshpw-title{font-size:15px;font-weight:600;line-height:1.4;color:var(--dsw-alias-label-primary)}
.dshpw-desc{font-size:13px;line-height:1.5;color:var(--dsw-alias-label-tertiary)}
.dshpw-chevron{flex:none;color:var(--dsw-alias-label-tertiary);transition:transform .16s}
.dshpw-chevron.open{transform:rotate(180deg)}
.dshpw-body{border-top:1px solid var(--dsw-alias-border-l2);margin:0 16px;padding:12px 0 14px;display:flex;flex-direction:column;gap:14px}
.dshpw-section{display:flex;flex-direction:column;gap:8px}
.dshpw-label{display:block;font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}
.dshpw-input{width:100%;padding:7px 10px;font-size:13px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l2);border-radius:8px;transition:border-color .15s,box-shadow .15s}
.dshpw-input:focus{outline:none;border-color:var(--dsw-alias-brand-primary);box-shadow:0 0 0 3px color-mix(in srgb,var(--dsw-alias-brand-primary) 18%,transparent)}
.dshpw-input::placeholder{color:var(--dsw-alias-label-tertiary)}
.dshpw-btn{appearance:none;border:0;border-radius:8px;padding:5px 14px;font-size:13px;line-height:1.5;font-weight:500;background:var(--dsw-alias-label-primary);color:var(--dsw-alias-bg-layer-3);cursor:pointer}
.dshpw-btn:hover:not(:disabled){filter:brightness(1.1)}
.dshpw-btn:disabled{opacity:.4;cursor:default}
.dshpw-btn.danger{background:none;border:1px solid var(--dsw-alias-label-error);color:var(--dsw-alias-label-error)}
.dshpw-btn.danger:hover:not(:disabled){filter:none;background:color-mix(in srgb,var(--dsw-alias-label-error) 10%,transparent)}
.dshpw-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.dshpw-user{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--dsw-alias-border-l2)}
.dshpw-user:last-child{border-bottom:none}
.dshpw-badge{font-size:11px;padding:1px 8px;border-radius:999px;border:1px solid var(--dsw-alias-brand-primary);color:var(--dsw-alias-brand-primary);margin-left:6px;white-space:nowrap}
.dshpw-badge.admin{border-color:var(--dsw-alias-label-warning,#f7ad31);color:var(--dsw-alias-label-warning,#f7ad31)}
.dshpw-error{color:var(--dsw-alias-label-error);font-size:12px}
.dshpw-ok{color:var(--dsw-alias-label-success,#22c55e);font-size:12px}
.dshpw-hint{font-size:12px;line-height:1.5;color:var(--dsw-alias-label-tertiary)}
`;

if (typeof document !== 'undefined') {
  const el = document.createElement('style');
  el.textContent = CSS;
  document.head.appendChild(el);
}

export const inject = ['slots', 'locale'] as const;

export function apply(ctx: ClientContext): void {
  ctx.slots.inject('settings.plugin.item', () =>
    ctx.slots.register(
      {
        name: 'settings.plugin.item',
        id: 'dsh-passwords',
        order: 55,
        locale: 'dshpw',
        inject: () => ({}),
      },
      DshPasswordsCard,
    ),
  );

  // 极简词典：卡片文字基本内嵌中文，locale 仅提供注册契约所需的表项
  ctx.effect(() => ctx.locale.register('dshpw', { zh: {}, en: {} }), 'dsh-passwords: dicts');
}
