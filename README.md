# dsh-passwords

给 DeepSeek Harness（dsh）加一道**密码门**：让 dsh 可以安全地**远程访问**，并支持**多用户**。

dsh 自带的网页界面没有任何登录功能。放上服务器/云主机后，任何人拿到地址就能用，还能烧你的 API key。dsh-passwords 在 dsh 前面挡一层登录页：没登录的人一律先看到登录页，输对账号密码才放进去。

> **一句话定位：dsh-passwords = dsh 的远程访问入口 + 多用户账号系统。** 纯本地用 dsh 不需要它；但只要访问地址不是 localhost，先装它。

🏅 已收录于 [Awesome DeepSeek Harness](https://github.com/0xsline/awesome-deepseek-harness) 生态索引（Infrastructure & Development）与 [Awesome DSH Plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin) 插件精选列表（Development & Runtime）。

> 名字的由来：这个项目最早叫 dsh-mcp-platform（当时带 MCP 功能），后来 MCP 删了，只剩一个登录网关，就改名 dsh-passwords——好记：dsh 的密码门。

## 两大核心能力

### 1️⃣ 远程连接

- 登录页 + 首次配置页（第一次访问先设主账号，之后谁访问都先过登录页）
- 登录一次管 12 小时（Cookie 会话，关浏览器也不丢）
- 支持 HTTPS + 80 端口自动跳转（公网部署强烈建议）
- 登录页自动跟着 dsh 的主题走（dsh 用深色它就深色）
- 远程浏览器可正常使用 dsh 的全部设置功能（dsh 默认只允许本机浏览器编辑设置，dsh-passwords 自动处理这件事；dsh 升级后若设置页出现异常，设置页卡片里有"重载补丁"一键修复）

### 2️⃣ 多用户

- 一个**主用户**（首次配置创建）+ 任意多个**子用户**，各自独立账号密码登录
- 所有账号管理都在 dsh 设置页的卡片里完成，不用 SSH：改密码、改用户名、创建/删除子用户
- 主用户可管理所有子用户；子用户只能改自己
- 改密后旧会话全部立即失效；每次登录/失败都有记录，一条命令就能查谁在什么时候登录过

## 界面截图

| 登录页（浅色 · 跟随系统） | 登录页（深色 · 跟随 dsh 主题） |
|---|---|
| <img src="docs/screenshots/login-light.png" width="380"> | <img src="docs/screenshots/login-dark.png" width="380"> |

| 首次配置页（首次访问） | dsh 主界面（登录后） |
|---|---|
| <img src="docs/screenshots/setup-page.png" width="380"> | <img src="docs/screenshots/dsh-ui.png" width="380"> |

## 本地先跑起来看看

需要 Node.js **22.5 以上**（`node -v` 看一眼）。

```bash
npm install           # 装依赖
cp .env.example .env  # 复制出配置文件
npm run build         # 编译
npm start             # 启动，浏览器打开 http://localhost:8080
```

启动前记得改 `.env` 里的 `SETUP_KEY`（下面讲它是什么）。

## SETUP_KEY 是什么？在哪？

`SETUP_KEY` 是**安装密钥**。第一次打开网页时会进入"首次配置"页，要求输入它，输对了才能创建主用户。作用就是防止陌生人抢在你前面把平台初始化了。

**它在项目根目录的 `.env` 文件里**，就是这一行：

```ini
SETUP_KEY=change-me-to-a-strong-random-key
```

操作很简单：

1. 打开 `.env`，找到 `SETUP_KEY=` 这一行
2. 把等号后面换成你自己生成的随机串：
   ```bash
   openssl rand -hex 24   # Linux/macOS 上跑，输出一串随机字符
   ```
3. 保存，重启网关
4. 打开网页，在"预设密钥"框里输入刚才这串值

⚠ 不改成随机值的话网关会拒绝启动。初始化完成后这个密钥就没用了，之后登录只认账号密码。

## 部署到服务器（跟着抄就行）

### 1. 装 Node.js 22+

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v   # 确认 >= v22.5.0
```

### 2. 装 dsh 并准备 API key

```bash
npm install -g @deepseek-ai/dsh
```

去 DeepSeek 开放平台拿一个 API key（`sk-` 开头），等会要用。

### 3. 下载本项目

```bash
cd /opt
git clone https://github.com/slywalker2006/dsh-passwords.git
cd dsh-passwords
npm install
cp .env.example .env
```

打开 `.env` 改三处：

| 改哪里 | 改成什么 |
|---|---|
| `SETUP_KEY=...` | 必须改，`openssl rand -hex 24` 生成 |
| `MCP_GATEWAY_PORT=8080` | 想对公网开放的端口，比如 `80` |
| `MCP_DB_ENC_KEY=` | 填上 `openssl rand -hex 32` 生成的值（数据加密密钥，**设了就不能改**） |

```bash
npm run build
```

### 3.5 把 dsh-passwords 注册成 dsh 插件（设置页卡片）

dsh 的设置页插件列表由 profile 的依赖决定，把本项目加进去：

```bash
cd ~/.dsh/profiles/web
pnpm add /opt/dsh-passwords
```

（dsh rc.6 用 pnpm 管理 profile 依赖；如果系统里没有 pnpm，先 `npm install -g pnpm@9`。）

这样 dsh 启动时就会加载 dsh-passwords 的主机侧插件：设置页出现"dsh-passwords · 密码门"卡片，账号管理都在里面。

### 4. 用 systemd 托管两个进程（重启服务器自动拉起）

dsh 服务（`/etc/systemd/system/dsh-web.service`）：

```ini
[Unit]
Description=DeepSeek Harness web
After=network.target

[Service]
Type=simple
Environment=DEEPSEEK_API_KEY=sk-你的key
Environment=DSH_PASSWORDS_ENV_FILE=/opt/dsh-passwords/.env
ExecStart=/usr/local/bin/dsh web --patch /opt/dsh-passwords/cordis.yml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> `DSH_PASSWORDS_ENV_FILE` 让 dsh 里的密码门插件读到和网关同一份 `.env`（同一个数据库、同一把密钥），必须加上。

网关服务（`/etc/systemd/system/dsh-gateway.service`）：

```ini
[Unit]
Description=dsh-passwords login gateway
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/dsh-passwords
ExecStart=/usr/local/bin/node dist/cli.js serve-gateway
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dsh-web dsh-gateway
sudo systemctl status dsh-web dsh-gateway   # 两个都 active 就对了
```

### 5. 防火墙放行

```bash
sudo ufw allow 80/tcp
```

⚠ 云服务器（阿里云/腾讯云等）还要去**控制台的安全组**里放行同一个端口，只配 ufw 是没用的。

### 6. 浏览器完成首次配置

访问 `http://你的服务器IP` → 输 `.env` 里的 `SETUP_KEY` → 创建主用户。之后所有人访问都先过登录页。

### 7. 强烈建议：开 HTTPS

明文 HTTP 下密码会被中间人抓包。开 HTTPS 三步：

```bash
cd /opt/dsh-passwords

# 1) 自签证书（用 EC 椭圆曲线，别用 RSA！RSA 握手在弱 CPU 服务器上可能要 1 秒以上，
#    EC 只要几毫秒；IP 换成你的服务器 IP；有域名建议用 Let's Encrypt）
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout tls.key -out tls.crt \
  -days 825 -nodes -subj "/CN=你的IP" -addext "subjectAltName=IP:你的IP"
chmod 600 tls.key

# 2) .env 里改成这样：
#   MCP_GATEWAY_PORT=443
#   MCP_GATEWAY_TLS_CERT=/opt/dsh-passwords/tls.crt
#   MCP_GATEWAY_TLS_KEY=/opt/dsh-passwords/tls.key
#   MCP_GATEWAY_REDIRECT_PORT=80

# 3) 重启 + 放行 443
sudo systemctl restart dsh-gateway
sudo ufw allow 443/tcp   # 安全组同样要放行 443
```

之后 `http://` 会自动跳到 `https://`。自签证书浏览器第一次会提示不安全，点"继续前往"就行。

## dsh 怎么启动（重要）

dsh 和网关是**两个独立进程**，都要跑起来才能用。启动 dsh 的命令：

```bash
DEEPSEEK_API_KEY=sk-你的key dsh web --patch /opt/dsh-passwords/cordis.yml
```

两个参数说明：

- `DEEPSEEK_API_KEY=...`：**必填**。dsh 调模型用的 API key。
- `--patch .../cordis.yml`：**远程访问时强烈建议加**。不加的话，网页上点"添加工作区"会尝试弹出**你电脑本地**的系统文件夹选择器——但你是远程访问服务器的，浏览器根本弹不出本机选择器，表现就是点添加工作区没反应/报错（`pickDirectory` 失败）。加上这个参数后，点"添加工作区"会在网页内弹出**服务器目录浏览器**，直接浏览并选择服务器上的文件夹（也能手动输入绝对路径，比如 `/opt/myapp`）。

不想每次敲参数：把 `cordis.yml` 的内容合并进 `~/.dsh/profiles/web/cordis.patch.yml`，之后直接 `dsh web` 就永久生效。

> 上面第 4 步的 systemd 配置里已经带上了 `--patch`，跟着教程走就不用管这节。

## 设置页里的密码门卡片

登录 dsh 后，打开 **设置 → 插件**，能看到"dsh-passwords · 密码门"卡片。里面可以：

| 功能 | 谁可用 | 说明 |
|---|---|---|
| **远程设置 + 重载补丁** | 所有登录用户 | 显示远程设置是否可用；dsh 升级后若设置页出现异常，点"重载补丁"一键修复（自动重启网页服务并刷新页面，不用 SSH） |
| **修改密码** | 本人改自己；主用户可改任何人 | 改密后旧会话全部立即失效，需重新登录 |
| **修改用户名** | 本人改自己；主用户可改任何人 | 改名后需用新用户名重新登录 |
| **子用户管理** | 仅主用户 | 创建/删除子用户（子用户可用登录页进入，但没有管理权限） |

说明：

- **主用户** = 首次配置时创建的那个账号；之后添加的都是**子用户**。
- 卡片里的账号管理走网关自己的接口，与 dsh 的设置相互独立。
- 密码要求与登录页一致：至少 12 位，且大写、小写、数字、符号各至少一位。

> dsh 默认只允许本机浏览器编辑设置。dsh-passwords 会自动处理，让经密码门登录的远程浏览器也能正常使用全部设置功能。dsh 升级后若设置页出现异常，点卡片里的"重载补丁"即可（网关每次启动也会自动处理，重启网关同样有效）。

## 配置速查表

| 变量 | 默认值 | 干什么的 |
|---|---|---|
| `SETUP_KEY` | 必填 | 首次配置的安装密钥（在 `.env` 里） |
| `MCP_DB_PATH` | `./data/platform.db` | 数据库文件放哪（自动建库，不需要装 MySQL） |
| `MCP_DB_ENC_KEY` | 空 | 数据加密密钥。`openssl rand -hex 32` 生成。**设了就不能换，换钥匙旧数据全废** |
| `MCP_GATEWAY_HOST` | `0.0.0.0` | 网关监听地址 |
| `MCP_GATEWAY_PORT` | `8080` | 网关端口 |
| `MCP_GATEWAY_UPSTREAM` | `http://127.0.0.1:3080` | dsh 网页的地址（保持默认） |
| `MCP_GATEWAY_TLS_CERT` / `MCP_GATEWAY_TLS_KEY` | 空 | 两个都填就开 HTTPS |
| `MCP_GATEWAY_REDIRECT_PORT` | 空 | 填 `80` 后 80 端口只做跳转 |
| `MCP_GATEWAY_PUBLIC_HOST` | 空 | 跳转固定用的公网 IP/域名（防 Host 伪造反射） |
| `MCP_DSH_SETTINGS_FILE` | 自动找 `~/.dsh/settings.yaml` | 网关和 dsh 不在同一台机器时才要填 |
| `DSH_PASSWORDS_ENV_FILE` | 空 | dsh 进程里读网关 `.env` 的路径（systemd 里配 `/opt/dsh-passwords/.env`） |
| `MCP_DSH_ROOT` | 自动探测 | dsh 安装目录（`@deepseek-ai/dsh` 所在处），探测不到时手动指定 |
| `MCP_DSH_RESTART_SERVICE` | `dsh-web` | 重载补丁后自动重启的 dsh systemd 服务名；留空不自动重启 |
| `MCP_INTERNAL_SECRET` | 由 SETUP_KEY 派生 | 网关内部接口密钥（dsh 插件→网关通知通道），一般不用改 |

## 常用命令

```bash
npm start                              # 启动网关
node dist/cli.js audit --limit 20    # 看最近 20 条审计日志（自动解密）
node dist/cli.js serve-gateway --port 9000   # 换个端口启动
node dist/cli.js patch status        # 看远程设置状态
node dist/cli.js patch               # 重载补丁（重新应用 + 重启 dsh-web）
```

## 常见问题

- **登录页一直显示"首次配置"？** 说明用户表是空的（新库或数据库被清过）。按页面提示输入 `SETUP_KEY` 重新创建主用户即可。
- **忘记主用户密码？** 停服后跑 `node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('data/platform.db');db.exec('DELETE FROM users;')"`，重启后重新走首次配置。
- **dsh 报 `crypto.randomUUID is not a function`？** 旧版网关没有 HTML 注入兼容层，更新代码后**强刷浏览器**（Ctrl+Shift+R）。
- **数据库文件被偷了要紧吗？** 不要紧。敏感字段全是密文或散列，没有 `.env` 里的密钥解不开；密码本身只有 bcrypt 哈希，本来就没有明文。
- **想换 `MCP_DB_ENC_KEY`？** 不行。这个密钥一旦启用就不能换，换了一切历史数据都解不开。备份数据库时必须连 `.env` 一起备份。
- **访问有点慢？** 网关本身每次请求只花约 1-2ms。先查 TLS 握手：`curl -sk -o /dev/null -w "TCP:%{time_connect}s TLS:%{time_appconnect}s\n" https://你的IP/gateway/login`——如果 TLS 那项要几百毫秒以上，多半是用了 RSA 证书（弱 CPU 服务器上 RSA 握手签名非常慢），换成 EC 证书即可（见第 7 步命令）。TCP 快、TLS 也快但还是慢的话，就是你的网络/代理到服务器的链路延迟，代码解决不了。
- **每次进去都卡在 "Loading plugins…"？** 这是 dsh 在加载它的 ~30 个插件脚本，而 dsh 对插件/静态资源返回的是 `no-cache`，浏览器每次都要全部重新下载。v2.0.4 起网关对 `/assets/*` 和带 `rev=` 的 `/plugins/*` 强制一年期 immutable 缓存（文件名/rev 都是内容哈希，dsh 更新会自动换新地址）。升级后**第一次访问仍会完整下载一次，之后刷新秒进**；如果升级后还慢，强刷一次浏览器（Ctrl+Shift+R）让新响应头生效。
- **npm 装 dsh 报错（allow-scripts / node-pty）？** 跑 `npm config set allow-scripts=... --location=user` 并装 `sudo apt install build-essential`（本项目自己没这个问题，是 dsh 的依赖要编译）。

## 安全与隐私

账号密码只存 bcrypt 哈希；用户名、IP、审计记录加密落盘；连续输错密码 5 次锁 15 分钟。所有密钥都在你自己的 `.env` 和数据库里，源码公开不影响安全。

## License

[BSD 3-Clause](./LICENSE) © 2026 slywalker2006——自由使用、修改、分发，保留版权声明即可。

本项目是 dsh 的独立扩展，与 DeepSeek 无隶属关系。dsh 本身按它自己的许可证（MIT）授权。
