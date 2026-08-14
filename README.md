# dsh-passwords

给 DeepSeek Harness（dsh）的网页界面加一道**密码门**。

dsh 自带的网页界面没有任何登录功能——只要别人知道你的服务器地址，打开就能用，还能烧你的 API key。这个项目在 dsh 前面挡一层登录页：没登录的人一律先看到登录页，输对账号密码才放进去。

> 名字的由来：这个项目最早叫 dsh-mcp-platform（当时带 MCP 功能），后来 MCP 删了，只剩一个登录网关，就改名 dsh-passwords——好记：dsh 的密码门。

## 它做了什么

- 登录页 + 首次配置页（第一次访问先设管理员账号）
- 登录一次管 12 小时（Cookie 会话，关浏览器也不丢）
- 密码用 bcrypt 哈希存库，乱试密码 5 次锁 15 分钟
- 每一步都有审计日志，一条命令就能看谁在什么时候登录/失败过
- **用户数据全部加密落盘**：用户名、IP、审计记录都是密文，就算数据库文件被偷走也看不懂
- 支持 HTTPS + 80 端口自动跳转（强烈建议公网开启）
- 登录页自动跟着 dsh 的主题走（dsh 用深色它就深色）

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

`SETUP_KEY` 是**安装密钥**。第一次打开网页时会进入"首次配置"页，要求输入它，输对了才能创建管理员账号。作用就是防止陌生人抢在你前面把平台初始化了。

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

### 4. 用 systemd 托管两个进程（重启服务器自动拉起）

dsh 服务（`/etc/systemd/system/dsh-web.service`）：

```ini
[Unit]
Description=DeepSeek Harness web
After=network.target

[Service]
Type=simple
Environment=DEEPSEEK_API_KEY=sk-你的key
ExecStart=/usr/local/bin/dsh web --patch /opt/dsh-passwords/cordis.yml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

网关服务（`/etc/systemd/system/dsh-gateway.service`）：

```ini
[Unit]
Description=dsh-passwords login gateway
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/dsh-passwords
ExecStart=/usr/local/bin/node dist/index.js serve-gateway
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

访问 `http://你的服务器IP` → 输 `.env` 里的 `SETUP_KEY` → 创建管理员账号。之后所有人访问都先过登录页。

### 7. 强烈建议：开 HTTPS

明文 HTTP 下密码会被中间人抓包。开 HTTPS 三步：

```bash
cd /opt/dsh-passwords

# 1) 自签证书（IP 换成你的服务器 IP；有域名建议用 Let's Encrypt）
openssl req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt \
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

## 常用命令

```bash
npm start                              # 启动网关
node dist/index.js audit --limit 20    # 看最近 20 条审计日志（自动解密）
node dist/index.js serve-gateway --port 9000   # 换个端口启动
```

## 常见问题

- **登录页一直显示"首次配置"？** 说明用户表是空的（新库或数据库被删过）。停服 → 删 `data/platform.db` → 重启 → 重新配置。
- **忘记管理员密码？** 停服后跑 `node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('data/platform.db');db.exec('DELETE FROM users;')"`，重启后重新配置。
- **dsh 报 `crypto.randomUUID is not a function`？** 旧版网关没有 HTML 注入兼容层，更新代码后**强刷浏览器**（Ctrl+Shift+R）。
- **数据库文件被偷了要紧吗？** 不要紧。敏感字段全是 AES-256-GCM 密文或 HMAC 散列，没有 `MCP_DB_ENC_KEY` 解不开；密码本身只有 bcrypt 哈希，本来就没有明文。
- **想换 `MCP_DB_ENC_KEY`？** 不行。这个密钥一旦启用就不能换，换了一切历史数据都解不开。备份数据库时必须连 `.env` 一起备份。
- **npm 装 dsh 报错（allow-scripts / node-pty）？** 跑 `npm config set allow-scripts=... --location=user` 并装 `sudo apt install build-essential`（本项目自己没这个问题，是 dsh 的依赖要编译）。

## 安全清单（都做了）

- 密码 bcrypt 哈希；安装密钥一次性使用；会话 12 小时 HttpOnly Cookie
- 暴力破解：5 次失败锁 15 分钟；SQL 注入三层防护
- HTTPS：TLS 1.2 起步、Cookie `Secure`、HSTS、80 只跳转
- 登录页安全头：严格 CSP、防点击劫持、禁缓存、禁嗅探
- 数据静态加密：用户名/IP/审计记录密文落盘，旧明文自动迁移并清残留
- 源码里没有任何秘密（密钥全在 `.env` 和数据库里），源码公开不影响安全
- 路径穿越防护：`/gateway/../api/xxx` 类请求先规范化再鉴权，未登录一律拦下
- 用户名枚举防护：用户不存在时也空跑一次 bcrypt，响应时序抹平
- 开放重定向防护：`next` 参数白名单校验（拒绝 `\`、`%2F%2F`、控制字符）
- Host 伪造防护：80 跳转目标固定用 `MCP_GATEWAY_PUBLIC_HOST`，不反射请求 Host
- Cookie 畸形编码容错：不会因一条坏 Cookie 让整个站点 500

## License

© 2026 dsh-passwords 版权所有者。**专有软件（闭源）**，保留所有权利——详见 [LICENSE](./LICENSE)。

本项目是 dsh 的独立扩展，与 DeepSeek 无隶属关系。dsh 本身按它自己的许可证（MIT）授权。
