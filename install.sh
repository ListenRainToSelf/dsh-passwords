#!/usr/bin/env bash
# dsh-passwords 一键安装（Linux/macOS 引导壳；实际逻辑在 scripts/install.mjs）
#
# 用法（二选一）:
#   1) curl 直接装:  curl -fsSL https://raw.githubusercontent.com/slywalker2006/dsh-passwords/main/install.sh | bash
#   2) 先 clone 再装: git clone https://github.com/slywalker2006/dsh-passwords && cd dsh-passwords && bash install.sh
# Windows 用户请运行 install.bat。
set -euo pipefail

if [ -f scripts/install.mjs ]; then
  node scripts/install.mjs
  exit $?
fi

command -v node >/dev/null 2>&1 || { echo "[dsh-passwords] 未找到 Node.js（需要 22.5+），请先安装"; exit 1; }
command -v git  >/dev/null 2>&1 || { echo "[dsh-passwords] 未找到 git，请先安装（apt-get install -y git）"; exit 1; }

if [ "$(id -u)" = "0" ]; then
  DEST="${DSH_PASSWORDS_DIR:-/opt/dsh-passwords}"
else
  DEST="${DSH_PASSWORDS_DIR:-$HOME/dsh-passwords}"
fi
if [ -d "$DEST" ]; then
  echo "[dsh-passwords] 目录已存在：$DEST（重装请先手动删除，注意备份 .env 和 data/）"
  exit 1
fi
git clone --depth 1 https://github.com/slywalker2006/dsh-passwords.git "$DEST"
cd "$DEST"
node scripts/install.mjs
