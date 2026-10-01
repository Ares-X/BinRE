#!/bin/bash
# 一键激活:启动本地 license lab,打开 Mole,激活后可随时关掉本脚本
set -euo pipefail
CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
command -v "$PYTHON" >/dev/null || PYTHON=python3
"$PYTHON" "$CASE_DIR/license_lab_server.py" &
LAB_PID=$!
trap 'kill "$LAB_PID" 2>/dev/null || true' EXIT
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:23949/health >/dev/null 2>&1 && break
  sleep 0.2
done
APP="${1:-/Applications/Mole.app}"
open "$APP"
echo "lab server on :23949 — 在 Mole 菜单 > License… 里输入任意 key 点激活即可"
echo "激活成功后 Ctrl-C 退出(之后离线启动也保持激活)"
wait "$LAB_PID"
