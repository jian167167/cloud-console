#!/bin/sh
# Cloud Console 云服务器控制台 - 傻瓜式一键安装（Linux / 路由器 / NAS）
# 用法：sh install.sh
# 特点：可重复运行 —— 重复运行 = 自动更新到最新版
set -e

APP_DIR="/opt/cloud-console"

echo "=============================================="
echo "  Cloud Console 云服务器控制台 - 一键安装"
echo "=============================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "[错误] 未检测到 Docker"
  echo "  请先安装："
  echo "    ImmortalWrt / OpenWrt : opkg install docker"
  echo "    Debian / Ubuntu       : apt install docker.io"
  exit 1
fi

echo "==> 1/3 获取最新代码 ..."
if [ -d "$APP_DIR/.git" ]; then
  cd "$APP_DIR" && git pull --ff-only
  rm -f "$APP_DIR/node_modules/.install-ok"
  echo "    已更新到最新版本"
else
  rm -rf "$APP_DIR"
  git clone --depth 1 https://github.com/jian167167/cloud-console.git "$APP_DIR"
  echo "    已下载到 $APP_DIR"
fi

echo "==> 2/3 启动容器（首次会自动安装依赖，约 1-2 分钟）..."
cd "$APP_DIR/docker"
docker compose up -d

echo "==> 3/3 安装完成！"
echo ""
echo "  浏览器打开： http://<路由器IP>:8088"
echo "  甲骨文直达： http://<路由器IP>:8088/#/oci"
echo ""
echo "  更新：再运行一次  sh install.sh"
echo "  停止：cd $APP_DIR/docker && docker compose down"
echo "  日志：docker logs -f cloud-console"
