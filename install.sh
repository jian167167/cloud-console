#!/bin/sh
# Cloud Console 一键安装脚本（Linux / 路由器 / NAS）
# 用法：在仓库根目录执行  ./install.sh
# 依赖：Docker（Debian/Ubuntu: apt install docker.io ；ImmortalWrt: opkg install docker）
set -e

echo "=============================================="
echo "  Cloud Console 云服务器控制台 - 一键安装"
echo "=============================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "[错误] 未检测到 Docker，请先安装："
  echo "  Debian/Ubuntu : sudo apt install -y docker.io"
  echo "  ImmortalWrt   : opkg install docker"
  echo "  OpenWrt       : opkg install docker"
  exit 1
fi

cd "$(dirname "$0")/docker"

echo "==> 启动容器（首次会自动安装依赖，约 1-2 分钟）..."
docker compose up -d

echo "==> 等待服务启动..."
sleep 3
echo "==> 安装完成！"
echo ""
echo "浏览器打开：  http://<本机IP>:8088"
echo "甲骨文直达：  http://<本机IP>:8088/#/oci"
echo ""
echo "查看状态：    docker compose logs -f"
echo "停止服务：    docker compose down"
