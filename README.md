# Cloud Console 云服务器控制台

一个本地 / 内网部署的云服务器管理面板：**AWS Lightsail（光帆）+ 甲骨文 OCI 双平台合一**。单进程、单端口，凭证按账号保存在服务端。

## 功能

- **AWS 光帆**：多区域实例聚合列表、开机 / 停止 / 重启、删除实例、防火墙入站规则整表编辑、一键开放全部 IPv4 / IPv6 端口、复制 IP（含 IPv6）、在线 SSH（点击即连，无需自己配密钥）、创建实例向导（区域 / 月租 / 系统自选）
- **甲骨文 OCI**：实例列表、开机 / 停止、防火墙（安全列表）规则、IPv6 显示、创建实例
- **账号系统**：注册 / 登录，AWS / OCI 凭证**按账号保存在服务端**——换电脑、清浏览器缓存后，登录同一账号即可，**无需重新配置凭证**
- 深色 AWS 主题，顶部一键切换 AWS / 甲骨文

## 一键安装

### 方式 A：本机运行（Windows / Linux / macOS）

```bash
# 1. 安装 Node.js 18+（https://nodejs.org）
# 2. 安装依赖
npm install
# 3. 启动
node server.js
# 4. 浏览器打开
#    http://localhost:8080
```

Windows 用户也可以直接双击：
- `安装依赖.bat`（装一次）
- `启动面板.bat`（每次启动，自动开浏览器）

### 方式 B：Docker（推荐，路由器 / NAS / VPS）

```bash
cd docker
docker compose up -d
# 浏览器打开 http://<主机IP>:8088
# 首次启动会自动安装依赖（约 1-2 分钟），之后秒起
```

- 数据（账号 / 凭证）保存在 `docker/data/`，升级代码不丢数据
- 书签直达甲骨文：`http://<主机IP>:8088/#/oci`

## 首次使用

1. 打开面板 → **注册账号**（账号 + 密码，自动登录）
2. 登录后到【设置】填写云凭证（**只填一次**，保存在服务端、跟随账号）：
   - **AWS**：Access Key / Secret Key / 区域
   - **OCI**：租户 OCID / 用户 OCID / API 密钥指纹 / 区域 / 私钥
3. 顶部切换 AWS / 甲骨文 OCI，即可管理实例

## 安全说明

- 凭证只保存在服务端（本机：`users/<账号>/`；Docker：`/data/users/<账号>/`），**不回显、不发送到任何第三方**
- 建议仅在内网使用；如要外网访问，请自行加 HTTPS 反向代理与访问控制
- 本仓库不含任何真实凭证 / 私钥（`.gitignore` 已排除）

## 目录结构

```
├── server.js          Node 后端（账号系统 + AWS 代理 + OCI 挂载）
├── oci.js             OCI 签名后端
├── index.html         前端（登录 + AWS 面板 + OCI 面板）
├── package.json       依赖清单
├── 安装依赖.bat        一键装依赖（Windows）
├── 启动面板.bat        一键启动（Windows）
└── docker/            Docker 部署（compose + 说明）
```

## 技术说明

- 纯 Node.js（无框架），前端单文件原生 JS，深色主题
- AWS 走 Lightsail REST API（SigV4 签名，服务端执行，凭证不出服务端）
- OCI 走 OCI REST API（RSA-SHA256 签名，同样服务端执行）
- 在线 SSH：AWS 用 Lightsail 临时证书 + 系统 ssh 客户端；OCI 不支持（避免触发风控）
