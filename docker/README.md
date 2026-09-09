# 云服务器控制台（AWS Lightsail + 甲骨文 OCI 整合版）

单容器、单进程、单端口（8088）部署在路由器 / 任意 Docker 主机上。
浏览器一个书签直达：`http://10.0.0.1:8088`

- 顶部切换器【AWS 光帆 | 甲骨文 OCI】切换两个面板
- 深色 AWS 运维主题统一
- 无 Python / Flask / 5000 端口，纯 Node.js 单进程
- 凭证只保存在容器内挂载的 `/data` 目录，不回显、不写入镜像

## 目录结构

```
docker/
├── docker-compose.yml      # 单容器编排（唯一入口）
├── README.md
├── aws/                    # 整合版前端 + Node 后端（含 OCI 纯 Node 实现）
│   ├── index.html          # 单文件前端（AWS 视图 + OCI 视图，深色主题）
│   ├── server.js           # Node 代理（AWS SigV4 + OCI RSA 签名都在这）
│   ├── oci.js              # OCI 后端模块（纯 Node，无 Python）
│   ├── vendor/             # xterm（在线 SSH 终端）
│   └── node_modules/       # ws + ssh2（在线 SSH 依赖）
└── data/                   # 凭证持久化目录（容器挂载 /data）
    ├── aws-credentials.json    # AWS 凭证（装好后网页填写，自动生成）
    └── oci-credentials.json    # OCI 凭证（装好后网页填写，自动生成）
```

## 部署步骤（ImmortalWrt 路由器 LuCI）

1. 把整个 `docker/` 目录上传到路由器，例如 `/opt/cloud-console/`
2. LuCI → Docker → 镜像，确认 `node:20-slim` 已拉取（没有就拉取）
3. 终端执行（或 LuCI 容器界面新建）：

```sh
cd /opt/cloud-console
docker compose up -d
```

4. 浏览器打开 `http://10.0.0.1:8088`，先**注册账号**（账号 + 密码），自动登录
5. 登录后配置云凭证（凭证保存在服务器端，跟随账号）：
   - 【AWS 光帆】→ 设置：填 Access Key / Secret Key / 区域 → 保存
   - 【甲骨文 OCI】→ 设置：填租户 OCID / 用户 OCID / 指纹 / 区域 / 私钥 → 保存
6. 书签直达：`http://10.0.0.1:8088/`（AWS）、`http://10.0.0.1:8088/#/oci`（甲骨文）

## 账号与多设备

- 凭证按**账号**隔离保存在服务器 `/data/users/<账号>/`，登录后自动读取
- 换电脑 / 清浏览器缓存后，用**同一账号密码**登录即可，**无需重新配置凭证**
- 首次注册的账号会自动继承旧版全局凭证（如果有），后续注册的账号各自独立配置
- 顶部右侧可查看当前账号、点击「退出」

## 替换旧版双容器

旧版是两个容器（aws-panel:8088 + oci-panel:5000）。升级为单容器：

```sh
cd /opt/cloud-console
docker rm -f oci-panel aws-panel
docker compose up -d
```

旧版 `/data/oci_config.json` 若存在可删除（新格式为 `oci-credentials.json`，
装好后在网页重新填写保存即可，私钥内容直接粘贴）。

## 常用操作

```sh
docker logs -f cloud-console        # 看日志
docker restart cloud-console        # 重启面板
docker compose down && docker compose up -d   # 彻底重来（凭证保留在 /data）
```

## 安全提醒

- **不要**把 8088 做端口转发暴露到公网；面板只应在局域网使用
- 凭证文件在 `/data/`，容器被删也不会丢；不要把这个目录拷给他人
- 首次启动容器会自动 `apt-get install openssh-client`（约几十秒），
  用于 AWS 在线 SSH 的「点击即连」；装完即可使用
