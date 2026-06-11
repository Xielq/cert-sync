# Cert-Sync - 阿里云 SSL 证书自动同步工具

自动从阿里云 CAS 获取最新 SSL 证书，同步到 K8s TLS Secret、Docker Nginx 容器和 EMQX Cloud 部署，支持指纹比对、按需更新。

## 功能特性

- 自动发现 K8s 集群中所有使用目标域名的 TLS Secret，比对指纹后按需更新
- 自动发现运行中的 Docker Nginx 容器，解析配置提取证书路径，更新后自动 reload
- 自动同步 EMQX Cloud 托管部署的 TLS 证书，通过 API 比对指纹后按需更新
- 支持通过 `SYNC_MODE` 切换运行模式（k8s / docker / emqx / all）
- 排除指定命名空间，避免误操作系统组件

## 架构

```
阿里云 CAS（证书服务）
        │
        ▼
  cert_sync.py（主入口）
        │
   ┌────┼───────┐
   ▼    ▼       ▼
 K8s  Docker   EMQX Cloud
Secret Nginx   TLS 证书
 更新  更新+reload  API 更新
```

## 项目结构

```
cert-sync/
├── cert_sync.py          # 主程序，K8s 证书同步逻辑
├── docker_nginx_sync.py  # Docker Nginx 证书同步逻辑
├── emqx_cloud_sync.py   # EMQX Cloud TLS 证书同步逻辑
├── Dockerfile            # 镜像构建
├── docker-compose.yaml   # Docker 部署配置
├── namespace.yaml        # ops 命名空间
├── cronjob.yaml          # K8s CronJob + RBAC + Secret
├── requirements.txt      # Python 依赖
└── README.md
```

## 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | 是 | - | 阿里云 AccessKey ID |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | 是 | - | 阿里云 AccessKey Secret |
| `ALIBABA_CLOUD_REGION` | 否 | cn-hangzhou | 阿里云区域 |
| `CERT_DOMAIN` | 否 | *.sisensing.com | 目标证书域名，多个用逗号分隔 |
| `SYNC_MODE` | 否 | all | 运行模式：k8s / docker / emqx / all |
| `EXCLUDE_NAMESPACES` | 否 | kube-system,kube-public,kube-node-lease | K8s 排除的命名空间 |
| `EMQX_API_BASE` | 否 | https://cloud.emqx.com | EMQX Cloud API 地址 |
| `EMQX_API_KEY` | EMQX模式必填 | - | EMQX Cloud API Key |
| `EMQX_API_SECRET` | EMQX模式必填 | - | EMQX Cloud API Secret |
| `EMQX_DEPLOYMENT_IDS` | EMQX模式必填 | - | EMQX 部署ID，多个用逗号分隔 |
| `EMQX_CERT_DOMAIN` | 否 | 取CERT_DOMAIN第一个 | EMQX 使用的证书域名 |

## 部署方式

### 方式一：K8s CronJob（每天定时同步集群 Secret）

```bash
# 1. 构建并推送镜像
docker build -t your-registry/cert-sync:latest .
docker push your-registry/cert-sync:latest

# 2. 创建命名空间
kubectl apply -f namespace.yaml

# 3. 修改 cronjob.yaml 中的 AK/SK 和镜像地址，然后部署
kubectl apply -f cronjob.yaml

# 4. 手动触发测试
kubectl create job --from=cronjob/cert-sync cert-sync-test -n ops
kubectl logs -n ops job/cert-sync-test
```

### 方式二：Docker Compose（同步宿主机 Nginx 容器证书 + EMQX Cloud）

容器内通过 entrypoint 循环执行，默认每 86400 秒（1天）同步一次，无需 crontab。

```bash
# 1. 配置环境变量
export ALIBABA_CLOUD_ACCESS_KEY_ID=<your-ak>
export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<your-sk>
# EMQX Cloud 配置
export EMQX_API_KEY=<your-api-key>
export EMQX_API_SECRET=<your-api-secret>
export EMQX_DEPLOYMENT_IDS=<deployment-id-1>,<deployment-id-2>

# 2. 后台启动（常驻运行，自动循环执行）
docker compose up -d --build

# 3. 查看日志
docker logs -f cert-sync
```

通过 `SYNC_INTERVAL` 环境变量调整执行间隔（单位秒，默认 86400）。


## 工作流程

1. 从阿里云 CAS 获取目标域名的最新证书（按过期时间取最新）
2. 计算阿里云证书 SHA256 指纹
3. **K8s 模式**：遍历所有 namespace 的 TLS Secret，解析证书域名匹配后比对指纹，不一致则更新
4. **Docker 模式**：发现 Nginx 容器 → 解析 nginx.conf 提取 ssl_certificate 路径 → 读取容器内证书比对指纹 → 更新证书文件 → nginx reload
5. **EMQX 模式**：通过 EMQX Cloud API 获取当前部署证书 → 比对指纹 → 不一致则调用 PUT API 更新

## 前置依赖

- 阿里云账号需开通 SSL 证书服务，且有已签发的证书
- K8s 模式需要集群内已存在 TLS Secret（工具只更新，不创建）
- Docker 模式需要挂载 `/var/run/docker.sock`
- EMQX 模式需要 EMQX Cloud API 访问凭证（在 EMQX Cloud 控制台创建）

## RBAC 权限说明

| 资源 | 权限 | 用途 |
|------|------|------|
| secrets | get, list, update, patch | 读取和更新 TLS Secret |
| namespaces | list | 发现所有命名空间 |
