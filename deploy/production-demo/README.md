# AgentGate 生产环境测试 Demo

这是一套隔离部署包，用于在生产服务器上验证 AgentGate 的控制面，不连接知源生产数据。

## 部署边界

- 部署目录：`/home/zhiyuan/agentgate-demo`
- Compose 项目：`agentgate-prod-demo`
- 管理入口：`127.0.0.1:18081`
- Kubernetes：`mock`
- VRP：`simulator`
- Redis：Compose 内独立实例
- PostgreSQL：Compose 内独立实例和独立数据卷
- 目标环境：`AG_ENV=prod`，用于触发生产级策略

## 一键部署

从本机 PowerShell 运行：

```powershell
cd D:\AgentGate
.\deploy\production-demo\deploy.ps1 -TargetHost zhiyuan-pgy -Port 18081
```

需要同时跑生产 smoke（允许、拒绝、待审批、审计链）时：

```powershell
.\deploy\production-demo\deploy.ps1 -TargetHost zhiyuan-pgy -Port 18081 -RunDemo
```

如果服务器已经构建过镜像，而镜像站短时不可用，可以复用现有镜像：

```powershell
.\deploy\production-demo\deploy.ps1 -TargetHost zhiyuan-pgy -Port 18081 -SkipBuild -RunDemo
```

## 访问管理界面

管理端口只绑定服务器回环地址。本机建立 SSH 隧道：

```powershell
ssh -N -L 18081:127.0.0.1:18081 zhiyuan-pgy
```

浏览器打开：

```text
http://127.0.0.1:18081/admin/ui
```

管理令牌位于服务器：

```text
/home/zhiyuan/agentgate-demo/agentgate.env
```

## 验收

```bash
curl -fsS http://127.0.0.1:18081/healthz
curl -fsS http://127.0.0.1:18081/readyz
docker compose -p agentgate-prod-demo \
  --env-file /home/zhiyuan/agentgate-demo/agentgate.env \
  -f /home/zhiyuan/agentgate-demo/app/docker-compose.yml \
  -f /home/zhiyuan/agentgate-demo/app/deploy/production-demo/docker-compose.prod-demo.yml \
  exec -T agentgate agentgate-cli audit verify
```

## 停止

保留数据库和审计数据：

```bash
docker compose -p agentgate-prod-demo \
  --env-file /home/zhiyuan/agentgate-demo/agentgate.env \
  -f /home/zhiyuan/agentgate-demo/app/docker-compose.yml \
  -f /home/zhiyuan/agentgate-demo/app/deploy/production-demo/docker-compose.prod-demo.yml \
  down
```

不要直接执行 `down -v`，除非确认要删除测试数据库和审计链。

## 当前限制

- 该 Demo 不连接真实 Kubernetes、Redis 或 NetGuard。
- 多副本审计链仍不安全，保持单副本。
- 要验证真实集群行为，需要另外准备 K3s 测试服务器并切换 `AG_K8S_MODE=cluster`。
