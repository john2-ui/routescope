# RouteScope

Linux 软路由流量观测与统计工具。

## 当前状态

项目目前是可启动的 Rust 服务骨架，尚未实现实际的 eBPF 流量采集、conntrack/NAT 关联、DNS 域名归因、SQLite 存储或本地账户认证。

- `GET /healthz` 可用于健康检查；
- `/login` 是公开的登录页面骨架；
- 仪表盘、设备页面和 `/api/v1/*` 管理接口在认证实现前全部返回 `503 Service Unavailable`；
- 所有业务集成点都以 `TODO` 标记，避免将空数据误报为真实网络观测数据。

## 开发

要求 Rust 工具链支持 Edition 2024。

```bash
cp .env.example .env
make run
```

默认地址为 `http://127.0.0.1:8080`。在实现本地账户认证前，请勿将监听地址改为 LAN 或 WAN 可访问的地址。

常用命令：

```bash
make fmt
make check
make test
```

## 项目结构

```text
src/api/       HTTP API 路由
src/auth.rs    管理认证边界（TODO）
src/collector.rs TC eBPF、conntrack、DNS 采集接口（TODO）
src/domain.rs  Device、Flow 和域名归因领域模型
src/storage.rs SQLite 仓储接口（TODO）
src/web.rs     服务端渲染页面与静态资源路由
templates/     Askama HTML 模板
static/        CSS 等静态资源
config/        示例配置
```

更多产品边界、数据保留期和验收标准见 [架构文档](docs/architecture.md)。
