# RouteScope

Linux 软路由流量观测与统计工具。

## 当前状态

项目目前是可启动的 Rust 服务，已实现领域模型、SQLite 存储、分钟聚合、只读 API
以及可选的模拟采集闭环。实际 eBPF 流量采集、conntrack/NAT 关联、DNS 代理和本地账户认证仍在后续阶段。

- `GET /healthz` 可用于健康检查；
- `/login` 是公开的登录页面骨架；
- 设置 `ROUTESCOPE_DEV_BYPASS_AUTH=1` 后可在本地联调 `/api/v1/*` 只读接口；
- 设置 `ROUTESCOPE_ENABLE_SIMULATOR=1` 后，服务会周期性写入可重复的测试 Flow；
- 真实采集器和正式认证尚未实现，生产环境不得开启开发绕过。

## 开发

要求 Rust 工具链支持 Edition 2024。

```bash
cp .env.example .env
make run
```

默认地址为 `http://127.0.0.1:8080`。在实现本地账户认证前，请勿将监听地址改为 LAN 或 WAN 可访问的地址。
模拟采集默认关闭；需要联调时将 `.env` 中的
`ROUTESCOPE_ENABLE_SIMULATOR` 改为 `1`。

常用命令：

```bash
make fmt
make check
make test
```

Linux namespace 集成环境（需要 root、`iproute2`、`nftables`、`curl` 和 Python 3）：

```bash
sudo make namespace-up
sudo make namespace-test
sudo make namespace-down
```

该环境创建 `client-a/client-b → router → wan` 拓扑，验证两台客户端经
IPv4 NAT 访问 WAN namespace 的 HTTP 服务。

## 项目结构

```text
src/api/       HTTP API 路由
src/auth.rs    管理认证边界（TODO）
src/collector.rs TC eBPF、conntrack、DNS 采集接口与模拟采集器
src/domain.rs  Device、Flow 和域名归因领域模型
src/service.rs 观测查询、Flow 写入和保留期清理
src/storage.rs SQLite 仓储、分钟聚合与清理
src/web.rs     服务端渲染页面与静态资源路由
scripts/namespace_lab.sh namespace 拓扑创建、清理和 smoke test
templates/     Askama HTML 模板
static/        CSS 等静态资源
config/        示例配置
```

更多产品边界、数据保留期和验收标准见 [架构文档](docs/architecture.md)。
