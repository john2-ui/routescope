# RouteScope

Linux 软路由流量观测与统计工具。

## 当前状态

项目目前是可启动的 Rust 服务，已实现领域模型、SQLite 存储、分钟聚合、观测 API、
设备名称管理以及可选的模拟采集闭环。第一版 TC eBPF 采集器已经接入，可在 Linux namespace
拓扑中采集 LAN ingress/egress 上的 IPv4 TCP/UDP 双向 Flow，并可选通过只读
conntrack netlink 快照补齐 NAT 关联；可选的本地 DNS UDP/TCP 转发与 IPv4 域名归因
已经接入，本地管理员账户认证、会话和 CSRF 防护也已经接入。

- `GET /healthz` 可用于健康检查；
- `GET /readyz` 用于判断存储和已启用采集器是否已完成启动；
- `/login` 是公开的登录页面，管理页和 `/api/v1/*` 需要有效会话；
- 设置 `ROUTESCOPE_DEV_BYPASS_AUTH=1` 后，仅当监听地址是 loopback 时可在本地联调
  `/api/v1/*` 只读接口；
- 首次部署时设置 `ROUTESCOPE_ADMIN_USERNAME` 和 Argon2id PHC 格式的
  `ROUTESCOPE_ADMIN_PASSWORD_HASH`；首个启动会将账户哈希写入 SQLite，后续启动从本地库读取；
- 可用 `printf '%s\n' 'your-password' | cargo run --quiet -- hash-password` 生成密码哈希；
- 通过 HTTPS 反向代理访问时设置 `ROUTESCOPE_SECURE_COOKIES=1`，会话 Cookie 同时启用
  `HttpOnly`、`SameSite=Lax`；
- 设置 `ROUTESCOPE_ENABLE_SIMULATOR=1` 后，服务会周期性写入可重复的测试 Flow；
- 设置 `ROUTESCOPE_ENABLE_TC_EBPF=1` 后可启用 TC eBPF 采集器；
- 设置 `ROUTESCOPE_ENABLE_CONNTRACK=1` 后可在 TC eBPF Flow 上启用 conntrack NAT 关联；
- 设置 `ROUTESCOPE_ENABLE_DNS_PROXY=1` 后可启用本地 DNS 转发器，默认监听
  `127.0.0.1:5353` 并转发至 `1.1.1.1:53`；生产环境还需用 nftables 将 LAN 的 DNS
  请求重定向到该端口；
- TC eBPF 需要 root、clang、BPF-capable Linux 内核，并且只能在已准备好的路由
  namespace 或真实软路由上启用；
- 生产环境不得开启开发绕过；服务本身默认使用 HTTP，生产部署应限制监听网段并在前置
  HTTPS 终止后启用安全 Cookie。
- `/`、`/devices` 和 `/devices/<mac>` 已接入 SQLite 中的设备、Flow、分钟趋势与域名
  Top 数据；设备列表支持手动命名，管理 API 为
  `POST /api/v1/devices/<mac>/name`（需要 `X-CSRF-Token`）。
- SQLite 使用 `PRAGMA user_version` 执行 schema 迁移，Flow 批次在单事务中写入；可用
  `make benchmark` 或 `cargo run --release -- benchmark-storage 10000` 做离线写入基准。
- 收到 SIGINT/SIGTERM 后会停止采集、DNS、清理后台任务并等待 HTTP 连接，超时由
  `ROUTESCOPE_SHUTDOWN_TIMEOUT_SECS` 控制。

## 开发

要求 Rust 工具链支持 Edition 2024。

```bash
cp .env.example .env
make run
```

默认地址为 `http://127.0.0.1:8080`。默认配置中的开发绕过只对 loopback 地址生效；
生产环境应配置管理员密码哈希并关闭绕过。
模拟采集默认关闭；需要联调时将 `.env` 中的
`ROUTESCOPE_ENABLE_SIMULATOR` 改为 `1`。

常用命令：

```bash
make fmt
make check
make test
make clippy
make benchmark
```

跨架构编译 eBPF 对象时，`build.rs` 默认从 Cargo target 推导架构，也可显式设置
`ROUTESCOPE_BPF_TARGET_ARCH=arm64` 等值；clang 路径仍可通过
`ROUTESCOPE_CLANG` 覆盖。

Linux namespace 集成环境（需要 root、`iproute2`、`nftables`、`curl` 和 Python 3）：

```bash
sudo make namespace-up
sudo make namespace-test
make namespace-collector-test
sudo make namespace-down
```

该环境创建 `client-a/client-b → router → wan` 拓扑，验证两台客户端经
IPv4 NAT 访问 WAN namespace 的 HTTP 服务。`make namespace-collector-test`
会先构建当前 RouteScope，再在 router namespace 内启动服务，验证真实 TC
eBPF 双向 Flow 能按客户端 MAC 出现在 API 中，并在启用 conntrack 时补齐 NAT 映射。

## 项目结构

```text
src/api/       HTTP API 路由
src/auth.rs    本地账户、Argon2id、会话、CSRF 与限速
src/collector.rs TC eBPF、采集管线与模拟采集器
src/conntrack.rs conntrack netlink 快照与 NAT 关联
src/dns.rs     DNS observation 队列、TTL 缓存与 Flow 域名归因
src/dns_proxy.rs 本地 DNS UDP/TCP 转发与 A 记录解析
src/routescope_tc.c TC eBPF IPv4 TCP/UDP 统计程序
build.rs          编译 TC eBPF 对象文件
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
