---
name: commit-message
description: 根据 RouteScope 的代码改动生成中文 Conventional Commit 提交信息。用户要求编写、建议或创建 commit message，或提到 feat、fix、chore、提交信息时使用。
---

# RouteScope Commit Message

## 格式

使用中文 Conventional Commit 标题和分点正文：

```text
<type>(<scope>): <中文摘要>

- <具体改动 1>
- <具体改动 2>
```

- `scope` 使用受影响模块，例如 `api`、`auth`、`collector`、`storage`、`web`、`docs`、`deps`；无法明确时可省略。
- 标题简洁，说明改动目的；正文逐项描述实际改动，不复述标题。
- 正文使用中文，代码、路径、命令和技术名保留原文。
- 先基于 Git diff 判断变更内容；不要为未发生的改动编写提交信息。

## 类型

- `feat`：新增用户可见功能、模块或能力。
- `fix`：修复错误、行为缺陷或安全问题。
- `chore`：构建、依赖、工具、配置或其他非功能性维护。
- `docs`：仅修改文档。
- `refactor`：不改变外部行为的代码重构。
- `test`：新增或调整测试。

## 示例

```text
feat(web): 搭建管理界面骨架

- 新增服务端渲染的登录、概览和设备页面
- 添加受认证边界保护的管理路由
- 为未实现的观测数据展示明确空状态
```

```text
fix(collector): 修正 Flow 上传方向统计

- 按 LAN 设备视角判断上传和下载方向
- 补充 NAT 映射下的方向回归测试
```
