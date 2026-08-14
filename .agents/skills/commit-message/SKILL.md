---
name: commit-message
description: 根据 RouteScope 的 Git 代码改动生成中文 Conventional Commit 提交信息。用户要求编写、建议、优化或创建 commit message，或者提到 feat、fix、chore、提交信息、提交说明时使用。
---

# RouteScope Commit Message

## 检查改动

先检查 Git 状态和 diff，再根据实际改动生成提交信息：

1. 使用 `git status --short` 确认变更范围。
2. 有 staged 变更时，以 `git diff --cached` 为主要依据；否则检查 `git diff`。
3. 必要时读取相关文件，确认改动目的和受影响模块。
4. 不描述 diff 中不存在的功能、修复或测试。

如果改动包含多个互不相关的主题，指出应拆分提交，并分别给出提交信息。

## 编写格式

使用中文 Conventional Commit 标题和分点正文：

```text
<type>(<scope>): <中文摘要>

- <具体改动 1>
- <具体改动 2>
```

- 使用受影响模块作为 `scope`，例如 `api`、`auth`、`collector`、`storage`、`web`、`docs`、`deps`；无法明确时省略。
- 保持标题简洁并说明改动目的，不添加句号。
- 使用正文逐项描述实际改动，不复述标题；简单改动可只写标题。
- 使用中文书写摘要和正文，代码、路径、命令、标识符和技术名称保留原文。
- 存在破坏性变更时，在类型或作用域后添加 `!`，并在正文末尾添加 `BREAKING CHANGE: <说明>`。
- 默认只输出可直接复制的提交信息，不添加分析过程、Markdown 代码围栏或额外前言。

## 选择类型

- `feat`：新增用户可见功能、模块或能力。
- `fix`：修复错误、行为缺陷或安全问题。
- `chore`：构建、依赖、工具、配置或其他非功能性维护。
- `docs`：仅修改文档。
- `refactor`：不改变外部行为的代码重构。
- `test`：新增或调整测试。

选择能够代表主要改动目的的单一类型，不根据改动文件数量选择类型。

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
