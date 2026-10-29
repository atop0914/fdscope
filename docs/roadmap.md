# 路线图与当前边界

本文档记录 **已经做了的**、**正在做的**、以及**明确不做的**。
项目状态以本文为准，README 只做概览。

## 已完成

| 能力 | 位置 | 说明 |
|------|------|------|
| `/proc` 快照采集 | `internal/probe` | 目录项 + `readlink` + `fdinfo` + `limits` |
| fd 指纹归一化 | `internal/model/fingerprint.go` | socket/pipe 去 inode、日志轮转合并、deleted 单列 |
| 按指纹分组的报告 | `internal/model/model.go` | 降序排列，稳定输出 |
| 上限与余量 | `internal/model/limit.go` `Headroom` | 三态（已知/unlimited/读不到）显式区分；JSON 只加字段不改名 |
| EMFILE 预测 | `internal/analyze/projection.go` | 实测速率 + 剩余量；无速率则不产出 ETA，ETA 带依据与置信度 |
| CLI `snapshot` | `internal/cli` | 表格 + `--json` + `--top` |
| 公共库 `pkg/fdscope` | `pkg/fdscope` | 快照 API；`CheckPID` 判定；`LeakCheck` goleak 式断言 |
| CLI `check` | `internal/cli/check.go` | 一次窗口一次结论，退出码 0/2/1（1 = 没能判定） |
| L1 归因 | `internal/attr` | 指纹 → 类别规则（数据驱动 + `--attr-rules`）；泄漏按类别分摊增长 |
| 跨平台可编译 + 非 Linux 明确拒绝 | `internal/probe/supported_*.go` | 不假装支持 |
| CI（test/lint/零依赖闸门/交叉编译） | `.github/workflows/ci.yml` | golangci-lint v2.12.2 |

## 进行中（两周计划）

| 阶段 | 能力 | 状态 |
|------|------|------|
| Day 2 | 快照 diff：两个时间点的指纹集合差异 + 已删文件检测 | done |
| Day 3 | `watch`：时序采样 + 时间序列存储 + 回落检测 | done |
| Day 4 | 泄漏判定：单调性 + 基线 + 速率 + 覆盖度，**含防误报语料**，`watch --judge` | done |
| Day 5 | `check` 子命令 + 库级断言 API（`CheckPID` / `LeakCheck`） | done |
| Day 6 | 上限余量与 `EMFILE` 预测 | done |
| Day 7 | L1 归因：指纹 → 类型/路径规则（`internal/attr` + `--attr-rules`） | done |
| Day 8 | L2 归因：泄漏起始时刻 ↔ 进程内事件（标注相关性） | todo |
| Day 9 | L3 归因：测试期 goroutine 配对 | todo |
| Day 10 | 真实语料回归（含外部项目里的真 bug 复现） | todo |
| Day 11 | 文档、基准、Release 工作流 | todo |
| Day 12 | 收尾与 v1.0.0 | todo |

## 明确不做

这些都是**有意的取舍**，不是遗漏：

| 不做 | 原因 |
|------|------|
| 自动 `Close()` 或「修复」泄漏 | 工具不能替调用方决定资源生命周期；关错 fd 比泄漏严重得多 |
| ptrace / eBPF 追踪 `open()` 调用 | 需要特权，且在容器里常常不可用；会改变被测进程行为 |
| 非 Linux 的平台兜底 | 空快照 = 静默通过，比不支持更危险（见 [design.md](design.md)） |
| 猜测「是哪个函数打开的」 | `/proc` 没有这个信息；编造归因比不给归因更有害 |
| L1 判「目录 fd」 | `readlink` 对目录与普通文件输出同形（实测），要区分只能 `stat`，而 `stat` 会依赖采样之外的世界状态 |
| L1 判「已删除且可写」 | 可写性来自 `fdinfo` 的 flags，指纹里没有 |
| 把相关性写成因果 | L2 归因始终标注为相关性 |
| 图形界面 | 目标是 CI 与排障终端，`--json` 供上层消费 |

## 判定「完成」的标准

一个能力算完成，必须同时满足：

1. 有**真实副作用**断言：证明被测事实真的发生了，而不是断言一个返回值
2. 有**反向断言**：该不报的不报（防误报），该拒绝的拒绝
3. 有**边界覆盖**：空输入、越界、权限不足、进程消失
4. **没有静默跳过**：CI 有 grep `--- SKIP` 的闸门
