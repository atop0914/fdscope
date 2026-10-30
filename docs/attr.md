# L1 归因：规则、阶梯与边界

**L1 只读指纹。** 它不是「猜猜谁打开的」，而是把指纹里**已经写着**的事实
翻译成读者要用的词：这是 socket、这是日志文件、这是一个已经 unlink 但仍被持有的文件。

一句话判据：**L1 的每一句话都能用 `readlink` 手工复核。** 做不到这一点的，不属于 L1。

规则实现在 `internal/attr`，输入是 `View`（scheme / kind / path / name / deleted），
构造自 `model.DecomposeFingerprint`。`View` 里**没有**进程、时钟、文件系统句柄，
所以规则在类型层面就无法越界去推断。

## 内置规则表

优先级由高到低，即「具体 → 笼统」。一个指纹命中多条时只输出一条：优先级最高的那条。

| 优先级 | 规则 | 类别 | 命中条件 | 依据（输出里会带这句） |
|---|---|---|---|---|
| 300 | `deleted-file` | 已删除但仍被持有 | `deleted:` 前缀 | 路径已 unlink 但描述符还在：空间没释放，`du` 看不见 |
| 280 | `anon-inode/eventpoll` | epoll 实例 | `anon_inode:eventpoll` | `epoll_create` 出来的事件集合，随它监视的 socket 增长 |
| 280 | `anon-inode/inotify` | inotify 监视 | `anon_inode:inotify` | `inotify_init` 的监视集，一个集合一个 fd |
| 280 | `anon-inode/timerfd` | 定时器 | `anon_inode:timerfd` | 只涨不落 = 定时器建了没关 |
| 280 | `anon-inode/eventfd` | 事件计数 | `anon_inode:eventfd` | 线程/进程间唤醒用 |
| 280 | `anon-inode/signalfd` | 信号队列 | `anon_inode:signalfd` | 把信号变成可读事件 |
| 280 | `anon-inode/io_uring` | io_uring 环 | `anon_inode:io_uring` | 提交/完成环 |
| 240 | `anon-inode` | 其他匿名 inode | 其余 `anon_inode:` | 内核给了名字，但没有更准确的说法 |
| 200 | `socket` | socket | kind = socket | `/proc` 只记录 inode，不记录对端 |
| 190 | `pipe` | 管道 | kind = pipe | 只涨不落通常意味着读端停了 |
| 180 | `terminal` | 终端 | `/dev/pts/*`、`/dev/tty*` | 正常一个进程一个，涨了值得看 |
| 175 | `null-device` | 丢弃设备 | 路径**恰好**是 `/dev/null` | 打开它只占描述符，不占资源 |
| 165 | `device` | 设备节点 | 其余 kind = device | `/dev/null` 与 tty 之外的字符/块设备 |
| 150 | `log-file` | 日志文件 | `.log` 后缀，或目录段为 `log`/`logs` | 只涨不落 = 轮转或回收没跟上 |
| 145 | `shared-memory` | 共享内存文件 | `/dev/shm/*` | tmpfs 对象，最后一个持有者关闭前一直占内存 |
| 140 | `temp-file` | 临时文件 | `/tmp/*`、`/var/tmp/*` | 打开了没关的暂存文件 |

命中不了任何规则时，输出的是 **`no rule matched`** 加一句原因，不是空白列。
空白列在泄漏报告里会被读成「这里没问题」，而那正是唯一确定错误的读法。

## 阶梯为什么是这个顺序

同一句话要能回答「先看哪一条」。四个维度，从强到弱：

1. **后果** > 一切。`deleted:` 说明磁盘空间被钉住了，这是唯一能立刻动手的事，
   所以它压过「这个路径原来是干什么的」。
2. **身份** > 路径推断。socket / pipe / 内核命名的 anon inode 是内核自己说的，
   比任何从路径猜出来的都硬。
3. **角色** > 位置。`/tmp/worker.log` 同时是「日志」和「临时文件」，报「日志」：
   `.log` 约束的是这个名字是什么，`/tmp` 只约束它在哪。
4. **位置** 只描述位置。

这几个关系都有断言守着（`TestBuiltinRulesAreOrderedFromSpecificToGeneral`、
`TestOneFingerprintYieldsOneCategory`），不是靠注释维持的。

## 覆盖率：分增长，不分责任

报告里的 `attribution` 是**按类别聚合**的，每行带 `coverage`
（该类别占本次泄漏增长的比例）。

分母是窗口内**每个涨了的指纹的净增长之和**，与 `totals` 行里那个
「总量涨了多少」是同一个量。断言在 `TestJudgeAttributesLeakedSeries`：
分解出来的增长之和必须等于进程总量的增长，否则说明用了第二套「增长」定义。

⚠️ 两个容易读错的点：

- **覆盖率不是责任比例。** 一个进程整体被判泄漏时，里面一个正常预热完成的连接池
  也占它的份额。哪个**单个资源**是真泄漏，看每个 series 自己的 verdict。
- **不要求每个 series 自己过泄漏门槛。** 最常见的真实形状是一百个不同路径各涨 1：
  总量在泄漏，每个 series 都只是一次脉冲，「哪个 series 泄漏」无解，
  但「哪一类在涨」有精确答案。要求逐 series 定罪，这种形状会一个字都报不出来。

不泄漏的运行**不产出** `attribution`（不是产出空数组）：
`"attribution": []` 会被读成「归因了，没问题」。

## 配置：`--attr-rules <file>`

用户规则叠加在内置规则之上，且优先于内置规则（优先级从 1000 起）：
写规则的动机就是「内置的答案不是我要的」，输给内置会让这个文件失去意义。

```json
{
  "version": 1,
  "rules": [
    {
      "name": "wal-segment",
      "category": "postgres WAL 段",
      "why": "pg_wal 下的文件：一段一个，只涨不落说明段没被回收",
      "path_contains": ["pg_wal"],
      "path_suffix": [".wal"],
      "priority": 0
    }
  ]
}
```

可用谓词：`kind`、`scheme`、`path_prefix`、`path_suffix`、`path_contains`、`deleted`。
**所有写出来的谓词必须同时成立**；同一个谓词里的多个值是「或」。
一个谓词都不写会被拒绝 —— 它匹配所有指纹，会把整份报告吞进一个类别。

`deleted` 是三态的：不写 ≠ 写 `false`。写成 `false` 的规则不会命中已删除文件。

### 严格性清单（全部非零退出 + 指明第几行）

| 情况 | 为什么必须报错 |
|---|---|
| JSON 语法错误 | 定位到那一行，而不是让人通读整个文件 |
| 未知字段（如 `path_prefx`） | 静默忽略会得到「我加了规则却没生效」这种无解的谜 |
| 一个谓词都没有 | 会吞掉全部指纹 |
| 未知 `kind`（如 `directory`） | 这类值永远不会出现，规则永不触发 |
| `rules` 为空数组 | 写了等于没写 |
| `version` 不是 1 | 拒绝按旧含义解释新格式 |
| 缺 `name` / `category` / `why` | 报告里会出现无法定位、无法解释的行 |

规则文件在**采样开始之前**读取。读失败立刻退出（exit 1，不是 2）：
配置错了是「没能测量」，不是「测出了泄漏」。

## 明确不做（都实际验证过前提）

| 不做 | 原因 |
|---|---|
| 目录 fd 归类 | `readlink` 对目录和普通文件输出**完全同形**（容器里实测：`/tmp/dirprobe` 与 `/etc/hostname` 都是纯路径、无后缀）。要区分只能 `stat`，那会让归因依赖采样之外的世界状态，且已删除文件根本 stat 不到。与其写一条永不触发的规则，不如写明不做 |
| 「deleted 且可写」 | 可写性来自 `fdinfo` 的 flags，**指纹里没有**。L1 只用指纹，所以只能报「已删除但仍被持有」这个后果，不报「可写」这个属性 |
| 用子串匹配 `log` | `strings.Contains(path, "log")` 会把 `/var/lib/catalog/index` 判成日志。规则用 `.log` 后缀或 `log`/`logs` **整段目录名**，理由与反例都写在 `looksLikeLog` 的注释里 |
| 任何「可能是 X 打开的」措辞 | 那是 L2/L3 的地盘，而且必须带强度标注。`TestReasonsContainNoGuesswork` 用禁词表守着这一条 —— 行为测试抓不到措辞，所以措辞也要有测试 |

## L1 与 L2 的强度差别

| | L1（本文件） | L2（`internal/correlate`） |
|---|---|---|
| 输入 | 指纹本身（scheme / kind / path / deleted） | 同一窗口内的进程级读数（threads / syscr / syscw / rss） |
| 说的话 | 「这类资源是什么」 | 「增长开始时，这个计数器也在动」 |
| 强度 | `high`，恒定为可证明的复述 | `low` / `medium` / `high`，只描述窗口里有多少个样本读到了值 |
| 能否说「谁」 | 不能，也不暗示 | **更不能**。note 里明写「不是关于谁打开的结论」 |
| 反向条件 | 该不报的不报（未泄漏的 series 不带归因） | 计数器没动、读不到、样本不足，都不产出 |
| 相关测试 | `TestReasonsContainNoGuesswork` | `TestNotesCarryNoCausalLanguage`（禁词表加了 `caused` / `because` / `due to`） |

一句话的分界线：**L1 复述证据，L2 报时间上的巧合**。两者都绝不能滑到
「所以是它干的」—— 那是三层里唯一永远不会有的结论，因为 `/proc` 不提供。

## 与 L3 的边界

- L3（Day 9，未实现）：测试期 `runtime.Stack` 与 fd 变化的**采样配对**，
  采样不到就说采样不到。

三层的字段与标签是同一套，读者不需要知道实现细节就能判断一句话有多硬。
