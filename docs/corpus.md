# 真实语料回归：三个外部项目里的 fd 缺陷

前九天的所有判定语料都是自己写的。自己写的场景有一个共同的毛病：
它们会不自觉地把工具设计成「刚好能测出来」——写夹具的人已经知道判据在哪，
于是路径数、增长速率、回落形状都落在判据想看到的位置上。

这一天换一个方向：拿**别人项目里真实存在**的 fd 生命周期缺陷，
按模式重写成可以跑的程序，再问 fdscope 同一个问题。

三条缺陷全部来自 **nutsdb** 的
[internal/fileio/fd_manager.go](https://github.com/nutsdb/nutsdb/blob/master/internal/fileio/fd_manager.go)，
是调研阶段挖到并在容器里实测复现过的。**没有一行代码是拷贝来的**：
该仓库没有被 import，也不可能被 import（`go.mod` 只有标准库，CI 有闸门）。

## 1. 三个缺陷的出处

| 夹具 | 上游位置 | 缺陷 | 实测现象 |
|------|----------|------|----------|
| `testdata/corpus/fdlistdrift` | `doubleLinkedList.removeNode` + `FdManager.GetFd` | 链表移除节点时**不递减自己的 `size`**；`GetFd` 又把 `size >= maxFdNums` 当成「缓存满了」，于是新开的 fd **不入缓存就返回**给调用方 | 链表计数永久停在满值，缓存从此认为自己是满的，之后每开一个文件就丢一个没人关的 fd（原实现观测到：Cache 只剩 2 个，`list.size` 仍是 10） |
| `testdata/corpus/usingunderflow` | `FdManager.ReduceUsing` | `using` 是 `uint`，`node.using--` 没有下界保护 | 同一 path 释放两次 → `using` 下溢到 `18446744073709551615` → entry 永远「在用」，`cleanUselessFd` 永远跳过它，fd 永久不可回收 |
| `testdata/corpus/panicunknown` | `FdManager.ReduceUsing` | cache 里找不到该 path 时**直接 panic**：`unexpected the node is not in cache` | 一次不该发生的释放让整个进程在窗口中间消失 |

每个夹具都带 `-fixed`：**同一份代码**，只改掉那一处记账（`size--` / `using > 0` 守卫 /
返回错误而不 panic）。这是这一天的证据形态——同速率、同资源、同样的代码形状，
只差一个语句。只追加一个「正确版本」而不控制变量，等于什么都没证明。

## 2. 怎么跑

```bash
# 三个真程序 + 真判定
go test -count=1 -v ./internal/corpus/

# 手工跑一个（容器内）
go build -o /tmp/fx ./testdata/corpus/fdlistdrift
/tmp/fx &                       # 第一行是 "ready <工作目录>"
go build -o /tmp/fd ./cmd/fdscope
/tmp/fd check $! --interval 100ms --samples 20
```

判定的窗口固定 20 个样本 × 100ms。短是刻意的：这一天的三个缺陷都是
「每轮丢一个 fd」的形状，两秒足够看清；需要十秒才显形的形状不属于这一天的题目。

## 3. fdscope 的判定结果

以下全部是**容器内真实运行**的输出，不是手写的期望值。

### 3.1 fdlistdrift —— 判出 LEAK

```
totals: 18 23 28 33 38 43 48 53 58 63 67 72 77 82 87 92 97 102 107 112
process total: LEAK (confidence medium)
  reason: grew 89 descriptors (387%) to 112 over 1.8s and did not fall back
  GROWTH      89        (floor 10, reached 890% of it)
  RATE        48.883/s  (floor 0.050/s)
no single resource was judged a leak on its own
attribution: share of the leak by resource class
  100%  temporary file [temp-file, L1 high]  growth 94 over 94 resource(s)
exit=2
```

### 3.2 usingunderflow —— 判出 LEAK

```
process total: LEAK (confidence medium)
  reason: grew 89 descriptors (287%) to 120 over 1.8s and did not fall back
no single resource was judged a leak on its own
attribution: share of the leak by resource class
  100%  temporary file [temp-file, L1 high]  growth 95 over 95 resource(s)
exit=2
```

注意「no single resource」这行不是缺陷，是这两个缺陷的**必然形状**：
每轮打开的是一个**新**路径，每个指纹只 +1，任何单条 series 都没有趋势可言
（`internal/analyze` 里那段注释描述的正是这种形状）。能回答问题的只有
进程总量与类别分摊，两者都判对了。

### 3.3 panicunknown —— **拒绝判定**（这是正确结果）

```
fdscope: checking pid 317 stopped after 5 of 20 samples: process not found: 317
exit=1
```

这一条是整份语料里最重要的断言。进程在窗口中间 panic，内核把它持有的 fd 全部
释放；一个把「fd 集合现在是空的」当成一次采样的实现，会得出
**「泄漏已修复」**——工具的核心结论在它最该说话的时刻反转，而且输出里没有任何
异常迹象。`CheckPID` 的契约是「每次失败都是错误，永远不是结论」，
这条用真进程的死证明了（另一次跑同一用例得到的是
`process exited: pid now belongs to a zombie`，同样是错误，同样不是结论）。

### 3.4 反向：三个 `-fixed` 版本都不报

同一组程序、同一速率、同一资源，只改掉那处记账 → 三条全部 `no leak`，
且置信度不是 `none`（不是「没法判定」被当成「没问题」）。

## 4. 没判出来的，以及为什么

这一节比上面那些绿字重要。**判不出来的写清楚，不许写成「通过」。**

| 没判出来的 | 为什么 |
|------------|--------|
| 泄漏的**代码位置** | `/proc` 不记录是谁打开的 fd。报告能说的是「`/tmp` 下的临时文件在涨」（L1，可用 `readlink` 人工复核），说不出「`removeNode` 少了一行 `size--`」。这需要 ptrace，本项目明确不做 |
| **账面漂移本身** | 如果上游只让计数漂移、却没有任何 fd 真的漏掉，fdscope 一句话都不会说——它审计的是 fd，不是别人的账本。这三条之所以能判出来，是因为漂移最终变成了真实泄漏 |
| 单资源级别的指控 | 三条缺陷都每轮开新路径，每个指纹只 +1。只有进程总量与类别分摊，没有 `LEAK` 的 series。这是设计，不是退化（见上面 3.2） |
| 小泄漏 | `growth >= 10` 且 `rate >= 0.05/s`。一个只漏 5 个 fd 的进程不会被判。这是拿漏报换不误报的显式取舍，数字写死在 `DefaultLeakOptions` 里 |
| panic 场景的「死前涨了多少」 | `CheckPID` 返回错误时丢弃了已采到的 timeline。判定层面这是对的（半份证据不是结论），但读者确实拿不到「它在死之前涨了 40 个」。库调用方目前也拿不到——这是边界，不是这次要修的 bug |

**一个阈值都没改。** 这一天的纪律是「改阈值前必须先证明现有阈值在这个语料上
确实错了」；三条都判对了，所以 `DefaultLeakOptions` 一个数字没动。

## 5. 语料当天抓到的第一个真问题

判 `usingunderflow` 时，人读输出是这样的：

```
no single resource was judged a leak on its own
（然后就没有了）
```

**类别分摊被吞掉了。** 而 `internal/analyze` 里引入这个块的注释写的恰恰是：
「一百个不同路径各涨一个：进程总量在漏，每条 series 都只是脉冲，'哪条 series 漏了'
没有答案，而'哪类资源在涨'有精确答案」。

也就是说：这个块**为这种形状而生**，却在唯一的这种形状上不打印——渲染调用
写在了「有单资源被判定」的那个分支里。数据一直在报告里（`--json` 里也有），
只是人读路径不说。

已修（`e36d5dc`）：分摊块移出分支，并在测试里两个方向都钉住——
没有单资源判定时**必须**打印，没有可分摊的增长时**必须不**打印空标题。

这是这一天方法论的价值所在：这条 bug 在 304 个自造用例里活了九天，
因为自造用例里每个泄漏都会顺便让某条 series 单独被判出来。

## 6. 变异检验（6 个变异体，6 个红在目标断言）

| 变异 | 期望 | 实测 |
|------|------|------|
| 关掉 `fdlistdrift -fixed` 的 `size--` | 反向断言红 | **红**：`fdlistdrift -fixed was judged a leak` |
| 关掉 `usingunderflow -fixed` 的守卫 | 反向断言红 | **红**：`judged a leak` |
| 关掉 `panicunknown -fixed` 的错误返回 | 反向断言红 | **红**：`check: stopped after 9 of 20 samples: process exited` |
| 夹具改成成对开闭（不再泄漏） | 真实副作用断言红 | **红**：`held 1 descriptors before and 8 after ... the fixture did not leak` |
| `CheckPID` 忽略 `res.Err` | panic 用例红 | **红**：`still returned a verdict`——而且是 `Leak:true, confidence medium`，基于 5 个样本给出自信结论 |
| `attachAttribution` 直接 return | 类别断言红 | **红**：`leaking with no attribution at all` |

第五条是最值得记的：把「运行中断算错误」这一行去掉，工具不但不报错，
还会用半截数据给出一份**看起来很可信**的泄漏结论。失败方向不对称——
安静方向的那一半，只有这种变异检验才抓得住。

## 7. 一句话边界

fdscope 能说的是：**哪一类资源在涨、涨得多快、置信度如何、离 EMFILE 还有多久。**
它说不出：是谁开的、哪一行代码、以及「没漏只是账错了」。
把这句话写在这里，比把它写进宣传语重要。
