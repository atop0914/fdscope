# `/proc` 字段参考

fdscope 只读 `/proc`，不 ptrace、不要求特权。本文列出它具体读了哪些字段、
每个字段的语义与陷阱。**判断「fdscope 能做什么」应以本文为准，
而不是以某个 Linux 版本的印象为准。**

## 1. `/proc/<pid>/fd/` — 描述符目录

一个目录，每个 fd 对应一个符号链接，名字是 fd 数字。

```console
$ ls -l /proc/1/fd | head -4
lr-x------ 1 root root 64 Oct 22 02:47 0 -> /dev/null
lrwx------ 1 root root 64 Oct 22 02:47 1 -> 'socket:[12345]'
lrwx------ 1 root root 64 Oct 22 02:47 2 -> 'pipe:[67890]'
```

**语义**：`readlink` 的结果就是 fdscope 的输入。

**陷阱**：

- 目录里的名字**只有数字**。读到非数字名（某些工具会造这样的东西）必须跳过，
  否则会把不是 fd 的项算进总数。
- fd 数字是整数，排序必须按数值。按字符串排会让 `10` 排在 `2` 前面 ——
  报告看起来很机械地「对」，但顺序是错的，而顺序错在对比快照时会误导人。
- 读目录与读链接之间 fd 可能已被关闭。`ENOENT` 在这里是**正常抖动**，
  不能算作「快照不完整」；只有 `EACCES` 才算读不到。

## 2. `/proc/<pid>/fdinfo/<n>` — 每个 fd 的详细信息

```console
$ cat /proc/1/fdinfo/0
pos:	0
flags:	0100002
mnt_id:	27
ino:	5
```

**fdscope 用到的字段**：

| 字段 | 含义 | 用途 |
|------|------|------|
| `pos` | 当前读写偏移（十进制） | 辅助：长期停在 0 的写文件可能从未被写过 |
| `flags` | 打开标志（**八进制**） | 辅助：区分只读/只写/追加 |
| `mnt_id` | 挂载点 id | 暂未使用 |
| `ino` | inode | **刻意不用**：inode 是实例 id，不是资源 id（见 [design.md](design.md)） |

**陷阱**：

- `flags` 是**八进制**，`0100002` 是 `O_LARGEFILE|O_RDWR`。按十进制解析会得到错误的标志位。
- 不同 fd 类型打印的字段不同（socket 没有 `pos`）。**缺字段不是错误**，
  留零值即可，不要因为解析不到就判失败。
- 该文件可能读失败（进程在同一瞬间退出、或权限不足）。fdscope 静默降级为
  零值，**不影响 fd 计数本身** —— 计数来自目录项，不依赖 fdinfo。

## 3. `/proc/<pid>/limits` — 资源上限

```console
$ grep "open files" /proc/1/limits
Max open files            1048576              1048576              files
```

两列分别是 **soft limit** 与 **hard limit**。

**fdscope 用 soft limit**，因为进程实际撞到的是它。

**陷阱（这一条很容易搞错）**：

- 拿 hard limit 会得出「还有 100 万个余量」，而进程在 soft limit 处就已经 `EMFILE` 了。
- 行格式由内核固定宽度打印，但**用 `strings.Fields` 按空白切分比按列位置切分稳**。
- 文件读不到时（容器限制、隐藏）返回 `0`。**调用方必须把 0 当「未知」，
  不能当「无限」** —— 「未知」与「无限」对风险的结论完全相反。
- soft limit 可以被**运行中**的进程下调。此时 `Used` 可能大于 `Limit`，
  余量会算出负数。这不是 bug，是真实状态，必须如实显示。

## 4. 为什么不用 `/proc/<pid>/exe`、`/proc/<pid>/maps`

- `exe` / `maps` 能告诉你二进制与内存映射，与「fd 泄漏」无关
- `maps` 里的文件映射**不占 fd**（映射建立后 fd 就可以关），
  把两者混起来是一个非常容易犯、且很难自察的错

## 5. 跨进程读取的权限

读 `/proc/<pid>/fd` 需要与目标进程**同用户**，或有 `CAP_SYS_PTRACE`。
否则 `readlink` 返回 `EACCES`。

fdscope 在这种情况下返回 `ErrPermission` 而不是空快照 —— 因为
「无权限」和「没有 fd」在数字上都是 0，混淆会让审计**静默通过**。

常见场景：容器里以非 root 跑 fdscope 去看 root 进程，会拿到权限错误。
这不是工具的问题，是权限模型的问题，错误信息会直说。

## 6. PID namespace 的坐标问题

在容器里跑 fdscope，看到的 pid 是**容器内的**；在宿主机上看同一个进程，
pid 是**宿主机的**。两者不自动对应，fdscope 也不做自动转换
（做这件事需要读 `/proc/<pid>/status` 的 `NSpid` 字段，属于后续工作）。

当前行为：你给它什么 pid，它就按那个 pid 去 `/proc/<pid>` 找。
**用错的 pid 会看到错的过程**，这是调用方的责任。
