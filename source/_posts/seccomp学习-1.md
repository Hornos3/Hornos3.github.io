---
title: seccomp学习 (1)
date: 2023-10-29 15:20:25
categories:
- 学习笔记
- seccomp 系列
---

今天打了ACTF-2023，惊呼已经不认识seccomp了，在被一道盲打题折磨了一整天之后，实在是不想面向题目高强度学习了。但是seccomp这个东西必然是要系统性的重学一遍了，绝不能把知识面仅限于orw。

学习目标：了解seccomp的保护原理，掌握常用的seccomp绕过姿势，学会手写seccomp BPF指令等。

# 0x01. seccomp规则添加原理

说到seccomp，都知道它是用来限制进程的系统调用的，但是对于Linux系统而言，有这么多的进程，seccomp又是如何精准拦截定义了规则的进程中调用的非法的系统调用呢？

这就又不得不进入一个令人不适的环节了——Linux源代码阅读。

在目前使用的Linux系统中，有两个系统调用与seccomp有关，一个是`prctl`，另一个是`seccomp`，系统调用号分别为157和317，对应的内核函数为`sys_prctl`和`sys_seccomp`：

```c
SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
			 void __user *, uargs)
{
	return do_seccomp(op, flags, uargs);
}
```

```c
SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
		unsigned long, arg4, unsigned long, arg5)
{
    ...
    switch (option) {
        ...
        case PR_GET_SECCOMP:
            error = prctl_get_seccomp();
            break;
        case PR_SET_SECCOMP:
            error = prctl_set_seccomp(arg2, (char __user *)arg3);
            break;
        ...
    }
    ...
}

long prctl_set_seccomp(unsigned long seccomp_mode, void __user *filter)
{
	unsigned int op;
	void __user *uargs;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}

	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}
```

可以看到，如果将`prctl`系统调用的第一个参数设置为`PR_SET_SECCOMP`，最终调用的与`sys_seccomp`相同，都是`do_seccomp`。这也是设置`seccomp`规则的入口函数。

```c
/* Common entry point for both prctl and syscall. */
static long do_seccomp(unsigned int op, unsigned int flags,
		       void __user *uargs)
{
	switch (op) {
	case SECCOMP_SET_MODE_STRICT:
		if (flags != 0 || uargs != NULL)
			return -EINVAL;
		return seccomp_set_mode_strict();
	case SECCOMP_SET_MODE_FILTER:
		return seccomp_set_mode_filter(flags, uargs);
	case SECCOMP_GET_ACTION_AVAIL:
		if (flags != 0)
			return -EINVAL;

		return seccomp_get_action_avail(uargs);
	case SECCOMP_GET_NOTIF_SIZES:
		if (flags != 0)
			return -EINVAL;

		return seccomp_get_notif_sizes(uargs);
	default:
		return -EINVAL;
	}
}
```

上面就是`do_seccomp`函数的定义。我们要重点关注的是前面两个switch分支，一个是`SECCOMP_SET_MODE_STRICT`

## A. 默认规则

添加默认规则的逻辑在`seccomp_set_mode_strict`中实现：

```c
static long seccomp_set_mode_strict(void)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_STRICT;
	long ret = -EINVAL;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

#ifdef TIF_NOTSC
	disable_TSC();
#endif
	seccomp_assign_mode(current, seccomp_mode, 0);
	ret = 0;

out:
	spin_unlock_irq(&current->sighand->siglock);

	return ret;
}

static inline bool seccomp_may_assign_mode(unsigned long seccomp_mode)
{
	assert_spin_locked(&current->sighand->siglock);

	if (current->seccomp.mode && current->seccomp.mode != seccomp_mode)
		return false;

	return true;
}

#define SECCOMP_MODE_STRICT 0
#define SECCOMP_MODE_FILTER 1
```

函数中的`current`是一个`task_struct`实例，表示当前内核进程。在加锁之后，调用了一个`seccomp_may_assign_mode`函数用于判断。从这个判断函数可以发现，当我们使用BPF定义规则（此时mode为`SECCOMP_MODE_FILTER`）时，就不能再切换成严格模式了，否则该函数返回`false`，直接跳过了规则修改流程。

随后进入主要的规则添加逻辑`seccomp_assign_mode`函数：

```c
static inline void seccomp_assign_mode(struct task_struct *task,
				       unsigned long seccomp_mode,
				       unsigned long flags)
{
	assert_spin_locked(&task->sighand->siglock);

	task->seccomp.mode = seccomp_mode;
	/*
	 * Make sure SYSCALL_WORK_SECCOMP cannot be set before the mode (and
	 * filter) is set.
	 */
	smp_mb__before_atomic();
	/* Assume default seccomp processes want spec flaw mitigation. */
	if ((flags & SECCOMP_FILTER_FLAG_SPEC_ALLOW) == 0)
		arch_seccomp_spec_mitigate(task);
	set_task_syscall_work(task, SECCOMP);
}

/* Valid flags for SECCOMP_SET_MODE_FILTER */
#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
/* Received notifications wait in killable state (only respond to fatal signals) */
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV	(1UL << 5)

#define set_task_syscall_work(t, fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
	
enum syscall_work_bit {
	SYSCALL_WORK_BIT_SECCOMP,
	SYSCALL_WORK_BIT_SYSCALL_TRACEPOINT,
	SYSCALL_WORK_BIT_SYSCALL_TRACE,
	SYSCALL_WORK_BIT_SYSCALL_EMU,
	SYSCALL_WORK_BIT_SYSCALL_AUDIT,
	SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH,
	SYSCALL_WORK_BIT_SYSCALL_EXIT_TRAP,
};
```

在这个函数之中，设置了当前进程的`mode`，随后出现了一个判断，判断成功时执行`arch_seccomp_spec_mitigate`函数。这个函数的内部逻辑比较复杂，先略过。最后调用`set_task_syscall_work`，这是一个宏定义，定义如上所示，就是设置一个位，表示这个线程已经开启了seccomp检查。

## B. 自定义规则

对于自定义规则而言，添加的过程要复杂许多。

```c
static long seccomp_set_mode_filter(unsigned int flags,
				    const char __user *filter)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_FILTER;
	struct seccomp_filter *prepared = NULL;
	long ret = -EINVAL;
	int listener = -1;
	struct file *listener_f = NULL;

	/* Validate flags. */
	if (flags & ~SECCOMP_FILTER_FLAG_MASK)
		return -EINVAL;

	/*
	 * In the successful case, NEW_LISTENER returns the new listener fd.
	 * But in the failure case, TSYNC returns the thread that died. If you
	 * combine these two flags, there's no way to tell whether something
	 * succeeded or failed. So, let's disallow this combination if the user
	 * has not explicitly requested no errors from TSYNC.
	 */
	if ((flags & SECCOMP_FILTER_FLAG_TSYNC) &&
	    (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) &&
	    ((flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH) == 0))
		return -EINVAL;

	/*
	 * The SECCOMP_FILTER_FLAG_WAIT_KILLABLE_SENT flag doesn't make sense
	 * without the SECCOMP_FILTER_FLAG_NEW_LISTENER flag.
	 */
	if ((flags & SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV) &&
	    ((flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) == 0))
		return -EINVAL;

	/* Prepare the new filter before holding any locks. */
	prepared = seccomp_prepare_user_filter(filter);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);

	if (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
		listener = get_unused_fd_flags(O_CLOEXEC);
		if (listener < 0) {
			ret = listener;
			goto out_free;
		}

		listener_f = init_listener(prepared);
		if (IS_ERR(listener_f)) {
			put_unused_fd(listener);
			ret = PTR_ERR(listener_f);
			goto out_free;
		}
	}

	/*
	 * Make sure we cannot change seccomp or nnp state via TSYNC
	 * while another thread is in the middle of calling exec.
	 */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC &&
	    mutex_lock_killable(&current->signal->cred_guard_mutex))
		goto out_put_fd;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

	if (has_duplicate_listener(prepared)) {
		ret = -EBUSY;
		goto out;
	}

	ret = seccomp_attach_filter(flags, prepared);
	if (ret)
		goto out;
	/* Do not free the successfully attached filter. */
	prepared = NULL;

	seccomp_assign_mode(current, seccomp_mode, flags);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		mutex_unlock(&current->signal->cred_guard_mutex);
out_put_fd:
	if (flags & SECCOMP_FILTER_FLAG_NEW_LISTENER) {
		if (ret) {
			listener_f->private_data = NULL;
			fput(listener_f);
			put_unused_fd(listener);
			seccomp_notify_detach(prepared);
		} else {
			fd_install(listener, listener_f);
			ret = listener;
		}
	}
out_free:
	seccomp_filter_free(prepared);
	return ret;
}
```

函数中有很多的判断条件，当这些判断条件不满足时，会直接返回一个错误值。需要注意的是`flags & ~SECCOMP_FILTER_FLAG_MASK = 0`，也就是`flags`除了最低6位其他位必须全为0。

通过3个判断之后，调用了`seccomp_prepare_user_filter`函数初始化`struct seccomp_filter`结构体实例。

```c
struct seccomp_filter {
	refcount_t refs;
	refcount_t users;
	bool log;
	bool wait_killable_recv;
	struct action_cache cache;
	struct seccomp_filter *prev;
	struct bpf_prog *prog;
	struct notification *notif;
	struct mutex notify_lock;
	wait_queue_head_t wqh;
};

static struct seccomp_filter *
seccomp_prepare_user_filter(const char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);

#ifdef CONFIG_COMPAT
	if (in_compat_syscall()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter __user *filter;
};

struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};
```

从上面的结构体定义和函数定义可以看出，我们传入的用户态指针需要是`sock_fprog`结构体实例，Linux中定义了一个seccomp规则的最大长度为4096，即len必须位于(0,4096]，上面的`sock_filter`可以理解为seccomp沙箱的一条“指令”。在`seccomp_prepare_user_filter`中也有一些检查，通过返回值我们就可以知道是针对什么的检查，后面两个是`EACCES`和`ENOMEM`，一个是权限相关，一个是内存不够，一般都不会发生。随后就是将用户传递的过滤器中的内容保存到`seccomp_filter`实例中返回。

初始化`seccomp_filter`完成后，我们先略过后面对一些flags的特殊处理，判断了一下是否能够加载规则，随后调用了`seccomp_attach_filter`，主要是处理已有的flags，随后将新的filter规则添加到头部的位置，使用`prev`属性连接成一个单链表，如下所示。

```c
static long seccomp_attach_filter(unsigned int flags,
				  struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;

	assert_spin_locked(&current->sighand->siglock);

	/* Validate resulting filter length. */
	total_insns = filter->prog->len;
	for (walker = current->seccomp.filter; walker; walker = walker->prev)
		total_insns += walker->prog->len + 4;  /* 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;

	...

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	seccomp_cache_prepare(filter);
	current->seccomp.filter = filter;
	atomic_inc(&current->seccomp.filter_count);

	/* Now that the new filter is in place, synchronize to all threads. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		seccomp_sync_threads(flags);

	return 0;
}
```

以上就是过滤器添加的大致流程。

# 0x02. seccomp沙箱“指令”格式

seccomp沙箱的每一条指令的长度都是8字节，分为4个字段——code、jt、jf、k。

```c
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};
```

在Linux中定义了一些方便编写seccomp code的宏定义（code含义定义在 `/include/uapi/linux/bpf_common.h` 中），这里引用[资料](https://bbs.kanxue.com/thread-273495.htm#msg_header_h1_2)中的注释便于理解：

```c
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/* Instruction classes */                    
#define BPF_CLASS(code) ((code) & 0x07)    //指定操作的类别
#define        BPF_LD        0x00               //将值复制到累加器中
#define        BPF_LDX        0x01               //将值加载到索引寄存器中
#define        BPF_ST        0x02               //将累加器中的值存到暂存器
#define        BPF_STX        0x03               //将索引寄存器的值存储在暂存器中
#define        BPF_ALU        0x04               //用索引寄存器或常数作为操作数在累加器上执行算数或逻辑运算
#define        BPF_JMP        0x05               //跳转
#define        BPF_RET        0x06               //返回
#define        BPF_MISC        0x07           // 其他类别
 
/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define        BPF_W        0x00 /* 32-bit */       //字
#define        BPF_H        0x08 /* 16-bit */       //半字
#define        BPF_B        0x10 /*  8-bit */       //字节
/* eBPF        BPF_DW        0x18    64-bit */       //双字
#define BPF_MODE(code)  ((code) & 0xe0)
#define        BPF_IMM        0x00                  //常数 
#define        BPF_ABS        0x20                  //固定偏移量的数据包数据(绝对偏移)
#define        BPF_IND        0x40                  //可变偏移量的数据包数据(相对偏移)
#define        BPF_MEM        0x60                  //暂存器中的一个字
#define        BPF_LEN        0x80                  //数据包长度
#define        BPF_MSH        0xa0
 
/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)       //当操作码类型为ALU时，指定具体运算符   
#define        BPF_ADD        0x00        
#define        BPF_SUB        0x10
#define        BPF_MUL        0x20
#define        BPF_DIV        0x30
#define        BPF_OR        0x40
#define        BPF_AND        0x50
#define        BPF_LSH        0x60
#define        BPF_RSH        0x70
#define        BPF_NEG        0x80
#define        BPF_MOD        0x90
#define        BPF_XOR        0xa0
                                               //当操作码是jmp时指定跳转类型
#define        BPF_JA        0x00
#define        BPF_JEQ        0x10
#define        BPF_JGT        0x20
#define        BPF_JGE        0x30
#define        BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define        BPF_K        0x00                    //常数
#define        BPF_X        0x08                    //索引寄存器
```

在笔者查资料的时候，发现这个BPF不仅能用来编写seccomp规则，它更像是一个较为成熟的汇编语言+胶水语言，并在2014年就拥有了自己的执行引擎eBPF。这又是一个完全的知识体系。

网络上针对BPF大多是通过C等进行编译获得BPF代码，但对于seccomp而言，我们要做的是直接编写BPF code。但专用于seccomp的BPF除了通用的BPF语法之外，还有一些额外的定义：

```c
/*
 * All BPF programs must return a 32-bit value.
 * The bottom 16-bits are for optional return data.
 * The upper 16-bits are ordered from least permissive values to most,
 * as a signed value (so 0x8000000 is negative).
 *
 * The ordering ensures that a min_t() over composed return values always
 * selects the least permissive choice.
 */
#define SECCOMP_RET_KILL_PROCESS 0x80000000U /* kill the process */
#define SECCOMP_RET_KILL_THREAD	 0x00000000U /* kill the thread */
#define SECCOMP_RET_KILL	 SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP	 0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	 0x00050000U /* returns an errno */
#define SECCOMP_RET_USER_NOTIF	 0x7fc00000U /* notifies userspace */
#define SECCOMP_RET_TRACE	 0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_LOG		 0x7ffc0000U /* allow after logging */
#define SECCOMP_RET_ALLOW	 0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION_FULL	0xffff0000U
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU
```

上面定义了seccomp BPF的返回值，从注释可知，返回值的低16bit用于传递其他数据，高16bit用于传递返回值的优先级。当一个系统调用匹配了多个seccomp规则时，会优先使用优先级高的返回值，这里从`SECCOMP_RET_KILL_PROCESS`的优先级最高，`SECCOMP_RET_ALLOW`最低，如果一个系统调用匹配了两个规则，返回值分别为`SECCOMP_RET_KILL`和`SECCOMP_RET_ALLOW`，那么最终将会选择`SECCOMP_RET_KILL`作为返回值，即杀死触发这个系统调用的线程。

```c
/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};
```

上面这段代码定义了一些编写seccomp BPF code可能会用到的东西，根据注释可知，我们可以在BPF code中获取该系统调用的：系统调用号、处理器架构、指令地址、6个参数的值。具体选择获取什么通过字段k来决定，k相当于`seccomp_data`结构体的偏移量，若指定`k=0`，则为获取`nr`，即系统调用号，若`k=4`，则为获取处理器架构等。

我们以一个实例对seccomp BPF code进行理解，尝试通过机器码恢复code本身。

```ebpf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  LD | ABS | Word, R0 = arch
 0001: 0x15 0x00 0x19 0xc000003e  JMP | JEQ after 0x19, R0 == AUDIT_ARCH_X86_64 ?
 0002: 0x20 0x00 0x00 0x00000000  LD | ABS | Word, R0 = nr
 0003: 0x35 0x00 0x01 0x40000000  JMP | JGE after 0x01, R0 >= 0x40000000 ?
 0004: 0x15 0x00 0x16 0xffffffff  JMP | JEQ after 0x16, R0 == 0xFFFFFFFF ?
 0005: 0x15 0x15 0x00 0x00000000  JMP | JEQ after 0x15, R0 == 0 ?
 0006: 0x15 0x14 0x00 0x00000001  JMP | JEQ after 0x14, R0 == 1 ?
 0007: 0x15 0x13 0x00 0x00000002  JMP | JEQ after 0x13, R0 == 2 ?
 ...
 0026: 0x06 0x00 0x00 0x7fff0000  return SECCOMP_RET_ALLOW
 0027: 0x06 0x00 0x00 0x00000000  return SECCOMP_RET_KILL
```

注意第二行的K字段，这里的K指的是`AUDIT_ARCH_X86_64`，定义于`/include/uapi/linux/audit.h`，其中为所有架构都定义了独特的标识符，而0xc000003e则是`AUDIT_ARCH_X86_64`的值。对于整个seccomp code而言，可能需要的外部数据也就只有`seccomp_data`了。

下面，我们就来通过一些具体的程序示例巩固一下我们的学习成果，使用seccomp BPF code完成自定义的filter规则。

## 实例

### Task 01

实现seccomp BPF filter，过滤x86-64之外所有架构的所有系统调用，过滤execve。

实现代码：
```c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <stddef.h>

int main(){
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ, AUDIT_ARCH_X86_64, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_STMT(BPF_ALU | BPF_K | BPF_SUB, 59),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 0, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    system("echo HELLO");
}
```

上述代码实现了对处理器架构与execve的检查，使用了一个`ALU`类型指令将系统调用号减去59，随后与0相比较。

对于seccomp BPF code而言，使用一个寄存器实际上已经足够了，对于多个返回值，我们可以在BPF code的最后几行进行统一定义，在编写前面的代码时，由于跳转指令的数量不确定，有时可能需要预留跳转数，在code编写完成后再进行计算。而对于seccomp的多个检查，我们完全可以将code除了返回之外的所有代码分片看待，每一片都进行一个检查，不同分片之间互不影响，每个分片中只使用一个寄存器即可完成检查，因此总的seccomp BPF code也只需要一个寄存器即可实现，这就使得我们不需要了解所有的BPF指令即可完美编写seccomp BPF filter。

在加载seccomp规则之前，代码中还执行了一次`prctl`。这里引用[参考资料](https://bbs.kanxue.com/thread-273495.htm#msg_header_h1_2)：

> PR_SET_NO_NEW_PRIVS()：是在Linux 3.5 之后引入的特性，当一个进程或者子进程设置了PR_SET_NO_NEW_PRIVS 属性,则其不能访问一些无法共享的操作，如setuid、chroot等。配置seccomp-BPF的程序必须拥有Capabilities 中 的CAP_SYS_ADMIN，或者程序已经定义了no_new_privs属性。 若不这样做 非 root 用户使用该程序时 seccomp保护将会失效，设置了 PR_SET_NO_NEW_PRIVS 位后能保证 seccomp 对所有用户都能起作用

### Task 02

实现seccomp BPF filter，过滤x86-64之外所有架构的所有系统调用，不允许第一个参数为3的read系统调用。

实现代码：
```c
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <stddef.h>
#include <fcntl.h>

int main(){
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ, AUDIT_ARCH_X86_64, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 0, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 3, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(struct sock_filter)),
        .filter = filter,
    };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    int fd = open("/bin/ls", 0);
    char buffer[8];
    printf("%d\n", fd);
    read(fd, buffer, 8);
}
```

注意`BPF_JUMP`宏定义的使用，后面的2个参数分别表示条件成立时跳过前面几条指令，条件不成立时跳过前面几条指令。在上面的代码中，首先判断处理器架构，如果不是x86_64则跳转到`KILL`，随后首先判断系统调用号是不是3，不是则跳转到`ALLOW`，是则继续执行，判断第一个参数是不是3，如果是则跳转到`KILL`。

# 0x03. 总结

本文简要分析了seccomp添加规则的流程，以及seccomp BPF的编写方法。

在后面的文章中，我们将尝试尽可能分析CTF pwn题中所有与seccomp有关的绕过姿势，并通过具体的示例进行学习。