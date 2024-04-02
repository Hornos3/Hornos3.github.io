how2heap下载网址: [传送门](https://github.com/shellphish/how2heap)
Glibc源码查看网址：[传送门](https://elixir.bootlin.com/glibc/glibc-2.23/source)
参考书籍：CTF竞赛权威指南-pwn篇

测试环境：Ubuntu 16.04
Glibc版本：Ubuntu GLIBC 2.23-0ubuntu11.3

按照顺序，本文分析glibc 2_23文件夹中的第17~19个源码，这也是glibc 2.23 how2heap给出的最后3个源码。
如果本文的分析有任何错漏之处，还请各位读者不吝赐教，不胜感激。

# 17. unsafe_unlink

众所周知，unlink是一种常用的堆漏洞利用方式，最为常见的利用场景是可以进行unlink而且堆指针保存在全局变量中。（例题：XCTF攻防世界-Noleak）

这种漏洞利用方式不是借助于fastbin完成，因此需要申请较大的堆块。在源码中定义了一个全局变量chunk0_ptr，为其分配了一个大小为0x90的堆块。之后又分配了一个0x90堆块chunk1_ptr，这也是接下来被攻击的chunk。设第一个chunk的起始地址为x，全局变量的地址为y，现在的内存情况如下：

|addr|+0x0|+0x8|
|:-:|:-:|:-:|
|x|-|(size) 0x91|
|...|...|...|
|x + 0x90|-|(size) 0x91|
|...|...|...|
|y|x|-|

接下来，我们需要在chunk0_ptr的chunk中伪造一个chunk，为接下来的unlink做准备。伪造后的堆区长这样：

|addr|+0x0|+0x8|
|:-:|:-:|:-:|
|x|-|(size) 0x91|
|x+0x10|-|-|
|x+0x20|<font color=red>(fake chunk fd) y-0x18</font>|<font color=red>(fake chunk bk) y-0x10</font>|
|...|...|...|
|x+0x90|<font color=red>(fake prev size) 0x80</font>|<font color=red>(size) 0x90</font>|
|...|...|...|

注意：这里将第二个chunk的prev_in_use位修改为了0，fake prev size就是假chunk的大小，将fake prev size设为0x80是为了让后面一个chunk能够通过prev chunk找到我们构造的假chunk。fake chunk的假fd和bk指针的构造很重要，后面会用到。

接下来，我们将第二个chunk释放，释放时第二个chunk会和第一个chunk里面的假chunk合并。这样就造成了堆块的重叠。

下面解释一下为什么这之后能够进行任一地址写。

## 为什么要设置fd=y-0x18，bk=y-0x10？

这是为了绕过libc的检查。

```C
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```

在unlink的源码中有一个检查是：``__builtin_expect (FD->bk != P || BK->fd != P, 0)``。因此需要保证此chunk的fd的bk等于bk的fd等于此chunk。由于C语言按照偏移获取结构体的成员，fd的偏移为0x10，bk的偏移为0x18。在全局变量中保存的就是第一个chunk，将fd指向y-0x18，那么fd->bk就为y；将bk指向y-0x10，那么bk->fd就为y。y中保存的正好就是x，这也就成功绕过了检查。检查通过之后，heap会进行堆块的合并操作，同时修改全局变量指针的值。

因为P = x，FD = y - 0x18，BK = y - 0x10，在语句``BK->fd = FD;``执行之后，全局变量的chunk0_ptr的值就变成了y-0x18。这样，我们就可以通过chunk0_ptr对其本身进行修改，此时可将chunk0_ptr的值修改为任意值。<font color=red>注意：不要被绕晕了，这个时候，全局变量保存的不再是第一个chunk的起始地址，而是通过unlink操作被修改了，但是libc误认为这里仍然保存的是一个chunk的指针，因此可以让这个全局变量自己修改自己。</font>在源码中，将这里修改到了栈区，之后再次使用这个指针就可以修改栈区的内容了。

# 18. unsorted_bin_attack

这种攻击方式实际上在前面已经提到过，比较简单。将第一个unsorted bin chunk的bk指针修改为我们想要写的地址附近，然后把这个chunk分配回去就能够让unsorted bin head指向我们想要的地址，然后再调用malloc函数就能分配一块内存到我们想要的地址了。

# 19. unsorted_bin_into_stack

也是unsorted bin attack。首先分配两个0x110的chunk，后一个防止top chunk影响。然后释放第一个chunk。接下来在堆块中伪造一个chunk，设置size为0x110，bk为这个假堆块头。接下来是漏洞关键操作：修改第一个chunk的size和bk。程序将第一个chunk的size改小为0x20，bk改为假chunk。将size改小是为了后面分配0x100大小的堆块时能够跳过这个堆块直接分配到栈上的假chunk。

后面调用malloc函数时，首先从unsorted bin中查找到了第一个chunk。但是因为这个chunk的大小被改小了，libc判定空间不足，就将这个chunk移到了small bins中。之后检查到了假chunk并将其返回。既然chunk已经分配到了栈上，那么就可以直接修改main函数的返回地址（如果有canary可能不能直接修改）并劫持控制流。

至此，how2heap glibc 2.23的所有源码已经分析完成。之后会进行glibc 2.27源码的分析。实际上glibc 2.23和2.27的最大区别就是tcache。其他方面区别不大，因此glibc 2.27的分析可能会短很多。实际上，在分析调试how2heap源码中，有很多地方仍然没有深入到原子操作去进行。待到我的水平再上一层时可能会来解决这一部分问题。但现在，所有给出的堆漏洞已经了解其利用方法，通过做题可以加深我们对漏洞利用方式的判断与应用。谢谢。
