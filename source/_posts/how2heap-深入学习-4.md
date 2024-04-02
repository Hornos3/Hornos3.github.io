---
title: how2heap 深入学习(4)
date: 2023-02-28 22:21:37
categories:
- 学习笔记
- glibc 系列
---
how2heap下载网址: [传送门](https://github.com/shellphish/how2heap)
Glibc源码查看网址：[传送门](https://elixir.bootlin.com/glibc/glibc-2.23/source)
参考书籍：CTF竞赛权威指南-pwn篇

测试环境：Ubuntu 16.04
Glibc版本：Ubuntu GLIBC 2.23-0ubuntu11.3

本人在前几天成功进入校队，因此后面的更新应该短时间内不会中断。
按照顺序，本文分析glibc 2_23文件夹中的第12~16个源码
如果本文的分析有任何错漏之处，还请各位读者不吝赐教，不胜感激。

# 12. large_bin_attack

large_bin_attack可以用于在栈区写入一个较大的值。通常是为其他攻击方式做准备。

首先，源码在栈区定义了两个变量stack_var1和stack_var2，类型为unsigned long。之后依次分配了大小为0x430(p1), 0x20, 0x510(p2), 0x20, 0x510(p3), 0x20大小的chunk。（0x20的chunk用于防止堆块合并）

之后，释放p1和p2。此时unsorted bin的结构应为：

``unsorted bin head <-> p2 <-> p1``

然后，malloc一个0xa0大小的chunk，在此过程中，p2被转移到了large bins中，p1被切割，仍在unsorted bin中且为last_remainder。

之后，释放p3。下面是释放p3之后的堆结构。

```
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0xa1

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6030a0
Size: 0x391
fd: 0x7ffff7dd1b78
bk: 0x6039a0

Allocated chunk
Addr: 0x603430
Size: 0x30

Free chunk (largebins) | PREV_INUSE
Addr: 0x603460
Size: 0x511
fd: 0x7ffff7dd1fa8
bk: 0x7ffff7dd1fa8
fd_nextsize: 0x603460
bk_nextsize: 0x603460

Allocated chunk
Addr: 0x603970
Size: 0x30

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6039a0
Size: 0x511
fd: 0x6030a0
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603eb0
Size: 0x30

Top chunk | PREV_INUSE
Addr: 0x603ee0
Size: 0x20121
```

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x6039a0 —▸ 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6039a0
smallbins
empty
largebins
0x500: 0x603460 —▸ 0x7ffff7dd1fa8 (main_arena+1160) ◂— 0x603460 /* '`4`' */
```

之后是漏洞部分。如果我们可以修改p2的控制字段。那么下面如此操作：

将p2的size从0x511改小为0x3f1，fd和fd_nextsize改为0，bk改为``(unsigned long)(&stack_var1-2)``，bk_nextsize改为``(unsigned long)(&stack_var2-4)``，调试时stack_var1的地址为0x7fffffffe470，stack_var2的地址为0x7fffffffe478。那么(unsigned long)(&stack_var1-2)的值就为0x7fffffffe460，(unsigned long)(&stack_var2-4)的值就为0x7fffffffe458。

修改之后，堆结构如下：

```
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0xa1

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x6030a0
Size: 0x391
fd: 0x7ffff7dd1b78
bk: 0x6039a0

Allocated chunk
Addr: 0x603430
Size: 0x30

Allocated chunk | PREV_INUSE
Addr: 0x603460
Size: 0x3f1

Allocated chunk
Addr: 0x603850
Size: 0x00
```

```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x6039a0 —▸ 0x6030a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x6039a0
smallbins
empty
largebins
0x500 [corrupted]
FD: 0x603460 ◂— 0x0
BK: 0x603460 —▸ 0x7fffffffe460 ◂— 0x0
```

最后，malloc大小为0xa0的chunk，然后我们就会惊奇地发现两个栈变量的值被修改为p3的地址。

这个漏洞的利用流程就是这样，而利用的关键就是_int_malloc函数中关于large bins的处理部分。

```C
	[...]

              else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
```

由于在修改p2之后，bin的结构如图：

所以遍历时会首先遍历到p1。通过源码进行调试发现这里直接跳过了else语句而从mark_bin开始执行。victim = p1，bck = fwd = main_arena + 984，这应该是p1现在的大小所对应的应该放入的small bin的位置（此时p1大小为0x391，属于small bins范围）。经历这4步之后，p1被成功链入到一个large bin中，目前一切正常。

然后，_int_malloc会进行下一次循环，去处理p3。此时victim = p3，fwd = p2，bck = 0x7fffffffe460。这时，else语句中会被执行。内部4个语句执行完成后，p1，p2，p3和部分栈区结构如下：

|addr|+0x0|+0x8|
|:-:|:-:|:-:|
|p1|0|0x391|
|p1 + 0x10|\<small bin addr\>|\<small bin addr\>|
|...|...|...|
|p2|0|0x3f1|
|p2 + 0x10|0|0x7fffffffe460|
|p2 + 0x20|0|\<p3\>（原为0x7fffffffe458，第三步修改）|
|...|...|...|
|p3|0|0x511|
|p3 + 0x10|\<unsorted bin head\>|\<unsorted bin head\>|
|p3 + 0x20|\<p2\>（第一步修改）|0x7fffffffe458（第二步修改）|
|...|...|...|
|(stack)|stack_var1 = 0|stack_var2 = \<p3\>（第四步修改）|

可以看到，在else语句里面，stack_var2在第4步被修改。跳出else语句之后，第四条语句``bck->fd = victim;``将stack_var1成功修改为p3的地址。至此，目标地址修改完成。stack_var1和stack_var2现在的值为p3的地址。

# 13. mmap_overlapping_chunks

源码中第一句就说，这是一个应该能够在所有libc版本中利用的漏洞。

在libc中，如果用户一次性申请的内存空间过大，malloc函数不会像通常那样从堆中分配内存给用户，而是调用mmap函数为用户映射一块单独的虚拟内存使用。同样，当用户将这块空间释放时，会调用munmap函数将这块空间返还给操作系统内核。

通过mmap获取的chunk在size域的bit-1上有体现。size的bit-0，bit-1，bit-2三位是用于保存控制信息的，其中bit-1就表示该chunk是否由mmap产生。mmap chunk有prev size域，它表示mmap chunk的剩余大小（内核调用mmap函数时通常会分配一块大于用户需求的内存块）。同时mmap chunk的fd和bk指针没有意义，在free时也不会放入bins中。在释放时，mmap chunk必须是页对齐的。

首先，程序分配一个小chunk用于初始化堆空间。然后分配一块大小为0x100000的chunk，这第一块chunk的位置是在libc的加载地址之上的，后面又分配了2个相同大小的大chunk就在libc的加载地址之下了，空间分配大致如下表：

|addr|content|
|:-:|:-:|
|(high address)|first mmap chunk|
||libc|
||second mmap chunk|
|(low address)|third mmap chunk|

此时，第三个mmap chunk的prev size为0，因为申请大小本身就是页对齐的，没有剩余空间。程序输出显示，第三个mmap chunk的size为0x101002。然后，我们只需要将这个chunk的大小改大，在释放的时候就能够将第二个mmap连带着释放掉。在程序中是将第三个chunk的size改为了0x202002，正好将第二个chunk全部覆盖。这实际上就是mmap版本的UAF。但是需要注意的是，由于munmap是将这块空间直接返还给了linux内核，因此释放后直接访问这段内存会导致程序崩溃。这点与一般的free不同。因此，现在需要做的就是将这段内存要回来，让两个指针指向相同位置。

随后，第三个chunk被释放，第二个连带着被释放，接下来又分配一个大小为0x300000的chunk，这个chunk完全覆盖了第二个和第三个chunk，大小为0x301002。此时第四个chunk的初始地址比第二个chunk小0x200000，由于所有mmap chunk的类型均设定为long long，因此索引应该为0x40000，即第四个chunk下标为0x40000的地方就是第二个chunk的开头，这样就能够通过第四个chunk修改第二个chunk的值了。

实际上这个漏洞还是比较好理解的，就是修改chunk的大小让chunk重叠。

# 14. overlapping_chunks

这是一个堆块重叠产生的漏洞利用。

首先有4个指针p1~p4，前三个分别分配0x100，0x100，0x80大小的chunk，然后将p1中的所有字节设为1，p2所有字节设为2，p3所有字节设为3。

然后将p2释放，p2会链入unsorted bin中。接下来是漏洞关键步骤：修改p2的大小，将其改大为0x180，这样p3将完全被p2重叠。之后，分配0x178大小的chunk到p4，这使得p2被重新分配出来，直接从unsorted bin中弹出。后面的过程就很好理解了，由于p4完全包含p3，这使得我们可以在p4中写入数据时随意修改p3中的值。

当然，从这里看，堆块重叠只是为其他漏洞利用方式做准备。

# 15. overlapping_chunks_2

这个文件与上面的overlapping_chunks基本上相似。

首先分配5个可用大小为1000的堆块，分别为p1~p5。之后释放p4，修改p2的大小使p2正好完全覆盖p3的同时保持其prev_in_use位为1。之后释放p2会将p3这块空间连带着释放掉，再将其分配回来到p6，就可以从p6里面写入数据随意修改p3的内容了。

利用方式与overlapping_chunks相同，不再赘述。

# 16. poison_null_byte

这是一种只溢出一个字节的漏洞利用方式。前面也分析过一个类似的漏洞house_of_einherjar。与house_of_einherjar相同。这种漏洞利用也是溢出一个空字符\x00。

程序首先将堆区构造成如下的结构（barrier防止top chunk的影响）：

|addr|content|
|:-:|:-:|
|0x0|chunk a(size = 0x111)|
|...|...|
|0x110|chunk b(size = 0x211)|
|...|...|
|0x320|chunk c(size = 0x111)|
|...|...|
|0x430|barrier(size = 0x111)|

然后，将b释放，进入关键步骤：从a溢出一个字节到b的size使b的size从0x211修改为0x200。这样b的实际大小就缩小了0x10。由于需要绕过检查，我们要在b的结尾处伪造一个prev size，这与house_of_einherjar类似，具体请参考我的how2heap第一篇笔记。

|addr|content|
|:-:|:-:|
|0x0|chunk a(size = 0x111)|
|...|...|
|0x110|chunk b(size = 0x211)|
|...|...|
|0x310|fake prev_size = 0x200|
|0x318|0|
|0x320|chunk c(size = 0x111)|
|...|...|
|0x430|barrier(size = 0x111)|

之后，分配一个大小为0x110的堆块，这个堆块的起始地址将和原b的起始地址相同，且分配之后会对假prev_size进行调整，调整为0xf0。然后继续分配一个0x90大小的空间p2，p2紧跟在p1之后。此时堆空间如图：

|addr|content|
|:-:|:-:|
|0x0|chunk a(size = 0x111)|
|...|...|
|0x110|chunk b1(size = 0x111)|
|...|...|
|0x220|chunk b2(size = 0x91)|
|...|...|
|0x2b0|\<unsorted bin chunk\>(size = 0x61)|
|...|...|
|0x310|fake prev_size = 0x60|
|0x318|fake size = 0|
|0x320|chunk c(size = 0x111)|
|...|...|
|0x430|barrier(size = 0x111)|

接下来，首先释放b1，然后紧接着释放c，此时会惊奇地发现，b1和c竟然合并了。

```
Allocated chunk | PREV_INUSE
Addr: 0x603000
Size: 0x111

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603110
Size: 0x321
fd: 0x6032b0
bk: 0x7ffff7dd1b78

Allocated chunk
Addr: 0x603430
Size: 0x110

Top chunk | PREV_INUSE
Addr: 0x603540
Size: 0x20ac1
```

释放c时，_int_free检查到c的prev_size对应偏移处的chunk（b1）是一个unsorted bin free chunk，因此执行了malloc_consolidate函数将二者进行了合并，但是请注意，此时的p2仍然可以进行任意读写操作，这就导致了c完全覆盖了b2，接下来我们将c重新分配回去就可以通过向c写入数据以随意修改p2的内容。

理解该漏洞的核心是溢出一个字节的空字节究竟对堆空间有什么样的影响，溢出一个字节后，b的大小被改小，因此之后分配内存时，修改的prev size是一个假的prev size，下一个chunk真正的prev size不会被修改，这就为后面的堆块合并创造了条件，我们不需要修改后面一个chunk的prev size就能够让它与前面的堆块合并，造成堆块的重叠。
