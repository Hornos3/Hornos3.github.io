how2heap下载网址: [传送门](https://github.com/shellphish/how2heap)
Glibc源码查看网址：[传送门](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3516)
参考书籍：CTF竞赛权威指南-pwn篇

测试环境：Ubuntu 18.04
Glibc 版本：Ubuntu GLIBC 2.27-3ubuntu1.5

按照顺序，本文将分析glibc 2.27文件夹下的第7~8源码，对house_of_storm进行了深入的分析。
如果本文的分析有任何错漏之处，还请各位读者不吝赐教，不胜感激。

# 7. house_of_mind_fastbin

这是一种伪造arena以将一个大chunk中的一处值改为很大的利用方式，和glibc 2.23差别不大，但是2.23的分析感觉逻辑不是太清晰，还是再写一遍吧。

**Step 1: 分配0x1010的chunk，要改写的地址为(chunk head + 0x40)。**

这里解释一下为什么改写的是chunk head + 0x40。
这个chunk是要作为伪造的arena使用的，参考2.27的arena结构体——malloc_state如下：

```C
struct malloc_state
{
  /* Serialize access.  */
  __libc_lock_define (, mutex);

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Set if the fastbin chunks contain recently inserted free blocks.  */
  /* Note this is a bool but not all targets support atomics on booleans.  */
  int have_fastchunks;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

后面分配的是0x60大小的fastbin chunk，会被链入到这个假chunk中，而链入的地址就是chunk head + 0x40。在2.23中这个地址为0x38，2.27由于添加了一个have_fastchunks这个成员，因此地址往后移动了8字节。

<table align=center>
	<tr align=center>
		<td> addr </td> <td> 0x0 </td> <td> 0x4 </td> <td> 0x8 </td> <td> 0xC </td>
	</tr>
	<tr align=center>
		<td> 0x603420 </td> <td> mutex </td> <td> flag </td> <td> have_fastchunks </td> <td>-</td>
	</tr>
	<tr align=center>
		<td> 0x603430 </td> <td colspan=2> fastbinsY[0] (for chunk size=0x20) </td> <td colspan=2> fastbinsY[1] (for chunk size=0x30) </td>
	</tr>
	<tr align=center>
		<td> 0x603440 </td> <td colspan=2> fastbinsY[2] (for chunk size=0x40) </td> <td colspan=2> fastbinsY[3] (for chunk size=0x50)  </td>
	</tr>
	<tr align=center>
		<td> 0x603450 </td> <td colspan=2> <font color=red> fastbinsY[4] (for chunk size=0x60) </font> </td> <td colspan=2> ...... </td>
	</tr>
</table>

**Step 2: 设置假arena的system_mem为0xFFFFFF。**

system_mem标志的是这个arena管理的空间大小。在_int_malloc函数中有这么一项检查：

```C
if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
				   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
```

这个检查是在分配unsorted bin和large bins前进行的，表明请求的内存不能大于system_mem。

**Step 3: 计算假arena管理的空间位置。**

在系统堆初始化之后，将堆的大小定为0x4000000，因此后面申请的假arena管理的地址在这个堆之后。要计算这个堆的起始地址。

**Step 4: 一直分配chunk直到系统heap被占满。**

在源码中，这里一直分配大小为0x1ff00的chunk，因为mmap_threshold=0x20000，它表示当用户分配大于0x20000的空间时，就不使用堆而是直接通过mmap获取了，这种情况需要避免，因此最大分配0x1ff00的chunk。

**Step 5: 分配一个0x60的chunk在堆空间之上。**

**Step 6: 填满0x60的tcache。**

**Step 7: 修改系统heap之上的假heap的控制信息。**

```C
typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;
```

将计算得到的假heap地址的开头写入假arena的地址，即ar_ptr

**Step 8: 修改0x60 chunk的non_main_arena标志位。**

**Step 9: 释放最后一个chunk，修改假main_arena对应位置的值。**

此时，当我们free时，libc会根据_heap_info的ar_ptr找到我们的假chunk，然后在假chunk里面更改内容。这也就是我们的目的。

# 8. house_of_storm

源码要修改bss段的一个全局变量。

Tips: 如果使用gdb调试需要加上-no-pie参数去掉pie，否则后面的检查通不过。

**Step 1: 构造堆环境并进行堆风水检查。**

本漏洞利用需要的堆环境为：一个unsorted bin chunk和一个large bins chunk，且unsorted bin chunk大于large bins chunk。

首先分配0x4f0的chunk（之后将作为unsorted bin chunk），检查该chunk的地址最高非0位的值x，这里需要检查的原因在后面说明。具体检查方式：

首先判断x是否小于0x10，x小于0x10不行。

然后判断x的最低4位——bit-0~bit-3：

bit-3必须为0；
bit-2为1时bit-1不能为0；

由于要分配的大小在tcache范围，因此需要填满对应的tcache。

然后分配0x4e0的chunk，之后将作为large bins chunk。
分配一个小chunk防止top chunk合并。
随后依次释放0x4e0和0x4f0，先释放小chunk。再分配回大chunk再释放，小chunk就能顺利进入large bins。
至此，堆结构构造完成。

检查原因：因为最高非0位是作为size呈现的，因此不能小于0x10这个最小值。其次，chunk的大小应该是0x10的倍数，因此bit-3不能为1。再次，bit-2是non_main_arena标志位，bit-1是mmap标志位，这两者也不能够有一定的组合：

```C
(_int_malloc glibc 2.27 line 3438)
  assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
          av == arena_for_chunk (mem2chunk (mem)));
```

不然也无法通过检查。

**Step 2: 修改unsorted bin chunk和large bins chunk的bk，large bins chunk的bk_nextsize。**

由于需要修改bss段内容，设需要修改的地址为y，要在这里伪造一个chunk，那么chunk头应该在y-0x10处。将unsorted bin chunk的bk修改为y-0x10，large bins chunk的bk修改为y-0x8。将large bins chunk的bk_nextsize修改为y-0x18-(偏移)。这个偏移指的是unsorted bin chunk的地址的非零字节数-1。

|addr|+0x0|+0x8|
|:-:|:-:|:-:|
|unsorted bin chunk + 0x10|fd|y - 0x10|
|...|...|...|
|large bin chunk + 0x10|fd|y - 0x8|
|large bin chunk + 0x20|fd_nextsize|y - 0x18 - \<offset\>|
|...|...|...|

下面是修改完成后两个chunk的情况：（目标地址为0x6020A0）

```
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x603250
Size: 0x4f1
fd: 0x7ffff7dcdca0
bk: 0x602090

Free chunk (largebins) | PREV_INUSE
Addr: 0x603a00
Size: 0x4e1
fd: 0x7ffff7dce0c0
bk: 0x602098
fd_nextsize: 0x603a00
bk_nextsize: 0x602076
```

**Step 3: 调用calloc返回目标地址。**

这里使用calloc而不使用malloc是为了避开tcache。而在这一步中蕴含了很多操作。

由于last_remainder为空，因此unsorted bin中的这个chunk实际上并不会被切割，而是直接被分配到bins中去了。这里的unsorted bin chunk大于small bins的最大阈值，因此被分配到了large bins中。

在glibc 2.23中对large bins的插入规则没有进行详细分析，这里解释一下。

## large bin的链入过程

在_int_malloc进入大循环中时，每一次会从unsorted bin中弹出一个chunk，不符合需求就将会被放入small bins或large bins中。假设unsorted bins中全部都会被放入一个large bins中。

```C
// (line 3734)
	bck = victim->bk;
	......
// (line 3778~3779)
	unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
    ......
// (line 3820)
	victim_index = largebin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;
    ......
	else
    {
      victim_index = largebin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;

      /* maintain large bins in sorted order */
      if (fwd != bck)
        {
          /* Or with inuse bit to speed comparisons */
          size |= PREV_INUSE;
          /* if smaller than smallest, bypass loop below */
          assert (chunk_main_arena (bck->bk));
          if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
            {
              fwd = bck;
              bck = bck->bk;

              victim->fd_nextsize = fwd->fd;
              victim->bk_nextsize = fwd->fd->bk_nextsize;
              fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
          else
            {
              assert (chunk_main_arena (fwd));
              while ((unsigned long) size < chunksize_nomask (fwd))
                {
                  fwd = fwd->fd_nextsize;
				  assert (chunk_main_arena (fwd));
                }

              if ((unsigned long) size == (unsigned long) chunksize_nomask (fwd))
                /* Always insert in the second position.  */
                fwd = fwd->fd;
              else
                {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
                }
              bck = fwd->bk;
            }
        }
      else
        victim->fd_nextsize = victim->bk_nextsize = victim;
    }
	mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
```

上面是所有涉及到bins修改的代码。每一次循环时，进行操作的chunk是victim，bck = victim->bk。

	a. 将victim脱离unsorted bin链，即line 3778~3779。
	b. 如果victim正好是请求的大小，直接返回，即line 3783~3808
	c. 发现是large bin，进入large bin调整过程，即line 3818

调整之前，首先找到这个large bin应该被放入的bin的索引，即line 3820的调用largebin_index函数；bck设置为这个bin的头指针，fwd设置为bck的fd指针。下面是判断这个bin是否有chunk。这里有一处需要注意：如果这个bin没有chunk，那么bck会指向前一个chunk。这样找到bck->fd时找到的是下一个bin，而下一个bin指向的正好是当前bin，就像下面这样。这就可以解释为什么``fwd != bck``可以用来判断bin中是否有chunk。不过存放chunk的真正bin应该是bck->fd而不是bck，这点也需要注意，在gdb调试过程中可以发现。

```
00:0000│ r8 0x7ffff7dce0d0 (main_arena+1168) —▸ 0x7ffff7dce0c0 (main_arena+1152) —▸ 0x7ffff7dce0b0 (main_arena+1136) —▸ 0x7ffff7dce0a0 (main_arena+1120) —▸ 0x7ffff7dce090 (main_arena+1104) ◂— ...
01:0008│    0x7ffff7dce0d8 (main_arena+1176) —▸ 0x7ffff7dce0c0 (main_arena+1152) —▸ 0x7ffff7dce0b0 (main_arena+1136) —▸ 0x7ffff7dce0a0 (main_arena+1120) —▸ 0x7ffff7dce090 (main_arena+1104) ◂— ...
02:0010│    0x7ffff7dce0e0 (main_arena+1184) —▸ 0x602250 ◂— 0x0
03:0018│    0x7ffff7dce0e8 (main_arena+1192) —▸ 0x602250 ◂— 0x0
04:0020│    0x7ffff7dce0f0 (main_arena+1200) —▸ 0x7ffff7dce0e0 (main_arena+1184) —▸ 0x602250 ◂— 0x0
05:0028│    0x7ffff7dce0f8 (main_arena+1208) —▸ 0x7ffff7dce0e0 (main_arena+1184) —▸ 0x602250 ◂— 0x0
06:0030│    0x7ffff7dce100 (main_arena+1216) —▸ 0x7ffff7dce0f0 (main_arena+1200) —▸ 0x7ffff7dce0e0 (main_arena+1184) —▸ 0x602250 ◂— 0x0
07:0038│    0x7ffff7dce108 (main_arena+1224) —▸ 0x7ffff7dce0f0 (main_arena+1200) —▸ 0x7ffff7dce0e0 (main_arena+1184) —▸ 0x602250 ◂— 0x0
```

如果这个bin中没有chunk，则将victim链入bin中，将fd_nextsize和bk_nextsize设为其自身。如果有，则继续下面的操作。这大致可以用几张图来展示。

如果victim的size小于这个bin中最后一个chunk的size，则进行下面的操作，将victim链入到bin的最后位置。<font color=red>**注意：每一个bin的第一个chunk的bk和最后一个chunk的fd指向的并不是这个bin的头指针，而是上一个bin的头指针！**</font>

![](https://img-blog.csdnimg.cn/d68f29357c494cec8f1e9bcfac0a44c2.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

否则，进行如下操作：

找到应该插入的位置，如果没有找到与victim大小相同的chunk，则进行插入操作，更新fd, bk, fd_nextsize和bk_nextsize。如下图：
![](https://img-blog.csdnimg.cn/4908f92cefb14ee49c54f5fd69e68888.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)


如果找到了与victim大小相同的chunk，则在其后进行插入，使victim成为这个大小的chunk中第二靠前的chunk。如下图：

![在这里插入图片描述](https://img-blog.csdnimg.cn/2dbc637079db42c680c0dc6be4bcff4b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

综上所述，large bin要维护的实际上是这样一个结构，其中每一个bin里面可以按照chunk的大小划分，bin head指向的是最大的chunk，那些大小相同的chunk中只有最靠前的chunk有fd_nextsize和bk_nextsize。

![](https://img-blog.csdnimg.cn/6361855305414fe18511dd86e492d732.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

---

再回到这个漏洞上面来。整个漏洞的执行过程一共有十几个调整bin的步骤。在漏洞调整chunk之后，bins的结构如图：

![](https://img-blog.csdnimg.cn/aa9ef778e43445a98099a3920bb0ef77.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)

调整的过程如下：

![](https://img-blog.csdnimg.cn/97c30be89a9448c59f161ddc8fc92fdc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATDNIX0NvTGlu,size_20,color_FFFFFF,t_70,g_se,x_16#pic_center)


```C
// line 3778~3779, Step 0
	unsorted_chunks (av)->bk = bck;
    bck->fd = unsorted_chunks (av);
// line 3820~3822, Step 1, 2
    victim_index = largebin_index (size);
    bck = bin_at (av, victim_index);
    fwd = bck->fd;
// line 3856~3859, Step 3, 4, 5, 6
	victim->fd_nextsize = fwd;
    victim->bk_nextsize = fwd->bk_nextsize;
    fwd->bk_nextsize = victim;
    victim->bk_nextsize->fd_nextsize = victim;
// line 3861, Step 7
	bck = fwd->bk;
// line 3869~3872, Step 8, 9, 10, 11
	victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;
```

之后再次进行一次循环，到达line 3778时将victim赋值为target-0x10（Step 0中已经将unsorted bin head赋值为target-0x10）。后面判断target-0x10这个chunk的大小，发现正好满足（Step 6中错位赋值所致），因此返回target。

这个地方非常不好理解，要知道它为什么会返回target，我死抠源码抠了好几天才捋清楚这一整个过程到底是怎么一个流程。建议对照源码仔细消化理解，搞清楚每一步干了什么。gdb有的时候调试源码定位不准确，因此只能这样一步步去推演了。

用了这么长时间，算是把house of storm研究透了，这种攻击方式真是巧妙，能够想到这种方式的人真的是天才。
