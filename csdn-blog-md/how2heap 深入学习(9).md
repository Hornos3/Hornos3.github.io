how2heap下载网址: [传送门](https://github.com/shellphish/how2heap)
Glibc源码查看网址：[传送门](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L3516)
参考书籍：CTF竞赛权威指南-pwn篇

测试环境：Ubuntu 20.04
Glibc 版本：Ubuntu GLIBC 2.31-0ubuntu9.7

最近做题，由于对2.31中添加的检查项缺乏总结，导致浪费了很多时间，本文分析glibc 2.31中关键函数中的检查项。如果读者仔细看过我写的前8篇文章，对于各种bin的结构应该已经较为熟悉，本文的阅读难度就不大了，如有疑问请移步。目前分析的函数有：_int_malloc，unlink_chunk，_int_free函数，之后会更新其他函数的分析。
如果本文的分析有任何错漏之处，还请各位读者不吝赐教，不胜感激。

# <font color=red>**一、_int_malloc**<font>

## **1. fastbin部分**

### （1）检查victim是否应该存在于该fastbin
```C
// line 3592
size_t victim_idx = fastbin_index (chunksize (victim));
if (__builtin_expect (victim_idx != idx, 0))
	malloc_printerr ("malloc(): memory corruption (fast)");
```

这里的``fastbin_index``函数指的应该是根据victim的大小获取到其应该存放的fastbin索引。显然0x30大小的chunk在正常情况下不可能跑到专门存放0x20大小chunk的fastbin中，该检查就是针对这种异常情况，能够防止victim的size被修改。

## **2. tcache部分**

在2.31版本中，通过搜索关键函数tcache_put、malloc_printerr没有找到对tcache的检查。

## **3. small bins部分**

### （1）检查``victim->bck->fwd``是否为victim

```C
// line 3643
if (__glibc_unlikely (bck->fd != victim))
	malloc_printerr ("malloc(): smallbin double linked list corrupted");
```

## **4. unsorted bin部分**

关于这部分的检查是最多的，也是最难以绕过的。

### （1）检查victim的size是否合法

```C
// line 3734
if (__glibc_unlikely (size <= 2 * SIZE_SZ)
    || __glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): invalid size (unsorted)");
```

victim的大小不应小于0x20（64位），不应大于av->system_mem

### （2）检查物理地址居victim高位的chunk的size是否合法

```C
mchunkptr next = chunk_at_offset (victim, size);
// line 3737
if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
    || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
  malloc_printerr ("malloc(): invalid next size (unsorted)");
```

这里的``chunk_at_offset``函数指的是将victim往后size处作为一个chunk返回，也就是这里检查物理相邻的chunk的size

### （3）检查物理地址居victim高位的prev_size是否等于victim的size

```C
// line 3740
if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
  malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
```

由于victim是一个free chunk，因此物理地址居高位的chunk的开头理应存放victim的size，这里进行检查。

### （4）检查unsorted bin链中``victim->bck->fd``是否是victim，``victim->fd``是否为unsorted bin头

```C
// line 3742
if (__glibc_unlikely (bck->fd != victim)
    || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
  malloc_printerr ("malloc(): unsorted double linked list corrupted");
```

大循环遍历期间，每一次拿出来的victim都在unsorted bin的尾部，其fd指针一定指向unsorted bin头，bk指向后一个chunk或unsorted bin头（当unsorted bin仅有这一个chunk时），因此正常情况下``victim->bck->fd==victim``与``victim->fd==unsorted_chunks(av)``一定成立。

### （5）检查物理地址居victim高位的chunk的prev_inuse位是否为0

```C
// line 3745
if (__glibc_unlikely (prev_inuse (next)))
  malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

### （6）第二次检查unsorted bin链中``victim->bck->fd``是否是victim

```C
// line 3785
if (__glibc_unlikely (bck->fd != victim))
  malloc_printerr ("malloc(): corrupted unsorted chunks 3");
```

在可能进行的remainder拆分后，再一次进行检查。目前尚不清楚这里再次检查的意义何在，理解后更新。

### （7）第三次检查unsorted bin链中``bck->fd``是否是victim

```C
// line 3954
bck = unsorted_chunks (av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("malloc(): corrupted unsorted chunks");
```

这个检查发生于非small bins大小申请的last_remainder拆分部分，又一次进行了unsorted bin的双向链表完整性检查。

### （8）第四次检查unsorted bin链中``bck->fd``是否是victim

```C
// line 4058
bck = unsorted_chunks (av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("malloc(): corrupted unsorted chunks 2");
```

这个检查发生在切割large bin部分，切割后剩余的部分作为last_remainder放入unsorted bin，因此检查。

## **5. large bins部分**

### （1）检查``fwd->bk_nextsize->fd_nextsize``是否等于fwd

```C
// line 3867
if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
  malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
```

这个检查发生在victim被链入到large bins的过程中，fwd表示victim被链入后处于victim之前的chunk。这里的检查在正常情况下显然成立。

### （2）检查``fwd->bk->fd``是否等于fwd

```C
// line 3872
bck = fwd->bk;
if (bck->fd != fwd)
  malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
```

这个检查也发生在victim被链入到large bins的过程中，检查large bin中双向链表的完整性。

## 6. top chunk部分

### （1）检查top chunk大小

```C
// line 4106
if (__glibc_unlikely (size > av->system_mem))
  malloc_printerr ("malloc(): corrupted top size");
```

检查top chunk是否大到离谱。

# <font color=red>**二、unlink_chunk**</font>

### （1）检查物理地址居victim高位的chunk的prev_size是否等于victim的size

```C
// line 1453
if (chunksize (p) != prev_size (next_chunk (p)))
  malloc_printerr ("corrupted size vs. prev_size");
```

### （2）检查前后双向链表完整性：``fd->bk != p || bk->fd != p``

```C
// line 1459
if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
  malloc_printerr ("corrupted double-linked list");
```

### （3）检查large bins双向链表完整性：``p->fd_nextsize->bk_nextsize != p || p->bk_nextsize->fd_nextsize != p``

```C
// line 1466
if (p->fd_nextsize->bk_nextsize != p
	|| p->bk_nextsize->fd_nextsize != p)
	malloc_printerr ("corrupted double-linked list (not small)");
```

# <font color=red>三、_int_free</font>

### （1）检查size是否合理，chunk是否正确对齐

```C
// line 4171
if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
    || __builtin_expect (misaligned_chunk (p), 0))
  malloc_printerr ("free(): invalid pointer");
```

简单解释一下第一个判断的意思：``(uintptr_t) p > (uintptr_t) -size``。它指的是chunk的地址加上chunk的size不能导致整形溢出。这很好理解，正常情况下这种情况不会发生。不过如果想理解这条语句，需要进行一些移项。

两边均为无符号整数，则-size==2^64-size，等式可以变形为：``p+size>2^64``。

### （2）检查size是否过小，检查size是否对齐

```C
// line 4176
if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
  malloc_printerr ("free(): invalid size");
```

这里的MINSIZE=0x10，最小的chunk不能小于这个大小。

### （3）检查tcache double free

```C
// line 4187
	tcache_entry *e = (tcache_entry *) chunk2mem (p);

	/* This test succeeds on double free.  However, we don't 100%
	   trust it (it also matches random payload data at a 1 in
	   2^<size_t> chance), so verify it's not an unlikely
	   coincidence before aborting.  */
	if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
```

在chunk被链入tcache时，会对chunk进行标记，也即将成员key标记为tcache的地址。

tcache chunk定义：
```C
// line 2894
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```
注意上面的tcache_entry结构体在chunk中的头部是可写段的头部而非chunk的头部，前面还有size和prev_size两个字段。

观察_int_free中的代码，我们可以发现，在这个过程中，如果glibc发现要free的chunk（以下称p）有标志，则说明很可能这是一次double free。为了确认无误，glibc会对相应的tcache中的所有chunk进行检查，如果确实发现该chunk已经存在于tcache中，再报错退出。这是为了防止异常的误报。如果本身这不是一个double free，而key正好填的也是tcache，glibc不能认定这是一次double free，因此它遍历tcache中的chunk进行确认。

### （4）检查fastbin chunk size

```C
// line 4236
	bool fail = true;
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might result in a false positive.  Redo the test after
	   getting the lock.  */
	if (!have_lock)
	  {
	    __libc_lock_lock (av->mutex);
	    fail = (chunksize_nomask (chunk_at_offset (p, size)) <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
	    __libc_lock_unlock (av->mutex);
	  }

	if (fail)
	  malloc_printerr ("free(): invalid next size (fast)");
      }
```

这里检查p的大小是否过小或过大，与_int_malloc中对应检查相同。在检查过程中对这个main_arena上锁以避免多线程的影响。

### （5）检查fastbin double free

```C
// line 4256
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;

    if (SINGLE_THREAD_P)
      {
	/* Check that the top of the bin is not the record we are going to
	   add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
	p->fd = old;
	*fb = p;
      }
    else
      do
	{
	  /* Check that the top of the bin is not the record we are going to
	     add (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	    malloc_printerr ("double free or corruption (fasttop)");
	  p->fd = old2 = old;
	}
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
	     != old2);
```

这里检查的是上一次free的chunk和这一次是不是同一个，即相邻检查。使用两个检查是为了兼容多线程，不用深究。

### （6）检查fastbin环境

```C
// line 4286
if (have_lock && old != NULL
&& __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
  malloc_printerr ("invalid fastbin entry (free)");
```

这里应该是检查原fastbin头的chunksize是否正确。

### （7）检查p是否为top chunk

```C
// line 4308
if (__glibc_unlikely (p == av->top))
  malloc_printerr ("double free or corruption (top)");
```

### （8）检查该chunk是否超出了main_arena的管辖范围

```C
// line 4311
if (__builtin_expect (contiguous (av)
 && (char *) nextchunk
 >= ((char *) av->top + chunksize(av->top)), 0))
	malloc_printerr ("double free or corruption (out)");
```

这里是检查chunk尾部的地址是否大于top chunk的尾部地址。

### （9）检查物理地址后一个chunk是否有prev_inuse位

```C
// line 4316
if (__glibc_unlikely (!prev_inuse(nextchunk)))
  malloc_printerr ("double free or corruption (!prev)");
```

### （10）检查物理地址后一个chunk的大小是否合理

```C
// line 4320
if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
|| __builtin_expect (nextsize >= av->system_mem, 0))
  malloc_printerr ("free(): invalid next size (normal)");
```

### （11）检查物理地址前一个chunk的size是否等于prev_size

```C
// line 4327
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  if (__glibc_unlikely (chunksize(p) != prevsize))
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
  unlink_chunk (av, p);
}
```

这里是尝试与前一个chunk进行合并，顺便进行一下前面chunk的size检查。

### （12）检查unsorted bin链表尾部的双向链表完整性

```C
// line 4353
bck = unsorted_chunks(av);
fwd = bck->fd;
if (__glibc_unlikely (fwd->bk != bck))
	malloc_printerr ("free(): corrupted unsorted chunks");
```

与_int_malloc中频繁进行的检查相同。
