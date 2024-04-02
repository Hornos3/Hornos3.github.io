---
title: how2heap 深入学习(10)
date: 2023-12-19 22:27:01
categories:
- 学习笔记
- glibc 系列
---

how2heap下载网址: [传送门](https://github.com/shellphish/how2heap)
Glibc源码查看网址：[传送门](https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L3770)
参考书籍：CTF竞赛权威指南-pwn篇

测试环境：Ubuntu 22.04
Glibc 版本：Ubuntu GLIBC 2.35-0ubuntu3.5

最近回看自己写过的所有blog，发现glibc系列已经许久没有更新了。这个系列是在我刚刚入门pwn的时候，花了不知道多少个晚上，一点点去啃glibc源码写出来的。现在看来这些是很有价值的，毕竟是自己写的东西，理解起来也很快。不过glibc更新换代的速度也很快，ubuntu 22.04使用的是glibc-2.35，属于高版本的glibc，在多种漏洞利用方式上和旧版有一些不同之处。现在想来，我已经有很长时间没有复习glibc的诸多攻击手段了，很多都已经记忆模糊。那么本文以及后面的几篇blog将是对how2heap的2.35版本常用glibc攻击手法的简单分析，毕竟how2heap使用源码的方式进行讲解，多少还是不太直观，我会尝试尽量使用图片让利用手法更加清晰易懂，这也算是我对glibc系列的回顾。

# decrypt_safe_linking
这实际上不是一种攻击方式，而是对高版本glibc一种特有的保护方式的介绍。

这种保护发生于tcache/fastbin链入新的chunk时。tcache是一个链栈结构，遵循后进先出的原则，后进的chunk会放在链首，以指针连接到原来的链首。在glibc 2.32之后，glibc对这个链接的指针进行了一个简单的加密，加密方式如下图所示。

![](1.png)

下面是加密与解密的宏定义以及在tcache_put/tcache_get中的应用。

```c
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");
  tcache->entries[tc_idx] = REVEAL_PTR (e->next);
  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

可以看到，解密算法也很简单。我们只需要知道当前被释放的chunk的地址即可。

在how2heap的源码中，假设a与b的高12位地址相同，在这种情况下可以在不知道a的情况下完成解密，也即经过5轮，每一轮获取明文的12位，最终获取所有明文位。如下图所示：

![](2.png)

# fastbin_dup
一个传统的double free问题，算是最好理解的一个漏洞了。

简单解释一下下图的一些构图元素。size后面的字符串中，点后面是一个以字母表示的chunk大小（包括chunk头部大小），前面是表示这个大小是什么bin能够链入的，如tcache.a就表示释放后可能进入tcache的大小a，下面还出现了fastbin.a，即表示大小a的chunk既可能进入tcache，也可能进入fastbin。菱形表示一个freelist。

![](3.png)

# fastbin_dup_consolidate
这是一种利用malloc_consolidate完成的double free。但实际上，它的本质是指针在free后没有清空，导致double free前被其他chunk所占用。在这个漏洞的任何一个时刻，都没有一个chunk在已被释放的状态下再一次被释放。两次释放同一个指针实际上释放的是不同的chunk。

![](4.png)

# house_of_einherjar
一个使用了off by one的漏洞利用方式。通过off by one可将下一个chunk的prev_inuse位消除，从而达到chunk重叠的效果，利用重叠可修改tcache chunk的fd指针，从而实现malloc返回任意地址。

[draw.io文件](https://hornos3.github.io/2023/12/19/how2heap-%E6%B7%B1%E5%85%A5%E5%AD%A6%E4%B9%A0-10/house_of_einherjar.drawio)

![](5.png)

# large_bin_attack
这是高版本中最为常用的一种攻击方式之一，不过与低版本的利用方式有一定区别。

注：对于一个chunk A，A表示用户可用空间的起始地址，'A表示chunk头的地址。

![](6.png)

[draw.io文件](https://hornos3.github.io/2023/12/19/how2heap-%E6%B7%B1%E5%85%A5%E5%AD%A6%E4%B9%A0-10/large_bin_attack.drawio)

# poison_null_byte
这种利用方式与house_of_einherjar类似，都是只能溢出一个字节，不过这里是溢出一个空字节，且利用过程差距较大。这种溢出即使是在做题的时候也是很难发现的，需要仔细观察。

