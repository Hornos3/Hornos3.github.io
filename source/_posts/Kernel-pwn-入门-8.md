---
title: Kernel pwn 入门 (8)
date: 2023-02-28 22:34:41
categories:
- 学习笔记
- kernel pwn 系列
---
在本篇文章中笔者不打算分析题目，而是对Linux中的slub系统进行深入的学习与分析。

参考资料：上一篇文章中提到的三篇与kernel内存分配有关的文章。在阅读本文时，建议与这三篇文章对照食用。

# 1. 伙伴系统重温
slub作为小块内存的分配器，其在伙伴系统之下运作，因此首先我们还是来回顾一下伙伴系统。

在第4篇文章中，我们简单介绍了伙伴系统的运作机理，以页为单位进行大块内存空间的分配与释放。其具体的数据结构如下图所示：

```c
/* 伙伴系统的一个块，描述1,2,4,8,16,32,64,128,256,512或1024个连续页框的块 */
struct free_area {
    /* 指向这个块中所有空闲小块的第一个页描述符，这些小块会按照MIGRATE_TYPES类型存放在不同指针里 */
    struct list_head    free_list[MIGRATE_TYPES];
    /* 空闲小块的个数 */
    unsigned long        nr_free;
};
```

<font color=red>**需要注意的是，伙伴系统并不是内核内存分配系统中最上层的结构，在其上还有其他的结构，但在Kernel pwn中我们对更为上层的结构接触较少，因此这里只介绍到伙伴系统。**</font>

上图的``free_area``表示一系列页的链表的数组。而在Linux系统内核中，一共有11个这样的``free_area``，分别保存所有大小为1,2,4,8,16,32,64,128,256,512,1024个页大小的内存空间（这些空间都是连续的），在``free_area``中，``free_list``是一系列这样的内存空间组成的链表的数组，内含多个链表，这些链表中的内存空间大小相同，但属性不同，对于``MIGRATE_TYPES``的定义如下：

```c
enum migratetype {
	MIGRATE_UNMOVABLE,
	MIGRATE_MOVABLE,
	MIGRATE_RECLAIMABLE,
	MIGRATE_PCPTYPES,	/* the number of types on the pcp lists */
	MIGRATE_HIGHATOMIC = MIGRATE_PCPTYPES,
#ifdef CONFIG_CMA
	/*
	 * MIGRATE_CMA migration type is designed to mimic the way
	 * ZONE_MOVABLE works.  Only movable pages can be allocated
	 * from MIGRATE_CMA pageblocks and page allocator never
	 * implicitly change migration type of MIGRATE_CMA pageblock.
	 *
	 * The way to use it is to change migratetype of a range of
	 * pageblocks to MIGRATE_CMA which can be done by
	 * __free_pageblock_cma() function.
	 */
	MIGRATE_CMA,
#endif
#ifdef CONFIG_MEMORY_ISOLATION
	MIGRATE_ISOLATE,	/* can't allocate from here */
#endif
	MIGRATE_TYPES
};
```

这里定义了链表中内存块的属性：
> linux为了防止内存中产生过多的碎片，一般把页的类型分为三种：
> 不可移动页：在内存中有固定位置，不能移动到其他地方。内核中使用的页大部分是属于这种类型。
可回收页：不能直接移动，但可以删除，页中的内容可以从某些源中重新生成。例如，页内容是映射到文件数据的页就属于这种类型。对于这种类型，在内存短缺(分配失败)时，会发起内存回收，将这类型页进行回写释放。
可移动页：可随意移动，用户空间的进程使用的没有映射具体磁盘文件的页就属于这种类型(比如堆、栈、shmem共享内存、匿名mmap共享内存)，它们是通过进程页表映射的，把这些页复制到新位置时，只要更新进程页表就可以了。一般这些页是从高端内存管理区获取。

上面的每一个链表中保存的所有内存块的属性都是一样的。因此总的来看，伙伴系统可以表示为下图所示的结构：

![](1.png)
其中枚举类型具体的含义我们只需要了解即可，在Kernel pwn中我们应该应对的最多的还是SLAB和SLUB系统。虽然SLAB系统正逐渐被SLUB替换，但还是有必要进行了解。

# 2. SLAB系统介绍
SLAB分配器建立在伙伴系统基础上，由于参考资料年代较为久远，部分源码与最近的Linux内核源码差距较大，因此不做解释，但影响不大。

在SLAB中，我们将可分配的内存块称之为<font color=red>**对象**</font>，一个分配器由结构体``kmem_cache``描述，结构如下（选自Linux 5.18.19版本内核）
```c
struct kmem_cache {
	struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

	slab_flags_t flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 3) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t allocflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size;

	/* constructor func */
	void (*ctor)(void *obj);

/* 4) cache creation/removal */
	const char *name;
	struct list_head list;
	int refcount;
	int object_size;
	int align;

/* 5) statistics */
#ifdef CONFIG_DEBUG_SLAB
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;

	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. 'size' contains the total
	 * object size including these internal fields, while 'obj_offset'
	 * and 'object_size' contain the offset to the user object and its
	 * size.
	 */
	int obj_offset;
#endif /* CONFIG_DEBUG_SLAB */

#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};
```
其中``kmem_cache_node *node[MAX_NUMNODES]``中就保存有SLAB分配器中的一些核心结构，这里的``MAX_NUMNODES``在x86-64架构下的值为64：
```c
struct kmem_cache_node {
	spinlock_t list_lock;

#ifdef CONFIG_SLAB
	struct list_head slabs_partial;	/* partial list first, better asm code */
	struct list_head slabs_full;
	struct list_head slabs_free;
	unsigned long total_slabs;	/* length of all slab lists */
	unsigned long free_slabs;	/* length of free slab list only */
	unsigned long free_objects;
	unsigned int free_limit;
	unsigned int colour_next;	/* Per-node cache coloring */
	struct array_cache *shared;	/* shared per node */
	struct alien_cache **alien;	/* on other nodes */
	unsigned long next_reap;	/* updated without locking */
	int free_touched;		/* updated without locking */
#endif

#ifdef CONFIG_SLUB
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
#endif

};
```
这里的``list_head``里面只保存了两个值：``next``指针和``prev``指针，也就是双向链表的经典结构。这里可以看到有三个双向链表：``slabs_partial``、``slabs_full``、``slabs_free``，分别保存的是**内部有部分对象被分配的SLAB、内部所有对象都被分配的SLAB、内部所有对象都空闲的SLAB**。这三个链表中的slab可以互相转化，如向一个所有对象都空闲的SLAB中申请空间成功后，这个SLAB就会从``slabs_free``移动到``slabs_partial``。

虽然文章开头参考的文章已经在一定程度上过时，但其中关于SLAB分配器的实现原理和思想却一直沿用至今。在5.18.19版本的``page``结构体中，已经找不到参考文章中的一些关键结构，不过这不影响我们对SLAB本身的分析。

下面是5.18.19版本内核的``slab``结构体声明：
```c
struct slab {
	unsigned long __page_flags;

#if defined(CONFIG_SLAB)

	union {
		struct list_head slab_list;
		struct rcu_head rcu_head;
	};
	struct kmem_cache *slab_cache;
	void *freelist;	/* array of free object indexes */
	void *s_mem;	/* first object */
	unsigned int active;

#elif defined(CONFIG_SLUB)

	union {
		struct list_head slab_list;
		struct rcu_head rcu_head;
#ifdef CONFIG_SLUB_CPU_PARTIAL
		struct {
			struct slab *next;
			int slabs;	/* Nr of slabs left */
		};
#endif
	};
	struct kmem_cache *slab_cache;
	/* Double-word boundary */
	void *freelist;		/* first free object */
	union {
		unsigned long counters;
		struct {
			unsigned inuse:16;
			unsigned objects:15;
			unsigned frozen:1;
		};
	};
	unsigned int __unused;

#elif defined(CONFIG_SLOB)

	struct list_head slab_list;
	void *__unused_1;
	void *freelist;		/* first free block */
	long units;
	unsigned int __unused_2;

#else
#error "Unexpected slab allocator configured"
#endif

	atomic_t __page_refcount;
#ifdef CONFIG_MEMCG
	unsigned long memcg_data;
#endif
};
```
可以看到，历史版本中的诸如``s_mem``等关键控制结构体从``page``移到了``slab``中。由此，``page``结构体中也就不需要定义这些属性了。``s_mem``指向的是该SLAB分配器中的第一个对象，而``freelist``指向的是一个重要的标识对象使用情况的结构，我们接下来就会提到。这两个指针指向同一页中的不同地址，其中如果一个``page``被用作SLAB分配器，那么它的``virtual``（``page``中的最后一个属性）属性值与SLAB中的``freelist``指向相同地址。

关于SLAB内的分配机制，以下面一张图进行展示，其中需要注意的是：**分配到哪一个对象不是外界能够决定的，而释放哪一个对象是外界能够决定的**。如下图所示的分配方式能够最大限度保证分配到的对象是最近释放的。**<font color=red>在进行分配时，active读取其索引指向的值，并向前移动一位，在进行释放时，active首先回退一位，在将这一位对应的索引值修改为被释放的对象的索引值。</font>**
![](2.png)
在这种分配机制下，很容易判断一个SLAB中的对象究竟是全部分配，还是全部释放，还是部分分配。因为分配对应一次索引值前移，而释放对应一次索引值后移，只要索引值为0，这个SLAB就一定为空；只要索引值等于SLAB中对象的个数-1，这个SLAB就一定为满。

看到这里，我们对于SLAB的分配机制应该有了一个基本的认识，但是SLAB中还有一个**染色**的问题。有了上面的组织形式，SLAB已经能够作为一个成熟的内存分配器了，至于为什么要添加染色的机制，主要是为了性能的考虑：

> 我们知道内存需要处理时要先放入CPU硬件高速缓存中，而CPU硬件高速缓存与内存的映射方式有多种。在同一个kmem_cache中所有SLAB都是相同大小，都是相同连续长度的页框组成，这样的话在不同SLAB中相同对象号对于页框的首地址的偏移量也相同，这样有很可能导致不同SLAB中相同对象号的对象放入CPU硬件高速缓存时会处于同一行，当我们交替操作这两个对象时，CPU的cache就会交替换入换出，效率就非常差。SLAB着色就是在同一个kmem_cache中对不同的SLAB添加一个偏移量，就让相同对象号的对象不会对齐，也就不会放入硬件高速缓存的同一行中，提高了效率。

> 着色空间就是前端的空闲区域，这个区有大小都是在分配新的SLAB时计算好的，计算方法很简单，node结点对应的kmem_cache_node中的colour_next乘上kmem_cache中的colour_off就得到了偏移量，然后colour_next++，当colour_next等于kmem_cache中的colour时，colour_next回归到0。
> ```c
>    偏移量 = kmem_cache.colour_off * kmem_cache.node[NODE_ID].colour_next;
>
>    kmem_cache.node[NODE_ID].colour_next++;
>    if (kmem_cache.node[NODE_ID].colour_next == kmem_cache.colour)
>        kmem_cache.node[NODE_ID].colour_next = 0;
>```
# 3. SLUB系统介绍
说完了SLAB，终于可以开始我们的重点——SLUB系统了。都说SLUB系统是SLAB的升级版，那么SLUB到底比SLAB升级在什么地方呢？

简单地来说，**首先SLUB直接删掉了两个SLAB链表，即在SLAB节点中表示全空和全满的对象链表，只保留了一个部分满的SLAB链表。其次，在``slab``结构体内部也有很大的变化，删去了SLAB中指引内存分配的关键的数组结构和描述符数组，而只是使用一个指针形成链表，将所有空闲的对象串连在一起：**

![](3.png)
（原文是有贴图的，但是在笔者的windows系统下加载不出来，在ubuntu倒是可以加载出来。上图选自[资料](https://blog.csdn.net/wh8_2011/article/details/52287557?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522166522587916800182720892%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=166522587916800182720892&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~baidu_landing_v2~default-4-52287557-null-null.142%5Ev52%5Ejs_top,201%5Ev3%5Econtrol_1&utm_term=slub&spm=1018.2226.3001.4187)）

注意slab和slub分别使用了不同的``kmem_cache``结构体，分别定义在``/include/linux/slab_def.h``和``/include/linux/slub_def.h``中。上面解释SLAB的时候使用的是``/include/linux/slab_def.h``的结构体。

```c
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	/* The size of an object including metadata */
	unsigned int object_size;/* The size of an object without metadata */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;	/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	/* Number of per cpu partial objects to keep around */
	unsigned int cpu_partial;
	/* Number of per cpu partial slabs to keep around */
	unsigned int cpu_partial_slabs;
#endif
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	struct kmem_cache_order_objects max;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	int refcount;		/* Refcount for slab cache destroy */
	void (*ctor)(void *);
	unsigned int inuse;		/* Offset to metadata */
	unsigned int align;		/* Alignment */
	unsigned int red_left_pad;	/* Left redzone padding size */
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SYSFS
	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	unsigned int remote_node_defrag_ratio;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};
```
在SLUB的``kmem_cache``中，有一个``kmem_cache_cpu``结构体指针，这是SLUB分配器的描述符：
```c
struct kmem_cache_cpu {
	void **freelist;	/* Pointer to next available object */
	unsigned long tid;	/* Globally unique transaction id */
	struct slab *slab;	/* The slab from which we are allocating */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	struct slab *partial;	/* Partially allocated frozen slabs */
#endif
	local_lock_t lock;	/* Protects the fields above */
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS];
#endif
};
```
结构如下图所示（图片选自[资料](https://blog.csdn.net/whenloce/article/details/88949002?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522166522587916800182720892%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=166522587916800182720892&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~baidu_landing_v2~default-3-88949002-null-null.142^v52^js_top,201^v3^control_1&utm_term=slub&spm=1018.2226.3001.4187)）

![](4.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3doZW5sb2Nl,size_16,color_FFFFFF,t_70)
其中需要重点关注的就是``freelist``，里面保存的就是对象本身，以链表连接。在上一篇文章中，我们使用了SLUB的结构特性实现了利用，在那道题中，读者可以进行调试发现，对象内部的内容非常简单，空闲的对象开头8字节保存的就是下一个空闲对象的地址，以链表形式连接，在释放一个对象时，会将该对象放在``freelist``链表头部。这也就是为什么在上一题中通过修改指针的值就可以让SLUB为我们分配到任意地址了。**在实际的pwn利用中，有一个思路就是恶意篡改SLUB中的``freelist``，破坏链表以实现任意地址分配，后续可能可以进行任意地址读写**。
