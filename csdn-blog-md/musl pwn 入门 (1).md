近年来，musl libc作为一个轻量级的libc越来越多地出现在CTF pwn题之中，其和glibc相比有一定的差距，因此本文我们就musl libc最常考的考点——内存分配，进行musl libc的源代码审计。

不同于glibc多达四五千行代码，大小超过10w字节的malloc.c，musl libc中的malloc.c大小甚至都不到1w字节，其轻量级的特性也使得我们更加容易去阅读它的代码。

musl libc在内存分配上经历过一次大的改动（1.2.0->1.2.1），本文针对发文时的最新版本1.2.3进行分析。

参考文章：[传送门](https://bbs.kanxue.com/thread-269533.htm#msg_header_h3_6)

# 1. 主要数据结构
## malloc_context
```c
struct malloc_context {
	uint64_t secret;
#ifndef PAGESIZE
	size_t pagesize;
#endif
	int init_done;
	unsigned mmap_counter;
	struct meta *free_meta_head;
	struct meta *avail_meta;
	size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
	struct meta_area *meta_area_head, *meta_area_tail;
	unsigned char *avail_meta_areas;
	struct meta *active[48];
	size_t usage_by_class[48];
	uint8_t unmap_seq[32], bounces[32];
	uint8_t seq;
	uintptr_t brk;
};
```
这个结构体是musl libc的堆管理最上层结构，其中字段的含义分别为：
- ``uint64_t secret``：一个随机生成的数，用于检查``meta``的合法性，也即一个check guard
- ``size_t pagesize``：页大小，在x86_64下一般为为0x1000
- ``int init_done``：判断``malloc_context``是否初始化完成，在``alloc_meta``函数中进行检查，如果没有则进行初始化，否则跳过初始化流程
- ``unsigned mmap_counter``：mmap计数器，通过mmap分配了多少次空间用于内存分配
- ``struct meta *free_meta_head``：被释放的``meta``结构体构成的链表表头，``meta``结构体是musl libc内存分配的低一级结构，后面会提到
- ``struct meta *avail_meta``：空闲的``meta``结构体构成的链表表头
- ``size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift``：
	- ``size_t avail_meta_count``：空闲``meta``的数量
	- ``size_t avail_meta_area_count``：空闲``meta_area``的数量，``meta_area``是``meta``的控制结构
	- ``size_t meta_alloc_shift``：<暂缺>
- ``struct meta_area *meta_area_head, *meta_area_tail``：``meta_area``链表表头，链表表尾
- ``unsigned char *avail_meta_areas``：<暂缺>
- ``struct meta *active[48]``：可以继续分配的``meta``
- ``size_t usage_by_class[48]``：对应大小的缓存的所有``meta``的``group``所管理的chunk个数
- ``uint8_t unmap_seq[32], bounces[32]``：<暂缺>
- `uint8_t seq`：<暂缺>
- ``uintptr_t brk``：记录目前的``brk(0)``

其中有一些字段无法通过简单查看代码得到，需要进一步代码审计获取其含义，我们后面再进行补充。

## meta_area
```c
struct meta_area {
	uint64_t check;
	struct meta_area *next;
	int nslots;
	struct meta slots[];
};
```
这个结构用于管理一页内的所有``meta``结构，属于``malloc_context``的下级结构，``meta``的上级结构。
- ``uint64_t check``：检查字段，与``malloc_context``中的``secret``字段对应，检查该``meta_area``是否可能被修改
- ``struct meta_area *next``：下一个``meta_area``的地址，构成链表
- ``int nslots``：该``meta_area``中管理的``meta``数量，一般为固定值
- ``struct meta slots[]``：管理的``meta``数组

## meta
```c
struct meta {
	struct meta *prev, *next;
	struct group *mem;
	volatile int avail_mask, freed_mask;
	uintptr_t last_idx:5;
	uintptr_t freeable:1;
	uintptr_t sizeclass:6;
	uintptr_t maplen:8*sizeof(uintptr_t)-12;
};
```
``meta``中保存有``group``结构体指针，后者直接保存有需要分配的内存块。即``meta``和其管理的内存块可能不在同一个page中。
- ``struct meta *prev, *next``：前后``meta``，构成双向链表
- ``struct group *mem``：管理的``group``结构体指针
- ``volatile int avail_mask, freed_mask``：掩码的形式，用一个bit表示存在与否
- ``uintptr_t last_idx:5``：该`meta`中最后一个chunk的索引
- ``freeable:1``：该``meta``中的chunk是否能够被释放
- ``uintptr_t sizeclass:6``：管理的group的大小。如果mem是mmap分配，固定为63
- ``uintptr_t maplen:8*sizeof(uintptr_t)-12``：如果管理的group是mmap分配的，则为内存页数，否则为0

## group
```c
struct group {
	struct meta *meta;
	unsigned char active_idx:5;
	char pad[UNIT - sizeof(struct meta *) - 1];
	unsigned char storage[];
};
```
``group``中即保存有需要分配出去的chunk。
- ``struct meta *meta``：所属的``meta``的地址
- ``unsigned char active_idx:5``：5个比特，表示还有多少可用chunk
- ``char pad[UNIT - sizeof(struct meta *) - 1]``：手动16字节对齐
- ``unsigned char storage[]``：要分配出去的内存空间，chunk

---
以上就是musl libc中主要的数据结构，下面我们通过代码审计彻底搞清楚musl libc的内存分配机制。
# 2. 代码审计
我们首先从内存分配相关的函数开始看起。对于辅助性的较为复杂的函数使用小标题的形式进行分析，辅助性的较为简单的函数只在第一次出现时直接写到主要函数分析代码中进行简单解释。
## malloc（``/src/malloc/mallocng/malloc.c line 299``）
```c
void *malloc(size_t n)
{
	if (size_overflows(n)) return 0;
	struct meta *g;
	uint32_t mask, first;
	int sc;
	int idx;
	int ctr;

	if (n >= MMAP_THRESHOLD) {
		size_t needed = n + IB + UNIT;
		void *p = mmap(0, needed, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANON, -1, 0);
		if (p==MAP_FAILED) return 0;
		wrlock();
		step_seq();
		g = alloc_meta();
		if (!g) {
			unlock();
			munmap(p, needed);
			return 0;
		}
		g->mem = p;
		g->mem->meta = g;
		g->last_idx = 0;
		g->freeable = 1;
		g->sizeclass = 63;
		g->maplen = (needed+4095)/4096;
		g->avail_mask = g->freed_mask = 0;
		// use a global counter to cycle offset in
		// individually-mmapped allocations.
		ctx.mmap_counter++;
		idx = 0;
		goto success;
	}

	sc = size_to_class(n);

	rdlock();
	g = ctx.active[sc];

	// use coarse size classes initially when there are not yet
	// any groups of desired size. this allows counts of 2 or 3
	// to be allocated at first rather than having to start with
	// 7 or 5, the min counts for even size classes.
	if (!g && sc>=4 && sc<32 && sc!=6 && !(sc&1) && !ctx.usage_by_class[sc]) {
		size_t usage = ctx.usage_by_class[sc|1];
		// if a new group may be allocated, count it toward
		// usage in deciding if we can use coarse class.
		if (!ctx.active[sc|1] || (!ctx.active[sc|1]->avail_mask
		    && !ctx.active[sc|1]->freed_mask))
			usage += 3;
		if (usage <= 12)
			sc |= 1;
		g = ctx.active[sc];
	}

	for (;;) {
		mask = g ? g->avail_mask : 0;
		first = mask&-mask;
		if (!first) break;
		if (RDLOCK_IS_EXCLUSIVE || !MT)
			g->avail_mask = mask-first;
		else if (a_cas(&g->avail_mask, mask, mask-first)!=mask)
			continue;
		idx = a_ctz_32(first);
		goto success;
	}
	upgradelock();

	idx = alloc_slot(sc, n);
	if (idx < 0) {
		unlock();
		return 0;
	}
	g = ctx.active[sc];

success:
	ctr = ctx.mmap_counter;
	unlock();
	return enframe(g, idx, n, ctr);
}
```

其中`MMAP_THRESHOLD`等于131052。第一个判断如果为真，说明要分配一块很大的内存。首先计算一共需要的内存大小，这里`IB`等于4、`UNIT`等于16。然后使用`mmap`函数分配一块内存。如果分配成功，上读写锁。后面使用`alloc_meta`分配一个`meta`给这块大空间，之后设置这个`meta`的一些基本信息。

从这个if语句我们可以知道，如果一次内存申请的大小过大，musl libc会为这块空间专门分配一个meta和group，这个meta和group只管理这一个空间。

如果申请的空间较小，则进入下面的代码。

`sc = size_to_class(n);`这条语句是为了计算这个大小的chunk应该被分到哪一个class。

在musl中定义有如下内容：

```c
// /src/malloc/mallocng/malloc.c, line 12
const uint16_t size_classes[] = {
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 12, 15,
	18, 20, 25, 31,
	36, 42, 50, 63,
	72, 84, 102, 127,
	146, 170, 204, 255,
	292, 340, 409, 511,
	584, 682, 818, 1023,
	1169, 1364, 1637, 2047,
	2340, 2730, 3276, 4095,
	4680, 5460, 6552, 8191,
};
```

`size_to_class`的代码如下：

```c
static inline int size_to_class(size_t n)
{
	n = (n+IB-1)>>4;
	if (n<10) return n;
	n++;
	int i = (28-a_clz_32(n))*4 + 8;
	if (n>size_classes[i+1]) i+=2;
	if (n>size_classes[i]) i++;
	return i;
}
```

其中经过试验可知`a_clz_32`这个函数返回的是n的最高位是32位中的倒数第几高位（最高位为0）。如`a_clz_32(1)=31`，`a_clz_32(2)=30`，`a_clz_32(4)=29`，以此类推。由此我们可以计算出不同大小的chunk对应于哪一个索引。这个部分实际上是将chunk的大小按照数组来进行分组，数组的每一项表示这一组中chunk右移4位的值不能超过多少。如索引为10的数组元素值为12，前面一个元素为10，则第10组chunk的大小范围应该在0x100-0x11F之间。同理，第11组chunk的大小范围为0x120-0x14F。

紧接着，上读写锁。后面`g = ctx.active[sc];`中的`ctx`指的是全局`__malloc_context`，其`active`数组长度与`size_classes`的相同，均为48。由此可见，<font color=red>**malloc_context将meta以管理的chunk大小进行分组，分组依据`size_classes`进行。**</font>

再往下的一个if语句有很多的判断条件，在某些条件成立时会修改`meta`指针的值，对整体影响不大，先向下看。

下面是一个循环。`first = mask&-mask;`是取`mask`的最低1位，即lowbit，这里的`avail_mask`实际就是选中的`meta`所管理的`group`中chunk的可用位，这里是通过可用位来查找第一个可用的chunk。内部的if-else语句是针对读写锁进行的检查，无需关注。如果在这里能够找到可用的chunk，则将chunk的索引保存到`idx`变量中。

如果在这个循环中没有找到合适的`idx`，则在循环外调用`alloc_slot`函数：

```c
static int alloc_slot(int sc, size_t req)
{
	uint32_t first = try_avail(&ctx.active[sc]);
	if (first) return a_ctz_32(first);

	struct meta *g = alloc_group(sc, req);
	if (!g) return -1;

	g->avail_mask--;
	queue(&ctx.active[sc], g);
	return 0;
}
```

其中`try_avail`函数尝试从该大小的`meta`中分配出一个可用的chunk并返回索引，如果该可用chunk不是由位于链首的`meta`所提供，则会将这个chunk所在的meta移动至链首。如果尝试分配成功，则这里直接返回。否则，后面调用`alloc_group`函数创建一个新的`meta`，创建成功后将其中的第一个chunk的索引（即0）返回，并将该`meta`放在链首。不论如何，最终只要能够执行到标号`success`，就一定能够获取到`idx`的值。

最后返回调用了`enframe`函数：

```c
static inline void *enframe(struct meta *g, int idx, size_t n, int ctr)
{
	size_t stride = get_stride(g);
	size_t slack = (stride-IB-n)/UNIT;
	unsigned char *p = g->mem->storage + stride*idx;
	unsigned char *end = p+stride-IB;
	// cycle offset within slot to increase interval to address
	// reuse, facilitate trapping double-free.
	int off = (p[-3] ? *(uint16_t *)(p-2) + 1 : ctr) & 255;
	assert(!p[-4]);
	if (off > slack) {
		size_t m = slack;
		m |= m>>1; m |= m>>2; m |= m>>4;
		off &= m;
		if (off > slack) off -= slack+1;
		assert(off <= slack);
	}
	if (off) {
		// store offset in unused header at offset zero
		// if enframing at non-zero offset.
		*(uint16_t *)(p-2) = off;
		p[-3] = 7<<5;
		p += UNIT*off;
		// for nonzero offset there is no permanent check
		// byte, so make one.
		p[-4] = 0;
	}
	*(uint16_t *)(p-2) = (size_t)(p-g->mem->storage)/UNIT;
	p[-3] = idx;
	set_size(p, end, n);
	return p;
}
```

这个函数的主要作用是从指定`meta`中取出指定索引的`chunk`。

## try_avail（`/src/malloc/mallocng/malloc.c, line 114`）
```c
static uint32_t try_avail(struct meta **pm)
{
	struct meta *m = *pm;
	uint32_t first;
	if (!m) return 0;
	uint32_t mask = m->avail_mask;
	if (!mask) {
		if (!m) return 0;
		if (!m->freed_mask) {
			dequeue(pm, m);
			m = *pm;
			if (!m) return 0;
		} else {
			m = m->next;
			*pm = m;
		}

		mask = m->freed_mask;

		// skip fully-free group unless it's the only one
		// or it's a permanently non-freeable group
		if (mask == (2u<<m->last_idx)-1 && m->freeable) {
			m = m->next;
			*pm = m;
			mask = m->freed_mask;
		}

		// activate more slots in a not-fully-active group
		// if needed, but only as a last resort. prefer using
		// any other group with free slots. this avoids
		// touching & dirtying as-yet-unused pages.
		if (!(mask & ((2u<<m->mem->active_idx)-1))) {
			if (m->next != m) {
				m = m->next;
				*pm = m;
			} else {
				int cnt = m->mem->active_idx + 2;
				int size = size_classes[m->sizeclass]*UNIT;
				int span = UNIT + size*cnt;
				// activate up to next 4k boundary
				while ((span^(span+size-1)) < 4096) {
					cnt++;
					span += size;
				}
				if (cnt > m->last_idx+1)
					cnt = m->last_idx+1;
				m->mem->active_idx = cnt-1;
			}
		}
		mask = activate_group(m);
		assert(mask);
		decay_bounces(m->sizeclass);
	}
	first = mask&-mask;
	m->avail_mask = mask-first;
	return first;
}
```

经过查找，这个函数只在`alloc_slot`这一处被调用，参数填的是一个`meta`链表的链首地址指针。

这个函数的参数是`meta`的二重指针，首先解引用一层获取到`meta`指针，如果这个`meta`指针无效，则返回0。

如果该`meta`存在，则取出其`avail_mask`。如果这个值为0，说明这个`meta`中已经没有可以用来分配的chunk了。这就进入到大if语句体内：

**`free_mask`与`avail_mask`相同，以比特位标识，每一个比特位表示一个chunk是否被释放。如被释放则比特值为1**。==如果`free_mask`为0==，而此时`avail_mask`也为1，说明这个`meta`中既不能分配`chunk`，也没有已经释放的`chunk`，这种情况下应该将这个`meta`从链表中移除，即调用`dequeue`函数脱链。脱链之后`pm`应该指向新的链首`meta`指针。如果链表中没有其他`meta`，就返回0。==如果`free_mask`不为0==，则找到下一个`meta`，并将链首修改为这个`meta`。

之后检查新链首`meta`中的chunk是否全部被释放且该`meta`不是不可释放的。这里的`mask == (2u<<m->last_idx)-1`就是在判断`free_mask`的所有有效的比特是不是全为1，如果是则跳过该chunk并再次修改链首的`meta`为下一个`meta`。

下面是`if (!(mask & ((2u<<m->mem->active_idx)-1)))`，`mask`是释放chunk的掩码，后面是全1的掩码，如果两者相与等于0，说明这个`meta`中没有chunk被释放。这个if语句是想要尽可能地使用已经有chunk被释放的`meta`而尽可能保留全部chunk都可以使用的`meta`，这样做的目的是减少脏页面的产生。内部判断如果这个`meta`不是仅有的一个`meta`，则使用下一个`meta`，否则没办法就只能使用这个“干净的”`meta`，else中所做的是在`group`中选择一个可以使用的chunk并设置相应控制位。

循环外面，是设置`meta`的`avail_mask`位，并返回将要分配出去的chunk索引。

## free（`/src/malloc/mallocng/free.c, line 101`）
```c
void free(void *p)
{
	if (!p) return;

	struct meta *g = get_meta(p);
	int idx = get_slot_index(p);
	size_t stride = get_stride(g);
	unsigned char *start = g->mem->storage + stride*idx;
	unsigned char *end = start + stride - IB;
	get_nominal_size(p, end);
	uint32_t self = 1u<<idx, all = (2u<<g->last_idx)-1;
	((unsigned char *)p)[-3] = 255;
	// invalidate offset to group header, and cycle offset of
	// used region within slot if current offset is zero.
	*(uint16_t *)((char *)p-2) = 0;

	// release any whole pages contained in the slot to be freed
	// unless it's a single-slot group that will be unmapped.
	if (((uintptr_t)(start-1) ^ (uintptr_t)end) >= 2*PGSZ && g->last_idx) {
		unsigned char *base = start + (-(uintptr_t)start & (PGSZ-1));
		size_t len = (end-base) & -PGSZ;
		if (len) {
			int e = errno;
			madvise(base, len, MADV_FREE);
			errno = e;
		}
	}

	// atomic free without locking if this is neither first or last slot
	for (;;) {
		uint32_t freed = g->freed_mask;
		uint32_t avail = g->avail_mask;
		uint32_t mask = freed | avail;
		assert(!(mask&self));
		if (!freed || mask+self==all) break;
		if (!MT)
			g->freed_mask = freed+self;
		else if (a_cas(&g->freed_mask, freed, freed+self)!=freed)
			continue;
		return;
	}

	wrlock();
	struct mapinfo mi = nontrivial_free(g, idx);
	unlock();
	if (mi.len) {
		int e = errno;
		munmap(mi.base, mi.len);
		errno = e;
	}
}
```

free用于释放chunk，首先需要找到该chunk所在的meta。这个功能是如何实现的呢？

每一个chunk的前面都保存着这个chunk在`group`中的索引，通过`get_slot_index`函数我们就可以知道：
```c
static inline int get_slot_index(const unsigned char *p)
{
	return p[-3] & 31;
}
```

可见索引值保存在索引为-3的位置。

对于索引值不为0的chunk，其还有一个`offset`保存在索引为-2的位置，它记录了当前chunk与第一个chunk首部的偏移量（右移4位的结果），因此通过这个值我们可以计算出该chunk所在`group`的首地址，由`group`中保存的`meta`地址找到`meta`。在`get_meta`函数中，找到`meta`后又找到了该`meta`所在的`meta_area`并进行了多项检查，防止`group`被伪造，如果我们想要通过伪造group来进行漏洞利用，就需要特别注意这里，这个我们以后再说。

```c
// /src/malloc/mallocng/meta.h, line 129
static inline struct meta *get_meta(const unsigned char *p)
{
	assert(!((uintptr_t)p & 15));
	int offset = *(const uint16_t *)(p - 2);
	int index = get_slot_index(p);
	if (p[-4]) {
		assert(!offset);
		offset = *(uint32_t *)(p - 8);
		assert(offset > 0xffff);
	}
	const struct group *base = (const void *)(p - UNIT*offset - UNIT);
	const struct meta *meta = base->meta;
	assert(meta->mem == base);
	assert(index <= meta->last_idx);
	assert(!(meta->avail_mask & (1u<<index)));
	assert(!(meta->freed_mask & (1u<<index)));
	const struct meta_area *area = (void *)((uintptr_t)meta & -4096);
	assert(area->check == ctx.secret);
	if (meta->sizeclass < 48) {
		assert(offset >= size_classes[meta->sizeclass]*index);
		assert(offset < size_classes[meta->sizeclass]*(index+1));
	} else {
		assert(meta->sizeclass == 63);
	}
	if (meta->maplen) {
		assert(offset <= meta->maplen*4096UL/UNIT - 1);
	}
	return (struct meta *)meta;
}
```

anyway，拿到了`meta`地址之后，通过`get_stride`函数获取到其中保存的chunk的大小。

后面定义了一系列的变量，看到第一个if语句：`if (((uintptr_t)(start-1) ^ (uintptr_t)end) >= 2*PGSZ && g->last_idx)`。前面一个判断条件是判断这个chunk的大小是否大于2页（`PGSZ`就是一页的大小），后面的则是判断这个chunk是否是由`malloc`通过`mmap`分配出来的。记得在分析`malloc`时提到当分配的chunk过大时会使用`mmap`直接分配且`last_idx`的值会被设置为0。这个if语句的主要目的是在释放一个较大的chunk时，将该chunk内含的一些页在内核层面上释放，这通过`madvice`系统调用来实现。

往后是一个循环。如果该chunk所在的`meta`的`free_mask`为0（表示当前的chunk是该`meta`中唯一一个释放的chunk）或该chunk释放后该`meta`中所有chunk都被释放，则跳出循环。否则修改`free_mask`位后返回。这里面的if-else语句不用管，因为涉及锁的问题，一般Linux系统都会加锁，因此else基本不会执行到。

如果释放的chunk既不是第一个，也不是最后一个，则会执行循环后面的代码。后面的调用`nontrivial_free`是关键操作，也是我们利用的突破点。

## nontrivial_free（`/src/malloc/mallocng/free.c, line 72`）
```c
static struct mapinfo nontrivial_free(struct meta *g, int i)
{
	uint32_t self = 1u<<i;
	int sc = g->sizeclass;
	uint32_t mask = g->freed_mask | g->avail_mask;

	if (mask+self == (2u<<g->last_idx)-1 && okay_to_free(g)) {
		// any multi-slot group is necessarily on an active list
		// here, but single-slot groups might or might not be.
		if (g->next) {
			assert(sc < 48);
			int activate_new = (ctx.active[sc]==g);
			dequeue(&ctx.active[sc], g);
			if (activate_new && ctx.active[sc])
				activate_group(ctx.active[sc]);
		}
		return free_group(g);
	} else if (!mask) {
		assert(sc < 48);
		// might still be active if there were no allocations
		// after last available slot was taken.
		if (ctx.active[sc] != g) {
			queue(&ctx.active[sc], g);
		}
	}
	a_or(&g->freed_mask, self);
	return (struct mapinfo){ 0 };
}
```

大多数的chunk释放请求都会执行到这个函数，第一个参数是`meta`，第二个是该`meta`内需要释放的chunk的索引。

`mask`是`free_mask`和`avail_mask`相或的结果，二者都是比特位标识的控制位。第一个判断`if (mask+self == (2u<<g->last_idx)-1 && okay_to_free(g))`中第一个条件指的是该`meta`中所有chunk是否都处于被使用或被释放的状态，第二个条件通过一个函数判断这个chunk是否可以释放，一般都为真。进入if语句体中判断该`meta`是否有下一个`meta`，如果有，将当前`meta`出链表，且如果该`meta`在出链表之前是链首且此时该链表中还有`meta`，则激活链首的`meta`。这里的激活（`activate_group`）是修改了`avail_mask`值，函数内强制要求该`meta`在修改前的`avail_mask`为0。然后调用`free_group`并返回。

如果进入了else语句体，说明`mask=0`，即`free_mask`和`avail_mask`均为0，该`meta`中所有chunk均正在被使用。如果该`meta`不是链首，则将该`meta`链入链表。最后更新`free_mask`并返回。

至此，有关于musl内存分配与释放的相关函数已经基本分析完毕，下一篇文章将重点介绍musl libc的利用方式。
