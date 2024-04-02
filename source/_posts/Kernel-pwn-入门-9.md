---
title: Kernel pwn 入门 (9)
date: 2024-02-07 11:25:46
categories:
- 学习笔记
- kernel pwn 系列
---
本文笔者计划简要分析kmalloc以及kfree的主要分支流程。

注：本文分析使用的Linux版本为6.7.4.

# kmalloc
```c
static __always_inline __alloc_size(1) void *kmalloc(size_t size, gfp_t flags)
{
	if (__builtin_constant_p(size) && size) {
		unsigned int index;

		if (size > KMALLOC_MAX_CACHE_SIZE)
			return kmalloc_large(size, flags);

		index = kmalloc_index(size);
		return kmalloc_trace(
				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
				flags, size);
	}
	return __kmalloc(size, flags);
}
```

kmalloc有两个参数，第一个为要分配的大小，第二个为分配选项。根据Linux kernel源代码注释，分配选项主要用于确定分配方式，最为常用的是GFP_KERNEL，可能会出现一定的sleep；另外还有GFP_NOWAIT（必须立即分配）与GFP_ATOMIC（必须立即分配且可能使用紧急内存池-emergency pools），除了3个主选项外还有几个副选项，可用于内核在分配后立即清空这块空间内的内容（__GFP_ZERO，实际上kzalloc也是调用的kmalloc，加上了这个选项），忽略分配失败警告等。

这个函数内首先有一个判断，`__builtin_constant_p`是一个gcc的内置函数，用于判断一个值是否是常量，使用这个函数主要是用于优化函数性能。在函数内部判断size，如果大于`KMALLOC_MAX_CACHE_SIZE`（x64中为8192）则转向分配大块空间的函数。随后调用`kmalloc_index`函数根据size判断需要在哪个`kmem_cache`里面完成分配工作。不同的`kmem_cache`中保存的内存块size可能不同，但一个`kmem_cache`中可分配的内存块size相同。由于这些`kmem_cache`在内核启动时完成初始化，因此索引是固定的。这里`kmalloc_caches`是一个二维的`kmem_cache*`数组，第一维表示的是内存块的类型，有通用类型、专用于DMA类型等多种类型。第二维表示索引。

# kmalloc_trace
```c
void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
{
	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
					    size, _RET_IP_);

	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);

	ret = kasan_kmalloc(s, ret, size, gfpflags);
	return ret;
}
EXPORT_SYMBOL(kmalloc_trace);
```
这里最后有一个`kasan_kmalloc`，它的主要功能是缓解针对内核内存管理器的攻击，没有对要分配的内存块本身进行任何操作，这里跳过。分配内存的主要逻辑在`__kmem_cache_alloc_node -> slab_alloc_node`中。

# slab_alloc_node
```c
static __always_inline void *
slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
		int nodeid, size_t orig_size, unsigned long caller)
{
	unsigned long save_flags;
	void *objp;
	struct obj_cgroup *objcg = NULL;
	bool init = false;

	flags &= gfp_allowed_mask;
	cachep = slab_pre_alloc_hook(cachep, lru, &objcg, 1, flags);
	if (unlikely(!cachep))
		return NULL;

	objp = kfence_alloc(cachep, orig_size, flags);
	if (unlikely(objp))
		goto out;

	local_irq_save(save_flags);
	objp = __do_cache_alloc(cachep, flags, nodeid);
	local_irq_restore(save_flags);
	objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);
	prefetchw(objp);
	init = slab_want_init_on_alloc(flags, cachep);

out:
	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
				cachep->object_size);
	return objp;
}
```

这个函数内部首先调用了一个`slab_pre_alloc_hook`，这是一个预处理钩子函数，查看源码发现主要完成一些检查工作，并不重要，后面的`slab_post_alloc_hook`是后处理钩子函数。这里核心的处理函数是`__do_cache_alloc`，它是所有内核内存分配函数都需要调用的。

# __do_cache_alloc
```c
static __always_inline void *
__do_cache_alloc(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	void *objp = NULL;
	int slab_node = numa_mem_id();

	if (nodeid == NUMA_NO_NODE) {
		if (current->mempolicy || cpuset_do_slab_mem_spread()) {
			objp = alternate_node_alloc(cachep, flags);
			if (objp)
				goto out;
		}
		/*
		 * Use the locally cached objects if possible.
		 * However ____cache_alloc does not allow fallback
		 * to other nodes. It may fail while we still have
		 * objects on other nodes available.
		 */
		objp = ____cache_alloc(cachep, flags);
		nodeid = slab_node;
	} else if (nodeid == slab_node) {
		objp = ____cache_alloc(cachep, flags);
	} else if (!get_node(cachep, nodeid)) {
		/* Node not bootstrapped yet */
		objp = fallback_alloc(cachep, flags);
		goto out;
	}

	/*
	 * We may just have run out of memory on the local node.
	 * ____cache_alloc_node() knows how to locate memory on other nodes
	 */
	if (!objp)
		objp = ____cache_alloc_node(cachep, flags, nodeid);
out:
	return objp;
}
```
在默认情况下，`CONFIG_NUMA`开启，调用的是上面的函数，若没有开启则用于表示NUMA节点的参数node无效，转而直接调用`____cache_alloc`函数。NUMA节点这个参数是Linux 6.1才添加到`__do_cache_alloc`函数中的。

> NUMA 全称 Non-Uniform Memory Access，译为“非一致性内存访问”。这种构架下，不同的内存器件和CPU核心从属不同的 Node，每个 Node 都有自己的集成内存控制器（IMC，Integrated Memory Controller）。

通过kmalloc调用传入的node参数实际上总为-1，即让系统自行决定节点，也就是走`if (nodeid == NUMA_NO_NODE)`内部。不过无论如何最终都需要调用`____cache_alloc`。

# ____cache_alloc

```c
static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *objp;
	struct array_cache *ac;

	check_irq_off();

	ac = cpu_cache_get(cachep);
	if (likely(ac->avail)) {
		ac->touched = 1;
		objp = ac->entry[--ac->avail];

		STATS_INC_ALLOCHIT(cachep);
		goto out;
	}

	STATS_INC_ALLOCMISS(cachep);
	objp = cache_alloc_refill(cachep, flags);
	/*
	 * the 'ac' may be updated by cache_alloc_refill(),
	 * and kmemleak_erase() requires its correct value.
	 */
	ac = cpu_cache_get(cachep);

out:
	/*
	 * To avoid a false negative, if an object that is in one of the
	 * per-CPU caches is leaked, we need to make sure kmemleak doesn't
	 * treat the array pointers as a reference to the object.
	 */
	if (objp)
		kmemleak_erase(&ac->entry[ac->avail]);
	return objp;
}
```

关于这个函数的解释，可以参考[资料](https://zhuanlan.zhihu.com/p/358891862)，这里添加一些方便理解的补充。

`cpu_cache_get`返回的是`kmem_cache`中定义的CPU专用的空闲对象链表。不过这个结构说是链表，实际上它还是通过数组的形式实现的，从上面的代码可以看出，`objp = ac->entry[--ac->avail];`这条语句表明这里的空闲的obj是直接通过下标索引的，相比传统链表大大提高效率。当这里没有可用的对象时，会调用`cache_alloc_refill`继续查找可用对象。

# cache_alloc_refill
```c
static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
	int batchcount;
	struct kmem_cache_node *n;
	struct array_cache *ac, *shared;
	int node;
	void *list = NULL;
	struct slab *slab;

	check_irq_off();
	node = numa_mem_id();

	ac = cpu_cache_get(cachep);
	batchcount = ac->batchcount;
	if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
		/*
		 * If there was little recent activity on this cache, then
		 * perform only a partial refill.  Otherwise we could generate
		 * refill bouncing.
		 */
		batchcount = BATCHREFILL_LIMIT;
	}
	n = get_node(cachep, node);

	BUG_ON(ac->avail > 0 || !n);
	shared = READ_ONCE(n->shared);
	if (!n->free_objects && (!shared || !shared->avail))
		goto direct_grow;

	raw_spin_lock(&n->list_lock);
	shared = READ_ONCE(n->shared);

	/* See if we can refill from the shared array */
	if (shared && transfer_objects(ac, shared, batchcount)) {
		shared->touched = 1;
		goto alloc_done;
	}

	while (batchcount > 0) {
		/* Get slab alloc is to come from. */
		slab = get_first_slab(n, false);
		if (!slab)
			goto must_grow;

		check_spinlock_acquired(cachep);

		batchcount = alloc_block(cachep, ac, slab, batchcount);
		fixup_slab_list(cachep, n, slab, &list);
	}

must_grow:
	n->free_objects -= ac->avail;
alloc_done:
	raw_spin_unlock(&n->list_lock);
	fixup_objfreelist_debug(cachep, &list);

direct_grow:
	if (unlikely(!ac->avail)) {
		/* Check if we can use obj in pfmemalloc slab */
		if (sk_memalloc_socks()) {
			void *obj = cache_alloc_pfmemalloc(cachep, n, flags);

			if (obj)
				return obj;
		}

		slab = cache_grow_begin(cachep, gfp_exact_node(flags), node);

		/*
		 * cache_grow_begin() can reenable interrupts,
		 * then ac could change.
		 */
		ac = cpu_cache_get(cachep);
		if (!ac->avail && slab)
			alloc_block(cachep, ac, slab, batchcount);
		cache_grow_end(cachep, slab);

		if (!ac->avail)
			return NULL;
	}
	ac->touched = 1;

	return ac->entry[--ac->avail];
}
```

注意这里的`if (!n->free_objects && (!shared || !shared->avail))`这条语句，这里的目的是检查所有CPU共享的空闲链表中是否有可分配的对象，以及检查该节点中是否有空闲对象（`free_objects`指的是一个`kmem_cache_node`中的空闲对象数量），如果都没有则需要调用伙伴系统分配空间。

随后调用`transfer_objects`尝试从共享空间中将`batchcount`个空闲对象批量移动到CPU专属空闲链表中。后面直接从这里进行分配。而如果共享空间中没有可用对象，则会调用`get_first_slab`获取空闲slab，调用`alloc_block`将空闲slab上的空闲对象转移到CPU专属空闲链表中进行后续分配。

从上面的分析可以看到，无论是CPU专属空闲对象链表，还是NUMA节点全CPU共享空闲对象链表，它们只是起到了一个临时保存空闲对象的作用，并不会影响内核决定使用哪一个slab。

---

以上就是对kmalloc的主要流程分析，下面是kfree的分析。

---

# kfree
```c
void kfree(const void *object)
{
	struct folio *folio;
	struct slab *slab;
	struct kmem_cache *s;

	trace_kfree(_RET_IP_, object);

	if (unlikely(ZERO_OR_NULL_PTR(object)))
		return;

	folio = virt_to_folio(object);
	if (unlikely(!folio_test_slab(folio))) {
		free_large_kmalloc(folio, (void *)object);
		return;
	}

	slab = folio_slab(folio);
	s = slab->slab_cache;
	__kmem_cache_free(s, (void *)object, _RET_IP_);
}
EXPORT_SYMBOL(kfree);
```

```c
void __kmem_cache_free(struct kmem_cache *cachep, void *objp,
		       unsigned long caller)
{
	__do_kmem_cache_free(cachep, objp, caller);
}
```

```c
static __always_inline
void __do_kmem_cache_free(struct kmem_cache *cachep, void *objp,
			  unsigned long caller)
{
	unsigned long flags;

	local_irq_save(flags);
	debug_check_no_locks_freed(objp, cachep->object_size);
	if (!(cachep->flags & SLAB_DEBUG_OBJECTS))
		debug_check_no_obj_freed(objp, cachep->object_size);
	__cache_free(cachep, objp, caller);
	local_irq_restore(flags);
}
```

```c
static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
					 unsigned long caller)
{
	bool init;

	memcg_slab_free_hook(cachep, virt_to_slab(objp), &objp, 1);

	if (is_kfence_address(objp)) {
		kmemleak_free_recursive(objp, cachep->flags);
		__kfence_free(objp);
		return;
	}

	/*
	 * As memory initialization might be integrated into KASAN,
	 * kasan_slab_free and initialization memset must be
	 * kept together to avoid discrepancies in behavior.
	 */
	init = slab_want_init_on_free(cachep);
	if (init && !kasan_has_integrated_init())
		memset(objp, 0, cachep->object_size);
	/* KASAN might put objp into memory quarantine, delaying its reuse. */
	if (kasan_slab_free(cachep, objp, init))
		return;

	/* Use KCSAN to help debug racy use-after-free. */
	if (!(cachep->flags & SLAB_TYPESAFE_BY_RCU))
		__kcsan_check_access(objp, cachep->object_size,
				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);

	___cache_free(cachep, objp, caller);
}
```

```c
void ___cache_free(struct kmem_cache *cachep, void *objp,
		unsigned long caller)
{
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();
	kmemleak_free_recursive(objp, cachep->flags);
	objp = cache_free_debugcheck(cachep, objp, caller);

	/*
	 * Skip calling cache_free_alien() when the platform is not numa.
	 * This will avoid cache misses that happen while accessing slabp (which
	 * is per page memory  reference) to get nodeid. Instead use a global
	 * variable to skip the call, which is mostly likely to be present in
	 * the cache.
	 */
	if (nr_online_nodes > 1 && cache_free_alien(cachep, objp))
		return;

	if (ac->avail < ac->limit) {
		STATS_INC_FREEHIT(cachep);
	} else {
		STATS_INC_FREEMISS(cachep);
		cache_flusharray(cachep, ac);
	}

	if (sk_memalloc_socks()) {
		struct slab *slab = virt_to_slab(objp);

		if (unlikely(slab_test_pfmemalloc(slab))) {
			cache_free_pfmemalloc(cachep, slab, objp);
			return;
		}
	}

	__free_one(ac, objp);
}
```

在`kfree`中首先要找到要被释放的对象所属的`kmem_cache`。在`__cache_free`中有一些有关kasan的钩子函数等，用于对释放的对象进行隔离等操作，这里忽略。

直接跟踪来到`___cache_free`。这里有关键的判断：`ac->avail < ac->limit`，如果条件为真，则表示CPU专属空闲对象链表还有可以存放对象的空间，就可以直接调用`__free_one`。如果为假，则需要首先调用`cache_flusharray`对数组进行清理。

# __free_one

```c
/* &alien->lock must be held by alien callers. */
static __always_inline void __free_one(struct array_cache *ac, void *objp)
{
	/* Avoid trivial double-free. */
	if (IS_ENABLED(CONFIG_SLAB_FREELIST_HARDENED) &&
	    WARN_ON_ONCE(ac->avail > 0 && ac->entry[ac->avail - 1] == objp))
		return;
	ac->entry[ac->avail++] = objp;
}
```

这里的逻辑就很简单了，更新avail，添加对象即可。在此之前有对于double free的检查。但这里的double free检查不严格，仅仅检查了上一个free到这个数组的对象是否也是这个对象。如果这个对象第一次free后又有其他对象被free到了这里，那么这里的double free检查会报假阳性。