---
title: Rust逆向学习 (6)
date: 2023-11-26 17:54:46
categories:
- 学习笔记
- Rust逆向系列
---

# Reverse for String

上一篇文章简单分析了Vec变长数组的结构，今天来介绍String。实际上Rust的字符串类型对于我们并不陌生，在前面几篇文章的几乎任何一个示例中都可以找到它们。

我们曾经提到过，String类型在栈中占0x18大小，其中包括字符串的指针、字符串长度、字符串容量。看上去好像什么问题都没有，但如果你使用Python或C/C++开发过一些项目，你可能会遇到一些与字符串编码有关的问题。在C++中，由于需要考虑多种字符编码方式，字符被分为char、wchar_t、tchar等等，它们占用的字节数量还不相同，如果需要转换还需要使用特定的函数完成，对于一些需要进行编码转换的场景来说，稍有一个不注意，可能就是一串乱码怼在你的脸上，让人深恶痛绝。

但对于Rust而言，它规定，只要是我Rust写的程序，程序里面的所有字符串全都用UTF-8编码。这样就从根本上杜绝了编码转换的问题。

不过，这也产生了一些问题，其中影响最大的可能就是字符串不可索引了。由于使用UTF-8编码，对于不同的字符，其占用的字节数量可能不同，而Rust又不能将字符串单纯地看做单字节数组，因此Rust无法知道在一个既有中文又有英文又有其他语言的字符串中，第某个有效字符在字符串中的偏移地址到底是多少。对于一个Rust字符串，它的长度指的是占用的内存空间大小，因此对于1个中文字符组成的字符串，它的长度实际上是3。

下面介绍一下Rust中String的常用操作。

## `push_str` 与 `+`
在Rust中，`push_str`方法与运算符`+`都能够将一个字符串拼接到另一个字符串的后面。让我们看一下二者在汇编上有什么区别。

```rust
pub fn main(){
    let mut s = String::from("CoLin");
    s += "666";
    println!("{}", s);
}

example::main:
    sub     rsp, 152
    lea     rsi, [rip + .L__unnamed_7]
    lea     rdi, [rsp + 32]
    mov     qword ptr [rsp + 24], rdi
    mov     edx, 5
    call    <alloc::string::String as core::convert::From<&str>>::from
    mov     rdi, qword ptr [rsp + 24]
    lea     rsi, [rip + .L__unnamed_8]
    mov     edx, 3
    call    <alloc::string::String as core::ops::arith::AddAssign<&str>>::add_assign
    jmp     .LBB36_3
```

首先看下`+`。这里的`+`运算符实际上是调用了`String`的方法，`String`这个结构重载了`+`这个运算符。这与C++的运算符重载类似。在汇编中，显示出调用的函数为`<alloc::string::String as core::ops::arith::AddAssign<&str>>::add_assign`。实际上，Rust运算符重载的本质就是对“加”这个操作的Trait的impl，它与Rust中其他Trait并没有太大的区别，只有在使用的时候能够直接用运算符代替显式的方法调用罢了。需要注意的是，使用`+`运算符或`push_str`时，参数只能是字符串切片而不能是字符串，这是因为这两个方法不需要获取`String`的所有权，如果能够传入`String`，那么在这个函数执行后参数实际上就被销毁了，这当然是不希望看到的。另外，由于有解引用强制转换，我们传入`String`的引用也是被允许的。

对于上面的示例，一开始的字符串创建时，其指针指向的实际上并不是堆地址空间，而是字符串切片`CoLin`中保存的字符串常量地址。此时`s`中的字符串长度与字符串容量相同，均为5。随后使用`+`运算符增加字符串长度时，由于检测到字符串没有多余容量，因此会在堆空间分配一块更大的空间，将字符串拼接的结果保存到这块空间中，与`realloc`有相似之处。

```rust
pub fn main(){
    let mut s = String::from("CoLin");
    s.push_str("666");
    println!("{}", s);
}

example::main:
    sub     rsp, 152
    lea     rsi, [rip + .L__unnamed_7]
    lea     rdi, [rsp + 32]
    mov     qword ptr [rsp + 24], rdi
    mov     edx, 5
    call    <alloc::string::String as core::convert::From<&str>>::from
    mov     rdi, qword ptr [rsp + 24]
    lea     rsi, [rip + .L__unnamed_8]
    mov     edx, 3
    call    alloc::string::String::push_str
    jmp     .LBB36_3
```

上面是使用`push_str`的汇编结果，可以看到只有函数调用发生了改变，甚至二者传入的参数都是一样的，分别是：原来的`String`栈地址，看做`this`、字符串指针、字符串长度。

## `format!`
当需要拼接的字符串较多，或符合某种格式时，使用`format!`宏是一种更加简洁的方法。对于`format!`宏，我们实际上已经分析过了，因为`println!`的前半部分就是`format!`，也就是`core::fmt::Arguments::new_v1`方法的调用流程。这个在第一篇文章中已经介绍过了，这里不再赘述。

## `bytes`方法
这个方法返回的是字符串中的所有字节。不过需要注意的是这个方法返回的是一个不可变借用，除非这个方法的返回值被删除，否则字符串不能修改。

```rust
pub fn main(){
    let s = String::from("CoLin");
    let t = String::from("666");
    let mut u = format!("{s} is {t}");
    let mut x = u.bytes();
    for b in x{
        println!("{}", b);
    }
}
```

```masm
...
.LBB27_9:
    mov     rax, qword ptr [rsp + 216]
    mov     qword ptr [rsp + 192], rax
    movups  xmm0, xmmword ptr [rsp + 200]
    movaps  xmmword ptr [rsp + 176], xmm0
    lea     rdi, [rsp + 176]
    call    <alloc::string::String as core::ops::deref::Deref>::deref
    mov     qword ptr [rsp + 64], rdx
    mov     qword ptr [rsp + 72], rax
    jmp     .LBB27_12
    ...
.LBB27_12:
    mov     rsi, qword ptr [rsp + 64]
    mov     rdi, qword ptr [rsp + 72]
    call    core::str::<impl str>::bytes
    mov     qword ptr [rsp + 48], rdx
    mov     qword ptr [rsp + 56], rax
    jmp     .LBB27_13
.LBB27_13:
    mov     rsi, qword ptr [rsp + 48]
    mov     rdi, qword ptr [rsp + 56]
    mov     rax, qword ptr [rip + <I as core::iter::traits::collect::IntoIterator>::into_iter@GOTPCREL]
    call    rax
    mov     qword ptr [rsp + 32], rdx
    mov     qword ptr [rsp + 40], rax
    jmp     .LBB27_14
.LBB27_14:
    mov     rax, qword ptr [rsp + 32]
    mov     rcx, qword ptr [rsp + 40]
    mov     qword ptr [rsp + 304], rcx
    mov     qword ptr [rsp + 312], rax
.LBB27_15:
    lea     rdi, [rsp + 304]
    call    <core::str::iter::Bytes as core::iter::traits::iterator::Iterator>::next
    mov     byte ptr [rsp + 30], dl
    mov     byte ptr [rsp + 31], al
    jmp     .LBB27_16
```

可以看到，上面的代码中，首先对`String`类型进行`deref`解引用获取字符串切片，然后调用`bytes`方法，这个方法的第一个参数是字符串指针，第二个参数是字符串长度。这个方法的返回值有两个，`rax`为字符串开头的地址，`rdx`为字符串末尾的地址。后面是`into_iter`方法，这个方法的参数和返回值一样。下面就是正常的迭代器迭代流程，在前面的文章中有分析。

## `chars`方法

这个方法返回的是字符串中所有字符的集合。由于字符串中每个字符占用的字节数量可能不同，那么如何表示字符的集合就很值得我们研究了。

```rust
pub fn main(){
    let s = String::from("CoLin");
    let t = String::from("太6了!");
    let mut u = format!("{s} {t}");
    let mut x = u.chars();
    for b in x{
        println!("{}", b);
    }
}
```

```masm
.LBB27_9:
    mov     rax, qword ptr [rsp + 216]
    mov     qword ptr [rsp + 192], rax
    movups  xmm0, xmmword ptr [rsp + 200]
    movaps  xmmword ptr [rsp + 176], xmm0
    lea     rdi, [rsp + 176]
    call    <alloc::string::String as core::ops::deref::Deref>::deref
    mov     qword ptr [rsp + 64], rdx
    mov     qword ptr [rsp + 72], rax
    jmp     .LBB27_12
    ...
.LBB27_12:
    mov     rsi, qword ptr [rsp + 64]
    mov     rdi, qword ptr [rsp + 72]
    call    core::str::<impl str>::chars
    mov     qword ptr [rsp + 48], rdx
    mov     qword ptr [rsp + 56], rax
    jmp     .LBB27_13
.LBB27_13:
    mov     rsi, qword ptr [rsp + 48]
    mov     rdi, qword ptr [rsp + 56]
    mov     rax, qword ptr [rip + <I as core::iter::traits::collect::IntoIterator>::into_iter@GOTPCREL]
    call    rax
    mov     qword ptr [rsp + 32], rdx
    mov     qword ptr [rsp + 40], rax
    jmp     .LBB27_14
.LBB27_14:
    mov     rax, qword ptr [rsp + 32]
    mov     rcx, qword ptr [rsp + 40]
    mov     qword ptr [rsp + 304], rcx
    mov     qword ptr [rsp + 312], rax
.LBB27_15:
    lea     rdi, [rsp + 304]
    call    <core::str::iter::Chars as core::iter::traits::iterator::Iterator>::next
    mov     dword ptr [rsp + 28], eax
    jmp     .LBB27_16
...
```

可以看到，这里与`bytes`类似。经过调试发现，`chars`方法返回的也是两个地址，开始地址和结尾地址。因为`chars`返回的类型是迭代器，所以Rust可以通过调用`next`方法动态地判断下一个字符占用的字节数量，因此不需要返回每一个字符占用的字节数。但是，我们有方法让Rust返回**真正的字符数组**，那就是使用`collect`方法将迭代器转换为`Vec`：

```rust
pub fn main(){
    let s = String::from("CoLin");
    let t = String::from("太6了!");
    let mut u = format!("{s} {t}");
    let mut x = u.chars();
    let y: Vec<char> = x.collect();
    println!("{}", y[0]);
}
```

```text
pwndbg> tele 0x5555555b6c00
00:0000│  0x5555555b6c00 ◂— 0x6f00000043 /* 'C' */
01:0008│  0x5555555b6c08 ◂— 0x690000004c /* 'L' */
02:0010│  0x5555555b6c10 ◂— 0x200000006e /* 'n' */
03:0018│  0x5555555b6c18 ◂— 0x360000592a /* '*Y' */
04:0020│  0x5555555b6c20 ◂— 0x2100004e86
```

`collect`方法在一个栈地址中保存了一个堆地址，而这个堆地址的内容就如上面所示。可以看到，Rust为每一个字符分配了4个字节的空间，虽然大多数字符都占不到4个字节，但是为了索引的需要，Rust必须分配一个足够容纳所有字符的空间，也就是UTF-8的一个字符可能占用的最大字节数。

# 总结
本文我们学习了：

1. 字符数组在内存中的结构
2. 字符串遍历过程的逆向
3. Rust字符串的相关知识