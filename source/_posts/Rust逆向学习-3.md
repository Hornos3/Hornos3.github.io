---
title: Rust逆向学习 (3)
date: 2023-10-27 18:18:15
categories:
- 学习笔记
- Rust逆向系列
---

在本文中，我们将跟随《Rust权威指南》的学习路线，继续进行Rust逆向的学习。

前两篇文章中，我们对猜数字这个程序进行了详细的逆向分析，学习了Rust元组、枚举类型、控制结构、函数调用规则等基础的Rust汇编语言层结构。本文将针对第3章——通用编程概念与第4章——认识所有权的部分内容，对书中提到的Rust特性进行逆向分析。一方面学习逆向，另一方面深入理解Rust语言本身。

# Reverse for Shadow

Rust逆向中有一个“隐藏”（Shadow）的概念。它指的是一个变量可以多次被`let`关键字修饰，第二次通过`let`关键字定义变量可以改变原变量的类型，或改变原变量的值。如书中的示例：

```rust
fn main(){
    let x = 5;
    let x = x + 1;
    let x = x * 2;
    ...
}
```

如此通过`let`关键字改变变量，与直接将变量用`mut`关键字声明的区别是可以在改变变量值的情况下保证变量的不可变性，还能够修改变量的类型。那么对于汇编语言层而言，在不改变变量类型的情况下，shadow特性是否会修改变量的保存位置？如果修改了变量类型，Rust又会将新的变量保存到什么位置呢？

## 0x01. 变量类型不修改

在没有修改变量类型的情况下，我们使用下面的代码示例进行测试：

```rust
pub fn main() {
    let x = 5;
    println!("{}", x); 
    let y = x + 2;
    let x = x + 1;
    println!("{} {}", x, y); 
}
```

这里每行语句的内容以及顺序是笔者通过调试选择的。

如果没有第一句`println!`语句，5这个值将会被保存到`eax`之中而不是一开始保存到内存，随后首先计算5+2将7保存到内存中某个位置。然后代码中通过`mov eax, 5`再将5赋值给x，计算5+1将6保存到内存中另一个位置。这是Rust编译器优化的结果，减少了内存交互。

而如果将第一个`println!`语句加上，情况则大不相同。因为根据我们前面文章的分析，`println!`需要首先获取若干个指针将第一个参数字符串中的中括号内容进行替换，因此在执行第一句`println!`前，`x`这个值必须要被保存到内存之中。使用网站编译后获取的部分汇编代码如下所示：

```masm
example::main:
        sub     rsp, 216
        mov     dword ptr [rsp + 12], 5
        lea     rax, [rsp + 12]
        mov     qword ptr [rsp + 200], rax
        mov     rax, qword ptr [rip + core::fmt::num::imp::<impl core::fmt::Display for i32>::fmt@GOTPCREL]
        mov     qword ptr [rsp + 208], rax
        mov     rcx, qword ptr [rsp + 200]
        mov     rax, qword ptr [rsp + 208]
        mov     qword ptr [rsp + 64], rcx
        mov     qword ptr [rsp + 72], rax
        lea     rdi, [rsp + 16]
        lea     rsi, [rip + .L__unnamed_4]
        mov     edx, 2
        lea     rcx, [rsp + 64]
        mov     r8d, 1
        call    core::fmt::Arguments::new_v1
        lea     rdi, [rsp + 16]
        call    qword ptr [rip + std::io::stdio::_print@GOTPCREL]
        mov     eax, dword ptr [rsp + 12]
        add     eax, 2
        mov     dword ptr [rsp + 8], eax
        seto    al
        test    al, 1
        jne     .LBB1_2
        mov     eax, dword ptr [rsp + 8]
        mov     dword ptr [rsp + 80], eax
        mov     eax, dword ptr [rsp + 12]
        inc     eax
        mov     dword ptr [rsp + 4], eax
        seto    al
        test    al, 1
        jne     .LBB1_4
        jmp     .LBB1_3
```

可以看到，5这个值首先被保存到了`[rsp+12]`这个地方。在输出后从这个地方取出值，+2，保存到`[rsp+8]`作为y。下面的`seto`指令指的是如果该指令执行时将溢出标志位（OF）的值保存到唯一一个操作数，也就是`al`中，这个主要是为了检查整数运算是否产生了数值溢出。

最后一部分，可以看到`eax`取出`[rsp+12]`这个地址的内容，+1，再保存到了另外一个地址空间`[rsp+4]`中。也就是说，这里Rust编译器选择不复用原来的内存空间，即使原来的内存空间在正常情况下已经不会再被访问。这造成了4字节的内存空间浪费。上述的代码是以无优化模式进行编译，没有进行优化。

不过当笔者在编译选项中添加`-C opt-level=3`，即最高级别优化时，具体的汇编代码虽然有所不同，原先的整数计算将不再进行溢出检查，但是`x`在shadow之后依然被保存到了不同的内存空间之中。

## 0x02. 变量类型修改

当变量类型修改时，有三种情况可能产生：新的变量类型占用的内存空间大小不变或更大或更小。

将上一节Rust代码中第二次使用`let`关键字定义的变量`x`从`i32`类型改变为`u32`类型，最终保存变量的内存空间排布与上一节完全相同，唯一不同的是溢出检查变成了`setb`命令，这个命令相当于是将进位/借位标志位赋值给寄存器，也就是检查无符号整数溢出的。

将上一节中的shadow变量`x`从`i32`类型改为`i16`类型，即将变量占用的内存空间变小，最终的结果依然是不会复用。改为`i64`类型也是如此。

由此可以得出结论：**Rust中一个变量将另一个变量隐藏后，无论新的变量类型是什么，都不会使用原来的变量内存空间保存新的变量。**

另外，当旧值为一个对象实例时，隐藏旧值后旧值将会自动删除。

经过思考，笔者认为Rust编译器这样做的原因是：有的时候一个变量将另一个变量隐藏时，新赋的值可能需要旧值参与运算。如果旧值为指针，那么此时新值不可能复用旧值的内存空间，旧值需要在新值赋值运算进行过程中一直保持不变，因此不复用内存空间在编译器设计上反而是最为简单的。另外，旧值在被隐藏后生命周期不会立即结束，针对其的引用依然能够使用，不过如果其所有权没有被夺走，隐藏后就无法获取其所有权了。

# Reverse for Array

Rust语言中有数组结构，对于数组的定义，Rust有较为方便的定义方式。当需要连续多个相同的值到相邻的数组索引时，可以使用分号定义，如`[5;5]`即为长度为5，5个索引值全为5的数组。

下面是`let x = [5; 10]`的反编译：

```masm
example::main:
        xor     eax, eax
        mov     qword ptr [rsp - 48], rax
.LBB0_1:
        mov     rax, qword ptr [rsp - 48]
        mov     qword ptr [rsp - 56], rax
        cmp     rax, 10
        jae     .LBB0_3
        mov     rax, qword ptr [rsp - 56]
        mov     dword ptr [rsp + 4*rax - 40], 5
        add     rax, 1
        mov     qword ptr [rsp - 48], rax
        jmp     .LBB0_1
.LBB0_3:
        ret
```

可以看到这里使用了一个循环结构来为各个索引赋值，而且经过测试发现，即使分号后面是2，Rust也会使用循环来定义。当优化等级为最高时，Rust编译器会通过`xmmword`赋值，一次可以赋值4个索引16个字节的内容。

# Reverse for Moving

对于一个对象实例，为防止其所有权被多个变量拥有，当另外一个变量尝试获取其所有权时，原先变量对其的所有权将被夺走。

```rust
fn main() {
    let x = String::from("I'm CoLin");
    println!("{}", x);
    let y = x;
    println!("{}", y);
}
```

对于上述代码，逆向出来的结果比较有趣，往下看。

```masm
sub     rsp, 280
mov     byte ptr [rsp + 231], 0
mov     byte ptr [rsp + 231], 1
lea     rsi, [rip + .L__unnamed_5]
lea     rdi, [rsp + 40]
mov     qword ptr [rsp + 16], rdi
mov     edx, 9
call    <alloc::string::String as core::convert::From<&str>>::from
```

上面是第一行`from`函数的逆向，可以看到`from`函数实际传参用了三个寄存器，`rdi`为目的`String`实例指针，`rsi`为字符串字面量地址，`rdx`为字符串长度。可以看到这里`[rsp+16]`保存了`String`实例的栈地址，这也就是变量`x`的保存位置。

后面略过`println!`看第三行：

```masm
mov     byte ptr [rsp + 231], 0
mov     rax, qword ptr [rsp + 56]
mov     qword ptr [rsp + 144], rax
movups  xmm0, xmmword ptr [rsp + 40]
movaps  xmmword ptr [rsp + 128], xmm0
lea     rax, [rsp + 128]
mov     qword ptr [rsp + 248], rax
lea     rax, [rip + <alloc::string::String as core::fmt::Display>::fmt]
mov     qword ptr [rsp + 256], rax
mov     rax, qword ptr [rsp + 248]
mov     qword ptr [rsp], rax
```

上面的代码将`String`实例占用的0x18大小内存空间（len、ptr、capacity）拷贝到了`[rsp+128]`的地方，一次使用`rax`拷贝，一次使用`xmm0`拷贝。随后，`[rsp+128]`这个指针被拷贝到`[rsp+248]`和`[rsp]`中，推测变量`y`就保存在`[rsp]`。

可以看到，`String`实例的移动会在栈上再创建一个`String`实例空间，但实际指向的字符串指针相同。不过有意思的是，Rust在后续并没有对变量`x`的内存空间进行任何处理。在`y`使用完之前，`x`不能将自身的实例删除，这样相当于也删除了`y`。但后续代码将不再使用变量`x`，即如果变量`y`在后续进行了更新，字符串地址发生了改变，变量`x`中保存的字符串地址也无法同步更新。不过Rust并没有将变量`x`的所有内容清空，而是继续保留在原来的位置。也就会说，变量`x`在移动操作完成之后，其保存的内容将永远是移动操作完成前一刻的内容，且此后正常情况下不再改变。不过没有清空就意味着有数据泄露的可能性。倘若Rust代码中有Unsafe部分代码被攻击者利用，这部分数据可就危险了。

下面的代码示例证明了变量移动后并没有被删除。两次输出的结果相同，均为llo，你可能会想：为什么已经被Rust废弃的变量依然能够具有引用。因为Rust中的废弃和生命周期走向结束并不相同，废弃仅仅代表后续代码无法对其进行访问，无法获取其所有权，但对于引用类型，还是可以使用的，但无法获取其所有权。

```rust
fn main() {
    let x: String = String::from("Hello");
    let y = &x[2..];
    println!("y = {}", y);
    let x = String::from("CoLin");
    println!("y = {}", y);
}
```

# Reverse for References and Borrows

引用和借用是Rust的重要特性，它允许一个变量在不获取所有权、不转移所有权的前提下使用某个变量。借用指的是通过引用传递参数给函数的方法。既然涉及函数传参，那么下面我们就来通过一个函数调用的示例对Rust的引用与借用进行源码和汇编层面的分析。

```rust
fn print_len(s: &String) {
    println!("the length of the string {} is: {}", s, s.len());
}

pub fn main() {
    let x = String::from("Hello");
    print_len(&x);
}
```

下面是`main`函数的部分反编译结果：

```masm
sub     rsp, 56
lea     rsi, [rip + .L__unnamed_6]
lea     rdi, [rsp + 16]
mov     qword ptr [rsp + 8], rdi
mov     edx, 5
call    <alloc::string::String as core::convert::From<&str>>::from
mov     rdi, qword ptr [rsp + 8]
call    example::print_len
```

可以看到，`main`函数直接将`x`的内存地址，即保存`String`实例地址的地址传递给`print_len`函数。这样子函数只需要通过获取该地址即可完成后续操作。

但是转念一想，如果子函数的参数不是引用，只是单纯的`String`，汇编代码层又会有什么不同呢？这样的例子总是存在的，当一个结构体非常庞大时，如果只通过寄存器与栈传递参数，未免有点太不优雅了。下面是将参数修改为`String`后`main`函数的部分反编译结果：

```rust
sub     rsp, 56
lea     rdi, [rsp + 8]
lea     rsi, [rip + .L__unnamed_6]
mov     edx, 5
call    <alloc::string::String as core::convert::From<&str>>::from
mov     rax, qword ptr [rsp + 8]
mov     qword ptr [rsp + 32], rax
mov     rax, qword ptr [rsp + 16]
mov     qword ptr [rsp + 40], rax
mov     rax, qword ptr [rsp + 24]
mov     qword ptr [rsp + 48], rax
lea     rdi, [rsp + 32]
call    example::print_len
```

可以看到，这里实际上传递到`print_len`函数的参数依然只有1个，但不同的是，`main`函数首先将`String`实例在栈上复制了一份，然后将复制那份的地址传了过去。另外，对于实例的删除位置不同，这是由Rust语言特性所决定的，不加引用意味着变量的所有权被转移到了子函数中，删除操作将在子函数中进行；加引用则所有权不转移，删除操作将在父函数中进行。不加引用的父函数操作与移动非常相似，只不过是没有将复制出来的实例地址放到栈的某处。想来其实也很合理，不加引用实际上就是完成了所有权的移动嘛。

# Reverse for String Slices

在Rust中，存在与Python类似的切片类型Slice，对于字符串而言，字符串字面量也可以看做是一个字符串切片。

考虑下面的Rust代码：

```rust
pub fn main() {
    let x = String::from("I'm CoLin");
    let y = &x[4..];
    println!("{}", y);
}
```

其部分反编译结果如下：
```masm
sub     rsp, 184
lea     rsi, [rip + .L__unnamed_5]
lea     rdi, [rsp + 40]
mov     qword ptr [rsp + 16], rdi
mov     edx, 9
call    <alloc::string::String as core::convert::From<&str>>::from
mov     rdi, qword ptr [rsp + 16]
mov     qword ptr [rsp + 80], 4
mov     rsi, qword ptr [rsp + 80]
lea     rdx, [rip + .L__unnamed_6]
call    <alloc::string::String as core::ops::index::Index<core::ops::range::RangeFrom<usize>>>::index
mov     qword ptr [rsp + 24], rdx
mov     qword ptr [rsp + 32], rax
```

可以看到，`String`实例指针，即变量`x`被保存在`[rsp+16]`的位置，随后程序调用了一个`core::ops::index::Index<core::ops::range::RangeFrom<usize>>>::index`方法，实际上也就是从字符串中获取切片的方法。该方法的参数按顺序依次为：`String`实例指针、切片的起始索引值、另外一个字符串切片，这第三个参数指向的是保存工程名的字符串，可以忽略。如果将Rust源码的`[4..]`改为`[4..7]`，会发现第三个参数变成了7，函数名变成了`Range`，如果是`[..4]`，则函数名为`RangeTo`，传参与`[4..]`完全相同。由此可见字符串取切片实际上有3个方法控制。返回值由两个寄存器传递，`rdx`保存的是长度，`rax`保存的是字符串指针。

# 总结

本文按照Rust权威指南的讲解顺序，向后学习了：
1. 变量隐藏在汇编层中的表现，隐藏后变量值不变
2. 数组变量在汇编层的数据结构，与C类似
3. 变量移动在汇编层与变量隐藏类似
4. 字符串切片相关操作在汇编层的实现