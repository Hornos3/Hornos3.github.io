---
title: Rust逆向学习 (5)
date: 2023-11-10 20:24:50
categories:
- 学习笔记
- Rust逆向系列
---

本文将对Rust中的通用集合类型——动态数组`Vec`进行学习，对应参考书中的第8章。

# Reverse for Vec
`Vec`是Rust中的动态数据结构，与C++中的`vector`功能类似。实际上Rust中的`String`就是一个特殊的`Vec`，这可以通过查看Rust的内核代码证实。

## vec! 与 添加元素

`vec!`是一个宏，用于快速初始化数组元素。

```rust
pub fn main() {
    let mut x = vec![1, 2, 3];
    x.push(4);
    println!("{}", x.len());
}
```

```masm
example::main:
        sub     rsp, 168
        mov     edi, 12
        mov     esi, 4
        call    alloc::alloc::exchange_malloc
        mov     qword ptr [rsp + 32], rax
        and     rax, 3
        cmp     rax, 0
        sete    al
        test    al, 1
        jne     .LBB31_1
        jmp     .LBB31_2
.LBB31_1:
        mov     rsi, qword ptr [rsp + 32]
        mov     dword ptr [rsi], 1
        mov     dword ptr [rsi + 4], 2
        mov     dword ptr [rsi + 8], 3
        mov     rax, qword ptr [rip + alloc::slice::<impl [T]>::into_vec@GOTPCREL]
        lea     rdi, [rsp + 40]
        mov     qword ptr [rsp + 24], rdi
        mov     edx, 3
        call    rax
        mov     rdi, qword ptr [rsp + 24]
        mov     rax, qword ptr [rip + alloc::vec::Vec<T,A>::push@GOTPCREL]
        mov     esi, 4
        call    rax
        jmp     .LBB31_5
```

第一段中，我们可以发现`vec!`宏执行时，汇编实际上执行的是什么操作。首先调用了一个`exchange_malloc`函数，传入第一个参数为12，第二个参数为4，根据源码可以判断出，第一个参数应该是总的内存分配字节数量，第二个参数为每个元素的字节数量。这个函数的返回值是`Box<[i32]>`，这是Rust中的一个智能指针类型，能够在堆分配内存并管理生命周期，指针保存在栈中。后面对返回值进行了判断，如果内存分配失败则会输出错误信息。Box的特性如下，参考资料：[传送门](https://blog.csdn.net/qq_21484461/article/details/131731732?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522169961961316800226578680%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=169961961316800226578680&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-2-131731732-null-null.142^v96^control&utm_term=Rust%20Box&spm=1018.2226.3001.4187)

> 在栈上存储指针，指向堆上的数据。\
> 在转移所有权时负责释放堆上的内存。\
> 大小固定，适用于已知大小的类型。\
> 只能有一个所有者，不可共享引用。

随后，代码中以`rsi`作为指针，初始化了3个数组元素。初始化完成后调用`into_vec`将`Box`转换为`Vec`类型。可以说，上面源码中的`vec!`宏基本等同于：

```rust
let mut b: Box<[i32]> = Box::new([1, 2, 3]);
let mut x = b.into_vec();
```

经过调试发现，调用`into_vec`后，`Vec`实例中的指针与`Box`的指针相同，但现在`Box`类型已经不复存在了，其所有权已经被转移到`Vec`中。

随后，程序调用了`push`方法扩充了`Vec`的空间，但原先的地址空间不足以容纳新的元素，因此需要将原先的内存空间释放掉再重新分配。考虑到Rust在汇编层调用的是libc，所以堆管理那套本质上还是`malloc`、`free`那些函数，与C/C++相同，方便进行分析。

在动态数组大小发生改变时，如果存在一个已有的对某个元素的引用，那么大小改变后该引用可能会指向被释放的空间，这是Rust所不能允许的，这就要回到所有权规则的定义。考虑存在不可变引用的情况，如果此时需要增加数组的长度，那么首先在增加前必然需要获取该动态数组的可变引用，而所有权规则不允许一个实例同时存在可变引用和不可变引用，因此导致编译失败。

## 元素访问
Rust中有两种方式访问动态数组中的元素，第一种是直接通过下标访问：

```rust
pub fn main() {
    let mut x = vec![1, 2, 3];
    x.push(4);
    let y = &x[2];
    println!("{}", y);
}
```

```masm
.LBB33_5:
        lea     rdx, [rip + .L__unnamed_6]
        mov     rax, qword ptr [rip + <alloc::vec::Vec<T,A> as core::ops::index::Index<I>>::index@GOTPCREL]
        lea     rdi, [rsp + 40]
        mov     esi, 2
        call    rax
        mov     qword ptr [rsp + 16], rax
        jmp     .LBB33_6
```

这是加`&`的汇编代码，第一个参数就是`Vec`实例地址，第二个参数是索引值，第三个参数疑似指向工程名的字符串切片，推测是在索引越界后输出错误信息用的。这里实际上是调用了`index`方法进行索引。这个`index`函数的返回值是一个地址，如果加了`&`，则直接对指针进行操作，如果不加则会直接解引用。

```masm
; 不加&
.LBB32_6:
        mov     rax, qword ptr [rsp + 16]
        mov     eax, dword ptr [rax]
        mov     dword ptr [rsp + 68], eax
        lea     rax, [rsp + 68]

; 加&
.LBB33_6:
        mov     rax, qword ptr [rsp + 16]
        mov     qword ptr [rsp + 64], rax
        lea     rax, [rsp + 64]
```

第二种元素访问的方法是使用`get`方法：

```rust
pub fn main() {
    let mut x = vec![1, 2, 3];
    x.push(4);
    let y = x.get(2).unwrap();
    println!("{}", y);
}
```

```masm
.LBB35_5:
        mov     rax, qword ptr [rip + <alloc::vec::Vec<T,A> as core::ops::deref::Deref>::deref@GOTPCREL]
        lea     rdi, [rsp + 72]
        call    rax
        mov     qword ptr [rsp + 40], rdx
        mov     qword ptr [rsp + 48], rax
        jmp     .LBB35_6
.LBB35_6:
        mov     rsi, qword ptr [rsp + 40]
        mov     rdi, qword ptr [rsp + 48]
        mov     rax, qword ptr [rip + core::slice::<impl [T]>::get@GOTPCREL]
        mov     edx, 2
        call    rax
        mov     qword ptr [rsp + 32], rax
        jmp     .LBB35_7
.LBB35_7:
        mov     rdi, qword ptr [rsp + 32]
        lea     rsi, [rip + .L__unnamed_7]
        mov     rax, qword ptr [rip + core::option::Option<T>::unwrap@GOTPCREL]
        call    rax
        mov     qword ptr [rsp + 24], rax
        jmp     .LBB35_8
```

使用`get`函数前，会首先调用`deref`方法解引用获取动态数组类型中保存的定长数组实例，随后对这个实例使用`get`方法获取`Option<T>`实例。可见如果使用`get`方法进行数组的越界访问，那么`get`方法返回后不会立即`panic!`退出。

## 元素遍历

对于动态数组，要遍历数组中的元素，只需要使用for循环即可完成。但Rust源码看着简单，实际在汇编层完成的工作可不少。

```rust
pub fn main() {
    let mut x = vec![1, 2, 3];
    x.push(4);
    for i in x {
        println!("{}", i);
    }
}
```

```masm
.LBB46_5:
        mov     byte ptr [rsp + 247], 0
        mov     rax, qword ptr [rsp + 56]
        mov     qword ptr [rsp + 112], rax
        movups  xmm0, xmmword ptr [rsp + 40]
        movaps  xmmword ptr [rsp + 96], xmm0
        mov     rax, qword ptr [rip + <alloc::vec::Vec<T,A> as core::iter::traits::collect::IntoIterator>::into_iter@GOTPCREL]
        lea     rdi, [rsp + 64]
        lea     rsi, [rsp + 96]
        call    rax
        jmp     .LBB46_6
.LBB46_6:
        mov     rax, qword ptr [rsp + 64]
        mov     qword ptr [rsp + 128], rax
        mov     rax, qword ptr [rsp + 72]
        mov     qword ptr [rsp + 136], rax
        mov     rax, qword ptr [rsp + 80]
        mov     qword ptr [rsp + 144], rax
        mov     rax, qword ptr [rsp + 88]
        mov     qword ptr [rsp + 152], rax
.LBB46_7:
        mov     rax, qword ptr [rip + <alloc::vec::into_iter::IntoIter<T,A> as core::iter::traits::iterator::Iterator>::next@GOTPCREL]
        lea     rdi, [rsp + 128]
        call    rax
        mov     dword ptr [rsp + 16], edx
        mov     dword ptr [rsp + 20], eax
        jmp     .LBB46_10
```

上面即为`for`循环的其中一段，其中`[rsp+40]`是`Vec`实例的地址。首先可以看到程序将`Vec`实例复制了一份，随后调用了`into_iter`方法获取了一个迭代器实例，该方法的第一个参数为需要初始化迭代器的地址，第二个参数为复制的`Vec`的地址。这个方法是可以单独调用的，返回一个迭代器：`fn into_iter(self) -> Self::IntoIter`。从下面的汇编代码（复制到`[rsp+128]`）可以得知，这个迭代器实例在栈中的大小为0x20。下面是这个迭代器在调试时获取的最初状态：

```text
08:0040│ rax rcx 0x7fffffffd840 —▸ 0x5555555b4ba0 ◂— 0x200000001
09:0048│         0x7fffffffd848 ◂— 0x6
0a:0050│         0x7fffffffd850 —▸ 0x5555555b4ba0 ◂— 0x200000001
0b:0058│         0x7fffffffd858 —▸ 0x5555555b4bb0 ◂— 0x0
```

其中第1个和第3个字保存的都是数组的起始地址，第4个字保存的是数组的末尾地址，第2个字的6保存的是数组的容量，注意这里的容量与数组长度不同，数组长度为4，但容量为6，只不过后面2个元素暂时还未被创建。

往下，代码调用了`next`方法，获取迭代器中的下一个元素，下面是调用后迭代器的状态：

```text
10:0080│ rcx rdi 0x7fffffffd880 —▸ 0x5555555b4ba0 ◂— 0x200000001
11:0088│         0x7fffffffd888 ◂— 0x6
12:0090│         0x7fffffffd890 —▸ 0x5555555b4ba4 ◂— 0x300000002
13:0098│         0x7fffffffd898 —▸ 0x5555555b4bb0 ◂— 0x0
```

可以看到第三个字表示的实际上就是当前的指针。`next`方法返回的是一个`Option<T>`实例，索引值和数据分别被保存在`rax`和`rdx`中。这一点在下面的汇编代码中得以证实。

```masm
.LBB46_10:
        mov     eax, dword ptr [rsp + 16]
        mov     ecx, dword ptr [rsp + 20]
        mov     dword ptr [rsp + 164], ecx
        mov     dword ptr [rsp + 168], eax
        mov     eax, dword ptr [rsp + 164]
        cmp     rax, 0
        jne     .LBB46_12
        mov     rax, qword ptr [rip + core::ptr::drop_in_place<alloc::vec::into_iter::IntoIter<i32>>@GOTPCREL]
        lea     rdi, [rsp + 128]
        call    rax
        jmp     .LBB46_13
```

下面的代码中进行了一个比较，通过数据流分析可以发现这里是将`next`返回值与0进行比较，在`Option<T>`中，如果`T`不是一个枚举类型，那么枚举索引值为1表示有效值，0则表示无效值。随后就是正常的宏展开与输出，输出内容后无条件跳转回`next`方法调用前，继续调用`next`方法获取下一个值。

当`next`方法调用失败，即已经到达迭代器的终点时，通过调试发现，返回的`rax`值为0，`rdx`值为0x5555。后续则是判断失败后跳出循环。

注意，上面的代码是`for i in x`，这里的x由于没有使用引用，在`for`循环一开始就丧失了所有权，其所有权会被转移到迭代器中，当`for`循环结束后，迭代器被销毁，后续将不能使用变量`x`。

如果使用`for i in &x`，情况则会有些许的不同，**不仔细观察还真的容易忽略**。

注意看，下面是两个`into_iter`方法在IDA反汇编界面中的函数名：

```text
_$LT$$RF$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$::into_iter::hed888fce85d317be

_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$::into_iter::he37dcd381eb06c85
```

可能你会纳闷：这里为啥会有这么多`$`符号？实际上，这是IDA用于表示某些标点符号的转义字符，这个转义的规则与Javascript类似。`$LT$`表示`<`，`$GT$`表示`>`，`$RF$`表示`&`，`$C$`表示`,`，`$u??$`表示`\x??`。因此上面的函数名就等同于：

```text
<&alloc::vec::Vec<T,A> as core::iter::traits::collect::IntoIterator>::into_iter::hed888fce85d317be

<alloc::vec::Vec<T,A> as core::iter::traits::collect::IntoIterator>::into_iter::he37dcd381eb06c85
```

上面那个是`for i in &x`调用的方法，下面是`for i in x`调用的方法，除了后面的哈希值之外，函数名真的只有一个`&`的差别。也即上面的方法是针对`&Vec`，下面的是针对`Vec`。二者的参数不同，上面那个只有1个参数：

```masm
.LBB33_5:
        mov     rax, qword ptr [rip + <&alloc::vec::Vec<T,A> as core::iter::traits::collect::IntoIterator>::into_iter@GOTPCREL]
        lea     rdi, [rsp + 64]
        call    rax
        mov     qword ptr [rsp + 32], rdx
        mov     qword ptr [rsp + 40], rax
        jmp     .LBB33_6
```

即`Vec`实例的地址。

且二者的返回值也不同，对于`<&alloc::vec::Vec<T,A> as core::iter::traits::collect::IntoIterator>::into_iter`，其返回值保存在`rax`和`rdx`中，其中`rax`为数组的开始地址，`rdx`为数组的结束地址。实际返回的迭代器的大小也只有16个字节。

`for i in &x`后面的汇编代码段如下：

```masm
.LBB33_6:
        mov     rax, qword ptr [rsp + 32]
        mov     rcx, qword ptr [rsp + 40]
        mov     qword ptr [rsp + 88], rcx
        mov     qword ptr [rsp + 96], rax
.LBB33_7:
        mov     rax, qword ptr [rip + <core::slice::iter::Iter<T> as core::iter::traits::iterator::Iterator>::next@GOTPCREL]
        lea     rdi, [rsp + 88]
        call    rax
        mov     qword ptr [rsp + 24], rax
        jmp     .LBB33_8
.LBB33_8:
        mov     rax, qword ptr [rsp + 24]
        mov     qword ptr [rsp + 104], rax
        mov     rdx, qword ptr [rsp + 104]
        mov     eax, 1
        xor     ecx, ecx
        cmp     rdx, 0
        cmove   rax, rcx
        cmp     rax, 0
        jne     .LBB33_10
```

可以看到这里调用的`next`方法也和不加`&`的不一样，参数只有1个，即数组的开始地址，返回值只有1个，即下一个元素的地址，该函数调用后，迭代器中的指针位置向前移动。可见对于引用类型的迭代器结构更为简单，只需要一个动态指针和一个结束指针即可，什么时候动态指针等于结束指针，迭代也就结束。

## 枚举数组

对于元素类型是枚举类型的数组，目前只有一个疑问：当枚举类型中不同枚举项所跟的数据类型不同，占用内存大小不同时，Rust将如何进行处理。

```rust
#[derive(Debug)]
enum Shapes {
    Round(f64),
    Rectangle(f64, f64),
    Triangle(f64, f64, f64),
}

pub fn main() {
    let mut x = vec![
        Shapes::Round(3.5),
        Shapes::Rectangle(7.5, 9.6),
        Shapes::Triangle(114.514, 19.1981, 1.57)
    ];
}
```

```masm
example::main:
        sub     rsp, 136
        mov     edi, 96
        mov     esi, 8
        call    alloc::alloc::exchange_malloc
        mov     qword ptr [rsp + 8], rax
        movsd   xmm0, qword ptr [rip + .LCPI10_5]
        movsd   qword ptr [rsp + 48], xmm0
        mov     qword ptr [rsp + 40], 0
        movsd   xmm0, qword ptr [rip + .LCPI10_4]
        movsd   qword ptr [rsp + 80], xmm0
        movsd   xmm0, qword ptr [rip + .LCPI10_3]
        movsd   qword ptr [rsp + 88], xmm0
        mov     qword ptr [rsp + 72], 1
        movsd   xmm0, qword ptr [rip + .LCPI10_2]
        movsd   qword ptr [rsp + 112], xmm0
        movsd   xmm0, qword ptr [rip + .LCPI10_1]
        movsd   qword ptr [rsp + 120], xmm0
        movsd   xmm0, qword ptr [rip + .LCPI10_0]
        movsd   qword ptr [rsp + 128], xmm0
        mov     qword ptr [rsp + 104], 2
        and     rax, 7
        cmp     rax, 0
        sete    al
        test    al, 1
        jne     .LBB10_1
        jmp     .LBB10_2
.LBB10_1:
        mov     rsi, qword ptr [rsp + 8]
        mov     rax, qword ptr [rsp + 40]
        mov     qword ptr [rsi], rax
        mov     rax, qword ptr [rsp + 48]
        mov     qword ptr [rsi + 8], rax
        mov     rax, qword ptr [rsp + 56]
        mov     qword ptr [rsi + 16], rax
        mov     rax, qword ptr [rsp + 64]
        mov     qword ptr [rsi + 24], rax
        mov     rax, qword ptr [rsp + 72]
        mov     qword ptr [rsi + 32], rax
        mov     rax, qword ptr [rsp + 80]
        mov     qword ptr [rsi + 40], rax
        mov     rax, qword ptr [rsp + 88]
        mov     qword ptr [rsi + 48], rax
        mov     rax, qword ptr [rsp + 96]
        mov     qword ptr [rsi + 56], rax
        mov     rax, qword ptr [rsp + 104]
        mov     qword ptr [rsi + 64], rax
        mov     rax, qword ptr [rsp + 112]
        mov     qword ptr [rsi + 72], rax
        mov     rax, qword ptr [rsp + 120]
        mov     qword ptr [rsi + 80], rax
        mov     rax, qword ptr [rsp + 128]
        mov     qword ptr [rsi + 88], rax
        lea     rdi, [rsp + 16]
        mov     edx, 3
        call    qword ptr [rip + alloc::slice::<impl [T]>::into_vec@GOTPCREL]
```

可以看到，Rust编译器似乎很喜欢通过大量的`mov`系列指令完成内存复制操作，在上面的示例中可以发现，Rust是将枚举类型可能占用的最大内存大小作为数组一个元素的大小进行存储，在下面的内存拷贝操作中甚至还拷贝了未被初始化的内存区域。我们可以将每一个枚举类型后面跟的值视作一个大的union结构，一个枚举类型的不同实例占用的内存大小相同，即使其中一个实例只保存了8字节而另一个实例保存了80字节，前者也需要80个字节的空间保存数据。这会造成一定的内存浪费，但便于数组索引寻址。

## 弹出最后一个元素——pop

`Vec`的`pop`方法能够弹出数组中最后一个元素，并在数组中将其删除。

```rust
pub fn main() {
    let mut x = vec![1, 2, 3];
    x.push(4);
    let y = x.pop().unwrap();
}
```

```masm
.LBB31_5:
        mov     rax, qword ptr [rip + alloc::vec::Vec<T,A>::pop@GOTPCREL]
        lea     rdi, [rsp + 32]
        call    rax
        mov     dword ptr [rsp + 8], edx
        mov     dword ptr [rsp + 12], eax
        jmp     .LBB31_6
.LBB31_6:
        mov     esi, dword ptr [rsp + 8]
        mov     edi, dword ptr [rsp + 12]
        lea     rdx, [rip + .L__unnamed_5]
        mov     rax, qword ptr [rip + core::option::Option<T>::unwrap@GOTPCREL]
        call    rax
        jmp     .LBB31_7
```

`pop`的参数只有一个，即`Vec`实例地址，返回值是`Option<T>`，`rdx`为有效值，`rax`为是否有效的索引值，1为有效。该方法调用后，数组的大小会变化，但容量不变，真正保存值的静态数组指针中的值也不变，而且也不需要改变，因为数组大小变小，所以后面的值在正常情况下无法访问。

在参考书中只给出了插入元素、获取元素、遍历元素等几个为数不多的`Vec`操作方法，但实际上`Vec`能完成的功能远不止于此，考虑到`Vec`的方法实在太多，这里无法全部完成分析，就先到这里了。不过我们已经掌握了`Vec`的基本结构，对于其他方法的分析也就万变不离其宗。

# 总结

本文我们学习了：
1. `Vec`动态数组结构在内存中的结构。
2. `Vec`在最后添加、删除元素、遍历、访问值的相关方法分析。
3. IDA中对一些含有特殊字符的Rust方法的转义方式与Javascript类似。
4. 枚举类型构成的数组中，每个枚举类型占用的内存大小相同，可能导致内存空间浪费。