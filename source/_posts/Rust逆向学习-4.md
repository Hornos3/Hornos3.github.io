---
title: Rust逆向学习 (4)
date: 2023-11-10 14:41:05
categories:
- 学习笔记
- Rust逆向系列
---

# Reverse for Struct

Rust中的结构体是一个重要的内容，由于Rust中没有类的概念，因此其他编程语言中的封装、继承、多态与Rust中的表现都有较大差异。

我们使用参考书中的一个示例开始进行分析。

## Struct 初始化

```rust
struct User {
    username: String,
    email: String,
    sign_in_count: u64,
    active: bool,
}

pub fn main() {
    let mut user1 = User {
        email: String::from("someone@example.com"),
        username: String::from("someusername123"),
        active: true,
        sign_in_count: 1
    };
    println!("{}, {}", user1.email, user1.active);
}
```

上面这段在汇编层是如何处理的呢？

### 第一段

```masm
example::main:
        sub     rsp, 296
        lea     rsi, [rip + .L__unnamed_5]
        lea     rdi, [rsp + 120]
        mov     edx, 19
        call    <alloc::string::String as core::convert::From<&str>>::from
        lea     rsi, [rip + .L__unnamed_6]
        lea     rdi, [rsp + 144]
        mov     edx, 15
        call    <alloc::string::String as core::convert::From<&str>>::from
        jmp     .LBB17_3
        ...
        
.L__unnamed_5:
        .ascii  "someone@example.com"

.L__unnamed_6:
        .ascii  "someusername123"
```

上面是第一段汇编内容，在源码中，我们是首先对`email`进行了初始化，在汇编中也是如此。这里分别将两个字符串实例保存到了`[rsp+120]`和`[rsp+144]`处。我们之前分析过，`String`实例在栈中的大小应该为0x18，可见这两个`String`实例是完全相邻的，中间没有其他的数据。

### 第二段

```rust
.LBB17_3:
        mov     rax, qword ptr [rsp + 160]
        mov     qword ptr [rsp + 64], rax
        movups  xmm0, xmmword ptr [rsp + 144]
        movaps  xmmword ptr [rsp + 48], xmm0
        lea     rax, [rsp + 72]
        mov     rcx, qword ptr [rsp + 136]
        mov     qword ptr [rsp + 88], rcx
        movups  xmm0, xmmword ptr [rsp + 120]
        movups  xmmword ptr [rsp + 72], xmm0
        mov     qword ptr [rsp + 96], 1
        mov     byte ptr [rsp + 104], 1
        mov     qword ptr [rsp + 280], rax
        lea     rax, [rip + <alloc::string::String as core::fmt::Display>::fmt]
        mov     qword ptr [rsp + 288], rax
        mov     rax, qword ptr [rsp + 280]
        mov     qword ptr [rsp + 32], rax
        mov     rax, qword ptr [rsp + 288]
        mov     qword ptr [rsp + 40], rax
        jmp     .LBB17_6
```

随后是第二段，这里有一个Rust 1.73与Rust 1.69的不同之处，在老版本中，对于宏将会调用`core::fmt::ArgumentV1::new_display`将中括号对应的内容转为字符串，而在新版本中，则只会将`core::fmt::Display`函数地址保存到栈而并不调用。并且结构体中各个元素的内存排列顺序也不相同，通过IDA分析可见在1.73版本中，元素排列与元素定义的顺序相同，但老版本中则不是。这里是因为`String`实例实现了`Display`这个`Trait`，所以能够直接输出。输出时调用的实际上也是`Display`的`Trait`。

需要注意的是，第一段中的字符串初始化并不是对结构体的字符串直接进行初始化，而是在栈中另外开辟了0x30大小的空间用于初始化这两个字符串，随后将这段内存的内容复制到结构体中。真正的结构体应该位于`[rsp+48]`。四个元素的保存地址分别为：`[rsp+48]`，`[rsp+72]`，`[rsp+96]`，`[rsp+104]`，因此，中间的两条指令`mov qword ptr [rsp + 96], 1`、`mov byte ptr [rsp + 104], 1`就是在对`sign_in_count`和`active`进行初始化，因为二者一个是整数类型，一个是布尔值，都是不需要通过`new`进行初始化的，因此可以直接赋值。

```c
00000000 revlab::User struc ; (sizeof=0x40, align=0x8, copyof_91)
00000000                                         ; XREF: _ZN6revlab4main17h1e5ad0972ab6a820E/r
00000000                                         ; _ZN6revlab4main17h1e5ad0972ab6a820E/r
00000000 username alloc::string::String ?        ; XREF: revlab::main::h1e5ad0972ab6a820+65/w
00000000                                         ; revlab::main::h1e5ad0972ab6a820+72/w
00000018 email alloc::string::String ?           ; XREF: revlab::main::h1e5ad0972ab6a820+77/o
00000018                                         ; revlab::main::h1e5ad0972ab6a820+84/w ...
00000030 sign_in_count dq ?                      ; XREF: revlab::main::h1e5ad0972ab6a820+93/w
00000038 active db ?                             ; XREF: revlab::main::h1e5ad0972ab6a820+9C/w
00000038                                         ; revlab::main::h1e5ad0972ab6a820+11C/o
00000039 db ? ; undefined
0000003A db ? ; undefined
0000003B db ? ; undefined
0000003C db ? ; undefined
0000003D db ? ; undefined
0000003E db ? ; undefined
0000003F db ? ; undefined
```

### 第三段

```masm
.LBB17_6:
        mov     rax, qword ptr [rsp + 40]
        mov     rcx, qword ptr [rsp + 32]
        mov     qword ptr [rsp], rcx
        mov     qword ptr [rsp + 8], rax
        lea     rax, [rsp + 104]
        mov     qword ptr [rsp + 264], rax
        mov     rax, qword ptr [rip + <bool as core::fmt::Display>::fmt@GOTPCREL]
        mov     qword ptr [rsp + 272], rax
        mov     rax, qword ptr [rsp + 264]
        mov     qword ptr [rsp + 16], rax
        mov     rax, qword ptr [rsp + 272]
        mov     qword ptr [rsp + 24], rax
        mov     rax, qword ptr [rsp + 24]
        mov     rcx, qword ptr [rsp + 16]
        mov     rdx, qword ptr [rsp + 8]
        mov     rsi, qword ptr [rsp]
        mov     qword ptr [rsp + 216], rsi
        mov     qword ptr [rsp + 224], rdx
        mov     qword ptr [rsp + 232], rcx
        mov     qword ptr [rsp + 240], rax
        lea     rsi, [rip + .L__unnamed_7]
        lea     rdi, [rsp + 168]
        mov     edx, 3
        lea     rcx, [rsp + 216]
        mov     r8d, 2
        call    core::fmt::Arguments::new_v1
        jmp     .LBB17_8
        
.L__unnamed_7:
        .quad   .L__unnamed_2
        .zero   8
        .quad   .L__unnamed_11
        .asciz  "\002\000\000\000\000\000\000"
        .quad   .L__unnamed_12
        .asciz  "\001\000\000\000\000\000\000"
        
.L__unnamed_11:
        .ascii  ", "

.L__unnamed_12:
        .ascii  "\n"
```

这一段的工作主要就是输出，通过调试发现，新版rustc在使用`println!`宏时将不再将临时字符串切片参数保存在栈中，但通过IDA依然可以较为容易地辨别。

## Struct 作为返回值

下面书中给出一个通过函数初始化结构体的实例：

```rust
struct User {
    username: String,
    email: String,
    sign_in_count: u64,
    active: bool,
}

fn build_user(email: String, username: String) -> User {
    User {
        email,
        username,
        active: true,
        sign_in_count: 1
    }
}

pub fn main() {
    let mut user1 = build_user(String::from("someone@example.com"), String::from("someusername123"));
    println!("{}, {}", user1.email, user1.active);
}
```

```masm
example::build_user:
        mov     rax, rdi
        mov     rcx, qword ptr [rdx]
        mov     qword ptr [rdi], rcx
        mov     rcx, qword ptr [rdx + 8]
        mov     qword ptr [rdi + 8], rcx
        mov     rcx, qword ptr [rdx + 16]
        mov     qword ptr [rdi + 16], rcx
        mov     rcx, qword ptr [rsi]
        mov     qword ptr [rdi + 24], rcx
        mov     rcx, qword ptr [rsi + 8]
        mov     qword ptr [rdi + 32], rcx
        mov     rcx, qword ptr [rsi + 16]
        mov     qword ptr [rdi + 40], rcx
        mov     qword ptr [rdi + 48], 1
        mov     byte ptr [rdi + 56], 1
        ret
```

从函数的汇编可以看到，这个函数实际上是将第一个参数作为指针完成初始化的，可以将第一个指针理解为`this`，这与C++类方法的函数调用规则类似。

## 实现 Debug Trait

一个结构体可以通过`#[derive(Debug)]`完成对Debug Trait的默认实现：

```rust
#[derive(Debug)]
struct Rect {
    width: u32,
    height: u32,
}

pub fn main() {
    let rect1 = Rect {width: 30, height: 50};
    println!("rect1 = {:?}", rect1);
}
```

```masm
example::main:
        sub     rsp, 88
        mov     dword ptr [rsp], 30
        mov     dword ptr [rsp + 4], 50
        mov     rax, rsp
        mov     qword ptr [rsp + 72], rax
        mov     rax, qword ptr [rip + <example::Rect as core::fmt::Debug>::fmt@GOTPCREL]
        mov     qword ptr [rsp + 80], rax
        mov     rcx, qword ptr [rsp + 72]
        mov     rax, qword ptr [rsp + 80]
        mov     qword ptr [rsp + 56], rcx
        mov     qword ptr [rsp + 64], rax
        lea     rdi, [rsp + 8]
        lea     rsi, [rip + .L__unnamed_4]
        mov     edx, 2
        lea     rcx, [rsp + 56]
        mov     r8d, 1
        call    core::fmt::Arguments::new_v1
        lea     rdi, [rsp + 8]
        call    qword ptr [rip + std::io::stdio::_print@GOTPCREL]
        add     rsp, 88
        ret
```

可以看到，汇编代码中获取的就是`Debug`这个`Trait`的函数指针，说明不同的宏实际上调用的函数也不同。如果将`{:?}`修改为`{:#?}`，则原先调用的`core::fmt::Arguments::new_v1`将会改为调用`core::fmt::Arguments::new_v1_formatted`。考虑到Rust的格式化字符串非常强大与灵活，有多种输出形式，后面将通过专门的分析对宏展开进行分析，这里不深入探讨。

## Reverse for Methods
在Rust中，结构体充当了其他语言中类的功能，可以在结构体下定义方法，使这个方法专属于该结构体。

```rust
struct Rect {
    width: u32,
    height: u32,
}

impl Rect {
    fn area(&self) -> u32 {
        self.width * self.height
    }
}

pub fn main() {
    let rect1 = Rect {width: 30, height: 50};
    println!("area = {}", rect1.area());
}
```

```masm
example::Rect::area:
        push    rax
        mov     eax, dword ptr [rdi]
        mul     dword ptr [rdi + 4]
        mov     dword ptr [rsp + 4], eax
        seto    al
        test    al, 1
        jne     .LBB1_2
        mov     eax, dword ptr [rsp + 4]
        pop     rcx
        ret
.LBB1_2:
        lea     rdi, [rip + str.0]
        lea     rdx, [rip + .L__unnamed_4]
        mov     rax, qword ptr [rip + core::panicking::panic@GOTPCREL]
        mov     esi, 33
        call    rax
        ud2

example::main:
        sub     rsp, 104
        mov     dword ptr [rsp + 8], 30
        mov     dword ptr [rsp + 12], 50
        lea     rdi, [rsp + 8]
        call    example::Rect::area
        mov     dword ptr [rsp + 84], eax
        lea     rax, [rsp + 84]
        mov     qword ptr [rsp + 88], rax
        mov     rax, qword ptr [rip + core::fmt::num::imp::<impl core::fmt::Display for u32>::fmt@GOTPCREL]
        mov     qword ptr [rsp + 96], rax
        mov     rcx, qword ptr [rsp + 88]
        mov     rax, qword ptr [rsp + 96]
        mov     qword ptr [rsp + 64], rcx
        mov     qword ptr [rsp + 72], rax
        lea     rdi, [rsp + 16]
        lea     rsi, [rip + .L__unnamed_5]
        mov     edx, 2
        lea     rcx, [rsp + 64]
        mov     r8d, 1
        call    core::fmt::Arguments::new_v1
        lea     rdi, [rsp + 16]
        call    qword ptr [rip + std::io::stdio::_print@GOTPCREL]
        add     rsp, 104
        ret
```

由上述汇编可知，这里还是将`rdi`作为`self`使用。

```rust
#[derive(Debug)]
struct Rect {
    width: u32,
    height: u32,
}

impl Rect {
    fn area(&self) -> u32 {
        self.width * self.height
    }
    fn can_hold(&self, other: &Rect) -> bool {
        self.width > other.width && self.height > other.height
    }
}

pub fn main() {
    let rect1 = Rect {width: 30, height: 50};
    let rect2 = Rect {width: 10, height: 40};
    println!("{}", rect1.can_hold(&rect2));
}
```

对于上面的代码，`can_hold`方法的参数有两个，都是指针，如果将第二个参数的`&`去掉，则参数有三个。经过试验发现，当一个结构体中的元素数量较少时，不加`&`可能会将结构体的每个元素分别作为参数传递，当元素数量较多时，则是首先复制然后传递指针。

对于关联函数，由于其第一个参数并不是`self`，类似于C++中的类静态函数，不需要首先获取结构体实例即可调用，参数传递与一般的函数相同。

# Reverse for enum (Part 2)

对于枚举类型，我们在第二篇文章中已经进行了较为详细的解释，对于枚举类型的内存排布有了一定的了解。

下面对枚举类型中定义的方法进行测试。

```rust
use std::any::Any;

pub enum Student {
    Freshman(String),
    Sophomore(String),
    Junior(String),
    Senior(String),
}

pub fn get_student(grade: i32, name: String) -> Option<Student> {
    match grade {
        1 => Some(Student::Freshman(name)),
        2 => Some(Student::Sophomore(name)),
        3 => Some(Student::Junior(name)),
        4 => Some(Student::Senior(name)),
        _ => None
    }
}

impl Student {
    fn test(&self) -> String {
        match self {
            Student::Freshman(name) => format!("{}", "Calculus").to_string(),
            Student::Sophomore(name) => format!("{}", "Data Structure").to_string(),
            Student::Junior(name) => format!("{}", "Computer Network").to_string(),
            Student::Senior(name) => format!("{}", "Graduation Design").to_string()
        }
    }
}

pub fn main() {
    let x = get_student(4, "CoLin".to_string()).unwrap();
    println!("{}", x.test());
}
```

上面代码中对于`test`方法的调用如下：

```masm
        mov     rax, qword ptr [rip + core::option::Option<T>::unwrap@GOTPCREL]
        lea     rdi, [rsp + 40]
        mov     qword ptr [rsp + 32], rdi
        call    rax
        mov     rsi, qword ptr [rsp + 32]
        lea     rdi, [rsp + 192]
        call    example::Student::test
        jmp     .LBB26_3
```

可以看到方法的第一个参数依然是`self`，第二个参数则是等待初始化的`String`实例地址。在代码中是返回`String`实例，实际上是传入未初始化的指针。

## `Option<T>`
针对`Option<T>`，Rust在汇编层有自己的处理方式。如果将`Option<T>`看做一个普通的枚举类型，且`Some`后面带的是另一个枚举类型，那么这样的话就会产生两层枚举对象，不太优雅。对于`get_student`函数，下面是部分反编译结果：

```masm
.text:0000000000009702 48 89 4C 24 18                mov     [rsp+108h+var_F0], rcx
.text:0000000000009707 83 E8 03                      sub     eax, 3
.text:000000000000970A 77 15                         ja      short def_971F                  ; jumptable 000000000000971F default case
.text:000000000000970A
.text:000000000000970C 48 8B 44 24 18                mov     rax, [rsp+108h+var_F0]
.text:0000000000009711 48 8D 0D B4 09 04 00          lea     rcx, jpt_971F
.text:0000000000009718 48 63 04 81                   movsxd  rax, ds:(jpt_971F - 4A0CCh)[rcx+rax*4]
.text:000000000000971C 48 01 C8                      add     rax, rcx
.text:000000000000971F FF E0                         jmp     rax                             ; switch jump
.text:000000000000971F
.text:0000000000009721                               ; ---------------------------------------------------------------------------
.text:0000000000009721
.text:0000000000009721                               def_971F:                               ; CODE XREF: revlab::get_student::h5c77d454e35cea03+3A↑j
.text:0000000000009721 48 8B 44 24 08                mov     rax, [rsp+108h+var_100]         ; jumptable 000000000000971F default case
.text:0000000000009726 48 C7 00 04 00 00 00          mov     qword ptr [rax], 4
.text:000000000000972D E9 43 02 00 00                jmp     loc_9975
```

下面的`def_971F`为默认分支，可以看到这里是将枚举类型的索引值赋值为4，但上面定义的枚举类型一共只有4个值，最大的索引值只能为3。将索引值设置为4实际上也就表示这个枚举类型是一个无效值，这样在内存中实际上并不存在二重枚举类型，而是只有一个`Student`枚举类型。由此可见，对泛型参数为枚举类型的`Option`，Rust进行了优化。

# Reverse for if-let

if let语句是针对只有一个处理条件和一个默认条件的`match`语句的平替。由于只有一个特殊条件和默认条件，因此在实际实现中只需要使用类似于if的逻辑即可完成。

```rust
pub fn main() {
    let x = get_student(4, "CoLin".to_string());
    if let Some(Student::Senior(y)) = x {
        println!("{}", y);
    }
}
```

```masm
example::main:
        sub     rsp, 216
        mov     byte ptr [rsp + 183], 0
        lea     rdi, [rsp + 56]
        lea     rsi, [rip + .L__unnamed_5]
        mov     edx, 5
        call    <str as alloc::string::ToString>::to_string
        lea     rdi, [rsp + 24]
        mov     esi, 4
        lea     rdx, [rsp + 56]
        call    qword ptr [rip + example::get_student@GOTPCREL]
        mov     byte ptr [rsp + 183], 1
        mov     eax, 1
        xor     ecx, ecx
        cmp     qword ptr [rsp + 24], 4
        cmove   rax, rcx
        cmp     rax, 1
        jne     .LBB18_2
        cmp     qword ptr [rsp + 24], 3
        je      .LBB18_3
```

可以发现，这里的判断逻辑和`match`是类似的，都是对枚举索引值进行比较。

# 总结

本文学习了：

1. Rust 结构体的内存排布以及结构体方法的参数传递，结构体方法参数传递遵照this参数传递法
2. Rust 枚举类型方法的参数传递与结构体方法的参数传递类似
3. Rust if-let语句的判断逻辑，`Option<T>`的内存结构