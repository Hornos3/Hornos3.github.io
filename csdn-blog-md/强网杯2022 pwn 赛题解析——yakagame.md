今天是2022强网杯比赛，笔者能力有限，仅做出来这道题。
2022强网杯的所有pwn附件已经上传至[github](https://github.com/Hornos3/pwnfile)，请读者自行取用。

这是一道llvm pass pwn题，有了前面几道题的分析做铺垫，这道题就不算太难了。有趣的是，这道题的出题人就是笔者之前写llvm pass pwn分析文章时参考的主要文章的作者。

# Step 1: 找到runOnFunction函数
runOnFunction函数一定在虚函数表的最后被引用，因此我们只要找到虚函数表就能找到runOnFunction的覆写函数：

![](https://img-blog.csdnimg.cn/51440c9fb4a5464795d6299cc2761250.png)
# Step 2: 分析runOnfunction函数
## Segment 1
![](https://img-blog.csdnimg.cn/cffc049cb8844d94a53af8a44cbd845b.png)
这一段主要是触发循环迭代，可以看到runOnFunction函数只会对函数名为gamestart的函数进行处理。在下面有一个getOpcode函数的调用，这是在遍历函数的指令，获取每一条指令的指令码。通过查询Instructions.def文件可知55表示的是call的指令码，即调用函数的指令码。
## Segment 2
![](https://img-blog.csdnimg.cn/494ef608827045d2b18b48c8f7f03e0f.png)
这里的getNumOperands函数我们之前说过，其如果传入的是一个call类型的指令对象，那么返回的应该是被调用函数的参数个数+1，因此这里表示fight函数只能有1个参数。看上去出题人想模拟一个游戏，fight传入的参数就是weapon_list的索引，在这里会从weapon_list中取出对应索引的值作为weapon的"攻击力"，然后和boss比较，如果大于等于boss则判定为赢，并赋值给相应的分数；否则判定为输，对分数没有影响。如果分数大于0x12345678就会执行后门函数。后门函数执行system(cmd)，但是初始化的cmd是一段乱码，需要我们对cmd的8个字节做出一些处理。
## Segment 3
![](https://img-blog.csdnimg.cn/ed34fd8079184b6f983b4f3b5dbd55aa.png)
这里的三个函数分别为merge、destroy、upgrade，融合（将一个weapon的“攻击力”加上另一个weapon的“攻击力”）、销毁（将一个weapon的“攻击力”清零）、升级（将所有weapon的“攻击力”加上一个值）。
## Segment 4
![](https://img-blog.csdnimg.cn/dd514afb739c483ba0509de8cf506208.png)
然后是上面的这4个函数名。看上去像是拼音。笔者还特地查了一下这些都是什么梗，查了之后发现全都是原神的梗，看来出题人还是一位原神玩家（笑）。我们可以看到这4个函数都会对cmd的8个字节进行一些处理，不过是统一异或、加减ASCII码。看上去像是一种加密方式，需要我们对这4中操作进行合理排序以获得真正想要执行的命令。
## Segment 5
![](https://img-blog.csdnimg.cn/c69b9a0207354bfbbce435ec726c4bb1.png)
如果被调用的函数的函数名不是上面的任何一个，那么这里会使用到一个map变量。首先会遍历map查找是否有以这个函数名为key的value。如果有就会在weapon_list的特定位置赋值为value。这里weapon的特定位置与遍历的顺序有关。这个key在第几次循环中被遍历到，那么就会在weapon_list的第几的位置赋值。

![](https://img-blog.csdnimg.cn/97873df9e81e413b9fc758ee9559b4fe.png)
如果在map中没有找到这个key值，那么就会向map中插入这个key值，将对应的value设置为第二个参数的值。

这段代码具有至关重要的作用，因为只有这里能够产生溢出。不知道细心的读者有没有发现，为weaponlist赋值的索引v33是一个char类型变量，是一个有符号数。而存放score的地址正好就在weaponlist上面。如果map中的key值足够多，那么多次遍历后，v33就有可能变成一个负数，影响到score的值。

![](https://img-blog.csdnimg.cn/236500bdb14d460291de09c9a73c44fe.png)
![](https://img-blog.csdnimg.cn/70f4dceb45da4e708ea6a51d59505293.png)
至此，我们已经知道应该如何恶意修改score的值了。**需要注意的是，map的遍历顺序是由value的大小决定的。本题中这里的map的key是字符串类型，因此其遍历顺序就是：字符串小的先遍历到，字符串大的后遍历到。遍历顺序对于我们正确写入score至关重要，这也要求我们设计好调用其他函数的函数名，不能随便起名。**

# Step 3: 解密
现在我们已经能够执行到后门了，但是后门的cmd指令原本是8个字节的乱码。下面来分析一下应该如何解密。

![](https://img-blog.csdnimg.cn/2a0cf7270244479a92d05311fe39671b.png)
上面就是初始化的cmd，共8个字节。我们能够对cmd进行的操作只有两个逐字节异或、一个逐字节加和一个减。因此字节与字节之间并没有关系，明文中相同字母最终会被加密为相同的密文。基于这个特性我们发现，在密文中有两个0x68，位于第2和第7个字节。合理猜测一下，明文极有可能是"cat flag"。即0x68是由0x61('a')加密而来。

下面我们来分析一下，如何才能通过4种操作解密。需要注意的是，明文中的所有字符的最高位都为0，但是密文中的第1和第6个字节的高位是9，说明最高1比特为1。两个异或（一个0x14，一个0x7F）都不会改变最高比特的值，那么最高比特从0变成1，有可能是从正数被减成了负数。

我们尝试将所有明文字节都与0x14和0x7F异或一次，发现第1个字节'c'和第6个字节'l'异或的结果比其他字母异或的结果都要小，且小于9。因此如果将此时的所有字节全部减9就可以得到第1个字节和第6个字节的最高比特1。

然后我们再一次进行异或尝试，笔者的运气还算不错，没有尝试多长时间就试出来了。读者可以尝试采用爆破的方式解密，不过笔者没有尝试过，不知道是否可以爆破出来。

解密的算法是：加2、异或0x14、异或0x7F、减9、加18、异或0x14、异或0x7F。

# Step 4: 编写exp
首先为了能够解密cmd，我们需要按照上一个步骤的顺序调用原神梗那4个函数，解密完毕后，我们需要定义256个函数，这256个函数的函数名依次递增，且都有1个int类型的参数。在gamestart函数中依次调用这256个函数1次，然后再一次调用其中几个特定的函数来修改score。（注意score保存的是地址不是score的真实值，需要修改成一个有效地址才行）

exp.c:
```c
void fight(int weapon){return;}
void merge(int weapon1, int weapon2){return;}
void destroy(int weapon){return;}
void upgrade(int val){return;}
void wuxiangdeyidao(){return;}
void zhanjinniuza(){return;}
void guobapenhuo(){return;}
void tiandongwanxiang(){return;}
void other000(int unknown){return;}
void other001(int unknown){return;}
void other002(int unknown){return;}
void other003(int unknown){return;}
void other004(int unknown){return;}
void other005(int unknown){return;}
void other006(int unknown){return;}
void other007(int unknown){return;}
void other008(int unknown){return;}
void other009(int unknown){return;}
void other010(int unknown){return;}
void other011(int unknown){return;}
void other012(int unknown){return;}
void other013(int unknown){return;}
void other014(int unknown){return;}
void other015(int unknown){return;}
void other016(int unknown){return;}
void other017(int unknown){return;}
void other018(int unknown){return;}
void other019(int unknown){return;}
void other020(int unknown){return;}
void other021(int unknown){return;}
void other022(int unknown){return;}
void other023(int unknown){return;}
void other024(int unknown){return;}
void other025(int unknown){return;}
void other026(int unknown){return;}
void other027(int unknown){return;}
void other028(int unknown){return;}
void other029(int unknown){return;}
void other030(int unknown){return;}
void other031(int unknown){return;}
void other032(int unknown){return;}
void other033(int unknown){return;}
void other034(int unknown){return;}
void other035(int unknown){return;}
void other036(int unknown){return;}
void other037(int unknown){return;}
void other038(int unknown){return;}
void other039(int unknown){return;}
void other040(int unknown){return;}
void other041(int unknown){return;}
void other042(int unknown){return;}
void other043(int unknown){return;}
void other044(int unknown){return;}
void other045(int unknown){return;}
void other046(int unknown){return;}
void other047(int unknown){return;}
void other048(int unknown){return;}
void other049(int unknown){return;}
void other050(int unknown){return;}
void other051(int unknown){return;}
void other052(int unknown){return;}
void other053(int unknown){return;}
void other054(int unknown){return;}
void other055(int unknown){return;}
void other056(int unknown){return;}
void other057(int unknown){return;}
void other058(int unknown){return;}
void other059(int unknown){return;}
void other060(int unknown){return;}
void other061(int unknown){return;}
void other062(int unknown){return;}
void other063(int unknown){return;}
void other064(int unknown){return;}
void other065(int unknown){return;}
void other066(int unknown){return;}
void other067(int unknown){return;}
void other068(int unknown){return;}
void other069(int unknown){return;}
void other070(int unknown){return;}
void other071(int unknown){return;}
void other072(int unknown){return;}
void other073(int unknown){return;}
void other074(int unknown){return;}
void other075(int unknown){return;}
void other076(int unknown){return;}
void other077(int unknown){return;}
void other078(int unknown){return;}
void other079(int unknown){return;}
void other080(int unknown){return;}
void other081(int unknown){return;}
void other082(int unknown){return;}
void other083(int unknown){return;}
void other084(int unknown){return;}
void other085(int unknown){return;}
void other086(int unknown){return;}
void other087(int unknown){return;}
void other088(int unknown){return;}
void other089(int unknown){return;}
void other090(int unknown){return;}
void other091(int unknown){return;}
void other092(int unknown){return;}
void other093(int unknown){return;}
void other094(int unknown){return;}
void other095(int unknown){return;}
void other096(int unknown){return;}
void other097(int unknown){return;}
void other098(int unknown){return;}
void other099(int unknown){return;}
void other100(int unknown){return;}
void other101(int unknown){return;}
void other102(int unknown){return;}
void other103(int unknown){return;}
void other104(int unknown){return;}
void other105(int unknown){return;}
void other106(int unknown){return;}
void other107(int unknown){return;}
void other108(int unknown){return;}
void other109(int unknown){return;}
void other110(int unknown){return;}
void other111(int unknown){return;}
void other112(int unknown){return;}
void other113(int unknown){return;}
void other114(int unknown){return;}
void other115(int unknown){return;}
void other116(int unknown){return;}
void other117(int unknown){return;}
void other118(int unknown){return;}
void other119(int unknown){return;}
void other120(int unknown){return;}
void other121(int unknown){return;}
void other122(int unknown){return;}
void other123(int unknown){return;}
void other124(int unknown){return;}
void other125(int unknown){return;}
void other126(int unknown){return;}
void other127(int unknown){return;}
void other128(int unknown){return;}
void other129(int unknown){return;}
void other130(int unknown){return;}
void other131(int unknown){return;}
void other132(int unknown){return;}
void other133(int unknown){return;}
void other134(int unknown){return;}
void other135(int unknown){return;}
void other136(int unknown){return;}
void other137(int unknown){return;}
void other138(int unknown){return;}
void other139(int unknown){return;}
void other140(int unknown){return;}
void other141(int unknown){return;}
void other142(int unknown){return;}
void other143(int unknown){return;}
void other144(int unknown){return;}
void other145(int unknown){return;}
void other146(int unknown){return;}
void other147(int unknown){return;}
void other148(int unknown){return;}
void other149(int unknown){return;}
void other150(int unknown){return;}
void other151(int unknown){return;}
void other152(int unknown){return;}
void other153(int unknown){return;}
void other154(int unknown){return;}
void other155(int unknown){return;}
void other156(int unknown){return;}
void other157(int unknown){return;}
void other158(int unknown){return;}
void other159(int unknown){return;}
void other160(int unknown){return;}
void other161(int unknown){return;}
void other162(int unknown){return;}
void other163(int unknown){return;}
void other164(int unknown){return;}
void other165(int unknown){return;}
void other166(int unknown){return;}
void other167(int unknown){return;}
void other168(int unknown){return;}
void other169(int unknown){return;}
void other170(int unknown){return;}
void other171(int unknown){return;}
void other172(int unknown){return;}
void other173(int unknown){return;}
void other174(int unknown){return;}
void other175(int unknown){return;}
void other176(int unknown){return;}
void other177(int unknown){return;}
void other178(int unknown){return;}
void other179(int unknown){return;}
void other180(int unknown){return;}
void other181(int unknown){return;}
void other182(int unknown){return;}
void other183(int unknown){return;}
void other184(int unknown){return;}
void other185(int unknown){return;}
void other186(int unknown){return;}
void other187(int unknown){return;}
void other188(int unknown){return;}
void other189(int unknown){return;}
void other190(int unknown){return;}
void other191(int unknown){return;}
void other192(int unknown){return;}
void other193(int unknown){return;}
void other194(int unknown){return;}
void other195(int unknown){return;}
void other196(int unknown){return;}
void other197(int unknown){return;}
void other198(int unknown){return;}
void other199(int unknown){return;}
void other200(int unknown){return;}
void other201(int unknown){return;}
void other202(int unknown){return;}
void other203(int unknown){return;}
void other204(int unknown){return;}
void other205(int unknown){return;}
void other206(int unknown){return;}
void other207(int unknown){return;}
void other208(int unknown){return;}
void other209(int unknown){return;}
void other210(int unknown){return;}
void other211(int unknown){return;}
void other212(int unknown){return;}
void other213(int unknown){return;}
void other214(int unknown){return;}
void other215(int unknown){return;}
void other216(int unknown){return;}
void other217(int unknown){return;}
void other218(int unknown){return;}
void other219(int unknown){return;}
void other220(int unknown){return;}
void other221(int unknown){return;}
void other222(int unknown){return;}
void other223(int unknown){return;}
void other224(int unknown){return;}
void other225(int unknown){return;}
void other226(int unknown){return;}
void other227(int unknown){return;}
void other228(int unknown){return;}
void other229(int unknown){return;}
void other230(int unknown){return;}
void other231(int unknown){return;}
void other232(int unknown){return;}
void other233(int unknown){return;}
void other234(int unknown){return;}
void other235(int unknown){return;}
void other236(int unknown){return;}
void other237(int unknown){return;}
void other238(int unknown){return;}
void other239(int unknown){return;}
void other240(int unknown){return;}
void other241(int unknown){return;}
void other242(int unknown){return;}
void other243(int unknown){return;}
void other244(int unknown){return;}
void other245(int unknown){return;}
void other246(int unknown){return;}
void other247(int unknown){return;}
void other248(int unknown){return;}
void other249(int unknown){return;}
void other250(int unknown){return;}
void other251(int unknown){return;}
void other252(int unknown){return;}
void other253(int unknown){return;}
void other254(int unknown){return;}
void other255(int unknown){return;}

void gamestart(){
	tiandongwanxiang();
	wuxiangdeyidao();
	zhanjinniuza();
	guobapenhuo();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	tiandongwanxiang();
	wuxiangdeyidao();
	zhanjinniuza();

	other000(233);
	other001(233);
	other002(233);
	other003(233);
	other004(233);
	other005(233);
	other006(233);
	other007(233);
	other008(233);
	other009(233);
	other010(233);
	other011(233);
	other012(233);
	other013(233);
	other014(233);
	other015(233);
	other016(233);
	other017(233);
	other018(233);
	other019(233);
	other020(233);
	other021(233);
	other022(233);
	other023(233);
	other024(233);
	other025(233);
	other026(233);
	other027(233);
	other028(233);
	other029(233);
	other030(233);
	other031(233);
	other032(233);
	other033(233);
	other034(233);
	other035(233);
	other036(233);
	other037(233);
	other038(233);
	other039(233);
	other040(233);
	other041(233);
	other042(233);
	other043(233);
	other044(233);
	other045(233);
	other046(233);
	other047(233);
	other048(233);
	other049(233);
	other050(233);
	other051(233);
	other052(233);
	other053(233);
	other054(233);
	other055(233);
	other056(233);
	other057(233);
	other058(233);
	other059(233);
	other060(233);
	other061(233);
	other062(233);
	other063(233);
	other064(233);
	other065(233);
	other066(233);
	other067(233);
	other068(233);
	other069(233);
	other070(233);
	other071(233);
	other072(233);
	other073(233);
	other074(233);
	other075(233);
	other076(233);
	other077(233);
	other078(233);
	other079(233);
	other080(233);
	other081(233);
	other082(233);
	other083(233);
	other084(233);
	other085(233);
	other086(233);
	other087(233);
	other088(233);
	other089(233);
	other090(233);
	other091(233);
	other092(233);
	other093(233);
	other094(233);
	other095(233);
	other096(233);
	other097(233);
	other098(233);
	other099(233);
	other100(233);
	other101(233);
	other102(233);
	other103(233);
	other104(233);
	other105(233);
	other106(233);
	other107(233);
	other108(233);
	other109(233);
	other110(233);
	other111(233);
	other112(233);
	other113(233);
	other114(233);
	other115(233);
	other116(233);
	other117(233);
	other118(233);
	other119(233);
	other120(233);
	other121(233);
	other122(233);
	other123(233);
	other124(233);
	other125(233);
	other126(233);
	other127(233);
	other128(233);
	other129(233);
	other130(233);
	other131(233);
	other132(233);
	other133(233);
	other134(233);
	other135(233);
	other136(233);
	other137(233);
	other138(233);
	other139(233);
	other140(233);
	other141(233);
	other142(233);
	other143(233);
	other144(233);
	other145(233);
	other146(233);
	other147(233);
	other148(233);
	other149(233);
	other150(233);
	other151(233);
	other152(233);
	other153(233);
	other154(233);
	other155(233);
	other156(233);
	other157(233);
	other158(233);
	other159(233);
	other160(233);
	other161(233);
	other162(233);
	other163(233);
	other164(233);
	other165(233);
	other166(233);
	other167(233);
	other168(233);
	other169(233);
	other170(233);
	other171(233);
	other172(233);
	other173(233);
	other174(233);
	other175(233);
	other176(233);
	other177(233);
	other178(233);
	other179(233);
	other180(233);
	other181(233);
	other182(233);
	other183(233);
	other184(233);
	other185(233);
	other186(233);
	other187(233);
	other188(233);
	other189(233);
	other190(233);
	other191(233);
	other192(233);
	other193(233);
	other194(233);
	other195(233);
	other196(233);
	other197(233);
	other198(233);
	other199(233);
	other200(233);
	other201(233);
	other202(233);
	other203(233);
	other204(233);
	other205(233);
	other206(233);
	other207(233);
	other208(233);
	other209(233);
	other210(233);
	other211(233);
	other212(233);
	other213(233);
	other214(233);
	other215(233);
	other216(233);
	other217(233);
	other218(233);
	other219(233);
	other220(233);
	other221(233);
	other222(233);
	other223(233);
	other224(233);
	other225(233);
	other226(233);
	other227(233);
	other228(233);
	other229(233);
	other230(233);
	other231(233);
	other232(233);
	other233(233);
	other234(233);
	other235(233);
	other236(233);
	other237(233);
	other238(233);
	other239(233);
	other240(0);
	other241(0);
	other242(0x40);
	other243(0);
	other244(233);
	other245(233);
	other246(233);
	other247(233);
	other248(233);
	other249(233);
	other250(233);
	other251(233);
	other252(233);
	other253(233);
	other254(233);
	other255(233);
	
	other243(0);
	other242(0);
	other241(0);
	other240(0);
	
	upgrade(0xFF);
	fight(0);
}
```

exp.ll:
```llvm
; ModuleID = 'exp.c'
source_filename = "exp.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @fight(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @merge(i32, i32) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, i32* %3, align 4
  store i32 %1, i32* %4, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @destroy(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @upgrade(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @wuxiangdeyidao() #0 {
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @zhanjinniuza() #0 {
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @guobapenhuo() #0 {
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @tiandongwanxiang() #0 {
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other000(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other001(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other002(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other003(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other004(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other005(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other006(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other007(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other008(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other009(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other010(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other011(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other012(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other013(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other014(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other015(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other016(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other017(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other018(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other019(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other020(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other021(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other022(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other023(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other024(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other025(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other026(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other027(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other028(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other029(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other030(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other031(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other032(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other033(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other034(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other035(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other036(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other037(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other038(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other039(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other040(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other041(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other042(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other043(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other044(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other045(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other046(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other047(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other048(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other049(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other050(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other051(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other052(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other053(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other054(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other055(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other056(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other057(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other058(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other059(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other060(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other061(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other062(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other063(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other064(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other065(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other066(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other067(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other068(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other069(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other070(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other071(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other072(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other073(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other074(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other075(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other076(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other077(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other078(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other079(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other080(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other081(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other082(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other083(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other084(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other085(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other086(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other087(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other088(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other089(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other090(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other091(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other092(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other093(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other094(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other095(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other096(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other097(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other098(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other099(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other100(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other101(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other102(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other103(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other104(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other105(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other106(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other107(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other108(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other109(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other110(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other111(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other112(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other113(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other114(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other115(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other116(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other117(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other118(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other119(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other120(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other121(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other122(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other123(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other124(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other125(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other126(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other127(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other128(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other129(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other130(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other131(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other132(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other133(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other134(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other135(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other136(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other137(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other138(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other139(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other140(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other141(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other142(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other143(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other144(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other145(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other146(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other147(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other148(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other149(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other150(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other151(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other152(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other153(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other154(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other155(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other156(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other157(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other158(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other159(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other160(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other161(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other162(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other163(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other164(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other165(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other166(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other167(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other168(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other169(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other170(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other171(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other172(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other173(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other174(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other175(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other176(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other177(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other178(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other179(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other180(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other181(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other182(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other183(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other184(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other185(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other186(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other187(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other188(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other189(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other190(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other191(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other192(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other193(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other194(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other195(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other196(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other197(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other198(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other199(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other200(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other201(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other202(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other203(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other204(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other205(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other206(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other207(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other208(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other209(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other210(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other211(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other212(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other213(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other214(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other215(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other216(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other217(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other218(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other219(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other220(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other221(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other222(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other223(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other224(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other225(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other226(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other227(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other228(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other229(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other230(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other231(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other232(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other233(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other234(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other235(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other236(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other237(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other238(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other239(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other240(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other241(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other242(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other243(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other244(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other245(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other246(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other247(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other248(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other249(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other250(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other251(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other252(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other253(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other254(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @other255(i32) #0 {
  %2 = alloca i32, align 4
  store i32 %0, i32* %2, align 4
  ret void
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @gamestart() #0 {
  call void @tiandongwanxiang()
  call void @wuxiangdeyidao()
  call void @zhanjinniuza()
  call void @guobapenhuo()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @tiandongwanxiang()
  call void @wuxiangdeyidao()
  call void @zhanjinniuza()
  call void @other000(i32 233)
  call void @other001(i32 233)
  call void @other002(i32 233)
  call void @other003(i32 233)
  call void @other004(i32 233)
  call void @other005(i32 233)
  call void @other006(i32 233)
  call void @other007(i32 233)
  call void @other008(i32 233)
  call void @other009(i32 233)
  call void @other010(i32 233)
  call void @other011(i32 233)
  call void @other012(i32 233)
  call void @other013(i32 233)
  call void @other014(i32 233)
  call void @other015(i32 233)
  call void @other016(i32 233)
  call void @other017(i32 233)
  call void @other018(i32 233)
  call void @other019(i32 233)
  call void @other020(i32 233)
  call void @other021(i32 233)
  call void @other022(i32 233)
  call void @other023(i32 233)
  call void @other024(i32 233)
  call void @other025(i32 233)
  call void @other026(i32 233)
  call void @other027(i32 233)
  call void @other028(i32 233)
  call void @other029(i32 233)
  call void @other030(i32 233)
  call void @other031(i32 233)
  call void @other032(i32 233)
  call void @other033(i32 233)
  call void @other034(i32 233)
  call void @other035(i32 233)
  call void @other036(i32 233)
  call void @other037(i32 233)
  call void @other038(i32 233)
  call void @other039(i32 233)
  call void @other040(i32 233)
  call void @other041(i32 233)
  call void @other042(i32 233)
  call void @other043(i32 233)
  call void @other044(i32 233)
  call void @other045(i32 233)
  call void @other046(i32 233)
  call void @other047(i32 233)
  call void @other048(i32 233)
  call void @other049(i32 233)
  call void @other050(i32 233)
  call void @other051(i32 233)
  call void @other052(i32 233)
  call void @other053(i32 233)
  call void @other054(i32 233)
  call void @other055(i32 233)
  call void @other056(i32 233)
  call void @other057(i32 233)
  call void @other058(i32 233)
  call void @other059(i32 233)
  call void @other060(i32 233)
  call void @other061(i32 233)
  call void @other062(i32 233)
  call void @other063(i32 233)
  call void @other064(i32 233)
  call void @other065(i32 233)
  call void @other066(i32 233)
  call void @other067(i32 233)
  call void @other068(i32 233)
  call void @other069(i32 233)
  call void @other070(i32 233)
  call void @other071(i32 233)
  call void @other072(i32 233)
  call void @other073(i32 233)
  call void @other074(i32 233)
  call void @other075(i32 233)
  call void @other076(i32 233)
  call void @other077(i32 233)
  call void @other078(i32 233)
  call void @other079(i32 233)
  call void @other080(i32 233)
  call void @other081(i32 233)
  call void @other082(i32 233)
  call void @other083(i32 233)
  call void @other084(i32 233)
  call void @other085(i32 233)
  call void @other086(i32 233)
  call void @other087(i32 233)
  call void @other088(i32 233)
  call void @other089(i32 233)
  call void @other090(i32 233)
  call void @other091(i32 233)
  call void @other092(i32 233)
  call void @other093(i32 233)
  call void @other094(i32 233)
  call void @other095(i32 233)
  call void @other096(i32 233)
  call void @other097(i32 233)
  call void @other098(i32 233)
  call void @other099(i32 233)
  call void @other100(i32 233)
  call void @other101(i32 233)
  call void @other102(i32 233)
  call void @other103(i32 233)
  call void @other104(i32 233)
  call void @other105(i32 233)
  call void @other106(i32 233)
  call void @other107(i32 233)
  call void @other108(i32 233)
  call void @other109(i32 233)
  call void @other110(i32 233)
  call void @other111(i32 233)
  call void @other112(i32 233)
  call void @other113(i32 233)
  call void @other114(i32 233)
  call void @other115(i32 233)
  call void @other116(i32 233)
  call void @other117(i32 233)
  call void @other118(i32 233)
  call void @other119(i32 233)
  call void @other120(i32 233)
  call void @other121(i32 233)
  call void @other122(i32 233)
  call void @other123(i32 233)
  call void @other124(i32 233)
  call void @other125(i32 233)
  call void @other126(i32 233)
  call void @other127(i32 233)
  call void @other128(i32 233)
  call void @other129(i32 233)
  call void @other130(i32 233)
  call void @other131(i32 233)
  call void @other132(i32 233)
  call void @other133(i32 233)
  call void @other134(i32 233)
  call void @other135(i32 233)
  call void @other136(i32 233)
  call void @other137(i32 233)
  call void @other138(i32 233)
  call void @other139(i32 233)
  call void @other140(i32 233)
  call void @other141(i32 233)
  call void @other142(i32 233)
  call void @other143(i32 233)
  call void @other144(i32 233)
  call void @other145(i32 233)
  call void @other146(i32 233)
  call void @other147(i32 233)
  call void @other148(i32 233)
  call void @other149(i32 233)
  call void @other150(i32 233)
  call void @other151(i32 233)
  call void @other152(i32 233)
  call void @other153(i32 233)
  call void @other154(i32 233)
  call void @other155(i32 233)
  call void @other156(i32 233)
  call void @other157(i32 233)
  call void @other158(i32 233)
  call void @other159(i32 233)
  call void @other160(i32 233)
  call void @other161(i32 233)
  call void @other162(i32 233)
  call void @other163(i32 233)
  call void @other164(i32 233)
  call void @other165(i32 233)
  call void @other166(i32 233)
  call void @other167(i32 233)
  call void @other168(i32 233)
  call void @other169(i32 233)
  call void @other170(i32 233)
  call void @other171(i32 233)
  call void @other172(i32 233)
  call void @other173(i32 233)
  call void @other174(i32 233)
  call void @other175(i32 233)
  call void @other176(i32 233)
  call void @other177(i32 233)
  call void @other178(i32 233)
  call void @other179(i32 233)
  call void @other180(i32 233)
  call void @other181(i32 233)
  call void @other182(i32 233)
  call void @other183(i32 233)
  call void @other184(i32 233)
  call void @other185(i32 233)
  call void @other186(i32 233)
  call void @other187(i32 233)
  call void @other188(i32 233)
  call void @other189(i32 233)
  call void @other190(i32 233)
  call void @other191(i32 233)
  call void @other192(i32 233)
  call void @other193(i32 233)
  call void @other194(i32 233)
  call void @other195(i32 233)
  call void @other196(i32 233)
  call void @other197(i32 233)
  call void @other198(i32 233)
  call void @other199(i32 233)
  call void @other200(i32 233)
  call void @other201(i32 233)
  call void @other202(i32 233)
  call void @other203(i32 233)
  call void @other204(i32 233)
  call void @other205(i32 233)
  call void @other206(i32 233)
  call void @other207(i32 233)
  call void @other208(i32 233)
  call void @other209(i32 233)
  call void @other210(i32 233)
  call void @other211(i32 233)
  call void @other212(i32 233)
  call void @other213(i32 233)
  call void @other214(i32 233)
  call void @other215(i32 233)
  call void @other216(i32 233)
  call void @other217(i32 233)
  call void @other218(i32 233)
  call void @other219(i32 233)
  call void @other220(i32 233)
  call void @other221(i32 233)
  call void @other222(i32 233)
  call void @other223(i32 233)
  call void @other224(i32 233)
  call void @other225(i32 233)
  call void @other226(i32 233)
  call void @other227(i32 233)
  call void @other228(i32 233)
  call void @other229(i32 233)
  call void @other230(i32 233)
  call void @other231(i32 233)
  call void @other232(i32 233)
  call void @other233(i32 233)
  call void @other234(i32 233)
  call void @other235(i32 233)
  call void @other236(i32 233)
  call void @other237(i32 233)
  call void @other238(i32 233)
  call void @other239(i32 233)
  call void @other240(i32 0)
  call void @other241(i32 0)
  call void @other242(i32 64)
  call void @other243(i32 0)
  call void @other244(i32 233)
  call void @other245(i32 233)
  call void @other246(i32 233)
  call void @other247(i32 233)
  call void @other248(i32 233)
  call void @other249(i32 233)
  call void @other250(i32 233)
  call void @other251(i32 233)
  call void @other252(i32 233)
  call void @other253(i32 233)
  call void @other254(i32 233)
  call void @other255(i32 233)
  call void @other243(i32 0)
  call void @other242(i32 0)
  call void @other241(i32 0)
  call void @other240(i32 0)
  call void @upgrade(i32 255)
  call void @fight(i32 0)
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-frame-pointer-elim"="true" "no-frame-pointer-elim-non-leaf" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 8.0.1-9 (tags/RELEASE_801/final)"}
```
![](https://img-blog.csdnimg.cn/a67919daf1d345f98c122c9af2d30788.png)
成功getshell。
