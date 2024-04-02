最近因为学校考试所以没怎么看pwn，但是中间虚拟机崩掉过，问题还挺严重。前几天发现能正常打开了，但是一用gdb就会出现下面让人窒息的提醒：
![](https://img-blog.csdnimg.cn/1118668a806b41028cc14e752435d8b3.png)
怎么调都不知道是怎么回事，很奇怪的是只有在开gdb的时候才会弹出这个错误，其他都是正常的。问过师傅时候无奈只能放弃这个与我并肩作战这么长时间的ubuntu 20.04，重装一个虚拟机。一不做二不休，干脆就将整个过程记录下来，便于日后查询。

# 虚拟机日常维护注意事项
在最新的VMware中对虚拟机有一个<font color="00FF00">**保护选项**</font>，可以在指定时间间隔内保存一个快照，这样在虚拟机崩溃的时候能够快速回档到前两天的快照中，有效减少文件等的损失，而不必每次都手动保存快照。（有读者可能会怀疑为什么我不能对崩掉的虚拟机回档，实际上我做了尝试，但是上面的问题还是存在，这就不是虚拟机状态的问题了，而是某些底层硬件配置的问题，可能是硬件出问题导致调试无法进行，但具体的我也不知道应该如何处理，因此只能重装）
![](https://img-blog.csdnimg.cn/d444eaec57f84fcfb4b79e13ff2a5a3b.png)
如上图所示，在虚拟机设置->选项中可以找到自动保护选项，根据你设置的保护间隔和最大自动保护快照数量可以计算出至少需要的磁盘空间，因此需要<font color=red>**保证有足够的磁盘空间**</font>。

另外，当虚拟机<font color=blue>**存在快照**</font>时，是<font color=blue>**不能扩充磁盘容量**</font>的，因此要想扩充虚拟机的虚拟磁盘，要么<font color=red>**在创建虚拟机时就分配足够大小的磁盘空间**</font>，要么就只能<font color=red>**删除所有的快照**</font>后再进行扩充（建议前者，因为有的快照删除特别慢，如果快照多的话可能要等很长时间）

# 从零搭建环境
下面就将介绍如何从零搭建一个CTF-pwn环境（由于学习仍在进行，故一些环境如远程执行环境还没有搭建的经历，如今后需要搭建，会在最后进行补充）

## 1. 创建虚拟机
可以在ubuntu官方网站上下载最新的长期支持版本，在笔者写这篇文章的时候，这个版本已经是22.04了，但还是按照20.04的版本来安装。[22.04下载](https://cn.ubuntu.com/download/desktop)/[历史版本下载](https://cn.ubuntu.com/download/alternative-downloads)

![](https://img-blog.csdnimg.cn/fbc36cfdc2414f00a9b91ba913680866.png)
下载的是光盘映像文件，将其放在虚拟机的工作目录中。

然后选择vmware上方工具栏的文件->新建虚拟机，打开新建虚拟机向导。如下：
![](https://img-blog.csdnimg.cn/a2b603c88beb4a01a2d03daf109f6bca.png)
选择自定义安装，点击下一步。

![](https://img-blog.csdnimg.cn/05cef1de90f44e33948d9db9ed60ce49.png)
硬件兼容性不需要改，一般默认选择最新的vmware版本兼容，你的vmware是什么版本就用什么版本，不用修改，直接点击下一步。

![](https://img-blog.csdnimg.cn/f20d9df8ab8b4a3a8d643e03acf74409.png)
选择安装程序光盘映像文件，点击浏览，选择你刚才下载的映像文件，然后点击下一步。

![](https://img-blog.csdnimg.cn/ed013bbc66f14150b85bf2f31b404d67.png)
输入全名（这个随便输，想输什么都行），以及你登录虚拟机的用户名和密码。之后点击下一步。

![](https://img-blog.csdnimg.cn/ec085415468345b3902738076ee21701.png)
输入虚拟机的名字，将位置浏览设置为你的虚拟机工作目录。

![](https://img-blog.csdnimg.cn/6e10263a29424dc8a6dd82c4828a2fac.png)
处理器数量选择。如果你的电脑配置很好而且虚拟机也需要一定的计算需要，可以设置多一些，内核数量不变，修改处理器数量。但是总数不能超过你电脑主机的内核数量。我一般选择8处理器。

![](https://img-blog.csdnimg.cn/bcd9df7260474273ba3396432d0f7c12.png)
内存大小设置。同样看主机的配置。最好不要超过主机的内存大小，否则虚拟机可能会变慢。对于pwn做题来说4GB一般就足够了。

![](https://img-blog.csdnimg.cn/089f64591a3f44b4b89500994bc8cfbc.png)
网络选择。这个网络的选择可以在虚拟机创建之后随时修改，这里简单介绍一下最常用的前两种：**桥接网络和NAT**。桥接网络如上面所说，直接访问外部以太网，前提是虚拟机要有自己的IP地址，因此桥接网络在使用的时候大多都是勾选“与主机共用IP地址”这个选项（这个选项在创建虚拟机到这一步的时候没有显示，但是可以在上方工具栏**虚拟机->设置**中找到并勾选，后面再说）。某些学校的校园网可能有接入设备数量限制（笔者学校就是），这个时候虚拟机选择桥接网络可能无法联网，可以考虑使用NAT模式，在这个模式下，主机相当于一个网关，而虚拟机为网关下的机器，与外部以太网连接需要借助主机。这种模式可以有效克服上面说的校园网接入数量限制问题。
因此这里选择默认NAT，**最好能够保证开机之后立刻联网**呃，因为需要下载一些包，安装完成之后也能改。以默认NAT进行下一步。

![](https://img-blog.csdnimg.cn/36d4869449b84b94aa7fa2f406eb89a4.png)
IO控制器类型，不用改直接下一步。

![](https://img-blog.csdnimg.cn/f9be0b0f51be4b2caa1999af5c1e23d0.png)
磁盘类型也不用改，直接下一步。

![](https://img-blog.csdnimg.cn/63db1daec903499a9a9fc6a732cd22cf.png)
磁盘类型不用改，下一步。

![](https://img-blog.csdnimg.cn/829ad28e615a47078c51ee00902065c0.png)
磁盘空间设置这里，除了最大磁盘大小之外其他都不要改。为了避免出现磁盘空间不足的问题，笔者这里设置为200GB。这个大小根据自己的物理磁盘空间决定，但是不要太小，**建议pwner们不要小于60GB**，后面做kernel pwn搭建环境可能很占空间的。

![](https://img-blog.csdnimg.cn/dc5e00ac7bee40999ce223c0800a783b.png)
磁盘文件，不用改直接下一步。

![](https://img-blog.csdnimg.cn/0adc1d23dbc444cb9a227d560637cce3.png)
上面是最后确认的界面，确定好虚拟机的配置后，点击完成就可以开始创建虚拟机了。

![](https://img-blog.csdnimg.cn/0b22f4d4bfbb424996917c500c5e425d.png)
之后是自动开机安装过程，耐心等待一段时间......

![](https://img-blog.csdnimg.cn/24d1b1c99b45470eb055da0258e3754f.png)
大约10分钟之后，我们就能够登录ubuntu系统了。

![](https://img-blog.csdnimg.cn/e6147fd6490848d3b412eafc799b43d8.png)
在笔者的vmware中，linux系统在安装的时候就已经安装了VMware Tools，它能够帮助你更加快捷地在主机和虚拟机中传递文件，只需拖动即可。但是笔者的虚拟机只能从打开的文件夹中拖动文件到主机，不能从桌面上直接拖动复制，从主机复制文件到虚拟机也是必须复制到打开的文件夹中。

自此，我们的ubuntu系统就成功搭建好了，下面进行一些配置使虚拟机能够更加轻松方便地使用。

## 2. 默认root权限设置
在做题的时候，如果我们能够直接以root的身份登录，就不需要输入n多次的密码了。

参考[资料](https://blog.csdn.net/willhu2008/article/details/121699938?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165499613116782184643247%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165499613116782184643247&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~baidu_landing_v2~default-4-121699938-null-null.142^v13^control,157^v14^control&utm_term=ubuntu20.04%E9%BB%98%E8%AE%A4root%E7%99%BB%E5%BD%95&spm=1018.2226.3001.4187)进行操作即可。根据步骤来，实测有效。

![](https://img-blog.csdnimg.cn/c8c04eda32054cc1a0b4c703d6a16c8d.png)
注意正上方的提示，重启之后我们已经成功自动以root用户登录了，完成。

## 3. 安装vim
``apt install vim``即可

## 4. 修改软件源
ubuntu自带的软件源是国外的，速度慢有的时候还连不上，于是应修改为国内的镜像。

[镜像与修改方法](https://blog.csdn.net/m0_37317193/article/details/121310922?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165499699616780366572573%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165499699616780366572573&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-121310922-null-null.142^v13^control,157^v14^control&utm_term=ubuntu20.04%E9%95%9C%E5%83%8F%E6%BA%90%E9%98%BF%E9%87%8C%E4%BA%91&spm=1018.2226.3001.4187)

笔者选择阿里云镜像。

修改完文件之后记得``apt update``和``apt upgrade``进行更新。第一次更新可能需要等一段时间，看你的网速怎么样......

## 5. 安装sublime-text（非必要）
使用系统自带的gedit没有补全功能，可以在ubuntu应用商店里面搜索sublime-text安装，打开py文件的时候右键选中“Open with other application”就可以使用sublime-text打开了。（这里图标显示不出来，但是安装没有问题）

![](https://img-blog.csdnimg.cn/f2016d8b64ef4c6bb096c51ed28912e2.png)
## 6. 安装pwntools
pwntools是pwn最常用的一个python包。
首先需要安装pip：``apt install python3-pip``
然后安装pwntools：``pip install pwntools``
完成。

## 7. 安装pwndbg
pwndbg是gdb的插件，帮助我们在做题时进行调试。
首先安装git：``apt install git``
然后拉取git库：``git clone https://github.com/pwndbg/pwndbg``
进入pwndbg目录运行bash脚本``setup.sh``即开始安装

![](https://img-blog.csdnimg.cn/cb873d25bd134315bbaebca8d40fcf34.png)
运行gdb下有pwndbg标识即表示安装成功。

## 8. 安装LibcSearcher
请参考[资料](https://blog.csdn.net/qq_40026795/article/details/107150265?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165501579816780357270501%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165501579816780357270501&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-107150265-null-null.142^v13^control,157^v14^control&utm_term=libcsearcher%E5%AE%89%E8%A3%85&spm=1018.2226.3001.4187)

注意不要使用~~pip install LibcSearcher~~，这两个是不一样的，链接中的是国人写的，准确度相对高一些。

## 9. 安装checksec

请参考[资料](https://blog.csdn.net/qq_43430261/article/details/105516051?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522165501780216782248583442%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=165501780216782248583442&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-1-105516051-null-null.142^v13^control,157^v14^control&utm_term=checksec%E5%AE%89%E8%A3%85&spm=1018.2226.3001.4187)

**到这一步完成之后，一般的pwn题就可以开始做了。如果需要kernel环境，则继续下面的步骤。**

## 10. 安装qemu
使用``apt list qemu*``可查看所有前缀为qemu的包。可以看到这里有很多支持不同架构的qemu。
![](https://img-blog.csdnimg.cn/13fca94a56444dda939c9563a457da77.png)
根据自己的需要安装对应架构的包即可。一般最为常用的是x86架构：``apt install qemu-system-x86``，注意不能只输入``apt install qemu``。

## 11. 配置kernel pwn环境
较为复杂，这里给出笔者以前写的资料。
[资料](https://blog.csdn.net/qq_54218833/article/details/124360103)

## 12. 安装vmlinux-to-elf
这是一个用于将bzImage解压为vmlinux的工具，在kernel pwn中经常用到：
```bash
git clone https://github.com/marin-m/vmlinux-to-elf
cd vmlinux-to-elf
sudo python3 ./setup.py install
```
然后就可以使用vmlinux-to-elf命令进行解压了。

## 13. ARM pwn环境搭建
参考[资料](https://blog.csdn.net/qq_38154820/article/details/125875703?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522166613948816782427428087%2522%252C%2522scm%2522%253A%252220140713.130102334..%2522%257D&request_id=166613948816782427428087&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduend~default-2-125875703-null-null.142^v59^pc_rank_34_1,201^v3^control_1&utm_term=arm%20pwn&spm=1018.2226.3001.4187)中的做法如下：

虽然说在x86-64的机器上无法直接运行ARM架构的elf文件，但我们可以通过qemu来实现。虽然可以使用docker在x86-64的机器上创建一个ARM架构的docker容器，但太过麻烦，在容器中还需要安装很多东西。因此可以直接使用qemu与gdb-multiarch配合。

实际上qemu不仅可以用来起一个qemu容器，还可以仅仅运行一个其他架构的elf文件，可以添加选项``-g <端口号>``将elf程序映射到某一个端口，而且还会等待接入，只有当我们使用gdb-multiarch接入时才会开始准备执行其中的第一条指令，非常方便我们下断点。

```bash
sudo apt install gdb-multiarch
sudo apt install qemu-user-static
```
如果要执行的文件名为./pwn，则使用qemu执行该ARM可执行文件的命令为：
``qemu-arm-static -g 9999 -L . ./pwn``
之后启动gdb-multiarch：
``gdb-multiarch ./pwn``
连接端口：
``pwndbg> target remote 9999``
即可开始调试。
如果想直接执行不调试，只需要删除qemu-arm-static中的-g选项即可。
