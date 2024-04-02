笔者学习pwn已经有一段时间了，有的时候想回顾一些知识点，翻看以前的文章却发现很难查找。这里编写一个快速索引，帮助自己以及各位读者快速找到自己需要了解的知识点。

笔者的github仓库内含多个方向的pwn题，在文章中分析过的题目会及时更新到这个仓库中：[pwnfile](https://github.com/Hornos3/pwnfile)

更新：由于做的题越来越多，github仓库不堪重负，为精简仓库，现将题目附件另外保存到网盘上，使读者能够选择性下载想要研究的题目而不是非要更新整个仓库。原github仓库只保存解题exp，如有不便敬请谅解。

链接：[https://pan.baidu.com/s/12_wpe0icND_Z5VXlLloKNg](https://pan.baidu.com/s/12_wpe0icND_Z5VXlLloKNg)
提取码：ipwn

# 1. glibc分析系列
[how2heap深入学习(1)](https://blog.csdn.net/qq_54218833/article/details/122868272)：glibc 2.23版本fastbin_dup、fastbin_dup_consolidate、fastbin_into_stack、house_of_einherjar、house_of_force、house_of_lore，部分_int_free函数检查（2.23版本）
[how2heap深入学习(2)](https://blog.csdn.net/qq_54218833/article/details/122897689)：glibc 2.23版本house_of_mind_fastbin、house_of_orange
[how2heap深入学习(3)](https://blog.csdn.net/qq_54218833/article/details/123306684)：glibc 2.23版本house_of_roman、house_of_spirit、house_of_storm
[how2heap深入学习(4)](https://blog.csdn.net/qq_54218833/article/details/123395646)：glibc 2.23版本large_bin_attack、mmap_overlapping_chunks、overlapping_chunks、overlapping_chunks_2、poison_null_byte
[how2heap深入学习(5)](https://blog.csdn.net/qq_54218833/article/details/123407435)：glibc 2.23版本unsafe_unlink、unsorted_bin_attack、unsorted_bin_into_stack
[how2heap深入学习(6)](https://blog.csdn.net/qq_54218833/article/details/123444930)：glibc 2.27版本fastbin_dup、fastbin_reverse_into_tcache、house_of_botcake、house_of_einherjar、house_of_force、house_of_lore
[how2heap深入学习(7)](https://blog.csdn.net/qq_54218833/article/details/123588647)：glibc 2.27版本house_of_mind_fastbin、house_of_storm，large_bin的链入过程
[how2heap深入学习(8)](https://blog.csdn.net/qq_54218833/article/details/123630186)：glibc 2.27版本large_bin_attack、mmap_overlapping_chunks、overlapping_chunks、poison_null_byte、tcache_house_of_spirit、tcache_poisoning、tcache_stashing_unlink_attack、unsafe_unlink，切割large_bin返回chunk的过程
[how2heap深入学习(9)](https://blog.csdn.net/qq_54218833/article/details/124239224)：glibc 2.31版本_int_malloc、_int_free函数堆块检查
[house of emma演示程序](https://blog.csdn.net/qq_54218833/article/details/126401517)：高版本glibc利用方式house of emma演示过程详细分析
[house of kiwi演示程序](https://blog.csdn.net/qq_54218833/article/details/128484409)：高版本glibc利用方式house of kiwi演示过程详细分析
[house of pig原题分析与演示程序](https://blog.csdn.net/qq_54218833/article/details/128575508)：glibc 2.31版本house of pig演示过程及原题详细分析
[house of apple v1演示程序](https://blog.csdn.net/qq_54218833/article/details/128624427)：glibc 2.35版本house of apple v1演示过程详细分析

# 2. Kernel pwn系列
[Kernel pwn 入门 (1)](https://blog.csdn.net/qq_54218833/article/details/124360103)：搭建kernel环境需要注意的问题、强网杯2018-core **ROP**法题解分析
[Kernel pwn 入门 (2)](https://blog.csdn.net/qq_54218833/article/details/124411025)：CISCN2017-babydriver **ret2usr**法题解分析（低版本内核SMAP/SMEP的绕过）
[Kernel pwn 入门 (3)](https://blog.csdn.net/qq_54218833/article/details/125647404)：LCTF2022-kgadget **ret2dir**法题解分析
[Kernel pwn 入门 (4)](https://blog.csdn.net/qq_54218833/article/details/124521291)：CISCN2017-babydriver另解，伙伴系统简介，InCTF-kqueue **内核堆溢出**法题解分析
[Kernel pwn 入门 (5)](https://blog.csdn.net/qq_54218833/article/details/125875027)：0CTF2018-baby **条件竞争（double fetch）** 题解分析
[Kernel pwn 入门 (6)](https://blog.csdn.net/qq_54218833/article/details/126004590)：强网杯2021-notebook **userfaultfd**法题解分析
[Kernel pwn 入门 (7)](https://blog.csdn.net/qq_54218833/article/details/126571321)：D^3CTF2019-knote **modprobe_path**学习与题解分析
[Kernel pwn 入门 (8)](https://blog.csdn.net/qq_54218833/article/details/127218102)：Linux内核内存分配机制简述（伙伴系统、slab、slub）

# 3. llvm pass pwn系列
[LLVM pass pwn 入门 (1)](https://blog.csdn.net/qq_54218833/article/details/125685242)：llvm pass基础知识
[LLVM pass pwn 入门 (2)](https://blog.csdn.net/qq_54218833/article/details/125699994)：CISCN-2021 satool 题解分析，llvm pass类题目调试方法
[LLVM pass pwn 入门 (3)](https://blog.csdn.net/qq_54218833/article/details/125853210)：红帽杯2021-simpleVM 题解分析
[LLVM pass pwn 入门 (4)](https://blog.csdn.net/qq_54218833/article/details/125879635)：CISCN-2022 satool 题解分析
[LLVM pass pwn 实战](https://blog.csdn.net/qq_54218833/article/details/126081315)：强网杯2022 yakagame 题解分析

# 4. buuoj 刷题记录
[buuctf-pwn write-ups (1)](https://blog.csdn.net/qq_54218833/article/details/124530348)：1~16题
[buuctf-pwn write-ups (2)](https://blog.csdn.net/qq_54218833/article/details/124533708)：17~26题，其中第26题是堆题
[buuctf-pwn write-ups (3)](https://blog.csdn.net/qq_54218833/article/details/124639635)：27~31题
[buuctf-pwn write-ups (4)](https://blog.csdn.net/qq_54218833/article/details/124834530)：32~38题，其中第38题沙箱初探
[buuctf-pwn write-ups (5)](https://blog.csdn.net/qq_54218833/article/details/125251517)：39~46题
[buuctf-pwn write-ups (6)](https://blog.csdn.net/qq_54218833/article/details/125385767)：47~53题，其中第53题是C++ pwn
[buuctf-pwn write-ups (7)](https://blog.csdn.net/qq_54218833/article/details/125458227)：54~61题，其中第60题考linux命令
[buuctf-pwn write-ups (8)](https://blog.csdn.net/qq_54218833/article/details/125567534)：62~66题
[buuctf-pwn write-ups (9)](https://blog.csdn.net/qq_54218833/article/details/125600497)：67~72题

# 5. ARM pwn 系列
[ARM pwn 入门 (1)](https://blog.csdn.net/qq_54218833/article/details/127658611)：ARM基础知识
[ARM pwn 入门 (2)](https://blog.csdn.net/qq_54218833/article/details/127658611)：第一道ARM pwn——buuoj 第139题 jarvisoj_typo
[ARM pwn 入门 (3)](https://blog.csdn.net/qq_54218833/article/details/127716198)：ROP Emporium ARM版本1-2题
[ARM pwn 入门 (4)](https://blog.csdn.net/qq_54218833/article/details/127723312)：ROP Emporium ARM版本3-5题

# 6. musl pwn系列
[musl pwn 入门 (1)](https://blog.csdn.net/qq_54218833/article/details/127316863)：musl内存分配关键数据结构与函数介绍
[musl pwn 入门 (2)](https://blog.csdn.net/qq_54218833/article/details/128692531)：musl libc内存分配free函数的unlink利用方式与演示程序
[musl pwn 入门 (3)](https://blog.csdn.net/qq_54218833/article/details/128728282)：musl libc的FSOP原理介绍与演示程序
[musl pwn 入门 (4)](https://blog.csdn.net/qq_54218833/article/details/128797680)：musl libc例题分析：DefCon Quals 2021 mooosl **<最新>**

# 7. 杂项
[ROP Emporium 1-6题](https://blog.csdn.net/qq_54218833/article/details/124061198)：x86_64架构
[ROP Emporium 7-8题](https://blog.csdn.net/qq_54218833/article/details/124069737)：x86_64架构
