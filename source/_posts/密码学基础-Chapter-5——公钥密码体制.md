---
title: 密码学基础 Chapter 5——公钥密码体制
date: 2023-02-28 23:00:16
categories:
- 课内笔记
- 密码学基础
---
# 公钥密码体制
## 对称密钥的三大问题
1. 密钥交换
2. 密钥管理：每两个用户之间的密钥都不相同
3. 抵赖行为：不承认发送过某条消息

## 单向陷门函数
希望可以找到一个密码体制，对于给定的加密e~k~，除了消息接受者，求d~k~在计算上不可行。其中e~k~可公开，无需分享密钥。
单向函数：一个函数容易计算但求逆困难。（还没有一个函数没证明单向）
单向陷门函数：存在一个单向函数，该函数在具有特定知识（称为陷门）后容易求逆

## 单向函数定义
假定n=pq（p、q为不同的大素数），b为正整数，定义f：Z~n~→Z~n~，f(x)=x^b^ mod n
陷门：大数n的因式分解
若已知n的因式分解n=pq，则$\varphi(n)$=(p-1)(q-1)
若gcd(b,φ(n))=1，且ab$\equiv$ 1 mod φ(n)
f^-1^：Z~n~→Z~n~，f^-1^(x)=x^a^ mod n

## 公钥密码使用方式
用于加密：公钥加密私钥解密，无需交换密钥
用于认证：防止抵赖，如果要证明某文件为自己生成，则可以使用自己的私钥加密，其他人接收到之后通过公钥验证签名，用手中的所有公钥尝试，使用谁的公钥能够解密就是谁生成的文件

# RSA算法
## 数学基础
欧拉定理：$(a,n)=1,a^{\varphi(n)}\equiv 1\pmod n$
费马小定理：$a^p\equiv a\pmod p$

## 密码算法
n=pq，K={(n,p,q,e,d): ed$\equiv$ 1 mod φ(n)}
定义$e_k(x)=x^e\pmod n,d_k(y)=y^d\pmod n,(x,y\in Z_n)$，(n,e)为公钥，(n,d)为私钥

## 参数生成
素性检测、公私钥对
加解密过程的快速实现：
- 平方-乘算法
- 蒙哥马利算法
- 中国剩余定理加速解密
### 平方-乘算法
要计算$a^b\mod n$：
$$b=\sum_{i=0}^{l-1}b_i2^i,b_i\in\{0,1\},b_{l-1}=1\\
b=b_{l-1}2^{l-1}+b_{l-2}2^{l-2}+...+b_1\cdot 2+b_0\\
=2(2(...(2(b_{l-1})+b_{l-2})+...)+b_1)+b_0\\
a^b=a^{\sum_{i=0}^{l-1}b_i2^i}=(((...(1\times a^{b_{l-1}})^2\times a^{b_{l-2}})^2\times ...)^2\times a^{b_1})^2\times a^{b_0}$$
（实际上就是模平方重复法的变体）
![](1.jpeg)
如上图示例：
9726^2^ $\equiv$ 2659(mod 11413)
2659^2^ $\equiv$ 5634(mod 11413)


### 蒙哥马利算法
**蒙哥马利变换**
d=2^32^，2^64^，假设d=2^32^
模N：：k=32n比特奇数，IN=-N^-1^ mod 2^32^
R=d^n^>N，(R,N)=1，a,b∈Z~N~
A=Mont(a) = aR mod N
MontInv(A) = AR^-1^ mod N
MontInv(Mont(a)) = a mod N

A = Mont(a), B = Mont(b)
MontMult(A,B)=ABR^-1^ = aRbRR^-1^ = abR mod N = Mont(ab mod N)
MontMult(A,MontMult(A,A))=Mont(a^3^ mod N)

MontMult(A,B) = ABR^-1^ mod N
T = AB, 2n位整数，T=(0t~2n-1~t~2n-2~...t~1~t~0~)
计算T'=T+N×((t~0~×IN) mod 2^32^)
(1) T' = T mod N
(2) T' = t~0~+(N×IN)t~0~ = 0 mod 2^32^
(3) T' >> 32, T' = T×2^32^ mod N
令T=T', 重复上述步骤n次，T×2^-32n^ = TR^-1^ mod N
T' = (0ct~n-1~'t~n-2~'...t~0~')，如果T'>N，返回T'-N，否则返回T'=(t~n-1~'t~n-2~'...t~0~')

快速模幂运算a^e^ mod N

### 中国剩余定理
把解密时的一个式子拆成两个式子来算（模p和q）

### 素数定理
$$\pi(N)\approx\frac{N}{\ln N}$$
若n=pq，为1024比特，则p,q为512比特
$\frac{1}{\ln 2^{512}}\approx\frac{1}{355}$（为素数的概率）

### 素性检测
**费马素性检测**：若p为素数，(a,p)=1，则a^p-1^ = 1 mod p

**伪素数**：设n为奇合数，如果整数b，(b,n)=1，使得b^n-1^=1 mod n，则称n为对于基b的伪素数

**Euler伪素数**：设n为正奇合数，整数b，(b,n)=1，满足$b^{\frac{p-1}{2}}\equiv (\frac{b}{n})\mod n$，称n为对于基b的Euler伪素数

p-1=2^s^t，$a^{p-1}-1=(a^{2^{s-1}t}+1)(a^{2^{s-2}t}+1)...(a^{t}+1)(a^{t}+1)$
则下列同余式中至少有一个成立：
$a^t\equiv -1\mod p, a^{2t}\equiv -1\mod p,...,a^{2^{s-1}t}\equiv -1\mod p$
**强伪素数**：设n为奇合数，n-1=2^s^t，t为奇数，整数b与n互素，满足b^t^=1 mod n，或者存在r，0≤r<s，有$b^{2^rt}\equiv -1\mod n$，称n为对于基b的强伪素数

**Solovay-Strassen算法**
随机选择整数a在1到n-1之间，x=$(\frac{a}{n})$，若x=0则n为合数；若$x\equiv a^{\frac{n-1}{2}}\pmod n$则n是素数，否则为合数（计算雅可比符号）
判断具有1/2的错误概率（若n为素数则输出一定为素数，若n为合数则有1/2的概率输出为合数）

**Miller-Rabin算法**
n-1=2^s^t的形式，其中t为奇数
随机选择整数a在1到n-1之间
计算$b=a^t\mod n$
如果$b\equiv 1\pmod n$，那么n为素数；否则进行下列循环：
for i=0 to s-1:
if $b\equiv -1\pmod n$，then n是素数
else b=b^2^ mod n
若循环能结束则n为合数

若n为强伪素数，则输出可能为素数；若n为素数，则输出一定为素数，具有1/4的错误概率，优于Solovay-Strassen算法

**AKS算法**
确定性素性检测方法
理论基础：$a\in Z,n\in N,n\ge 2,(a,n)=1$，n是素数，当且仅当$(x+a)^n=x^n+a\pmod n$
该算法为该理论复杂度的改进：$(x+a)^n=x^n+a\pmod {x^r-1,n}$
算法的时间复杂度高于概率算法
- 若存在整数a>0且b>1，满足n=a^b^，则输出合数
- 找出满足$\operatorname {ord}_r(n)>\log_2n$的最小的r
- 若对a≤r，1<gcd(a,n)<n，输出合数
- 若n≤r，输出素数
- for a=1 to $\lfloor{\sqrt{\varphi(r)}\log n}\rfloor$ do
	- if (x+a)^n^≠x^n^+a (mod x^r^-1, n)，输出合数
- 输出素数

## 共模攻击
给群组中每个人相同的公钥n，但指数e和d不同时可能产生共模攻击
- 对于群组内成员，即使不分解n也可以解密其他人消息
$e_1d_1\equiv 1\mod \varphi(n),e_2d_2\equiv 1\mod \varphi(n)$
$e_2d_2'\equiv 1\mod(e_1d_1-1)\Rightarrow e_2d_2'\equiv 1\mod \varphi(n)$
（自己有$e_1,d_1$，因此可以计算$d_2'$）
- 群组外人员如果截获到发送给群组不同成员的同一消息，而两个加密指数互素，则可以直接恢复消息
令m为明文消息，加密指数为$e_1,e_2$，且二者互素，故存在r,s使得$re_1+se_2=1$，假设r为负数
则$(c_1^{-1})^{-r}c_2^s=m^{re_1+se_2}=m\mod n$

## 小加密指数攻击
若选择的e较小（如3），则加密会很快
**Coppersmith定理攻击**：n为大整数，f为次数为e的多项式，可以在log n时间内有效计算出f(x)=0 mod n的小于$n^{\frac{1}{e}}$的解。
应避免使用小的加密指数，e最少应选取2^16^+1=65537
在短消息加密之前应该首先填充

## 总结
教科书式的RSA方案是不安全的，速度慢是其主要缺点（硬件实现比DES慢1000倍，软件慢100倍，选择特定的e值能够大大加快RSA的速度）
可用于加密、密钥交换和数字签名

# Rabin密码体制
设n=pq，其中p,q为素数，均为4k+3型素数
P=C=Z~n~，且定义K={(n,p,q)}
对于k=(n,p,q)，定义
$e_k(x)=x^2\pmod n, d_k(y)=\sqrt y\pmod n$
（x,y∈Z~n~），其中n为公钥，p、q为私钥

这是一个单向陷门函数，陷门为n的分解。f(x)=x^2^ mod n

# 公开密钥算法
加密：$C=E_{K_{pub}}(P)$
解密：$P=D_{K_{prv}}(C)$
两个密钥不能相互推导（或推导的难度不亚于密码分析）
其中一个密钥公开（$K_{pub}$），另一个密钥保密（$K_{prv}$）
每一个用户掌握一个私钥，并将相应的公钥放在公共目录中

问题：如何让别人正确知道你的公钥？（如何保证你发出的公钥不被篡改/如何证明一个公钥是不是你的？）
答案：通过可信授权中心（PKI），每个人将自己的公钥发给PKI，由PKI为该公钥签名，相当于提供一个证书，在将这个有签名的公钥返还给用户。

# 离散对数问题
对于乘法群$(G,\cdot)$，一个n阶元素a∈G和β∈\<a\>
问题：找到唯一非负整数i不大于n-1，满足a^i^=β
将整数i记为$\operatorname {ind}_{\alpha}(\beta)$，称为β的离散对数

# Diffie-Hellman算法
交换素数p和本原元g
Alice和Bob选择各自的私钥，Alice向Bob发送X=g^x^ mod p，Bob向Alice发送Y=g^y^ mod p。
之后Alice计算k=Y^x^ mod p，Bob计算k=X^y^ mod p，二者计算的值相等，实现密钥交换。

上述的密钥交换方案不安全。容易遭受中间人攻击。
如果Eve能够截获两者发送的X和Y，他用自己的密钥进行计算然后分别发送给Alice和Bob，这样A和B接收到的就是Eve的值。

# ElGamal密码体制
假设p为一个大素数，使得p构成乘法群上的离散对数问题难解。令α∈Z~p~是一个本原元，令P=Z~p~*，C=Z~p~*×Z~p~*，定义K={(p,α,a,β): β=α^a^ mod p}
其中p,α,β为公钥，a为私钥。
对k=(p,α,a,β)以及一个秘密的随机数r∈Z~p-1~，定义e~k~(x,r)=(y~1~, y~2~)
其中y~1~=α^r^ mod p, y~2~=xβ^r^ mod p
定义d~k~(y~1~, y~2~)=y~2~(y~1~^a^)^-1^ mod p
注意r在加密的时候需要随机选择，加密后应立即销毁不能在信道上传输。
加密运算具有不确定性。
<font color=red>注意三个公钥中只有β与私钥a直接相关。</font>

# 椭圆曲线
设a,b∈R是满足$4a^3+27b^2\ne 0$的实常数，方程$y^2=x^3+ax+b$所有解(x, y)∈R×R连同一个无穷远点$O$组成的集合E称为一个非奇异椭圆曲线。

从函数图像来看，椭圆曲线有两种，一种有一条线，一种有两条线
## Weierstrass方程
定义在代数闭域$\bar K$上射影平面坐标的一般方程
$Y^2Z+a_1XYZ+a_3YZ^2=X^3+a_2X^2Z+a_4XZ^2+a_6Z^3 (a_1,a_2,a_3,a_4,a_6\in\bar K)$
K上的射影平面P^2^(K)是K^3^/{(0, 0, 0)}上关系~的等价类集合，每个等价类记作(X:Y:Z)
(X~1~,Y~1~,Z~1~) ~ (X~2~,Y~2~,Z~2~)
$F(X,Y,Z)=Y^2Z+a_1XYZ+a_3YZ^2-X^3-a_2X^2Z-a_4XZ^2-a_6Z^3=0$
非奇异：$\frac{\partial F}{\partial X},\frac{\partial F}{\partial Y},\frac{\partial F}{\partial Z}$在P点至少有一个非0。

椭圆曲线E：非奇异Weierstrass方程的所有P^2^($\bar K$)的解
y^2^+a~1~xy+a~3~y=x^3^+a~2~x^2^+a~4~x+a~6~

(E,+)是一个以无穷远点0为单位元的阿贝尔群，加法规则为：
$P+0=0+P=P\\
-0=0\\
P=(x_1,y_1)\ne 0, -P=(x_1,-y_1-a_1x_1-a_3)\\
Q=-P,P+Q=0
P,Q\ne 0,Q\ne -P,P+Q=-R$
其中R为直线PQ或过点P的切线与椭圆曲线的第三个交点
![](2.jpeg)
（当P和Q重合时，直线是曲线的切线，把y作为因变量对x求导计算$\frac{dy}{dx}$）

## 椭圆曲线密码（ECC）
阶：有限域F~q~上的椭圆曲线E(F~q~)由点组成，其上点的数量即为#E(F~q~)。称为椭圆曲线的阶。

倍点运算：P+P

椭圆曲线离散对数问题：已知曲线E(F~q~)，阶为n的点G∈E(F~q~)，P∈\<G\>，椭圆曲线离散对数问题是指确定整数k∈[0,...,n-1]使得P=KG成立。

安全参数的选取：
(q, a, b, G, n, h)
对于特征为p的有限域F~q~
其中a、b为椭圆曲线的参数，G为基点，阶为n，有限域F~q~的特征为p

$F_p(p>3): y^2=x^3+ax+b,a,b\in F_p,(4a^3+27b^2)\mod p\ne 0$
$F_{2^m}(p=2): y^2+xy=x^3+ax+b,a,b\in F_{2^m}, b\ne 0$

存在弱椭圆曲线：超奇异曲线（$p|q+1-\#E(F_q)$）和异常曲线（$\#E(F_q)=p$）

**可以基于ECC构建DH密钥交换协议**：首先选择公开参数$(q,F_q,E,G,n)$，Alice发送$P_a=aG$，Bob发送$P_b=bG$，二者交换后计算分别得到$S=abG$即为私钥。（仍然易受到中间人攻击）

**也可以基于ECC构建ElGamal密码体制**：首先选择公开参数$(q,F_q,E,G,n), A:(d_A,P_A),P_A=d_AG$
B发送明文消息m给A需要加密：
随机选择$r\in Z_n$
计算$C_1=rG, Q=rP_A(Q_x\ne 0);C_2=mQ_x$
发送$(C_1,C_2)$给A
解密：$d_AC_1=d_ArG=rP_A=Q,m=C_2Q_x^{-1}$

# 数字签名
签名方案：一个签名方案由一个五元组构成（P,A,K,S,V），其中
P是所有可能的消息组成的有限集
A是所有可能的签名组成的有限集
K是所有可能的密钥组成的有限集（密钥空间）
对于每一个k∈K，有一个秘密的签名函数sig~k~∈S和一个相应的公开的验证函数ver~k~∈V，sig~k~：P→A，ver~k~：P×A→{true, false}，满足：
当y=sig~k~(x)时，ver~k~(x,y)=true，否则为false

## RSA签名方案
设n=pq，p，q为素数，P=A=Z~n~，定义K={(n,p,q,e,d): ed $\equiv$ 1 mod φ(n)}
对于k=(n,p,q,e,d)，定义sig~k~(x)=x^d^ mod n和ver~k~(x,y)=true ↔ x=y^e^ mod n
(x,y∈Z~n~)，(n,e)为公钥，(n,d)为私钥

**存在性伪造问题**：任何人都可以伪造他人的签名y，对应消息为x=e~k~(y)=y^e^，一般这个消息是无意义的，但要防止攻击者计算大量的e~k~(y)，找出有意义的值从而伪造签名。
可以通过给消息添加可以识别的冗余信息或者对消息摘要后签名

**选择密文攻击**：
假设A响应E的任何签名要求：$c=m^e mod n$
$x=r^e\mod n,y=xc\mod n$
$y^d\mod n=(xc)^d\mod n=rc^d\mod n$
$r^{-1}y^d\mod n=r^{-1}rc^d\mod n=m$

若E想得到A关于消息m的签名，$m=m_1m_2\mod n$，可以通过m~1~和m~2~的签名构造m的签名。
$m^d\mod n=(m_1m_2)^d\mod n=(m_1^d\mod n)(m_2^d\mod n)\mod n$

因此不要对陌生消息签名，签名之前先对消息求摘要、身份认证。

**签名和公钥加密结合的方案：**
- 第一种方案：先签名后加密——$y=sig_{Alice}(x),z=e_{Bob}(x,y)$
- 第二种方案：先加密后签名——$z=e_{Bob}(x),y=sig_{Alice}(z)$
- 第二种方案可能存在伪造签名混淆发送者的问题，因此采用第一种方案更好。

**ElGamal签名方案**：
设p为一个大素数，使得$(Z_p^*, \cdot)$上的离散对数问题难解。令$\alpha\in Z_p^*$是一个本原元，令$P=Z_p^*,A=Z_p^*\times Z_{p-1}$，定义$K=\{(p,\alpha,a,\beta):\beta=\alpha^a\mod p\}$
其中$p,\alpha,\beta$为公钥，$a$为私钥
对$k=(p,\alpha,a,\beta)$以及一个秘密的随机数$r\in Z_{p-1}^*$，定义$sig_k(x,r)=(\gamma,\delta)$
其中$\gamma=\alpha^r\mod p,\delta=(x-a\gamma)r^{-1}\mod p-1$
对于$x,\gamma\in Z_p^*,\delta\in Z_{p-1}$
定义$ver(x,(y,\delta))=true\Leftrightarrow \beta^\gamma\gamma^\delta\equiv\alpha^x\mod p$
容易证明$\beta^\gamma\gamma^\delta\equiv\alpha^{a\gamma+r(x-a\gamma)r^{-1}\mod p-1}\equiv\alpha^x\mod p$

## 数字签名标准
DSA算法，签名比验证快很多，不能加密和密钥分配，专用于数字签名，比RSA慢
设p是一个大素数，使得$(Z_p^*, \cdot)$上的离散对数问题难解。令$\alpha\in Z_p^*$是一个q阶元素（q为素数），$<\alpha>$上的离散对数问题也难解。（整数k与p-1互素，k∈[0, p-2]，q|p-1）

$$\gamma=\alpha^k\mod p,\delta=(x+a\gamma)k^{-1}\mod p-1(k\in Z_{p-1}^*)\\
\because k\delta\equiv x+a\gamma\mod p-1,\therefore\alpha^{k\delta}\equiv\alpha^{x+a\gamma}\mod p\\
\Rightarrow\alpha^x\beta^\gamma\equiv\gamma^\delta\mod p,\delta=(x+a\gamma)k^{-1}\mod q\\
\gamma'=\gamma\mod q=(\alpha^k\mod p)\mod q,\delta=(x+a\gamma')k^{-1}\mod q\\
\alpha^x\beta^{\gamma'}\equiv\gamma^\delta\mod p\\
\gamma=(\alpha^x\beta^{\gamma'})^{\delta^{-1}\mod q}\mod p\Rightarrow \gamma=
(\alpha^{x\delta^{-1}\mod q}\beta^{\gamma'\delta^{-1}\mod q}\mod p)\mod q=\gamma'$$
验证$\gamma=
(\alpha^{x\delta^{-1}\mod q}\beta^{\gamma'\delta^{-1}\mod q}\mod p)\mod q=\gamma'$是否成立。成立则数字签名有效。

$$sig_K(x,k)=(\gamma, \delta), \gamma=(\alpha^k\mod p)\mod q,\delta=(\operatorname {SHA-1}(x)+a\gamma)k^{-1}\mod q\\
e_1=\operatorname {SHA-1}(x)\delta^{-1}\mod q,e_2=\gamma\delta^{-1}\mod q\\
ver_K(x,(\gamma,\delta))=true\Leftrightarrow(\alpha^{e_1}\beta^{e_2}\mod p)\mod q=\gamma$$

### 椭圆曲线数字签名
p是一个大素数，E定义在F~p~上的椭圆曲线。设A是E上阶为q（素数）的一个点，使得在\<A\>上的离散对数问题是难处理的。设P={0,1}\*，A=Z~q~\*×Z~q~\*，定义K={(p,q,E,A,m,B): B=mA}
其中0≤m≤q-1，值p,q,E,A,B为公钥，m为私钥。
对于K和一个秘密的随机数k，1≤k≤q-1，定义
$$sig_K(x,k)=(r,s)$$
其中

## PGP安全协议
一种以用户为中心的可提供机密性和鉴别的安全协议。
![](3.jpeg)
若需要签名和加密，则先签名再加密，如需压缩则加密后压缩：$Z(Sig(H(M),kR_a)||M)$
