<font color=blue>定义4.1</font> 设m为正整数，若同余式$x^2\equiv a(\mod m),(a,m)=1$，有解，则a称为模m的二次剩余，否则称为模m的二次非剩余

<font color=blue>定义4.2</font> 勒让德符号：$(\frac{a}{p})$，当a为模p的二次剩余时，值为1；非2次剩余时值为-1，若$p|a$则值为0

<font color=red>定理4.1</font> p为素数，若$a\equiv b(\mod p)$，则$(\frac{a}{p})=(\frac{b}{p})$
求同余式$x^2\equiv a(\mod p)$的解可以看成是在有限域$\mathbb Z_p$中求多项式$x^2-a$的根。

<font color=red>定理4.2</font> 欧拉判别法则：p为奇素数，则对于任意整数a，$(\frac{a}{p})\equiv a^{\frac{p-1}{2}}(\mod p)$
证明：
设$g$是$\mathbb Z_p$的本原元，则$\mathbb Z_p^*=\{g^0,g^1,...,g^{p-2}\}$
对于所有$0\le i\le \frac{p-1}{2}$，$(g^{2i})^{\frac{p-1}{2}}=(g^{p-1})^i=1,(g^{2i+1})^{\frac{p-1}{2}}=(g^{p-1})^ig^{\frac{p-1}{2}},g^{\frac{p-1}{2}}=-1$（由g为本原元可知$g^{\frac{p-1}{2}}\ne 1$，但$(g^{\frac{p-1}{2}})^2= 1$，故其只能为-1），故$(g^{\frac{p-1}{2}})^{2i+1}=-1$
由于考虑模p的二次同余式，因此a可以看做是$\mathbb Z_p$中与之同余等价的元素
当$a\equiv g^{2i}(\mod p),0\le i<\frac{p-1}{2}$，多项式$x^2-a=x^2-g^{2i}$有根±g^i^，故$(\frac{a}{p})=1\equiv a^{\frac{p-1}{2}}(\mod p)$
当$a\equiv g^{2i+1}(\mod p),0\le i<\frac{p-1}{2}$，多项式$x^2-a=x^2-g^{2i+1}$一定没有根。否则若$x_0^2=g^{2i+1}$，那么$1=(x_0^2)^{\frac{p-1}{2}}=(g^{2i+1})^{\frac{p-1}{2}}=-1$矛盾。故$(\frac{a}{p})=-1\equiv a^{\frac{p-1}{2}}(\mod p)$

**由上述定理可知，模p的二次剩余有$\frac{p-1}{2}$个（本原元的所有偶数次幂）**

<font color=green>推论</font> 设p为奇素数，则
$(\frac{1}{p})=1$
$(\frac{-1}{p})=(-1)^\frac{p-1}{2}$
$(\frac{ab}{p})=(\frac{a}{p})(\frac{b}{p})$
$(\frac{a^n}{p})=(\frac{a}{p})^n,n>0$

<font color=red>定理4.3</font> 设p为奇素数，则$(\frac{2}{p})=(-1)^{\frac{p^2-1}{8}}$
证明：**构造证明**
$(p-1)!\equiv 1\cdot 3\cdot 5\cdot ... \cdot (p-2)\cdot 2\cdot 4\cdot ... \cdot (p-1)$
对于4k+1型的p有
$\equiv 1\cdot (p-2)\cdot 3\cdot (p-4)\cdot 5\cdot ...\cdot \frac{p-3}{2}\cdot (p-\frac{p-1}{2})\cdot 2^{\frac{p-1}{2}}\cdot (\frac{p-1}{2}!)(\mod p)$（后面一半所有偶数提个2出来，前半部分可以交替提一个-1）
$\equiv (-1)^{\frac{p-1}{4}}\cdot 2^{\frac{p-1}{2}}\cdot(\frac{p-1}{2}!)^2(\mod p)$
对于4k+3型的p有
$\equiv 1\cdot (p-2)\cdot 3\cdot (p-4)\cdot 5\cdot ...\cdot(p-\frac{p-3}{2})\cdot\frac{p-1}{2}\cdot 2^{\frac{p-1}{2}}\cdot (\frac{p-1}{2}!)(\mod p)$
$\equiv (-1)^{\frac{p-3}{4}}\cdot 2^{\frac{p-1}{2}}\cdot(\frac{p-1}{2}!)^2(\mod p)$
Wilson定理知$(p-1)!\equiv -1(\mod p)$，及$(\frac{p-1}{2}!)^2\equiv(-1)^{\frac{p+1}{2}}(\mod p)$ **（转化为$(-1)^{\frac{p-1}{2}}(p-1)!$）** 可知当$p\equiv ±1(\mod 8)$时，$2^{\frac{p-1}{2}}\equiv 1(\mod p)$，当$p\equiv ±3(\mod 8)$时，$2^{\frac{p-1}{2}}\equiv -1(\mod p)$，综合验证得$2^{\frac{p-1}{2}}\equiv(-1)^{\frac{p^2-1}{8}}(\mod p)$，由欧拉判别法则$(\frac{2}{p})=(-1)^{\frac{p^2-1}{8}}$

<font color=red>定理4.4</font> 二次互反律：p，q是互素奇素数，则$(\frac{q}{p})=(-1)^{\frac{p-1}{2}\frac{q-1}{2}}(\frac{p}{q})$
证明：太复杂了，不要求掌握

<font color=blue>定义4.3</font> 雅可比符号：$m=\prod_{i=1}^np_i,p_i$是奇素数，对于任意整数a定义a模m的雅可比符号为$(\frac{a}{m})=\prod_{i=1}^n(\frac{a}{p_i})$，m为奇素数时，其雅克比符号就是勒让德符号。

<font color=red>定理4.5</font> 设m为正奇数，$a\equiv b(\mod m)\Rightarrow (\frac{a}{m})=(\frac{b}{m})$

<font color=red>定理4.6</font> 设m为正奇数，则
(1) $(\frac{1}{m})=1$
(2) $(\frac{ab}{ m})=(\frac{a}{m})(\frac{b}{m})$
(3) $(\frac{a^n}{m})=(\frac{a}{m})^n$
(4) $(\frac{-1}{m})=(-1)^{\frac{m-1}{2}}$
(5) $(\frac{2}{m})=(-1)^{\frac{m^2-1}{8}}$

<font color=red>定理4.7</font> 设m,n为正奇数，则$(\frac{n}{m})=(-1)^{\frac{m-1}{2}\frac{n-1}{2}}(\frac{m}{n})$

<font color=blue>定义4.4</font> 二次剩余问题：未知n的分解式的情况下，一般性地判断一个整数a是否是模n的二次剩余是一个难解的问题，称为二次剩余问题。

<font color=orange>加密算法1——Rabin加密算法</font>
Alice选择两个4k+3型的素数（称为Blum素数）p,q，计算n=pq，将p，q作为私钥公开n。
加密：明文为整数m，密文c=m^2^(mod n)
解密：解同余方程c=x^2^(mod n)可以得到4个解，选择其中有意义的解作为明文m。

<font color=pink>计算方法——a=x^2^(mod p)，p=4k+3的解法</font>
若上式有解，则在[0,p-1]中一定有解，因此数字不大时可以对a一直加p直到找到一个完全平方数即可（这种方法对p无4k+3的限制，但是p很大时不方便）
由$(\frac{a}{p})=1$由欧拉判别法则$a^{\frac{p-1}{2}}\equiv 1(\mod p)$，故有$(a^{\frac{p-1}{4}})^2\equiv a(\mod p)$，故解为$x\equiv ±a^{\frac{p-1}{4}}(\mod p)$

<font color=orange>加密算法2——Goldwasser-Micali加密算法</font>
Alice选择两个不同的素数p，q，和整数y满足$(\frac{y}{p})=(\frac{y}{q})=-1$。计算n=pq，p和q座位私钥公开n，y
加密：将二进制整数m作为明文，第i位记为b~i~，对于每一位，随机选择0<x~i~<n，若该位为0计算c~i~=x~i~^2^(mod n)，否则计算c~i~=yx~i~^2^(mod n)，密文为所有的c
解密：若c~i~为模n的二次剩余，则判断b~i~=0，否则b~i~=1

<font color=blue>定义4.5</font> 设\<g\>是一个由元素g生成的一个n元循环群，则对于任意a∈\<g\>，存在0≤i<n，a=g^i^，称i为以g为底a的指标，记作ind~g~a。求指标的问题，在密码学中通常称为离散对数问题。n充分大的整数时求解离散对数问题为一个难解问题。

<font color=red>定理4.8</font> 设\<g\>是一个n元循环群，a∈\<g\>，如果对于正整数m有：
(1) a^m^=e
(2) 对于任意素因子p|m，$a^{\frac{m}{p}}\ne e$，则ord(a)=m，且m|n

<font color=blue>定义4.8</font> 原根：设m为正整数，整数a满足(a,m)=1，a模m的阶ord~m~(a)是指a(mod m)在$\mathbb Z_m^*$中的阶；如果$\mathbb Z_m^*$为循环群，整数a称为模m的原根是指a(mod m)为$\mathbb Z_m^*$的生成元

根据上述定义，a所在模m剩余类中所有整数的模m阶均为ord~m~(a)

根据原根定义：当m=2,4时，模m原根分别为1,3
一般地，当且仅当m=2,4,p^a^,2p^a^（p为奇素数，a≥1），模m有原根

<font color=red>定理4.9</font> 设\<g\>是一个n元循环群，a，b∈\<g\>，则ind~g~ab$\equiv$ind~g~a+ind~g~b(mod n)
证明：ind~g~a=x，ind~g~b=y，则g^x+y^=ab=$g^{ind_gab}$
即$g^{x+y-ind_gab}=e$，又ord(g)=n，故n|x+y-ind~g~ab，故结论成立

<font color=blue>定义4.9</font> 设m是大于1的正整数，如果n次同余式x^n^=a(mod m), (a,m)=1有解，则a称作模m的n次剩余，否则为模m的n次非剩余。

<font color=red>定理4.14</font> （高次剩余）设m为大于1的正整数，g为模m的一个原根，(a,m)=1，d=(n,$\varphi$(m))，那么x^n^=a(mod m)有解的充要条件为$a^{\frac{\varphi(m)}{d}}\equiv 1(\mod m)$
证明：g为模m的一个原根，所以$\mathbb Z_m^*=<g>,x^n\equiv a(\mod m)$有解的充要条件是$ind_gx^n=ind_ga\Rightarrow nind_gx\equiv ind_ga(\mod \varphi(m))$**（注意模m的循环群一共只有$\varphi(m)$个元素，因此要模$\varphi(m)$！）**，令X=ind~g~x，则有$nX\equiv ind_ga(\mod \varphi(m))$
该一次同余式有解的充要条件为(n,φ(m))|ind~g~a，即d|ind~g~a，等价于ind~g~a$\equiv$ 0(mod d)
由定理2.4(4)有$\frac{\varphi(m)}{d}ind_ga\equiv 0(\mod \varphi(m))$。两边取“指数”得$a^{\frac{\varphi(m)}{d}}\equiv 1(\mod m)$，故原命题成立。

**注**：该定理还能帮助求解高次同余式的解数。对于同余式$ax\equiv b(\mod m)$，其有解的充要条件为$(a,m)|b$，且通解可以写成$x=x_0+\frac{m}{(a,m)}t,t=0,1,...,(a,m)-1$的形式，因此解的数量为$(a,m)$。那么$nX\equiv ind_ga(\mod \varphi(m))$的解数应该有$(n,\varphi(m))$个
