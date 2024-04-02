---
title: 信息安全数学基础 Chapter 3——有限域（二）
date: 2023-02-28 22:53:26
categories:
- 课内笔记
- 信息安全数学基础
---
<font color=purple>定理3.20</font> 设$\mathbb F_q$为q元有限域，$f(x)\in \mathbb F_q[x]$为n次不可约多项式，那么有$f(x)|x^{q^n}-x$

<font color=dblue>证明方法：</font>构造$f(x)$的扩域$\mathbb F_q[x]_{f(x)}$，对于任意$x\in F_q[x]_{f(x)}$均有$x^{q^n}-x=0$（定理3.19），则有$(x^{q^n}-x)_{f(x)}=0$（定理3.7）。证毕。

---

<font color=purple>定理3.21</font> 设$m,n$均为正整数，则有$(x^m-1,x^n-1)=x^{(m,n)}-1$

<font color=dblue>证明方法：</font>归纳法。
当$max\{m,n\}=1$时显然成立
假设当$max\{m,n\}=k$时成立，若$m>n$，那么有$(x^m-1,x^n-1)=(x^{m-n}-1,x^n-1)$（定理3.11），此时$max\{m,n\}<k$，故成立。

<font color=orange>推论</font> 设$m,n,q$为整数，则$(x^{q^m}-x,x^{q^n}-x)=x^{q^{(m,n)}}-x$（使用上面定理即可，证明略）

---

<font color=purple>定理3.22</font> 设$\mathbb F_q$为q元域，$n$为正整数，$f(x)\in\mathbb F_q[x]$为m次不可约多项式，且$m>n$，那么$f(x)∤x^{q^n}-x$

<font color=dblue>证明方法：</font>反证法。

假设能够整除。则有$x^{q^n}_{f(x)}=x_{f(x)}$
对于任意$\mathbb F_q[x]_{f(x)}$中元素$g(x)=\sum_{i=0}^{m-1}a_ix^i$，有
$$g(x)^{q^n}=\sum_{i=0}^{m-1}(a_ix^i)^{q^n}$$
（二项式定理）
根据定理3.19有
$$g(x)^{q^n}=\sum_{i=0}^{m-1}a_i(x^i)^{q^n}$$
注意$(a_i)^{q^n}=a_i$
因此
$$(g(x)^{q^n}-g(x))_{f(x)}=\sum_{i=0}^{m-1}a_i((x^i)^{q^n}-x^i)_{f(x)}=\sum_{i=0}^{m-1}a_i((x^{q^n})^i-x^i)_{f(x)}=\sum_{i=0}^{m-1}a_i(x^i-x^i)_{f(x)}=0$$

故任意$\mathbb F_q[x]_{f(x)}$中元素均是$x^{q^n}-x$的根，而$n<m$，故矛盾。

---

<font color=purple>定理3.23</font> 设$\mathbb F_q$为q元域，$n,d$为正整数，$f(x)\in\mathbb F_q[x]$为$d$次不可约多项式，那么有$f(x)|x^{q^n}-x$当且仅当$d|n$。

<font color=dblue>证明方法：</font>
充分性：$f(x)|x^{q^d}-x$，根据定理3.21，$x^{q^d}-x|x^{q^n}-x$，证毕
必要性：$f(x)|x^{q^d}-x,f(x)|x^{q^n}-x\Rightarrow f(x)|(x^{q^d}-x, x^{q^n}-x)=x^{q^{(d,n)}}-x$，又$\deg(f(x))=d\le (d,n)$，故$d|n$

---

<font color=blue>定义3.10</font> 导式

---

<font color=blue>定义3.11</font> 重因式、k重因式、重根、k重根、导式

---

<font color=purple>定理3.24</font> $\mathbb F_q$为q元有限域，$f(x),g(x)\in\mathbb F_q[x]$，若$g(x)$是$f(x)$的k重因式，则$g(x)^{k-1}|f'(x)$

<font color=dblue>证明方法：</font>求导

<font color=orange>推论1</font> $\mathbb F_q$为q元有限域，$f(x)\in\mathbb F_q[x]$，若$(f(x),f'(x))=1$，则$f(x)$在域$\mathbb F_q$上没有重因式，也没有重根。（证明反证法）
<font color=orange>推论2</font> $\mathbb F_q$为q元有限域，n为正整数，则$x^{q^n}-x$在域$\mathbb F_q$上没有重因式。（用推论1证明）

<font color=red>$x^{q^n}-x$可以表示为所有次数为n的因子的首1不可约多项式的乘积，每个因式仅出现一次 **（注意理解：n的因子！如当n=4时，所有1、2、4次不可约多项式都是其因子）** </font>

---

<font color=purple>定理3.25</font> 设$\mathbb F_q$为q元域，n为正整数，那么$\mathbb F_q$上一定存在n次不可约多项式。

<font color=dblue>证明方法：</font>容斥原理

$\phi(k)$为$\mathbb F_q$上次数为$k$的因子的首1不可约多项式的乘积，即$\phi(k)=x^{q^k}-x$，$A$为$n$次首1不可约多项式的乘积。
设$n=\prod_{i=1}^S p_i^{\alpha_i}$
$$A=\phi(n)\cdot\prod_{1\le i\le S}\phi(\frac{n}{p_i})^{-1}\prod_{1\le i_1<i_2\le S}\phi(\frac{n}{p_{i_1}p_{i_2}})...\phi(\frac{n}{p_1p_2...p_S})^{(-1)^S}$$

首先，次数不是n的因子的首1不可约多项式，在等式两边都不出现。
其次，任何一个次数为n的首1不可约多项式在等式两边各出现1次，分别在$A$和$\phi(n)$中
再者，对于任意$d|n,d<n$，设
$$d=p_1^{f_1}p_2^{f_2}...p_r^{f_r}p_{r+1}^{\alpha_{r+1}}...p_S^{\alpha_S}$$
那么在$\frac{n}{p_{i_1}p_{i_2}...p_{i_t}}(0\le t<s,1\le i_1<i_2<...<i_t\le S)$中，只有n,$\frac{n}{p_i}(1\le i\le r),\frac{n}{p_ip_j}(1\le i<j\le r),...,\frac{n}{p_1p_2...p_r}$以d为因子，所以任一d次首1不可约多项式在等式右边出现的次数为：$1-\begin{pmatrix} r \\ 1 \end{pmatrix}+\begin{pmatrix} r \\ 2 \end{pmatrix}-...+(-1)^r\begin{pmatrix} r \\ r \end{pmatrix}=(1-1)^r=0$。显然其在左边出现次数也为0，等式得证。

又$\phi(n)=x^{q^n}-x$，所以
$$\deg A=q^n-\sum_{1\le i\le S}q^{\frac{n}{p_i}}+\sum_{1\le i_1<i_2\le S}q^{\frac{n}{p_{i_1}p_{i_2}}}+...+(-1)^S q^\frac{n}{p_1p_2...p_S}$$
故$\deg A\equiv (-1)^Sq^\frac{n}{p_1p_2...p_S}\ne 0 (\mod q^{\frac{n}{p_1p_2...p_S}+1})$[$q^{\frac{n}{p_1p_2...p_S}+1}|q^n$，前面项全消去仅剩最后一项]，故$\deg A>0$，因此$A$至少包含1个不可约多项式

---

<font color=purple>定理3.26</font> 对于任意素数$p$，正整数$n$，$p^n$元有限域一定存在。

<font color=dblue>证明方法：</font>根据定理3.25能在$\mathbb Z_p$找到n次不可约多项式，因此可以根据定理3.16构造一个元素个数为$p^n$的有限域。

---

<font color=red>若$\mathbb F_{q^n}$是$\mathbb F_q$的扩域，则$\mathbb F_{q^n}$可以看做$\mathbb F_q$的n维向量空间，一组基能够按照定理3.18的方式构造：$\{1,\beta_1,\beta_2,...\beta_{n-1}\}$，$\mathbb F_{q^n}$中任意一个元素可以唯一表示为</font>
$$a_0+a_1\beta_1+...+a_{n-1}\beta_{n-1},a_i\in\mathbb F_q$$
的形式。

如$\{1,x,x^2,...,x^{n-1}\}$就是一组基。

---

<font color=green>引理1</font> 设群$G$的元素$\alpha$的阶为$n$，则对于任意整数m，$ord(\alpha^m)=\frac{n}{(m,n)}$

证明：设$ord(a^m)=d$，分别证明$d|\frac{n}{(m,n)},\frac{n}{(m,n)}|d$即可。
$d|\frac{n}{(m,n)}$易证
$(\alpha^m)^d=1$，故$n|md$，即$\frac{n}{(m,n)}|\frac{m}{(m,n)}d$，且有$(\frac{m}{(m,n)},\frac{n}{(m,n)})=1$，故$\frac{n}{(m,n)}|d$

---

<font color=green>引理2</font> 设群$G$中，$ord(\alpha)=m,ord(\beta)=n$，若$(m,n)=1$，则$ord(\alpha\beta)=mn$
证明：证明思路与引理1相同
$d|mn$易证
$(\alpha\beta)^d=1$，故$\alpha^d=\beta^{-d}$，故$ord(\alpha^d)=\frac{m}{(d,m)}=\frac{n}{(-d,m)}=ord(\beta^{-d})$。$(m,n)=1\Rightarrow(\frac{m}{(d,m)},\frac{n}{(d,n)})=1,\frac{m}{(d,m)}=\frac{n}{(d,n)},\therefore \frac{m}{(d,m)}=\frac{n}{(d,n)}=1$。故$m|d,n|d\Rightarrow mn|d$

---

<font color=purple>定理3.27</font> 有限域的乘法群是循环群。

<font color=dblue>证明方法：</font>设$\mathbb F_{p^n}$是元素个数为$p^n$的有限域，其乘法群元素个数为$p^n-1$，设$\alpha$是其中阶最大的元素，设其阶$ord(\alpha)=d$，则$d|p^n-1$，故有$d\le p^n-1$。
对任意$\beta\in\mathbb F_{p^n}$，设$ord(\beta)=s=\prod_{i=1}^t p_i^{\alpha_i},d=\prod_{i=1}^t p_i^{\beta_i},\alpha_i\ge 0,\beta_i\ge 0$，那么$[d,s]=\prod_{i=1}^tp_i^{\max\{\alpha_i, \beta_i\}}$，将前面的式子拆分为两份：$s'=\prod_{\alpha_i\ge \beta_i}p_i^{\alpha_i},d'=\prod_{\alpha_i<\beta_i}p_i^{\beta_i}$，则易得$d'|d,s'|s,(d,s)=1,d's'=[d,s]$，此时$ord(\alpha^{\frac{d}{d'}})=d',ord(\beta^{\frac{s}{s'}})=s'$，由引理2可得，$ord(\alpha^{\frac{d}{d'}}\beta^{\frac{s}{s'}})=d's'=[d,s]\le d$，因为d是最大的阶。故有$s|d$。于是$\mathbb F_{p^n}^*$中任意一个元素的阶都是d的因子，即$\mathbb F_{p^n}^*$中$p^n-1$个元素均为$x^d-1=0$的根，故有$p^n-1\le d$。综上有$d=p^n-1$，证毕。

<font color=red>将域乘法群的生成元称为其本原元。</font>

---

<font color=blue>定义3.12</font> 极小多项式：$\mathbb F_q$是元素个数为q的有限域，有限域$\mathbb F$为其扩域，则$\mathbb F$中任意一个元素$\alpha$在$\mathbb F_q$上的极小多项式指$\mathbb F_q$上以$\alpha$为根的首1不可约多项式。<font color=red>**（$\alpha$为$\mathbb F_q$扩域上，$\mathbb F$上元素，故其不一定是$\mathbb F_q$上元素，因此虽然$x-\alpha$整除该多项式，但该多项式不一定就是$x-\alpha$。但如果$\alpha\in\mathbb F_q$，则该多项式就是$x-\alpha$）**</font>

---

<font color=purple>群的定理</font> 设$<a>$为由a构成的循环群，则：
1. $<a>$的子群都是循环群
2. 对于任意正整数$d|n$，$<a>$存在唯一d元子群
3. 若整数$s,t$不全为0，则$<a^s,a^t>=\{a^{sx+ty}\}=<a^{(s,t)}>$

---

<font color=green>引理3</font> 设$\mathbb F_q$是元素个数为q的有限域，有限域$\mathbb F$为其扩域，$\mathbb F$任一元素$\alpha$在$\mathbb F_q$上的极小多项式存在且唯一。
证明：存在性。设$|\mathbb F|=q^n$，则其中任意一个元素一定为$x^{q^n}-x$的根，其可以在$\mathbb F$中分解为若干首1不可约多项式的乘积：$x^{q^n}-x=p_1(x)p_2(x)...p_s(x),p_i(x)\in\mathbb F_q[x]$，故存在$1\le i\le s,p_i(\alpha)=0$，$p_i(x)$即为$\mathbb F_q$上的极小多项式。
唯一性。由定理3.24定理的推论，不存在重根，设存在两个极小多项式$a(x),b(x)$，因为$(a(x),b(x))=1$，代入$\alpha$可得：$0=s(\alpha)a(\alpha)+t(\alpha)b(\alpha)=1$，矛盾。

由上可知，$\alpha$在$\mathbb F_q$上的极小多项式是以$\alpha$为根的次数最低的多项式，且唯一。（反证法：假设可约则存在有次数更低的多项式，代入$\alpha$得其中一个多项式必为0，矛盾）

---

<font color="0080FF">结论1</font> 设$f(x)$是一个n次不可约多项式，那么包含$f(x)$的根$\alpha$的最小扩域为$\mathbb F_{q^n}$，所有包含$f(x)$的根的域都是$\mathbb F_{q^n}$的扩域。

<font color=dblue>证明：</font>设包含$f(x)$的根$\alpha$的最小扩域为$\mathbb F_{q^k}$，设
$$x^{q^k}-x=g(x)f(x)+r(x),\deg r(x)<\deg f(x)$$
代入$\alpha$可得$r(x)=0$，即$\alpha$是r(x)的一个根，但f(x)是$\mathbb F_q$上以$\alpha$为根的次数最小的多项式，因此r(x)只能为0。
故$f(x)|x^{q^k}-x,n|k$，最小正整数k即为n（定理3.20，3.22）

---

<font color="0080FF">结论2</font> $\mathbb F_q$为q元有限域，那么其扩域$\mathbb F_{q^n}$中包含所有次数为n的因子的不可约多项式的所有根，而不包含次数不为n的因子的不可约多项式的任何根。

<font color=dblue>证明：</font>由结论1易证。

---

<font color=green>引理4</font> 设$\mathbb F_q$是元素个数为q的有限域，有限域$\mathbb F$为其扩域，$\alpha\in\mathbb F^*$，$\alpha$的阶为m，设k是使$q^k\equiv1(\mod m)$的最小正整数，则$\alpha$在$\mathbb F_q$上的极小多项式为k次，该多项式的k个根为$\alpha,\alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}}$。若$|\mathbb F|=q^n$，$\alpha$为$\mathbb F$的本原元，则$\alpha$在$\mathbb F_q$上的极小多项式一定为n次。

证明：构造k次多项式
$$g(x)=(x-\alpha)(x-\alpha^q)...(x-\alpha^{q^{k-1}})$$
对于$0\le i\le k$，g(x)的1次项系数可以看做$\mathbb F_q$的素域$\mathbb F_p$上的k元多项式，不妨设为$c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}})$，即$g(x)=\sum_{i=0}^kc_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}})x^i$
由$q^k\equiv 1(\mod m)$，$\alpha$的阶为m，得到$\alpha^{q^k}=\alpha$，又q为p的幂，因此由定理3.5：
$$(c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}}))^q=c_i(\alpha^q,\alpha^{q^2},...,\alpha^{q^{k}})=c_i(\alpha^q,\alpha^{q^2},...,\alpha)$$
又$g(x)=(x-\alpha^q)...(x-\alpha^{q^{k-1}})(x-\alpha)$，所以g(x)的i次项系数又可以表示为$c_i(\alpha^q,\alpha^{q^2},...,\alpha)$，也即$c_i(\alpha^q,\alpha^{q^2},...,\alpha)=c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}})$。因此有
$$(c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}}))^q=c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}})$$
由定理3.19可知$c_i(\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}})\in\mathbb F_q$，即$g(x)\in\mathbb F_q[x]$

下面证明$g(x)$在$\mathbb F_q[x]$中不可约。
易得$\alpha, \alpha^q,\alpha^{q^2},...,\alpha^{q^{k-1}}$互不相等。若存在两项$\alpha^{q^i},\alpha^{q^j}$相等，则$\alpha^{q^i(q^{j-i}-1)}=1$，故$m|q^i(q^{j-i}-1)$。由$q^k\equiv 1(\mod m)$可知$(q,m)=1$**（q^k^和1属于模m的同一个剩余类，故(q^k^,m)=(1,m)=1，即有(q,m)=1）**，故$m|q^{j-i}-1$，即$q^{j-i}\equiv 1(\mod m)$，但$0<j-i<k$，与k最小矛盾。

若$g(x)$在$\mathbb F_q[x]$上可约，则存在因式$f_1(x),f_2(x)\in\mathbb F_q[x]$
由$g(\alpha)=0$可得$f_1(\alpha)=0$或$f_2(\alpha)=0$，不妨设$f_1(\alpha)=0$，则有$f_1(\alpha)=f_1(\alpha^q)=...=f_1(\alpha^{q^{k-1}})=0$**（$f_1(\alpha)=\sum_{i=0}^Sa_i\alpha^i,a_i^q=a_i$，故$f_1(\alpha)=\sum_{i=0}^Sa_i\alpha^{qi}=\sum_{i=0}^Sa_i^q\alpha^{qi}=(f_1(\alpha))^q=0$）**，其根的个数超过其次数，矛盾。

由极小多项式的定义和唯一性可知g(x)即为$\alpha$在$\mathbb F_q$上的极小多项式。
<font color=red>**所有根的阶数均为m。**</font>

---

<font color=green>引理5</font> 设$\mathbb F_q$是元素个数为q的有限域，$f(x)$为$\mathbb F_q$上的$n(n\ge 1)$的首1不可约多项式，$\mathbb F_{q^n}$为$\mathbb F_q$的任一扩域，那么$f(x)$在$\mathbb F_{q^n}$中有根，且若$\alpha$是$f(x)$在$\mathbb F_{q^n}$中的一个根，那么$f(x)$在$\mathbb F_{q^n}$中的所有根为$\alpha,\alpha^q,\alpha^{q^2},...,\alpha^{q^{n-1}}$。

证明：当$f(x)=cx,c\in\mathbb F_q^*$时，结论成立。
不妨设$f(x)$是首一n次不可约多项式，且$f(x)\ne cx,c\in \mathbb F_q^*$。由定理3.20可知$f(x)|x^{q^n}-x$，而$\mathbb F_{q^n}$中所有$q^n$个元素均为$x^{q^n}-x$的根。令$x^{q^n}-x=f(x)g(x),\deg g(x)=q^n-n$，则$x^{q^n}-x$的根一定是f(x)或g(x)的根，且f(x)的根至少有n个。又$\deg f(x)=n$，则f(x)有n个根。

$\alpha$是$f(x)$在$\mathbb F_{q^n}$中的一个根，则$f(x)$为$\alpha$在$\mathbb F_q$上的极小多项式，其所有根为$\alpha,\alpha^q,\alpha^{q^2},...,\alpha^{q^{n-1}}$。

---

<font color=blue>定义3.13</font> 极小多项式所有根的阶称为多项式的周期，周期为最大（$q^n-1$）时称该多项式为$\mathbb F_q$上的本原多项式

---

<font color=purple>定理3.28</font> 所有元素相同的有限域均同构。

<font color=dblue>证明方法：</font>

---

<font color=purple>定理3.29</font> （有限域伽罗华定理）设p为素数，$\mathbb F_{p^n}$为元素个数为p^n^的有限域，$\alpha$为$\mathbb F_{p^n}$的本原元，$\alpha$在$\mathbb F_p$上的极小多项式为n次本原多项式$f(x)$，则：
(1) $\mathbb F_{p^n}$的任意自同构都保持其素域$\mathbb F_p$中的元素不变。
(2) $\mathbb F_{p^n}$的任意自同构都只能将$f(x)$的根映射成$f(x)$的根。
