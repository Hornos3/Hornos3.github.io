# Chapter 3 有限域

<font color=blue>定义3.1</font> 设$\mathbb F$为一个非空集合，在其上定义两种运算：加法和乘法，这两种运算在集合上封闭，且满足下列条件：

1. $\mathbb F$中所有元素对于加法形成加法交换群
2. $\mathbb F$中所有非零元素（记为$\mathbb F^*$）对于乘法构成乘法交换群
3. 任意$\mathbb F$中元素满足乘法对加法的交换律（与实数集中的交换律形式上相同）

则称$\mathbb F$对于规定的乘法和加法构成一个域。
<font color=red>一个域至少有两个元素：加法群零元（称为域的零元，$0$）和乘法单位元（称为域的单位元，$e$）</font>。域元素个数有限称为有限域或伽罗华域，否则称为无限域。有理数集合$\mathbb Q$和复数集合$\mathbb C$按定义的加法和乘法均为域

---

<font color=blue>定义3.2</font> 设$\mathbb F$是一个域，$\mathbb F_0$是$\mathbb F$的非空子集，如果对于$\mathbb F$上的加法和乘法，$\mathbb F_0$本身也是一个域，则称$\mathbb F_0$是$\mathbb F$的子域，$\mathbb F$是$\mathbb F_0$的扩域，记作$\mathbb F_0\subsetneq\mathbb F$

---

<font color=purple>定理3.1</font> 设$\mathbb F_0$，$\mathbb F_0^*$均是域$\mathbb F$的非空子集，当且仅当下面两个条件成立时$\mathbb F_0$是$\mathbb F$的子域：
1. 对于任意$a, b\in \mathbb F_0$，都有$-a, a+b\in\mathbb F_0$
2. 对于任意非零元素$a, b\in\mathbb F_0$，都有$a^{-1}, ab\in\mathbb F_0$

<font color=dblue>证明方法：</font>需要证明$\mathbb F_0$是$\mathbb F$的加法子群，$\mathbb F_0^*$是$\mathbb F$的乘法子群。这个证明与证明子群很相似。
$\because a,-a\in\mathbb F_0, \therefore0\in\mathbb F_0$，有加法单位元，每个元素有逆元。
$\because \forall a, b\in \mathbb F_0, a+b\in \mathbb F_0$，故运算封闭。
该运算由于在$\mathbb F$中构成域，因此满足交换律与结合律。因此$\mathbb F_0$是$\mathbb F$的加法子群。
$\because \forall a\in\mathbb F_0, a^{-1}\in\mathbb F_0$，故每个元素有逆元，有乘法单位元$e$
$\because \forall a, b\in \mathbb F_0, ab\in \mathbb F_0$，故运算封闭。
该运算由于在$\mathbb F$中构成域，因此满足交换律与结合律。因此$\mathbb F_0^*$是$\mathbb F$的乘法子群。
由于这两个运算在$\mathbb F$中满足分配律，因此在$\mathbb F_0$中同样满足。$\Box$

<font color=red>定义$a^{-n}=(a^n)^{-1}$，当$a\ne 0$时，定义$a^0=e$。</font>

---

<font color=purple>定理3.2</font> 设$\mathbb F$是一个域，那么：
1. 对于任意$a\in\mathbb F$，$0a=a0=0$；
2. 对于任意$a,b\in\mathbb F$，若$ab=0$，则$a=0$或$b=0$

<font color=dblue>证明方法：</font>$0a=(0+0)a$ 证明1
若$a\ne 0$，则$ab=a^{-1}ab=b=0$，若$b=0$同理。

<font color=red>在域中，二项式定理成立。</font>

---

<font color=purple>定理3.3</font> 设$\mathbb F$是一个域，$a,b\in\mathbb F$，对于任意正整数$n$，有
$$(a+b)^n=\sum_{i=0}^n C_n^i a^{n-i} b^i
=\sum_{i=0}^n\begin{pmatrix}n\\i\end{pmatrix}a^{n-i} b^i$$

<font color=dblue>证明方法：</font>分配律易证。

---

<font color=blue>定义3.3</font> 设$\mathbb F$是一个域，如果存在正整数$m$，使得对于任意$a\in\mathbb F$均有$ma=0$，则在所有满足上述条件的m中，最小的正整数称为域$\mathbb F$的特征。如果$m$不存在则称$\mathbb F$的特征为0。特征记作$char(\mathbb F)$。

---

<font color=blue>定义3.4</font> 设$\mathbb F, \mathbb k$是两个域，如果存在$\mathbb F$到$\mathbb k$的一一映射$\delta$，使得对于任意$a,b\in\mathbb F$，均有
$$\delta(a+_{\mathbb F}b)=\delta(a)+_{\mathbb k}\delta(b), \delta(a\times_{\mathbb F} b)=\delta(a)\times_{\mathbb k}\delta(b)$$
则称$\delta$为$\mathbb F$到$\mathbb k$的同构映射，称$\mathbb F, \mathbb k$同构，记作$\mathbb F\cong\mathbb k$。如果$\mathbb F=\mathbb k$则称$\delta$为自同构映射，若对于任意$a\in\mathbb F$均有$\delta(a)=a$，则称$\delta$为恒等自同构映射。<font color=red>一个域的最小子域称为该域的素域。</font>

---

<font color=purple>定理3.4</font> 设$\mathbb F$是一个域，则$char(\mathbb F)$为0或某个素数$p$。特征为素数$p$的域的素域与$\mathbb Z_p$同构，特征为0的域的素域与$\mathbb Q$同构。

<font color=dblue>证明方法：</font>此证明显然需要分为三个部分进行。
首先证明特征为0或素数。如果特征不是素数，则可写为$s\times t$的形式，也即$\forall a\in \mathbb F, (st)a=sta=0$，故$sa=0$或$ta=0$。此时特征就应该是$s$或$t$而非$st$。
当$\mathbb F$是一个域且特征不为0时，其所有子域显然均需要包含$0$和$e$，由于需要满足运算的封闭性，所以还需要包含$2e, 3e, ...,(p-1)e$。由这些元素构成的集合容易证明其是一个域（需要注意乘法逆元的证明，由于$p$是素数，故对于任意的$0<k<p$，均能找到其关于模$p$的逆元，也就是对应的乘法逆元），因此这就是$\mathbb F$上最小的域。同构映射$\delta(ke)=k$与$\mathbb Z_p$构成同构。
当$\mathbb F$的特征为0时，同样其所有子域均需要包含$0,e,2e,3e,...$。由加法运算的封闭性，还需要包含$-e,-2e,-3e,...$。又由于需要满足乘法逆元也包含于域中，所以$e^{-1}, 2e^{-1},...-e^{-1},-2e^{-1},...$也在子域中。又需要满足乘法的封闭性，故任意子域均需包含$\mathbb F_0=\{(ae)(be)^{-1}|a,b\in\mathbb Z,b\ne 0\}$。这个集合容易证明域的所有判定性质，因此其本身就是一个域，而且是最小的子域。同构映射$\delta((ae)(be)^{-1})=\frac{a}{b}$与$\mathbb Q$构成同构。

---

<font color=purple>定理3.5</font> 设$\mathbb F$是一个域，$char(\mathbb F)=p$，则对于任意$a,b\in\mathbb F,n\ge 0$，均有
$$(a\pm b)^{p^n}=a^{p^n}\pm b^{p^n}$$

<font color=dblue>证明方法：</font>首先使用二项式定理证明$(a+b)^p=a^p+b^p$：
$(a+b)^p$中的第i项为$\frac{p!}{i!(p-i)!}a^ib^{p-i}$，即证明$\frac{p!}{i!(p-i)!}$是$p$的倍数$(i\ne 0,i\ne p)$。显然这是一个整数，且$\frac{p!}{i!(p-i)!}=p\times \frac{(p-1)!}{i!(p-i)!}$。后面的数不可能是分数，因为如果是，那么分母必然是$p$的倍数，但是分母显然与$p$互素。因此后面的数是整数，也就是说这个数能够被$p$整除。故得证第一项。
然后使用数学归纳法，用类似的方式证明后面的式子即可。

---

<font color=blue>定义3.5</font> 对于非负整数$i$，$a_ix^i,a_i\in\mathbb F$表示域$\mathbb F$上文字为x的单项式，称形式和$f(x)=a_nx^n+a_{n-1}x^{n-1}+...+a_1x^1+a_0x^0,a_i\in\mathbb F$为域上文字为x的多项式，简称域$\mathbb F$上的多项式。$a_ix^i$称为$f(x)$的$i$次项，$a_i$称为$f(x)$的$i$次项系数。当$a_n\ne 0$时，称该多项式为n次多项式，$a_n$称为$f(x)$的首项系数，多项式$f(x)$的次数称为$\deg f(x)$。如果多项式各项系数均为0，称为零多项式，记为0，次数规定为$-\infty$。
<font color=red>域$\mathbb F$上文字为x的所有多项式的集合用符号$\mathbb F[x]$表示，规定$x^0=1\in\mathbb F,a_0x^0=a_0\in\mathbb F$，则有$\mathbb F\subsetneq\mathbb F[x]$。注意按照上面的定义，$\mathbb F[x]$不是域。</font>
<font color=red>关于多项式次数，下面结论成立：</font>
$$\deg (f(x)+g(x))\le max\{\deg f(x), \deg g(x)\}
\\\deg(f(x)g(x))=\deg f(x)+\deg g(x)$$

<font color=red>注意：这里的x可以表示任意的东西而不仅限于$\mathbb F$，即anything，但是需要定义次方。</font>

---

<font color=purple>定理3.6</font> 设$f(x),g(x)$为域$\mathbb F$上的两个多项式，$g(x)\ne 0$，则存在唯一一对多项式$q(x),r(x)$使得
$$f(x)=q(x)g(x)+r(x),\deg r(x)<\deg g(x)$$
<font color=red>注意：不要看系数能否被整除，而应该注意到域的性质。由于域的特征只可能为素数或0，因此不要想当然地用诸如$5x^2+1$和$2x^2+4$来挑战这条定理，因为整数集并不是域！</font>

<font color=dblue>证明方法：</font>归纳。
存在性易证，总存在一个系数能够消去被除式的最高次项（利用乘法逆元）
唯一性：$(q(x)-q'(x))g(x)=r'(x)-r(x),\deg (r'(x)-r(x))<\deg g(x)$，故$q(x)=q'(x), r(x)=r'(x)$

定理中的式子称为多项式带余除法算式，$r(x)$称为余式，记作<font color=red>$(f(x))_{g(x)}=r(x)$</font>

---

<font color=purple>定理3.7</font> 多项式满足模加和模乘运算。证明略。

---

<font color=blue>定义3.6</font> 
整除：$r(x)=0$
倍式与因式
真因式：次数小于倍式的因式

---

<font color=blue>定义3.7</font> 
可约多项式：不含次数大于0的真因式的多项式
不可约多项式

---

<font color=purple>定理3.8</font> 域$\mathbb F$上多项式$f(x)$可约，则当且仅当存在两个域$\mathbb F$上多项式$f_1(x),f_2(x)$，$\deg f_1(x)<\deg f(x), \deg f_2(x)<\deg f(x)$，使得$f(x)=f_1(x)f_2(x)$

证明略。

---

<font color=purple>定理3.9</font> 如果有$g(x)|f_1(x), g(x)|f_2(x)$，则任意多项式$s(x),t(x)$，有$g(x)|s(x)f_1(x)+t(x)f_2(x)$

<font color=dblue>证明方法：</font>
设$f_1(x)=g(x)q_1(x),f_2(x)=g(x)q_2(x)$
则$s(x)f_1(x)+t(x)f_2(x)=(s(x)q_1(x)+t(x)q_2(x))g(x)$一定是$g(x)$的倍式

---

<font color=blue>定义3.8</font> 公因式、最高公因式（首项系数为1，次数最高）、互素

---

<font color=purple>定理3.10</font> 欧几里得辗转相除法
$r_i(x)=q_{i+1}(x)r_{i+1}(x)+r_{i+2}(x)$

1. 经过有限步之后，余式必然为0。
2. 存在多项式$s(x),t(x)\in \mathbb F[x]$，使得$s(x)r_0(x)+t(x)r_1(x)=r_n(x)$。
3. 设$r_n(x)$首项系数为$c$，则$(r_0(x), r_1(x))=c^{-1}r_n(x)$，且最高公因式唯一存在。
4. 对于任意$c(x)\in \mathbb F(x)$，如果$c(x)|r_0(x),c(x)|r_1(x)$，那么$c(x)|(r_0(x),r_1(x))$

<font color=orange>推论</font> 多项式的裴蜀定理（描述、证明略）

---

<font color=purple>定理3.11</font> 设$f(x),g(x)$为域$\mathbb F$上两个不全为0的多项式，则对于任意$k(x)\in \mathbb F[x],(f(x)+g(x)k(x),g(x))=(f(x),g(x))$
类比整数，证明略。

---

<font color=purple>定理3.12</font> 设$f_1(x),f_2(x)$为域$\mathbb F$上的多项式，$p(x)$为域$\mathbb F$上的不可约多项式，且$p(x)|f_1(x)f_2(x)$，若$(p(x),f_1(x))=1$，则$p(x)|f_2(x)$
类比整数，证明使用定理3.10推论证明，略。

---

<font color=purple>定理3.13</font> 设$f_1(x),f_2(x)$为域$\mathbb F$上的多项式，$p(x)$为域$\mathbb F$上的不可约多项式，且$p(x)|f_1(x)f_2(x)$，则$p(x)|f_1(x)$或$p(x)|f_2(x)$
类比整数，证明略。

---

<font color=purple>定理3.14</font> 唯一因式分解定理：设$f(x)$是域$\mathbb F$上次数大于0的多项式，则$f(x)$可以唯一地表示为域$\mathbb F$上一些次数大于0的不可约多项式的乘积。特别地，若$f(x)$为首1多项式，且
$$f(x)=p_1(x)p_2(x)...p_s(x)=q_1(x)q_2(x)...q_t(x)$$
其中$p_i(x),q_i(x)$为域$\mathbb F$上次数大于0的首1不可约多项式，则有$s=t$，经过适当调整可以使得对任意$i$均有$p_i(x)=q_i(x)$

<font color=dblue>证明方法：</font>归纳法。略

---

<font color=blue>定义3.9</font> 根：设$f(x)$为域$\mathbb F$上的多项式，如果$a\in \mathbb F$使得$f(a)=0$，则称$a$是$f(x)$在域$\mathbb F$上的一个根。

---

<font color=purple>定理3.15</font> 余元定理：设$f(x)$为域$\mathbb F$上的多项式，对于任意$a\in \mathbb F$，存在$g(x)\in \mathbb F[x]$使得$f(x)=(x-a)g(x)+f(a)$

<font color=dblue>证明方法：</font>设$f(x)=(x-a)g(x)+c$，代入$a$即可。

<font color=red>本定理可以这样理解：将其看成域上离散的中值定理——$\frac{f(x)-f(a)}{x-a}=g(x)$，认为中值定理在域上也成立。但是实际上写的时候不能写分式，因为并没有定义除这个运算。</font>

<font color=orange>推论1</font> 设$f(x)$为域$\mathbb F$上的多项式，$a$为$f(x)$在域$\mathbb F$的根的充要条件为$(x-a)|f(x)$
<font color=orange>推论2</font> 设$f(x)$为域$\mathbb F$上的多项式，如果$a_1,a_2,...a_m$为$f(x)$在域$\mathbb F$的根，则存在$n-m$次多项式$g(x)\in \mathbb F[x]$使得$f(x)=(x-a_1)(x-a_2)...(x-a_m)g(x)$
<font color=orange>推论3</font> 设$f(x)$为域$\mathbb F$上的多项式，则$f(x)$在$\mathbb F$的任意扩域中，不同根的个数不会超过$n$（证明使用推论2证明）

---

<font color=purple>定理3.16</font> 设$f(x)$是域$\mathbb F$上的$n\ge 1$次不可约多项式，集合$\mathbb F[x]_{f(x)}=\{\sum_{i=0}^{n-1}a_ix^i|a_i\in\mathbb F\}$按照模$f(x)$的模加和模乘形成一个域。特别地，若$f(x)$是有限域$\mathbb F_q$上的$n$次不可约多项式，则$\mathbb F[x]_{f(x)}=\{\sum_{i=0}^{n-1}a_ix^i|a_i\in\mathbb F_q\}$按照模$f(x)$的模加和模乘形成一个元素个数为$q^n$的有限域。

<font color=dblue>证明方法：</font>证明该运算系统满足域的每条性质。每个项的系数都可以取q个值，因此构造的域的元素个数为$q^n$

以$\mathbb F_q[x]^*_{f(x)}$表示$\mathbb F_q[x]_{f(x)}$的乘法群，其元素个数为$q^n-1$。

<font color=red>注意：任何次数大于等于n的多项式在$\mathbb F[x]_{f(x)}$中均等于一个次数小于n的多项式，每一项的系数关于$\mathbb F$取余，整个多项式关于$f(x)$取余</font>

---

<font color=purple>定理3.17</font> 设$f(x)$是域$\mathbb F$上的一个次数大于0的不可约多项式，那么$f(x)$必然在$\mathbb F$的某个扩域中有根。

<font color=dblue>证明方法：</font>使用定理3.16构造的扩域。

<font color=green>举例：</font>定义在$\mathbb Z_2$上的多项式$f(x)=x^2+1$在其上不可约，因此构造扩域，集合元素为$\{0,1,x,x+1\}$，则显然有$f(x)=x^2+1=0$，即$f(x)=0$，x是多项式的一个根。（这里的x指的是扩域中的x，不要混淆了）

<font color=orange>推论</font> $\mathbb F$上的任意一个次数为$n\ge 1$的多项式，必然在$\mathbb F$的扩域中可以分解为$n$个一次不可约多项式的乘积。

---

<font color=purple>定理3.18</font> 设$\mathbb E$是有限域，$\mathbb F_q$是其q元子域，则存在正整数n使得$|\mathbb E|=q^n$。

<font color=dblue>证明方法：</font>逐步扩大法。$\mathbb F_q=\mathbb E_1$如果存在$\beta\in \mathbb E \setminus \mathbb E_1$，那么定义$\mathbb E_2=\{a_0+a_1\beta|a_0,a_1\in\mathbb F_q\}$，其元素个数为$q^2$，如果还存在不在$\mathbb E_2$的元素，则继续扩展，直到$\mathbb E_n=\mathbb E$为止。

<font color=red>注意：这其中的$\mathbb E_i$不一定是一个域！在严格证明中将其描述为集合。</font>

<font color=orange>推论</font> 有限域的元素个数必为$p^n$，其中$p$为素数。任何有限域都是其素域的扩域。

---

<font color=purple>定理3.19</font> 设$\mathbb F_q$为q元有限域，$\mathbb F$为$\mathbb F_q$的扩域，$\alpha\in\mathbb F$，那么$\alpha$是多项式$x^q-x$的根当且仅当$\alpha\in\mathbb F_q$

<font color=dblue>证明方法：</font>对于任意$\alpha\in\mathbb F_q$，$\alpha^q-\alpha=(e+e+e+...+e)^q-\alpha=e^q+e^q+...+e^q-\alpha=\alpha-\alpha=0$，故$x^q-x$的根是$\mathbb F_q$的所有元素，而其也只有这么多根（次数限制）。
