# Chapter 2 同余
<font color=blue>定义2.1</font> 同余、不同余

---

<font color=purple>定理2.1</font> 同余是一种等价关系（自反性、对称性、传递性依次证明）

---

<font color=blue>定义2.2</font> 模m剩余类，模m完全剩余系

---

<font color=blue>定义2.3</font> 模m简化剩余类，完全剩余类中所有与m互素的剩余类。模m简化剩余系。欧拉函数：整数1,2,...,m中所有与m互素的整数个数，即为$\varphi(m)$

---

<font color=purple>定理2.2</font> $a,b$正整数，$a\equiv b(\mod mn)\Rightarrow a\equiv b(\mod m), a\equiv b(\mod n)$（逆定理不成立）

---

<font color=purple>定理2.3</font> $m,n$正整数，$a\equiv b(\mod m),a\equiv b(\mod n)\Rightarrow a\equiv b(\mod [m,n])$

---

<font color=purple>定理2.4</font> 同余性质：
(1) $a\equiv b(\mod m)\Rightarrow a+c\equiv b+c(\mod m)$
(2) $a\equiv b(\mod m), k\in Z\Rightarrow ak\equiv bk(\mod m)$
(3) $ak\equiv bk(\mod m), k\in Z,(k,m)=1\Rightarrow a\equiv b(\mod m)$
(4) $a\equiv b(\mod m), k\in N\Leftrightarrow ak\equiv bk(\mod mk)$
(5) $a\equiv b(\mod m), f(x)$为一整系数多项式，$f(a)\equiv f(b)(\mod m)$

<font color=orange>推论</font> 若$a_1\equiv a_2(\mod m),b_1\equiv b_2(\mod m)$，则$a_1+b_1\equiv a_2+b_2(\mod m),a_1b_1\equiv a_2b_2(\mod m)$

---

<font color=purple>定理2.5</font> 设m为正整数，若(a,m)=1，则当x遍历m的一个完全剩余系时，对于任意整数b，ax+b遍历模m的一个完全剩余系；当x遍历m的一个简化剩余系时，ax遍历m的一个简化剩余系。

<font color=dblue>证明：</font>
设$r_1,r_2,...,r_m$是模m的一个完全剩余系，当$i\ne j$时，$r_i\ne r_j(\mod m)$，又$(a,m)=1$，则$ar_i+b\ne ar_j+b(\mod m)$，故x遍历r~1~，r~2~，...，r~m~时，ax+b是m个关于m两两互不同余的整数，因此构成完全剩余系。
如果$r_1,r_2,...,r_{\varphi(m)}$是简化剩余系，对于所有$r_i,(r_i,m)=1$，因为$(a,m)=1$，则有$(ar_i,m)=1$，即任意ar~i~均在简化剩余系中且两两互不同余。因此构成简化剩余系。

---

<font color=purple>定理2.6</font> 设m,n为正整数，(m,n)=1，则当x遍历模n的一个完全剩余系，y遍历模m的一个完全剩余系时，mx+ny遍历模mn的一个完全剩余系；当x遍历模n的一个简化剩余系，y遍历模m的一个简化剩余系时，mx+ny遍历模mn的一个简化剩余系。

<font color=dblue>证明：</font>
假设$mx_1+ny_1\equiv mx_2+ny_2(\mod mn)$，由定理2.2可知，$mx_1+ny_1\equiv mx_2+ny_2(\mod m),mx_1+ny_1\equiv mx_2+ny_2(\mod n)$，又(m,n)=1，故$y_1\equiv y_2(\mod m),x_1\equiv x_2(\mod n)$。因此mx+ny互不同余，构成模mn的完全剩余系。
若$(x,n)=1,(y,m)=1$，则$(mx+ny,m)=(ny,m)=(y,m)=1,(mx+ny,n)=1$，故$(mx+ny,mn)=1$，即任意一个与mn互素的整数都在遍历所产生的$\varphi(m)\varphi(n)$个简化剩余类中。

---

<font color=purple>定理2.7</font> （欧拉定理）m为正整数，(a,m)=1，则$a^{\varphi(m)}\equiv 1(\mod m)$

<font color=dblue>证明：</font>
构造模m的简化剩余系$r_1,r_2,...,r_{\varphi(m)}$，(a,m)=1，故由定理2.4有$ar_1,ar_2,...,ar_{\varphi(m)}$也是模m简化剩余系。故对于任意$1\le i\le \varphi(m)$有且仅有唯一$1\le j\le \varphi(m)$使得$ar_i=r_j$。故
$$r_1r_2...r_{\varphi(m)}\equiv a^{\varphi(m)}r_1r_2...r_{\varphi(m)}(\mod m)$$
证毕

---

<font color=purple>定理2.8</font> （费马小定理）p为素数，则对于任意整数a，$a^p\equiv a(\mod p)$

<font color=dblue>证明：</font>
由欧拉定理可知若(a,p)=1，则$a^{\varphi(p)}=a^{p-1}\equiv 1(\mod p)$，原命题成立
否则必有p|a，即$a^{p-1}\equiv a\equiv 0(\mod p)$

---

<font color=purple>定理2.9</font> m,n为正整数，若互素，则$\varphi(m)\varphi(n)=\varphi(mn)$

<font color=dblue>证明：</font>
定理2.6

---

<font color=purple>定理2.10</font> p为素数，e为正整数，则$\varphi(p^e)=p^e-p^{e-1}$

<font color=dblue>证明：</font>
从1到p^e^中与p^e^不互素的只有p的倍数，共有p^e-1^个。

---

<font color=purple>定理2.11</font> 设m为正整数，$m=\prod_{i=1}^Sp_i^{a_i}$，则$\varphi(m)=m\prod_{i=1}^S(1-\frac{1}{p_i})$

<font color=dblue>证明：</font>
定理2.9，2.10

---

<font color=blue>定义2.4</font> 模m同余式：$f(x)=\sum_{i=0}^{n}a_ix^i$为一个整系数多项式，m为正整数，称$f(x)\equiv 0(\mod m)$为模m同余式。若$a_n\ne 0(\mod m)$则称该同余式次数为n，如果整数a满足$f(a)\equiv 0(\mod m)$则称a为同余式的解。解数：同余式解的个数。

---

<font color=purple>定理2.12</font> m为正整数，同余式$ax\equiv b(\mod m)$有解的充要条件是(a,m)|b。有解时结束为(a,m)，且若x=x~0~是同余式的一个特解，则同余式的所有解可以表示为
$$x\equiv x_0+\frac{m}{(a,m)}t(\mod m),t=0,1,2,...,(a,m)-1$$

<font color=dblue>证明：</font>
若$ax\equiv b(\mod m)$有解，则存在整数y使得ax-b=my，且若x=x~0~，y=y~0~是ax-b=my的一个解，则$x\equiv x_0(\mod m)$就是$ax\equiv b(\mod m)$的一个解。根据定理1.8可知，ax-b=my有解的充要条件是(a,m)|b。
若x=x~0~，y=y~0~是ax-b=my的一个解，则ax-b=my的所有解可以表示为：
$$\left\{  
		\begin{aligned}
             x=x_0+\frac{m}{(a,m)}t\\
             y=y_0+\frac{a}{(a,m)}t
       \end{aligned}
       ,t\in\mathbb Z
\right.
$$
可将$x=x_0+\frac{m}{(a,m)}t,t\in\mathbb Z$写为(a,m)个模m的同余类，即t取0,1,...,(a,m)-1

---

<font color=purple>定理2.13</font> m为正整数，(a,m)=1，则$a^{\varphi(m)-1}$是a模m的逆元。

<font color=dblue>证明：</font>略

---

<font color=purple>定理2.14</font> （Wilson定理）设p为素数，则$(p-1)!\equiv -1(\mod p)$

<font color=dblue>证明：</font>
p=2时结论显然成立
p>2，对于$1\le a\le p-1$，因为(a,p)=1，因此a存在逆元a'，由$ax\equiv 1(\mod m)$的解数为1，故满足$1\le a'\le p-1$的逆元也是唯一的。在1,2,...,p-1中将这些数一一配对，每一对的两数均互为逆元，则结论显然成立。

---

<font color=purple>定理2.15</font> （中国剩余定理）设$m_1,m_2,...,m_S$为两两互素的正整数，$b_1,b_2,...,b_S$为任意整数，则同余式组
$$
\left\{  
		\begin{array}{rcl}
             x\equiv b_1(\mod m_1)\\
             x\equiv b_2(\mod m_2)\\
             ...\\
             x\equiv b_S(\mod m_S)
       \end{array}
\right.
$$
模$M=m_1...m_S$有唯一解$x\equiv \sum_{i=1}^S b_i\frac{M}{m_i}(\frac{M}{m_i})^{-1}(\mod m_i)(\mod M)$

<font color=dblue>证明：</font>
存在性：代入上式即可
唯一性：设有一个解为x~0~，则其满足上面任意一个式子，根据定理1.14有$M=[m_1,m_2,...,m_S]|x-x_0$，即$x\equiv x_0(\mod M)$，解唯一。

---

<font color=purple>定理2.16</font> 设$m_1,m_2,...,m_S$为两两互素的正整数，对于$1\le i\le s$，同余式$f_i(x)\equiv 0(\mod m_i)$有C~i~个解，则同余式组
$$
\left\{  
		\begin{array}{rcl}
             f(x)\equiv 0(\mod m_1)\\
             f(x)\equiv 0(\mod m_2)\\
             ...\\
             f(x)\equiv 0(\mod m_S)
       \end{array}
\right.
$$
关于模$M=m_1...m_S$有$C_1C_2...C_s$个解。

<font color=dblue>证明：</font>组合。
证明这些解互不同余：
若有$x\equiv x'(\mod M)$，则由定理2.2可知对于任意i均有$x\equiv x'(\mod m_i)$，故x=x'。
任何b~i~变化都会导致解不同。

---

<font color=purple>定理2.17</font> p为素数，$i_1\ge i_2\ge ... i_S,b_1,b_2,...,b_S$为任意整数，同余式组
$$
\left\{  
		\begin{array}{rcl}
             x\equiv b_1(\mod p^{i_1})\\
             x\equiv b_2(\mod p^{i_2})\\
             ...\\
             x\equiv b_S(\mod p^{i_S})
       \end{array}
\right.
$$
有解的充要条件为
$$
\left\{  
		\begin{array}{rcl}
             b_1\equiv b_2(\mod p^{i_2})\\
             b_1\equiv b_3(\mod p^{i_3})\\
             ...\\
             b_1\equiv b_S(\mod p^{i_S})
       \end{array}
\right.
$$

<font color=dblue>证明：</font>
充分性易证
必要性：若有解x~0~，则由定理2.2可知$x_0\equiv b_1(\mod p^{i_2})$，故$b_1$是第二个式子的解，同理b~1~也是后面所有式子的解。

---

<font color=blue>定义2.6</font> 导式

---

<font color=purple>定理2.18</font> 设p为素数，$k\ge 1$，若$x\equiv x_k(\mod p^k)$为同余式$f(x)\equiv 0(\mod p^k)$的一个解，则在这个剩余类中：
(1) 若$(p,f'(x^k))=1$，则同余式$f(x)\equiv 0(\mod p^{k+1})$有唯一解。
(2) 若$p|f'(x^k)$，当$f(x_k)\ne 0(\mod p^{k+1})$时，同余式$f(x)\equiv 0(\mod p^{k+1})$无解，否则有p个解。

<font color=dblue>证明：</font>
由定理2.2可知，同余式$f(x)\equiv 0(\mod p^{k+1})$的解一定是$f(x)\equiv 0(\mod p^k)$的解，因此我们只需对$f(x)\equiv 0(\mod p^k)$的解进行筛选即可。

从$x=x_k+p^kt,t\in\mathbb Z$中进行筛选：
将其代入到$f(x)\equiv 0(\mod p^{k+1})$中使用泰勒公式可得：
$$f(x_k)+f'(x_k)p^kt+\sum_{i=2}^n\frac{f^{(i)}(x_k)p^{ik}}{i!}t^i\equiv 0(\mod p^{k+1})$$
因为$\frac{f^{(i)}(x_k)}{i!}=\frac{a_n\cdot n!}{i!(n-i)!}$为整数，因此有$i!|f^{(i)}(x_k)$。即泰勒展开除前面两项之外后面所有项均整除$p^{k+1}$，可以全部消去，化简为：
$$f(x_k)+f'(x_k)p^kt\equiv 0(\mod p^{k+1})$$
又$p^k|f(x_k)$，上式可以化为：
$$\frac{f(x_k)}{p^k}+f'(x_k)t\equiv 0(\mod p^{k+1})$$
若$(f'(x_k),p)=1$则t仅有1个取值。若为0则与定理结论相符。

<font color=orange>推论</font> p为素数，若$x\equiv x_1(\mod p)$是同余式$f(x)\equiv 0(\mod p)$的一个解，且满足$(f'(x_1),p)=1$，则对于任意正整数k>1，$f(x)\equiv 0(\mod p^k)$的满足$x\equiv x_1(\mod p)$的解x~k~可以通过以下递推式得到：
$$x_i=x_{i-1}-f(x_{i-1})((f'(x_1))^{-1}(\mod p))(\mod p^i),i=1,2,3,...,k$$

<font color=dblue>证明：</font>数学归纳法

---
