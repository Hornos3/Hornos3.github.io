<font color=red>定理1.1</font> 任意给定整数a和正整数b>0，存在唯一的一对整数q，0≤r≤b，使得a=qb+r

<font color=green>推论1</font> 任意给定整数a和正整数b<0，存在唯一的一对整数q，$0\le r\le |b|$，使得a=qb+r
<font color=green>推论2</font> 任意给定整数a,c和整数b≠0，存在唯一的一对整数q,c≤r≤|b|+c，使得a=qb+r

<font color=blue>定义1.1</font> 整除、倍数、因子、商

<font color=red>定理1.2</font> 设a,b,c为整数：
(1) 若a|b，b|a，则a=b
(2) 设整数k≠0，若a|b，则ka|kb，反之亦然
(3) 对任意整数k，若a|b，则a|kb
(4) 若a|b，b≠0，则$\frac{b}{a}|b$
(5) 若a|b，b|c，则a|c
(6) 若a|b，a|c，则对任意整数s和t，a|sb+tc（裴蜀定理）

<font color=blue>定义1.2</font> 公因数、互素

<font color=red>定理1.3</font> 设a,b为两个不全为0的整数，且a=qb+r，q，r为整数，则(a,b)=(b,r)

<font color=green>推论</font> 设a,b为两个不全为0的整数，q为整数，则(a, b)=(a±bq, b)=(a, b±aq)

<font color=red>定理1.4</font> 设a,b为两个正整数，r~n-2~=q~n-1~r~n-1~+r~n~，0≤r~n~≤r~n-1~为欧几里得辗转相除算式，则：
(1) (a,b)=r~n~
(2) 存在整数s,t，使得r~n~=sa+tb
(3) 任意整数c，若满足c|a且c|b，则c|r~n~

<font color=red>定理1.5</font> 设a,b为两个正整数，上式为其欧几里得辗转相除算式，则由S~0~=0，S~1~=1，S~i+1~=S~i-1~-q~n-i~S~i~，n≥i≥1递推所得的S~n-1~和S~n~满足S~n-1~a+S~n~b=r~n~

证明：写成矩阵形式

<font color=red>定理1.6</font> 设a,b为两个不全为0的整数，则
(1) 对于任意正整数k，(ka,kb)=k(a,b)
(2) $(\frac{a}{(a,b)},\frac{b}{(a,b)})=1$

<font color=red>定理1.7</font> 设a,b,c是三个整数，a≠0，c≠0，若(a,b)=1，则(a,bc)=(a,c)

<font color=red>定理1.8</font> 设a,b是两个不全为0的整数，关于x和y的整系数不定方程ax+by=c有整数解的充要条件是(a,b)|c。若x=x~0~，y=y~0~是方程的一个特解，那么方程的所有整数解都可以表示为：$x=x_0-\frac{b}{(a,b)}t, y=y_0+\frac{a}{(a,b)}t,t\in\mathbb Z$

<font color=blue>定义1.3</font> 多个数的公因数、最大公因数、互素

<font color=red>定理1.9</font> 设a~1~,a~2~,...,a~n~是n个不全为0的整数，不妨设a~1~≠0，定义d~1~=(a~1~, a~2~)，d~2~=(d~1~, a~3~)，...，d~n-1~=(d~n-2~, a~n~)，则d~n-1~=(a~1~, a~2~, ... a~n~)

<font color=green>推论</font> 设正整数d是a~1~，a~2~，...，a~n~的最大公因数，存在s~1~，s~2~，...，s~n~有d=s~1~a~1~+s~2~a~2~+...+s~n~a~n~

<font color=red>定理1.10</font> 正整数c是a~1~，a~2~，...，a~n~的最大公因数，当且仅当：
(1) c|a~1~, c|a~2~, ..., c|a~n~
(2) 任一整数d若满足d|a~1~, d|a~2~, ..., d|a~n~，则d|c

<font color=blue>定义1.4</font> 公倍数、最小公倍数

<font color=red>定理1.11</font> 设a,b为两个正整数，且(a,b)=1
(1) 若a|c，b|c，则ab|c
(2) [a,b]=ab

<font color=red>定理1.12</font> 设a,b为两个正整数
(1) 对于任何正整数k，[ka, kb]=k[a,b]
(2) $[a,b]=\frac{ab}{(a,b)}$
(3) 若a|c，b|c，则[a,b]|c

<font color=red>定理1.13</font> 设a~1~，a~2~，...，a~n~是n个不为0的整数，定义m~1~=[a~1~, a~2~]，m~2~=[m~1~, a~3~]，...，m~n-1~=[m~n-2~, a~n~]，则[a~1~, a~2~, ..., a~n~]=m~n-1~

<font color=red>定理1.14</font> 与定理1.10类似，不想抄了

<font color=blue>定义1.5</font> 素数

<font color=red>定理1.15</font> 合数的最小的不等于1的正因子p一定是素数且小于根号m
<font color=green>推论</font> 若所有小于根号m的素数都不是m的因子，则m为素数

<font color=red>定理1.16</font> 素数有无穷多个

<font color=red>定理1.17</font> 素数定理：$\lim_{x\rightarrow\infty}\pi(x)\frac{\ln(x)}{x}=1$

<font color=red>定理1.18</font> 切比雪夫定理：设整数n>3，则至少存在一个素数p满足n<p<2n-2

<font color=red>定理1.19</font> 算数基本定理：n为一个大于1的正整数，则n必然可以分解为一些素数的乘积，如果将素因子顺序排列，则n分解方式唯一。

<font color=blue>定义1.6</font> 标准分解式

<font color=blue>定义1.7</font> 高斯函数

<font color=red>定理1.20</font>
(1) 若x≤y，则[x]≤[y]
(2) 整数a满足x-1<a≤x$\Leftrightarrow$a=[x]
(3) 整数a满足a≤x<a+1$\Leftrightarrow$a=[x]
(4) 任意整数n，[n+x]=n+[x]

<font color=red>定理1.21</font> 整数a,b且b>0，带余除法算式a=qb+r，0≤r<b，则q=$[\frac{a}{b}]$

<font color=red>定理1.22</font> n!中包含的p次幂次数为$\sum_{i\ge 1}[\frac{n}{p^i}]$


