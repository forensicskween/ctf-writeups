
# 🔐 Crypto Challenge

  

## 🏷️ Name: Copperbox

  

## 🔥 Difficulty: Medium

  

## 🎯 Points: 1000

  

## 📜 Challenge Description:

> Cedric found a mysterious box made of pure copper in the old archive. He is convinced that it contains the secrets he is looking for, but he is unable to penetrate the metal case. Can you help?

  

## 📂 Provided Files:

-  **Filename:**  `crypto_copperbox.zip`

  

-  **SHA-256 Hash:**  `c17f0e6e4e7c194122e13ed0702eccc599d1292b279c38e554dfae3233a943ec`

  

# 🚀 Methodology

  

### 🔎 1️⃣ Understanding the Cryptosystem

The cryptosystem uses a Linear Congruential Generator (LCG) defined as follows:

$$\text{Initial seed:} \quad x_0 \in \mathbb{Z}_p$$

$$x_{n+1} \equiv a x_n + b \pmod{p}, \quad \text{for } n \geq 0$$

--- 

We're given:
- A 254-bit **prime** modulus
- Constants $a$ and $b$
- Two truncated outputs: $hint_1$ and $hint_2$

The internal values are computed via:

$$
\begin{aligned}
x_n &= a x_{n-1} + b \\
x_{n+1} &= a x_n + b \\
h_n &= \left( x_n \cdot x_{n+1}^{-1} \right) \bmod p
\end{aligned}
$$


Or more consisely:

$$h_n = \left( \dfrac{x_n}{x_{n+1}} \right) \bmod p$$


The challenge discards the lowest 48 bits of each $h_n$​ :

$$
\begin{aligned}
\text{hint}_n &= \left\lfloor \frac{h_n}{2^{48}} \right\rfloor
\end{aligned}
$$



### ⚡ 2️⃣ Identifying Vulnerabilities

The core of this challenge relies on **modular arithmetic over finite fields**, specifically over the multiplicative group $\mathbb{Z}_p^*$.

- The values $h_1$ and $h_2$ are elements of the group $\mathbb{Z}_p^*$.  In this group, every nonzero element has a **multiplicative inverse**, which makes operations like division (i.e., modular inverses) well-defined.
- The LCG forms a **linear recurrence** over $\mathbb{Z}_p$. This means that each $x_n$ is a polynomial in the intial seed, $x_0$ (in other words - the padded flag). 

The key vulnerability is information leakage:

- The hints leak most of the bits of $h_1$ and $h_2$, ~206 out of 254 bits of information per hint. That’s an **enormous leak**.

- The unknowns are in the least significant bits, and the truncation to 48 bits means the actual space of uncertainty is just $2^{48}$, which is small relative to the 254-bit modulus.

- We also know that the initial seed is 30 bytes long and starts with b'HTB{'; which gives us an additional ~32 known bits.


We can start by defining our polynomials in SageMath:

```python

poly.<x,lsb_1,lsb_2> = PolynomialRing(GF(p))

H1 = (hint1 << 48) + lsb_1
H2 = (hint2 << 48) + lsb_2
X = b2l(b'HTB{' + bytes(26)) + x

gen = lcg(X,a,b)

poly_h1 = next(gen) - H1 * next(gen)
poly_h2 = next(gen) - H2 * next(gen)

```

This produces two bivariate polynomials that share a common root in $x$. 

### 🔨 3️⃣ Exploiting the Weakness

Given the challenge's name it's obvious we are expected to use Coppersmith's small roots method. However, solving directly with poly_h1 and poly_h2 is infeasible. This is because there aren't enough known bits of $x$. 

But, the two polynomials share a common root in $x$, therefore we can eliminate the seed variable $x$ using a resultant, which will give us a bivariate polynomial in $lsb_1$ and $lsb_2$. 

To do that, we can convert the polynomials to the Integer Ring and calculate the resultant polynomial, and map it back to our original PolynomialRing. 

*Side note: Defund's Coppersmith implementation will check that the number of variables in the polynomial are equal to the number of variables of the Polynomial Ring, therefore we will need to remove variable x from the Polynomial Ring before applying the small roots method* 

```python

poly_h1_zz = poly_h1.change_ring(ZZ)
poly_h2_zz = poly_h2.change_ring(ZZ)

poly_resultant = poly_h1_zz.resultant(poly_h2_zz)

poly = poly.remove_var(x)
poly_resultant = poly(poly_resultant)

```

### 🔑 4️⃣ Recovering the Flag


Now we have a bivariate polynomial with **small roots**: both $lsb_1$ and $lsb_2$ are less than $2^{48}$. This is exactly the kind of problem that **Coppersmith’s method** solves.

I used [defund’s Coppersmith implementation](https://github.com/defund/coppersmith/blob/master/coppersmith.sage):

```python

bounds = (2**48,2**48)
roots = coppersmith.small_roots(poly_resultant,bounds)
print(roots[0])

```
The roots:
```python

# (53006259096585, 248699398699637)

```
Substituting them back in our original polynomials to get the LSB of $x$:
```python

poly_x1 = poly_h1.subs(lsb_1=roots[0][0]).univariate_polynomial().monic()
poly_x2 = poly_h2.subs(lsb_2=roots[0][1]).univariate_polynomial().monic()

assert poly_x1 == poly_x2

x = poly_x1.roots()[0][0]

flag = b'HTB{' + l2b(int(x))
print(flag)

#HTB{sm1th1ng_mY_c0pp3r_fl4G}L\xc6
```

**🚩 Final Flag:**  `HTB{sm1th1ng_mY_c0pp3r_fl4G}`
