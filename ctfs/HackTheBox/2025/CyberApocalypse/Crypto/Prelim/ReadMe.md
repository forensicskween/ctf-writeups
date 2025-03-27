# 🔐 Crypto Challenge

## 🏷️ Name: Prelim

## 🔥 Difficulty: Easy

## 🎯 Points: 975

## 📜 Challenge Description: 
> Cedric has now found yet another secret message, but he dropped it on the floor and it got all scrambled! Do you think you can find a way to undo it?

## 📂 Provided Files:
- **Filename:** `crypto_prelim.zip`

- **SHA-256 Hash:** `2cc8c37c9c6f3378618d130a597a167322dd841f2566d3b98c9f6e0c0fc3ce1b`

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

This is a cryptosystem that can uses a permutations to 'scramble' a message. 

#### Parameters
- `n = 0x1337 = 4919`: Length of the message and the domain of permutations.
- `e = 0x10001 = 65537`: Public exponent (typical RSA public exponent).

The **scramble function** can be defined as:

- `a` and `b` be permutations on `n` elements, represented as lists of integers.
- The function `scramble(a, b)` is defined as:
\
$$\text{scramble}(a, b)[i] = b[a[i]] \quad \text{for } i = 0, \dots, n-1$$

Or in other words, it's **function composition**:  $$b \circ a$$

#### Super Scramble = Modular Exponentiation on Permutations

There was a CTF challenge in HTB a few years ago that was similar to this one.

The function `super_scramble(a, e)`:
- Computes the **e-th power** of permutation `a` using exponentiation by squaring, acting on the identity permutation $\text{id}$
  $$\text{superscramble}(a, e) = a^e \circ \text{id}$$

- Each application of `scramble` is a composition, so overall this is:
  $$P = a^e \in S_n$$
- The result is the permutation $P$ applied to the identity, which gives:
  
 $$\text{scrambledmessage} = P(i) \quad \text{for } i = 0, \dots, n-1$$


The original permutation, `message` is converted to a string and hashed with Sha256; which becomes the AES key used to encrypt the flag. 

### ⚡ 2️⃣ Recovering Message and the flag

In SageMath, we can recover the message by calculating the inverse of $e$ modulo the order of the permutation. To do that, we will have to add 1 to each element of the scrambled_message, because we cannot define a SymmetricGroupElement if there is 0 in the list.

```python

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

n = 0x1337
e = 0x10001


scrambled_1based = [x + 1 for x in scrambled_message]
G = SymmetricGroup(n)
P_e = G(scrambled_1based)
order = P_e.order()
d = inverse_mod(e, order)
P = P_e ^ d
original_message = [P(i + 1) - 1 for i in range(n)]

```

Then, we simply hash the original message, and decrypt it using AES:


```python

key = sha256(str(original_message).encode()).digest()
ct = bytes.fromhex(enc_flag)
dec_flag = AES.new(key, AES.MODE_ECB).decrypt(ct)
flag = unpad(dec_flag,16).decode()
print(flag)

```

**🚩 Final Flag:** `HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}`

