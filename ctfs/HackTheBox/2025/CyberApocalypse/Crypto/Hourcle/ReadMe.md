# 🔐 Crypto Challenge

## 🏷️ Name: Hourcle

## 🔥 Difficulty: Easy

## 📜 Challenge Description: 
> A powerful enchantment meant to obscure has been carelessly repurposed, revealing more than it conceals. A fool sought security, yet created an opening for those who dare to peer beyond the illusion. Can you exploit the very spell meant to guard its secrets and twist it to your will?

## 📂 Provided Files:
- **Filename:** `crypto_hourcle.zip`

---

# 🚀 Methodology

### 🔎 1️⃣ Understanding the Cryptosystem

The server uses AES in **CBC mode**, with a randomly generated 32-byte key (`KEY`) and a 16-byte IV per encryption. A random 20-character password is generated and stored server-side.

The function `encrypt_creds(user)` is suspicious—it *decrypts* the padded user+password string using AES-CBC, instead of encrypting it. This inversion becomes a major weakness.

The encrypted output is shown to the user, which gives us an oracle: we can input a username and observe how the "encrypted" credentials look.

The goal is to recover the password to get the flag.

### ⚡ 2️⃣ Identifying Vulnerabilities

There are **two major issues here**:

- 💼 **Encryption is actually decryption**: CBC decryption is misused as encryption. This makes it act like ECB in certain scenarios.
- 🔀 **Input-dependent structure**:  Block alignment is under our control, since we can control the username, we also control how the password lines up within AES blocks.


In AES-CBC, decryption works as:
```
P_i = D(C_i) ⊕ C_{i-1}
```
So if two decrypted plaintext blocks are the same, and they’re XORed with the same input (like a controlled previous block), the ciphertext blocks will also be the same. That gives us a way to tell if our guess matches part of the password.



### 🔨 3️⃣ Exploiting the Weakness


We recover the password **character-by-character** with a block comparison trick:

1. Use a prefix of `A` * 16 to fill one block.
2. Pad and insert our guess in a place where it aligns exactly with where the password will fall.
3. Send the crafted "username" and get the ciphertext from the oracle.
4. Compare two ciphertext blocks. If they match, our guess is correct.

Repeat this for each position in the 20-character password. Since the charset is limited (letters, numbers, underscore), brute-forcing each character takes very little time.

Example logic:
```python
xor(blocks[my_idx], blocks[his_idx])[:pos] == bytes([pos]) * pos
```
That’s how we confirm a correct guess—it only matches when the decrypted plaintexts are identical at that block.


### 🔑 4️⃣ Recovering the Flag

Once we’ve got the full password, we use it in the login function via menu option 2. If it matches the server’s password, we can request access and get the flag!

---

**🚩 Final Flag:** `HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_6f095f37e50b00d11a14a785e8d31d28}`


