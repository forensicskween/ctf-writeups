# 🔐 Crypto Challenge

## 🏷️ Name: Twin Oracles

## 🔥 Difficulty: Hard

## 🎯 Points: 1000

## 📜 Challenge Description: 
> A powerful artifact—meant to generate chaos yet uphold order—has revealed its flaw. A misplaced rune, an unintended pattern, an oversight in the design. The one who understands the rhythm of its magic may predict its every move and use it against its creators. Will you be the one to claim its secrets?

## 📂 Provided Files:
- **Filename:** `crypto_twin_oracles.zip`

- **SHA-256 Hash:** `513048e8a6890fe9c7dbc5e0feda405a09daa5b080074a3c3b834941a338d224`

# 🚀 Methodology

This challenge involves a dynamic RSA oracle with partial bit leakage, backed by a weak BBS-based PRNG.


### 🔎 1️⃣ Understanding the Cryptosystem

This challenge is split into multiple parts:

---

#### 1. **ObsidianSeers** — The Oracle

- The `ObsidianSeers` class implements RSA with `e = 65537` and 1024-bit `n`.
- Its encryption and decryption functions are standard.
- But the twist lies in `consult_seers`, where we submit a ciphertext and **receive either the LSB or MSB of the decrypted value** — determined dynamically.

Specifically:
- If `relic.get_bit() == 0`:  
  → We receive the **LSB** of `m = c^d mod n`
- If `relic.get_bit() == 1`:  
  → We receive whether `m >= n//2` (the **MSB**)

This dynamic leakage is what makes the challenge non-trivial — and interesting.

---

#### 2. ChaosRelic

ChaosRelic is initialized as follows:

- Two 8-bit primes `p`, `q` → `M = p * q` (known to us)
- A secret 15-bit prime `x0` → used as the seed
- Its internal state `x` evolves via:
  
  $$ x_{i+1} = x_i^2 \bmod M $$

- Each call to `get_bit()` triggers a state update and returns `x % 2`.

This is a classic **Blum Blum Shub (BBS)** PRNG pattern — which is **predictable** due to the small size of `M` and low entropy of `x0`.

We can interact with the oracle by passing in ciphertext `1`:

### Why ciphertext `1`?

```python
consult_seers(1)
```

Since $c = 1 → m = 1^d \mod n = 1$ for any `d`, it simplifies the output:

- If we get `0`:  
  → It came from **MSB** ( `get_bit() == 1`), because `1 < n//2` ⇒ returns 0.
- If we get `1`:  
  → It came from **LSB** ( `get_bit() == 0`), because `1 % 2 == 1`.
  

This gives us the exact output of `get_bit()` for any call, which allows us to **reconstruct the BBS PRNG**.

---


#### 3. The Server

We're allowed up to **1500 interactions**. Each loop gives us 3 options:

- **[1]** Request RSA public key and encrypted flag
- **[2]** Submit a ciphertext and receive a leak (LSB or MSB, depending on the ChaosRelic)
- **[3]** Exit

That gives us **1499 consultable oracle calls** after retrieving the challenge parameters.

---

### ⚡ 2️⃣ Identifying Vulnerabilities


I approached this problem in perhaps not the most elegant/economic way. I knew that I wanted to recover the plaintext via the LSB oracle only. 

---

#### Recovering the message via the LSB oracle:

The classic LSB oracle attack works like this:

- Start with interval `[low, high] = [0, n)`
- For `i = 1 to k` (bitlength of `n`):
  - Multiply ciphertext `c` by `2^e mod n`
  - Submit to oracle
  - Get LSB of decrypted `m / 2^i`
  - Update interval accordingly:
    - If LSB = 0: `high = (low + high) // 2`
    - If LSB = 1: `low = (low + high) // 2`
- After enough steps, the interval narrows to `m`


This requires **one oracle call per bit**, so we must **ensure we can make 1024 calls where `get_bit() == 0`**.

--- 

#### Recovering the relic and predicting the output:

ChaosRelic is **unsafe**. If we can predict the outputs of the relic, then we can predict if it will leak the LSB or the MSB. 

Breaking down the search space:

- 8-bit primes: There are 23 in the [128, 255] range  
  ⇒ 253 unique composite values for `M = p * q`
- 15-bit primes: 1612 values in [2^14, 2^15]  
  ⇒ ~400k total (`M`, `x0`) pairs

Using a few hundred `get_bit()` outputs, we can **brute-force and reconstruct the exact ChaosRelic** instance used.

> BUT the *goal* isn’t just identifying the relic — it's ensuring **at least 1024 LSB oracle responses** for the full LSB attack to succeed.

That shifts our focus to:

- Maximizing the number of future `get_bit()`s that are `0` ( LSB oracle access)
- Balancing **relic recovery time** vs. number of usable LSB queries remaining


### 🔍 3️⃣ Reconstructing the Oracle (ChaosRelic)


The key 'problem', in my approach was figuring out which $M$ and which $x0$ will give me what I need. 

Therefore, I did a 'pre-image' attack, to 'study' the outputs. Since this takes a long time, I just had it running in another window and saved the outputs to a json file.

I modified ChaosRelic to:
- be initialized with a given M and x0
- Calculate the next_bits and count the number of zeros. 

```python

from itertools import product, combinations
from tqdm import tqdm
import time
import json

class ChaosRelic_study:
    def __init__(self,M,x0):
        self.M = M
        self.x0 = x0
        self.x = self.x0

    def next_state(self):
        self.x = pow(self.x, 2, self.M)
        
    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()
    
    def extract_bit_from_state(self):
        return self.x % 2
    
    def gen_and_count_bits(self,n_range):
        next_bits = ''.join([str(self.get_bit()) for _ in range(n_range)])
        return (next_bits,next_bits.count('0'))


def get_potential_ms():
    primes_p_q = list(primes(2**7,2**8))
    combos =  list(combinations(primes_p_q,int(2)))
    potential_ms = [prod(x) for x in combos]
    return potential_ms

def gen_relics_for_M(M):
    relics_for_m = dict()
    for x0 in potential_x0s:
        relic = ChaosRelic_study(M,x0)
        relics_for_m[int(x0)] = relic.gen_and_count_bits(1500)
    return relics_for_m

potential_x0s = list(primes(2**14,2**15))

potential_ms = get_potential_ms()
all_relics = {}

start = time.time()

for i, M in tqdm(enumerate(potential_ms), total=len(potential_ms)):
    tqdm.write(f'Current M = {M}')
    relics_for_m = gen_relics_for_M(M)
    sorted_relics = sorted(tuple(relics_for_m.items()),key=lambda x: x[1][1],reverse=True)
    tqdm.write(f'Most Zeros for x0: {sorted_relics[0][0]} --> {sorted_relics[0][1][1]}/1500')
    all_relics[int(M)] = relics_for_m

end = time.time()

elapsed = end - start
print(f"Total time: {elapsed:.2f} seconds")

with open("all_relics.json",'w') as of:
    of.write(json.dumps(all_relics))

```

It took around 24 minutes on my computer.

Once I generated all potential relic states, the next step was to determine the **optimal number of queries** (`n_queries`) required for each modulus `M` to:

1. **Uniquely identify** the correct `x0` (initial seed)
2. Ensure that the remaining bitstream (after identification) contains **at least 1024 bits equal to `0`**, enabling a successful LSB oracle attack

To do this, I implemented a search that:

- Iterates over possible prefix lengths `k` (from 20 to 500)
- For each `k`, groups relics by the first `k` bits of their bitstream
- Checks if the prefix uniquely identifies a single `x0` (there can be more than one so to avoid confusion we kick the duplicates out)
- Validates that the **suffix** ( bits after position `k`) contains at least **1024 zeros**
- Ensures that all selected prefixes are **unique** for that specific M. This makes sure we won't use the wrong x0 when creating the relic.

This gives me, for each valid `M`, the **minimal number of queries** required to identify the relic and guarantee that there are enough future LSB oracle responses to recover the plaintext.


```python

import json

def gen_optimal_values_for_m(bit_dict, min_required_zeros=1024, min_k=20, max_k=500):
    optimal_ks = {}
    all_ks = set()
    for k in range(min_k, max_k):
        prefix_map = {}
        for x0, (bits, _) in bit_dict.items():
            prefix = bits[:k]
            prefix_map.setdefault(prefix, []).append((x0, bits))
        for prefix, candidates in prefix_map.items():
            if len(candidates) == 1:
                x0, bits = candidates[0]
                suffix = bits[k:]
                if suffix.count('0') >= min_required_zeros:
                    if x0 not in optimal_ks:
                        optimal_ks[x0] = []
                    optimal_ks[x0].append((k, suffix.count('0')))
                    all_ks.add(k)
    if all_ks == set():
        return None
    minimum = min(all_ks)
    for minimum in all_ks:
        TARGETS = [bit_dict[x][0][:minimum] for x in optimal_ks]
        if len(set(TARGETS)) == len(TARGETS):
            break
    all_targets = [x[0][:minimum] for x in bit_dict.values()]
    optimal_dict = {bit_dict[x][0][:minimum]:x for x in optimal_ks}
    assert [all_targets.count(x)==1 for x in TARGETS]
    return minimum,optimal_dict

def get_optimal_values_for_all_ms(all_relics):
    optimals = {}
    for M,bit_dict in all_relics.items():
        if any([x[1]>=1024 for x in bit_dict.values()]):
            result = gen_optimal_values_for_m(bit_dict)
            if result:
                optimals[M] = result
    return optimals


with open('all_relics.json','r') as inf:
    all_relics = json.load(inf)


optimals = get_optimal_values_for_all_ms(all_relics)

with open('optimal_relics.json','w') as of:
    of.write(json.dumps(optimals))

```

Now, we have 4264 optimal M-x0 pairs. 

This means that before proceeding with anything, we are going to:

- check that the server's M is in our optimal values (because not all Ms give a 'valid' relic - based on my approach to the challenge)
- request consult_seers(1) x times the minimum number of bits for this particular M
- check that the output is in the optimal values for the specific M.
- If it is, we can continue, otherwise, byebye and we start over.


### 🔑 4️⃣ Recovering the Flag

**Step 1: Get an oracle with valid M-x0 pair**

We do someething along the lines of:

```python

with open("optimal_relics.json","r") as inf:
    optimal_relics = json.loads(inf.read())

optimal_relics = {int(k):v for k,v in optimal_relics.items()}

while True:
    counter = 0 
    t = remote(host,port)
    M = get_m(t)
    result = optimal_relics.get(M)
    if result:
        n_range, valid_relics = result
    else:
        t.close()
        continue
    partial_relic = get_relic_n_bits(t,n_range)
    found = valid_relics.get(partial_relic)
    if found:
        n,enc_flag = get_n_and_enc_flag(t)
        relic = ChaosRelic_study(M,found)
        previous_bits,_ = relic.gen_and_count_bits(n_range)
        assert previous_bits == partial_relic
        break
    else:
        t.close()
```


Once we find a valid oracle, recovering the flag via the LSB attack is easy. 

```python

e = 65537

upper_limit = n
lower_limit = 0

i0 = 1

limits1 = []
limits0 = []
# for 1024 bit N

for i in range(1500-counter):
    chosen_ct = ((enc_flag*pow(2**i0, e, n)) % n)
    bit = relic.get_bit()
    output = oracle(chosen_ct)
    if bit == 0:
        if output == 0:
            limits0.append((upper_limit + lower_limit))
            upper_limit = (upper_limit + lower_limit)/2
        elif output == 1:
            limits1.append((lower_limit + upper_limit))
            lower_limit = (lower_limit + upper_limit)/2
        else:
            raise Exception("BAD")
        if i0 >= 1024:
            print(l2b(int(upper_limit)))
            break
        i0 += 1
    else:
        pass
    #if the bit is 1, aka MSB, we don't calculate the intervals.

```


**🚩 Final Flag:** `HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_3c5f85d1bc17b52581e3bbf1f730d129}`

