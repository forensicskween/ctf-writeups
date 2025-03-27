from pwn import remote
import json
from Crypto.Util.number import long_to_bytes as l2b
from preimage import ChaosRelic_study

def get_m(t):
    t.recvuntil(b"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = ")
    M = int(t.recvline().decode().strip())
    return M

def get_n_and_enc_flag(t):
    global counter
    t.sendlineafter(b'> ',b'1')
    t.recvuntil(b"The Elders grant you insight: n = ")
    n = int(t.recvline().decode().strip())
    t.recvuntil(b"The ancient script has been sealed: ")
    enc_flag =  int(t.recvline().decode().strip())
    counter+=1
    return n,enc_flag

def consult_seers(t,x=1,recovery=False):
    global counter
    t.sendlineafter(b'> ',b'2')
    t.sendlineafter(b"Submit your encrypted scripture for the Seers' judgement: ",hex(x).encode())
    t.recvuntil(b'The Seers whisper their answer: ')
    counter+=1 
    result = int(t.recvline().decode().strip())
    if recovery:
        return '0' if result else '1'
    return result

def get_relic_n_bits(t,n_range):
    partial_relic = ''.join([consult_seers(t,recovery=True) for _ in range(n_range)])
    return partial_relic

with open("optimal_relics.json","r") as inf:
    optimal_relics = json.loads(inf.read())

optimal_relics = {int(k):v for k,v in optimal_relics.items()}

host,port = '94.237.51.215','49524'

while True:
    counter = 0 
    #t = process(['python3.11','server_modified.py'])
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
        print(f'Found a valid oracle for M = {M} and x0 = {found}')
        break
    else:
        t.close()


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
    output = consult_seers(t,chosen_ct)
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
            print(l2b(int(upper_limit)).decode())
            break
        i0 += 1
    else:
        pass

#HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_db1c4ce8c6d7e57e607f4b29e9184cd1}
