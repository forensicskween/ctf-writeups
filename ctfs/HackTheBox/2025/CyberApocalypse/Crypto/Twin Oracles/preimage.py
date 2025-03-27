from itertools import product, combinations
from tqdm import tqdm
import time
import json
from sage.all import prod, primes

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
        relics_for_m[x0] = relic.gen_and_count_bits(1500)
    return relics_for_m

potential_x0s = list(primes(2**14,2**15))

def generate_all_relics_study():
    potential_ms = get_potential_ms()
    all_relics = {}

    start = time.time()

    for i, M in tqdm(enumerate(potential_ms), total=len(potential_ms)):
        tqdm.write(f'Current M = {M}')
        relics_for_m = gen_relics_for_M(M)
        sorted_relics = sorted(tuple(relics_for_m.items()),key=lambda x: x[1][1],reverse=True)
        tqdm.write(f'Most Zeros for x0: {sorted_relics[0][0]} --> {sorted_relics[0][1][1]}/1500')
        all_relics[M] = sorted_relics

    end = time.time()

    elapsed = end - start
    print(f"Total time: {elapsed:.2f} seconds")

    with open("all_relics.json",'w') as of:
        of.write(json.dumps(all_relics))

if __name__ == '__main__':
    generate_all_relics_study()