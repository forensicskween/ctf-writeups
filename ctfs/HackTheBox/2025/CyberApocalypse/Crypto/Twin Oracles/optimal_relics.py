
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
