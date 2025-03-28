import hashlib
from itertools import permutations
import base64

def hashit(sequence):
    sequence_str = ''.join(sequence)  # sequence is a list of strings
    sha256_hash = hashlib.sha256(sequence_str.encode()).digest()
    return sha256_hash

TARGET_HASH = base64.b64decode("18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=")

found = False
TARGETS = [ "c1", "c2", "c3", "c4" ]*3
for i in range(2,len(TARGETS)):
    for perm in permutations(TARGETS,int(i)):
        if hashit(perm) == TARGET_HASH:
            print(f'Found Correct Sequence: {perm}')
            found = True
            break
    if found:
        break