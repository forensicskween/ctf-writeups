from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

n = 0x1337
e = 0x10001

def reverse_permutation(scrambled_message):
    scrambled_1based = [x + 1 for x in scrambled_message]
    G = SymmetricGroup(n)
    P_e = G(scrambled_1based)
    order = P_e.order()
    d = inverse_mod(e, order)
    P = P_e ^ d
    original_message = [P(i + 1) - 1 for i in range(n)]
    return original_message


def decrypt_flag(message,enc_flag):
    key = sha256(str(message).encode()).digest()
    ct = bytes.fromhex(enc_flag)
    dec_flag = AES.new(key, AES.MODE_ECB).decrypt(ct)
    return unpad(dec_flag,16).decode()

def load_params():
    with open('tales.txt', 'r') as f:
        scrambled_message = eval(f.readline().split('=')[1].strip())
        enc_flag = f.readline().split('=')[1].strip()[1:-1]
    return scrambled_message,enc_flag

scrambled_message,enc_flag = load_params()
message = reverse_permutation(scrambled_message)
flag = decrypt_flag(message,enc_flag)
print(flag)

#HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}