from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes as l2b

def load_out():
    with open('source/pubkey.pem', 'rb') as f:
        key = RSA.import_key(f.read())
    with open('source/output.txt','r') as inf:
        data = inf.read().strip().split('\n')
    data = [x.split('= ')[1].strip() for x in data]
    enc_flag = int(data[0][1:-1],16)
    R = eval(data[1])
    return enc_flag,R,key


#https://github.com/josephsurin/lattice-based-cryptanalysis/blob/5b0541dcfd475d1f3838c568618198b5f6367368/lbc_toolkit/common/babai_cvp.sage

def babai_cvp(B, t):
    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]
    return t - b


def solve_hnp(N,R):
    n = len(R)

    #Generating Target Vector
    k = N.bit_length() #1024
    a = 2**(k-15)
    a_prime = a + N // 2^17
    t = vector(QQ,[N/(2**17)] + [a_prime]*n)

    #Generating Lattice
    B = Matrix(QQ,n+1,n+1)

    for i in range(len(R)):
        B[0,i+1] = R[i]

    B[0,0] = 1/(65536)

    for i in range(1,n+1):
        B[i,i] = N

    B = B.LLL()

    m = babai_cvp(B,t)

    return m



enc_flag, R, key = load_out()

m = solve_hnp(key.n,R)
m0 = int(m[0]*65536)

flag = l2b(m0).split(b'\x00')[1].decode()
print(flag)
#HTB{Bleichenbacher_Lattice_Attack_and_The_Hidden_Number_Problem___Cool_Right?!}
