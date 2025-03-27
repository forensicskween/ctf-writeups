from pwn import remote

def format_factors(factors):
    flattend = flatten(list(factors))
    answer = [str(flattend[0])]
    middle = flattend[1:-1]
    for i in range(0,len(middle),2):
        pair = middle[i:i+2]
        answer.append(f'{pair[0]}_{pair[1]}')
    answer.append(str(flattend[-1]))
    result =  ','.join(answer)
    return result

def get_answer_curve_p3():
    F_P3.<z> = GF(p^3)
    E3 = EllipticCurve(F_P3,[a,b])

    E3_order = E3.order()
    assert E3_order%p ==0 
    partial_order = E3_order//p #otherwise it will take forever in sage

    factors = list(factor(partial_order))
    factors.append((p,1))
    factors = sorted(factors,key=lambda x: x[0])

    answer = format_factors(factors)
    return answer

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

def is_generator(g, p,factors):
    for q, _ in factors:
        if pow(g, (p - 1)//q, p) == 1:
            return 0
    return 1


p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b =  8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134

E = EllipticCurve(GF(p),[a,b])

G = E.lift_x(10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771)

factors = factor(p-1)

QUESTION_3 = b'[3] For this question, you will have to send 1 if the element is a generator of the finite field F_p, otherwise 0.\n'

answer_1 = str(p.bit_length()).encode()
answer_2 = format_factors(factors).encode()
answer_4 = str(p).encode()
answer_5 = get_answer_curve_p3().encode()

host,port = '94.237.59.98','51551'

conn = remote(host,port)

conn.sendlineafter(b'> ',answer_1)
conn.sendlineafter(b'> ',answer_2)
conn.recvuntil(QUESTION_3)

for _ in range(17):
    g = int(conn.recvuntil(b'?').decode().strip()[:-1])
    answer = is_generator(g,p,factors)
    conn.sendlineafter(b'> ',str(answer).encode())

conn.sendlineafter(b'> ',answer_4)
conn.sendlineafter(b'> ',answer_5)

conn.recvuntil(b'A has x-coordinate: ')
A_x = ZZ(conn.recvline().decode().strip())

A = E.lift_x(A_x)
d = SmartAttack(G,A,p)
conn.sendlineafter(b'> ',str(d).encode())

conn.recvline()
FLAG = conn.recvline()
print(FLAG.decode().strip())