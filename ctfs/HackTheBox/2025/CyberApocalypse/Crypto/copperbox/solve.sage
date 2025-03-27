from Crypto.Util.number import long_to_bytes as l2b,bytes_to_long as b2l 

load("path/to/defund/coppersmith.sage")


p = 0x31337313373133731337313373133731337313373133731337313373133732ad
a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de


hint1 = 77759147870011250959067600299812670660963056658309113392093130
hint2 = 50608194198883881938583003429122755064581079722494357415324546

def lcg(x, a, b):
    while True:
        yield (x := a*x + b)


def solve_challenge():
    poly.<x,lsb_1,lsb_2> = PolynomialRing(GF(p))

    H1 = (hint1 << 48) + lsb_1
    H2 = (hint2 << 48) + lsb_2

    X = b2l(b'HTB{' + bytes(26)) + x

    gen = lcg(X,a,b)

    poly_h1 = next(gen) - H1 * next(gen)
    poly_h2 = next(gen) - H2 * next(gen)

    poly_h1_zz = poly_h1.change_ring(ZZ)
    poly_h2_zz = poly_h2.change_ring(ZZ)

    poly_resultant = poly_h1_zz.resultant(poly_h2_zz)

    poly = poly.remove_var(x)
    poly_resultant = poly(poly_resultant)

    bounds = (2**48,2**48)
    roots = small_roots(poly_resultant,bounds)
    
    print(roots[0])


    poly_x1 = poly_h1.subs(lsb_1=roots[0][0]).univariate_polynomial().monic()
    poly_x2 = poly_h2.subs(lsb_2=roots[0][1]).univariate_polynomial().monic()

    assert poly_x1 == poly_x2

    x = poly_x1.roots()[0][0]

    flag = b'HTB{' + l2b(int(x))
    print(flag.decode())
