#!/usr/bin/env python3

##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import random

def check(t, n=61):
    assert t < 2**(2 * n)
    p = 2**n - 1
    a = t % p
    b = (t >> n) + (t & p)
    if b >= p: b -= p
    if b >= p: b -= p  # only necessary to prevent a=b=2^n-1 -> results in 2*p -> not necessary if t=x*y <<< 2^2n
    assert a == b, f"{t} ({t:X}) -- {a} ({a:X}) vs {b} ({b:X})"


if __name__ == "__main__":
    Q = 2**61-1
    for _ in range(10**7):
        x = random.randint(0,Q-1)
        y = random.randint(0,Q-1)
        a = random.randint(0,Q-1)
        b = random.randint(0,Q-1)
        c = random.randint(0,Q-1)
        z = x+y+a+b+c
        z = (z % 2**61) + (z >> 61)
        assert z == ((x+y+a+b+c) % Q)

    for _ in range(1024):
        check(random.randint(0, 2**122 - 2))
    check(2**122 - 1)
