#!/usr/bin/env python3

##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import matplotlib.pyplot as plt
import numpy as np
import random
from typing import List


def mymod(x: int, N: int) -> int:
    mask = (1 << N.bit_length()) - 1
    masked = x & mask
    if masked >= N: return masked - N
    return masked


def mymod2(x: int, N: int) -> int:
    mask = (1 << N.bit_length()) - 1
    masked = x & mask
    if masked >= N: return masked - ((1 << N.bit_length()) - N)
    return masked


def mymod3(x: int, N: int) -> int:
    mask = (1 << N.bit_length()) - 1
    masked = x & mask
    dist = (1 << N.bit_length()) - N
    if (masked - N) > dist // 2:
        assert (masked - dist) < N
        return masked - dist
    if masked > N: return masked - N
    return masked


def mymod4(x: int, N: int) -> int:
    mask = (1 << N.bit_length()) - 1
    masked = x & mask
    if masked >= N:
        assert (masked ^ N) < N
        return masked ^ N
    return masked


def mulmod(x: int, N: int) -> int:
    # https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    v = (x * N) >> MAX.bit_length()
    assert v < N
    return v


def dist(xs: List[int], N: int, label: str, width: float = 0.1, offset: float = 0):
    d = np.array([xs.count(i) for i in range(N)])
    plt.bar(np.arange(N) + offset, d, width=width, label=label)
    print(f'{label}: mean {np.mean(d)} min {np.min(d)} max {np.max(d)} std {np.std(d)}')


MAX = 4096
N = 200
data = [random.randint(0, MAX) for _ in range(2**16)]
real_mod = [x % N for x in data]
dist(real_mod, N, label='real mod', offset=0)
my_mod = [mymod(x, N) for x in data]
dist(my_mod, N, label='stupid 1', offset=0.1)
my_mod = [mymod2(x, N) for x in data]
dist(my_mod, N, label='stupid 2', offset=0.2)
my_mod = [mymod3(x, N) for x in data]
dist(my_mod, N, label='stupid 3', offset=0.3)
my_mod = [mymod4(x, N) for x in data]
dist(my_mod, N, label='stupid 4', offset=0.4)
my_mod = [mulmod(x, N) for x in data]
dist(my_mod, N, label='mulmod', offset=0.5)
plt.legend()
plt.show()
