##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

from ctypes import CDLL
from ctypes.util import find_library
from typing import Callable
from random import randint

libc = CDLL(find_library("c"))
rand: Callable[[], int] = libc.rand


class FieldElement:
    mod = 2305843009213693951 # 0x1FFFFFFFFFFFFFFF -> 2^61-1

    def __init__(self, real: int, img: int):
        self.real = real
        self.img = img

    def __eq__(self, o):
        if not isinstance(o, FieldElement): return False
        return self.img == o.img and self.real == o.real

    def __add__(self, o) -> 'FieldElement':
        if isinstance(o, FieldElement):
            im = self.img + o.img
            re = self.real + o.real
            if self.mod <= im: im -= self.mod
            if self.mod <= re: re -= self.mod
            return self.__class__(re, im)
        else: raise ValueError('Adding invalid objects')

    def __sub__(self, o) -> 'FieldElement':
        if isinstance(o, FieldElement):
            tmp_r = o.real ^ self.mod  # tmp_r == -b.real is true in this prime field
            tmp_i = o.img ^ self.mod
            im = self.img + tmp_i
            re = self.real + tmp_r
            if self.mod <= im: im -= self.mod
            if self.mod <= re: re -= self.mod
            return self.__class__(re, im)
        else: raise ValueError('Subtracting invalid objects')

    def __mul__(self, o) -> 'FieldElement':
        if isinstance(o, FieldElement):
            t1 = self.real * o.real
            t2 = self.img * o.img
            re = (t1 - t2) % self.mod
            im = ((self.real + self.img) * (o.real + o.img) - t1 - t2) % self.mod
            return self.__class__(re, im)
        else: raise ValueError('Multiplying invalid objects')

    def __neg__(self) -> 'FieldElement':
        re = (self.mod - self.real) % self.mod  # do modular in case real = 0
        im = (self.mod - self.img) % self.mod
        return self.__class__(re, im)

    def __repr__(self):
        return f'FieldElement({self.real}, {self.img})'

    def __str__(self):
        return f'{self.real:016x}.{self.img:016x}'

    @classmethod
    def random(cls) -> 'FieldElement':
        re = rand() % cls.mod
        im = rand() % cls.mod
        return cls(re, im)

    @classmethod
    def random2(cls) -> 'FieldElement':
        re = randint(0,cls.mod-1) % cls.mod
        im = randint(0,cls.mod-1) % cls.mod
        return cls(re, im)

    @classmethod
    def from_str(cls, string: str) -> 'FieldElement':
        parts = string.split('.')
        if len(parts) != 2: raise ValueError('Invalid format, expected xxx.xxx')
        re = int(parts[0], 16)
        im = int(parts[1], 16)
        return cls(re, im)
