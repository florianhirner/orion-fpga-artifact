#!/bin/python3

##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

from ctypes import * 

trivium32_so_file = "./pythonConnector32.so"
trivium64_so_file = "./pythonConnector64.so"

CHandler_PRNG_32 = CDLL(trivium32_so_file)
CHandler_PRNG_64 = CDLL(trivium64_so_file)

def trivium32_next():
    CHandler_PRNG_32.trivium32_next.restype = c_uint32
    return CHandler_PRNG_32.trivium32_next()

def trivium32_setseed(seed, seq):
    CHandler_PRNG_32.trivium32_setseed(c_uint32(seed), c_uint32(seq))

def trivium64_next():
    CHandler_PRNG_64.trivium64_next.restype = c_uint64
    return CHandler_PRNG_64.trivium64_next()

def trivium64_setseed(seed, seq):
    CHandler_PRNG_64.trivium64_setseed(c_uint64(seed), c_uint64(seq))

trivium32_setseed(0, 0)
print(f"{hex(trivium32_next())}")
print(f"{hex(trivium32_next())}")
print(f"{hex(trivium32_next())}")

trivium64_setseed(0, 0)
print(f"{hex(trivium64_next())}")
print(f"{hex(trivium64_next())}")
print(f"{hex(trivium64_next())}")