#!/usr/bin/env python3

##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import shutil


HBM_WORD_SIZE = 512
DDR_WORD_SIZE = 256

BURST_LENGTH = 4096*8 # 4KB in bits
HBM_NUM_BURST_WORDS = BURST_LENGTH // HBM_WORD_SIZE
DDR_NUM_BURST_WORDS = BURST_LENGTH // DDR_WORD_SIZE

OP_GG = True
OP_PP = True

# Latency
LATENCY_GG = 0
LATENCY_PP = 0

# Graph-Generation
NUM_RD_GG_OPs = 0
NUM_WR_GG_OPs = 0

# Post-Processing
NUM_RD_PP_OPs = 0
NUM_WR_PP_OPs = 0

# Patch-Size
GG_PATH_SIZE = 0    # not used
PP_PATCH_SIZE_FULL = 1   # 1, ..., x
PP_PATCH_SIZE_MINI = 16   # 1, 2, 4, 8, 16, ... 2^x

# Seeds
PRNG_SEED_ADDR_GG = 0
PRNG_SEED_ADDR_PP = 0
PRNG_SEED_WEIGHT  = 1

# PrimeField
LOGQ = 64
LOGP = 61
PRIME = (1<<LOGP)-1

PATH_MEM_FILES = "../../../hw/rtl/memory_content/rom/"
PATH_PKG_FILES = "../../../hw/rtl/"

HBM_CTR = 0

###############################################################################

from ctypes import *
import math
from primefield import FieldElement as ComplexPrimeFieldElement

trivium32_so_file = "./../prng/trivium/pythonConnector32.so"
trivium64_so_file = "./../prng/trivium/pythonConnector64.so"
trivium64_so_file_0 = "./../prng/trivium/pythonConnector64_0.so"
trivium64_so_file_1 = "./../prng/trivium/pythonConnector64_1.so"
trivium64_so_file_2 = "./../prng/trivium/pythonConnector64_2.so"

CHandler_PRNG_32 = CDLL(trivium32_so_file)
CHandler_PRNG_64 = CDLL(trivium64_so_file)
CHandler_PRNG_64_0 = CDLL(trivium64_so_file_0)
CHandler_PRNG_64_1 = CDLL(trivium64_so_file_1)
CHandler_PRNG_64_2 = CDLL(trivium64_so_file_2)

# 32 bit
def trivium32_next():
    CHandler_PRNG_32.trivium32_next.restype = c_uint32
    return CHandler_PRNG_32.trivium32_next()

def trivium32_setseed(seed, seq):
    CHandler_PRNG_32.trivium32_setseed(c_uint32(seed), c_uint32(seq))

# 64 bit
def trivium64_setseed(seed, seq):
    CHandler_PRNG_64.trivium64_setseed(c_uint64(seed), c_uint64(seq))

def trivium64_next():
    CHandler_PRNG_64.trivium64_next.restype = c_uint64
    return CHandler_PRNG_64.trivium64_next()

# 64 bit
def trivium64_0_setseed(seed, seq):
    CHandler_PRNG_64_0.trivium64_setseed(c_uint64(seed), c_uint64(seq))

def trivium64_0_next():
    CHandler_PRNG_64_0.trivium64_next.restype = c_uint64
    return CHandler_PRNG_64_0.trivium64_next()

def trivium64_1_setseed(seed, seq):
    CHandler_PRNG_64_1.trivium64_setseed(c_uint64(seed), c_uint64(seq))

def trivium64_1_next():
    CHandler_PRNG_64_1.trivium64_next.restype = c_uint64
    return CHandler_PRNG_64_1.trivium64_next()

def trivium64_2_setseed(seed, seq):
    CHandler_PRNG_64_2.trivium64_setseed(c_uint64(seed), c_uint64(seq))

def trivium64_2_next():
    CHandler_PRNG_64_2.trivium64_next.restype = c_uint64
    return CHandler_PRNG_64_2.trivium64_next()

RND_MASK = 2**32 - 1

###############################################################################

def mymod(x: int, N: int) -> int:
    mask = (1 << N.bit_length()) - 1
    masked = x & mask
    if masked >= N: 
        return masked - N
    return masked

###############################################################################

def getRecInfoInvGraphLeftToRight(size, rounds, alpha1, rate, deg1, deg2):
    print(f'[getRecInfoInvGraphLeftToRight]')
    print(f'')

    NUM_OP_RD = 0
    NUM_OP_WR = 0

    deg1_l = 10
    deg2_l = 20

    round_info = []

    n = size
    n_in = n
    n_out = n

    rd_min = 0
    rd_max = n
    rd_offset = []

    wr_min = 0
    wr_max = 0
    wr_offset = []

    raddr_max = 0
    waddr_max = 0

    ptr = 0
    ns = []

    # Left Graph-Generation (Recursion-Down)
    for round in range(rounds):
        ns.append(n)
        # run expander
        n_new = int(alpha1 * n)
        deg1_r = deg1

        n_out += n_new
        L = n
        R = n_new
        raddr_max += (n_new * deg1_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min += L
        rd_max += R

        wr_min += L
        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])

        print(f'> n = {n}, \tL = {L}, \tR = {R},  \tptr = {ptr}, \td1 = {deg1_r}')

        NUM_OP_RD += L + L * deg1_l
        NUM_OP_WR += 0 + L * deg1_l

        round_info.append([n, n, n_new, ptr, deg1_r])
        ptr += n
        n = n_new

    # Right Graph-Generation (Recursion-Up)
    wr_min = wr_max
    for round in range(rounds):
        n = ns.pop()
        n_new = int(alpha1 * n)
        if round != 0:
            n_new = int(rate * n_new)
        r = int(n * (rate - 1)) - n_new
        deg2_r = deg2

        n_out += r
        L = n_new
        R = r
        raddr_max += (r * deg2_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min -= n
        rd_max += R

        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])
        wr_min += R

        print(f'> n = {n}, \tL = {L},  \tR = {R},  \tptr = {ptr}, \td2 = {deg2_r}')

        NUM_OP_RD += L + L * deg2_l
        NUM_OP_WR += 0 + L * deg2_l

        round_info.append([n, n_new, r, ptr, deg2_r])
        ptr -= n

    print(f'')
    print(f'= {NUM_OP_RD=}')
    print(f'= {NUM_OP_WR=}')
    print(f'')
    print(f'[getRecInfoInvGraphLeftToRight]')
    print(f'')
    return NUM_OP_RD, NUM_OP_WR


def getRecInfoInvGraphRightToLeft(size, rounds, alpha1, rate, deg1, deg2):
    print(f'[getRecInfoInvGraphRightToLeft]')
    print(f'')

    NUM_OP_RD = 0
    NUM_OP_WR = 0

    deg1_l = 10
    deg2_l = 20

    round_info = []

    n = size
    n_in = n
    n_out = n

    rd_min = 0
    rd_max = n
    rd_offset = []

    wr_min = 0
    wr_max = 0
    wr_offset = []

    raddr_max = 0
    waddr_max = 0

    ptr = 0
    ns = []

    # Left Graph-Generation (Recursion-Down)
    for round in range(rounds):
        ns.append(n)
        # run expander
        n_new = int(alpha1 * n)
        deg1_r = deg1

        n_out += n_new
        L = n
        R = n_new
        raddr_max += (n_new * deg1_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min += L
        rd_max += R

        wr_min += L
        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])

        print(f'> n = {n}, \tL = {L}, \tR = {R},  \tptr = {ptr}, \td1 = {deg1_r}')

        NUM_OP_RD += R * deg1_r
        NUM_OP_WR += R

        round_info.append([n, n, n_new, ptr, deg1_r])
        ptr += n
        n = n_new

    # Right Graph-Generation (Recursion-Up)
    wr_min = wr_max
    for round in range(rounds):
        n = ns.pop()
        n_new = int(alpha1 * n)
        if round != 0:
            n_new = int(rate * n_new)
        r = int(n * (rate - 1)) - n_new
        deg2_r = deg2

        n_out += r
        L = n_new
        R = r
        raddr_max += (r * deg2_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min -= n
        rd_max += R

        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])
        wr_min += R

        print(f'> n = {n}, \tL = {L},  \tR = {R},  \tptr = {ptr}, \td2 = {deg2_r}')

        NUM_OP_RD += R * deg2_r
        NUM_OP_WR += R

        round_info.append([n, n_new, r, ptr, deg2_r])
        ptr -= n

    print(f'')
    print(f'= {NUM_OP_RD=}')
    print(f'= {NUM_OP_WR=}')
    print(f'')
    print(f'[getRecInfoInvGraphRightToLeft]')
    print(f'')
    return NUM_OP_RD, NUM_OP_WR

###############################################################################

def getRecursionInformations(size, rounds, alpha1, rate, deg1, deg2):
    print(f'[getRecursionInformations]')
    print(f'')

    NUM_CYCLES = 0
    round_info = []

    n = size
    n_in = n
    n_out = n

    rd_min = 0
    rd_max = n
    rd_offset = []

    wr_min = 0
    wr_max = 0
    wr_offset = []

    raddr_max = 0
    waddr_max = 0

    ptr = 0
    ns = []

    # Left Graph-Generation (Recursion-Down)
    for round in range(rounds):
        ns.append(n)
        # run expander
        n_new = int(alpha1 * n)
        deg1_r = deg1

        n_out += n_new
        L = n
        R = n_new
        raddr_max += (n_new * deg1_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min += L
        rd_max += R

        wr_min += L
        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])

        print(f'> n = {n}, \tL = {L}, \tR = {R},  \tptr = {ptr}, \td1 = {deg1_r}')
        NUM_CYCLES += (R * deg1_r)

        round_info.append([n, n, n_new, ptr, deg1_r])
        ptr += n
        n = n_new

    # Right Graph-Generation (Recursion-Up)
    wr_min = wr_max
    for round in range(rounds):
        n = ns.pop()
        n_new = int(alpha1 * n)
        if round != 0:
            n_new = int(rate * n_new)
        r = int(n * (rate - 1)) - n_new
        deg2_r = deg2 

        n_out += r
        L = n_new
        R = r
        raddr_max += (r * deg2_r)
        waddr_max += R

        rd_offset.append([rd_min, rd_max])
        rd_min -= n
        rd_max += R

        wr_max = wr_min + R
        wr_offset.append([wr_min, wr_max])
        wr_min += R

        print(f'> n = {n}, \tL = {L},  \tR = {R},  \tptr = {ptr}, \td2 = {deg2_r}')
        # NUM_CYCLES += (L * deg2_r)
        NUM_CYCLES += (R * deg2_r)

        round_info.append([n, n_new, r, ptr, deg2_r])
        ptr -= n

    # print(f'')
    # print(f'= n_in      = {n_in}')
    # print(f'= n_out     = {n_out}')
    # print(f'= raddr_max = {raddr_max}')
    # print(f'= waddr_max = {waddr_max}')
    # print(f'')
    # print(f'= rd_offset = {rd_offset}')
    # print(f'= wr_offset = {wr_offset}')
    print(f'')
    print(f'[getRecursionInformations]')
    print(f'')
    return n_in, n_out, raddr_max

###############################################################################

num_of_effected_edges = 0
num_of_resamples = 0

le_gg_list_of_all_nodes = []
le_gg_list_of_rec_nodes = []

le_gg_list_of_all_edges = []
le_gg_list_of_rec_edges = []

le_pp_list_of_all_nodes = []
le_pp_list_of_rec_nodes = []

le_pp_list_of_all_edges = []
le_pp_list_of_rec_edges = []

###############################################################################

def calcResemblingAmount(E, d, d_min, d_max, depth, size_L, size_R, addr_it, weight_it, out_data, ptr):
   
    global num_of_effected_edges
    global num_of_resamples

    global NUM_RD_GG_OPs
    global NUM_WR_GG_OPs

    global NUM_RD_PP_OPs
    global NUM_WR_PP_OPs
    
    
    # calculate edge distrubtion
    list_affected_nodes = [0 for _ in range(d_max)]
    for i, Ei in enumerate(E):
        # only take edged with less than d_max outgoing edges
        if Ei < d_max:
            list_affected_nodes[Ei] += 1
        # calculate computational overhead
        if Ei < d:
            NUM_RD_PP_OPs += 1
            NUM_RD_PP_OPs += (d - Ei)
            NUM_WR_PP_OPs += (d - Ei)

    # check how many are edges are under d_min 
    _num_of_effected_edges = 0
    _num_of_resamples = 0

    for _i, _edge in enumerate(list_affected_nodes):
        if _i < d:
            # print(f'>> {_i=} {_edge=} {d=}')
            _num_of_effected_edges += _edge
            _num_of_resamples += (d - _i) * _edge

    num_of_effected_edges += _num_of_effected_edges
    num_of_resamples += _num_of_resamples

    return


# params: size, rounds, alpha1, rate, deg1, deg2
def getEdgeInformations(size, full_size, weight_size, rounds, alpha1, rate, deg1_r, deg2_r, interleaves):
    print(f'')
    print(f'[getEdgeInformations] begin')
    print(f'')

    global NUM_RD_GG_OPs
    global NUM_WR_GG_OPs

    global NUM_RD_PP_OPs
    global NUM_WR_PP_OPs

    DEBUG_OP_GG = False
    DEBUG_OP_PP = False

    PRNG_ADDR_REJECTION_SAMPLING = True

    n_addr_samples     = 10 * weight_size * interleaves 
    n_weight_samples   = 10 * weight_size 

    in_data_full        = [None for _ in range(size * interleaves)]
    addr_data_full      = [None for _ in range(n_addr_samples)]
    weight_data_full    = [None for _ in range(n_weight_samples)]
    out_data_full       = [None for _ in range(full_size * interleaves)]

    addr_data           = [(trivium64_0_next() & RND_MASK) for _ in range(n_addr_samples//interleaves)]
    addr_mod_data       = []
    weight_data64       = [trivium64_2_next() for _ in range(n_weight_samples)]
    weight_data         = [ComplexPrimeFieldElement((_ & RND_MASK), ((_>>32) & RND_MASK)) for _ in weight_data64]

    ##################################################################
    ##################################################################

    d1, d1_min, d1_max =  8, 0, 10
    d2, d2_min, d2_max = 18, 0, 20

    d1 = D1_MIN
    d2 = D2_MIN

    ##################################################################
    ##################################################################

    ROM_LE_REC_PTR_RD = []
    ROM_LE_REC_PTR_WR = []

    ROM_LE_REC_GG_N_RN = []
    ROM_LE_REC_GG_N_LN = []

    ROM_LE_REC_GG_N_RD = []
    ROM_LE_REC_GG_N_LD = []

    ROM_LE_REC_PP_PATCH_FULL = []
    ROM_LE_REC_PP_PATCH_MINI = []

    ROM_LE_REC_PP_PATCH_MINI_NODES = []
    ROM_LE_REC_PP_PATCH_MINI_EDGES = []

    ##################################################################
    # latency calculation of linear encoding

    LE_GG_L_OP = [] # 42
    LE_GG_R_OP = [] # 26
    LE_PP_L_OP = [] # 0..8 (d1_min)
    LE_PP_R_OP = [] # 0..18 (d1_min)

    ##################################################################
    ##################################################################

    for inter in range(interleaves):
        if DEBUG_OP_GG: print(f'> inter = {inter}/{interleaves}')

        in_data64   = [trivium64_2_next() for _ in range(size)]
        in_data     = [ComplexPrimeFieldElement.random2() for _ in in_data64]
        out_data    = [in_data[i] for i in range(size)]

        for i, v in enumerate(in_data):
            in_data_full[i * interleaves + inter] = v
        for i, v in enumerate(addr_data):
            addr_data_full[i * interleaves + inter] = v
        for i, v in enumerate(weight_data):
            # weight_data_full[i * interleaves + inter] = v
            weight_data_full[i] = v

        gg_addr_it = iter(addr_data)
        pp_addr_it = iter(addr_data)
        weight_it = iter(weight_data)

        n = size
        ptr = 0
        ns = []

        # keep track off all size
        le_gg_list_of_rec_nodes = []
        le_gg_list_of_rec_edges = []

        # keep track off all read and write addresses
        _le_gg_pp_list_of_rd_addr = []
        _le_gg_pp_list_of_wr_addr = []
        _le_gg_list_of_rd_addr = []
        _le_gg_list_of_wr_addr = []
        _le_pp_list_of_rd_addr = []
        _le_pp_list_of_wr_addr = []

        _le_pp_list_of_rd_addr_rec = [[] for _ in range(rounds*2)]
        _le_pp_list_of_wr_addr_rec = [[] for _ in range(rounds*2)]

        if DEBUG_OP_GG: print(f'')
        if DEBUG_OP_GG: print(f'')

        # run expander L 
        rd_offset = 0
        wr_offset = size

        # clean list
        ROM_LE_REC_PTR_RD = []
        ROM_LE_REC_PTR_WR = []
        ROM_LE_REC_GG_N_LN = []
        ROM_LE_REC_GG_N_RN = []
        ROM_LE_REC_GG_N_RD = []
        ROM_LE_REC_GG_N_LD = []
        ROM_LE_REC_PP_PATCH_FULL = []
        ROM_LE_REC_PP_PATCH_MINI = []
        ROM_LE_REC_PP_PATCH_MINI_NODES = []
        ROM_LE_REC_PP_PATCH_MINI_EDGES = []

        # clean list to ignore interleaves
        LE_GG_L_OP = [] # 42
        LE_GG_R_OP = [] # 26
        LE_PP_L_OP = [] # 0..8 (d1_min)
        LE_PP_R_OP = [] # 0..18 (d1_min)

        E = [0 for _ in range(full_size)]
        for round in range(rounds):

            if DEBUG_OP_GG: print("######################################################################")
            if DEBUG_OP_GG: print(f'>> L-Expander: {round=}/{rounds}')
            E = [0 for _ in range(full_size)]

            ns.append(n)
            n_new = int(alpha1 * n)

            size_L = n
            size_R = n_new

            if DEBUG_OP_GG: print(f'>>> n = {n}, \t L = {size_L}, \t R = {size_R}, \t ptr = {ptr}, \td = {deg1_r}')
            if DEBUG_OP_GG: print(f'>> {rd_offset=}, {wr_offset=}')

            # add offset to ROM
            ROM_LE_REC_PTR_RD.append(rd_offset)
            ROM_LE_REC_PTR_WR.append(wr_offset)

            ROM_LE_REC_GG_N_LN.append(size_L)
            ROM_LE_REC_GG_N_RN.append(size_R)

            ROM_LE_REC_GG_N_RD.append(deg1_r)
            ROM_LE_REC_GG_N_LD.append(10) 

            #######################################################################################
            # BEGIN Graph-Generation
            #######################################################################################

            _le_gg_list_of_rec_nodes = []
            _le_gg_list_of_all_edges = []
            for i in range(n_new):

                # RN -> accumulate (node_l * weight)
                res = ComplexPrimeFieldElement(0, 0)

                for j in range(deg1_r):

                    # get address of left side node from PRNG_ADDR
                    _target = next(gg_addr_it)
                    target = mymod(_target, n)
                    addr_mod_data.append(target)
                    
                    # count outgoing edges from L to R
                    E[ptr + target] += 1

                    # get left side node
                    node_l_addr = ptr + target
                    node_l      = out_data[node_l_addr]
                    _le_gg_pp_list_of_rd_addr.append([target, 1])
                    _le_gg_list_of_rd_addr.append([target, 1])

                    # sample random weight from PRNG_WEIGHT
                    weight = next(weight_it)

                    val = node_l
                    mul = val * weight
                    res = res + mul

                    _le_gg_list_of_all_edges.append([target, 1])
                    le_gg_list_of_all_edges.append([target, 1])

                    NUM_RD_GG_OPs += 1
                NUM_WR_GG_OPs += 1
                LE_GG_L_OP.append(deg1_r)

                out_data.append(res)

                _le_gg_pp_list_of_wr_addr.append([i, 1])
                _le_gg_list_of_wr_addr.append([i, 1])

                le_gg_list_of_all_nodes.append([i, deg1_r])
                _le_gg_list_of_rec_nodes.append([i, deg1_r])

            le_gg_list_of_rec_nodes.append(_le_gg_list_of_rec_nodes)
            le_gg_list_of_rec_edges.append(_le_gg_list_of_all_edges)
            
            #######################################################################################
            # END Graph-Generation
            #######################################################################################

            #######################################################################################
            # BEGIN Post- Processing
            #######################################################################################

            if OP_PP: 

                if DEBUG_OP_PP: print("----------------------------------------------------------------------")

                # E           = E[ptr:]
                d           = d1
                d_min       = d1_min
                d_max       = d1_max
                depth       = round
                size_L      = n
                size_R      = n_new
                # addr_it     = pp_addr_it
                weight_it   = weight_it
                out_data    = out_data
                ptr         = ptr

                E_round     = E[ptr:ptr+size_L]

                if DEBUG_OP_PP: print(f'>>> n = {n}, \t L = {n}, \t R = {n_new}, \t ptr = {ptr}, \td = {deg1_r}')
                if DEBUG_OP_PP: print(f'>>>> {PP_PATCH_SIZE_MINI=}, {d=}, {d_min=}, {d_max=}')
                if DEBUG_OP_PP: print(f'>>>> {PP_PATCH_SIZE_MINI=} * {d=} = {PP_PATCH_SIZE_MINI*d}')
                if DEBUG_OP_PP: print(f'')
                
                num_aff_nodes = 0
                num_aff_edges = 0

                # calculate size of patch-size-mini for post-processing
                _PP_PATCH_SIZE_MINI = PP_PATCH_SIZE_MINI
                while _PP_PATCH_SIZE_MINI > int(size_R/d):
                    if _PP_PATCH_SIZE_MINI == 0:
                        break
                    _PP_PATCH_SIZE_MINI = int(_PP_PATCH_SIZE_MINI / 2)
                ROM_LE_REC_PP_PATCH_FULL.append(size_R)
                ROM_LE_REC_PP_PATCH_MINI.append(_PP_PATCH_SIZE_MINI)

                # perform post-processing
                if _PP_PATCH_SIZE_MINI == 0:
                    # if DEBUG_OP_PP: 
                    if DEBUG_OP_PP: print(f"INFO: {_PP_PATCH_SIZE_MINI*d=}, {size_R=} -> skip post-processing")
                    le_pp_list_of_rec_edges.append([])
                    le_pp_list_of_rec_nodes.append([])
                elif size_R < d:
                    if DEBUG_OP_PP: print(f"INFO: {size_R=}, {d=} -> skip post-processing")
                    le_pp_list_of_rec_edges.append([])
                    le_pp_list_of_rec_nodes.append([])
                else:
                    if DEBUG_OP_PP: print(f"[post-processing] begin")
                    calcResemblingAmount(E=E_round, d=d, d_min=d_min, d_max=d_max, depth=depth, size_L=size_L, size_R=size_R, addr_it=pp_addr_it, weight_it=weight_it, out_data=out_data, ptr=ptr)

                    # patch processing of left side nodes
                    _le_pp_patch_ctr = 0 # 0..._PP_PATCH_SIZE_MINI-1
                    _le_pp_patch_rs_ctr = 0 # 0...???-1

                    # store target addresses for rejection sampling
                    _list_of_target_addr_for_rejection_sampling = []

                    # resample all lift side nodes that have a edge count below d_min
                    _list_of_nodes = []
                    _le_pp_list_of_rec_node_edges = []
                    if DEBUG_OP_PP: print(f"> E[{ptr}:{ptr+size_L}]")
                
                    # for i, Ei in enumerate(E):
                    for i, Ei in enumerate(E[ptr:ptr+size_L]): # TODO check boundries
                        if DEBUG_OP_PP: print(f">> {i=} {Ei=} / {d_min}")
                        if Ei < d:
                            if DEBUG_OP_PP: print(f"\t>> {ptr=} : L:{i} R{Ei} / {d_min} -> resample {d-Ei} times")
                            _le_pp_patch_ctr += 1
                            num_aff_nodes += 1
                            num_aff_edges += (d-Ei)

                            _list_of_nodes.append([i, d-Ei]) # node_address, node_degree, num_resamples
                            le_pp_list_of_all_nodes.append([i, d-Ei])

                            # get left side node
                            node_l_addr = ptr + i
                            node_l = out_data[node_l_addr]                  # CMD RD LN
                            _le_gg_pp_list_of_rd_addr.append([i, (d-Ei)])   # [i, 1] or [i, (d-Ei)]
                            _le_pp_list_of_rd_addr.append([i, (d-Ei)])      # [i, 1] or [i, (d-Ei)]
                            _le_pp_list_of_rd_addr_rec[0*rounds+round].append([i, (d-Ei)])      # [i, 1] or [i, (d-Ei)]

                            # store target addresses for rejection sampling
                            if _PP_PATCH_SIZE_MINI <= 1:
                                _list_of_target_addr_for_rejection_sampling = []

                            LE_PP_L_OP.append(d-Ei)
                            for _rs_edge in range(d-Ei):
                                _le_pp_patch_rs_ctr += 1

                                # get address of left side node from PRNG_ADDR
                                target = mymod(next(pp_addr_it), size_R)

                                # check if target address is already in use
                                if PRNG_ADDR_REJECTION_SAMPLING:
                                    if target in _list_of_target_addr_for_rejection_sampling:
                                        while target in _list_of_target_addr_for_rejection_sampling:
                                            target = mymod(next(pp_addr_it), size_R)

                                _list_of_target_addr_for_rejection_sampling.append(target)

                                if DEBUG_OP_PP: print(f"\t\t>> L={i} * w + R={target} -> R={target}")

                                # count outgoing edges from L to R
                                E[ptr + i] += 1
                                
                                # get right side node
                                node_r_addr = wr_offset + target
                                node_r = out_data[node_r_addr]                      # CMD RD RN
                                _le_gg_pp_list_of_rd_addr.append([target, (d-Ei)])  # [target, 1] or [target, (d-Ei)]
                                _le_pp_list_of_rd_addr.append([target, (d-Ei)])     # [itarget 1] or [target, (d-Ei)]
                                _le_pp_list_of_rd_addr_rec[0*rounds+round].append([target, (d-Ei)])     # [itarget 1] or [target, (d-Ei)]
                    
                                # sample random weight from PRNG_WEIGHT
                                weight = next(weight_it)

                                # connect weighted left side node with right side node
                                mul = node_l * weight
                                res = node_r + mul

                                # store adapted (post- processed) right side node 
                                out_data[node_r_addr] = res  # CMD WR RN
                                _le_gg_pp_list_of_wr_addr.append([target, 1])
                                _le_pp_list_of_wr_addr.append([target, 1])

                                _le_pp_list_of_rec_node_edges.append([target, 1])
                                le_pp_list_of_all_edges.append([target, 1])

                        ## patch processing reset
                        if _le_pp_patch_ctr == _PP_PATCH_SIZE_MINI:
                            # reset counter and list
                            _le_pp_patch_ctr = 0
                            _le_pp_patch_rs_ctr = 0
                            _list_of_target_addr_for_rejection_sampling = []

                    le_pp_list_of_rec_edges.append(_le_pp_list_of_rec_node_edges)
                    le_pp_list_of_rec_nodes.append(_list_of_nodes)
                    if DEBUG_OP_PP: print(f"[post-processing] end")

                    # Verifyif post processing worked
                    E_round     = E[ptr:ptr+size_L]
                    if DEBUG_OP_PP: print(f"E= {E_round}")

                    calcResemblingAmount(E=E_round, d=d, d_min=d_min, d_max=d_max, depth=depth, size_L=size_L, size_R=size_R, addr_it=pp_addr_it, weight_it=weight_it, out_data=out_data, ptr=ptr)
                    
                ROM_LE_REC_PP_PATCH_MINI_NODES.append(num_aff_nodes)
                ROM_LE_REC_PP_PATCH_MINI_EDGES.append(num_aff_edges)

                if DEBUG_OP_PP: print("######################################################################\n")

            if DEBUG_OP_GG: print("######################################################################\n")

            #######################################################################################
            # END Post- Processing
            #######################################################################################

            rd_offset += n
            wr_offset += n_new

            if DEBUG_OP_GG: print(f'>> {rd_offset=}, {wr_offset=}')

            ptr += n
            n = n_new

        if DEBUG_OP_GG: print(f'')
        if DEBUG_OP_GG: print(f'')

        # run expander L 
        E = [0 for _ in range(full_size)]
        for round in range(rounds):

            if DEBUG_OP_GG: print("######################################################################")
            if DEBUG_OP_GG: print(f'>> R-Expander: {round=}/{rounds}')
            E = [0 for _ in range(full_size)]

            n = ns.pop()

            if round == 0:
                n_new = int(alpha1 * n)
            else:
                n_new = int(rate * int(alpha1 * n))

            r = int(n * (rate - 1)) - n_new

            size_L = n_new
            size_R = r

            if DEBUG_OP_GG: print(f'[gg] n = {n}, \t L = {size_L}, \t R = {size_R}, \t ptr = {ptr}, \td = {deg2_r}')
            if DEBUG_OP_GG: print(f'>> {rd_offset=}, {wr_offset=}')

            # add offset to ROM
            ROM_LE_REC_PTR_RD.append(rd_offset)
            ROM_LE_REC_PTR_WR.append(wr_offset)

            ROM_LE_REC_GG_N_LN.append(size_L)
            ROM_LE_REC_GG_N_RN.append(size_R)

            ROM_LE_REC_GG_N_RD.append(deg2_r)
            ROM_LE_REC_GG_N_LD.append(20) 

            #######################################################################################
            # BEGIN Graph-Generation
            #######################################################################################

            _le_gg_list_of_rec_nodes = []
            _le_gg_list_of_all_edges = []
            for i in range(r):
                
                # RN -> accumulate (node_l * weight)
                res = ComplexPrimeFieldElement(0, 0)

                for j in range(deg2_r):

                    # get address of left side node from PRNG_ADDR
                    target = mymod(next(gg_addr_it), n_new)
                    addr_mod_data.append(target)
        
                    # count outgoing edges from L to R
                    E[ptr + target] += 1

                    # get left side node
                    node_l_addr = ptr + target
                    node_l      = out_data[node_l_addr]
                    _le_gg_pp_list_of_rd_addr.append([target, 1])
                    _le_gg_list_of_rd_addr.append([target, 1])

                    # sample random weight from PRNG_WEIGHT
                    weight = next(weight_it)

                    # val = out_data[ptr + target]
                    val = node_l
                    mul = val * weight
                    res = res + mul

                    _le_gg_list_of_all_edges.append([target, 1])
                    le_gg_list_of_all_edges.append([target, 1])

                    NUM_RD_GG_OPs += 1
                NUM_WR_GG_OPs += 1
                LE_GG_R_OP.append(deg2_r)

                out_data.append(res)

                _le_gg_pp_list_of_wr_addr.append([i, 1])
                _le_gg_list_of_wr_addr.append([i, 1])

                le_gg_list_of_all_nodes.append([i, deg2_r])
                _le_gg_list_of_rec_nodes.append([i, deg2_r])
                

            le_gg_list_of_rec_nodes.append(_le_gg_list_of_rec_nodes)
            le_gg_list_of_rec_edges.append(_le_gg_list_of_all_edges)

            #######################################################################################
            # END Graph-Generation
            #######################################################################################

            #######################################################################################
            # BEGIN Post- Processing
            #######################################################################################

            if DEBUG_OP_PP: print(f'[pp] n = {n}, \t L = {n_new}, \t R = {r}, \t ptr = {ptr}, \td = {deg2_r}')

            if OP_PP: 
                # E_round     = E[ptr:]
                d           = d2
                d_min       = d2_min
                d_max       = d2_max
                depth       = round+rounds
                size_L      = n_new
                size_R      = r
                # addr_it     = pp_addr_it
                weight_it   = weight_it
                out_data    = out_data
                ptr         = ptr

                E_round     = E[ptr:ptr+size_L]

                if DEBUG_OP_PP: print(f'>>> n = {n}, \t L = {n}, \t R = {n_new}, \t ptr = {ptr}, \td = {deg1_r}')
                if DEBUG_OP_PP: print(f'>>>> {PP_PATCH_SIZE_MINI=}, {d=}, {d_min=}, {d_max=}')
                if DEBUG_OP_PP: print(f'>>>> {PP_PATCH_SIZE_MINI=} * {d=} = {PP_PATCH_SIZE_MINI*d}')
                if DEBUG_OP_PP: print(f'')

                num_aff_nodes = 0
                num_aff_edges = 0

                # calculate size of patch-size-mini for post-processing
                _PP_PATCH_SIZE_MINI = PP_PATCH_SIZE_MINI
                while _PP_PATCH_SIZE_MINI > int(size_R/d):
                    if _PP_PATCH_SIZE_MINI == 0:
                        break
                    _PP_PATCH_SIZE_MINI = int(_PP_PATCH_SIZE_MINI / 2)
                ROM_LE_REC_PP_PATCH_FULL.append(size_R)
                ROM_LE_REC_PP_PATCH_MINI.append(_PP_PATCH_SIZE_MINI)
                if DEBUG_OP_PP: print(f"INFO: {_PP_PATCH_SIZE_MINI=}")

                # perform post-processing
                if _PP_PATCH_SIZE_MINI == 0:
                    if DEBUG_OP_PP: print(f"INFO: {_PP_PATCH_SIZE_MINI*d=}, {size_R=} -> skip post-processing")
                    le_pp_list_of_rec_edges.append([])
                    le_pp_list_of_rec_nodes.append([])
                elif size_R < d:
                    if DEBUG_OP_PP: print(f"INFO: {size_R=}, {d=} -> skip post-processing")
                    le_pp_list_of_rec_edges.append([])
                    le_pp_list_of_rec_nodes.append([])
                else:
                    if DEBUG_OP_PP: print(f"INFO: {size_R=}, {d=} -> start post-processing")
                    if DEBUG_OP_PP: print(f"[post-processing] begin")
                    calcResemblingAmount(E=E_round, d=d, d_min=d_min, d_max=d_max, depth=depth, size_L=size_L, size_R=size_R, addr_it=pp_addr_it, weight_it=weight_it, out_data=out_data, ptr=ptr)

                    # patch processing of left side nodes
                    _le_pp_patch_ctr = 0 # 0..._PP_PATCH_SIZE_MINI-1
                    _le_pp_patch_rs_ctr = 0 # 0...???-1

                    # store target addresses for rejection sampling
                    _list_of_target_addr_for_rejection_sampling = []

                    # resample all left side nodes that have a edge count below d_min
                    _list_of_nodes = []
                    _le_pp_list_of_rec_node_edges = []
                    if DEBUG_OP_PP: print(f"> E[{ptr}:{ptr+size_L}]")

                    # for i, Ei in enumerate(E):
                    for i, Ei in enumerate(E[ptr:ptr+size_L]): # TODO check boundries
                        if DEBUG_OP_PP: print(f">> {i=} {Ei=} / {d_min}")
                        if Ei < d:
                            if DEBUG_OP_PP: print(f"\t>> {ptr=} : L:{i} R{Ei} / {d_min} -> resample {d-Ei} times")
                            _le_pp_patch_ctr += 1
                            num_aff_nodes += 1
                            num_aff_edges += (d-Ei)

                            _list_of_nodes.append([i, d-Ei]) # node_address, node_degree, num_resamples
                            le_pp_list_of_all_nodes.append([i, d-Ei])

                            # get left side node
                            node_l_addr = ptr + i
                            node_l = out_data[node_l_addr]                  # CMD RD LN
                            _le_gg_pp_list_of_rd_addr.append([i, (d-Ei)])   # [i, 1] or [i, (d-Ei)]
                            _le_pp_list_of_rd_addr.append([i, (d-Ei)])      # [i, 1] or [i, (d-Ei)]
                            _le_pp_list_of_rd_addr_rec[1*rounds+round].append([i, (d-Ei)])      # [i, 1] or [i, (d-Ei)]

                            # store target addresses for rejection sampling
                            if _PP_PATCH_SIZE_MINI <= 1:
                              _list_of_target_addr_for_rejection_sampling = []

                            LE_PP_R_OP.append(d-Ei)
                            for _rs_edge in range(d-Ei):

                                # get address of left side node from PRNG_ADDR
                                target = mymod(next(pp_addr_it), size_R)
                                # addr_mod_data.append(target)

                                # check if target address is already in use
                                if PRNG_ADDR_REJECTION_SAMPLING:
                                    if target in _list_of_target_addr_for_rejection_sampling:
                                        while target in _list_of_target_addr_for_rejection_sampling:
                                            target = mymod(next(pp_addr_it), size_R)

                                _list_of_target_addr_for_rejection_sampling.append(target)

                                if DEBUG_OP_PP: print(f"\t\t>> L={i} * w + R={target} -> R={target}")

                                # count outgoing edges from L to R
                                E[ptr + i] += 1
                                
                                # get right side node
                                node_r_addr = wr_offset + target
                                node_r = out_data[node_r_addr]                      # CMD RD LN
                                _le_gg_pp_list_of_rd_addr.append([target, (d-Ei)])  # [i, 1] or [i, (d-Ei)]
                                _le_pp_list_of_rd_addr.append([target, (d-Ei)])     # [i, 1] or [i, (d-Ei)]
                                _le_pp_list_of_rd_addr_rec[1*rounds+round].append([target, (d-Ei)])     # [i, 1] or [i, (d-Ei)]
                                
                                # sample random weight from PRNG_WEIGHT
                                weight = next(weight_it)

                                # connect weighted left side node with right side node
                                mul = node_l * weight
                                res = node_r + mul

                                # store adapted (post- processed) right side node 
                                out_data[node_r_addr] = res  # CMD WR RN
                                _le_gg_pp_list_of_wr_addr.append([target, 1])
                                _le_pp_list_of_wr_addr.append([target, 1])

                                _le_pp_list_of_rec_node_edges.append([target, 1])
                                le_pp_list_of_all_edges.append([target, 1])
                        
                        ## patch processing reset
                        if _le_pp_patch_ctr == _PP_PATCH_SIZE_MINI:
                            # reset counter and list
                            _le_pp_patch_ctr = 0
                            _le_pp_patch_rs_ctr = 0
                            _list_of_target_addr_for_rejection_sampling = []

                    le_pp_list_of_rec_edges.append(_le_pp_list_of_rec_node_edges)
                    le_pp_list_of_rec_nodes.append(_list_of_nodes)

                    # TEST if post processing worked
                    E_round     = E[ptr:ptr+size_L]

                    # calcResemblingAmount(E=E[ptr:], d=d1, d_min=d1_min, d_max=d1_max, depth=round, size_L=n, size_R=n_new, addr_it=addr_it, weight_it=weight_it, out_data=out_data, ptr=ptr)
                    calcResemblingAmount(E=E_round, d=d, d_min=d_min, d_max=d_max, depth=depth, size_L=size_L, size_R=size_R, addr_it=pp_addr_it, weight_it=weight_it, out_data=out_data, ptr=ptr)

                ROM_LE_REC_PP_PATCH_MINI_NODES.append(num_aff_nodes)
                ROM_LE_REC_PP_PATCH_MINI_EDGES.append(num_aff_edges)

            
            #######################################################################################
            # END Post- Processing
            #######################################################################################

            rd_offset -= n
            wr_offset += r
            ptr -= n


        for i, v in enumerate(out_data):
            out_data_full[i * interleaves + inter] = v
        print("")


    ##################################################################
    # Calculate Latency of FPGA
    ##################################################################

    # print(f'LE_GG_L_OP : {len(LE_GG_L_OP)}')
    # print(f'LE_GG_R_OP : {len(LE_GG_R_OP)}')
    # print(f'LE_PP_L_OP : {len(LE_PP_L_OP)}')
    # print(f'LE_PP_R_OP : {len(LE_PP_R_OP)}')
    # print(f'')

    # print(f'{LE_GG_L_OP=}')
    # print(f'{LE_GG_R_OP=}')
    # print(f'{LE_PP_L_OP=}')
    # print(f'{LE_PP_R_OP=}')
    # print(f'')

    latency_gg = 0
    latency_gg_l = 0
    latency_gg_r = 0

    latency_pp = 0
    latency_pp_l = 0
    latency_pp_r = 0

    LATENCY_GG_L = 1680 # 40*42 -> 40*deg1_r
    LATENCY_GG_R = 1040 # 40*26 -> 40*deg2_r

    for _ in LE_GG_L_OP:
        if _ == deg1_r:
            latency_gg_l += LATENCY_GG_L
        else:
            assert False, f"node degree invalid"

    for _ in LE_GG_R_OP:
        if _ == deg2_r:
            latency_gg_r += LATENCY_GG_R
        else:
            assert False, f"node degree invalid"

    latency_gg = latency_gg_l + latency_gg_r
    print(f'latency_gg_l : {latency_gg_l}')
    print(f'latency_gg_r : {latency_gg_r}')
    print(f'latency_gg   : {latency_gg}')
    print(f'')    

    ######################################################################

    print(f'{ROM_LE_REC_PP_PATCH_MINI_NODES=}')
    print(f'{ROM_LE_REC_PP_PATCH_MINI_EDGES=}')

    #                  0  1    2    3    4    5    6    7     8     9     10    11    12    13    14    15    16    17    18 
    # latency_gg_rs = [0, 510, 600, 690, 780, 870, 960, 1050, 1140, 1230, 1320, 1410, 1500, 1590, 1680, 1770, 1860, 1950, 2040]

    latency_gg_rs_init = 290
    latency_gg_rs_calc = [ ((_-1)*40)+160 for _ in range(0, PP_PATCH_SIZE_MINI*deg2_r) ]
    latency_gg_rs_wait = [ 240+(_*50) for _ in range(0, PP_PATCH_SIZE_MINI*deg2_r) ]

    LE_PP_OP = LE_PP_L_OP + LE_PP_R_OP

    addr_offset = 0
    for _rec_nodes, _rec_patch_mini_size in zip(ROM_LE_REC_PP_PATCH_MINI_NODES, ROM_LE_REC_PP_PATCH_MINI):

        # get list of affected nodes for each recursion recursion data 
        REC_LE_PP_OP = LE_PP_OP[addr_offset:addr_offset+_rec_nodes]

        if _rec_patch_mini_size != 0:
            for i in range(0, len(REC_LE_PP_OP), _rec_patch_mini_size):
                _patch_mini_nodes = _rec_patch_mini_size
                _patch_mini_edges = sum(REC_LE_PP_OP[i:i+_rec_patch_mini_size])
                _patch_mini_load  = _patch_mini_edges + _rec_patch_mini_size
                _patch_mini_store = _patch_mini_edges

                # calculate patch size latency
                _patch_mini_calc = latency_gg_rs_calc[_patch_mini_load]
                _patch_mini_wait = latency_gg_rs_wait[_patch_mini_store]
                _patch_mini_latency = _patch_mini_calc + _patch_mini_wait

                # sum up latency
                latency_pp += _patch_mini_latency

        # increment address offset for next recursion
        addr_offset += _rec_nodes

    print(f'latency_pp   : {latency_pp}')
    print(f'')

    ######################################################################

    latency_graph_gen = latency_gg + latency_pp
    print(f'latency_gg  : {latency_gg}')
    print(f'latency_pp  : {latency_pp}')
    print(f'latency     : {latency_graph_gen}')

    print(f'latency overhead of pp vs gg: {(latency_pp / latency_gg)*100:.2f} %')
    print(f'')

    ##################################################################
    # Generate ROM for recursion pointers
    ##################################################################

    print(f'')
    print(f'>> ROM_LE_REC_PTR_RD : {len(ROM_LE_REC_PTR_RD)} : {ROM_LE_REC_PTR_RD}')
    print(f'>> ROM_LE_REC_PTR_WR : {len(ROM_LE_REC_PTR_WR)} : {ROM_LE_REC_PTR_WR}') 
    print(f'')

    f = open(f"mem/le_rec_ptr_rd.mem", "w")
    for _ in ROM_LE_REC_PTR_RD:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_rec_ptr_wr.mem", "w")
    for _ in ROM_LE_REC_PTR_WR:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    # graph generation info

    print(f'')
    print(f'>> ROM_LE_REC_GG_N_LN : {len(ROM_LE_REC_GG_N_LN)} : {ROM_LE_REC_GG_N_LN}') 
    print(f'>> ROM_LE_REC_GG_N_RN : {len(ROM_LE_REC_GG_N_RN)} : {ROM_LE_REC_GG_N_RN}')
    print(f'')

    f = open(f"mem/le_rec_gg_n_ln.mem", "w")
    for _ in ROM_LE_REC_GG_N_LN:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_rec_gg_n_rn.mem", "w")
    for _ in ROM_LE_REC_GG_N_RN:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    # post-processing info 

    print(f'')
    print(f'>> ROM_LE_REC_GG_N_LD : {len(ROM_LE_REC_GG_N_LD)} : {ROM_LE_REC_GG_N_LD}')
    print(f'>> ROM_LE_REC_GG_N_RD : {len(ROM_LE_REC_GG_N_RD)} : {ROM_LE_REC_GG_N_RD}') 
    print(f'')

    f = open(f"mem/le_rec_gg_n_ld.mem", "w")
    for _ in ROM_LE_REC_GG_N_LD:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_rec_gg_n_rd.mem", "w")
    for _ in ROM_LE_REC_GG_N_RD:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    # patch processing info

    print(f'')
    print(f'>> ROM_LE_REC_PP_PATCH_FULL : {len(ROM_LE_REC_PP_PATCH_FULL)} : {ROM_LE_REC_PP_PATCH_FULL}')
    print(f'>> ROM_LE_REC_PP_PATCH_MINI : {len(ROM_LE_REC_PP_PATCH_MINI)} : {ROM_LE_REC_PP_PATCH_MINI}') 
    print(f'')

    f = open(f"mem/le_rec_pp_patch_full.mem", "w")
    for _ in ROM_LE_REC_PP_PATCH_FULL:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_rec_pp_patch_mini.mem", "w")
    for _ in ROM_LE_REC_PP_PATCH_MINI:
        hex_str = "{:08x}".format(_) + "\n"
        f.write(hex_str)

    ##################################################################
    # Read Address that are stored in DDR memory
    ##################################################################

    # create memory file for read addresses

    f = open(f"mem/le_gg_pp_addr_rd.mem", "w")
    for _node in _le_gg_pp_list_of_rd_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)


    f = open(f"mem/le_gg_addr_rd.mem", "w")
    for _node in _le_gg_list_of_rd_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)


    f = open(f"mem/le_pp_addr_rd.mem", "w")
    for _node in _le_pp_list_of_rd_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    # prepose DDR0 content: random vector (K coefs), post-processing addresses
    f = open(f"mem/le_ddr_0_i.mem", "w")
    for _ in range(2*2**lg_k):
        hex_str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n" # 256bit
        f.write(hex_str)

    # post-processing addressed are 4KB aligned to avoid axi burst read issues
    _addr_offset = 0
    for _rec in _le_pp_list_of_rd_addr_rec:
        # Align _addr_offset to next multiple of DDR_NUM_BURST_WORDS
        if _addr_offset % DDR_NUM_BURST_WORDS != 0:
            pad = DDR_NUM_BURST_WORDS - (_addr_offset % DDR_NUM_BURST_WORDS)
            for _ in range(pad):
                f.write("00000000\n")
            _addr_offset += pad
        for _node in _rec:
            hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
            f.write(hex_str)
            _addr_offset += 1

    # create memory file for write addresses

    f = open(f"mem/le_gg_pp_addr_wr.mem", "w")
    for _node in _le_gg_pp_list_of_wr_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_gg_addr_wr.mem", "w")
    for _node in _le_gg_list_of_wr_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    f = open(f"mem/le_pp_addr_wr.mem", "w")
    for _node in _le_pp_list_of_wr_addr:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)
    
    ##################################################################
    # Graph generation
    ##################################################################

    fname = f"mem/le_hbm_{HBM_CTR:02}"
    with open(fname + f"_i.mem", 'w') as f:
        i = 0
        hex_str = ""
        for elem in in_data_full:
            hex_str = f'{elem.img:016x}{elem.real:016x}' + hex_str
            if i == interleaves-1:
                i = 0
                f.write(hex_str + "\n")
                hex_str = ""
            else:
               i += 1

    with open(fname + f"_o.mem", 'w') as f:
        i = 0
        hex_str = ""
        for elem in out_data_full:
            hex_str = f'{elem.img:016x}{elem.real:016x}' + hex_str
            if i == interleaves-1:
                i = 0
                f.write(hex_str + "\n")
                hex_str = ""
            else:
               i += 1

    with open(f"mem/le_prng_addr.mem", 'w') as f:
        for elem in addr_data_full:
            f.write(f'{elem:016x}\n')
    with open(f"mem/le_prng_addr_mod.mem", 'w') as f:
        for elem in addr_mod_data:
            f.write(f'{elem:016x}\n')

    with open(f"mem/le_prng_weights.mem", 'w') as f:
        for elem in weight_data_full:
            f.write(f'{elem.img:016x}{elem.real:016x}\n')

    ##################################################################
    # Post Processing
    ##################################################################

    # create memory file 
    f = open(f"mem/le_gg_all_nodes.mem", "w")
    for _node in le_gg_list_of_all_nodes:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    # create memory file
    f = open(f"mem/le_gg_rec_nodes.mem", "w")
    for _list_of_nodes in le_gg_list_of_rec_nodes: # [0:rounds*2]:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:08x}".format(len(_list_of_nodes)) + "\n"
        f.write(hex_str)

    # create memory file 
    f = open(f"mem/le_gg_all_edges.mem", "w")
    for _node in le_gg_list_of_all_edges:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    # create memory file
    f = open(f"mem/le_gg_rec_edges.mem", "w")
    for _list_of_nodes in le_gg_list_of_rec_edges: # [0:rounds*2]:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:08x}".format(len(_list_of_nodes)) + "\n"
        f.write(hex_str)

    # create memory file 
    f = open(f"mem/le_pp_all_nodes.mem", "w")
    for _node in le_pp_list_of_all_nodes:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    # create memory file
    f = open(f"mem/le_pp_rec_nodes.mem", "w")
    for _list_of_nodes in le_pp_list_of_rec_nodes[0:rounds*2]:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:08x}".format(len(_list_of_nodes)) + "\n"
        f.write(hex_str)

    # create memory file 
    f = open(f"mem/le_pp_all_edges.mem", "w")
    for _node in le_pp_list_of_all_edges:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:06x}".format(_node[0]) + "{:02x}".format(_node[1]) + "\n"
        f.write(hex_str)

    # create memory file
    f = open(f"mem/le_pp_rec_edges.mem", "w")
    for _list_of_nodes in le_pp_list_of_rec_edges[0:rounds*2]:
        # 32bit -> 24bit and 8bit - 8 hex -> 6 hex 2 hex
        hex_str = "{:08x}".format(len(_list_of_nodes)) + "\n"
        f.write(hex_str)

    ##################################################################
    # Create SV-PKG file
    ##################################################################

    HEX_PRNG_SEED_ADDR_GG = "64'h{:016x}".format(PRNG_SEED_ADDR_GG)
    HEX_PRNG_SEED_ADDR_PP = "64'h{:016x}".format(PRNG_SEED_ADDR_PP)
    HEX_PRNG_SEED_WEIGHT  = "64'h{:016x}".format(PRNG_SEED_WEIGHT )

    # # create memory file
    # file_data = f""
    # file_data += f"//////////////////////////////////////////////////////////////////////////////////\n"
    # file_data += f"// Company: Institute of Information Security, Graz Universtiy of Technology\n"
    # file_data += f"// Engineer: Florian Hirner and Florian Krieger\n"
    # file_data += f"//////////////////////////////////////////////////////////////////////////////////\n"
    # file_data += f"\n"
    # file_data += f"`timescale 1ns / 1ps\n"
    # file_data += f"\n"
    # file_data += f"// Defines parameters, types and conversion functions for your cipher.\n"
    # file_data += f"\n"
    # file_data += f"package linear_encoder_pkg;\n"
    # file_data += f"\n"
    # file_data += f"//---------------------------------------------------------------------------------------\n"
    # file_data += f"// Linear Encoding\n"
    # file_data += f"// - Recursion\n"
    # file_data += f"//   - Graph Generation\n"
    # file_data += f"//   - Post Processing\n"
    # file_data += f"//---------------------------------------------------------------------------------------\n"
    # file_data += f"\n"
    # file_data += f"\n"
    # file_data += f"localparam int PRNG_SEED_ADDR_GG = {HEX_PRNG_SEED_ADDR_GG};\n"
    # file_data += f"localparam int PRNG_SEED_ADDR_PP = {HEX_PRNG_SEED_ADDR_PP};\n"
    # file_data += f"localparam int PRNG_SEED_WEIGHT  = {HEX_PRNG_SEED_WEIGHT};\n"
    # file_data += f"\n"
    # file_data += f"localparam int lg_k = {lg_k};\n"
    # file_data += f"localparam int lg_d = {lg_d};\n"
    # file_data += f"localparam int lg_n = lg_k + lg_d;\n"
    # file_data += f"\n"
    # file_data += f"// - Recursion\n"
    # file_data += f"\n"
    # file_data += f"localparam int LE_N_RECURSIONS = \n"
    # file_data += f"  (lg_d==7 ) ?  2 * 2: // N=14\n"
    # file_data += f"  (lg_d==8 ) ?  3 * 2: // N=15\n"
    # file_data += f"  (lg_d==9 ) ?  3 * 2: // N=16\n"
    # file_data += f"  (lg_d==10) ?  3 * 2: // N=17\n"
    # file_data += f"  (lg_d==11) ?  4 * 2: // N=18\n"
    # file_data += f"  (lg_d==12) ?  4 * 2: // N=19\n"
    # file_data += f"  (lg_d==13) ?  5 * 2: // N=20\n"
    # file_data += f"  (lg_d==14) ?  5 * 2: // N=21\n"
    # file_data += f"  (lg_d==15) ?  6 * 2: // N=22\n"
    # file_data += f"  (lg_d==16) ?  6 * 2: // N=23\n"
    # file_data += f"  (lg_d==17) ?  7 * 2: // N=24\n"
    # file_data += f"  (lg_d==18) ?  7 * 2: // N=25\n"
    # file_data += f"  (lg_d==19) ?  8 * 2: // N=26\n"
    # file_data += f"  (lg_d==20) ?  8 * 2: // N=27\n"
    # file_data += f"  (lg_d==21) ?  9 * 2: // N=28\n"
    # file_data += f"  (lg_d==22) ? 10 * 2: // N=29\n"
    # file_data += f"  (lg_d==23) ? 10 * 2: // N=30\n"
    # file_data += f"                0;\n"
    # file_data += f"\n"
    # file_data += f"//   - Graph Generation\n"
    # file_data += f"\n"
    # file_data += f"localparam int LE_GG_N_ALL_NODES  = {int(len(le_gg_list_of_all_nodes)/interleaves)};\n"
    # file_data += f"localparam int LE_GG_N_ALL_EDGES  = {int(len(le_gg_list_of_all_edges)/interleaves)};\n"
    # file_data += f"\n"
    # file_data += f"//   - Post Processing\n"
    # file_data += f"\n"
    # file_data += f"localparam int LE_PP_N_ALL_NODES  = {int(len(le_pp_list_of_all_nodes)/interleaves)}; \n"
    # file_data += f"localparam int LE_PP_N_ALL_EDGES  = {int(len(le_pp_list_of_all_edges)/interleaves)};\n"
    # file_data += f"\n"
    # file_data += f"//\n"
    # file_data += f"\n"
    # file_data += f"// Graph Generation\n"
    # file_data += f"parameter int ROM_N_LE_GG_ADDR_RD = {int(len(le_gg_list_of_all_edges)/interleaves)};\n"
    # file_data += f"parameter int ROM_N_LE_GG_ADDR_WR = {int(len(le_gg_list_of_all_nodes)/interleaves)};\n"
    # file_data += f"\n"
    # file_data += f"// Post Processing\n"
    # file_data += f"parameter int ROM_N_LE_PP_ADDR    = {int(len(le_pp_list_of_all_edges)/interleaves)} + {int(len(le_pp_list_of_all_nodes)/interleaves)};\n"
    # file_data += f"parameter int ROM_N_LE_PP_ADDR_RD = {int(len(le_pp_list_of_all_edges)/interleaves)} + {int(len(le_pp_list_of_all_nodes)/interleaves)};\n"
    # file_data += f"parameter int ROM_N_LE_PP_ADDR_WR = {int(len(le_pp_list_of_all_edges)/interleaves)};\n"
    # file_data += f"\n"
    # file_data += f"parameter int ROM_N_LE_ADDR_RD    = ROM_N_LE_GG_ADDR_RD + ROM_N_LE_PP_ADDR_RD;\n"
    # file_data += f"parameter int ROM_N_LE_ADDR_WR    = ROM_N_LE_GG_ADDR_WR + ROM_N_LE_PP_ADDR_WR;\n"
    # file_data += f"\n"
    # file_data += f"// Issue post processing as patches to avoid axi4 wait error\n"
    # file_data += f"// {ROM_LE_REC_PP_PATCH_MINI_NODES=}\n"
    # file_data += f"// {ROM_LE_REC_PP_PATCH_MINI_EDGES=}\n"
    # file_data += f"\n"
    # file_data += f"localparam logic [31:0] ROM_LE_REC_PP_PATCH_RD_ALEN [0:{len(ROM_LE_REC_PP_PATCH_MINI_NODES)}] = '{{\n"
    # addr_offset = 0
    # for idx, (_rec_nodes, _rec_edges) in enumerate(zip(ROM_LE_REC_PP_PATCH_MINI_NODES, ROM_LE_REC_PP_PATCH_MINI_EDGES)):
    #     _addr_offset = (_rec_nodes + _rec_nodes)
    #     file_data += f"  32'h{_rec_edges:08x} + 32'h{_rec_nodes:08x}, // {_rec_edges} + {_rec_nodes} = {_rec_edges+_rec_nodes}; {_addr_offset=}\n"
    #     addr_offset += _addr_offset
    # file_data += f"  32'h0\n}};\n"
    # file_data += f"\n"
    # file_data += f"localparam logic [31:0] ROM_LE_REC_PP_PATCH_RD_OFFSET [0:{len(ROM_LE_REC_PP_PATCH_MINI_NODES)}] = '{{\n"
    # addr_total = 0
    # addr_offset = 0
    # for idx, (_rec_nodes, _rec_edges) in enumerate(zip(ROM_LE_REC_PP_PATCH_MINI_NODES, ROM_LE_REC_PP_PATCH_MINI_EDGES)):
    #     _addr_offset = (_rec_nodes + _rec_edges)
    #     # Align addr_offset to next multiple of DDR_NUM_BURST_WORDS
    #     if addr_offset % DDR_NUM_BURST_WORDS != 0:
    #         addr_offset = ((addr_offset // DDR_NUM_BURST_WORDS) + 1) * DDR_NUM_BURST_WORDS
    #     file_data += f"  32'h{addr_offset:08x}, // {addr_offset} + {_addr_offset} = {addr_offset+_addr_offset}\n"
    #     addr_total = addr_offset + _addr_offset
    #     addr_offset += _addr_offset
    # file_data += f"  32'h0\n}};\n"
    # file_data += f"\n"
    # file_data += f"parameter int ROM_N_LE_PP_ADDR_RD_4KB_ALIGNED = {addr_total};\n"
    # file_data += f"\n"
    # file_data += f"endpackage\n"

    # f = open(PATH_PKG_FILES + f"linear_encoder_pkg.sv", "w")
    # f.write(file_data)

    print(f'')
    print(f'[getEdgeInformations] end')
    print(f'')

    return E, len(_le_gg_pp_list_of_rd_addr), len(_le_gg_pp_list_of_wr_addr)

###############################################################################
# main
###############################################################################

import sys

if __name__ == "__main__":

    # total arguments
    n_argv = len(sys.argv)
    print("Total arguments passed:", n_argv)
    if n_argv != 7+1:
        print("[ERROR] Usage: python3 enode.py <d:[7...23]> <d1> <d2> <d1_min> <d2_min>  <pp_patch_size_mini>")
        print("[ERROR] - d                  : [7...23]")
        print("[ERROR] - d1                 : 42")
        print("[ERROR] - d2                 : 26")
        print("[ERROR] - d1_min             : 8")
        print("[ERROR] - d2_min             : 18")
        print("[ERROR] - pp_patch_size_mini : [1...2^x]")
        print("[ERROR] - hbm_ctr : 0...32")
        exit(-1)

    trivium64_0_setseed(PRNG_SEED_ADDR_GG, 0) # std = 0
    trivium64_1_setseed(PRNG_SEED_ADDR_PP, 0) # std = 0
    trivium64_2_setseed(PRNG_SEED_WEIGHT , 0) # std = 0

    HBM_CTR = int(sys.argv[7])

    lg_k = 7
    lg_d = int(sys.argv[1])
    lg_n = lg_k + lg_d

    if lg_d < 4 or lg_d > 23:
        print("[ERROR] d must be between 7 and 23")
        exit()

    print(f"{lg_k=}")
    print(f"{lg_d=}")
    print(f"{lg_n=}")
    print("")
  
    DEG1 = int(sys.argv[2])
    DEG2 = int(sys.argv[3])
    D1_MIN = int(sys.argv[4])
    D2_MIN = int(sys.argv[5])
    PP_PATCH_SIZE_MINI = int(sys.argv[6])

    print(f"{DEG1=}")
    print(f"{DEG2=}")
    print(f"{D1_MIN=}")
    print(f"{D2_MIN=}")
    print("")

    inf     = "ref_data/in_full.mem"
    out     = "ref_data/out_full.mem"
    rnd     = "ref_data/weights_full.mem"
    loc     = "ref_data/locs_full.mem"
    addr_mod = "ref_data/locs_mod_full.mem"

    # k = 7
    # d = 20
    # n = k + d

    size        = 2**lg_d   # 128, 566, ...
    rounds      = 2     # 128=2; 256=3 # enc_depth
    deg         = 0     # not used
    weight_size = 0     # 128=(30�42+7�42+14�26+71�26)=3764; 256=(60�42+14�42+3�46+7�8+19�25+81�25)=5802
    full_size   = 0     # 206
    alpha1      = 0.238
    rate        = 1.72
    interleaves = 4     # num_pe
    deg1_r      = DEG1
    deg2_r      = DEG2
    rounds      = 2
    
    if lg_d == 4 : rounds = 1     # N=11 
    if lg_d == 5 : rounds = 1     # N=12 
    if lg_d == 6 : rounds = 2     # N=13 
    if lg_d == 7 : rounds = 2     # N=14
    if lg_d == 8 : rounds = 3     # N=15
    if lg_d == 9 : rounds = 3     # N=16
    if lg_d == 10: rounds = 3     # N=17
    if lg_d == 11: rounds = 4     # N=18
    if lg_d == 12: rounds = 4     # N=19
    if lg_d == 13: rounds = 5     # N=20
    if lg_d == 14: rounds = 5     # N=21
    if lg_d == 15: rounds = 6     # N=22
    if lg_d == 16: rounds = 6     # N=23
    if lg_d == 17: rounds = 7     # N=24
    if lg_d == 18: rounds = 7     # N=25
    if lg_d == 19: rounds = 8     # N=26
    if lg_d == 20: rounds = 8     # N=27
    if lg_d == 21: rounds = 9     # N=28

    print(f'{size=} {rounds=}')

    size, full_size, weight_size = getRecursionInformations(size, rounds, alpha1, rate, deg1_r, deg2_r)

    OP_PP = True
    E, INV_R2L_GP_NUM_OP_RD, INV_R2L_GP_NUM_OP_WR = getEdgeInformations(size, full_size, weight_size, rounds, alpha1, rate, deg1_r, deg2_r, interleaves)

    # print("Copying .mem files to rtl folder...")
    # for _ in ["le_rec_ptr_rd.mem", "le_rec_ptr_wr.mem", "le_rec_gg_n_ln.mem", "le_rec_gg_n_rn.mem", "le_rec_gg_n_ld.mem",
    #           "le_rec_gg_n_rd.mem", "le_rec_pp_patch_mini.mem", "le_gg_rec_nodes.mem", "le_pp_rec_nodes.mem"]:
    #   src = "./mem/" + _
    #   dst = PATH_MEM_FILES + _
      
    #   shutil.copyfile(src=src, dst=dst)

    print(f'\n\n')
    print(f'------------------------------------------------------------')
    print("Done")
    print(f'------------------------------------------------------------')
    print(f'\n\n')
