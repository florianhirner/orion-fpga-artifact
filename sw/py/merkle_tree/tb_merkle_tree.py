##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import os
import sys
import math
import random
import hashlib 
import shutil

from prove_leafs import hashSingleFieldElem, leafNodeHashing_CheckAgainstOrion

import sys
sys.path.insert(1, '../linear_encoder/')

from primefield import FieldElement

from ssl import RAND_bytes

###############################################################################
# DEBUG Flags
###############################################################################

# Commit to Message
DEBUG_MERKEL_HASH = False
DEBUG_MERKEL_TREE = False

###############################################################################
# Global Parameters
###############################################################################

# PATH_MEM_FILES = "../../../hw/rtl/memory_content/mem/"
PATH_MEM_FILES = "../../../hw/mem/"

N_HBM_PC            = 32

k           = 7
n           = 17
N           = math.pow(2, n)
NUM_COEFS   = N

NUM_ROWS    = int(math.pow(2, k))   # FIXED -> 2^7=128  
NUM_COLS    = int(N // NUM_ROWS)

COEF_SIZE   = 128
COL_SIZE    = COEF_SIZE * NUM_ROWS

col_bytes = COL_SIZE // 8
col_bytes = col_bytes


################################
## helper
################################

def reverse_hex_string(hex_string):
    # Ensure the string has an even length
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length should be even.")

    # Split into bytes and reverse
    reversed_bytes = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)][::-1]

    # Join the reversed bytes back into a string
    reversed_hex = ''.join(reversed_bytes)
    return reversed_hex


###############################################################################
# Merkle-Hash  function
###############################################################################

def merkle_hash(matrix: list) -> list:
    print(f"[INFO] Start Merkle-Hash with SHA3-256:")
    print(f"\t{NUM_ROWS=}")
    print(f"\t{NUM_COLS=}")

    # encode-matrix     col[0]  col[1]  col[2]  col[3]
    # row[0]            00      10      20      30
    # row[1]            01      11      21      31
    # row[2]            02      12      22      32
    # row[3]            03      13      23      33

    merkle_hash = []

    # iterate through colums of encoder matrix
    # for _ in range(NUM_ROWS):
    for _ in range(NUM_COLS):
        if DEBUG_MERKEL_HASH: print(f"> hash column[{_}]")

        col = matrix[_]
        # print(f"hex(col) in hex  : {col.hex()}") 
        # print(f"len(col) in bytes: {len(col.hex())//2}")
        # print(f"len(col) in bits : {len(col.hex())//2*8}") 
        # print(f"")

        # Using hashlib.sha3_256() method 
        gfg = hashlib.sha3_256() 
        gfg.update(col) 
        digest = gfg.digest()
        # print(f"hex(digest) in hex  : {digest.hex()}") 
        # print(f"len(digest) in bytes: {len(digest.hex())}")
        # print(f"len(digest) in bits : {len(digest.hex())*8}") 
        # print(f"")

        if DEBUG_MERKEL_HASH: print(f"  = digest: {digest.hex()}") 

        merkle_hash.append(digest)


    # for _i, _hash in enumerate(merkle_hash):
    #     print(f"merkle_hash[{_i}] : hex(_hash) in hex  : {digest.hex()}") 
    #     print(f"merkle_hash[{_i}] : len(_hash) in bytes: {len(digest.hex())//2}")
    #     print(f"merkle_hash[{_i}] : len(_hash) in bits : {len(digest.hex())//2*8}") 
    #     print(f"")

    print(f"[INFO] Finish Merkle-Hash with SHA3-256")
    print(f"")
    
    return merkle_hash

###############################################################################
# Merkle-Tree function
###############################################################################

def merkle_tree(merkle_hash: list) -> list:
    print(f"[INFO] Start Merkle-Tree with SHA3-256")
    print(f"\t#leafs: {len(merkle_hash)}")
    print(f"\t#depth: {int(math.log2(len(merkle_hash)))}")
    # print(f"\t#nodes: {int((len(merkle_hash)*(len(merkle_hash)+1))/2)}")
    print(f"\t#nodes: {int(len(merkle_hash)+(len(merkle_hash)-1))}")

    merkle_tree = []
    merkle_tree.append(merkle_hash)

    merkle_tree_iter = 0
    num_nodes = len(merkle_tree[merkle_tree_iter])
    if DEBUG_MERKEL_TREE: print(f"- merkle_hash has {num_nodes=}")
    if DEBUG_MERKEL_TREE: print(f"")

    while len(merkle_tree[merkle_tree_iter]) != 1:
        if DEBUG_MERKEL_TREE: print(f"> {merkle_tree_iter=}:")

        # hash nodes to generate new layer
        _nodes = merkle_tree[merkle_tree_iter]
        _num_nodes = len(_nodes)
        _num_digest = _num_nodes//2
        _nodes_digest = []

        for _i in range(0, _num_nodes, 2):
            _combined_nodes = _nodes[_i] + _nodes[_i+1]
            if DEBUG_MERKEL_TREE: print(f"hex(_nodes[_i]) in hex      : {_nodes[_i].hex()}") 
            if DEBUG_MERKEL_TREE: print(f"hex(_nodes[_i+1]) in hex    : {_nodes[_i+1].hex()}") 
            if DEBUG_MERKEL_TREE: print(f"hex(_combined_nodes) in hex  : {_combined_nodes.hex()}") 
            if DEBUG_MERKEL_TREE: print(f"len(_combined_nodes) in bytes: {len(_combined_nodes.hex())//2}")
            if DEBUG_MERKEL_TREE: print(f"len(_combined_nodes) in bits : {len(_combined_nodes.hex())//2*8}") 

            _gfg = hashlib.sha3_256() 
            _gfg.update(_combined_nodes) 
            _digest = _gfg.digest()
            if DEBUG_MERKEL_TREE: print(f"hex(_digest) in hex  : {_digest.hex()}") 
            if DEBUG_MERKEL_TREE: print(f"len(_digest) in bytes: {len(_digest.hex())//2}")
            if DEBUG_MERKEL_TREE: print(f"len(_digest) in bits : {len(_digest.hex())//2*8}") 
            if DEBUG_MERKEL_TREE: print(f"")

            _nodes_digest.append(_digest)


        if DEBUG_MERKEL_TREE: print(f"> _num_nodes    = {_num_nodes}")
        if DEBUG_MERKEL_TREE: print(f"> _num_digest   = {_num_digest}")
        if DEBUG_MERKEL_TREE: print(f"> _nodes_digest = {len(_nodes_digest)}")

        merkle_tree.append(_nodes_digest)
        merkle_tree_iter += 1
        if DEBUG_MERKEL_TREE: print(f"")

    # print tree for debug purpose
    # for _i, _merkle_tree_level in enumerate(merkle_hash):
    #     print(f"merkle_tree[{_i}] : hex(_hash) in hex  : {digest.hex()}") 
    #     for _j, _hash in enumerate(_merkle_tree_level):
    #         print(f"merkle_hash[{_i}] : hex(_hash) in hex  : {digest.hex()}") 
    #         print(f"merkle_hash[{_i}] : len(_hash) in bytes: {len(digest.hex())//2}")
    #         print(f"merkle_hash[{_i}] : len(_hash) in bits : {len(digest.hex())//2*8}") 
    #         print(f"")

    print(f"[INFO] Finish Merkle-Tree with SHA3-256")
    print(f"")

    return merkle_tree


def compareToOrionSW():
    log_size = 8+1

    ref_mt = [[] for _ in range(log_size)]
    with open("./orion_merkle_tree.txt","r") as f:
        f.readline() # first line is 0

        for level in range(log_size):
            for node in range(2**level):
                h = int(f.readline(),16)
                ref_mt[len(ref_mt)-1-level] += [bytearray(int.to_bytes(h,32,'little'))]

    
    leaf_hashes = ref_mt[0]
    tree = merkle_tree(leaf_hashes)

    for l in range(log_size):
        for i in range(len(ref_mt[l])):
            assert tree[l][i] == ref_mt[l][i]
    print("comparison to Orion Software passed!")


###############################################################################
# Main funtion
###############################################################################

if __name__ == '__main__':
    q = 2**61-1

    ########################################
    # Comparison to Orion SW:
    compareToOrionSW()
    leafNodeHashing_CheckAgainstOrion()
    ########################################

    random.seed(9876)

    matrix = []
    matrix_ba = []

    ########################################
    # Read the encoded matrix from files
    ########################################
    lines = [None for _ in range(NUM_ROWS//4)]
    for _ in range(NUM_ROWS//4):
      with open(f"../linear_encoder/mem/le_hbm_{_:02}_o.mem", "r") as f:
        lines[_] = f.readlines()

    it = 0
    for line_it in range(len(lines[0])):
      _col = [0]*NUM_ROWS
      _col_ba = bytearray()
      for _ in range(NUM_ROWS//4):
        elem = int(lines[_][line_it], 16)
        r0 = (elem >> (0*128)) % 2**128
        r1 = (elem >> (1*128)) % 2**128
        r2 = (elem >> (2*128)) % 2**128
        r3 = (elem >> (3*128)) % 2**128
        _col[_*4 + 0] = r0
        _col_ba += bytearray([(r0 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 1] = r1
        _col_ba += bytearray([(r1 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 2] = r2
        _col_ba += bytearray([(r2 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 3] = r3
        _col_ba += bytearray([(r3 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
      
      it += 1
      matrix.append(_col)
      matrix_ba.append(_col_ba)

    ########################################
    # Zero-pad the encoded matrix to power-of-two row length
    ########################################
    it_tmp = it
    for _ in range(it_tmp, 2**int(math.ceil(math.log2(it_tmp)))):
      _col = [0]*NUM_ROWS
      _col_ba = bytearray()
      r0 = 0
      r1 = 0
      r2 = 0
      r3 = 0
      for _ in range(NUM_ROWS//4):
        _col[_*4 + 0] = r0
        _col_ba += bytearray([(r0 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 1] = r1
        _col_ba += bytearray([(r1 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 2] = r2
        _col_ba += bytearray([(r2 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
        _col[_*4 + 3] = r3
        _col_ba += bytearray([(r3 >> _) % (2**8) for _ in range(0,COEF_SIZE,8)])
      
      it += 1
      matrix.append(_col)
      matrix_ba.append(_col_ba)

      NUM_COLS = it


    print(f"[INFO] #row: {len(matrix)}")
    print(f"[INFO] #col: {len(matrix[0])}")


    encoded_matrix = matrix
    encoded_matrix_ba = matrix_ba

    ########################################
    # Write the zero-padded matrix to file
    # choose random verifier challenge
    ########################################

    v_challenge_0 = [None]*NUM_ROWS
    v_challenge_1 = [None]*NUM_ROWS
    for pc_i in range(N_HBM_PC):
      str_pc_i = str(pc_i).zfill(2)
      q = 2**61-1
      f = open(f"mem/hbm_mt_din_{str_pc_i}.mem", "w")
      for i in range(NUM_COLS):
          data = ""
          col = encoded_matrix_ba[i]
          for _ in range(4*COEF_SIZE//8):
            # print(_+pc_i*4*COEF_SIZE//8, pc_i, _)
            fe = col[_+pc_i*4*COEF_SIZE//8]
            data += "{:02x}".format(fe)
          hex_str = reverse_hex_string(data)+"\n"

          f.write(hex_str)
          if i == 0: # TODO: FIX THIS: TAKE RANDOM VALUES AND PUT IT TO END OF HBM memory
             val = int(hex_str, 16)
             v_challenge_0[0+4*pc_i] = (val >> 0*128) % 2**128
             v_challenge_0[1+4*pc_i] = (val >> 1*128) % 2**128
             v_challenge_0[2+4*pc_i] = (val >> 2*128) % 2**128
             v_challenge_0[3+4*pc_i] = (val >> 3*128) % 2**128
          if i == 1:
             val = int(hex_str, 16)
             v_challenge_1[0+4*pc_i] = (val >> 0*128) % 2**128
             v_challenge_1[1+4*pc_i] = (val >> 1*128) % 2**128
             v_challenge_1[2+4*pc_i] = (val >> 2*128) % 2**128
             v_challenge_1[3+4*pc_i] = (val >> 3*128) % 2**128
             
      f.close()

    ########################################
    # Compute the column hashes
    ########################################

    hash = merkle_hash(matrix=encoded_matrix_ba)

    ########################################
    # Compute Merkle Tree
    ########################################

    tree = merkle_tree(merkle_hash=hash)

    file_path = "mem/merkle_tree_data.mem"
    if os.path.exists(file_path):
        f = open(file_path, "w")
    else:
        f = open(file_path, "x")
    for _level in tree:
        for _ in _level:
            f.write(reverse_hex_string(_.hex()) + "\n")
    f.close()

    #############################################
    # Export HBM input and reference content
    #############################################    

    for pc_i in range(N_HBM_PC):
      str_pc_i = str(pc_i).zfill(2)
      shutil.copyfile(f"mem/hbm_mt_din_{str_pc_i}.mem",      PATH_MEM_FILES + f"hbm_{str_pc_i}_o.mem")
      shutil.copyfile(f"../linear_encoder/mem/le_hbm_{str_pc_i}_i.mem", PATH_MEM_FILES + f"hbm_{str_pc_i}_i.mem")

    #############################################
    # Export DDR input content
    #############################################
    with open(PATH_MEM_FILES + "ddr_00_i.mem", "w") as f:
      for _ in range(len(v_challenge_0)):
        fe = 0 # v_challenge_0[_] # legacy: verifier challenge was initially in DDR0
        f.write("{:064x}\n".format(fe))
      for _ in range(len(v_challenge_1)):
        fe = 0 # v_challenge_1[_] # legacy: verifier challenge was initially in DDR0
        f.write("{:064x}\n".format(fe))

    with open(PATH_MEM_FILES + "ddr_00_i.mem", "a") as dst, open("../linear_encoder/mem/le_ddr_0_i.mem", "r") as src:
        arr = src.readlines()
        for line in arr[2**k*2:]:
            dst.write(line)
       
    #############################################
    # Export DDR reference content
    #############################################
    
    shutil.copyfile("./mem/merkle_tree_data.mem", PATH_MEM_FILES + "ddr_01_o.mem") # This copies the column hashes and the MT

    with open(PATH_MEM_FILES + "ddr_01_o.mem", "a") as f:
        f.write("0"*64 + "\n") # merkle tree has just n-1 elements

        # Do matrix-vector-mul for proving 0:
        pr0_leafs = [0]*NUM_COLS
        for i in range(NUM_COLS):
          col = encoded_matrix[i]
          acc = FieldElement(0,0)
          for row_idx in range(NUM_ROWS):
              fe = col[row_idx]
              c = v_challenge_0[row_idx]
              acc += FieldElement(fe % 2**64, fe >> 64) * FieldElement(c % 2**64, c >> 64)
          pr0_leafs[i] = acc

        # Do leaf hashing for proving 0:
        hash = []
        for _ in pr0_leafs:
          fe = (_.img << 64) | _.real
          f.write("{:064x}\n".format(fe))

          hash += [hashSingleFieldElem(fe)]
        
        for _ in hash:
          f.write("{:064x}\n".format(_))

        # Do MT for proving 0:
        hash_bytes = [int.to_bytes(_,32,'little') for _ in hash]
        tree = merkle_tree(merkle_hash=hash_bytes)[1:]
        for _level in tree:
            for _ in _level:
                f.write(reverse_hex_string(_.hex()) + "\n")

        f.write("0"*64 + "\n") # merkle tree has just n-1 elements


        # Do matrix-vector-mul for proving 1:
        pr1_leafs = [0]*NUM_COLS
        for i in range(NUM_COLS):
          col = encoded_matrix[i]
          acc = FieldElement(0,0)
          for row_idx in range(NUM_ROWS):
              fe = col[row_idx]
              c = v_challenge_1[row_idx]
              acc += FieldElement(fe % 2**64, fe >> 64) * FieldElement(c % 2**64, c >> 64)
          pr1_leafs[i] = acc

        # Do leaf node hashing for proving 1:
        hash = []
        for _ in pr1_leafs:
          fe = (_.img << 64) | _.real
          f.write("{:064x}\n".format(fe))

          hash += [hashSingleFieldElem(fe)]
        
        for _ in hash:
          f.write("{:064x}\n".format(_))

        # Do MT for proving 1:
        hash_bytes = [int.to_bytes(_,32,'little') for _ in hash]
        tree = merkle_tree(merkle_hash=hash_bytes)[1:]
        for _level in tree:
            for _ in _level:
                f.write(reverse_hex_string(_.hex()) + "\n")

        f.write("0"*64 + "\n") # merkle tree has just n-1 elements
