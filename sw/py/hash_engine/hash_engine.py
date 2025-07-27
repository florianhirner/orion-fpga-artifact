##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import hashlib
from random import randint, seed 

N_HBM_PC            = 32

XFER_WIDTH_IN_BITS  = 512
XFER_WIDTH_IN_BYTES = XFER_WIDTH_IN_BITS // 8

NUM_COEF_PER_FIELD  = 2
COEF_SIZE           = 64
FIELD_SIZE          = COEF_SIZE * NUM_COEF_PER_FIELD
NUM_FIELDS_PER_PC   = XFER_WIDTH_IN_BITS // FIELD_SIZE

N_SHA_UNIT  = 8
D_SHA_UNIT  = 16
D_SHA_PIPE  = N_SHA_UNIT * D_SHA_UNIT

XFER_INPUT          = 4096
XFER_OUTPUT         = 4096


def reverse_hex_string(hex_string):
    # Ensure the string has an even length
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string length should be even.")

    # Split into bytes and reverse
    reversed_bytes = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)][::-1]

    # Join the reversed bytes back into a string
    reversed_hex = ''.join(reversed_bytes)
    return reversed_hex

seed(7689)

for pc_i in range(N_HBM_PC):

    str_pc_i = str(pc_i).zfill(2)

    #random HBM content
    q = 2**61-1
    # f = open(f"../../fpga/hash_engine/SPM_HE_Testing_new/rtl/tb/hbm/merkle_tree/hbm_mt_din_{str_pc_i}.mem", "w")
    f = open(f"../../rtl/hash_engine/data/hbm_mt_din_{str_pc_i}.mem", "w")
    col_string = ""
    for i in range(XFER_INPUT):
        data = ""
        for _ in range(4):
          r = randint(0,q-1)
          i = randint(0,q-1)
          fe = (r << 64) | i
          data += "{:032x}".format(fe)

        hex_str = data+"\n"

        f.write(hex_str)
    f.close()

cols = ["" for _ in range(XFER_INPUT)]

for pc_i in range(N_HBM_PC):
    str_pc_i = str(pc_i).zfill(2)
    # with open(f"../../fpga/hash_engine/SPM_HE_Testing_new/rtl/tb/hbm/merkle_tree/hbm_mt_din_{str_pc_i}.mem", "r") as f:
    with open(f"../../rtl/hash_engine/data/hbm_mt_din_{str_pc_i}.mem", "r") as f:
      for _ in range(XFER_INPUT):
        cols[_] += reverse_hex_string(f.readline()[:-1])

# with open("../../fpga/hash_engine/SPM_HE_Testing_new/rtl/tb/hbm/hashes.txt", "w") as f:
with open("../../rtl/hash_engine/data/hashes.mem", "w") as f:
  for col in range(XFER_INPUT):
    _gfg = hashlib.sha3_256() 
    _gfg.update(bytearray(int.to_bytes(int(cols[col],16), len(cols[col])//2, 'big'))) 
    _digest = _gfg.digest()
    f.write(hex(int.from_bytes(_digest,'little'))[2:] + "\n")
