##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import hashlib


def hashSingleFieldElem(field_element):
  # 000 | re | 000 | im
  # field_element = 0x1b7cca286c4c45b30b0c6a2d57dc29d9
  # field_element = 0

  fe_bytearray = bytearray(int.to_bytes(field_element,64,'little'))

  _gfg = hashlib.sha3_256() 
  _gfg.update(fe_bytearray) 
  _digest = _gfg.digest()

  # print(hex(int.from_bytes(_digest,'little')))
  # print("0xff91bc81b8839438de2d2a09148360e26789cba8eac5ca0756e1a21f59a9ceb1")

  # for fe = 0
  # print("0xe0815ed7fb7a050a8d2a04b91e5548306967191f94424dd17e55cc6faba10f07")
  return int.from_bytes(_digest,'little')

def leafNodeHashing_CheckAgainstOrion(s=67, nr_leaf_nodes = 2**12):

  # check against Orion SW:
  with open("./orion_prove_leafNodeHasing_output.txt", "r") as f:
    for l in f.readlines():
      s = l.split(" ")
      h = int(s[0],16)
      fe = int(s[1],16)

      my_h = hashSingleFieldElem(fe)
      assert my_h == h


if __name__ == "__main__":
  leafNodeHashing_CheckAgainstOrion()