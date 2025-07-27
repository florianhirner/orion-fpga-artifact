##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

# this takes the memory content files (memory_content/*.mem) and transforms them to *.bin files
# it also prepares the reference file

import os

# path_mem_files = "../../hw/rtl/memory_content/mem/"
path_mem_files = "../../hw/mem/"
path_bin_input_files = "./mem/input/"
path_bin_output_files = "./mem/output/"
path_bin_ref_files = "./mem/reference/"

NUM_DDR = 1
NUM_HBM = 32

WORD_SIZE_DDR = 256 # bits
WORD_SIZE_HBM = 512 # bits

D = os.path.getsize(path_mem_files + "hbm_00_i.mem") // (128+1)

def toBinaryFile(src_filename, dst_filename, num_bytes, zero_pad = None):
  """
  Write data from host to FPGA memory (H2C).
  
  Args:
      src_filename (str): Path to the source data file *.mem.
      dst_filename (str): Path to the destination file *.bin.
      num_bytes (int): Bytes per memory word.
      zero_pad (None, "page", or int): None: no padding, "page": pad to multiple of 4096 bytes, int: number of 0-bytes appended
  """
  os.makedirs(os.path.dirname(dst_filename), exist_ok=True)
  with open(src_filename, "r") as f_src, open(dst_filename, "wb") as f_dst:
    bytes_written = 0
    for src_line in f_src.readlines():
      src_line_int = int(src_line, 16)
      word = src_line_int.to_bytes(num_bytes, 'little')
      f_dst.write(word)
      bytes_written += num_bytes
    if zero_pad is None:
      return
    elif zero_pad == "page":
      if bytes_written % 4096 != 0:
        src_line_int = 0
        word = src_line_int.to_bytes(4096 - (bytes_written % 4096), 'little')
        f_dst.write(word)
    else:
      for _ in range(zero_pad):
        src_line_int = 0
        word = src_line_int.to_bytes(num_bytes, 'little')
        f_dst.write(word)


def read_and_print_file(file_name, word_size):
  """Read a binary file and print its content."""
  with open(file_name, "rb") as f:
    data = f.read()
    for i in range(0, len(data), word_size):
      word = data[i:i+word_size]
      print(f"word[{(i//word_size):08d}]: {word.hex()}")
  print("")

def compare_bytes(data1, data2, word_size):
  """ Compares two byte objects and prints status information """
  if data1 == data2 and  len(data1) != 0:
    print("    == SUCCESS data file and ref file are the same! == ")
    return 0
  else:
    print("    == FAIL data file and ref file are different! ==")
  
  if len(data1) != len(data2):
    print("  mismatch in size",len(data1),len(data2))

  ctr = 5

  for i in range(0, min(len(data1),len(data2)), word_size):
    word1 = data1[i:i+word_size]
    word2 = data2[i:i+word_size]
    if word1 != word2:
      print(f"word[{i//word_size}] is incorrect")
      print(word1.hex())
      print(word2.hex())
      ctr -= 1

    if ctr < 0:
      break
  
  return 1

def compare_bytes_mt(data1, data2, word_size):
  """ Compare two byte objects for merkle trees and prints status information """
  error = 0

  if len(data1) != len(data2) or len(data1) == 0:
    print("  mismatch in size",len(data1),len(data2))
    error = 1

  words2 = []
  for i in range(0, min(len(data1),len(data2)), word_size):
    words2 += [data2[i:i+word_size]]

  ctr = 5
  for i in range(0, min(len(data1),len(data2)), word_size):
    word1 = data1[i:i+word_size]
    
    if word1 not in words2:
      print(f"word1[{i//word_size}] is missing!")
      print(word1.hex())
      error = 1
      ctr -= 1
    
    if ctr < 0:
      break
  
  if error == 0:
    print("    == SUCCESS data file and ref file are the same! ==")
  else:
    print("    == FAIL data file and ref file are different! ==")
  
  return error

def compare_files(file_name1, file_name2, word_size):
  """Compare two binary files and print differences."""
  with open(file_name1, "rb") as f1, open(file_name2, "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()

    return compare_bytes(data1, data2, word_size)
  
def compare_files_mt(file_name1, file_name2, word_size):
  """Compare two binary files for merkle trees and print differences."""
  with open(file_name1, "rb") as f1, open(file_name2, "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()
    error = compare_bytes_mt(data1, data2, word_size)

    if data1[-word_size:] != data2[-word_size:]:
      print("  MT: invalid root node!")
      error |= 1

    return error
    

def compare_files_ddr(file_name1, file_name2, word_size, data_size):
  """Compares the expected and actual output of Orion's DDR."""
  with open(file_name1, "rb") as f1, open(file_name2, "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()
    
    if len(data1) != data_size:
      print("mismatch in data_size",len(data1),data_size)

    if len(data1) != len(data2):
      print("mismatch in size",len(data1),len(data2))

    error = 0
    data_size = data_size // 8

    print("    > Compare column hashes...")
    d1 = data1[0*data_size:1*data_size]
    d2 = data2[0*data_size:1*data_size]
    error |= compare_bytes(d1, d2, word_size)
    print("    > Compare column MT...")
    d1 = data1[1*data_size:2*data_size-1]
    d2 = data2[1*data_size:2*data_size-1]
    error |= compare_bytes_mt(d1, d2, word_size)
    print("    > Compare inner product 0...")
    d1 = data1[2*data_size:3*data_size]
    d2 = data2[2*data_size:3*data_size]
    error |= compare_bytes(d1, d2, word_size)
    print("    > Compare inner product hashes 0...")
    d1 = data1[3*data_size:4*data_size]
    d2 = data2[3*data_size:4*data_size]
    error |= compare_bytes(d1, d2, word_size)
    print("    > Compare inner product MT 0...")
    d1 = data1[4*data_size:5*data_size-1]
    d2 = data2[4*data_size:5*data_size-1]
    error |= compare_bytes_mt(d1, d2, word_size)
    print("    > Compare inner product 1...")
    d1 = data1[5*data_size:6*data_size]
    d2 = data2[5*data_size:6*data_size]
    error |= compare_bytes(d1, d2, word_size)
    print("    > Compare inner product hashes 1...")
    d1 = data1[6*data_size:7*data_size]
    d2 = data2[6*data_size:7*data_size]
    error |= compare_bytes(d1, d2, word_size)
    print("    > Compare inner product MT 1...")
    d1 = data1[7*data_size:8*data_size-1]
    d2 = data2[7*data_size:8*data_size-1]
    error |= compare_bytes_mt(d1, d2, word_size)

    return error

if __name__ == "__main__":
  os.makedirs(os.path.dirname(path_bin_output_files), exist_ok=True)

  # Create binary files for HBM input:
  for _ in range(NUM_HBM):
    name = f"hbm_{_:02}_i"
    name_tmp = name # f"hbm_{_:02}_o"  # THIS IS FOR DEBUG
    toBinaryFile(path_mem_files+name_tmp+".mem", path_bin_input_files+name+".bin", WORD_SIZE_HBM//8, zero_pad=D)
  
  # Create binary file for DDR input:
  toBinaryFile(path_mem_files+"ddr_00_i.mem", path_bin_input_files+"ddr_i.bin", WORD_SIZE_DDR//8, zero_pad="page")
  # toBinaryFile(path_mem_files+"ddr_01_o.mem", path_bin_input_files+"ddr_i.bin", WORD_SIZE_DDR//8, zero_pad="page") # THIS IS FOR DEBUG


  # Create binary files for HBM reference:
  for _ in range(NUM_HBM):
    name = f"hbm_{_:02}"
    toBinaryFile(path_mem_files+name+"_o.mem", path_bin_ref_files+name+"_r.bin", WORD_SIZE_HBM//8)
  
  # Create binary files for DDR reference:
  toBinaryFile(path_mem_files+"ddr_01_o.mem", path_bin_ref_files+"ddr_r.bin", WORD_SIZE_DDR//8)

