##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import os
from gen_mem_for_orion import compare_files, compare_files_ddr
from time import sleep

# python script to interact with alveo fpga via host 

###########################################################################################################################################
# PARAMETERS
###########################################################################################################################################

# memory size

NUM_DDR_PCHANNELS   = 1
NUM_HBM_PCHANNELS   = 32

DDR_PCH_MEMORY_SIZE = 16 * 1024 * 1024 * 1024 # 16GB DDR4
HBM_PCH_MEMORY_SIZE = 256 * 1024 * 1024       # 256MB HBM2

DDR_MEMORY_SIZE     = DDR_PCH_MEMORY_SIZE * NUM_DDR_PCHANNELS # 16GB DDR4 or 32GB DDR4
HBM_MEMORY_SIZE     = HBM_PCH_MEMORY_SIZE * NUM_HBM_PCHANNELS # 8GB HBM2

DDR_WORD_SIZE       = 32 # 32B (256b), or 64B (512b)
HBM_WORD_SIZE       = 64 # 32B (256b), or 64B (512b)

DDR_MEMORY_ENTRIES  = DDR_MEMORY_SIZE // DDR_WORD_SIZE
HBM_MEMORY_ENTRIES  = HBM_MEMORY_SIZE // HBM_WORD_SIZE

# transfer size in bytes:
D = os.path.getsize("./mem/input/hbm_00_i.bin") // (128*4//8) // 2
FIELD_ELEMENT_BYTES  = 128 // 8
HASH_BYTES           = 256 // 8

HBM_WR_BYTES = 2 * 4 * D * FIELD_ELEMENT_BYTES
HBM_RD_BYTES = 2 * 4 * D * FIELD_ELEMENT_BYTES

DDR_WR_BYTES = os.path.getsize(f"./mem/input/ddr_i.bin")
DDR_RD_BYTES = 2 * D * (2 + 3 + 3) * HASH_BYTES


# memory address offset

CSR_OFFSET          = 0x0000_0000_0000_0000
HBM_OFFSET          = 0x0000_0002_0000_0000
DDR_OFFSET          = 0x0000_0014_0000_0000

# xdma

XDMA_PATH           = "./dma_ip_drivers/XDMA/linux-kernel/tools"
XDMA_XID            = 0         # 0..3

###########################################################################################################################################
# WRITE DATA TO FPGA MEMORY (H2C)
###########################################################################################################################################

# write data from host to fpga memory (H2C)
# use c programm :
#   $XDMA_PATH/dma_to_device 
#       -d /dev/${XDMA_XID}_h2c_${curChannel} \
#       -f data/datafile${i}_4K.bin \
#       -s $transferSz \
#       -a $base_addr \
#       -c $transferCount &

def write_data_to_fpga_memory(data_file, addr_offset, transfer_size, transfer_count):
  """
  Write data from host to FPGA memory (H2C).
  
  Args:
      data_file (str): Path to the data file to be written.
      addr_offset (int): Address offset in FPGA memory.
      transfer_size (int): Size of the transfer in bytes.
      transfer_count (int): Number of transfers.
  """
  cmd = f"{XDMA_PATH}/dma_to_device -d /dev/xdma{XDMA_XID}_h2c_0 -f {data_file} -s {transfer_size} -a {addr_offset} -c {transfer_count}"
  print(f"[EXEC] cmd: {cmd}")

  # Execute the command
  if os.system(cmd) != 0:
    print("FAIL!")
    exit(-1)

  return

# write to hbm
def write_data_to_hbm_memory():
  addr_offset = HBM_OFFSET
  for _pch in range(NUM_HBM_PCHANNELS):
    datafile        = f"./mem/input/hbm_{_pch:02}_i.bin"
    addr_offset     = HBM_OFFSET + (_pch * HBM_PCH_MEMORY_SIZE)
    transfer_size   = HBM_WR_BYTES
    transfer_count  = 1
    write_data_to_fpga_memory(datafile, addr_offset, transfer_size, transfer_count)

  print(f"")
  return

# write to ddr
def write_data_to_ddr_memory():
  # write graph info:
  datafile        = f"./mem/input/ddr_i.bin"
  addr_offset     = DDR_OFFSET
  transfer_size   = DDR_WR_BYTES
  transfer_count  = 1
  write_data_to_fpga_memory(datafile, addr_offset, transfer_size, transfer_count)

  # clear destination region:
  datafile        = f"/dev/zero"
  addr_offset     = DDR_OFFSET + DDR_PCH_MEMORY_SIZE//2 # overwrite second half from DDR. This contains the hashes etc.
  transfer_size   = DDR_RD_BYTES
  transfer_count  = 1
  write_data_to_fpga_memory(datafile, addr_offset, transfer_size, transfer_count)

  print(f"")
  return


###########################################################################################################################################
# READ DATA FROM FPGA MEMORY TO HOST (C2H)
###########################################################################################################################################

# read data from fpga memory to host (C2H)
# use c programm:
#   $XDMA_PATH/dma_from_device \
#     -d /dev/${XDMA_XID}_c2h_${curChannel} \
#     -f data/output_datafile${i}_4K.bin \
#     -s $transferSz \
#     -a $base_addr \
#     -c $transferCount &

# read from hbm
def read_data_from_hbm_memory():
  addr_offset = HBM_OFFSET
  for _pch in range(NUM_HBM_PCHANNELS):
    datafile        = f"./mem/output/hbm_{_pch:02}_o.bin"
    addr_offset     = HBM_OFFSET + (_pch * HBM_PCH_MEMORY_SIZE)
    transfer_size   = HBM_RD_BYTES
    transfer_count  = 1
    cmd = f"{XDMA_PATH}/dma_from_device -d /dev/xdma{XDMA_XID}_c2h_0 -f {datafile} -s {transfer_size} -a {addr_offset} -c {transfer_count}"
    print(f"[EXEC] cmd: {cmd}")
    if os.system(cmd) != 0:
      print("FAIL!")
      exit(-1)
  print(f"")
  return

## read from ddr. This read is performed page-wise
def read_data_from_ddr_memory():
  datafile        = f"./mem/output/ddr_o.bin"
  datafile_tmp    = f"./mem/output/ddr_o_tmp.bin"
  addr_offset     = DDR_OFFSET + DDR_PCH_MEMORY_SIZE//2 # read second half from DDR. This contains the hashes
  transfer_size   = 4096
  transfer_count  = 1
  
  os.system(f"rm {datafile}")
  os.system(f"touch {datafile}")
  for _ in range(0,DDR_RD_BYTES,transfer_size):
    addr = addr_offset + _
    cmd = f"{XDMA_PATH}/dma_from_device -d /dev/xdma{XDMA_XID}_c2h_0 -f {datafile_tmp} -s {transfer_size} -a {addr} -c {transfer_count}"
    print(f"[EXEC] cmd: {cmd}")
    if os.system(cmd) != 0:
      print("FAIL!")
      exit(-1)
    os.system(f"cat {datafile_tmp} >> {datafile}")

  os.system(f"rm {datafile_tmp}")

  print(f"")
  return

###########################################################################################################################################
# MAIN FUNCTION
###########################################################################################################################################

if __name__ == "__main__":
  print("reload xdma drivers...")
  os.system(XDMA_PATH+"/../tests/reload_driver.sh")

  sleep(2)

  # set up the environment and parameters
  print(f"")
  print(f"Number of DDR Channels: {NUM_DDR_PCHANNELS}")
  print(f"Number of HBM Channels: {NUM_HBM_PCHANNELS}")
  print(f"")
  print(f"HBM_PCH Memory Size   : {DDR_PCH_MEMORY_SIZE // (1024 * 1024)} MB")
  print(f"HBM_PCH Memory Size   : {HBM_PCH_MEMORY_SIZE // (1024 * 1024)} MB")
  print(f"DDR Memory Size       : {DDR_MEMORY_SIZE     // (1024 * 1024)} MB")
  print(f"HBM Memory Size       : {HBM_MEMORY_SIZE     // (1024 * 1024)} MB")
  print(f"")
  print(f"DDR_WORD_SIZE         : {DDR_WORD_SIZE} B -> {DDR_WORD_SIZE * 8} b")
  print(f"HBM_WORD_SIZE         : {HBM_WORD_SIZE} B -> {HBM_WORD_SIZE * 8} b")
  print(f"")
  print(f"DDR_MEMORY_ENTRIES    : {DDR_MEMORY_ENTRIES}")
  print(f"HBM_MEMORY_ENTRIES    : {HBM_MEMORY_ENTRIES}")
  print(f"")

  # write data to the FPGA memory
  write_data_to_hbm_memory()
  write_data_to_ddr_memory()

  # start the FPGA kernel
  print("Waiting for FPGA execution. After FPGA is done, press 'Enter' to continue...")
  input()

  # read data from the FPGA memory
  read_data_from_hbm_memory()
  read_data_from_ddr_memory()

  # check if the data is correct
  print("Do Compare? Y/n")
  if input() != "n":  
    print("Starting comparing files...")

    error = 0

    # compare all HBM channels
    for _pch in range(NUM_HBM_PCHANNELS):
      reference_filename = f"./mem/reference/hbm_{_pch:02}_r.bin"
      output_filename    = f"./mem/output/hbm_{_pch:02}_o.bin"
      print(f"  > Comparing hbm_{_pch:02}")
      error |= compare_files(reference_filename, output_filename, HBM_WORD_SIZE)

    # compare the DDR result
    for ddr_pch in range(NUM_DDR_PCHANNELS):
      _pch = ddr_pch + NUM_HBM_PCHANNELS
      reference_filename = f"./mem/reference/ddr_r.bin"
      output_filename    = f"./mem/output/ddr_o.bin"
      print(f"  > Comparing ddr")
      error |= compare_files_ddr(reference_filename, output_filename, DDR_WORD_SIZE, DDR_RD_BYTES)

    # print result
    if error:
      print("")
      print("=======================================")
      print("==== THERE ARE ERRORS IN COMPARISON ===")
      print("=======================================\n")
    else:
      print("")
      print("======================")
      print("==== EVERYTHING OK ===")
      print("======================\n")

