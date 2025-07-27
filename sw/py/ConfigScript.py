##################################################################################
## Company: Institute of Information Security, Graz Universtiy of Technology
## Engineer: Florian Hirner and Florian Krieger
##################################################################################

import subprocess

###################################################################################################
# Main Python script. This generates configuraion files (*.pkg), ddr memory content and test cases
###################################################################################################

#### Set the targeted polynomial degree here: ####
log_message_columns = 9  # 9..23
# i.e.: log N = log_message_columns + 7
# -> log N = 16 -> log_message_columns = 9
# -> log N = 18 -> log_message_columns = 11
##################################################

# Set the parameters for the linear encoder and merkle tree
# These parameters are used to generate the configuration files and test cases
# The values are based on the polynomial degree and other configurations
rdegree1            = 42
rdegree2            = 26
min_ldegree1        = 8
min_ldegree2        = 18
patch_mini          = 16
alpha               = 1.72

# Define the number of HBM channels and DDR/Memory widths
# These values are used to configure the memory interfaces and widths
NUM_HBM             = 32
DDR_WIDTH           = 256
HBM_WIDTH           = 512

# Define the script name and arguments
script_name_LE = "tb_linear_encode.py"
script_name_CHU_MT_PROVE = "tb_merkle_tree.py"

# Create header file for C code
with open("../fpga_mb/orion_config.h", "w") as f:
  f.write("//////////////////////////////////////////////////////////////////////////////////\n")
  f.write("// Company: Institute of Information Security, Graz Universtiy of Technology\n")
  f.write("// Engineer: Florian Hirner and Florian Krieger\n")
  f.write("//////////////////////////////////////////////////////////////////////////////////\n\n")
  
  f.write("// This file is generated via ConfigScript.py\n")
  f.write(f"#define LOG_D ({log_message_columns})\n")
  f.write(f"#define NUM_COLUMNS_MSG (1 << LOG_D)\n")
  f.write(f"#define NUM_COLUMNS_CODE ({int(alpha * 2**log_message_columns)})\n")
  f.write(f"#define NUM_COLUMNS_TOTAL (2 * NUM_COLUMNS_MSG)\n")
  f.write(f"#define DDR_WIDTH ({DDR_WIDTH})\n")
  f.write(f"#define HBM_WIDTH ({HBM_WIDTH})\n")

# Compile the Trivium shared library
subprocess.run("make", cwd="./prng/trivium")

# Run the script with arguments
for _ in range(NUM_HBM):
  res = subprocess.run(["python3", script_name_LE, str(log_message_columns), str(rdegree1), str(rdegree2), str(min_ldegree1), str(min_ldegree2), str(patch_mini), str(_)], cwd="./linear_encoder/")
  if res.returncode != 0:
    print("============ Error LE ==========")
    exit(-1)

res = subprocess.run(["python3", script_name_CHU_MT_PROVE], cwd="./merkle_tree/")
if res.returncode != 0:
  print("============ Error CHU ==========")
  exit(-1)
