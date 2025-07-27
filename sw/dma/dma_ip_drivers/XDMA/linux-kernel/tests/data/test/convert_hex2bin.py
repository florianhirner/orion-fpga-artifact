fname = "le_hbm_o"

def convert_hex2bin(fname):
    fo = open(fname + ".bin", "wb")
    fi = open(fname + ".mem", "r")
    for line_num, line in enumerate(fi, 1):
        hex_str = line.strip()
        data_size_in_bytes = len(hex_str) // 2
        if data_size_in_bytes != 512//8:
            raise ValueError(f"Line {line_num} is not 512 bits (128 hex chars): {hex_str}")
        
        # Convert to bytes and interpret as integer (little-endian or big-endian)
        byte_data = bytes.fromhex(hex_str)
        # int_val_le = int.from_bytes(byte_data, 'little')
        int_val_be = int.from_bytes(byte_data, 'big')

        # print(f"Line {line_num}: {data_size_in_bytes=}")
        # print(f"  Hex: {hex_str}")
        # print(f"  Int (LE): 0x{int_val_le:0128x}")
        # print(f"  Int (BE): 0x{int_val_be:0128x}")

        fo.write(int_val_be.to_bytes(data_size_in_bytes, byteorder='little'))

convert_hex2bin("le_hbm_i")
convert_hex2bin("le_hbm_o")