/******************************************************************************
* Copyright (c) 2021 Xilinx, Inc.  All rights reserved.
* SPDX-License-Identifier: MIT
* Adapted by Florian Hirner and Florian Krieger
 ******************************************************************************/

#include <stdio.h>
#include "xparameters.h"
#include "xil_types.h"
#include "xstatus.h"
#include "xil_testmem.h"

#include "platform.h"
#include "memory_config.h"
#include "xil_printf.h"

#include "orion_config.h"

void putnum(unsigned int num);

void test_memory_range(struct memory_range_s *range) {
    XStatus status;

    /* This application uses print statements instead of xil_printf/printf
     * to reduce the text size.
     *
     * The default linker script generated for this application does not have
     * heap memory allocated. This implies that this program cannot use any
     * routines that allocate memory on heap (printf is one such function).
     * If you'd like to add such functions, then please generate a linker script
     * that does allocate sufficient heap memory.
     */

    print("Testing memory region: "); print(range->name);  print("\n\r");
    print("    Memory Controller: "); print(range->ip);  print("\n\r");
    #if defined(__MICROBLAZE__) && !defined(__arch64__)
        #if (XPAR_MICROBLAZE_ADDR_SIZE > 32)
            print("         Base Address: 0x"); putnum((range->base & UPPER_4BYTES_MASK) >> 32); putnum(range->base & LOWER_4BYTES_MASK);print("\n\r");
        #else
            print("         Base Address: 0x"); putnum(range->base); print("\n\r");
        #endif
        print("                 Size: 0x"); putnum(range->size); print (" bytes \n\r");
    #else
        xil_printf("         Base Address: 0x%lx \n\r",range->base);
        xil_printf("                 Size: 0x%lx bytes \n\r",range->size);
    #endif

#if defined(__MICROBLAZE__) && !defined(__arch64__) && (XPAR_MICROBLAZE_ADDR_SIZE > 32)
    status = Xil_TestMem32((range->base & LOWER_4BYTES_MASK), ((range->base & UPPER_4BYTES_MASK) >> 32), 4096*16, 0xAAAA5555, XIL_TESTMEM_ALLMEMTESTS);
    print("          32-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");

    status = Xil_TestMem16((range->base & LOWER_4BYTES_MASK), ((range->base & UPPER_4BYTES_MASK) >> 32), 2048, 0xAA55, XIL_TESTMEM_ALLMEMTESTS);
    print("          16-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");

    status = Xil_TestMem8((range->base & LOWER_4BYTES_MASK), ((range->base & UPPER_4BYTES_MASK) >> 32), 4096, 0xA5, XIL_TESTMEM_ALLMEMTESTS);
    print("           8-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");
#else
    status = Xil_TestMem32((u32*)range->base, 1024, 0xAAAA5555, XIL_TESTMEM_ALLMEMTESTS);
    print("          32-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");

    status = Xil_TestMem16((u16*)range->base, 2048, 0xAA55, XIL_TESTMEM_ALLMEMTESTS);
    print("          16-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");

    status = Xil_TestMem8((u8*)range->base, 4096, 0xA5, XIL_TESTMEM_ALLMEMTESTS);
    print("           8-bit test: "); print(status == XST_SUCCESS? "PASSED!":"FAILED!"); print("\n\r");
#endif

}

void printMem(uint64_t* p, int offset, int word_size, int num_words)
{
	xil_printf("=== \r\n");
	for(int i = offset; i < offset + num_words; i++)
	{
		xil_printf("[%4u] ",i);
		for(int j = word_size/64 - 1; j >= 0; j--)
		{
			xil_printf("%016llx",p[i*word_size/64+j]);
		}
		xil_printf("\r\n");
	}
}

volatile uint64_t * const axi_address_base_hbm00 	   = (uint64_t *) 0x0000000200000000;
volatile uint64_t * const axi_address_base_hbm01	   = (uint64_t *) 0x0000000210000000;
volatile uint64_t * const axi_address_base_hbm02 	   = (uint64_t *) 0x0000000220000000;
volatile uint64_t * const axi_address_base_hbm03	   = (uint64_t *) 0x0000000230000000;
volatile uint64_t * const axi_address_base_hbm04	   = (uint64_t *) 0x0000000240000000;
volatile uint64_t * const axi_address_base_hbm05	   = (uint64_t *) 0x0000000250000000;
volatile uint64_t * const axi_address_base_hbm06	   = (uint64_t *) 0x0000000260000000;
volatile uint64_t * const axi_address_base_hbm07	   = (uint64_t *) 0x0000000270000000;
volatile uint64_t * const axi_address_base_hbm08	   = (uint64_t *) 0x0000000280000000;
volatile uint64_t * const axi_address_base_hbm09	   = (uint64_t *) 0x0000000290000000;
volatile uint64_t * const axi_address_base_hbm10	   = (uint64_t *) 0x00000002A0000000;
volatile uint64_t * const axi_address_base_hbm11	   = (uint64_t *) 0x00000002B0000000;
volatile uint64_t * const axi_address_base_hbm12	   = (uint64_t *) 0x00000002C0000000;
volatile uint64_t * const axi_address_base_hbm13	   = (uint64_t *) 0x00000002D0000000;
volatile uint64_t * const axi_address_base_hbm14	   = (uint64_t *) 0x00000002E0000000;
volatile uint64_t * const axi_address_base_hbm15	   = (uint64_t *) 0x00000002F0000000;
volatile uint64_t * const axi_address_base_hbm16 	   = (uint64_t *) 0x0000000300000000;
volatile uint64_t * const axi_address_base_hbm17	   = (uint64_t *) 0x0000000310000000;
volatile uint64_t * const axi_address_base_hbm18 	   = (uint64_t *) 0x0000000320000000;
volatile uint64_t * const axi_address_base_hbm19	   = (uint64_t *) 0x0000000330000000;
volatile uint64_t * const axi_address_base_hbm20	   = (uint64_t *) 0x0000000340000000;
volatile uint64_t * const axi_address_base_hbm21	   = (uint64_t *) 0x0000000350000000;
volatile uint64_t * const axi_address_base_hbm22	   = (uint64_t *) 0x0000000360000000;
volatile uint64_t * const axi_address_base_hbm23	   = (uint64_t *) 0x0000000370000000;
volatile uint64_t * const axi_address_base_hbm24	   = (uint64_t *) 0x0000000380000000;
volatile uint64_t * const axi_address_base_hbm25	   = (uint64_t *) 0x0000000390000000;
volatile uint64_t * const axi_address_base_hbm26	   = (uint64_t *) 0x00000003A0000000;
volatile uint64_t * const axi_address_base_hbm27	   = (uint64_t *) 0x00000003B0000000;
volatile uint64_t * const axi_address_base_hbm28	   = (uint64_t *) 0x00000003C0000000;
volatile uint64_t * const axi_address_base_hbm29	   = (uint64_t *) 0x00000003D0000000;
volatile uint64_t * const axi_address_base_hbm30	   = (uint64_t *) 0x00000003E0000000;
volatile uint64_t * const axi_address_base_hbm31	   = (uint64_t *) 0x00000003F0000000;

volatile uint64_t * const axi_address_base_ddr1	       = (uint64_t *) 0x0000001400000000;
volatile uint64_t * const axi_address_base_ddr_outputs = (uint64_t *) 0x0000001600000000;

volatile uint32_t * const axi_address_base             = (uint32_t*)0x20000000;
volatile uint32_t * const axi_csr                      = axi_address_base + 0;
volatile uint32_t * const axi_scalar00                 = axi_address_base + 4;


int main()
{
    sint32 i;

    init_platform();

    print("--Starting Memory Test Application--\n\r");
    for (i = 0; i < n_memory_ranges; i++) {
        test_memory_range(&memory_ranges[i]);
    }
    print("--Memory Test Application Complete--\n\r");
    print("Successfully ran Memory Test Application\r\n\n");

    // Wait until the FPGA is idle, print the status register
    uint32_t control_signals = 0;
	do {
		control_signals = *axi_csr;
		xil_printf("-- control_signals %x\n\r", control_signals);
		if (control_signals == (1 << 0)) {
			print("-- ap_start\n\r");
		}
		if (control_signals == (1 << 1)) {
			print("-- ap_done\n\r");
		}
		if (control_signals == (1 << 2)) {
			print("-- ap_idle\n\r");
		}
		if (control_signals == (1 << 3)) {
			print("-- ap_ready\n\r");
		}
		if (control_signals == (1 << 7)) {
			print("-- auto_restart\n\r");
		}
		if (control_signals == (1 << 9)) {
			print("-- interrupt\n\r");
		}
		print("\n\r");
	} while((control_signals & (1 << 2)) == 0);


	// now, performa a NOP instruction cycle
	*axi_scalar00 = 0; // NOP instruction
	*axi_csr |= (1 << 0); // start execution
	while((*axi_csr & (1 << 2)) == 0); // wait for idle
	print("===================\r\n");
	print("Startup Successful!\r\n");
	print("===================\r\n\n");

	int user_input = '0';
	while(user_input == '0')
	{
		*axi_scalar00 = 0; // NOP
		*axi_scalar00 |= (1 << 0); // Enable Encode
		*axi_scalar00 |= (1 << 1); // Enable HE
		*axi_scalar00 |= (1 << 2); // Enable MT
		*axi_scalar00 |= (1 << 3); // Enable PR0
		*axi_scalar00 |= (1 << 4); // Enable PR1
		while((*axi_csr & (1 << 2)) == 0); // wait for idle

		print("-> Now, send the data via PCI. Then, press any key+enter to continue...\r\n");
		user_input = getchar();
		getchar();

        // Start execution on FPGA:
		*axi_csr |= (1 << 0);
		print("Execution on FPGA running ....\r\n");

        // Wait for completion:
		do
		{
			for(i = 0; i < 100; i++);
			xil_printf("-- control_signals %x\n\r", *axi_csr);
		}
		while((*axi_csr & (1 << 2)) == 0);
		print("Execution on FPGA done!\r\n");

        // Print DDR memory content:
		print("==== DDR CONTENT AFTER EXECUTION ====\r\n");
		// Column Hashes
		print("======================\r\nColumn Hash\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 0, DDR_WIDTH, 5);
		printMem((uint64_t*)axi_address_base_ddr_outputs, NUM_COLUMNS_CODE-2, DDR_WIDTH, 5);
		printMem((uint64_t*)axi_address_base_ddr_outputs, NUM_COLUMNS_TOTAL-5, DDR_WIDTH, 5);
		// MerkleTree
		print("======================\r\nMerkle Tree Root Node\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 2*NUM_COLUMNS_TOTAL-2, DDR_WIDTH, 1);

		print("======================\r\nAdder Tree PR0\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 2*NUM_COLUMNS_TOTAL, DDR_WIDTH, 5);
		print("======================\r\nLeaf Hashes PR0\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 3*NUM_COLUMNS_TOTAL, DDR_WIDTH, 5);
		print("======================\r\nMerkle Tree PR0 Root Node\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 5*NUM_COLUMNS_TOTAL-2, DDR_WIDTH, 1);
		print("======================\r\nAdder Tree PR1\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 5*NUM_COLUMNS_TOTAL, DDR_WIDTH, 5);
		print("======================\r\nLeaf Hashes PR1\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 6*NUM_COLUMNS_TOTAL, DDR_WIDTH, 5);
		print("======================\r\nMerkle Tree PR1 Root Node\r\n");
		printMem((uint64_t*)axi_address_base_ddr_outputs, 7*NUM_COLUMNS_TOTAL-2, DDR_WIDTH, 1);

        // Print Merkle Tree root nodes
		uint64_t* hash_base;
		print("\r\n");
		print("============= RESULTS ===========\r\n");
		xil_printf("MT Root Commit: ");
		hash_base = (uint64_t*) (axi_address_base_ddr_outputs+(2*NUM_COLUMNS_TOTAL-2)*DDR_WIDTH/(sizeof(uint64_t)*8));
		printMem(hash_base, 0, DDR_WIDTH, 1);
		xil_printf("MT Root Proximity (PR0): ");
		hash_base = (uint64_t*) (axi_address_base_ddr_outputs+(5*NUM_COLUMNS_TOTAL-2)*DDR_WIDTH/(sizeof(uint64_t)*8));
		printMem(hash_base, 0, DDR_WIDTH, 1);
		xil_printf("MT Root Consistency (PR1): ");
		hash_base = (uint64_t*) (axi_address_base_ddr_outputs+(8*NUM_COLUMNS_TOTAL-2)*DDR_WIDTH/(sizeof(uint64_t)*8));
		printMem(hash_base, 0, DDR_WIDTH, 1);
		print("=================================\r\n");
		print("\r\n");

		print("-> Done. Receive the data via PCI. Then, press 0+enter to re-run, any other key ends program\r\n");
		user_input = getchar();
		getchar();
	}

	print("=== DONE! EXIT PROGRAM ===\r\n");

    cleanup_platform();
    return 0;
}
