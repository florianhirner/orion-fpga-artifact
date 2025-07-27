# orion-fpga-artifact


This is a repository for the paper "Accelerating Hash-Based Polynomial Commitment Schemes with Linear Prover Time" (https://ia.cr/2024/1918). It includes ready-to-use bitstream files to evaluate our artifact for the Orion Prover on a Alveo U280 FPGA.

All content of this repo is for academic research use only. It does not come with any support, warranty, or responsibility.

## Configuration and Setup:

Using this code requires:
- Ubuntu 20.04 GA (Kernel 5.15.*)
- Python version 3.8.10 (or newer)
- Vivado and Vitis 2022.2
- gcc 9.4.0 and GNU Make 4.2.1
- Alveo U280 FPGA

## Folder structure
```
/
├── hw/                       All hardware-related files to run artifact
│   ├── mem/                  Memory related files used to fill HBM and DDR with data
│   └── xsa/                  Contains hardware specification files (bitstreams) to be flashed onto FPGA
├── sw/                       All software-related files (including Vitis)
│   ├── dma/                  Code and scripts for data echange over PCI (card to host and host to card)
│   ├── fpga_mb/              Code to run on the Microblaze CPU and to interface with the RTL design
|   ├── py/                   Code for generating test cases
|   └── vitis/                Contains Vitis template projects and a folder for Vitis workspace
└── README.md
```

Note: There are some folders starting with "_". This means that the files in these folders are not used in the project. They're just there for reference.


## Running the Artifact on the Alveo U280 FPGA:

This repo contains ready-to-use bitstream files. These are the steps to execute the prepared tests on the FPGA:

 0) Make sure the U280 FPGA is in the Vivado flow and xdma is loaded properly. If everything is correctly `lspci` should give a similar output as below
```
8d:00.0 Serial controller: Xilinx Corporation Device 9041 (prog-if 01 [16450])
	Subsystem: Xilinx Corporation Device 0007
	Control: I/O- Mem- BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx-
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Interrupt: pin A routed to IRQ 109
	NUMA node: 0
	Region 0: Memory at e6600000 (32-bit, non-prefetchable) [virtual] [size=64K]
	Capabilities: <access denied>
	Kernel driver in use: xdma
	Kernel modules: xdma
```
 1) Navigate to `cd sw/py/`
 2) In ConfigScript.py, you can adapt the scheme paramters. Most importantly, set log_message_columns to the number of columns (number of columns = 2**poly degree / 128). Make sure to use a proper bitstream or run the implementation again using Vivado.
 3) After setting up ConfigScript.py, execute `python3 ConfigScript.py`
 4) Then navigate to the dma dirctory through `cd ../dma/` and execute `python3 gen_mem_for_orion.py`
 5) Launch Vitis and choose an empty Vitis workspace folder, e.g. `sw/vitis/vitis_workspace`
 6) Go to `File -> New -> Platform Project`. Give a name and click `Next`
 7) Click `Browse...` and select the desired bitstream file. Make sure the selected bitstream matches step 2. Click `Finish`
 8) Go to `File -> New -> Application Project`. Click `Next`, select the platform you just created and press `Next`
 9) Give a name, click `Next` twice and choose `Empty Application (C)`. Click `Finish`
10) Double-click on `lscript.ld` and increase stack and heap size to 0x4000 and 0x1000, respectively. Save the file.
11) In the Application Project, right-click on `src/` folder, select `Properties -> c/c++ general -> Paths and Symbols -> Source Location -> Link Folder ...`
12) Give a folder name like `fpga_mb`, check `link folder in the file system`, click `Browse` and select the `sw/fpga_dma/` folder.
13) Click `OK -> Apply and Close`
14) Build the project (e.g. `Ctrl+b`)
15) Open a serial terminal to observe the FPGA output via UART. Execute `sw/dma/runU280Terminal.sh`
16) Flash the FPGA by right-clicking on the Application Project, then `Run As -> Launch Hardware -> Proceed`
16) Now, the FPGA performs memory tests. If the tests pass, the serial output will look like below
```
===================
Startup Successful!
===================

-> Now, send the data via PCI. Then, press any key+enter to continue...
``` 
17) The FPGA is now ready to receive data from PCI if you see the output below. Do not press anything yet in this terminal since we first need to send the data via PCI.
```
Waiting for FPGA execution. After FPGA is done, press 'Enter' to continue...
```
18) To send data via PCI, open a new terminal, go to `sw/dma/` and execute
```sudo python3 pci_transaction.py.py```.
19) This will print the text below and wait for the FPGA to start execution. Do not press any key in this terminal!
```
Wait for FPGA execution. After FPGA is done, press 'Enter' to continue ...
```
20) Switch to the serial terminal with the FPGA output and press any key + enter. The FPGA will perform the tests and prints the following:
```
============= RESULTS ===========
MT Root Commit: === 
[   0] 0253A239213C1CDFD54C3E53DF7522B48310B25FC7B637C0B36411752319954A
MT Root Proximity (PR0): === 
[   0] 850317E5950893CCB057F1D1057D07753F48F0AF225C9FAA3C48372D41975C27
MT Root Consistency (PR1): === 
[   0] E0815ED7FB7A050A8D2A04B91E5548306967191F94424DD17E55CC6FABA10F07
=================================

-> Done. Receive the data via PCI. Then, press 0+enter to re-run, any other key ends program
```
This output shows the Merkle root nodes. In addition, timing information using the RTL clock is printed.

21) Switch to the other terminal and press any key to continue the python script. This will receive the FPGA's memory content via PCI. Then, press "Y"+enter to perform the comparison with the reference output. 
22) If the comparison succeeds, you should see:
```
======================
==== EVERYTHING OK ===
======================
```

-----

# Contributors

Florian Hirner - `florian.hirner@tugraz.at`

Florian Krieger - `florian.krieger@tugraz.at`

Constantin Piber - `constantin.piber@student.tugraz.at`

Sujoy Sinha Roy - `sujoy.sinharoy@tugraz.at`

The Authors are affiliated with the [Institute of Information Security](https://www.isec.tugraz.at/), [Graz University of Technology](https://www.tugraz.at/), Austria

-----

# License

[![License: MIT](https://img.shields.io/badge/License-GNU-green.svg)](https://opensource.org/licenses/GNU)

Copyright (c) 2025 @ CryptoEngineering Group, ISEC, TU Graz 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.