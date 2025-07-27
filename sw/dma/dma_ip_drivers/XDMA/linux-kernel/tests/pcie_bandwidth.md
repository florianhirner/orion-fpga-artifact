\\ PCI WRITE BANDWIDTH

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 131072 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 131072, 488.607910

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 262144 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 262144, 830.084473

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 524288 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 524288, 897.747253

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 1048576 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 1048576, 1038.464478

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 2097152 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 2097152, 1045.432861

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 4194304 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 4194304, 1074.413208

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_to_device -d /dev/xdma0_h2c_0 -f tests/data/datafile_32M.bin -s 8388608 -a 8589934592 -c 1
/dev/xdma0_h2c_0 ** Average BW = 8388608, 1061.722168




\\ PCI READ BANDWIDTH

root@ipd005:/home/fhirner/Documents/dma_ip_drivers/XDMA/linux-kernel# ./tools/dma_from_device -d /dev/xdma0_c2h_0 -s 131072 -a 8589934592 -c 1
