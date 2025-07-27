modprobe -r xdma
echo 1 > /sys/bus/pci/devices/0000\:8d\:00.0/remove
echo 1 > /sys/bus/pci/rescan

./load_driver.sh
./run_test.sh
