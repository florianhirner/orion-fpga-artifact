#!/bin/bash
tool_path=../tools

h2cchannels=$1
c2hchannels=$2
if [ "$#" -ne 2 ];then
  echo "usage $0 <no:of h2cchannels> <no:of c2hchannels>"
  exit -1
fi
rm hw_log_h2c.txt
rm hw_log_c2h.txt
echo "h2cchannels $h2cchannels"
echo "c2hchannels $c2hchannels"
# TODO add device check
## u250
h2c=/dev/xdma0_h2c_0
c2h=/dev/xdma0_c2h_0
#h2c=/dev/xdma0_bypass_h2c_0
#c2h=/dev/xdma0_bypass_c2h_0
## u280
#h2c=/dev/xdma1_h2c_0
#c2h=/dev/xdma1_c2h_0


iter=1

#jmax=16
jmax=1

out_h2c=hw_log_h2c.txt
out_c2h=hw_log_c2h.txt

for ((i=0;i<h2cchannels;i++))
do
	# TODO add device check
	h2c=/dev/xdma0_h2c_$i
	c2h=/dev/xdma0_c2h_$i
	#h2c=/dev/xdma0_bypass_h2c_$i
	#c2h=/dev/xdma0_bypass_c2h_$i
	
	#byte=64
	byte=4096
	
	for ((j=0; j<=jmax; j++)) do
		echo "** HW H2C = $h2c bytecount = $byte and iteration = $iter and j = $j" | tee -a $out_h2c
		$tool_path/performance -d $h2c -c $iter -s $byte | tee -a $out_h2c
		byte=$(($byte*2))
		echo ""
	done
	echo ""
	
	wait
	
	#byte=64
	byte=4096
	for ((j=0; j<=jmax; j++)) do
		echo "** HW C2H = $c2h bytecount = $byte and iteration = $iter and j = $j" | tee -a $out_c2h
		$tool_path/performance -d $c2h -c $iter -s $byte | tee -a  $out_c2h
		byte=$(($byte*2))
		echo ""
	done
	echo ""

done
