#!/bin/bash

#Compile BPF code
clang -O -target bpf -c /root/zux/fw/bpf/ingress/xdp.c -o /root/zux/fw/bpf/ingress/xdp_ingress.o
#clang -target bpf -g -O2 -c /root/zux/fw/bpf/egress/tc.c -o /root/zux/fw/bpf/egress/tc_egress.o


if [ $? -eq 0 ]; then
echo "XDP BPF program compiled successfully!"
else
echo "XDP BPF program compilation failed!"
exit 1
fi


#Build the Go program
go build

if [ $? -eq 0 ]; then
echo "Go program built successfully!"
else
echo "Go program build failed!"
exit 1
fi

#Run the executable
./xdp -iface enp3s0f1np1 