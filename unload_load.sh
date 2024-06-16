#!/bin/bash
sudo bps
sudo xdp-loader unload lo -a
clang -I/usr/include/aarch64-linux-gnu  -O2 -g -Wall -target bpf -c xdp_poc.c -o xdp_poc.o 
sudo xdp-loader load -m skb -s xdp_pass lo xdp_poc.o  --pin-path /sys/fs/bpf/
sudo bps
# ping -4 localhost
