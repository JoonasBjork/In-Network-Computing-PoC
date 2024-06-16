# In-Network-Computing PoC

This repository contains the code for the proof-of-concept application that was developed as a part of the bachelor's thesis titled IIoT Data Integration with In-Network Computing.

## Installation on a Multipass VM

### Create a new VM

multipass launch docker --name name-of-vm 

### Install dependencies

```
sudo apt-get install clang llvm gcc
sudo apt-get install libelf-dev libpcap-dev build-essential
sudo apt-get install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt-get install libbpf-dev
```

### Install network utilities (ifconfig)

```
sudo apt-get install net-tools
```

### Install XDP-loader to load the eBPF program into the kernel

```
git clone https://github.com/xdp-project/xdp-tools.git
sudo apt-get install m4
cd xdp-tools
make
sudo make install
```

### Link asm-generic to asm to use <asm/header.h>

```
cd /usr/include
sudo ln -s asm-generic asm
```

### On Debian if Stubs-32.h is missing (Not tested)

```
sudo apt-get install libc6-dev-i386
```

### To view installed eBPF programs and maps

```
sudo apt-get install bps
```

## Hooking the progam and running it

```
source unload_load.sh
```

The script first prints all attached eBPF programs and unloads the programs attached to the **lo** interface. It then compiles the C program and uses XDP-loader to hook it onto the **lo** interface. 

## Inspecting the program

### Reading prints

```
source tracepipe.sh
```

The script monitors the `/sys/kernel/debug/tracing/trace_pipe` trace buffer, which receives the output of `bpf_printk()`.

### View what traffic is received by the lo interface

```
sudo tcpdump -X -i lo
```

## Creating traffic

### Python script to create a CBOR payload

```
pip install cbor2
python create_cbor_payload.py
```

### Sending the CBOR payload

[The CoAP-cli library tool](https://github.com/coapjs/coap-cli) is used to send a CoAP packet

```
cat payload1.cbor | coap -c post coap://localhost
```

