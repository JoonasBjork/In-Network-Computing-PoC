/*
 * XDP Proof of Concept
 *
 * The current implementation uses a single shared BPF_MAP_TYPE_ARRAY, which contains one struct.
 * The struct contains the average value, number of packets, and a bpf_spin_lock 'mutex'.
 * All atomic operations should use this spin lock using the bpf_spin_lock/bpf_spin_unlock helper functions. 
*/

#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h> 
#include <linux/if_ether.h> 
#include <arpa/inet.h> 
#include <linux/ip.h>
#include <linux/udp.h>

// The number of packets taken in a single average
#define NUM_OF_PACKETS (__u8)10

// The structure of the CBOR payload
struct cbor_struct {
  __u8 array;
  __u8 operation;
  __u8 value;
};

// Needs to be packed or compiler aligns bytes
#pragma pack(1)
struct coaphdr {
  __u8 ver_type_len;
  __u8 code;
  __u16 message_id;
  __u64 token;
  __u8 ones;
};

// The data structure in the BPF_MAP_TYPE_ARRAY
struct avg_counter {
	__u32 packet_count;
  __u32 total;
  struct bpf_spin_lock mutex;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct avg_counter);
	__uint(max_entries, 1);
  // __uint(pinning, LIBBPF_PIN_BY_NAME); // If pinned, the map is retained after the eBPF program has been unloaded. 
} xdp_avg_map SEC(".maps");

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
  bpf_printk("Received new packet");

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Check that the packet size is large enough for eth+ip+udp+CoAP+CBOR payload
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct coaphdr) + sizeof(struct cbor_struct) > data_end) {
    bpf_printk("Passing packet with too few bytes\n");
    return XDP_PASS;
  }

  // Create ETH header struct
  struct ethhdr *eth = data; 
  __u16 h_proto = eth->h_proto; 

  // Check that packet uses IPv4
  if(h_proto != htons(ETH_P_IP)) {
    bpf_printk("Passing IPV6 packet\n");
    return XDP_PASS;
  }

  // Create IP header struct
  struct iphdr* ip_hdr = data + sizeof(struct ethhdr);
  __u8 ip_proto = ip_hdr->protocol;

  // Check that IP proto is UDP
  if (ip_proto != (__u8)17) {
    bpf_printk("Passing non-UDP packet. Protocol: %u\n", (unsigned int)ip_proto);
    return XDP_PASS;
  }

  // Create cbor payload struct
  struct cbor_struct* cbor_payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct coaphdr);

  // Print out each byte of the CoAP payload
  for (unsigned int i = 0; (void*)cbor_payload + i < data_end && i < 500; i++) {
    bpf_printk("cbor byte: %x", *((unsigned char *)cbor_payload + i));
  }

  // Check that the first byte indicates an array
  if ((cbor_payload->array >> 4) != (__u8)8) {
    bpf_printk("Coap payload is not an array\n");
    return XDP_PASS;
  }

  // If the operation is 1, the value should be aggregated. Otherwise pass the packet.
  if (cbor_payload->operation == 1) {
    bpf_printk("Operation is 1, processing in eBPF");
  } else {
    bpf_printk("Passing to the higher layer with operation: %u", cbor_payload->operation);
    return XDP_PASS;
  }

  struct avg_counter *avg_map;

  // Access the first index in the map
  __u32 key = 0;
  avg_map = bpf_map_lookup_elem(&xdp_avg_map, &key);

  if (!avg_map) {
    bpf_printk("avg_map is null");
    return XDP_ABORTED;
  }

  // Packet count in the map before
  bpf_printk("Start packet_count: %u", avg_map->packet_count);
  bpf_printk("Start total: %u", avg_map->total);

  __u8 max_packets_reached = 0;
  __u32 average;

  // ** Start atomic section **
  bpf_spin_lock(&avg_map->mutex);

  // Increment map values accordingly
  avg_map->packet_count++;
  avg_map->total += cbor_payload->value;

  if (avg_map->packet_count >= NUM_OF_PACKETS) {
    
    // Save the average value
    max_packets_reached = 1;
    average = avg_map->total / NUM_OF_PACKETS;

    // Reset the map
    avg_map->packet_count = 0;
    avg_map->total = 0;
  }
  bpf_spin_unlock(&avg_map->mutex);
  // ** Atomic section ends **


  bpf_printk("New packet_count: %u", avg_map->packet_count);
  bpf_printk("New total: %u", avg_map->total);

  if (max_packets_reached) {
    // Set the operation to 3 (=average) and the value to the average
    cbor_payload->operation = (__u8)3;
    cbor_payload->value = (__u8)average;

    // How much the payload should be adjusted and what direction
    int payload_delta = (__u64)data_end - (__u64)cbor_payload - sizeof(struct cbor_struct);

    // Set the CoAP payload to be exactly the size of cbor_struct bytes to only send the operation and the average
    if (payload_delta != 0) {
      bpf_printk("Adjusting packet tail by %i", payload_delta);
      __u32 err = bpf_xdp_adjust_tail(ctx, payload_delta);
      if (err) {
        bpf_printk("Error in bpf_xdp_adjust_tail");
        return XDP_ABORTED;
      }
    }

    bpf_printk("Passing packet with average: %u based on %u packets\n", average, NUM_OF_PACKETS);
    return XDP_PASS;
  }

  bpf_printk("Dropping aggregated packet!\n\n");
  return XDP_DROP;
}

// Disregard this licence. A licence is sometimes required by the verifier. 
char _license[] SEC("license") = "GPL";