#pragma once
#include <netinet/in.h>
struct arp_packet {

	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_address_len;
	uint8_t protocol_address_len;
	uint16_t op_code;
	uint8_t source_mac[6];
	uint32_t source_ip;
	uint8_t dest_mac[6];
	uint32_t dest_ip;

}__attribute__((packed));

struct arp_table {
	uint32_t ip;
	uint8_t mac[6];
	int interface;
}__attribute__((packed));

struct arp_table *search_in_arptable(struct arp_table *arptable, int size, uint32_t ip);