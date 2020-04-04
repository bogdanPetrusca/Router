#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "skel.h"
#include "parser.h"
#include "utils.h"
#include "queue.h"
#include "list.h"
#include "arp.h"

struct route_table_entry *get_best_route(struct node *tree, uint32_t ip_dest) {
	uint32_t mask = (1 << 31);
	struct route_table_entry *last_found= NULL;
	while(1) {

		if(tree->table_entry != NULL) 
			last_found = tree->table_entry;

		if((mask & ip_dest) == 0)
			tree = tree->left;
		else 
			tree = tree->right;
		mask >>= 1;
		if(tree == NULL ||  mask == 0)
			break;
	}
	return last_found;
}


void send_arp_reply(packet m) {
	packet send;
	send.interface = m.interface;
	send.len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	struct ether_header *send_eth_hdr = (struct ether_header *)send.payload;
	struct arp_packet *send_arp_hdr = (struct arp_packet *)(send.payload + sizeof(struct ether_header));

	struct ether_header *m_eth_hdr = (struct ether_header *)m.payload;
	struct arp_packet *m_arp_hdr = (struct arp_packet *)(m.payload + sizeof(struct ether_header));

	send_eth_hdr->ether_type = htons(0x806);
	get_interface_mac(m.interface, send_eth_hdr->ether_shost);
	memcpy(send_eth_hdr->ether_dhost, m_eth_hdr->ether_shost, 6);

	send_arp_hdr->hardware_type = htons(1);
	send_arp_hdr->protocol_type = htons(0x800);
	send_arp_hdr->hardware_address_len = 6;
	send_arp_hdr->protocol_address_len = 4;
	send_arp_hdr->op_code = htons(0x2);

	get_interface_mac(m.interface, send_arp_hdr->source_mac);
	memcpy(send_arp_hdr->dest_mac, m_arp_hdr->source_mac, 6);

	send_arp_hdr->source_ip = htonl(convertIpToInt(get_interface_ip(m.interface)));
	send_arp_hdr->dest_ip = m_arp_hdr->source_ip;

	send_packet(send.interface, &send);
}

void send_arp_request(struct route_table_entry *best_route) {

	packet req;
	req.len = sizeof(struct ether_header) + sizeof(struct arp_packet);
	req.interface = best_route->interface;

	struct ether_header *req_eth_hdr = (struct ether_header *)req.payload;
	struct arp_packet *req_arp_hdr = (struct arp_packet *)(req.payload + sizeof(struct ether_header));

	uint8_t *mac_aux = malloc(sizeof(char) * 6);
	get_interface_mac(req.interface, mac_aux);

	req_eth_hdr->ether_type = htons(0x806);
	memcpy(req_eth_hdr->ether_shost, mac_aux, sizeof(char) * 6);
	memset(req_eth_hdr->ether_dhost, 0xff, sizeof(char) * 6);

	req_arp_hdr->hardware_type = htons(0x1);
	req_arp_hdr->protocol_type = htons(0x800);
	req_arp_hdr->hardware_address_len = 6;
	req_arp_hdr->protocol_address_len = 4;
	req_arp_hdr->op_code = htons(0x1);



	memcpy(req_arp_hdr->source_mac, mac_aux, sizeof(char) * 6);
	memset(req_arp_hdr->dest_mac, 0, sizeof(char) * 6);

	req_arp_hdr->source_ip = htonl(convertIpToInt(get_interface_ip(req.interface)));
	req_arp_hdr->dest_ip = htonl(best_route->next_hop);


	send_packet(req.interface, &req);
}

void send_icmp_packet(packet m, uint8_t err_code) {

	m.len = sizeof(struct ether_header) + sizeof(struct iphdr)+ sizeof(struct icmphdr);

	struct ether_header *eth_hdr = (struct ether_header *)m.payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

	u_char *mac_aux = malloc(sizeof(char) * 6);
	memcpy(mac_aux, eth_hdr->ether_shost, sizeof(char) * 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(char) * 6);
	memcpy(eth_hdr->ether_dhost, mac_aux, sizeof(char) * 6);


	ip_hdr->protocol = 1;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->id = htons(getpid());
	ip_hdr->ttl = 255;
	ip_hdr->tot_len = htons(m.len - sizeof(struct ether_header));

	uint32_t ip_aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = ip_aux;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

	icmp_hdr->type = err_code;
	icmp_hdr->code = 0;
	icmp_hdr->un.echo.id = htons(getpid());
	icmp_hdr->un.echo.sequence = htons(1);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof (struct icmphdr));

	send_packet(m.interface, &m);

}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	setvbuf(stdout, NULL, _IONBF, 0);
	init();
	queue q = queue_create();
	struct node *rtree = newNode(-1, NULL);
	rtable_read(rtree);
	struct arp_table *arptable = malloc(sizeof(struct arp_table) * 20);
	int arptable_size = 0;


	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

		if(htonl(convertIpToInt(get_interface_ip(m.interface))) == ip_hdr->daddr) {
			if(ip_hdr->protocol == 1) {
				send_icmp_packet(m, 0);
				continue;
			}
		}

		if(eth_hdr->ether_type == htons(0x806)) {
			struct arp_packet *arp_hdr = (struct arp_packet *)(m.payload + sizeof(struct ether_header));
			if(arp_hdr->op_code == htons(0x1)) {
				struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				struct arp_table arp_entry;

				arp_entry.ip = ip_hdr->saddr;
				memcpy(arp_entry.mac, eth_hdr->ether_shost, 6);

				arptable[arptable_size++] = arp_entry;

				send_arp_reply(m);
			} else {
				struct arp_table arp_entry;
				arp_entry.ip = arp_hdr->source_ip;
				memcpy(arp_entry.mac, arp_hdr->source_mac, sizeof(struct arp_table));
				//ip_frumos(arp_entry.ip);
				//mac_frumos(arp_entry.mac);
				arptable[arptable_size++] = arp_entry;
				
				queue q_aux = queue_create();
				while(!queue_empty(q)) {
					packet p = *(packet *)queue_deq(q);
					
					struct ether_header *p_eth_hdr = (struct ether_header *)p.payload;
					struct iphdr *p_ip_hdr = (struct iphdr *)(p.payload + sizeof(struct ether_header));

					struct arp_table *arp = search_in_arptable(arptable, arptable_size, p_ip_hdr->daddr);
					
					if(arp != NULL) {
						

						//get_interface_mac(p.interface, p_eth_hdr->ether_shost);
						memcpy(p_eth_hdr->ether_dhost, arp->mac, 6);
						rc = send_packet(p.interface, &p);
						DIE(rc < 0, "get_message");	
					} else {
						queue_enq(q_aux, &p);
					}
				}
				while(!queue_empty(q_aux))
					queue_enq(q, queue_deq(q_aux));
			}
		} else {
			//pachet normal


			if(ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				printf("crapa la checksum\n");
				continue;
			}

			if(ip_hdr->ttl <= 1) {
				send_icmp_packet(m, 11);
				printf("crapa la ttl\n");
				continue;
			}

			(ip_hdr->ttl)--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum (ip_hdr, sizeof (struct iphdr));


			
			struct route_table_entry *best_route = get_best_route(rtree, ntohl(ip_hdr->daddr));
			if(best_route == NULL) {
				send_icmp_packet(m, 3);
				printf("NU SE POATE GASI DEST\n");
				continue;
			}

			struct arp_table *arp = search_in_arptable(arptable, arptable_size, ip_hdr->daddr);
			
			if(arp == NULL) {

				packet *aux = malloc(sizeof(packet));
				memcpy(aux, &m, sizeof(packet));
				aux->interface = best_route->interface;
				queue_enq(q, aux);
				send_arp_request(best_route);

			} else {

				//get_interface_mac (best_route->interface, s_eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, arp->mac, 6);

				rc = send_packet(best_route->interface, &m);
				DIE(rc < 0, "get_message");
				
			}	
		}
	}
}
