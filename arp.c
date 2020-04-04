#include "arp.h"
#include <stdlib.h>
struct arp_table *search_in_arptable(struct arp_table *arptable, int size, uint32_t ip) {
	struct arp_table *elem = NULL;
	for(int i = 0; i < size; i++)
		if(ip == arptable[i].ip) {
			elem = &arptable[i];
		}
	return elem;
} 