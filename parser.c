#include "parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
uint32_t convertIpToInt(char *ip) {
	unsigned int byte3, byte2, byte1, byte0;
	sscanf(ip, "%u.%u.%u.%u", &byte3, &byte2, &byte1, &byte0);

	uint32_t rez = (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0;
	return rez;
}


struct node *newNode(int info, struct route_table_entry *rtable_entry) {
	struct node* node = (struct node *) malloc(sizeof(struct node));
	node->info = info;
	node->table_entry = malloc(sizeof(struct route_table_entry));
	node->table_entry = rtable_entry;
	node->left = NULL;
	node->right = NULL;
	return node;
}


void rtable_read(struct node *original_tree) {
	FILE *in;
	in = fopen("rtable.txt", "rt");
	if(!in) {perror("Fisierul rtable nu poate fi deschis"); return;}

	char buffer[50];
	while(fgets(buffer, 50, in)) {
		buffer[strlen(buffer) - 1] = '\0';
		char *prefix = strtok(buffer, " ");
		char *next_hop = strtok(NULL, " ");
		char *mask_ip = strtok(NULL, " ");
		char *interface = strtok(NULL, " ");
		if(strcmp(prefix, next_hop) == 0)
			continue;
		struct route_table_entry *elem = malloc(sizeof(struct route_table_entry));
		elem->prefix = convertIpToInt(prefix);
		elem->next_hop = convertIpToInt(next_hop);
		elem->mask = convertIpToInt(mask_ip);
		elem->interface = atoi(interface);

		uint32_t ip_mask = elem->mask;
		//mask este cel mai din stanga 1
		uint32_t mask = (1 << 31);
		struct node* tree = original_tree;
		while(mask != 0) {

			if((mask & elem->prefix) == 0) {
				if(tree->left == NULL) {
					if(ip_mask == (1 << 31))
						tree->left = newNode(0, elem);
					else
						tree->left = newNode(0, NULL);
				} else {
					if(ip_mask == (1 << 31))
						tree->left->table_entry = elem;
					else
						tree->left->table_entry = NULL;
				}
				tree = tree->left;
			} else {

				if(tree->right == NULL) {
					if(ip_mask == (1 << 31))
						tree->right = newNode(1, elem);
					else
						tree->right = newNode(1, NULL);
				} else {
					if(ip_mask == (1 << 31))
						tree->right->table_entry = elem;
					else
						tree->right->table_entry = NULL;
				}
				tree = tree->right;
			}
			mask >>= 1;
			ip_mask <<= 1;
		}
		
	}
	fclose(in);
}
