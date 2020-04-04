#include <netinet/in.h>
struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct node {
	int info;
	struct route_table_entry *table_entry;
	struct node *left;
	struct node *right;
};

void rtable_read(struct node *tree);
uint32_t convertIpToInt(char *ip);
struct node *newNode(int info, struct route_table_entry *rtable_entry);