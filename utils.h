#include <netinet/in.h>
void mac_frumos(u_char *mac);
void ip_frumos(uint32_t ip);
uint16_t ip_checksum(void* vdata,size_t length);
