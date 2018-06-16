#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static uint32_t ipchksum(void *packet);
void fill_eth_hdr(union eth_buffer *buffer_u, unsigned char srcMAC[6], unsigned char dstMAC[6]);
void fill_ip_hdr(union eth_buffer *buffer_u, unsigned char srcIP[4], unsigned char dstIP[4], uint16_t length);
void fill_udp_hdr(union eth_buffer *buffer_u, uint16_t src_port, uint16_t dst_port, uint16_t length);
void fill_dhcp_hdr(union eth_buffer *buffer_u ,int dhcp_tp);
