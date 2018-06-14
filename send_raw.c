#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "dhcp.h"

char this_mac[6];
unsigned char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static uint32_t ipchksum(void *packet)
{
	uint8_t *data = (uint8_t*)packet;
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)data[i] << 8) | (uint32_t)data[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum;
}

void fill_eth_hdr(union eth_buffer *buffer_u, unsigned char srcMAC[6], unsigned char dstMAC[6])
{
	/* fill the Ethernet frame header */
	memcpy(buffer_u->cooked_data.ethernet.dst_addr, dstMAC, 6); // Set the destination MAC
	memcpy(buffer_u->cooked_data.ethernet.src_addr, srcMAC, 6); // Set my MAC
	buffer_u->cooked_data.ethernet.eth_type = htons(ETHER_TYPE); // Set type
}

union eth_buffer fill_ip_hdr(union eth_buffer *buffer_u, unsigned char srcIP[4], unsigned char dstIP[4], uint16_t length)
{
	uint32_t sum;
	/* fill the IP frame header */
	buffer_u->cooked_data.payload.ip.ver = 0x4; // IP version (4)
	buffer_u->cooked_data.payload.ip.hl = 0x5; // HDR length (20 bytes)
	buffer_u->cooked_data.payload.ip.tos = 0x00; // Don't care here
	buffer_u->cooked_data.payload.ip.len = length; // Total packet length
	buffer_u->cooked_data.payload.ip.id = 0x00; // Don't care too
	buffer_u->cooked_data.payload.ip.off = 0x00; // Neither
	buffer_u->cooked_data.payload.ip.ttl = 0xff; // Full time to live
	buffer_u->cooked_data.payload.ip.proto = 0x11; // UDP protocol
	buffer_u->cooked_data.payload.ip.sum = 0x00; // First set 0 to calculate that
	memcpy(buffer_u->cooked_data.payload.ip.src, srcIP, 4); // Set my IP
	memcpy(buffer_u->cooked_data.payload.ip.dst, dstIP, 4); // Set the destination IP

	sum = (~ipchksum((void*)&buffer_u->cooked_data.payload.ip)) & 0xffff;
	buffer_u->cooked_data.payload.ip.sum = (sum&0xff) << 8 | (sum) >> 8; // Now set the properly checksum
}

void fill_udp_hdr(union eth_buffer *buffer_u, uint16_t src_port, uint16_t dst_port, uint16_t length)
{
	/* fill the UDP frame header */
	buffer_u->cooked_data.payload.udp.udphdr.src_port = src_port; // Set the reception port
	buffer_u->cooked_data.payload.udp.udphdr.dst_port = dst_port; // Set the destination port
	buffer_u->cooked_data.payload.udp.udphdr.udp_chksum = 0x00; // Don't care the checksum
	buffer_u->cooked_data.payload.udp.udphdr.udp_len = length; // Total packet length
}

void fill_dhcp_hdr(union eth_buffer *buffer_u ,int dhcp_tp)
{
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_op = 2; // Boot operation (2 = reply)
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_htype = 0x01; // Hardware type (0x01 = ethernet)
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_hlen = 6; // Lenght of MAC address
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_hops = 1; // Controll area (server responds with 1)
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_xid // Client generate this
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_secs = 0; // Don't socket_address
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_flags = 0x0000; // Unicast
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_ciaddr // Client IP
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_yiaddr, buffer_u->cooked_data.payload.ip.dst, 4); // New client's IP
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_siaddr, buffer_u->cooked_data.payload.ip.src, 4); // My IP
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_giaddr, 0, 6); // Don't care
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_chaddr // Client MAC
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_legacy, 0, sizeof(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_legacy)); // Don't care
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_magic // Client cares :)
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options, 0, sizeof(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options)); // Clean all
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options, (dhcp_tp == 2)? "\x35\x01\x02" : "\x35\x01\x05", 3); // DHCP message type

	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+3, "\x36\x04", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+5, buffer_u->cooked_data.payload.ip.src, 4); // My IP

	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+9, "\x33\x04\x00\x01\x38\x80", 6); // Lease time

	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+15, "\x01\x04\xff\xff\xff\x00", 6); // Subnet mask

	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+21, "\x1c\x04", 2); // Broadcast
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+23, buffer_u->cooked_data.payload.ip.src, 3); // Subnet mask













}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts, if_addr;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	unsigned char my_ip[4];
	unsigned char my_mac[6];
	union eth_buffer buffer_u;

	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");

	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(my_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* Get the IP address of the interface */
	if_addr.ifr_addr.sa_family = AF_INET;
	strncpy(if_addr.ifr_name, ifName, IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &if_addr) < 0)
		perror("SIOCGIFPADDR");
	memcpy(my_ip, if_addr.ifr_addr.sa_data+2, 4);

	printf("My IP: %d.%d.%d.%d\n",my_ip[0],my_ip[1],my_ip[2],my_ip[3]);

	printf("My MAC: %x:%x%x:%x:%x:%x\n", my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

	/* End of configuration. Now we can send data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */


	/* fill payload data */


	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, 1472, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	return 0;
}
