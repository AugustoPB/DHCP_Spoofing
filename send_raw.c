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
#include "dhcp_reply.h"

char this_mac[6];
unsigned char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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

	fill_eth_hdr(&buffer_u, my_mac, bcast_mac);
	fill_ip_hdr(&buffer_u, my_ip, my_ip, 360);
	fill_udp_hdr(&buffer_u, BOOTPS, BOOTPC, 340);
	fill_dhcp_hdr(&buffer_u, 5);

	//printf("%ld\n", buffer_u.cooked_data.payload);
	//buffer_u.cooked_data.payload.ip.len = sizeof(buffer_u.cooked_data.payload.)


	/* Send it.. */
	memcpy(socket_address.sll_addr, bcast_mac, 6);
	if (sendto(sockfd, buffer_u.raw_data, 374, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	return 0;
}
