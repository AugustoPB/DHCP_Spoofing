#include "dhcp.h"
#include "dhcp_reply.h"

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

void fill_ip_hdr(union eth_buffer *buffer_u, unsigned char srcIP[4], unsigned char dstIP[4], uint16_t length)
{
	uint32_t sum;
	/* fill the IP frame header */
	//buffer_u->cooked_data.payload.ip.ver = ; // IP version (4)
	//buffer_u->cooked_data.payload.ip.hl = ; // HDR length (20 bytes)
	buffer_u->cooked_data.payload.ip.vhl = 0x45;
	buffer_u->cooked_data.payload.ip.tos = 0x00; // Don't care here
	buffer_u->cooked_data.payload.ip.len = htons(length); // Total packet length 349
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
	buffer_u->cooked_data.payload.udp.udphdr.src_port = htons(src_port); // Set the reception port
	buffer_u->cooked_data.payload.udp.udphdr.dst_port = htons(dst_port); // Set the destination port
	buffer_u->cooked_data.payload.udp.udphdr.udp_chksum = 0x00; // Don't care the checksum
	buffer_u->cooked_data.payload.udp.udphdr.udp_len = htons(length); // Total packet length 329
}

void fill_dhcp_hdr(union eth_buffer *buffer_u ,int dhcp_tp)
{
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_op = 2; // Boot operation (2 = reply)
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_htype = 0x01; // Hardware type (0x01 = ethernet)
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_hlen = 6; // Lenght of MAC address
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_hops = 0; // Don't care
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_xid // Client generate this
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_secs = 0; // Don't care
	buffer_u->cooked_data.payload.udp.payload.dhcp.dp_flags = 0x0000; // Unicast
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_ciaddr // Client IP
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_yiaddr, buffer_u->cooked_data.payload.ip.dst, 4); // New client's IP
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_siaddr, buffer_u->cooked_data.payload.ip.src, 4); // My IP
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_giaddr, 0, 6); // Don't care
	//buffer_u->cooked_data.payload.udp.payload.dhcp.dp_chaddr // Client MAC
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_legacy, 0, sizeof(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_legacy)); // Don't care
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_magic,"\x63\x82\x53\x63",4); // Client cares :)

	// Clean all
	memset(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options, 0, sizeof(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options));
	// DHCP message type
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options, (dhcp_tp == 2)? "\x35\x01\x02" : "\x35\x01\x05", 3);
	// Server IP
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+3, "\x36\x04", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+5, buffer_u->cooked_data.payload.ip.src, 4);
	// Lease time
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+9, "\x33\x04\x00\x01\x38\x80", 6);
	// Subnet mask
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+15, "\x01\x04\xff\xff\xff\x00", 6);
	// Broadcast
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+21, "\x1c\x04", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+23, buffer_u->cooked_data.payload.ip.src, 3);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+26, "\xff", 1);
	// Renewal time
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+27, "\x3a\x04\x00\x05\x46\x00", 6);
	// Rebinding time
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+33, "\x3b\x04\x00\x09\x3a\x80", 6);
	// Router
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+39, "\x03\x04", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+41, buffer_u->cooked_data.payload.ip.src, 4);
	// Domain Name = portoalegre.pucrsnet.br
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+45, "\x0f\x18portoalegre.pucrsnet.br\x00", 26);
	// DNS
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+71, "\x06\x08", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+73, "\x0a\x28\x30\x0a", 4);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+77, "\x0a\x28\x30\x0b", 4);
	// NetBios
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+81, "\x2c\x08", 2);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+83, "\x0a\x28\x30\x0a", 4);
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+87, "\x0a\x28\x30\x0b", 4);
	// End
	memcpy(buffer_u->cooked_data.payload.udp.payload.dhcp.dp_options+91, "\xff", 1);

}
