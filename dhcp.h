#include<stdint.h>
#define ETH_LEN	1518
#define ETHER_TYPE	0x0800
#define DEFAULT_IF	"eth0"

enum ports {
    BOOTPS = 67,
    BOOTPC = 68
};

struct eth_hdr {
	uint8_t dst_addr[6];
	uint8_t src_addr[6];
	uint16_t eth_type;
};

struct ip_hdr {
	uint8_t vhl;		/* version, header length */
	uint8_t tos;			/* type of service */
	int16_t len;			/* total length */
	uint16_t id;			/* identification */
	int16_t off;			/* fragment offset field */
	uint8_t ttl;			/* time to live */
	uint8_t proto;			/* protocol */
	uint16_t sum;			/* checksum */
	uint8_t src[4];			/* source address */
	uint8_t dst[4];			/* destination address */
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct dhcp_hdr {
	uint8_t dp_op;			/* packet opcode type */
	uint8_t dp_htype;		/* hardware addr type */
	uint8_t dp_hlen;		/* hardware addr length */
	uint8_t  dp_hops;		/* gateway hops */
	uint32_t dp_xid;		/* transaction ID */
	uint16_t dp_secs;		/* seconds since boot began */
	uint16_t dp_flags;
	uint8_t dp_ciaddr[4];		/* client IP address */
	uint8_t dp_yiaddr[4];		/* 'your' IP address */
	uint8_t dp_siaddr[4];		/* server IP address */
	uint8_t dp_giaddr[4];		/* gateway IP address */
	uint8_t dp_chaddr[16];		/* client hardware address */
	uint8_t dp_legacy[192];
	uint8_t dp_magic[4]; 										//240 bytes
	uint8_t dp_options[275];	/* options area */
} __attribute__((packed));

union udp_packet_payload {
	uint8_t data[1472];
	struct dhcp_hdr dhcp;
};

struct udp_packet {
	struct ip_hdr iphdr;
	struct udp_hdr udphdr;
	union udp_packet_payload payload;
};

union packet_u {
	struct ip_hdr ip;
	struct udp_packet udp;
};

struct eth_frame_s {
	struct eth_hdr ethernet;
	union packet_u payload;
};

union eth_buffer {
	struct eth_frame_s cooked_data;
	uint8_t raw_data[ETH_LEN];
};
