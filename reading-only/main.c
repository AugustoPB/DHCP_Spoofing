/*--------------------------------------------------------*/
/* DHCP Spoofer - Captura pacotes ethernet e quebra eles  */
/* até o nivel da aplicação DHCP, ignorando outras        */
/*--------------------------------------------------------*/

/* Compiled with:
 *  gcc -o main main.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#include <unistd.h> // exec
#include <ifaddrs.h> // Interfaces disponiveis

#define BUFFSIZE 1518
#define DEBUG 1

unsigned char raw_in_buff[BUFFSIZE]; // buffer de recepcao

/**
 * Depois da inicializacao (main), esta variavel tem um string de no maximo 10 chars
 * contendo a interface (ex: eth0) atual utilizada no computador.
 */
char * interface_selecionada;

/**
 * Indice do raw_socket utilizado para receber/enviar dados
 */
int sockd;

/**
 * Struct com dados da interface atual, inicializada no main.
 *
 * Site com detalhes dos parametros e dados contidos:
 *  http://man7.org/linux/man-pages/man7/netdevice.7.html
 */
struct ifreq ifr;

/**
 * Inicio de um pacote ethernet, completamente inutil pois não estamos utilizando.
 * Vou remover em breve.
 */
typedef struct {
	char target[6];
	char source[6];
	char length[2];
} ethernet_packet_start;

/**
 * Enum do tipo de um pacote ethernet, para facilitar a filtragem.
 * Criei este enum para remover a ambiguidade do campo "type" no pacote ethernet.
 */
typedef enum {
	Eth_UNKNOWN,
	Eth_RAW_ETHERNET,
	Eth_IPv4,
	Eth_IPv6,
	Eth_ARP,
	Eth_IPX
} ethernet_content_type;

/**
 * Helper function - Verificar se um dado mac address (6 bytes) é broadcast (0xFFFFFF)
 */
int is_broadcast_mac(char target[6]) {
	return (target[0] & 0xff == 0xff && target[1] & 0xff == 0xff && target[2] & 0xff == 0xff && target[3] & 0xff == 0xff && target[4] & 0xff == 0xff && target[5] & 0xff == 0xff);
}

/** INCOMPLETE Helper function - Coloca o MAC address de uma interface em um buffer
 *
 * @param char* buffer - Deve ter no minimo 6 bytes, senão vai causar Segmentation Fault
 * @return int - Retorna 0 em caso de sucesso, ou um numero positivo de erro caso contrario.
 */
int get_interface_mac_address(char * interface, char ** buffer_ptr) {
    char fname[256];
    char mac_strings[18];
    snprintf(fname, 256, "/sys/class/net/%s/address", interface);
	//printf("\nDiscovering the mac of %s\n", fname);
    FILE * file;
    int i, j = 0;
    if (file = fopen(fname, "r")) {
		//printf("Content:\n");
        for (i = 0; i<18; i++) {
            char c = fgetc(file);
			//printf("%c", c);
            if (c != '\0' && c != '\n') {
                mac_strings[j++] = (c == ':')?'\0':c;
            } else {
                break;
            }
        }
		//printf("\n");
        fclose(file);
    } else {
		printf("Could not read file");
		return 2;
	}
    // The MAC file must fill our buffer, otherwise our value is obviously wrong.
    if (j != 17) {
		printf("FILE DOES NOT COMPLY: %d\n", j);
        return 1;
    }
    // Convert mac_strings to individual bytes in the buffer.
	char * buffer = *buffer_ptr;
    for (i=0;i<6;i++) {
		char * target = &mac_strings[i*3];
        buffer[i] = (char)((int)strtol(target, NULL, 16));
    }
	
  return 0;
}

int print_interface_mac_address(char * interface) {
	int i = 0;
	char buffer[7];
	char * ptr_buf = (char *)&buffer;
	get_interface_mac_address(interface, &ptr_buf);
	printf("%02x", buffer[0] & 0xFF);
	for (i=1;i<6;i++) {
		printf(":%02x", buffer[i] & 0xFF);
	}
}

/**
 * Helper function - Verifica se um MAC de 6 bytes é o da interface selecionada
 * @return int - 0 (zero) em caso falso, 1 (um) em caso verdadeiro (match).
 */
int is_origin_mac(char origin[6]) {
    char this_mac[6];
	char * ptr_mac = (char *)&this_mac;
    this_mac[0] == origin[0]+1; // Isso nos garante o return 0 no caso de nao saber this_mac.
    if (get_interface_mac_address(interface_selecionada, &ptr_mac) != 0) {
		return 0;
    }
    int i;
	//printf("Comparando mac %02x:%02x:%02x com %02x:%02x:%02x\n",this_mac[0] & 0xff, this_mac[1] & 0xff, this_mac[2] & 0xff,origin[0] & 0xff, origin[1] & 0xff, origin[2] & 0xff);
    for (i=0;i<6;i++) {
        if ((origin[i] & 0xff) != (this_mac[i] & 0xff)) {
            return 0;
        }
    }
    return 1;
}

/**
 * Funcao chamada quando um DHCP Discover passar pela rede
 */
void on_dhcp_discover(char * data, int data_length, char transaction_id[4], char client_mac_address[6]) {
	char request_ip_address[4];
	char host_name_length = data[250] & 0xff;
	char * host_name = (char *)malloc(sizeof(char) * (host_name_length+1));
	memcpy(request_ip_address, data+246, 4);
	memcpy(host_name, data+251, host_name_length);
	host_name[host_name_length] = '\0';
	//printf("[DHCP Disc] Client Name: \"%s\"", host_name);
	//printf(" - ClientMAC: %02x:%02x:%02x:%02x:%02x:%02x", client_mac_address[0] & 0xff, client_mac_address[1] & 0xff, client_mac_address[2] & 0xff, client_mac_address[3] & 0xff, client_mac_address[4] & 0xff, client_mac_address[5] & 0xff);
	//printf(" - IP address: %d.%d.%d.%d\n", request_ip_address[0] & 0xff, request_ip_address[1] & 0xff, request_ip_address[2] & 0xff, request_ip_address[3] & 0xff);
	free(host_name);
}

/**
 * Funcao chamada quando um DHCP Request passar pela rede
 */
void on_dhcp_request(char * data, int data_length, char transaction_id[4], char client_mac_address[6]) {
	char dhcp_server_identifier[4];
	char request_ip_address[4];
	char host_name_length = data[256] & 0xff;
	char * host_name = (char *)malloc(sizeof(char) * (host_name_length+1));

	memcpy(dhcp_server_identifier, data+245, 4);
	memcpy(request_ip_address, data+251, 4);
	memcpy(host_name, data+257, host_name_length);
	host_name[host_name_length] = '\0';

	//printf("[DHCP Requ] Client Name: \"%s\"", host_name);
	//printf(" - ClientMAC: %02x:%02x:%02x:%02x:%02x:%02x", client_mac_address[0] & 0xff, client_mac_address[1] & 0xff, client_mac_address[2] & 0xff, client_mac_address[3] & 0xff, client_mac_address[4] & 0xff, client_mac_address[5] & 0xff);
	//printf(" - IP address: %d.%d.%d.%d\n", request_ip_address[0] & 0xff, request_ip_address[1] & 0xff, request_ip_address[2] & 0xff, request_ip_address[3] & 0xff);
	free(host_name);
	/*printf("(id 0x%8x) ", (*((unsigned int *)transaction_id)) & 0xffffffff);
	printf("%d.%d.%d.%d requested by ", dhcp_server_identifier[0] && 0xff, dhcp_server_identifier[1] && 0xff, dhcp_server_identifier[2] && 0xff, dhcp_server_identifier[3] && 0xff);
	printf("%d.%d.%d.%d ", request_ip_address[0] && 0xff, request_ip_address[1] && 0xff, request_ip_address[2] && 0xff, request_ip_address[3] && 0xff);
	printf("(%s)\n", host_name);
	if (dhcp_message_type == 1) {
		on_dhcp_discover(dhcp_server_identifier, request_ip_address, host_name);
	}
	free(host_name);
*/
}

/**
 * Funcao chamada quando uma aplicação DNS passar pela rede,
 * Esta função é responsavel por chamar as funções on_dhcp_*
 */
int on_bootstrap_received(char * bootstrap, int data_length) {
	int i;
	char dhcp_message_type_length = bootstrap[241] & 0xff;
	char dhcp_message_type = bootstrap[242] & 0xff;
	char transaction_id[4];
	char client_mac_address[6];

	memcpy(transaction_id, bootstrap+4, 4);
	memcpy(client_mac_address, bootstrap+28, 6);

	if (dhcp_message_type_length != 1) {
		printf("Invalid DHCP: Message Type Length is %02x\n", dhcp_message_type_length);
		return 0;// can't be a valid DHCP
	}
	if (dhcp_message_type == 1) {
		printf("[Bootstrap] - Type: DHCP Discover - Transaction: 0x%08x\n", transaction_id);
		on_dhcp_discover(bootstrap+236, data_length-236, transaction_id, client_mac_address);
	} else if (dhcp_message_type == 3) {
		printf("[Bootstrap] - Type: DHCP Request - Transaction: 0x%08x\n", transaction_id);
		on_dhcp_request(bootstrap+236, data_length-236, transaction_id, client_mac_address);
	} else {
		printf("Invalid DHCP: Unknown DHCP message type: %d (0x%02x)\n", dhcp_message_type, dhcp_message_type);
		return 0;
	}
/*
		printf("Content: \n");
		int j = 0;
		for (i=230;i<280;i++) {
			if (i < 16 && j == 0) {
				if (i == 0) {
					printf("Starts with: %02x",  bootstrap[i] & 0xff);
				} else if (i != 15) {
					printf(" %02x",  bootstrap[i] & 0xff);
				} else {
					printf(" %02x\n",  bootstrap[i] & 0xff);
				}
			} else if (j == 0 && i > 26+8 && bootstrap[i] & 0xff != 0)  {
				i-=3;
				j = 1;
				printf("Non zero at %d:\n", i);
			}
			if (j == 1) {
				printf(" %02x",  bootstrap[i] & 0xff);
			}
		}
		printf("\n");
*/

	return 1;
}

/**
 * Funcao chamada quando um pacote UDP com 20 bytes passar pela rede,
 * Esta função é responsavel por chamar a função on_bootstrap_received(...)
 * Vale lembrar que aqui, embora o conteudo de 20 bytes indique DHCP, isso não é 100% certo ainda.
 */
void on_udp_received(char * udp_data, int data_length, char ethernet_mac_origin[6]) {
	uint16_t source_port = (udp_data[0] & 0xff << 8) + udp_data[1] & 0xff;
	uint16_t target_port = (udp_data[2] & 0xff << 8) + udp_data[3] & 0xff;
	uint16_t total_length = (udp_data[4] & 0xff << 8) + udp_data[5] & 0xff;
	printf("[UDP] - Tam: %d", total_length);
	printf(" - TargetPort: %d", target_port);
	printf(" - SourcePort: %d\n", source_port);
	on_bootstrap_received(udp_data + 8, data_length - 8);
}

/**
 * Funcao chamada quando um pacote IPv4 passar pela rede
 * Esta função é responsavel por chamar a função on_udp_received(...)
 */
void on_ipv4_broadcast(char * ipv4_data, int data_length, char ethernet_mac_origin[6]) {
	int ip_version = ipv4_data[0] & 0xf0 >> 2;
	int header_length = (ipv4_data[0] & 0x0f)*4;
	int total_length = (ipv4_data[2] & 0xff << 8) + ipv4_data[3] & 0xff;
	if (ip_version != 4) {
		printf("Erro: Pacote IPv4 nao deveria ter versao %d\n", ip_version);
		printf("Inicio do IPv4: 0x%2x 0x%2x 0x%2x 0x%2x 0x%2x 0x%2x\n", ipv4_data[0] & 0xff, ipv4_data[1] & 0xff, ipv4_data[2] & 0xff, ipv4_data[3] & 0xff, ipv4_data[4] & 0xff, ipv4_data[5] & 0xff);
		exit(1);
	}
	if (header_length == 20) {
		// todos pacotes DHCP tem 20 bytes e portanto nao usam o campo opcoes do ipv4
		//printf("IPv4 with %d bytes, in which %d bytes is header\n", total_length, header_length);
		//printf("origin: %d.%d.%d.%d\n", ipv4_data[12] & 0xff, ipv4_data[13] & 0xff, ipv4_data[14] & 0xff, ipv4_data[15] & 0xff);
		//printf("target: %d.%d.%d.%d\n", ipv4_data[16] & 0xff, ipv4_data[17] & 0xff, ipv4_data[18] & 0xff, ipv4_data[19] & 0xff);
		printf("[IPv4] - Tam: %d - ", data_length);
		printf("Origin: %d.%d.%d.%d - ", ipv4_data[12] & 0xff, ipv4_data[13] & 0xff, ipv4_data[14] & 0xff, ipv4_data[15] & 0xff);
		printf("Target: %d.%d.%d.%d\n", ipv4_data[16] & 0xff, ipv4_data[17] & 0xff, ipv4_data[18] & 0xff, ipv4_data[19] & 0xff);
		on_udp_received(ipv4_data + 20, data_length - 20, ethernet_mac_origin);
	}
}

/**
 * Funcao chamada quando um pacote Ethernet passar pela rede
 * Esta função é responsavel por chamar a função de on_ipv4_broadcast(...)
 */
void on_ethernet_package_received(char target[6], char origin[6], ethernet_content_type type, char * ethernet_data, int data_length) {
	if (type == Eth_IPv4) {
		if (is_broadcast_mac(target)) {
			if (is_origin_mac(origin)) {
				printf("[Self Ethernet]");
			} else {
				printf("[     Ethernet]");
			}
			printf(" - Tam: %d - MAC: ", data_length);
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n", origin[0] & 0xff, origin[1] & 0xff, origin[2] & 0xff, origin[3] & 0xff, origin[4] & 0xff, origin[5] & 0xff);
			on_ipv4_broadcast(ethernet_data + 14, data_length - 14, origin);
			printf("\n");
		}
		// debug // if (data_length > 130) { printf("Origin: %2x:%2x:%2x:%2x:%2x:%2x \n\n", target[0] & 0xff,target[1] & 0xff,target[2] & 0xff,target[3] & 0xff,target[4] & 0xff,target[5] & 0xff); }
	}
}

/**
 * Helper Function - Coloca em um buffer uma lista de todas as interfaces que estão disponiveis
 * Utilizada na inicialização para o usuario selecionar qual interface será utilizada
 */
void get_all_interfaces(int max_interface_length, int max_interfaces, char * buffer, int * length) {
	struct ifaddrs *addrs, *tmp;
	getifaddrs(&addrs);
	tmp = addrs;
	*length = 0;
	char * ptr = buffer;
	while (tmp) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
			memcpy(ptr, tmp->ifa_name, max_interface_length);
			ptr[max_interface_length - 1] = '\0';
			*length = (*length) + 1;
			ptr = ptr + max_interface_length;
			if (*length > max_interfaces) {
				break;
			}
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
}

int main(int argc,char *argv[]) {
	/* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
	/* htons: converte um short (2-byte) integer para standard network byte order. */
	if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		printf("Erro na criacao do socket.\n");
		exit(1);
	}
	int i, j, k;

	/* Mostra as interfaces para o usuario escolher: */
	char interfaces[16*10];
	memset(interfaces, 16*10-1, '\0');
	int interfaces_length = 0;
	get_all_interfaces(16, 10, interfaces, &interfaces_length);
	if (interfaces_length > 0) {
		printf("Existem %d interfaces disponiveis:\n\n", interfaces_length);
		for (i=0;i<interfaces_length;i++) {
			if (i*10 >= 16*10) {
				break;
			}
			//interfaces[i*10+8] = '\0';
			printf("[%d] ", i);
			int writing = 1;
			for (j=0;j<10;j++) {
				if (interfaces[i*16+j] == '\0') {
					writing = 0;
				}
				putchar((writing == 1) ? interfaces[i*16+j]:' ');
			}
			printf(" (MAC: ");
			print_interface_mac_address(&interfaces[i*16]);
			printf(")\n");
		}
		printf("\nEscolha a interface: ");
		char c = getchar();
		while (c == 10 || c <= '0' || c >= '9' || (c-'0') >= interfaces_length) {
			if (c > 10 && c != ' ' && c != '\n' && c != '\r') {
				printf("\nEscolha um valor valido: ");
			}
			c = getchar();
		}
		interface_selecionada = &interfaces[(c-'0')*16];
	} else {
		printf("Erro: Lista de interfaces nao foi encontrada\n");
		printf("Setado para o default\n");
		interface_selecionada = interfaces;
		memcpy(interfaces, "enp4s0", 8);
	}

	/* Setar a interface em modo promiscuo */
	printf("\nSetando a interface \"%s\" em modo promiscuo\n", interface_selecionada);
	strcpy(ifr.ifr_name, interface_selecionada);
	if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0) {
		printf("Erro ao setar a interface em modo promiscuo (no ioctl)\n");
		//exit(1);
	}
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	/* Aloca variaveis para chamar que lida com ethernet */
	char target[6];
	char origin[6];
	int length;
	int type_or_length;

	/* Leitura dos pacotes */
	printf("Iniciando processo de leitura de pacotes\n");
	while (1) {
   		length = recvfrom(sockd,(char *) &raw_in_buff, sizeof(raw_in_buff), 0x0, NULL, NULL);
		if (length <= 0) {
			printf("Recebido mensagem sem dados, algo esta errado\n");
		} else {
			type_or_length = (raw_in_buff[12] << 8) + raw_in_buff[13];
			ethernet_content_type type = Eth_UNKNOWN;
			if (type_or_length <= 1500) {
				type = Eth_RAW_ETHERNET;
			} else if (type_or_length == 0x0800) {
				type = Eth_IPv4;
			} else if (type_or_length == 0x0806) {
				type = Eth_ARP;
			} else if (type_or_length == 0x8137) {
				type = Eth_IPX;
			} else if (type_or_length == 0x86dd) {
				type = Eth_IPv6;
			}
			memcpy((void *) target, raw_in_buff, 6);
			memcpy((void *) origin, raw_in_buff+6, 6);
			on_ethernet_package_received(target, origin, type, raw_in_buff, length);
		}
	}
}
