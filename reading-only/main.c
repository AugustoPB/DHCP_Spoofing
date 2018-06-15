/*--------------------------------------------------------*/
/* DHCP Spoofer - Captura pacotes ethernet e quebra eles  */
/* até o nivel da aplicação DHCP, ignorando outros pacots */
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
/* as estruturas de dados do header dos protocolos                  */

#include <net/if.h>  // estrutura ifr
#include <netinet/ether.h> // header ethernet
#include <netinet/in.h> // definicao de protocolos
#include <arpa/inet.h> // funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> // tipos de dados

#include <unistd.h> // exec
#include <ifaddrs.h> // Interfaces disponiveis

#define BUFFSIZE 1518
#define DEBUG 1

#ifndef NET_PACKET_H
#define NET_PACKET_H
struct sockaddr_ll {
    unsigned short sll_family;
    unsigned short sll_protocol;
    int            sll_ifindex;
    unsigned short sll_hatype;
    unsigned char  sll_pkttype;
    unsigned char  sll_halen;
    unsigned char  sll_addr[8];
};
#endif /* NET_PACKET_H */

/**
 * Buffer de recepção de dados
 * Utilizados para ler o retorno de recv
 */
unsigned char raw_in_buff[BUFFSIZE]; // buffer de recepcao

/**
 * Buffer de saida de dados
 * Utilizados para responder requisições DHCP
 */
unsigned char raw_out_buff[BUFFSIZE]; // buffer de recepcao

/**
 * Esta variavel tem um string de no maximo 10 chars contendo o
 * nome da interface (ex: eth0) atual utilizada no computador.
 * É inicializada na função main
 */
char * interface_selecionada;

/**
 * Estas variaveis guardam o IP e MAC da interface selecionada.
 */
char self_ip_address[4];
char self_mac_address[6];

/**
 * Indice do raw_socket utilizado para receber/enviar dados
 */
int sockfd;

/**
 * Struct com dados da interface atual, inicializada no main.
 *
 * Site com detalhes dos parametros e dados contidos:
 *  http://man7.org/linux/man-pages/man7/netdevice.7.html
 */
struct ifreq ifr;

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
 * Essa função é chamada sempre que um pacote DHCP pode ser respondido
 *
 * Se o pacote recebido for Discover, dhcp_tp será 2, indicando que precisa responder com OFFER
 * Se for Request, tipo será 5, indicando que a resposta deve ser um ACK
 *
 */
void reply_dhcp(int dhcp_tp, char * hostname, char transaction_id[4], char target_mac_address[6], char requested_ip_address[4]) {
    struct sockaddr_ll socket_address;
    struct ifreq if_idx;

    printf("----> Respondendo");
    if (dhcp_tp == 2) {
        printf(" com offer\n");
    } else if (dhcp_tp == 5) {
        printf(" com ack\n");
    } else {
        printf(" com message type %d\n", dhcp_tp);
    }

    /* Seta o indice da interface no socket */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface_selecionada, 10);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
    }
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;

    /* Set target of message */
    memcpy(socket_address.sll_addr, target_mac_address, 6);

    /* Fill up structure */
    memset(raw_out_buff, BUFFSIZE, 1);

    /* Efectively send the message */
    if (sendto(sockfd, raw_out_buff, BUFFSIZE, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        printf("Erro: Nao foi possivel responder a requisicao\n");
    }
}

/**
 * Helper function - Verificar se um dado mac address (6 bytes) é broadcast (0xFFFFFF)
 */
int is_broadcast_mac(char target[6]) {
    return ((target[0] & 0xFF) == 0xFF && (target[1] & 0xFF) == 0xFF && (target[2] & 0xFF) == 0xFF && (target[3] & 0xFF) == 0xFF && (target[4] & 0xFF) == 0xFF && (target[5] & 0xFF) == 0xFF);
}

/**
 * Helper function - Coloca o MAC address de uma interface em um buffer
 *
 * @param char* interface - O nome da interface com um \0 no final
 * @param char** buffer - Deve ter no minimo 6 bytes, senão vai causar Segmentation Fault
 * @return int - Retorna 0 em caso de sucesso, ou um numero positivo de erro caso contrario.
 */
int get_interface_mac_address(char * interface, char ** buffer_ptr) {
    char fname[256];
    char mac_strings[18];
    snprintf(fname, 256, "/sys/class/net/%s/address", interface);
    FILE * file;
    int i, j = 0;
    if (file = fopen(fname, "r")) {
        for (i = 0; i<18; i++) {
            char c = fgetc(file);
            if (c != '\0' && c != '\n') {
                mac_strings[j++] = (c == ':')?'\0':c;
            } else {
                break;
            }
        }
        fclose(file);
    } else {
        printf("COULD NOT OPEN MAC ADDRESS FILE DESCRIPTOR\n");
        return 2;
    }
    // The MAC file must fill our buffer, otherwise our value is obviously wrong.
    if (j != 17) {
        printf("ADDRESS SIZE DOES NOT COMPLY: %d\n", j);
        return 1;
    }
    // Convert mac_strings to individual bytes in the buffer.
    char * write_to = *buffer_ptr;
    for (i=0;i<6;i++) {
        char * target = &mac_strings[i*3];
        write_to[i] = (char)((int)strtol(target, NULL, 16));
    }
    return 0;
}

/**
 * Helper function - Coloca o IP address do socket atual em um buffer
 *
 * @param char* interface - O nome da interface com um \0 no final
 * @param char* buffer - Deve ter no minimo 4 bytes, senão vai causar Segmentation Fault
 * @return int - Retorna 0 em caso de sucesso, ou um numero positivo de erro caso contrario.
 */
int get_interface_ip_address(char * interface, char ** buffer_ptr) {
    char * write_to = *buffer_ptr;
    //printf("Buffer has:\n");
    //printf("%c%c\n", write_to[0], write_to[1]);
    struct ifreq if_addr;
    if_addr.ifr_addr.sa_family = AF_INET;
    strncpy(if_addr.ifr_name, interface, 10);
    if(ioctl(sockfd, SIOCGIFADDR, &if_addr) < 0) {
        printf("SIOCGIFPADDR\n");
        return 0;
    }
    memcpy(write_to, if_addr.ifr_addr.sa_data+2, 4);
    return 1;
}

/**
 * Helper function - Printa um endereço mac de uma interface no formato FF:FF:FF:FF:FF
 *
 * @param string interface Nome da interface para printar
 */
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
 *
 * @return int - 0 (zero) em caso falso, 1 (um) em caso verdadeiro (match).
 */
int is_origin_mac(char origin[6]) {
    char * this_mac = (char *)self_mac_address;
    this_mac[0] == origin[0]+1; // Isso nos garante o return 0 no caso de nao saber this_mac.
    if (get_interface_mac_address(interface_selecionada, &this_mac) != 0) {
        return 0;
    }
    int i;
    //printf("Comparando mac %02x:%02x:%02x com %02x:%02x:%02x\n",this_mac[0] & 0xFF, this_mac[1] & 0xFF, this_mac[2] & 0xFF,origin[0] & 0xFF, origin[1] & 0xFF, origin[2] & 0xFF);
    for (i=0;i<6;i++) {
        if ((origin[i] & 0xFF) != (this_mac[i] & 0xFF)) {
            return 0;
        }
    }
    return 1;
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

/**
 * Funcao chamada quando um DHCP Discover passar pela rede.
 */
void on_dhcp_discover(char * data, int data_length, char transaction_id[4], char client_mac_address[6]) {
    if ((data[0] & 0xFF) != 0x63 || (data[1] & 0xFF) != 0x82 || (data[2] & 0xFF) != 0x53 || (data[3] & 0xFF) != 0x63) {
        printf("[DHCP Invalido] Inicio do DHCP: %02x %02x %02x %02x\n", data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF, data[3] & 0xFF);
        return;
    }
    char dhcp_message_type;
    char requested_ip_address[4] = {192, 168, 1, 179};
    char hostname[16+1] = "sem_nome";
    char parameter_request_list[99+1] = "";
    char option;
    int option_length;
    int address;
    int options_added = 0;
    int i;

    printf("    [DHCP] Discover - Options:\n");

    for (address = 7; address < data_length; address++) {
        option = data[address] & 0xFF; // First byte is unique identifier
        option_length = (data[address+1] & 0xFF); // Second byte is size
        if (option == 0x35) { // DHCP Message Type
            options_added++;
            if (option_length == 0x01) {
                dhcp_message_type = data[address+2] & 0xFF;
            }
            printf("\n\n\n\n\n");
            printf("     Message Type: %d\n", (int)dhcp_message_type & 0xFF);
        } else if (option == 0x32) { // Requested Ip Address
            options_added++;
            if (option_length == 0x04) {
                memcpy(requested_ip_address, data+address+2, 4);
            }
            printf("     Requested Ip: %d.%d.%d.%d\n", requested_ip_address[0] & 0xFF, requested_ip_address[1] & 0xFF, requested_ip_address[2] & 0xFF, requested_ip_address[3] & 0xFF);
        } else if (option == 0x0c) { // Host Name
            options_added++;
            if (option_length < 16) {
                memcpy(hostname, data+address+2, option_length);
                hostname[option_length] = '\0';
            } else {
                memcpy(hostname, data+address+2, 16);
                hostname[16] = '\0';
            }
            printf("     Hostname    : %s\n", hostname);
        } else if (option == 0x37) { // Parameter Request List
            options_added++;
            if (option_length < 99) {
                memcpy(parameter_request_list, data+address+2, option_length);
                parameter_request_list[option_length] = '\0';
            } else {
                memcpy(parameter_request_list, data+address+2, 99);
                hostname[99] = '\0';
            }
            printf("     Parameters  :");
            for(i=0;i<100;i++) {
                if ((parameter_request_list[i] & 0xFF) == 0) {
                    break;
                } else {
                    printf(" %02x", parameter_request_list[i] & 0xFF);
                }
            }
            printf("\n");
        } else if ((option & 0xFF) == 255 || option == 0) { // END
            break;
        } else {
            printf("     Unkown option id: %d (0x%02x)\n", option & 0xFF, option & 0xFF);
            option_length = 0;
        }
        address += 1+option_length;
    }
    reply_dhcp(5, hostname, transaction_id, client_mac_address, requested_ip_address);
}

/**
 * Funcao chamada quando um DHCP Request passar pela rede.
 */
void on_dhcp_request(char * data, int data_length, char transaction_id[4], char client_mac_address[6]) {
    if ((data[0] & 0xFF) != 0x63 || (data[1] & 0xFF) != 0x82 || (data[2] & 0xFF) != 0x53 || (data[3] & 0xFF) != 0x63) {
        printf("[DHCP Invalido] Inicio do DHCP: %02x %02x %02x %02x\n", data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF, data[3] & 0xFF);
        return;
    }
    char dhcp_message_type;
    char requested_ip_address[4] = {192, 168, 1, 179};
    char server_ip[4] = {1, 1, 1, 1};
    char hostname[16+1] = "sem_nome";
    char parameter_request_list[99+1] = "";
    char option;
    int option_length;
    int address;
    int options_added = 0;
    int i;

    printf("    [DHCP] Request - Options:\n");

    for (address = 7; address < data_length; address++) {
        option = data[address] & 0xFF; // First byte is unique identifier
        option_length = (data[address+1] & 0xFF); // Second byte is size
        if (option == 0x35) {
            options_added++;
            if (option_length == 0x01) {
                dhcp_message_type = data[address+2] & 0xFF;
            }
            printf("     Message Type: %d\n", dhcp_message_type);
        } else if (option == 0x36) {
            options_added++;
            if (option_length == 0x04) {
                memcpy(server_ip, data+address+2, 4);
            }
            printf("     Server Ip   : %d.%d.%d.%d\n", server_ip[0] & 0xFF, server_ip[1] & 0xFF, server_ip[2] & 0xFF, server_ip[3] & 0xFF);
        } else if (option == 0x32) {
            options_added++;
            if (option_length == 0x04) {
                memcpy(requested_ip_address, data+address+2, 4);
            }
            printf("     Requested Ip: %d.%d.%d.%d\n", requested_ip_address[0] & 0xFF, requested_ip_address[1] & 0xFF, requested_ip_address[2] & 0xFF, requested_ip_address[3] & 0xFF);
        } else if (option == 0x0c) {
            options_added++;
            if (option_length < 16) {
                memcpy(hostname, data+address+2, option_length);
                hostname[option_length] = '\0';
            } else {
                memcpy(hostname, data+address+2, 16);
                hostname[16] = '\0';
            }
            printf("     Hostname    : %s\n", hostname);
        } else if (option == 0x37) { // Parameter Request List
            options_added++;
            if (option_length < 99) {
                memcpy(parameter_request_list, data+address+2, option_length);
                parameter_request_list[option_length] = '\0';
            } else {
                memcpy(parameter_request_list, data+address+2, 99);
                hostname[99] = '\0';
            }
            printf("     Parameters  :");
            for(i=0;i<100;i++) {
                if ((parameter_request_list[i] & 0xFF) == 0) {
                    break;
                } else {
                    printf(" %02x", parameter_request_list[i] & 0xFF);
                }
            }
            printf("\n");
        } else if ((option & 0xFF) == 255 || option == 0) { // END
            break;
        } else {
            printf("     Unkown option id: %d (0x%02x)\n", option & 0xFF, option & 0xFF);
        }
        address += 1+option_length;
    }
    reply_dhcp(2, hostname, transaction_id, client_mac_address, requested_ip_address);
}

/**
 * Funcao chamada quando uma aplicação DNS passa pela rede,
 * Esta função é responsavel por chamar as funções on_dhcp_request ou on_dhcp_request
 */
int on_bootstrap_received(char * bootstrap, int data_length) {
    int i;
    char dhcp_message_type_length;
    char dhcp_message_type;
    if ((bootstrap[240] & 0xFF) == 0x35) {
        dhcp_message_type_length = bootstrap[241];
        dhcp_message_type = bootstrap[242];
    } else {
        printf("   [Bootp] Unknown DHCP option start: %02x with %d bytes\n",(bootstrap[240] & 0xFF), (bootstrap[241] & 0xFF));
        return 0;
    }
    char transaction_id[4];
    char client_mac_address[6];

    memcpy(transaction_id, bootstrap+4, 4);
    memcpy(client_mac_address, bootstrap+28, 6);

    printf("   [Bootp] Transaction: 0x");
    printf("%02x%02x%02x%02x - ", transaction_id[0] & 0xFF, transaction_id[1] & 0xFF, transaction_id[2] & 0xFF, transaction_id[3] & 0xFF);
    printf("Type: %02x ", bootstrap[242]) & 0xFF;

    if ((dhcp_message_type_length != 1) || ((bootstrap[240] & 0xFF) != 0x35)) {
        printf(" - Invalido\n");
        printf("   Message Type Length: %d - Divisor (0x35): %02x - Starting data below\n", dhcp_message_type_length & 0xFF, bootstrap[240] & 0xFF);
        printf("   >");
        for( i = 0; i < 20; i ++) {
            printf(" %02x", bootstrap[236+i] & 0xFF);
        }
        printf("\n");
    } else if (dhcp_message_type == 1) {
        printf("(DHCP Disc)\n");
        on_dhcp_discover(bootstrap+236, data_length-236, transaction_id, client_mac_address);
    } else if (dhcp_message_type == 3) {
        printf("(DHCP Req)\n");
        on_dhcp_request(bootstrap+236, data_length-236, transaction_id, client_mac_address);
    } else if (dhcp_message_type == 5) {
        printf("(DHCP Ack)\n");
    } else {
        printf("(Unknown)\n");
        return 0;
    }
    return 1;
}

/**
 * Funcao chamada quando um pacote UDP com 20 bytes passar pela rede,
 * Esta função é responsavel por chamar a função on_bootstrap_received(...)
 * Vale lembrar que aqui, embora o conteudo de 20 bytes indique DHCP, isso não é 100% certo ainda.
 */
void on_udp_received(char * udp_data, int data_length) {
    uint16_t source_port = (udp_data[0] & 0xFF << 8) + udp_data[1] & 0xFF;
    uint16_t target_port = (udp_data[2] & 0xFF << 8) + udp_data[3] & 0xFF;
    uint16_t total_length = (udp_data[4] & 0xFF << 8) + udp_data[5] & 0xFF;
    printf("  [UDP] Tam: %d", total_length);
    printf(" - Portas de: %d para %d\n", target_port, source_port);
    on_bootstrap_received(udp_data + 8, data_length - 8);
}

/**
 * Funcao chamada quando um pacote IPv4 passar pela rede
 * Esta função é responsavel por chamar a função on_udp_received(...)
 */
void on_ipv4_broadcast(char * ipv4_data, int data_length) {
    int ip_version = ipv4_data[0] & 0xf0 >> 2;
    int header_length = (ipv4_data[0] & 0x0f)*4;
    int total_length = (ipv4_data[2] & 0xFF << 8) + ipv4_data[3] & 0xFF;
    if (ip_version != 4) {
        printf("Erro: Pacote IPv4 nao deveria ter versao %d\n", ip_version);
        printf("Inicio do IPv4: %02x %02x %02x %02x %02x %02x\n", ipv4_data[0] & 0xFF, ipv4_data[1] & 0xFF, ipv4_data[2] & 0xFF, ipv4_data[3] & 0xFF, ipv4_data[4] & 0xFF, ipv4_data[5] & 0xFF);
        exit(1);
    }
    if (header_length == 20) {
        //printf("IPv4 with %d bytes, in which %d bytes is header\n", total_length, header_length);
        //printf("origin: %d.%d.%d.%d\n", ipv4_data[12] & 0xFF, ipv4_data[13] & 0xFF, ipv4_data[14] & 0xFF, ipv4_data[15] & 0xFF);
        //printf("target: %d.%d.%d.%d\n", ipv4_data[16] & 0xFF, ipv4_data[17] & 0xFF, ipv4_data[18] & 0xFF, ipv4_data[19] & 0xFF);
        printf(" [IPv4] Tam: %d - ", data_length);
        printf("Orig: %d.%d.%d.%d - ", ipv4_data[12] & 0xFF, ipv4_data[13] & 0xFF, ipv4_data[14] & 0xFF, ipv4_data[15] & 0xFF);
        printf("Alvo: %d.%d.%d.%d\n", ipv4_data[16] & 0xFF, ipv4_data[17] & 0xFF, ipv4_data[18] & 0xFF, ipv4_data[19] & 0xFF);
        on_udp_received(ipv4_data + 20, data_length - 20);
    } else {
        // Não é DHCP, pois dhcp não tem campo opcoes no ip
    }
}

/**
 * Funcao chamada quando um pacote Ethernet passar pela rede
 * Esta função é responsavel por chamar a função de on_ipv4_broadcast(...)
 */
void on_ethernet_package_received(char target[6], char origin[6], ethernet_content_type type, char * ethernet_data, int data_length) {
    if (type == Eth_IPv4) {
        if (is_broadcast_mac(target)) {
                printf("[Ethernet] ");
            printf("Tam: %d - MAC Origem: ", data_length);

            if (is_origin_mac(origin)) {
                printf("(Self)\n");
            } else {
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n", origin[0] & 0xFF, origin[1] & 0xFF, origin[2] & 0xFF, origin[3] & 0xFF, origin[4] & 0xFF, origin[5] & 0xFF);
            }
            on_ipv4_broadcast(ethernet_data + 14, data_length - 14);
            printf("\n");
        }
        // debug // if (data_length > 130) { printf("Origin: %2x:%2x:%2x:%2x:%2x:%2x \n\n", target[0] & 0xFF,target[1] & 0xFF,target[2] & 0xFF,target[3] & 0xFF,target[4] & 0xFF,target[5] & 0xFF); }
    }
}

int main(int argc,char *argv[]) {
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
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
            if (c > 10 && c != ' ' && c != '\n' && c != '\r' && c != 27 && c != 91) {
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

    /* Preencher e printar IP e MAC da interface atual */
    char * write_to;
    write_to = (char *) self_ip_address;
    get_interface_ip_address(interface_selecionada, &write_to);

    write_to = (char *) self_mac_address;
    get_interface_mac_address(interface_selecionada, &write_to);

    printf("Interface: \"%s\" - Ip: %d.%d.%d.%d - ", interface_selecionada, self_ip_address[0] & 0xFF, self_ip_address[1] & 0xFF, self_ip_address[2] & 0xFF, self_ip_address[3] & 0xFF);
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", self_mac_address[0] & 0xFF, self_mac_address[1] & 0xFF, self_mac_address[2] & 0xFF, self_mac_address[3] & 0xFF, self_mac_address[4] & 0xFF, self_mac_address[5] & 0xFF);

    /* Setar a interface em modo promiscuo */
    strcpy(ifr.ifr_name, interface_selecionada);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        printf("Erro ao setar a interface em modo promiscuo (no ioctl)\n");
        exit(1);
    }
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sockfd, SIOCSIFFLAGS, &ifr);

    /* Aloca variaveis para chamar que lida com ethernet */
    char target[6];
    char origin[6];
    int length;
    int type_or_length;

    /* Leitura dos pacotes */
    printf("Iniciando processo de leitura de pacotes\n----------------------------------------\n\n");
    while (1) {
        length = recvfrom(sockfd,(char *) &raw_in_buff, sizeof(raw_in_buff), 0x0, NULL, NULL);
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
    close(sockfd);
}
