#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>  //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h> //definicao de protocolos
#include <arpa/inet.h> //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados
#include "checksum.h"

#define BUFFSIZE 1518
#define MAC_SRC {0xa4, 0x1f, 0x72, 0xf5, 0x90, 0x7f}

unsigned char buff2[BUFFSIZE]; // buffer de saida

void monta_ipv4(uint8_t *src_ip, uint8_t *dest_ip) {
    uint8_t temp[20];
    uint16_t ret;

    // ip version && IHL (4 && 5)
    temp[0] = 0x45;
    
    // type of service
    temp[1] = 0x00;

    // Total Lenght 350
    temp[2] = 0x01;
    temp[3] = 0x5e;

    // Identification
    temp[4] = 0xfe;
    temp[5] = 0xb7;

    // Flags & Fragment offset 0x4000
    temp[6] = 0x40;
    temp[7] = 0x00;

    // TTL 64
    temp[8] = 0x40;

    // Protocol UDP: 17
    temp[9] = 0x11;

    // Checksum 
    temp[10] = 0x00;
    temp[11] = 0x00;

    // Source Address 10.32.143.24
    temp[12] = src_ip[0];
    temp[13] = src_ip[1];
    temp[14] = src_ip[2];
    temp[15] = src_ip[3];

    // Destination Address 10.32.143.32 (escolhido aleatoriamente)
    temp[16] = dest_ip[0];
    temp[17] = dest_ip[1];
    temp[18] = dest_ip[2];
    temp[19] = dest_ip[3];

    ret = in_cksum((unsigned short *)temp, 20);

    // Coloca checksum no header
    temp[10] = ret >> 8;
    temp[11] = ret;

    memcpy(buff2+14, temp, 20);

    // printf("buff2: \n");
    // for (int i = 0; i < sizeof(buff2); i++) {
    //     printf("%.2x ", buff2[i]);
    // }
    // printf("\n");
}

void monta_udp(uint8_t *src_port, uint8_t *dest_port) {
    uint8_t temp[8];
    uint16_t ret;

    // porta origem
    temp[0] = src_port[0];
    temp[1] = src_port[1];

    // porta destino
    temp[2] = dest_port[0];
    temp[3] = dest_port[1];

    // length: 330
    temp[4] = 0x01;
    temp[5] = 0x4a;

    // Checksum 
    temp[6] = 0x00;
    temp[7] = 0x00;

    ret = in_cksum((unsigned short *)temp, 8);

    // Coloca checksum no header 
    temp[6] = ret >> 8;;
    temp[7] = ret;

    memcpy(buff2+34, temp, 8);

    // printf("buff2: \n");
    // for (int i = 0; i < sizeof(buff2); i++) {
    //     printf("%.2x ", buff2[i]);
    // }
    // printf("\n");
}

void monta_bootp(uint8_t *src_ip, uint8_t *dest_ip, uint8_t *dest_mac){
    uint8_t temp[322] = {0};

    // Message Type
    temp[0] = 0x02;

    // Hardware Type
    temp[1] = 0x01;

    // Hardware Address Length
    temp[2] = 0x06;

    // Hops
    temp[3] = 0x00;

    // ID
    temp[4] = 0x3e;
    temp[5] = 0xfc;
    temp[6] = 0x5b;
    temp[7] = 0xc3;

    // Seconds elapsed
    temp[8] = 0x00;
    temp[9] = 0x00;

    // Boop flags
    temp[10] = 0x00;
    temp[11] = 0x00;

    // Client IP address:
    temp[12] = 0x00;
    temp[13] = 0x00;
    temp[14] = 0x00;
    temp[15] = 0x00;

    // Your IP Address
    temp[16] = dest_ip[0];
    temp[17] = dest_ip[1];
    temp[18] = dest_ip[2];
    temp[19] = dest_ip[3];

    // Next Server IP Address
    temp[20] = src_ip[0];
    temp[21] = src_ip[1];
    temp[22] = src_ip[2];
    temp[23] = src_ip[3];
    
    // Gateway IP Address
    temp[24] = src_ip[0];
    temp[25] = src_ip[1];
    temp[26] = src_ip[2];
    temp[27] = src_ip[3];

    // Client MAC Address
    temp[28] = dest_mac[0];
    temp[29] = dest_mac[1];
    temp[30] = dest_mac[2];
    temp[31] = dest_mac[3];
    temp[32] = dest_mac[4];
    temp[33] = dest_mac[5];

    // Client HW Address Padding
    temp[34] = 0x00;
    temp[35] = 0x00;
    temp[36] = 0x00;
    temp[37] = 0x00;
    temp[38] = 0x00;
    temp[39] = 0x00;
    temp[40] = 0x00;
    temp[41] = 0x00;
    temp[42] = 0x00;
    temp[43] = 0x00;

    // Server host name (not given)
    for (int i = 0; i < 64; i++) {
        temp[i + 44] = 0x00;
    }
    
    // Boot file name (not given)
    for (int i = 0; i < 128; i++) {
        temp[i + 108] = 0x00;
    }
    
    // Magic Cookie
    temp[235] = 0x63;
    temp[236] = 0x82;
    temp[237] = 0x53;
    temp[238] = 0x63;

    // DHCP Message Type (Offer)
    temp[239] = 0x35;
    temp[240] = 0x01;
    temp[241] = 0x02;

    // Subnet Mask
    temp[242] = 0x01;
    temp[243] = 0x04;
    temp[244] = 0xff;
    temp[245] = 0xff;
    temp[246] = 0xff;
    temp[247] = 0x00;

    // Renewal Time Value
    temp[248] = 0x3a;
    temp[249] = 0x04;
    temp[250] = 0x00;
    temp[251] = 0x00;
    temp[252] = 0x38;
    temp[253] = 0x40;

    // Rebinding Time Value
    temp[254] = 0x3b;
    temp[255] = 0x04;
    temp[256] = 0x00;
    temp[257] = 0x00;
    temp[258] = 0x62;
    temp[259] = 0x70;

    // IP Address Lease Time
    temp[260] = 0x33;
    temp[261] = 0x04;
    temp[262] = 0x00;
    temp[263] = 0x00;
    temp[264] = 0x70;
    temp[265] = 0x80;

    // DHCP Server Identifier
    temp[266] = 0x36;
    temp[267] = 0x04;
    temp[268] = 0x0a;
    temp[269] = 0x28;
    temp[270] = 0x30;
    temp[271] = 0xc8;

    // Router
    temp[272] = 0x03;
    temp[273] = 0x04;
    temp[274] = src_ip[0];
    temp[275] = src_ip[1];
    temp[276] = src_ip[2];
    temp[277] = src_ip[3];

    // Domain Name
    temp[278] = 0x0f;
    temp[279] = 0x12;
    sprintf(temp+280, "xupinga.server.br");

    // Domain Name Server
    temp[298] = 0x06;
    temp[299] = 0x04;
    temp[300] = src_ip[0];
    temp[301] = src_ip[1];
    temp[302] = src_ip[2];
    temp[303] = src_ip[3];

    // Netbios over TCP/IP Server
    temp[304] = 0x2c;
    temp[305] = 0x04;
    temp[306] = 0x00;
    temp[307] = 0x00;
    temp[308] = 0x00;
    temp[309] = 0x00;

    // End
    temp[310] = 0xff;

    // printf("Teste monta_udp\nBuff2:\n");
    // for (int i = 0; i < sizeof(temp); i++) {
    //     printf("[%d]:%.2x ",i , temp[i]);
    // }
    // printf("\n");

    memcpy(buff2+42, temp, 311);
}

int main(){
    // Atencao!! Confira no /usr/include do seu sisop o nome correto
    // das estruturas de dados dos protocolos.

    unsigned char buff1[BUFFSIZE]; // buffer de recepcao

    int sockd;
    int on;
    struct ifreq ifr;

    uint8_t cont = 0;
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
       printf("Erro na criacao do socket.\n");
       exit(1);
    }

	// O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
	strcpy(ifr.ifr_name, "enp4s0");

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
        printf("erro no ioctl!");
        
	ioctl(sockd, SIOCGIFFLAGS, &ifr);

	ifr.ifr_flags |= IFF_PROMISC;

	ioctl(sockd, SIOCSIFFLAGS, &ifr);

    // Cria socket para mandar msg
    int sockFd = 0;
    int retValue = 0;
    struct sockaddr_ll destAddr;
    short int etherTypeT = htons(0x8200);
    
    /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
    destAddr.sll_family = htons(PF_PACKET);
    destAddr.sll_protocol = htons(ETH_P_ALL);
    destAddr.sll_halen = 6;
    destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados. Eh necessario conferir este valor. */

    if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
    
        // Se é um pacote DHCP Discover
        if(buff1[6] != 0xFF && buff1[7] != 0 && buff1[8] != 0 && buff1[9] != 0 && buff1[10] != 0 && buff1[11] != 0){

            uint16_t destination_port = (buff1[36] << 8) + buff1[37];

            if(destination_port == 0x0043){   // Se é pacote DHCP para o servidor

                printf("achei dhcp\n");

                uint8_t dhcp_type = buff1[284];
                uint8_t mac_src[6] = MAC_SRC;

                switch(dhcp_type){
                    case 0x01:                     // quando for dhcp discovery manda um offer
                        printf("é discovery\n");
                        
                        memcpy(&(destAddr.sll_addr), mac_src, sizeof(mac_src));

                        for (int i = 0; i < 6; i++) {   // buffer de saida recebe mac destino e origem
                            buff2[i] = buff1[i + 6];
                            buff2[i+6] = mac_src[i];
                        }

                        // Ethernet type
                        buff2[12] = 0x08;
                        buff2[13] = 0x00;

                        uint8_t src_ip[4] = {0x0a, 0x20, 0x8f, 0x18};
                        uint8_t dest_ip[4] = {0x0a, 0x20, 0x8f, 0x45};

                        monta_ipv4(src_ip, dest_ip);

                        uint8_t src_port[2] = {0x00, 0x43};
                        uint8_t dest_port[2] = {0x00, 0x44};

                        monta_udp(src_port, dest_port);

                        monta_bootp(src_ip, dest_ip, mac_src);

                        sendto(sockd, buff2, sizeof(buff2), 0x0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll));
                    break;

                    default:
                    break;
                }
                
            }
        }
    }
}