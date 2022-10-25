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

    memcpy(buff2+15, temp, 20);
    printf("buff2: %s", buff2);

}

void monta_udp(uint8_t *src_port, uint8_t *dest_port){
    
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

	// recepcao de pacotes
	while (1) {
   		recv(sockd,(char *) &buff1, sizeof(buff1), 0x0);
    
        // Se é um pacote DHCP Discover
        if(buff1[6] != 0xFF && buff1[7] != 0 && buff1[8] != 0 && buff1[9] != 0 && buff1[10] != 0 && buff1[11] != 0){

            uint16_t destination_port = (buff1[36] << 8) + buff1[37];

            if(destination_port == 0x0043){   // Se é pacote DHCP para o servidor

                uint8_t dhcp_type = buff1[284];
                uint8_t mac_src[6] = MAC_SRC;

                switch(dhcp_type){
                    case 0x01:                     // quando for dhcp discovery manda um offer
                        for (int i = 0; i < 6; i++) {   // buffer de saida recebe mac destino e origem
                            buff2[i] = buff1[i + 6];
                            buff2[i+6] = mac_src[i];
                        }

                        // Ethernet type
                        buff2[13] = 0x08;
                        buff2[14] = 0x00;

                        uint8_t src_ip[4] = {0x0a, 0x20, 0x8f, 0x18};
                        uint8_t dest_ip[4] = {0x0a, 0x20, 0x8f, 0x20};

                        monta_ipv4(src_ip, dest_ip);

                        uint8_t src_port[2] = {0x00, 0x43};
                        uint8_t dest_port[2] = {0x00, 0x44};
                        monta_udp(src_port, dest_port);
                    break;

                    default:
                    break;
                }
                
            }
        }
    }
}