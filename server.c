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

#define BUFFSIZE 1518

#include <stdio.h>
#include <stdint.h>

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
    }

    // Se é um pacote DHCP Discover
    if(buff1[6] != 0xFF && buff1[7] != 0 && buff1[8] != 0 && buff1[9] != 0 && buff1[10] != 0 && buff1[11] != 0){


        uint16_t destination_port = (buff1[36] << 8) + buff1[37];

        if(destination_port == 0x67){
            
        }
    }
}