#include "sniffer.h"

int sniffer(uint8_t *buff1) {
    uint8_t cont = 0;

    uint16_t total = 0, arp = 0, ipv4 = 0, ipv6 = 0, icmp = 0, icmpv6 = 0, udp = 0, tcp = 0, dns = 0;

	
    if(buff1[0] == 0xa4 && buff1[1] == 0x1f && buff1[2] == 0x72 && buff1[3] == 0xf5 && buff1[4] == 0x90 && buff1[5] == 0x7f) {
        if(buff1[6] == 0xa4 && buff1[7] == 0x1f && buff1[8] == 0x72 && buff1[9] == 0xf5 && buff1[10] == 0x90 && buff1[11] == 0x14) {

            uint16_t eth_type;
            // Concatena os 2 bytes de tipo do Ethernet
            eth_type = (buff1[12] << 8) + buff1[13];

            switch (eth_type){
            case 0x0806:

                total++;
                arp++;

                printf("\nEthernet:\n");
                printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
                printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);

                printf("Tipo: 0x%.4x \nARP:\n", eth_type);

                uint16_t hw_addr_type;
                hw_addr_type = (buff1[14] << 8) + buff1[15];
                printf("    Hardware Address Type: ");
                switch (hw_addr_type){
                case 0x0001:
                    printf("    1 - Ethernet\n");
                    break;
                
                case 0x0006:
                    printf("    6 - IEEE 802 LAN\n");
                    break;
                
                default:
                    break;
                }
                
                uint16_t prot_addr_type = (buff1[16] << 8) + buff1[17];
                printf("    Protocol Address Type: %d - IPv4 (0x0800)\n", prot_addr_type);

                uint8_t hw_addr_len = buff1[18];
                printf("    Hardware Address Length: %d - for Ethernet/IEEE 802\n", prot_addr_type);

                uint8_t prot_addr_len = buff1[19];
                printf("    Protocol Address Length: %d - for IPv4\n", prot_addr_len);

                uint16_t op = (buff1[20] << 8) + buff1[21];
                printf("    Operation: ");
                switch (op){
                case 0x0001:
                    printf("    1 - Request\n");
                    break;
                
                case 0x0002:
                    printf("    2 - Reply\n");
                    break;
                
                default:
                    break;
                }

                printf("    Source Hardware Address: %x:%x:%x:%x:%x:%x\n", buff1[22],buff1[23],buff1[24],buff1[25],buff1[26],buff1[27]);
                printf("    Source Protocol Address: %d.%d.%d.%d\n", buff1[28],buff1[29],buff1[30],buff1[31]);
                printf("    Target Hardware Address: %x:%x:%x:%x:%x:%x\n", buff1[32],buff1[33],buff1[34],buff1[35],buff1[36],buff1[37]);
                printf("    Target Protocol Address: %d.%d.%d.%d\n", buff1[38],buff1[39],buff1[40],buff1[41]);

                break;
            
            case 0x0800:

                total++;
                ipv4++;

                printf("\nEthernet:\n");
                printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
                printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);

                printf("Tipo: 0x%.4x \nIPv4:\n", eth_type);

                uint8_t ver_ihl = buff1[14];
                printf("    Version: %d\n", (ver_ihl & 0xF0));
                printf("    Internet Header Length: %d\n", (ver_ihl & 0x0F));

                uint8_t type_service = buff1[15];
                printf("    Type of service: 0x%.2x - ", type_service);

                uint8_t precedence = type_service >> 5;
                printf("Precedence: 0x%.1x - ", precedence);

                type_service = type_service & 0x1F;
                switch (type_service) {
                case 0x01:
                    printf("0x%x: Reserved\n", type_service);
                    break;
                
                case 0x02:
                    printf("0x%x: Minimize cost\n", type_service);
                    break;
                
                case 0x04:
                    printf("0x%x: Maximize Reliability\n", type_service);
                    break;
                
                case 0x08:
                    printf("0x%x: Maximize throughout\n", type_service);
                    break;
                
                case 0x10:
                    printf("0x%x: Minimize delay\n", type_service);
                    break;
                
                default:
                    printf("0x%x\n", type_service);
                    break;
                }

                uint16_t tot_len = (buff1[16] << 8) + buff1[17];
                printf("    Total Length: %d\n", tot_len);

                uint16_t id = (buff1[18] << 8) + buff1[19];
                printf("    Identification: 0x%.4x\n", id);

                uint16_t flag_fragoffset = (buff1[20] << 8) + buff1[21];
                uint8_t flag = buff1[20] >> 5;
                uint16_t offset = (flag_fragoffset << 3);
                offset = offset >> 3;
                switch (flag) {
                case 0x02:
                    printf("    Flags 0x%.2x - Don't fragment\n", flag);
                    break;
                
                case 0x01:
                    printf("    Flags 0x%.2x - More fragments\n", flag);
                    break;

                default:
                    printf("    Flags 0x%.2x not used\n", flag);
                    break;
                }
                printf("    Fragment Offset 0x%.4x\n", offset);

                uint8_t ttl = buff1[22];
                printf("    Time to Live: %d\n", ttl);

                uint8_t protocol = buff1[23];
                printf("    Protocol: %d\n", protocol);

                uint16_t header_checksum = (buff1[24] << 8) + buff1[25];
                printf("    Header Checksum - 0x%.4x\n", header_checksum);

                printf("    Source Address %d.%d.%d.%d\n", buff1[26],buff1[27],buff1[28],buff1[29]);
                printf("    Destination Address %d.%d.%d.%d\n", buff1[30],buff1[31],buff1[32],buff1[33]);

                switch (protocol)
                {
                case 1:
                    icmp ++;

                    printf("    ICMP:\n");
                    uint8_t type = buff1[34];
                    // printf("        Type - %d\n", type);

                    uint8_t code = buff1[35];
                    // printf("        Code - %d\n", code);
                    
                    switch (type) {
                    case 0:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Echo Reply\n", code);
                        break;
                    
                    case 3:
                    printf("        Type - %d\n", type);
                        switch (code)
                        {
                        case 0:
                        printf("        Code - %d - Net Unreachable\n", code);
                            break;
                        case 1:
                        printf("        Code - %d - Host Unreachable\n", code);
                            break;
                        case 2:
                        printf("        Code - %d - Protocol Unreachable\n", code);
                            break;
                        case 3:
                        printf("        Code - %d - Port Unreachable\n", code);
                            break;
                        case 4:
                        printf("        Code - %d - Fragmentation Needed & DF Set\n", code);
                            break;
                        case 5:
                        printf("        Code - %d - Source Route Failed\n", code);
                            break;
                        case 6:
                        printf("        Code - %d - Destination Network Unknown\n", code);
                            break;
                        case 7:
                        printf("        Code - %d - Destination Host Unknown\n", code);
                            break;
                        case 8:
                        printf("        Code - %d - Source Route Isolation\n", code);
                            break;
                        case 9:
                        printf("        Code - %d - Network Administratively Prohibited\n", code);
                            break;
                        case 10:
                        printf("        Code - %d - Host Administratively Prohibited\n", code);
                            break;
                        case 11:
                        printf("        Code - %d - Network Unreachable for TOS\n", code);
                            break;
                        case 12:
                        printf("        Code - %d - Host Unreachable for TOS\n", code);
                            break;
                        case 13:
                        printf("        Code - %d - Communication Administratively Prohibited\n", code);
                            break;
                        default:
                            break;
                        }
                        break;

                    case 4:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Source Quench\n", code);
                        break;

                    case 5:
                    printf("        Type - %d\n", type);
                        switch (code)
                        {
                        case 0:
                        printf("        Code - %d - Redirect Datagram for the Network\n", code);
                            break;
                        case 1:
                        printf("        Code - %d - Redirect Datagram for the Host\\n", code);
                            break;
                        case 2:
                        printf("        Code - %d - Redirect Datagram for the TOS & Network\\n", code);
                            break;
                        case 3:
                        printf("        Code - %d - Redirect Datagram for the TOS & Host\\n", code);
                            break;
                        default:
                            break;
                        }
                        break;

                    case 8:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Echo\n", code);
                        break;

                    case 9:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Router Advertisement\n", code);
                        break;

                    case 10:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Router Selection\n", code);
                        break;

                    case 11:
                    printf("        Type - %d\n", type);
                        switch (code)
                        {
                        case 0:
                        printf("        Code - %d - Time to Live exceeded in Transit\n", code);
                            break;

                        case 1:
                        printf("        Code - %d - Fragment Reassembly Time Exceeded\n", code);
                            break;
                        
                        default:
                            break;
                        }
                        break;

                    case 12:
                    printf("        Type - %d\n", type);
                        switch (code)
                        {
                        case 0:
                        printf("        Code - %d - Pointer Indicates the error\n", code);
                            break;

                        case 1:
                        printf("        Code - %d - Missing a Required Option\n", code);
                            break;

                        case 2:
                        printf("        Code - %d - Bad Length\n", code);
                            break;
                        default:
                            break;
                        }
                        break;

                    case 13:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Timestamp\n", code);
                        break;

                    case 14:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Timestamp reply\n", code);
                        break;

                    case 15:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Information Request\n", code);
                        break;

                    case 16:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Information Reply\n", code);
                        break;
                    
                    case 17:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Address Mask Request\n", code);
                        break;

                    case 18:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Address Mask Reply\n", code);
                        break;

                    case 30:
                    printf("        Type - %d\n", type);
                    printf("        Code - %d - Tracerout\n", code);
                        break;
                            
                    default:
                        break;
                    }
                    uint16_t checksum1 = buff1[36] + buff1[37];
                    printf("        Length - %d\n", checksum1);

                    uint32_t others = buff1[38] + buff1[39] + buff1[40] + buff1[41];
                    printf("        Checksum - 0x%.4x\n", others);
                    break;
                
                case 2:
                    printf("    IGMP\n");
                    break;
                
                case 6:
                    tcp++;

                    printf("    TCP:\n");
                    uint16_t source_port_tcp = (buff1[34] << 8) + buff1[35];
                    printf("        Source Port - %u\n", source_port_tcp);

                    uint16_t destination_port_tcp = (buff1[36] << 8) + buff1[37];
                    printf("        Destination Port - %u", destination_port_tcp);
                    switch (destination_port_tcp) {
                    case 7:
                        printf(" - ECHO\n");
                        break;
                    
                    case 19:
                        printf(" - CHARGEN\n");
                        break;
                    
                    case 20:
                        printf(" - FTP-DATA\n");
                        break;
                    
                    case 21:
                        printf(" - FTP-CONTROL\n");
                        break;
                    
                    case 22:
                        printf(" - SSH\n");
                        break;
                    
                    case 23:
                        printf(" - TELNET\n");
                        break;
                    
                    case 25:
                        printf(" - SMTP\n");
                        break;
                    
                    case 53:
                        printf(" - DNS\n");
                        break;
                    
                    case 79:
                        printf(" - FINGER\n");
                        break;
                    
                    case 80:
                        printf(" - HTTP\n");
                        break;
                    
                    case 110:
                        printf(" - POP3\n");
                        break;
                    
                    case 111:
                        printf(" - SUNRPC\n");
                        break;
                    
                    case 119:
                        printf(" - NNTP\n");
                        break;
                    
                    case 139:
                        printf(" - NETBIOS-SSN\n");
                        break;
                    
                    case 143:
                        printf(" - IMAP\n");
                        break;
                    
                    case 179:
                        printf(" - BGP\n");
                        break;
                    
                    case 389:
                        printf(" - LDAP\n");
                        break;
                    
                    case 443:
                        printf(" - HTTPS\n");
                        break;
                    
                    case 445:
                        printf(" - MICROSOFT-DS\n");
                        break;
                    
                    case 1080:
                        printf(" - SOCKS\n");
                        break;
                    
                    default:
                        printf("\n");
                        break;
                    }

                    uint32_t seq_number = (buff1[38] << 24) + (buff1[39] << 16) + (buff1[40] << 8) + buff1[41];
                    printf("        Sequence Number - %u\n", seq_number);

                    uint32_t ack_number = (buff1[42] << 24) + (buff1[43] << 16) + (buff1[44] << 8) + buff1[45];
                    printf("        Acknowledgment Number - %u\n", ack_number);

                    uint8_t off_res = buff1[46];
                    uint8_t off = off_res >> 4;
                    printf("        Offset - %d\n", off);

                    uint8_t reserved = off_res << 4;
                    reserved = reserved >> 4;
                    printf("        Reserved - %d\n", reserved);

                    uint8_t flags = buff1[47];
                    printf("        Flags - 0x%.4x\n", flags);

                    uint16_t window = (buff1[48] << 8) + buff1[49];
                    printf("        Window - %d\n", window);

                    uint16_t checksum2 = (buff1[50] << 8) + buff1[51];
                    printf("        Checksum - 0x%.4x\n", checksum2);

                    uint16_t urg_pt = (buff1[52] << 8) + buff1[53];
                    printf("        Urgent Ponter - 0x%.4x\n", urg_pt);
                    
                    if(destination_port_tcp == 53) {

                        dns++;

                        printf("        DNS:\n");

                        uint16_t dns_len = (buff1[54] << 8) + buff1[55];
                        printf("            Length: %d\n", dns_len);

                        uint16_t id3 = (buff1[56] << 8) + buff1[57];
                        printf("            ID: %d\n", id3);

                        uint8_t qr_op_aa_tc_rd = buff1[58];
                        uint8_t qr = qr_op_aa_tc_rd >> 7;
                        printf("            Query/Response: %x\n", qr);

                        uint8_t opcode = qr_op_aa_tc_rd << 1;
                        opcode = opcode >> 4;
                        printf("            Opcode: %x\n", opcode);

                        uint8_t aa = qr_op_aa_tc_rd << 5;
                        aa = aa >> 7;
                        printf("            AA: %x\n", aa);

                        uint8_t tc = qr_op_aa_tc_rd << 6;
                        tc = tc >> 7;
                        printf("            TC: %x\n", tc);

                        uint8_t rd = qr_op_aa_tc_rd << 7;
                        rd = rd >> 7;
                        printf("            RD: %x\n", rd);

                        uint8_t ra_z_rcode = buff1[59];
                        uint8_t ra = ra_z_rcode >> 7;
                        printf("            RA: %x\n", ra);

                        uint8_t z = ra_z_rcode << 1;
                        z = z >> 5;
                        printf("            Z: %x\n", z);

                        uint8_t rcode = ra_z_rcode << 4;
                        rcode = rcode >> 4;
                        switch (rcode) {
                        case 0:
                            printf("            Response Code: %x - No error\n", rcode);
                            break;
                        
                        case 1:
                            printf("            Response Code: %x - Format error\n", rcode);
                            break;

                        case 2:
                            printf("            Response Code: %x - Server failure\n", rcode);
                            break;

                        case 3:
                            printf("            Response Code: %x - Non-exixtant domain\n", rcode);
                            break;

                        case 4:
                            printf("            Response Code: %x - Query type not implemented\n", rcode);
                            break;

                        case 5:
                            printf("            Response Code: %x - Query refused\n", rcode);
                            break;

                        default:
                            break;
                        }

                        uint16_t qdcount = (buff1[60] << 8) + buff1[61];
                        printf("            QDCOUNT: %d\n", qdcount);

                        uint16_t ancount = (buff1[62] << 8) + buff1[63];
                        printf("            ANCOUNT: %d\n", ancount);
                        
                        uint16_t nscount = (buff1[64] << 8) + buff1[65];
                        printf("            NSCOUNT: %d\n", nscount);
                        
                        uint16_t arcount = (buff1[66] << 8) + buff1[67];
                        printf("            ARCOUNT: %d\n", arcount);
                        
                        uint16_t qs = (buff1[68] << 8) + buff1[69];
                        printf("            Question Section: %x\n", qs);
                        
                        uint16_t an_s = (buff1[70] << 8) + buff1[71];
                        printf("            Answer Section: %x\n", an_s);
                        
                        uint16_t aut_s = (buff1[72] << 8) + buff1[73];
                        printf("            Authority Section: %x\n", aut_s);
                        
                        uint16_t add_info_s = (buff1[74] << 8) + buff1[75];
                        printf("            Additional Information Section: %x\n", add_info_s);
                        
                    }
                    break;
                
                case 9:
                    printf("    IGRP\n");
                    break;
                
                case 17:
                    udp++;

                    printf("    UDP:\n");
                    uint16_t source_port = (buff1[34] << 8) + buff1[35];
                    printf("        Source Port - %u\n", source_port);

                    uint16_t destination_port = (buff1[36] << 8) + buff1[37];
                    printf("        Destination Port - %u", destination_port);
                    switch (destination_port) {
                    case 7:
                        printf(" - ECHO\n");
                        break;
                    
                    case 19:
                        printf(" - CHARGEN\n");
                        break;
                    
                    case 37:
                        printf(" - TIME\n");
                        break;
                    
                    case 53:
                        printf(" - DNS\n");
                        break;
                    
                    case 67:
                        printf(" - BOOTPS\n");
                        break;
                    
                    case 68:
                        printf(" - BOOTPC\n");
                        break;
                    
                    case 69:
                        printf(" - TFTP\n");
                        break;
                    
                    case 137:
                        printf(" - NETBIOS-NS\n");
                        break;
                    
                    case 138:
                        printf(" - NETBIOS-DGM\n");
                        break;
                    
                    case 161:
                        printf(" - SNMP\n");
                        break;
                    
                    case 162:
                        printf(" - SNMP-TRAP\n");
                        break;
                    
                    case 500:
                        printf(" - ISAKMP\n");
                        break;
                    
                    case 514:
                        printf(" - SYSLOG\n");
                        break;
                    
                    case 520:
                        printf(" - RIP\n");
                        break;
                    
                    case 33434:
                        printf(" - TRACEROUTE\n");
                        break;
                    
                    default:
                        printf("\n");
                        break;
                    }
                    
                    uint16_t length = (buff1[38] << 8) + buff1[39];
                    printf("        Length - %u\n", length);

                    uint16_t checksum = (buff1[40] << 8) + buff1[41];
                    printf("        Checksum - 0x%.4x\n", checksum);


                    if(destination_port == 53) {
                        dns++;

                        printf("        DNS:\n");

                        uint16_t id2 = (buff1[42] << 8) + buff1[43];
                        printf("            ID: %d\n", id2);

                        uint8_t qr_op_aa_tc_rd = buff1[44];
                        uint8_t qr = qr_op_aa_tc_rd >> 7;
                        printf("            Query/Response: %x\n", qr);

                        uint8_t opcode = qr_op_aa_tc_rd << 1;
                        opcode = opcode >> 4;
                        printf("            Opcode: %x\n", opcode);

                        uint8_t aa = qr_op_aa_tc_rd << 5;
                        aa = aa >> 7;
                        printf("            AA: %x\n", aa);

                        uint8_t tc = qr_op_aa_tc_rd << 6;
                        tc = tc >> 7;
                        printf("            TC: %x\n", tc);

                        uint8_t rd = qr_op_aa_tc_rd << 7;
                        rd = rd >> 7;
                        printf("            RD: %x\n", rd);

                        uint8_t ra_z_rcode = buff1[45];
                        uint8_t ra = ra_z_rcode >> 7;
                        printf("            RA: %x\n", ra);

                        uint8_t z = ra_z_rcode << 1;
                        z = z >> 5;
                        printf("            Z: %x\n", z);

                        uint8_t rcode = ra_z_rcode << 4;
                        rcode = rcode >> 4;
                        switch (rcode) {
                        case 0:
                            printf("            Response Code: %x - No error\n", rcode);
                            break;
                        
                        case 1:
                            printf("            Response Code: %x - Format error\n", rcode);
                            break;

                        case 2:
                            printf("            Response Code: %x - Server failure\n", rcode);
                            break;

                        case 3:
                            printf("            Response Code: %x - Non-exixtant domain\n", rcode);
                            break;

                        case 4:
                            printf("            Response Code: %x - Query type not implemented\n", rcode);
                            break;

                        case 5:
                            printf("            Response Code: %x - Query refused\n", rcode);
                            break;

                        default:
                            break;
                        }

                        uint16_t qdcount = (buff1[46] << 8) + buff1[47];
                        printf("            QDCOUNT: %d\n", qdcount);

                        uint16_t ancount = (buff1[48] << 8) + buff1[49];
                        printf("            ANCOUNT: %d\n", ancount);
                        
                        uint16_t nscount = (buff1[50] << 8) + buff1[51];
                        printf("            NSCOUNT: %d\n", nscount);
                        
                        uint16_t arcount = (buff1[52] << 8) + buff1[53];
                        printf("            ARCOUNT: %d\n", arcount);
                        
                        uint16_t qs = (buff1[54] << 8) + buff1[55];
                        printf("            Question Section: %x\n", qs);
                        
                        uint16_t an_s = (buff1[56] << 8) + buff1[57];
                        printf("            Answer Section: %x\n", an_s);
                        
                        uint16_t aut_s = (buff1[58] << 8) + buff1[59];
                        printf("            Authority Section: %x\n", aut_s);
                        
                        uint16_t add_info_s = (buff1[60] << 8) + buff1[61];
                        printf("            Additional Information Section: %x\n", add_info_s);
                        
                    }
                    break;
                
                case 47:
                    printf("    GRE\n");
                    break;
                
                case 50:
                    printf("    ESP\n");
                    break;
                
                case 51:
                    printf("    AH\n");
                    break;
                
                case 57:
                    printf("    SKIP\n");
                    break;
                
                case 88:
                    printf("    EIGRP\n");
                    break;
                
                case 89:
                    printf("    OSPF\n");
                    break;
                
                case 115:
                    printf("    L2TP\n");
                    break;
                
                default:
                    break;
                }

                break;
            
            case 0x86DD:
                total++;
                ipv6++;

                printf("\nEthernet:\n");
                printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0],buff1[1],buff1[2],buff1[3],buff1[4],buff1[5]);
                printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6],buff1[7],buff1[8],buff1[9],buff1[10],buff1[11]);

                printf("Tipo: 0x%.4x \nIPv6:\n", eth_type);

                uint16_t traf_class = (buff1[14] << 8) + buff1[15];
                uint8_t version_ipv6 = traf_class >> 12;
                traf_class = traf_class << 4;
                traf_class = traf_class >> 9;

                printf("    Version: %d\n", version_ipv6);
                printf("    Traffic Class: %d\n",traf_class);

                uint32_t flow_label = (buff1[15] << 16) + (buff1[16] << 8) + buff1[17];
                flow_label = flow_label & 0x1FFFFF;
                printf("    Flow Label: %d\n", flow_label);

                uint16_t payload_length = (buff1[18] << 8) + buff1[19];
                printf("    Payload Length: %d\n", payload_length);

                uint8_t next_header = (buff1[20]);
                printf("    Next Header: %d\n", next_header);

                uint8_t hop_limit = (buff1[21]);
                printf("    Hop Limit: %d\n", hop_limit);

                printf("    Source Address     : %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x \n", buff1[22],buff1[23],buff1[24],buff1[25],buff1[26],buff1[27], buff1[28],buff1[29],buff1[30],buff1[31],buff1[32],buff1[33],buff1[34],buff1[35],buff1[36],buff1[37]);
                printf("    Destination Address: %x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x \n", buff1[38],buff1[39],buff1[40],buff1[41],buff1[42],buff1[43], buff1[44],buff1[45],buff1[46],buff1[47],buff1[48],buff1[49],buff1[50],buff1[51],buff1[52],buff1[53]);

                switch (next_header)
                {
                case 6:

                    tcp++;

                    printf("    TCP:\n");
                    uint16_t source_port_tcp_v6 = (buff1[54] << 8) + buff1[55];
                    printf("        Source Port - %u\n", source_port_tcp_v6);

                    uint16_t destination_port_tcp_v6 = (buff1[56] << 8) + buff1[57];
                    printf("        Destination Port - %u", destination_port_tcp_v6);
                    switch (destination_port_tcp_v6) {
                    case 7:
                        printf(" - ECHO\n");
                        break;
                    
                    case 19:
                        printf(" - CHARGEN\n");
                        break;
                    
                    case 20:
                        printf(" - FTP-DATA\n");
                        break;
                    
                    case 21:
                        printf(" - FTP-CONTROL\n");
                        break;
                    
                    case 22:
                        printf(" - SSH\n");
                        break;
                    
                    case 23:
                        printf(" - TELNET\n");
                        break;
                    
                    case 25:
                        printf(" - SMTP\n");
                        break;
                    
                    case 53:
                        printf(" - DNS\n");
                        break;
                    
                    case 79:
                        printf(" - FINGER\n");
                        break;
                    
                    case 80:
                        printf(" - HTTP\n");
                        break;
                    
                    case 110:
                        printf(" - POP3\n");
                        break;
                    
                    case 111:
                        printf(" - SUNRPC\n");
                        break;
                    
                    case 119:
                        printf(" - NNTP\n");
                        break;
                    
                    case 139:
                        printf(" - NETBIOS-SSN\n");
                        break;
                    
                    case 143:
                        printf(" - IMAP\n");
                        break;
                    
                    case 179:
                        printf(" - BGP\n");
                        break;
                    
                    case 389:
                        printf(" - LDAP\n");
                        break;
                    
                    case 443:
                        printf(" - HTTPS\n");
                        break;
                    
                    case 445:
                        printf(" - MICROSOFT-DS\n");
                        break;
                    
                    case 1080:
                        printf(" - SOCKS\n");
                        break;
                    
                    default:
                        printf("\n");
                        break;
                    }

                    uint32_t seq_number_v6 = (buff1[58] << 24) + (buff1[59] << 16) + (buff1[60] << 8) + buff1[61];
                    printf("        Sequence Number - %u\n", seq_number_v6);

                    uint32_t ack_number_v6 = (buff1[62] << 24) + (buff1[63] << 16) + (buff1[64] << 8) + buff1[65];
                    printf("        Acknowledgment Number - %u\n", ack_number_v6);

                    uint8_t off_res_v6 = buff1[66];
                    uint8_t off_v6 = off_res_v6 >> 4;
                    printf("        Offset - %d\n", off_v6);

                    uint8_t reserved_v6 = off_res_v6 << 4;
                    reserved_v6 = reserved_v6 >> 4;
                    printf("        Reserved - %d\n", reserved_v6);

                    uint8_t flags_v6 = buff1[67];
                    printf("        Flags_v6 - 0x%.4x", flags_v6);

                    uint16_t window_v6 = (buff1[68] << 8) + buff1[69];
                    printf("        Window - %d\n", window_v6);

                    uint16_t checksum2_v6 = (buff1[70] << 8) + buff1[71];
                    printf("        Checksum - 0x%.4x\n", checksum2_v6);

                    uint16_t urg_pt_v6 = (buff1[72] << 8) + buff1[73];
                    printf("        Urgent Ponter - 0x%.4x\n", urg_pt_v6);
                    
                    if(destination_port_tcp_v6 == 53) {

                        dns++;

                        printf("        DNS:\n");

                        uint16_t dns_len_v6 = (buff1[74] << 8) + buff1[75];
                        printf("            Length: %d\n", dns_len_v6);

                        uint16_t id3_v6 = (buff1[76] << 8) + buff1[77];
                        printf("            ID: %d\n", id3_v6);

                        uint8_t qr_op_aa_tc_rd_v6 = buff1[78];
                        uint8_t qr_v6 = qr_op_aa_tc_rd_v6 >> 7;
                        printf("            Query/Response: %x\n", qr_v6);

                        uint8_t opcode_v6 = qr_op_aa_tc_rd_v6 << 1;
                        opcode_v6 = opcode_v6 >> 4;
                        printf("            Opcode: %x\n", opcode_v6);

                        uint8_t aa_v6 = qr_op_aa_tc_rd_v6 << 5;
                        aa_v6 = aa_v6 >> 7;
                        printf("            AA: %x\n", aa_v6);

                        uint8_t tc_v6 = qr_op_aa_tc_rd_v6 << 6;
                        tc_v6 = tc_v6 >> 7;
                        printf("            TC: %x\n", tc_v6);

                        uint8_t rd_v6 = qr_op_aa_tc_rd_v6 << 7;
                        rd_v6 = rd_v6 >> 7;
                        printf("            RD: %x\n", rd_v6);

                        uint8_t ra_z_rcode_v6 = buff1[79];
                        uint8_t ra_v6 = ra_z_rcode_v6 >> 7;
                        printf("            RA: %x\n", ra_v6);

                        uint8_t z_v6 = ra_z_rcode_v6 << 1;
                        z_v6 = z_v6 >> 5;
                        printf("            Z: %x\n", z_v6);

                        uint8_t rcode_v6 = ra_z_rcode_v6 << 4;
                        rcode_v6 = rcode_v6 >> 4;
                        switch (rcode_v6) {
                        case 0:
                            printf("            Response Code: %x - No error\n", rcode_v6);
                            break;
                        
                        case 1:
                            printf("            Response Code: %x - Format error\n", rcode_v6);
                            break;

                        case 2:
                            printf("            Response Code: %x - Server failure\n", rcode_v6);
                            break;

                        case 3:
                            printf("            Response Code: %x - Non-exixtant domain\n", rcode_v6);
                            break;

                        case 4:
                            printf("            Response Code: %x - Query type not implemented\n", rcode_v6);
                            break;

                        case 5:
                            printf("            Response Code: %x - Query refused\n", rcode_v6);
                            break;

                        default:
                            break;
                        }

                        uint16_t qdcount_v6 = (buff1[80] << 8) + buff1[81];
                        printf("            QDCOUNT: %d\n", qdcount_v6);

                        uint16_t ancount_v6 = (buff1[82] << 8) + buff1[83];
                        printf("            ANCOUNT: %d\n", ancount_v6);
                        
                        uint16_t nscount_v6 = (buff1[84] << 8) + buff1[85];
                        printf("            NSCOUNT: %d\n", nscount_v6);
                        
                        uint16_t arcount_v6 = (buff1[86] << 8) + buff1[87];
                        printf("            ARCOUNT: %d\n", arcount_v6);
                        
                        uint16_t qs_v6 = (buff1[88] << 8) + buff1[89];
                        printf("            Question Section: %x\n", qs_v6);
                        
                        uint16_t an_s_v6 = (buff1[90] << 8) + buff1[91];
                        printf("            Answer Section: %x\n", an_s_v6);
                        
                        uint16_t aut_s_v6 = (buff1[92] << 8) + buff1[93];
                        printf("            Authority Section: %x\n", aut_s_v6);
                        
                        uint16_t add_info_s_v6 = (buff1[94] << 8) + buff1[95];
                        printf("            Additional Information Section: %x\n", add_info_s_v6);
                        
                    }
                    break;
                
                case 17:
                    udp++;

                    printf("    UDP:\n");
                    uint16_t source_port = (buff1[54] << 8) + buff1[55];
                    printf("        Source Port - %u\n", source_port);

                    uint16_t destination_port = (buff1[56] << 8) + buff1[57];
                    printf("        Destination Port - %u", destination_port);
                    switch (destination_port) {
                    case 7:
                        printf(" - ECHO\n");
                        break;
                    
                    case 19:
                        printf(" - CHARGEN\n");
                        break;
                    
                    case 37:
                        printf(" - TIME\n");
                        break;
                    
                    case 53:
                        printf(" - DNS\n");
                        break;
                    
                    case 67:
                        printf(" - BOOTPS\n");
                        break;
                    
                    case 68:
                        printf(" - BOOTPC\n");
                        break;
                    
                    case 69:
                        printf(" - TFTP\n");
                        break;
                    
                    case 137:
                        printf(" - NETBIOS-NS\n");
                        break;
                    
                    case 138:
                        printf(" - NETBIOS-DGM\n");
                        break;
                    
                    case 161:
                        printf(" - SNMP\n");
                        break;
                    
                    case 162:
                        printf(" - SNMP-TRAP\n");
                        break;
                    
                    case 500:
                        printf(" - ISAKMP\n");
                        break;
                    
                    case 514:
                        printf(" - SYSLOG\n");
                        break;
                    
                    case 520:
                        printf(" - RIP\n");
                        break;
                    
                    case 33434:
                        printf(" - TRACEROUTE\n");
                        break;
                    
                    default:
                        printf("\n");
                        break;
                    }
                    
                    uint16_t length = (buff1[58] << 8) + buff1[59];
                    printf("        Length - %u\n", length);

                    uint16_t checksum = (buff1[60] << 8) + buff1[61];
                    printf("        Checksum - 0x%.4x\n", checksum);


                    if(destination_port == 53) {

                        dns++;

                        printf("        DNS:\n");

                        uint16_t id2 = (buff1[62] << 8) + buff1[63];
                        printf("            ID: %d\n", id2);

                        uint8_t qr_op_aa_tc_rd = buff1[64];
                        uint8_t qr = qr_op_aa_tc_rd >> 7;
                        printf("            Query/Response: %x\n", qr);

                        uint8_t opcode = qr_op_aa_tc_rd << 1;
                        opcode = opcode >> 4;
                        printf("            Opcode: %x\n", opcode);

                        uint8_t aa = qr_op_aa_tc_rd << 5;
                        aa = aa >> 7;
                        printf("            AA: %x\n", aa);

                        uint8_t tc = qr_op_aa_tc_rd << 6;
                        tc = tc >> 7;
                        printf("            TC: %x\n", tc);

                        uint8_t rd = qr_op_aa_tc_rd << 7;
                        rd = rd >> 7;
                        printf("            RD: %x\n", rd);

                        uint8_t ra_z_rcode = buff1[65];
                        uint8_t ra = ra_z_rcode >> 7;
                        printf("            RA: %x\n", ra);

                        uint8_t z = ra_z_rcode << 1;
                        z = z >> 5;
                        printf("            Z: %x\n", z);

                        uint8_t rcode = ra_z_rcode << 4;
                        rcode = rcode >> 4;
                        switch (rcode) {
                        case 0:
                            printf("            Response Code: %x - No error\n", rcode);
                            break;
                        
                        case 1:
                            printf("            Response Code: %x - Format error\n", rcode);
                            break;

                        case 2:
                            printf("            Response Code: %x - Server failure\n", rcode);
                            break;

                        case 3:
                            printf("            Response Code: %x - Non-exixtant domain\n", rcode);
                            break;

                        case 4:
                            printf("            Response Code: %x - Query type not implemented\n", rcode);
                            break;

                        case 5:
                            printf("            Response Code: %x - Query refused\n", rcode);
                            break;

                        default:
                            break;
                        }

                        uint16_t qdcount = (buff1[66] << 8) + buff1[67];
                        printf("            QDCOUNT: %d\n", qdcount);

                        uint16_t ancount = (buff1[68] << 8) + buff1[69];
                        printf("            ANCOUNT: %d\n", ancount);
                        
                        uint16_t nscount = (buff1[70] << 8) + buff1[71];
                        printf("            NSCOUNT: %d\n", nscount);
                        
                        uint16_t arcount = (buff1[72] << 8) + buff1[73];
                        printf("            ARCOUNT: %d\n", arcount);
                        
                        uint16_t qs = (buff1[74] << 8) + buff1[75];
                        printf("            Question Section: %x\n", qs);
                        
                        uint16_t an_s = (buff1[76] << 8) + buff1[77];
                        printf("            Answer Section: %x\n", an_s);
                        
                        uint16_t aut_s = (buff1[78] << 8) + buff1[79];
                        printf("            Authority Section: %x\n", aut_s);
                        
                        uint16_t add_info_s = (buff1[80] << 8) + buff1[81];
                        printf("            Additional Information Section: %x\n", add_info_s);
                        
                    }
                    break;
                    
                case 58:
                    icmpv6++;

                    printf("    ICMPv6:\n");
                    uint8_t type = buff1[54];
                    uint8_t code = buff1[55];
                    switch (type) {
                    case 1:
                        printf("       Type: %d\n", type);
                        switch (code) {
                        case 0:
                            printf("      Code: %d - No route to destination\n", code);
                            break;
                        
                        case 1:
                            printf("      Code: %d - Communication administratively prohibited\n", code);
                            break;
                        
                        case 2:
                            printf("      Code: %d - (not assigned)\n", code);
                            break;
                        
                        case 3:
                            printf("      Code: %d - Address unreachable\n", code);
                            break;
                        
                        case 4:
                            printf("      Code: %d - Port unreachable\n", code);
                            break;
                        
                        default:
                            printf("      Code: %d\n", code);
                            break;
                        }
                        break;

                    case 2:
                        printf("      Type: %d\n", type);
                        printf("      Code: %d - Packet too big mesage\n", code);
                        break;

                    case 3:
                        printf("     Type: %d\n", type);
                        switch (code) {
                        case 0:
                            printf("        Code: %d - hop limit exceeded in transit\n", code);
                            break;
                        
                        case 1:
                            printf("        Code: %d - fragment reassembly time exceeded\n", code);
                            break;
                        
                        default:
                            printf("        Code: %d\n", code);
                            break;
                        }
                        break;
                    
                    case 4:
                        printf("        Type: %d\n", type);
                        switch (code) {
                        case 0:
                            printf("        Code: %d\n - Erroneous header field encountered", code);
                            break;
                        
                        case 1:
                            printf("        Code: %d\n - Unrecognized 'Next Header' type encountered", code);
                            break;
                        
                        case 2:
                            printf("        Code: %d\n - Unrecognized IPv6 opion encountered", code);
                            break;
                        
                        default:
                            printf("        Code: %d\n", code);
                            break;
                        }

                    case 128:
                        printf("        Type: %d\n", type);
                        printf("        Code: %d\n - Echo request", code);
                        break;

                    case 129:
                        printf("        Type: %d\n", type);
                        printf("        Code: %d - Echo reply", code);
                        break;

                    default:
                        // printf("Other Protocol
                        break;
                    }
                    break;

                default:
                    // printf("Other Protocol!");
                    break;
                }

                break;

            
            default:
                break;
            }
        }
    }
}