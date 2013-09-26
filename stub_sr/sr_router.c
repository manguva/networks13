/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

#ifdef linux
#	define	NEWSOCKET()	socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP))
#else
#	define	NEWSOCKET()	socket(SOL_SOCKET, SOCK_RAW, ETHERTYPE_REVARP)
#endif

arp_cache_entry arp_table;
/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */
    
} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacke(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
	
    arp_cache_entry *entry = (arp_cache_entry *)malloc(sizeof(arp_cache_entry));
//    printf("Received packet\n");
    int i = len;
    uint8_t src[6];
    /*retrieving arp packet information */
    if(i>15){
        if( packet[12] == htons(8) && packet[13] == htons(6)){
            //		printf("Packet is of type arp\n");
            //1. get our machine IP and MAC
            //IP: uint8_t us_IP[4]
            //MAC: uint8_t us_MAC[6]
	    uint8_t bytes [] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
            //************if it is an ARP request******************
	    //if broadcast, check destination ip and compare with local ip
	    //if yes, construct arp reply to sender
 	    if(!memcmp(packet, bytes, 6)){
		if(!memcmp(packet + 38, retrieve_ip_address(), 4)){
			memcpy(src, packet+6, 6);		
			sr_send_packet(sr, src, 42, interface);
		}
	    }

            //if broadcast, check destination ip and compare with local ip
            //if yes, construct arp reply to sender


            //**********if it is an ARP reply**********************
            uint8_t* des_IP = (uint8_t *) malloc (sizeof(uint8_t) * 4);
            memcpy(des_IP, packet + 38, 4);
            //if the destination IP is the us_IP
            if(memcmp(us_IP, des_IP, 4) == 0)
            {
                dealWithARPReply(sr, packet, interface, entry,
                        us_IP, us_MAC);
            }

        //

        }
    }


}/* end sr_ForwardPacket */



/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void dealWithARPReply(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        char* interface/* lent */,
        arp_cache_entry* entry,       
        uint8_t* us_IP,
        uint8_t* us_MAC)
{
    /* update the ARP cache table  */
    //get the IP and MAC of sender
    uint8_t* sender_IP = (uint8_t* )malloc(sizeof(uint8_t) * 4);
    memcpy(sender_IP, packet + 28, 4);
    //Building the Arp cache entry
    entry->ip_address = convert_ip_to_integer(sender_IP);
    
    uint8_t* sender_MAC = (uint8_t* )malloc(sizeof(uint8_t) * 6);
    memcpy(sender_MAC, packet + 6, 4);
    memcpy(entry->mac_address_uint8_t, sender_MAC, 6);
    memcpy(entry->mac_address_unsigned_char, sender_MAC, 6);
    entry->interface_type = interface;
    entry->next = NULL;
    add_arp_entry(entry, &arp_table);
    
    unsigned char* us_MAC_unsigned_char = (unsigned char*) malloc(sizeof(unsigned char) * 6);
    memcpy(us_MAC_unsigned_char, us_MAC, 6);
    PARPPACKET buf = getSentARPPacket(us_MAC, 
            us_MAC_unsigned_char,
            convert_ip_to_integer(us_IP),
            entry->ip_address);

    sr_send_packet(sr, buf, 42, interface);

}

void dealWithARPRequest(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  
}




void assignBroadcastEthernetAddr(uint8_t* ether_dhost)
{
    for(int i = 0; i < 6; i++)
        ether_dhost[i] = htons(255);    
}

void assignDefaultTargetEthernetAddr(unsigned char* ar_tha)
{
    for(int i = 0; i < 6; i++)
        ar_tha[i] = htons(0);    
}

void assignSourceEthernetAddrFirst(uint8_t* ether_shost, uint8_t* info)
{
    for(int i = 0; i < 6; i++)
        ether_shost[i] = info[i]; 
}

void assignSourceEthernetAddrSecond(unsigned char* ar_sha, unsigned char* info)
{
    for(int i = 0; i < 6; i++)
        ar_sha[i] = info[i];
}

void assignIPAddr(uint32_t* ipAddr, uint32_t info)
{
    ipAddr = info;
}

/*----------------------------------------------------------------------
 *  Construct the ARP packet 
 *  pass the constructed ARP packet as buf in sr_send_packet()
 *----------------------------------------------------------------------*/
PARPPACKET getSentARPPacket(uint8_t* s_mac_address_uint8_t, unsigned char* s_mac_address_unsigned_char, uint32_t s_IP, uint32_t d_IP)
{
    PARPACKET arpPacket = (PARPACKET)malloc(sizeof(ARPACKET));

    assignBroadcastEthernetAddr(arpPacket->et_hdr->ether_dhost); 
    assignSourceEthernetAddrFirst(arpPacket->et_hdr->ether_shost, s_mac_address_uint8_t); 
    arpPacket->et_hdr->ether_type = htons(2054); 
 
    arpPacket->arp_hdr->ar_hrd = htons(1);
    arpPacket->arp_hdr->ar_pro = htons(2048);
    arpPacket->arp_hdr->ar_hln = (unsigned char*)htons(6);
    arpPacket->arp_hdr->ar_pln = (unsigned char*)htons(4);
    arpPacket->arp_hdr->ar_op = htons(1);
    assignSourceEthernetAddrSecond(arpPacket->arp_hdr->ar_sha, s_mac_address_unsignchar);
    assignIpAddr(& arpPacket->arp_hdr->ar_sip, s_IP);
    assignDefaultTargetEthernetAdd(arpPacket->arp_hdr->artha);
    assignIpAddr(& arpPacket->arp_hdr->ar_tip, d_IP);
    
    return arpPacket;
}

/*code to add an entry to the arp table */
void add_arp_entry(arp_cache_entry *entry, arp_cache_entry *arp_cache){
    assert(entry);
    if(!arp_cache->ip_address){
        arp_cache->ip_address = entry->ip_address;  
        memcpy(arp_cache->mac_address_uint8_t, entry->mac_address_uint8_t, 6);
        memcpy(arp_cache->mac_address_unsigned_char, entry->mac_address_unsigned_char, 6);
        arp_cache->interface_type = entry->interface_type;
        arp_cache->next = NULL;
        return;
    }
    assert(arp_cache);

    //search if entry already exists
    arp_cache_entry *arp_pointer = arp_cache;
    while(arp_pointer != NULL){
        if (arp_pointer->ip_address ==  entry->ip_address){
            //IP Address already exists in cache
            //  			printf("IP Address exists is cache already\n");
            return;
        }
        arp_pointer = arp_pointer->next;
    }	

    while(arp_pointer->next != NULL){
        arp_pointer = arp_pointer->next;
    }
    arp_pointer->next = entry;
}
/*
* method to pretty print arp table 
void pretty_print_arp_table(arp_cache_entry *arp_cache){
    arp_cache_entry *arp_pointer = arp_cache;
    int i = 0;
    //    printf("IP address: \n");
    while(arp_pointer){
        while (i < 4){
            //			printf("%hx" , arp_pointer->ip_address[i]);
            i++;
        }
        printf("Char representation: %s\n", arp_pointer->mac_address_uint8_t);
        //              printf("\n");
        arp_pointer = arp_pointer->next;
    }
}
*/

uint32_t convert_ip_to_integer(uint8_t ip_address[]){
        int mask = 0xFF;
        uint32_t result = 0;
        result = ip_address[0] & mask;
        result += ((ip_address[1] & mask) << 8);
        result += ((ip_address[2] & mask) << 16);
        result += ((ip_address[3] & mask) << 24);
    return result;
}

const char* retrieve_mac_address(char address []){
	int fd;
    struct ifreq ifr;
    char *iface = "eth0";
    unsigned char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    //display mac address
    printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    memcpy(address, mac, 6);
    return address;

}

const uint8_t* retrieve_ip_address(uint8_t num[]){

    struct ifaddrs *myaddrs, *ifa;
    void *in_addr;
    char buf[64];
    char ip[15];
    char ip_copy[15];
    char temp[3], temp_copy[3], l_copy[1], l2_copy[2];

    if(getifaddrs(&myaddrs) != 0)
    {
        perror("getifaddrs");
        exit(1);
    }
    int i = 0;
    for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {

        if (ifa->ifa_addr == NULL)
            continue;
        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        switch (ifa->ifa_addr->sa_family)
        {
            case AF_INET:
            {
                struct sockaddr_in *s4 = (struct sockaddr_in *)ifa->ifa_addr;
                in_addr = &s4->sin_addr;
                break;
            }

            case AF_INET6:
            {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                in_addr = &s6->sin6_addr;
                break;
            }

            default:
                continue;
        }
if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, buf, sizeof(buf)))
        {
            printf("%s: inet_ntop failed!\n", ifa->ifa_name);
        }
        else
        {
            printf("%s: %s\n", ifa->ifa_name, buf);
        }
        if (i == 1){
                memcpy(ip, buf, 15);
                int j = 0, k = 0, l = 0, g = 0;
                while (ip[j] <= 57 && ip[j] > 45 ){
                        if (ip[j] != 46){
                                ip_copy[k++] = ip[j++];
                                temp[l++] = ip_copy[k-1];
                        }
                        else {
                                j++;
                                if ( l == 1){
                                        memcpy(l_copy, temp+2, 1);
                                        num[g++] = (uint8_t)atoi(l_copy);
                                        printf("l_copy: %s, temp+2: %s\n", l_copy, temp+2);
                                }
                                else if (l == 2) {
                                        temp[2] = '\0';
                                        memcpy(l2_copy, temp, 2);
                                        num[g++] = (uint8_t)atoi(l2_copy);
                                        printf("l2_copy: %s, temp+2: %s\n", l2_copy, temp+1);
                                }
                                else {
                                        memcpy(temp_copy, temp, l);
                                        num[g++] = (uint8_t)atoi(temp_copy);
                                }
                                l = 0;
                        }
                }
                if ( l == 1){
                                        memset(temp_copy, 0, 3);
                                        memcpy(temp_copy+1, temp, 2);
                                        num[g++] = (uint8_t)atoi(temp_copy);
                }
                else if (l == 2) {
                                        temp[2] = '\0';
                                        memcpy(l2_copy, temp, 2);
                                        num[g++] = (uint8_t)atoi(l2_copy);

                      }

                else {
                           memcpy(temp_copy, temp, l);
                           num[g++] = (uint8_t)atoi(temp_copy);
                }
                j = 0;
                printf("Value of j after all: ");
                while(j < g){
                        printf("\t%d, copy: %s", num[j++], temp_copy);
                }
                memset(temp, 0, 3);
                ip_copy[k] = '\0';
                printf("\nAfter memcpy: %s, ip_copy: %s\n", ip, ip_copy);
                printf("The size of resultant array = %lu %d\n", sizeof(ip), j);
        }
        i++;
    }

    freeifaddrs(myaddrs);
    return num;
}


