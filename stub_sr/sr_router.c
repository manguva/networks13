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
	
    uint8_t *server_mac_address = (uint8_t *)malloc(6 * sizeof(uint8_t));
    uint8_t *server_ip_address = (uint8_t *)malloc(sizeof(uint8_t) * 4);
    arp_cache_entry *entry = (arp_cache_entry *)malloc(sizeof(arp_cache_entry));
//    printf("Received packet\n");
    int i = len;

    /*retrieving arp packet information */
    if(i>15){
        if( packet[12] == htons(8) && packet[13] == htons(6)){
            //		printf("Packet is of type arp\n");
            //1. get our machine IP and MAC
            //IP: uint8_t us_IP[4]
            //MAC: uint8_t us_MAC[6]

            //************if it is an ARP request******************


            //**********if it is an ARP reply*********************
            
        }
    }


}/* end sr_ForwardPacket */



/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void dealWithARPReply(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    //Building the Arp cache entry
    entry->ip_address = convert_ip_to_integer(server_ip_address);

    memcpy(entry->mac_address_uint8_t, server_mac_address, 6);
    memcpy(entry->mac_address_unsigned_char, server_mac_address, 6);
    entry->interface_type = interface;
    entry->next = NULL;

    add_arp_entry(entry, &arp_table);

    //    pretty_print_arp_table(&arp_table);

    printf("*** -> Received packet of length %d \n",len);
    //send the broadcasting ARP packet
    PARPPACKET buf = getSentARPPacket();
    sr_send_packet(sr, buf, 42, interface);







    //retrieve mac address, and IP address of server
    memcpy(server_mac_address, packet + 6, 6);
    memcpy(server_ip_address, packet + 28, 4);

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
    PARPACKET arpPacket = (PARPACKET)malloc(sizeof(PARPACKET));

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

