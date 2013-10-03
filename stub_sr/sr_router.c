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

/********function declaration***********/
void dealWithARPRequest();
void dealWithARPReply();
PARPPACKET constructReplyARPPacket();
PARPPACKET constructBroadcastARPPacket();










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
    /*retrieving arp packet information */
    if(i > 15){
	    if( packet[12] == 8 && packet[13] == 6){
		    //printf("Packet is of type arp\n");
		    //1. get our machine IP and MAC
		    //IP: uint8_t* us_IP: length 4
		    //MAC: uint8_t* us_MAC: length 6
		    unsigned char* us_MAC = retrieve_mac_address(sr, interface);
		    uint8_t* us_IP = retrieve_ip_address(sr, interface); 
		    uint8_t bytes [] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		    //testing buffer
		    uint8_t *buf = (uint8_t*)malloc(42 * sizeof(char));
		    memset(buf, 0, 42);
	            uint8_t reply[] = {0x00, 0x02};
		    //************if it is an ARP request******************/
		    //if broadcast, check destination ip and compare with local ip
		    //if yes, construct arp reply to sender
		    if(!memcmp(packet, bytes, 6)){
			    if(!memcmp(packet + 38, us_IP, 4)){
				    //construct reply ARP packet
			//   dealWithARPRequest(sr, packet, interface, entry, us_IP, us_MAC);                   
				    memcpy(buf, packet + 6, 6);
				    memcpy(buf+6, us_MAC, 6);
				    memcpy(buf+12, packet+12, 2);
   				    memcpy(buf+14, packet+14, 2);
				    memcpy(buf+16, packet+16, 2);
				    memcpy(buf+18, packet+18, 1);
				    memcpy(buf+19, packet+19, 1);
				    memcpy(buf+20, reply, 2);
				    memcpy(buf+28, packet+38, 4);
                                    memcpy(buf+22, us_MAC, 6);
                                  //  memcpy(buf+32, packet+6, 6);
				    memcpy(buf+38, packet+28, 4);
				    sr_send_packet(sr,(uint8_t* )buf, 42, interface);
				    //printf("complete ARP request\n");
			    }
		    }
		    else
		    {  
			    //**********if it is an ARP reply**********************/
			    uint8_t* des_IP = (uint8_t *) malloc (sizeof(uint8_t) * 4);
			    memcpy(des_IP, packet + 38, 4);
			    //if the destination IP is the us_IP
			    if(memcmp(us_IP, des_IP, 4) == 0)
			    {
				    dealWithARPReply(sr, packet, interface, entry,
						    us_IP, us_MAC);
				    printf("complete ARP reply\n");
			    }

		    }

	    }
    }

}/* end sr_ForwardPacket */



/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
void dealWithARPRequest(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        char* interface,
        arp_cache_entry* entry,
        uint8_t* us_IP,
        uint8_t* us_MAC)
{
    //update the ARP cache table
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

    //construct the ARP reply packet
    uint8_t* dest_mac_address_uint8_t = (uint8_t *)malloc(sizeof(uint8_t) * 6);
    memcpy(dest_mac_address_uint8_t, packet + 6, 6);
    unsigned char* dest_mac_address_unsigned_char = (unsigned char *)malloc(sizeof(unsigned char) * 6);
    memcpy(dest_mac_address_unsigned_char, packet + 6, 6);
    unsigned char* us_MAC_unsigned_char = (unsigned char*)malloc(sizeof(unsigned char));
    memcpy(us_MAC_unsigned_char, us_MAC, 6); 
    uint32_t* dest_IP_temp = (uint32_t* )malloc(sizeof(uint32_t));
    uint32_t dest_IP = (*dest_IP_temp);
    
    PARPPACKET buf = constructReplyARPPacket(dest_mac_address_uint8_t,
            dest_mac_address_unsigned_char,
            us_MAC,
            us_MAC_unsigned_char,
            dest_IP,
            us_IP);
    
    sr_send_packet(sr,(uint8_t* )buf, 42, interface);
}

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
    
    unsigned char* us_MAC_unsigned_char = (unsigned char*)malloc(sizeof(unsigned char) * 6);
    memcpy(us_MAC_unsigned_char, us_MAC, 6);
    PARPPACKET buf = constructBroadcastARPPacket(us_MAC, 
            us_MAC_unsigned_char,
            convert_ip_to_integer(us_IP),
            entry->ip_address);

    sr_send_packet(sr, (uint8_t*)buf, 42, interface);

}

void assignBroadcastEthernetAddr(uint8_t* ether_dhost)
{
    uint8_t temp = 255;
    for(int i = 0; i < 6; i++)
        ether_dhost[i] = temp;    
}

void assignDefaultTargetEthernetAddr(unsigned char* ar_tha)
{
    for(int i = 0; i < 6; i++)
        ar_tha[i] = 0;    
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
/*----------------------------------------------------------------------
 *  Construct the Broadcast ARP packet 
 *  pass the constructed ARP packet as buf in sr_send_packet()
 *----------------------------------------------------------------------*/
PARPPACKET constructBroadcastARPPacket(uint8_t* s_mac_address_uint8_t, unsigned char* s_mac_address_unsigned_char, uint32_t s_IP, uint32_t d_IP)
{
    PARPPACKET arpPacket = (PARPPACKET)malloc(sizeof(ARPPACKET));

    assignBroadcastEthernetAddr(arpPacket->et_hdr.ether_dhost); 
    assignSourceEthernetAddrFirst(arpPacket->et_hdr.ether_shost, s_mac_address_uint8_t); 
    arpPacket->et_hdr.ether_type = htons(2054); 
 
    arpPacket->arp_hdr.ar_hrd = htons(1);
    arpPacket->arp_hdr.ar_pro = htons(2048);
    arpPacket->arp_hdr.ar_hln = 6;
    arpPacket->arp_hdr.ar_pln = 4;
    arpPacket->arp_hdr.ar_op = htons(1);
    assignSourceEthernetAddrSecond(arpPacket->arp_hdr.ar_sha, s_mac_address_unsigned_char);
    arpPacket->arp_hdr.ar_sip = s_IP;
    assignDefaultTargetEthernetAddr(arpPacket->arp_hdr.ar_tha);
    arpPacket->arp_hdr.ar_tip = d_IP;
    
    return arpPacket;
}

/*----------------------------------------------------------------------
 *  Construct the Reply ARP packet 
 *  pass the constructed ARP packet as buf in sr_send_packet()
 *----------------------------------------------------------------------*/
PARPPACKET constructReplyARPPacket(uint8_t* dest_mac_address_uint8_t, unsigned char* dest_mac_address_unsigned_char, uint8_t* source_mac_address_uint8_t, unsigned char* source_mac_address_unsigned_char, uint32_t dest_IP, uint32_t source_IP)
{
    PARPPACKET arpPacket = (PARPPACKET)malloc(sizeof(ARPPACKET));

    memcpy(arpPacket->et_hdr.ether_dhost, dest_mac_address_uint8_t, 6);
    memcpy(arpPacket->et_hdr.ether_shost, source_mac_address_uint8_t, 6); 
    arpPacket->et_hdr.ether_type = htons(2054); 
 
    arpPacket->arp_hdr.ar_hrd = htons(1);
    arpPacket->arp_hdr.ar_pro = htons(2048);
    arpPacket->arp_hdr.ar_hln = 6;
    arpPacket->arp_hdr.ar_pln = 4;
    arpPacket->arp_hdr.ar_op = htons(1);
    memcpy(arpPacket->arp_hdr.ar_sha, source_mac_address_unsigned_char, 6);
    arpPacket->arp_hdr.ar_sip = source_IP;
    memcpy(arpPacket->arp_hdr.ar_tha, dest_mac_address_unsigned_char, 6);
    arpPacket->arp_hdr.ar_tip =  dest_IP;
    
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
        printf("IP address: \n");
    while(arp_pointer){
        printf("IP address: %d\n" , arp_pointer->ip_address);
        printf("Char representation: %s\n", arp_pointer->mac_address_uint8_t);
                      printf("\n");
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

unsigned char* retrieve_mac_address(struct sr_instance* sr, char* interface)
{	
	struct sr_if* if_walker = 0;
	if(sr->if_list == 0)
	{
		printf("Interface list empty \n");
		return NULL;
	}
	if_walker = sr->if_list;

	unsigned char* mac = (unsigned char*)malloc(sizeof(unsigned char) * 6);

	while(if_walker)
	{
		if(!strncmp(if_walker->name, interface, 6))
		{
			memcpy(mac, if_walker->addr, 6);
		}
		if_walker= if_walker->next;	
	}
	return mac;
}	

uint8_t* retrieve_ip_address(struct sr_instance* sr, char* interface){
	struct sr_if* if_walker = 0;
	if(sr->if_list == 0)
	{
		printf("Interface list empty \n");
		return NULL;
	}
	if_walker = sr->if_list;

	uint8_t* ip = (uint8_t*)malloc(sizeof(uint8_t) * 4);

	while(if_walker)
	{
		if(!strncmp(if_walker->name, interface, 6))
		{
			*(ip) = if_walker->ip;
			*(ip + 1) = if_walker->ip>>8;
			*(ip + 2) = if_walker->ip>>16;		
			*(ip + 3) = if_walker->ip>>24;
		}	
		if_walker = if_walker->next;
	}
	return ip;
}

