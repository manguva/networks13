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
	
    uint8_t *sender_mac_address = (uint8_t *)malloc(6 * sizeof(uint8_t));
    uint8_t *sender_ip_address = (uint8_t *)malloc(4 * sizeof(uint8_t));
    arp_cache_entry *entry = (arp_cache_entry *)malloc(sizeof(arp_cache_entry));
//    printf("Received packet\n");
    int i = 0;
    while ( i < len){
        i++;
    }
    /*retrieving arp packet information */
    if(i>15){
	if( packet[12] == 8 && packet[13] == 6){
//		printf("Packet is of type arp\n");
	//retrieve mac address of sender
       
	memcpy(sender_mac_address, packet + 6, 6);
        memcpy(sender_ip_address, packet + 28, 4);
     }
    }
        arp_cache_entry copy;
	entry->mac_address = sender_mac_address;
        entry->ip_address = sender_ip_address;
        entry->interface_type = interface;
	entry->next = NULL;

        add_arp_entry(entry, &arp_table);
  //      pretty_print_arp_table(&arp_table);
    /*retrieving arp packet information */
    
}/* end sr_ForwardPacket */


/*code to add an entry to the arp table */
void add_arp_entry(arp_cache_entry *entry, arp_cache_entry *arp_cache){
     	assert(entry);
	if(!arp_cache->ip_address){
		arp_cache->ip_address = entry->ip_address;  
		arp_cache->mac_address= entry->mac_address;
		arp_cache->interface_type = entry->interface_type;
		arp_cache->next = NULL;
		return;
	}
        assert(arp_cache);

	//search if entry already exists
        arp_cache_entry *arp_pointer = arp_cache;
	while(arp_pointer != NULL){
                if (!memcmp(arp_pointer->ip_address, entry->ip_address, 4)){
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

/* method to pretty print arp table */
void pretty_print_arp_table(arp_cache_entry *arp_cache){
	arp_cache_entry *arp_pointer = arp_cache;
        int i = 0;
    //    printf("IP address: \n");
	while(arp_pointer){
                while (i < 4){
//			printf("%hx" , arp_pointer->ip_address[i]);
			i++;
		}
  //              printf("\n");
		arp_pointer = arp_pointer->next;
        }

}

/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
