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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

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
 * Method: sr_handlepacket(uint8_t* p,char* interface)
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


    printf("*** -> Received packet of length %d \n",len);

    //for the to be sent Packet
    ARPPACKET buf = getSentARPPacket(.....);
    
    sr_send_packet(sr, buf, 42, interface);


}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

void assignBroadcastEthernetAddr(uint8_t* ether_dhost)
{
    for(int i = 0; i < 6; i++)
        ether_dhost[i] = htons(255);    
}

void assignDefaultTargetEthernetAddr(unsigned char* ar_tha)
{
    for(int i = 0; i < 6; i++)
        ether_dhost[i] = htons(0);    
}

void assignSourceEthernetAddrFirst(uint8_t* ether_shost, uint8_t* info)
{
    /*.....wait for wallace value*/
}

void assignSourceEthernetAddrSecond(unsigned char* ether_shost, unsigned char* info)
{
    /*.....wait for wallace value*/
}

void assignIPAddr(uint32_t ipAddr, uint32_t info)
{
    /*.....wait for wallace value*/
}

/*----------------------------------------------------------------------
 *  Construct the ARP packet 
 *  pass the constructed ARP packet as buf in sr_send_packet()
 *----------------------------------------------------------------------*/
ARPPACKET getSentARPPacket(struct arp_entry* entry)
{
    ARPACKET arpPacket = 0;
    assignBroadcastEthernetAddr(arpPacket->et_hdr->ether_dhost, 6); 
   //................wait......
    assignSourceEthernetAddrFirst(arpPacket->et_hdr->ether_shost, ....);
   
    arpPacket->et_hdr->ether_type = htons(2054); 
    arpPacket->arp_hdr->ar_hrd = htons(1);
    arpPacket->arp_hdr->ar_pro = htons(2048);
    arpPacket->arp_hdr->ar_hln = (unsigned char*)htons(6);
    arpPacket->arp_hdr->ar_pln = (unsigned char*)htons(4);
    arpPacket->arp_hdr->ar_op = htons(1);
    
    //..........wait............
    assignSourceEthernetAddrSecond(arpPacket->arp_hdr->ar_sha, ...);
    //............wait..........
    assignIpAddr(arpPacket->arp_hdr->ar_sip, ....);
    
    assignDefaultTargetEthernetAdd(arpPacket->arp_hdr->artha);
    //...........wait............
    assignIpAddr(arpPacket->arp_hdr->ar_tip, ...);

    return arpPacket;
} 
