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
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

arp_cache_entry arp_table;
/* 
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
	memset(&(sr->hosts[0]),0,sizeof(Host) * MAX_HOSTS);
    	memset(&(sr->cache[0]),0,sizeof(mPacket) * MAX_CACHE);

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

	//arp_cache_entry *entry = (arp_cache_entry *)malloc(sizeof(arp_cache_entry));
	//    printf("Received packet\n");
	//int i = len;
        printf("Packet received: \n");
	struct sr_if *eth_if = (struct sr_if *) sr_get_interface(sr, interface);
	if(eth_if) {
		printf("Dealing with interface: %s \n", eth_if->name);
	} else {
		printf("!!! Invalid Interface: %s \n", interface);
	}

	/* Ethernet Header */
	struct sr_ethernet_hdr *eth_hdr = (struct sr_ethernet_hdr *) packet;
	switch(ntohs(eth_hdr->ether_type)) {
		case ETHERTYPE_ARP:
			/*{
				unsigned char* us_MAC = retrieve_mac_address(sr, interface);
				uint8_t* us_IP = retrieve_ip_address(sr, interface); 
				uint8_t bytes [] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				//testing buffer
				uint8_t *buf = (uint8_t*)malloc(42 * sizeof(char));
				memset(buf, 0, 42);
			*/
				/************if it is an ARP request******************/
				//if broadcast, check destination ip and compare with local ip
				//if yes, construct arp reply to sender
			/*	if(!memcmp(packet, bytes, 6)){
					if(!memcmp(packet + 38, us_IP, 4)){

						//construct reply ARP packet
						uint8_t reply[] = {0x00, 0x02};
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
						memcpy(buf+38, packet+28, 4);
			*/
						/* update the ARP cache table  */
			/*			//get the IP and MAC of sender
						uint8_t* sender_IP = (uint8_t* )malloc(sizeof(uint8_t) * 4);
						memcpy(sender_IP, packet + 28, 4);
						entry->ip_address = convert_ip_to_integer(sender_IP);
						uint8_t* sender_MAC = (uint8_t* )malloc(sizeof(uint8_t) * 6);
						memcpy(sender_MAC, packet + 6, 4);
						memcpy(entry->mac_address_uint8_t, sender_MAC, 6);

						memcpy(entry->mac_address_unsigned_char, sender_MAC, 6);      

						entry->interface_type = interface;
						entry->next = NULL;
						add_arp_entry(entry, &arp_table);


						sr_send_packet(sr,(uint8_t* )buf, 42, interface);
						printf("complete ARP request\n");
					}
				} else	{  
			*/		/**********if it is an ARP reply**********************/
					/**********just update the ARP cache table*****************/	
			/*		uint8_t* des_IP = (uint8_t *) malloc (sizeof(uint8_t) * 4);
					memcpy(des_IP, packet + 38, 4);
					//check if the destination IP is the us_IP
					if(memcmp(us_IP, des_IP, 4) == 0)
					{

			*/			/* update the ARP cache table  */
						//get the IP and MAC of sender
			/*			uint8_t* sender_IP = (uint8_t* )malloc(sizeof(uint8_t) * 4);
						memcpy(sender_IP, packet + 28, 4);
						entry->ip_address = convert_ip_to_integer(sender_IP);
						uint8_t* sender_MAC = (uint8_t* )malloc(sizeof(uint8_t) * 6);
						memcpy(sender_MAC, packet + 6, 4);
						memcpy(entry->mac_address_uint8_t, sender_MAC, 6);

						memcpy(entry->mac_address_unsigned_char, sender_MAC, 6);      

						entry->interface_type = interface;
						entry->next = NULL;
						add_arp_entry(entry, &arp_table);
						printf("complete ARP reply\n");
					}

				}
			}*/
			sr_handle_arp_packet(sr, len, interface, packet);
			break;

		case ETHERTYPE_IP:
			{
				/* Copy over input parameters for thread */
				//struct sr_handlepacket_input *input = malloc(sizeof(struct sr_handlepacket_input));

				//uint8_t* version = (uint8_t*)malloc(sizeof(uint8_t)*4);
				struct ip *iphdr;
				iphdr = construct_ip_hdr(packet);
				add_host_to_cache(sr,iphdr,interface);
				struct sr_if *interfaces = sr->if_list;
				while(interfaces) {
					if (iphdr->ip_dst.s_addr == interfaces->ip) break;
					interfaces = interfaces->next;
				}				
				if (interfaces){
					printf("Packet delivered to interface: %s\n", interface);
					struct custom_icmp* my_icmp = (struct custom_icmp*)(packet + sizeof(struct sr_ethernet_hdr) + iphdr->ip_hl * 4); 
					if(iphdr->ip_p == IPPROTO_ICMP && my_icmp->type == ICMP_ECHO_REQUEST){ 
						my_icmp = get_icmp_hdr(packet, iphdr);
						printf("Echo request inside IP packet\n");
						sr_handle_icmp_packet(sr, len, interface, my_icmp, packet, iphdr, (struct sr_ethernet_hdr *) packet);
					}
					else {
						printf("Echo request inside IP packet interfaces\n");
						send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
					}
				} else {
					if (iphdr->ip_ttl > 1) {
							sr_route_packet(sr,packet,len,interface);
					} else {
						send_icmp_message(sr, len, interface, packet, ICMP_TIME_EXCEEDED, 0);
					}
				}
			}
			break;


		default:
			{
				printf("Invalid protocol\n");
				send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
			}
	}

}/* end sr_ForwardPacket */



/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/

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

void sr_handle_icmp_packet(struct sr_instance* sr, unsigned int len, char* interface, struct custom_icmp* icmphdr, uint8_t* packet, struct ip* ip_hdr, struct sr_ethernet_hdr* ethr_hdr) {
	if (icmphdr->type == ICMP_ECHO_REQUEST) { /*echo request*/
		printf("Echo request from %s to ", inet_ntoa(ip_hdr->ip_src));
		printf("%s.\n", inet_ntoa(ip_hdr->ip_dst));
		if (1) { /*(iface->ip)==((ip_hdr->ip_dst.s_addr))) { echo request to router*/
			int i;
			int tmp;
			for (i = 0; i < ETHER_ADDR_LEN; i++) {
				tmp = ethr_hdr->ether_dhost[i];
				ethr_hdr->ether_dhost[i] = ethr_hdr->ether_shost[i];
				ethr_hdr->ether_shost[i] = tmp;
			}
			ethr_hdr->ether_type = htons(ETHERTYPE_IP);
			in_addr_t* dest = malloc(sizeof (in_addr_t));
			*dest = (ip_hdr->ip_src.s_addr);
			ip_hdr->ip_src.s_addr = (ip_hdr->ip_dst.s_addr);
			ip_hdr->ip_dst.s_addr = *dest;
			free(dest);
			struct custom_icmp* icmphdr = get_icmp_hdr(packet, ip_hdr);
			icmphdr->type = ICMP_ECHO_REPLY;
			setICMPchecksum(icmphdr, packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4, len - sizeof (struct sr_ethernet_hdr) - ip_hdr->ip_hl * 4);
			sr_send_packet(sr, packet, len, interface);
		} else { /*echo request to app server or other interface */
		
			}
		}
	}

	struct custom_icmp *get_icmp_hdr(uint8_t *packet, struct ip* ip_hdr) {
		return (struct custom_icmp *) (packet + sizeof (struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);
	}

	void send_icmp_message(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet, uint8_t type, uint8_t code) {
		uint8_t * outpack = malloc(sizeof (struct sr_ethernet_hdr) + 64);
		struct sr_ethernet_hdr * out_eth_hdr = (struct sr_ethernet_hdr *) outpack;
		memcpy(out_eth_hdr, packet, sizeof (struct sr_ethernet_hdr));
		out_eth_hdr->ether_type = ntohs(ETHERTYPE_IP);
		int i;
		char tmp;
		for (i = 0; i < ETHER_ADDR_LEN; i++) {
			tmp = out_eth_hdr->ether_dhost[i];
			out_eth_hdr->ether_dhost[i] = out_eth_hdr->ether_shost[i];
			out_eth_hdr->ether_shost[i] = tmp;
		}
		struct ip* in_ip_hdr = get_ip_hdr(packet);
		
		//sr_get_interface(sr, interface)->ip;
		struct ip* tmp_ip = create_ip_hdr(0, 20, IPPROTO_ICMP, in_ip_hdr->ip_dst, in_ip_hdr->ip_src);
		struct ip* out_ip_hdr = (struct ip *) (outpack + sizeof (struct sr_ethernet_hdr));
		memcpy(outpack + sizeof (struct sr_ethernet_hdr), tmp_ip, 20);
		out_ip_hdr->ip_id = in_ip_hdr->ip_id;

		/* create and fill an icmp header */
		struct custom_icmp * out_icmp = (struct custom_icmp *) (outpack + sizeof (struct sr_ethernet_hdr) + 20);
		struct custom_icmp * tmpicmp = create_icmp_hdr(type, code, 0, 0);
		memcpy(out_icmp, tmpicmp, 8);
		free(tmpicmp);
		memcpy(((uint8_t *) out_icmp) + 8, in_ip_hdr, in_ip_hdr->ip_hl * 4 + 8);
		out_ip_hdr->ip_len = ntohs(28 + in_ip_hdr->ip_hl * 4 + 8);

		/* calculate checksums for message */
    		setICMPchecksum(out_icmp, outpack + sizeof (struct sr_ethernet_hdr) + 20, 16 + in_ip_hdr->ip_hl * 4);
    		setIPchecksum(out_ip_hdr);


		/* send message*/
		sr_send_packet(sr, outpack, sizeof (struct sr_ethernet_hdr) + 36 + in_ip_hdr->ip_hl * 4, interface);
		free(outpack);

		free(tmp_ip);
	}

	struct ip *get_ip_hdr(uint8_t *packet) {
		return (struct ip *) (packet + sizeof (struct sr_ethernet_hdr));
	}

	struct ip* create_ip_hdr(uint8_t type, uint8_t ttl, uint8_t protocol, struct in_addr src, struct in_addr dest) {
		struct ip* ip_hdr = malloc(20);
		ip_hdr->ip_v = 4;
		ip_hdr->ip_ttl = ttl;
		ip_hdr->ip_hl = 5;
		ip_hdr->ip_p = protocol;
		ip_hdr->ip_src = src;
		ip_hdr->ip_dst = dest;
		ip_hdr->ip_off = 0;
		ip_hdr->ip_tos = type;
		return ip_hdr;
	}

	struct custom_icmp* create_icmp_hdr(uint8_t type, uint8_t code, uint16_t id, uint16_t seq) {
		struct custom_icmp* icmp_hdr = malloc(sizeof (struct custom_icmp));
		icmp_hdr->type = type;
		icmp_hdr->code = code;
		icmp_hdr->id = id;
		icmp_hdr->seq = seq;

		uint16_t sum = 0;
		sum = ((type << 8)&0xFF00) + code;
		sum = sum + id + seq;

		return icmp_hdr;
	}


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

	void setIPchecksum(struct ip* ip_hdr) {
		uint32_t sum = 0;
		ip_hdr->ip_sum = 0;

		uint16_t* tmp = (uint16_t *) ip_hdr;

		int i;
		for (i = 0; i < ip_hdr->ip_hl * 2; i++) {
			sum = sum + tmp[i];
		}

		sum = (sum >> 16) + (sum & 0xFFFF);
		sum = sum + (sum >> 16);

		ip_hdr->ip_sum = ~sum;
	}

	void setICMPchecksum(struct custom_icmp* icmphdr, uint8_t * packet, int len) {
		uint32_t sum = 0;
    		icmphdr->checksum = 0;
    		uint16_t* tmp = (uint16_t *) packet;

    		int i;
    		for (i = 0; i < len / 2; i++) {
        		sum = sum + tmp[i];
    		}

    		sum = (sum >> 16) + (sum & 0xFFFF);
    		sum = sum + (sum >> 16);

    		icmphdr->checksum = ~sum;
	}

        struct ip* construct_ip_hdr(uint8_t *packet){
		return (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));	
	}

	void sr_handle_arp_packet(struct sr_instance* sr, unsigned int len, char* interface, uint8_t* packet) {
		struct sr_ethernet_hdr* ethr_hd = (struct sr_ethernet_hdr *) packet;
		struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

		if (arp_hdr->ar_op == ntohs(ARP_REQUEST)) {
			struct sr_if * iface = sr->if_list;
			while (iface) {
				if (iface->ip == arp_hdr->ar_tip) break;
				iface = iface->next;
			}
			int j;
			for (j = 0; j < MAX_HOSTS; j++) {
				if (sr->hosts[j].ip == arp_hdr->ar_tip &&  sr->hosts[j].iface && strcmp((char *)ethr_hd->ether_dhost, (char *)sr->hosts[j].iface->addr)) {
					break;
				}
			}
			if (iface || j < MAX_HOSTS) {
				struct sr_arphdr* arp_reply = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

				memcpy(ethr_hd->ether_dhost, ethr_hd->ether_shost, sizeof (ethr_hd->ether_dhost));
				memcpy(ethr_hd->ether_shost, sr->if_list->addr, sizeof (ethr_hd->ether_shost));
				ethr_hd->ether_type = htons(ETHERTYPE_ARP);

				arp_reply->ar_hrd = htons(ARPHDR_ETHER);
				arp_reply->ar_pro = htons(ETHERTYPE_IP);
				arp_reply->ar_hln = 06;
				arp_reply->ar_pln = 04;
				arp_reply->ar_op = htons(ARP_REPLY);
				memcpy(arp_reply->ar_sha, sr_get_interface(sr,interface)->addr, sizeof (ethr_hd->ether_dhost));

				memcpy(arp_reply->ar_tha, ethr_hd->ether_shost, sizeof (ethr_hd->ether_shost));
				uint32_t tmp = arp_reply->ar_tip;
				arp_reply->ar_tip = arp_reply->ar_sip;
				arp_reply->ar_sip = tmp;


				printf("--->Sending ARP REPLY!!\n");
				sr_send_packet(sr, packet, len, interface);
			}
		} else if (arp_hdr->ar_op == ntohs(ARP_REPLY)) {
			printf("got ARP reply\n");
			uint32_t naddr = arp_hdr->ar_sip;
			int i;
			int j;
			for (i = 0; i < MAX_HOSTS; i++) {
				if (sr->hosts[i].ip == naddr) {
					for (j = 0; j < ETHER_ADDR_LEN; j++) {
						sr->hosts[i].daddr[j] = arp_hdr->ar_sha[j];
					}
					sr->hosts[i].age = time(0);
					sr->hosts[i].queue = 0;
					sr->hosts[i].iface = sr_get_interface(sr,interface);
					break;
				} 
			}
			if (i < MAX_HOSTS) {
				for (j = 0; j < MAX_CACHE; j++) {
					if (sr->cache[j].len > 0 && sr->cache[j].ip == naddr) {
						sr_route_packet(sr,sr->cache[j].packet,sr->cache[j].len,"");
						sr->cache[j].len = 0;
						free(sr->cache[j].packet);
					}
				}
			}
		}
	}

	void add_host_to_cache(struct sr_instance * sr, struct ip* ip_hdr, char *interface){
		uint32_t ip = ip_hdr->ip_src.s_addr;
		struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *)
			(((uint8_t *)ip_hdr) - sizeof(struct sr_ethernet_hdr));
		int i;
		for (i = 0; i < MAX_HOSTS; i++){
			if (sr->hosts[i].ip == ip){
				sr->hosts[i].iface = sr_get_interface(sr, interface);
				sr->hosts[i].queue = 0;
            			sr->hosts[i].age = time(0);
				int j = 0;
				while ( j < ETHER_ADDR_LEN){
					sr->hosts[i].daddr[j] = eth_hdr->ether_shost[j];
					j++;
				}
				break;
			}
		}

		if (i == MAX_HOSTS) {
			for (i = 0; i < MAX_HOSTS; i++){
				if (sr->hosts[i].ip == 0){
					sr->hosts[i].ip = ip;
					sr->hosts[i].iface = sr_get_interface(sr, interface);
					sr->hosts[i].queue = 0;
            				sr->hosts[i].age = time(0);
					int j = 0;
					while ( j < ETHER_ADDR_LEN){
						sr->hosts[i].daddr[j] = eth_hdr->ether_shost[j];
						j++;
					}
					break;
				}
			}

		}


	}

	void sr_route_packet(struct sr_instance * sr, uint8_t * packet, int len, char* interface) {
		struct ip* ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
		uint32_t dst_ip = ip_hdr->ip_dst.s_addr;
                int flag = 0;
		int i;
		uint8_t to_cache = 1;
		for (i = 0; i < MAX_HOSTS; i ++) {
			if (sr->hosts[i].ip == dst_ip) {
				if (sr->hosts[i].queue == 0 && strcmp(sr->hosts[i].iface->name,interface)) {
					to_cache = 0;
				} else {
					send_arp_request(sr, dst_ip, interface);
					sr->hosts[i].queue += 1;
				}
				printf("host number %d\n",i);
				break;
			}
		}
		if (i < MAX_HOSTS) {
			if (to_cache == 0) {
				ip_hdr->ip_ttl -= 1;
				setIPchecksum(ip_hdr);
				struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
				int j;
				for (j = 0; j < ETHER_ADDR_LEN; j++) {
					eth_hdr->ether_dhost[j] = sr->hosts[i].daddr[j];
					eth_hdr->ether_shost[j] = sr->hosts[i].iface->addr[j];
				}
				printf("routing a packet\n");
				sr_send_packet(sr,packet,len,sr->hosts[i].iface->name);
			} else {
				printf("caching an old host packet\n");
				for (i = 0; i < MAX_CACHE; i++) {
					if (sr->cache[i].len == 0) {
						uint8_t * npacket = malloc(len + 1);
						memcpy(npacket,packet,len);
						sr->cache[i].packet = npacket;
						sr->cache[i].len = len;
						sr->cache[i].age = time(0);
						sr->cache[i].ip = dst_ip;
						break;
					}
				struct custom_icmp* my_icmp = (struct custom_icmp*)(packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);
                                                
                                              if (ip_hdr->ip_p == IPPROTO_ICMP && my_icmp->type == ICMP_ECHO_REQUEST && !flag){
                                        //      printf("Echo request inside IP packet ttl with protocol type: %d and icmp_type: %d\n", iphdr->ip_p, my_icmp->type);
                                              send_icmp_message(sr, len, interface, packet, ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE);
                                        	flag = 1; 
					     }

				}
			}
		} else {
			int k;
			printf("caching a new host packet\n");
			for (k = 0; k < MAX_CACHE; k++) {
				if (sr->cache[k].len == 0) {
					uint8_t * npacket = malloc(len + 1);
					memcpy(npacket, packet, len);
					sr->cache[k].packet = npacket;
					sr->cache[k].len = len;
					sr->cache[k].age = time(0);
					sr->cache[k].ip = dst_ip;
					break;
				}
			}   
			printf("cached, trying to obtain host address\n");
			for (k = 0; k < MAX_HOSTS; k++) {
				printf("looking at host %d\n",k);
				if (sr->hosts[k].ip == 0) {
					printf("find empty at host %d\n",k);
					sr->hosts[k].ip = dst_ip;
					sr->hosts[k].queue = 1;
					printf("find going at host %d\n",k);
					send_arp_request(sr,dst_ip,interface);
					break;
				}
			}
		}
	}



	void send_arp_request(struct sr_instance * sr, uint32_t dst_ip, char* interface) {
		printf("sending arp request\n");
		uint8_t * packet = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));

		struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
		struct sr_arphdr * arp_hdr = (struct sr_arphdr *) (packet + sizeof (struct sr_ethernet_hdr));

		eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
		eth_hdr->ether_dhost[0] = 255;
		eth_hdr->ether_dhost[1] = 255;
		eth_hdr->ether_dhost[2] = 255;
		eth_hdr->ether_dhost[3] = 255;
		eth_hdr->ether_dhost[4] = 255;
		eth_hdr->ether_dhost[5] = 255;

		arp_hdr->ar_hrd = ntohs(1);
		arp_hdr->ar_op = ntohs(ARP_REQUEST);
		arp_hdr->ar_pro = ntohs(ETHERTYPE_IP);
		arp_hdr->ar_hln = 6;
		arp_hdr->ar_pln = 4;
		arp_hdr->ar_tip = dst_ip;

		struct sr_if * iface = sr->if_list;
		while (iface) {
			if (strcmp(iface->name, interface)) {
				int j;
				for (j = 0; j < ETHER_ADDR_LEN; j++) {
					arp_hdr->ar_sha[j] = iface->addr[j];
					eth_hdr->ether_shost[j] = arp_hdr->ar_sha[j];
				}
				arp_hdr->ar_sip = iface->ip;
				sr_send_packet(sr, packet, sizeof (struct sr_ethernet_hdr) + sizeof (struct sr_arphdr), iface->name);
			}
			iface = iface->next;
		}
		free(packet);
	}

