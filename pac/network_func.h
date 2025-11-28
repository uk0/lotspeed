#ifndef	NETWORK_FUNC_H
#define	NETWORK_FUNC_H

#include <linux/skbuff.h>
#include <linux/time.h>  

//Function to calculate microsecond-granularity TCP timestamp value
static unsigned int get_tsval(void)
{	
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

//Function: modify incoming TCP packets
//return RTT sample value 
static unsigned int tcp_modify_incoming(struct  sk_buff *skb)
{
	struct iphdr *ip_header=NULL;			//IP  header structure
	struct tcphdr *tcp_header=NULL;      //TCP header structure
	unsigned int tcp_header_len=0;		  	//TCP header length
	unsigned char *tcp_opt=NULL;		  	//TCP option pointer
	unsigned int *tsecr=NULL;			 			//TCP Timestamp echo reply pointer
	int tcplen=0;						  						//Length of TCP
	unsigned char tcp_opt_value=0;		  	//TCP option pointer value
	unsigned int rtt=0;				 	  				//Sample RTT
	unsigned int option_len=0;			 		//TCP option length
	
	//If we can not modify this packet, return 0
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
	}
	
	//Get IP header
	ip_header=(struct iphdr *)skb_network_header(skb);
	//Get TCP header on the base of IP header
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	//Get TCP header length
	tcp_header_len=(unsigned int)(tcp_header->doff*4);
	
	//Minimum TCP header length=20(Raw TCP header)+10(TCP Timestamp option)
	if(tcp_header_len<30)
	{
		return 0;
	}
	
	//TCP option offset=IP header pointer+IP header length+TCP header length
	tcp_opt=(unsigned char*)ip_header+ ip_header->ihl*4+20;
	
	while(1)
	{
		//If pointer has moved out off the range of TCP option, stop current loop
		if(tcp_opt-(unsigned char*)tcp_header>=tcp_header_len)
		{
			break;
		}
		//Get value of current byte
		tcp_opt_value=*tcp_opt;
		
		if(tcp_opt_value==1)//No-Operation (NOP)
		{
			//Move to next byte
			tcp_opt++;
		}
		else if(tcp_opt_value==8) //TCP option kind: Timestamp (8)
		{
			//Get pointer to Timestamp echo reply (TSecr)
			tsecr=(unsigned int*)(tcp_opt+6);
			//Get one RTT sample
			rtt=get_tsval()-ntohl(*tsecr);
			//printk(KERN_INFO "RTT: %u\n",rtt);
			//Modify TCP TSecr back to jiffies
			//Don't disturb TCP. Wrong TCP timestamp echo reply may reset TCP connections
			*tsecr=htonl(jiffies);
			break;
		}
		else //Other TCP options (e.g. MSS(2))
		{
			//Move to next byte to get length of this TCP option 
			tcp_opt++;
			//Get length of this TCP option
			tcp_opt_value=*tcp_opt;
			option_len=(unsigned int)tcp_opt_value;
			
			//Move to next TCP option
			tcp_opt=tcp_opt+1+(option_len-2);
		}
	}
	
	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
			
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                  tcplen, ip_header->protocol,
                                  csum_partial((char *)tcp_header, tcplen, 0));
								  
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	return rtt;
}

//Function: modify outgoing TCP packets
// 	1. modify millisecond-granularity TCP timestamp to microsecond-granularity value
// 	2. modify TCP receive window
//Input: 
//	win: receive window value (in bytes)
//	time: microsecond-granularity value 
//If successfully, return 1. Else, return 0.
static unsigned int tcp_modify_outgoing(struct sk_buff *skb, unsigned int win, unsigned int time)
{
	struct iphdr *ip_header=NULL;			//IP  header structure
	struct tcphdr *tcp_header=NULL;      //TCP header structure
	unsigned int tcp_header_len=0;		  	//TCP header length
	unsigned char *tcp_opt=NULL;		  	//TCP option pointer
	unsigned int *tsval=NULL;			  		//TCP Timestamp value pointer
	int tcplen=0;						  						//Length of TCP
	unsigned char tcp_opt_value=0;		  	//TCP option pointer value
	unsigned int option_len=0;			 		 //TCP option length
	
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
	}
	
	//Get IP header
	ip_header=(struct iphdr *)skb_network_header(skb);
	//Get TCP header on the base of IP header
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	//Get TCP header length
	tcp_header_len=(unsigned int)(tcp_header->doff*4);
	
	//Minimum TCP header length=20(Raw TCP header)+10(TCP Timestamp option)
	if(tcp_header_len<30)
	{
		return 0;
	}
	
	//Modify TCP window. Note that TCP received window should be smaller than 65536 bytes and larger than 0 bytes
    if(win<65536&&win>0)
    {
        tcp_header->window=htons(win);
    }

	//TCP option offset=IP header pointer+IP header length+TCP header length
	tcp_opt=(unsigned char*)ip_header+ ip_header->ihl*4+20;
	
	while(1)
	{
		//If pointer has moved out off the range of TCP option, stop current loop
		if(tcp_opt-(unsigned char*)tcp_header>=tcp_header_len)
		{
			break;
		}
		
		//Get value of current byte
		tcp_opt_value=*tcp_opt;
		
		if(tcp_opt_value==1)//No-Operation (NOP)
		{
			//Move to next byte
			tcp_opt++;
		}
		else if(tcp_opt_value==8) //TCP option kind: Timestamp (8)
		{
			if(time>0) 
			{
				//Get pointer to Timestamp value 
				tsval=(unsigned int*)(tcp_opt+2);
				//Modify TCP Timestamp value
				*tsval=htonl(time);
			}
			break;
		}
		else //Other TCP options (e.g. MSS(2))
		{
			//Move to next byte to get length of this TCP option 
			tcp_opt++;
			//Get length of this TCP option
			tcp_opt_value=*tcp_opt;
			option_len=(unsigned int)tcp_opt_value;
			
			//Move to next TCP option
			tcp_opt=tcp_opt+1+(option_len-2);
		}
	}
	
	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
			
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
											tcplen, ip_header->protocol,
											csum_partial((char *)tcp_header, tcplen, 0));
								  									 
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	return 1;
}

//Maximum 32-bit integer value: 4294967295
//Function: determine whether seq1 is larger than seq2
//If Yes, return 1. Else, return 0.
static unsigned short int is_larger(unsigned int seq1, unsigned int seq2)
{
    if(seq1>seq2)
        return 1;
    //A simple heuristic to handle wrapped TCP sequence number 
     else if(seq1<seq2-4294900000)
        return 1;
     else
        return 0;
}

//Function: determine whether seq1 is smaller than seq2
//If Yes, return 1. Else, return 0.
static unsigned short int is_smaller(unsigned int seq1,unsigned seq2)
{
    //larger
    if(is_larger(seq1,seq2)==1)
        return 0;
    //equal
    else if(seq1==seq2)
        return 0;
    else
        return 1;
}

static unsigned int cumulative_ack(unsigned int seq1, unsigned int seq2)
{
    if(seq1>=seq2)
        return seq1-seq2;
    else
        return 4294967295-(seq2-seq1); 
}

#endif