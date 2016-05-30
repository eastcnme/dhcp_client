
#include <stdio.h>		
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <stddef.h>
#include <fcntl.h>		/* To set non blocking on socket  */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>		/* Generic socket calls */
#include <sys/ioctl.h>
#include <sys/types.h>       
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "lpf_dhcp.h"

#define ETHER_HDR_SIZE      14	
#define IP_HDR_SIZE         20	
#define UDP_HDR_SIZE        8	
#define PORT                67
#define DHCP_GIADDR         "0.0.0.0"

static u_int8_t l3_tos =    0x10;	
static char ip_str[32] = {0};

static char *get_ip_str(u_int32_t ip)
{
	struct in_addr src;
    memset(&src, '\0', sizeof(src));
    memset(ip_str, '\0', sizeof(ip_str));

    src.s_addr = ip;
    
	inet_ntop(AF_INET, ((struct sockaddr_in *)&src), ip_str, sizeof(ip_str));
    
	return ip_str;
}

static void reset_dhopt_size(struct dhcp_option *opt)
{
    memset(opt->dhopt_buff, 0, sizeof(opt->dhopt_buff));
	opt->dhopt_size = 0;
}

/* 设置 DHCP xid */
static void set_rand_dhcp_xid(struct dhcp_option *opt)
{
	if (opt->dhcp_xid == 0) 
    {
		srand(time(NULL) ^ (getpid() << 16));
		opt->dhcp_xid = rand() % 0xffffffff;
	}
}

/* 计算IP校验和 */
static u_int16_t ipchksum(u_int16_t *buff, int words) 
{
	unsigned int sum;
    int i;
	sum = 0;
	for(i = 0;i < words; i++){
		sum = sum + *(buff + i);
	}
	sum = (sum >> 16) + sum;
	return (u_int16_t)~sum;
}


/* 计算TCP/UDP校验和 */
static u_int16_t l4_sum(u_int16_t *buff, int words, u_int16_t *srcaddr, u_int16_t *dstaddr, u_int16_t proto, u_int16_t len) 
{
	unsigned int sum, last_word = 0;
    int i;
    
	if ((htons(len) % 2) == 1) 
    {
		last_word = *((u_int8_t *)buff + ntohs(len) - 1);
		last_word = (htons(last_word) << 8);
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}
		sum = sum + last_word;
		sum = sum + *(srcaddr) + *(srcaddr + 1) + *(dstaddr) + *(dstaddr + 1) + proto + len;
        sum = (sum >> 16) + sum;
		return ~sum;
	} 
    else
    {
		sum = 0;
		for(i = 0;i < words; i++){
			sum = sum + *(buff + i);
		}

		sum = sum + *(srcaddr) + *(srcaddr + 1) + *(dstaddr) + *(dstaddr + 1) + proto + len;
		sum = (sum >> 16) + sum;
		return ~sum;
	}
}

/* Function maps all pointers on OFFER/ACK/ARP/ICMP packet */
static int map_all_layer_ptr(struct dhcp_client *client)
{   
	client->eth_hg  = (struct ethernet_hdr *)client->dhcp_packet_recv;
	client->iph_g   = (struct iphdr *)(client->dhcp_packet_recv + ETHER_HDR_SIZE);
	client->uh_g    = (struct udphdr *)(client->dhcp_packet_recv + ETHER_HDR_SIZE + IP_HDR_SIZE);
	client->dhcph_g = (struct dhcpv4_hdr *)(client->dhcp_packet_recv + ETHER_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE);
	client->dhopt_pointer_g = (u_int8_t *)(client->dhcp_packet_recv + ETHER_HDR_SIZE + IP_HDR_SIZE + 
        UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr));

    return 0;
}

/* 设置DHCP 53消息类型选项 */
static void build_option53(u_int8_t msg_type, struct dhcp_option *option)
{   
    u_int8_t msgtype = DHCP_MESSAGETYPE;
	u_int8_t msglen = 1;
	u_int8_t msg = msg_type;

	memcpy(option->dhopt_buff, &msgtype, 1);
    strncpy((char *)(option->dhopt_buff + 1), (char *)&msglen, 1);
    strncpy((char *)(option->dhopt_buff + 2), (char *)&msg, 1);
	option->dhopt_size = option->dhopt_size + 3;
}

/* 设置DHCP 50向dhcp服务器申请指定IP选项 */
static void build_option50(struct dhcp_option *opt)
{   
#if 0
    TRACE("--------option50_ip: %u %s %d\r\n", opt->option50_ip, MDL);
    TRACE("------- option50_ip: %s \n", get_ip_str(opt->option50_ip));
#endif
    
    u_int8_t msgtype = DHCP_REQUESTEDIP;
	u_int8_t msglen = 4;
	u_int32_t msg = opt->option50_ip; 

	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), &msg, 4);
	opt->dhopt_size = opt->dhopt_size + 6; 
}

/* 设置DHCP 51向dhcp服务器申请IP分配有效时间选项 */
static void build_option51(struct dhcp_option *opt)
{
	u_int8_t msgtype = DHCP_LEASETIME;
	u_int8_t msglen = 4;
	u_int32_t msg = htonl(opt->option51_lease_time); 

	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), &msg, 4);
	opt->dhopt_size = opt->dhopt_size + 6; 
}

/* 设置DHCP 54 DHCP服务器地址选项 */
static void build_option54(struct dhcp_option *opt)
{
	u_int8_t msgtype = DHCP_SERVIDENT;
	u_int8_t msglen = 4;
	u_int32_t msg = opt->server_id;

#if 0
    TRACE("------- server_id: %s \n", get_ip_str(opt->server_id));
#endif
    
	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), &msg, 4);
	opt->dhopt_size = opt->dhopt_size + 6; 
}

/* 设置DHCP 55 DHCP可选参数选项 */
static void build_option55(struct dhcp_option *opt) 
{
	u_int32_t msgtype = DHCP_PARAMREQUEST;
	u_int32_t msglen = 4;
	u_int8_t msg[4] = { 0 };
    
	msg[0] = DHCP_SUBNETMASK;
	msg[1] = DHCP_ROUTER;
	msg[2] = DHCP_DOMAINNAME;
	msg[3] = DHCP_DNS;
	/* msg[4] = DHCP_LOGSERV; */

	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), msg, 4);
	opt->dhopt_size = opt->dhopt_size + 6; 
}

/* Builds DHCP option60 on dhopt_buff */
static void build_option60_vci(struct dhcp_option *opt)
{
	u_int32_t msgtype = DHCP_CLASSSID;
	u_int32_t msglen = strlen((const char *)opt->vci_buff);

	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), opt->vci_buff, strlen((const char *)opt->vci_buff));

	opt->dhopt_size = opt->dhopt_size + 2 + strlen((const char *)opt->vci_buff);
}

/*
 * Builds DHCP option 12, hostname, on dhopt_buff
 * The DHCP Client Option12 feature specifies the hostname of the client
 */
static void build_option12_hostname(struct dhcp_option *opt)
{
	u_int32_t msgtype = DHCP_HOSTNAME;
	u_int32_t msglen = strlen(opt->hostname_buff);
    
	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), opt->hostname_buff, strlen(opt->hostname_buff));

	opt->dhopt_size = opt->dhopt_size + 2 + strlen(opt->hostname_buff);
}


/*
 * Builds DHCP option 81, fqdn, on dhopt_buff
 */
static void build_option81_fqdn(struct dhcp_option *opt)
{
	u_int32_t msgtype = DHCP_FQDN;
	u_int8_t flags = 0;
	u_int8_t rcode1 = 0;
	u_int8_t rcode2 = 0;
	u_int32_t msglen = strlen((const char *)opt->fqdn_buff) + 3;

	if (opt->fqdn_n)
		flags |= FQDN_N_FLAG;
	if (opt->fqdn_s)
		flags |= FQDN_S_FLAG;

	memcpy((opt->dhopt_buff + opt->dhopt_size), &msgtype, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 1), &msglen, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 2), &flags, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 3), &rcode1, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 4), &rcode2, 1);
	memcpy((opt->dhopt_buff + opt->dhopt_size + 5), opt->fqdn_buff, strlen((const char *)opt->fqdn_buff));

	opt->dhopt_size = opt->dhopt_size + 2 + msglen;
}

/*
 * Builds DHCP end of option on dhopt_buff
 */
static void build_optioneof(struct dhcp_option *opt)
{
	u_int8_t eof = 0xff;
    
	memcpy((opt->dhopt_buff + opt->dhopt_size), &eof, 1);
	opt->dhopt_size = opt->dhopt_size + 1; 
}

void build_discover_option(struct dhcp_option *option)
{
    set_rand_dhcp_xid(option); 
    
    /* option 53: 设置dhcp消息类型 */
	build_option53(DHCP_MSGDISCOVER, option);	/* Option53 for DHCP discover */

    /* option 12: The DHCP Client Option12 feature specifies the hostname of the client */
    if (option->hostname_flag) 
    {
		build_option12_hostname(option);
	}
    
	if (option->fqdn_flag) 
    {
		build_option81_fqdn(option);
	}

    /* option 50: dhcp-requested-address */
	if (option->option50_ip) 
    {
		build_option50(option);		/* Option50 - req. IP  */
	}

    /* option 51: dhcp-lease-time  */
	if (option->option51_lease_time) 
    {
		build_option51(option);               /* Option51 - DHCP lease time requested */
	}
    
	if (option->vci_flag == 1) 
    {
		build_option60_vci(option); 		/* Option60 - VCI  */
	}
    
	build_optioneof(option);			/* End of option */
}

void build_request_option(struct dhcp_option *opt)
{
	reset_dhopt_size(opt);

    build_option53(DHCP_MSGREQUEST, opt); 

#if 0
    char buff[32] = {0};
    get_fix_ipaddr(opt->option50_ip, buff, sizeof(buff));
    
    TRACE("--option50_ip: (%u)%s, server_id: (%u)%s %s %d\n", opt->option50_ip, buff, 
        opt->server_id, get_ip_str(opt->server_id), MDL);
    
    TRACE("--option50_ip: %u-%s %s %d\r\n", opt->option50_ip, get_ip_str(opt->option50_ip), MDL);
#endif
    
    if (opt->option50_ip)
    {
        build_option50(opt);       /* option */
    }

    if (opt->server_id)
    {
        build_option54(opt);
    }
    
    if (opt->hostname_flag) 
    {
		build_option12_hostname(opt);
	}
    
	if (opt->fqdn_flag) 
    {
		build_option81_fqdn(opt);
	}
    
	if (opt->vci_flag == 1) 
    {
		build_option60_vci(opt);  
	}

    if(opt->option51_lease_time) 
    {
		build_option51(opt);                       /* Option51 - DHCP lease time requested */
	}
    
	build_option55(opt);
    
	build_optioneof(opt);
}

int build_discover_packet(struct dhcp_client *client)
{
    u_int16_t buf[2048] = {0};
	u_int32_t dhcp_packet_size = sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size;

    memset(client->dhcp_packet_send, 0, sizeof(client->dhcp_packet_send));
    
    if (!client->opt.dhcp_release_flag) 
    {
		u_char dmac_tmp[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		memcpy(client->remote_mac, dmac_tmp, ETHER_ADDR_LEN);
	}

    if (client->opt.vlan == 0) 
    {       
        struct ethernet_hdr t_ethhdr;
        memset(&t_ethhdr, 0, sizeof(struct ethernet_hdr));
        struct ethernet_hdr *ethhdr = &t_ethhdr;

		memcpy(ethhdr->ether_dhost, client->remote_mac, ETHER_ADDR_LEN);      /* 目的mac地址 */
        memcpy(ethhdr->ether_shost, client->local_mac, ETHER_ADDR_LEN);     /* 源mac地址 */
        
        ethhdr->ether_type = htons(ETHERTYPE_IP);                           /* 类型 */

        memcpy(client->dhcp_packet_send, (char *)ethhdr, sizeof(struct ethernet_hdr));
	}
    else
    {
        struct vlan_hdr t_vhdr;
        memset(&t_vhdr, 0, sizeof(struct vlan_hdr));
        struct vlan_hdr *vhdr = &t_vhdr;

		memcpy(vhdr->vlan_dhost, client->remote_mac, ETHER_ADDR_LEN);
		memcpy(vhdr->vlan_shost, client->local_mac, ETHER_ADDR_LEN);
		vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
		vhdr->vlan_priority_c_vid = htons(client->opt.vlan);
		vhdr->vlan_len = htons(ETHERTYPE_IP);
        
        memcpy(client->dhcp_packet_send, (char *)vhdr, sizeof(struct vlan_hdr));  
	}

	if (client->opt.padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) 
    {
		memset(client->opt.dhopt_buff + client->opt.dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
		client->opt.dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
	}

    /* ------------------------------------------------------------------------------------------------------ */
    
    /* 填充ip头部  */
    struct iphdr t_iphdr;
    memset(&t_iphdr, 0, sizeof(t_iphdr));
    struct iphdr *iph = &t_iphdr;

    iph->version = 4;
	iph->ihl = 5;
	iph->tos = l3_tos;
    /* ip数据报总长度 = ip头20字节 + udp头8字节 + dhcp头 + dhcp选项数据 */
	iph->tot_len = htons(IP_HDR_SIZE +  UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size);  
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 128;
	iph->protocol = 17;
	iph->check = 0; // Filled later;

    iph->saddr = client->inaddr_any.s_addr;
    iph->daddr = client->sockaddr_broadcast.sin_addr.s_addr;
    
    #if 0
    if (client->opt.unicast_flag)
		iph->saddr = client->opt.unicast_ip_address;
	else
		iph->saddr = inet_addr("0.0.0.0");

    iph->daddr = inet_addr(SERVER_ADDR);
    #endif

    memset(buf, 0, sizeof(buf));
    memcpy(buf, iph, sizeof(struct iphdr));
    iph->check = ipchksum((u_int16_t *)buf, iph->ihl << 1);
    
    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE, (char *)iph, sizeof(struct iphdr));

    /* ------------------------------------------------------------------------------------------------------ */

    /* 填充udp头部 */
    struct udphdr t_uh;
    memset(&t_uh, 0, sizeof(struct udphdr));
    struct udphdr *uh = &t_uh;

#if 0
    uh->source = htons(PORT + 1);
	uh->dest = htons(PORT);
#endif

    uh->source = client->local_port;
	uh->dest = client->sockaddr_broadcast.sin_port;

    u_int16_t l4_proto = 17;
	u_int16_t l4_len = (UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size);
	uh->len = htons(l4_len);
	uh->check = 0; /* UDP checksum will be done after dhcp header*/

    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE, (char *)uh, sizeof(struct udphdr));
    
    /* ------------------------------------------------------------------------------------------------------ */

    /* 填充dhcp头部 */
	struct dhcpv4_hdr t_dhpointer;
    memset(&t_dhpointer, 0, sizeof(t_dhpointer));
    struct dhcpv4_hdr *dhpointer = &t_dhpointer;

    dhpointer->dhcp_opcode = DHCP_REQUEST;
	dhpointer->dhcp_htype = ARPHRD_ETHER;
	dhpointer->dhcp_hlen = ETHER_ADDR_LEN;
	dhpointer->dhcp_hopcount = 0;
	dhpointer->dhcp_xid = htonl(client->opt.dhcp_xid);
	dhpointer->dhcp_secs = 0;
	dhpointer->dhcp_flags = client->opt.bcast_flag;
	if (client->opt.unicast_flag)
		dhpointer->dhcp_cip = client->opt.unicast_ip_address;
	else
		dhpointer->dhcp_cip = 0;
	dhpointer->dhcp_yip = 0;
	dhpointer->dhcp_sip = 0;
	dhpointer->dhcp_gip = inet_addr(DHCP_GIADDR);
	memcpy(dhpointer->dhcp_chaddr, client->local_mac, ETHER_ADDR_LEN);
	/*dhpointer->dhcp_sname 
	  dhpointer->dhcp_file*/
	dhpointer->dhcp_magic = htonl(DHCP_MAGIC);

    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE, 
            (char *)dhpointer, 
            sizeof(struct dhcpv4_hdr));      
    
	/* DHCP option buffer is copied here to DHCP packet */
	u_char *dhopt_pointer = (u_char *)(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE 
	                                    + UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr));
	memcpy(dhopt_pointer, client->opt.dhopt_buff, client->opt.dhopt_size);
    client->dhcp_packet_len = ETHER_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size;

	/* UDP checksum is done here */
    memset(buf, 0, sizeof(buf));
    memcpy(buf, client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE, 
                sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size + UDP_HDR_SIZE);

    u_int16_t saddr = 0;
    u_int16_t daddr = 0;
    memcpy(&saddr, &iph->saddr, sizeof(saddr));
    memcpy(&daddr, &iph->daddr, sizeof(daddr));
        
    uh->check = l4_sum((u_int16_t *)buf, 
                ((sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size + UDP_HDR_SIZE) / 2), 
                &saddr, 
                &daddr,
                htons(l4_proto), 
                htons(l4_len)); 

    return 0;
}

int build_request_packet(struct dhcp_client *client)
{
    u_int16_t buf[2048] = {0};
	u_int32_t dhcp_packet_size = sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size;

    memset(client->dhcp_packet_send, 0, sizeof(client->dhcp_packet_send));
    
    if (!client->opt.dhcp_release_flag) 
    {
		memset(client->remote_mac, 0xff, ETHER_ADDR_LEN);
	}

    if (client->opt.vlan == 0) 
    {   
        struct ethernet_hdr t_ethhdr;
        memset(&t_ethhdr, 0, sizeof(struct ethernet_hdr));
        struct ethernet_hdr *ethhdr = &t_ethhdr;
        
		memcpy(ethhdr->ether_dhost, client->remote_mac, ETHER_ADDR_LEN);
		memcpy(ethhdr->ether_shost, client->local_mac, ETHER_ADDR_LEN);

        ethhdr->ether_type = htons(ETHERTYPE_IP);
        
        memcpy(client->dhcp_packet_send, (char *)ethhdr, sizeof(struct ethernet_hdr));
	} 
    else 
    {
        struct vlan_hdr t_vhdr;
        memset(&t_vhdr, 0, sizeof(struct vlan_hdr));
        struct vlan_hdr *vhdr = &t_vhdr;

		memcpy(vhdr->vlan_dhost, client->remote_mac, ETHER_ADDR_LEN);
		memcpy(vhdr->vlan_shost, client->local_mac, ETHER_ADDR_LEN);
		vhdr->vlan_tpi = htons(ETHERTYPE_VLAN);
		vhdr->vlan_priority_c_vid = htons(client->opt.vlan);
		vhdr->vlan_len = htons(ETHERTYPE_IP);
        
        memcpy(client->dhcp_packet_send, (char *)vhdr, sizeof(struct vlan_hdr));
	}

	if (client->opt.padding_flag && dhcp_packet_size < MINIMUM_PACKET_SIZE) 
    {
		memset(client->opt.dhopt_buff + client->opt.dhopt_size, 0, MINIMUM_PACKET_SIZE - dhcp_packet_size);
		client->opt.dhopt_size += MINIMUM_PACKET_SIZE - dhcp_packet_size;
	}

    /* ----------------------------------------------------------------------------------- */
    
    struct iphdr t_iph;
    memset(&t_iph, 0, sizeof(t_iph));
    struct iphdr *iph = &t_iph;

    iph->version = 4;
	iph->ihl = 5;
	iph->tos = l3_tos;
	iph->tot_len = htons(IP_HDR_SIZE +  UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size);  
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 128;
	iph->protocol = 17;
	iph->check = 0; // Filled later;

#if 0
    if (client->opt.unicast_flag)
		iph->saddr = client->opt.unicast_ip_address;
	else
		iph->saddr = inet_addr("0.0.0.0");
	iph->daddr = inet_addr(SERVER_ADDR);
#else

    iph->saddr = client->inaddr_any.s_addr;
    iph->daddr = client->sockaddr_broadcast.sin_addr.s_addr;

#endif

    memset(buf, 0, sizeof(buf));
    memcpy(buf, iph, sizeof(struct iphdr));
    iph->check = ipchksum((u_int16_t *)buf, iph->ihl << 1);
    
    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE, (char *)iph, sizeof(struct iphdr));

    /* ----------------------------------------------------------------------------------- */

    struct udphdr t_uh;
    memset(&t_uh, 0, sizeof(t_uh));
    struct udphdr *uh = &t_uh;

#if 0
	uh->source = htons(PORT + 1);
	uh->dest = htons(PORT);
#else
    uh->source = client->local_port;
	uh->dest = client->sockaddr_broadcast.sin_port;
#endif

    u_int16_t l4_proto = 17;
	u_int16_t l4_len = (UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size);
	uh->len = htons(l4_len);
	uh->check = 0; /* UDP checksum will be done after building dhcp header*/
    
    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE, (char *)uh, sizeof(struct udphdr));

    /* ----------------------------------------------------------------------------------- */

    struct dhcpv4_hdr t_dhhdr;
    memset(&t_dhhdr, 0, sizeof(struct dhcpv4_hdr));
    struct dhcpv4_hdr *dhhdr = &t_dhhdr;

    dhhdr->dhcp_opcode = DHCP_REQUEST;
	dhhdr->dhcp_htype = ARPHRD_ETHER;
	dhhdr->dhcp_hlen = ETHER_ADDR_LEN;
	dhhdr->dhcp_hopcount = 0;
	dhhdr->dhcp_xid = htonl(client->opt.dhcp_xid);
	dhhdr->dhcp_secs = 0;
	dhhdr->dhcp_flags = client->opt.bcast_flag;
	if (client->opt.unicast_flag)
		dhhdr->dhcp_cip = client->opt.unicast_ip_address;
	else
		dhhdr->dhcp_cip = 0;
	dhhdr->dhcp_yip = 0;
	dhhdr->dhcp_sip = 0;
	dhhdr->dhcp_gip = inet_addr(DHCP_GIADDR);
	memcpy(dhhdr->dhcp_chaddr, client->local_mac, ETHER_ADDR_LEN);
	/*dhpointer->dhcp_sname 
	  dhpointer->dhcp_file*/
	dhhdr->dhcp_magic = htonl(DHCP_MAGIC);
    
    memcpy(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE, 
            (char *)dhhdr, sizeof(struct dhcpv4_hdr)); 
    
	/* DHCP option buffer is copied here to DHCP packet */
	u_char *dhopt_pointer = (u_char *)(client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE + 
	                                        UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr));
	memcpy(dhopt_pointer, client->opt.dhopt_buff, client->opt.dhopt_size);
    
    client->dhcp_packet_len = ETHER_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE + sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size;
        
    /* ----------------------------------------------------------------------------------- */

    memset(buf, 0, sizeof(buf));
    memcpy(buf, client->dhcp_packet_send + ETHER_HDR_SIZE + IP_HDR_SIZE, 
            sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size + UDP_HDR_SIZE);

    u_int16_t saddr = 0;
    u_int16_t daddr = 0;
    memcpy(&saddr, &iph->saddr, sizeof(saddr));
    memcpy(&daddr, &iph->daddr, sizeof(daddr));

    /* UDP checksum */
    uh->check = l4_sum((u_int16_t *)buf,
                ((sizeof(struct dhcpv4_hdr) + client->opt.dhopt_size + UDP_HDR_SIZE) / 2), 
                &saddr, 
                &daddr, 
                htons(l4_proto), 
                htons(l4_len)); 
    
    return 0;
}

static int check_packet(int pkt_type, struct dhcp_client *client) 
{
    int result = UNKNOWN_PACKET;
    
	map_all_layer_ptr(client);

    u_int8_t *tmp_dhopt = client->dhopt_pointer_g;

#if 0
    TRACE("---- DHCP_MSGOFFER: %d, DHCP_MSGACK = %d, DHCP_MSGNACK = %d \r\n", DHCP_MSGOFFER, DHCP_MSGACK, DHCP_MSGNACK);
    
    TRACE("---- ETHER_TYPE: 0x%04x, protocol = %d, source = %d, dest = %d, "
          "*(tmp_dhopt + 2) = %d, client->dhcph_g->dhcp_xid = 0x%x, client->opt.dhcp_xid = 0x%x \r\n",      
                    ntohs(client->eth_hg->ether_type), client->iph_g->protocol, 
                    ntohs(client->uh_g->source), ntohs(client->uh_g->dest),
                    *(tmp_dhopt + 2), htonl(client->dhcph_g->dhcp_xid), client->opt.dhcp_xid);
#endif

    int msgType = *(tmp_dhopt + 2);
    int dhcpXid = htonl(client->dhcph_g->dhcp_xid);
    
    switch (pkt_type)
    {
        case DHCP_MSGOFFER:
           if (client->eth_hg->ether_type == htons(ETHERTYPE_IP) 
               && client->iph_g->protocol == 17
               && client->uh_g->source == htons(PORT) 
               && client->uh_g->dest == htons(PORT + 1)) 
           {
    			if (msgType == DHCP_MSGOFFER && dhcpXid == client->opt.dhcp_xid) 
                {
    				result =  DHCP_OFFR_RCVD;
    			} 
           }
           
           break;

        case DHCP_MSGACK:
            if (client->eth_hg->ether_type == htons(ETHERTYPE_IP) 
                && client->iph_g->protocol == 17 
                && client->uh_g->source == htons(PORT) 
                && client->uh_g->dest == htons(PORT + 1)) 
            {
    			if (msgType == DHCP_MSGACK 
                    && dhcpXid == client->opt.dhcp_xid) 
                {
    				result = DHCP_ACK_RCVD;
    			} 
                else if (msgType == DHCP_MSGNACK
                    && dhcpXid == client->opt.dhcp_xid) 
                {
    				result = DHCP_NAK_RCVD;
    			} 
    		}

            break;

        default:
            result = UNKNOWN_PACKET;
            break;
    }
    
    return result;  
}

void set_request_opt50_and_opt54(struct dhcp_client *client, const char *servIp)
{
    struct in_addr dst;

    memset(&dst, 0, sizeof(dst));
    inet_pton(AF_INET, servIp, (void *)&dst);
    
    client->opt.server_id = dst.s_addr;
    client->opt.option50_ip = client->dhcph_g->dhcp_yip;        /* offerered ip */
}


void set_option54(const char *ip_str, struct dhcp_option *option)
{
    if (ip_str == NULL)
    {   
        option->server_id = 0;
        return;
    }
    
    struct in_addr dst;

    memset(&dst, 0, sizeof(dst));
    inet_pton(AF_INET, ip_str, (void *)&dst);
    option->server_id = dst.s_addr;
}

void set_option50(const char *ip_str, struct dhcp_option *option)
{
    if (ip_str == NULL)
    {
        option->option50_ip = 0;
        return;
    }
    
    struct in_addr dst;

    memset(&dst, 0, sizeof(dst));
    inet_pton(AF_INET, ip_str, (void *)&dst);
    option->option50_ip = dst.s_addr;
}

int decode_dhcp_packet(struct dhcp_client *client, DHCP_RESULT *result)
{
    int retval = -1;
    u_int16_t tmp;
    u_int16_t dnsNum = 0;

#if DHCLIENT_DEBUG
    fprintf(stdout, "\n* decode_dhcp_packet\n");
	fprintf(stdout, "* ----------------------------------------------------------\n");
	fprintf(stdout, "* DHCP offered IP from server - %s\n", get_ip_str(client->dhcph_g->dhcp_yip));
	fprintf(stdout, "* Next server IP(Probably TFTP server) - %s\n", get_ip_str(client->dhcph_g->dhcp_sip));

    if (client->dhcph_g->dhcp_gip)
    {
		fprintf(stdout, "* DHCP Relay agent IP - %s\n", get_ip_str(client->dhcph_g->dhcp_gip));
	}
#endif

    memset(result, 0, sizeof(DHCP_RESULT));

    if (client->iface_name[0] != '\0')
    {
        strncpy(result->if_name, client->iface_name, sizeof(result->if_name) - 1);
    }

    if (client->ssid[0] != '\0')
    {
        strncpy(result->ssid, client->ssid, sizeof(result->ssid) - 1);
    }

    strncpy(result->fixed_address, get_ip_str(client->dhcph_g->dhcp_yip), sizeof(result->fixed_address) - 1);

    u_int8_t *tmp_dhopt = client->dhopt_pointer_g;
    
    while (*(tmp_dhopt) != DHCP_END)
    {   
        u_int32_t tmp_data = 0;
        
		switch (*(tmp_dhopt))
        {
			case DHCP_SERVIDENT:
                tmp_data = 0;
                memcpy((char *)&tmp_data, tmp_dhopt + 2, sizeof(tmp_data));
                strncpy(result->serv_ident, get_ip_str(tmp_data), sizeof(result->serv_ident) - 1);
#if DHCLIENT_DEBUG
                fprintf(stdout, "* DHCP server  - %s\n", result->serv_ident);
#endif
				break;

			case DHCP_LEASETIME:
                tmp_data = 0;
                memcpy((char *)&tmp_data, tmp_dhopt + 2, sizeof(tmp_data));
                result->lease_time = ntohl(tmp_data);
#if DHCLIENT_DEBUG
				fprintf(stdout, "* Lease time - %d Days %d Hours %d Minutes\n", \
						(ntohl(tmp_data)) / (3600 * 24), \
						((ntohl(tmp_data)) % (3600 * 24)) / 3600, \
						(((ntohl(tmp_data)) % (3600 * 24)) % 3600) / 60); 
#endif
				break;

			case DHCP_SUBNETMASK:
                tmp_data = 0;
                memcpy((char *)&tmp_data, tmp_dhopt + 2, sizeof(tmp_data));
                strncpy(result->sub_netmask, get_ip_str(tmp_data), sizeof(result->sub_netmask) - 1);
#if DHCLIENT_DEBUG
				fprintf(stdout, "* Subnet mask - %s\n", result->sub_netmask);
#endif
				break;

			case DHCP_ROUTER:
				for(tmp = 0; tmp < (*(tmp_dhopt + 1) / 4); tmp++) 
                {
                    tmp_data = 0;
                    memcpy((char *)&tmp_data, (tmp_dhopt + 2 + (tmp * 4)), sizeof(tmp_data));
                    strncpy(result->router, get_ip_str(tmp_data), sizeof(result->router) - 1);
#if DHCLIENT_DEBUG
					fprintf(stdout, "* Router/gateway - %s\n", result->router);
#endif
				}
				break;

			case DHCP_DNS:
                dnsNum = ((*(tmp_dhopt + 1)) / 4);
                if (dnsNum > 2)
                    dnsNum = 2;
				for(tmp = 0; tmp < dnsNum; tmp++) 
                {
                    tmp_data = 0;
                    memcpy(&tmp_data, (tmp_dhopt + 2 + (tmp * 4)), sizeof(tmp_data));
                    strncpy(result->dns_server[tmp], get_ip_str(tmp_data), sizeof(result->dns_server[tmp]) - 1);
#if DHCLIENT_DEBUG
					fprintf(stdout, "* DNS server - %s\n", result->dns_server[tmp]);
#endif
				}
				break;

			case DHCP_FQDN:
			{
                tmp_data = 0;
                memcpy((char *)&tmp_data, tmp_dhopt + 1, sizeof(tmp_data));
                
				/* Minus 3 beacause 3 bytes are used to flags, rcode1 and rcode2 */
				u_int32_t size = tmp_data - 3;
                
				/* Plus 2 to add string terminator */
				u_char fqdn_client_name[size + 1];

				/* Plus 5 to reach the beginning of the string */
				memcpy(fqdn_client_name, tmp_dhopt + 5, size);
				fqdn_client_name[size] = '\0';
                
#if DHCLIENT_DEBUG
				fprintf(stdout, "* FQDN Client name - %s\n", fqdn_client_name);
#endif
			}
		}

		tmp_dhopt = tmp_dhopt + *(tmp_dhopt + 1) + 2;
	}
    
	TRACE("* ---------------------------------------------------------- %s %d\r\n", MDL);
    TRACE("* IP             - %s \r\n", result->fixed_address);
    TRACE("* Netmask        - %s \r\n", result->sub_netmask);
    TRACE("* Gateway        - %s \r\n", result->router);
    TRACE("* Dns            - %s \r\n", result->dns_server[0]);
    TRACE("* Dns            - %s \r\n", result->dns_server[1]);
    TRACE("* ServIdent      - %s \r\n", result->serv_ident);
    TRACE("* LeaseTime      - %d \r\n", result->lease_time);
    TRACE("* ---------------------------------------------------------- %s %d\r\n", MDL);

    if (result->lease_time <= 0 || result->lease_time > 86400)
    {
        result->lease_time = 86400;          
    }
    
    if (result->fixed_address[0] != '\0' &&
        //IsIP(result->fixed_address) == 0 &&                 /* 合法IP地址 */
        result->sub_netmask[0] != '\0' &&
        result->router[0] != '\0' 
        /* && IsIP(result->router) == 0*/) 
    {
        TRACE("* decode dhcp packet success. %s %d\r\n", MDL);
        retval = 0;
    }
    
	return retval;
}

ssize_t lpf_send_packet(struct dhcp_client *c)
{
    int result = -1;
 
	result = write(c->wfdesc, c->dhcp_packet_send, c->dhcp_packet_len);
	if (result < 0)
		TRACE("> ERROR, send_packet fail(%s). %s %d\r\n", strerror(errno), MDL);
    
	return result;
}

ssize_t lpf_recv_msg(struct dhcp_client *cli, unsigned char *buf, size_t len)
{    
	size_t length = 0;
	unsigned char ibuf [1536];
	unsigned bufix = 0;
	struct iovec iov = {
		.iov_base = ibuf,
		.iov_len = sizeof(ibuf),
	};
	
	unsigned char cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf,
		.msg_controllen = sizeof(cmsgbuf),
	};

	length = recvmsg(cli->rfdesc, &msg, 0);
	if (length <= 0)
		return length;

    if (length >= len)
        return -1;

#if 0
	/*  Use auxiliary packet data to:
	 *
	 *  a. Weed out extraneous VLAN-tagged packets - If the NIC driver is
	 *  handling VLAN encapsulation (i.e. stripping/adding VLAN tags),
	 *  then an inbound VLAN packet will be seen twice: Once by
	 *  the parent interface (e.g. eth0) with a VLAN tag != 0; and once
	 *  by the vlan interface (e.g. eth0.n) with a VLAN tag of 0 (i.e none).
	 *  We want to discard the packet sent to the parent and thus respond
	 *  only over the vlan interface.  (Drivers for Intel PRO/1000 series
	 *  NICs perform VLAN encapsulation, while drivers for PCnet series
	 *  do not, for example. The linux kernel makes stripped vlan info
	 *  visible to user space via CMSG/auxdata, this appears to not be
	 *  true for BSD OSs.).  NOTE: this is only supported on linux flavors
	 *  which define the tpacket_auxdata.tp_vlan_tci.
	 *
	 *  b. Determine if checksum is valid for use. It may not be if
	 *  checksum offloading is enabled on the interface.  */

    int csum_ready = 1;
    struct cmsghdr *cmsg;
    
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_PACKET &&
		    cmsg->cmsg_type == PACKET_AUXDATA) {
			struct tpacket_auxdata *aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
			/* Discard packets with stripped vlan id */

#ifdef VLAN_TCI_PRESENT
			if (aux->tp_vlan_tci != 0)
				return 0;
#endif

			csum_ready = ((aux->tp_status & TP_STATUS_CSUMNOTREADY)
				      ? 0 : 1);
		}
	}
#endif

    memset(buf, 0, len);
	memcpy(buf, &ibuf[bufix], length);
    
	return length;
}

int lpf_recv_packet(int packType, struct dhcp_client *c)
{   
    int result = DHCP_DISC_RESEND;
    int length = -1;
    int retval = -1;
	fd_set readfds; 
	struct timeval tval;
    
	tval.tv_sec = c->timeout / 1000L; 
	tval.tv_usec = 0;

	while (tval.tv_sec != 0)
    {   
        usleep(1000);

        length = 0;
		FD_ZERO(&readfds);
		FD_SET(c->rfdesc, &readfds);
        
		retval = select(c->rfdesc + 1, &readfds, NULL, NULL, &tval);
		if (retval == 0) 
        {
			TRACE("> ERROR, dhco receive timeout, continue. %s %d\r\n", MDL);
            continue;
		} 
        else if (retval > 0 && FD_ISSET(c->rfdesc, &readfds)) 
        {
            length = lpf_recv_msg(c, c->dhcp_packet_recv, sizeof(c->dhcp_packet_recv));
		}

        TRACE("--- LENGTH = %d \r\n", length);
        
		if (length >= 60) 
        {
            /* check packet */
            result = check_packet(packType, c);
            if (result == DHCP_OFFR_RCVD 
                || result == DHCP_ACK_RCVD)
            {
                break;
            }
		}
	}
    
	return result;    
}

