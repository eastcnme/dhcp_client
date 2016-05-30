

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <asm/types.h>
#include <linux/filter.h>

#include "lpf_dhcp.h"


#define DHCP_RETRY_CNT       5
#define DHCP_DISCOVER_CNT    3
#define DHCP_LEASE_RETRY_CNT 3
#define TIME_OUT             5000           /* select³¬Ê±Ê±¼ä5Ãë */

#define bpf_insn sock_filter /* Linux: dare to be gratuitously different. */

struct bpf_insn dhcp_bpf_filter[] = 
{
	/* Make sure this is an IP packet... */
	BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 8),

	/* Make sure it's a UDP packet... */
	BPF_STMT (BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6),

	/* Make sure this isn't a fragment... */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

	/* Get the IP header length... */
	BPF_STMT (BPF_LDX + BPF_B + BPF_MSH, 14),

	/* Make sure it's to the right port... */
	BPF_STMT (BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 67, 0, 1),             /* patch */

	/* If we passed all the tests, ask for the whole packet. */
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

	/* Otherwise, drop it. */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

int dhcp_bpf_filter_len = sizeof(dhcp_bpf_filter) / sizeof(struct bpf_insn);

static int lpf_send_discover(struct dhcp_client *c)
{
    int result = -1;
     
    build_discover_option(&c->opt);
    build_discover_packet(c);

	result = lpf_send_packet(c);
    if (result < 0) 
    {
	    TRACE("> ERROR, Failed to send %d byte long packet over %s interface. %s %d\r\n", 
            c->dhcp_packet_len, c->iface_name, MDL);
        return -1;
	}
    
    result = lpf_recv_packet(DHCP_MSGOFFER, c);
    if (result != DHCP_OFFR_RCVD)
    {
        TRACE("> ERROR, recv dhcp offer packet fail. %s %d\r\n", MDL);
        return -1;
    }

    return 0;
}

static int lpf_send_request(struct dhcp_client *client)
{
    int result = -1;

    build_request_option(&client->opt);
    build_request_packet(client); 		/* Builds specified packet */

    result = lpf_send_packet(client);
    if (result < 0)
    {
        TRACE("> ERROR, Failed to send %d byte long packet over %s interface. %s %d\r\n", 
            client->dhcp_packet_len, client->iface_name, MDL);
        return -1;
    }

    result = lpf_recv_packet(DHCP_MSGACK, client);
    if (result != DHCP_ACK_RCVD) 
    {
        TRACE("> ERROR, recv dhcp ack packet fail. %s %d\r\n", MDL);
        if (result == DHCP_NAK_RCVD) 
        {
            TRACE("> ERROR, dhcp nack received. %s %d\r\n", MDL);
            return 1;           /* return NAK */
        }

        return -1;
    }
    
    return 0;
}

static int lpf_dhclient_discover(struct dhcp_client *client)
{   
    int ret = -1;
    DHCP_RESULT result;
      
    ret = lpf_send_discover(client);
    if (0 != ret)
    {
        TRACE("> ERROR, send dhcp discover packet fail. %s %d\r\n", MDL);
        return -1;
    }
    
    if (decode_dhcp_packet(client, &result) != 0)
    {
        TRACE("> ERROR, decode dhcp client fail. %s %d\r\n", MDL);
        return -1;
    }

    /* 
    *  Set request packet option50 and option54, option50 is the request ip and
    *  option54 is the dhcp server ip.
    */
    set_request_opt50_and_opt54(client, result.serv_ident);
        
    ret = lpf_send_request(client);
    if (0 != ret)
    {
        TRACE("> ERROR, send dhcp request packet fail. %s %d\r\n", MDL);
        return -1;    
    }
    
    if (decode_dhcp_packet(client, &result) != 0)
    {
        TRACE("> ERROR, decode dhcp client fail. %s %d\r\n", MDL);
        return -1;
    }
    
    return 0;
}

static int lpf_dhclient_request(struct dhcp_client *client)
{   
    int retval = -1;
    DHCP_RESULT result;
    
    retval = lpf_send_request(client);
    if (0 != retval)
    {
        TRACE("> ERROR, lpf send request fail, ret = %d. %s %d\r\n", retval, MDL);
        if (retval == 1)
        {
            return 1;           /* return NAK */
        }
        
        return -1;
    }  
    
    retval = decode_dhcp_packet(client, &result);
    if (0 != retval)
    {   
        TRACE("> ERROR, decode dhcp packet fail. %s %d\r\n", MDL);
        return -1;
    }
    
    return 0;
}

char *lpf_print_hw_addr(const int hlen, const unsigned char *data)
{
	static char habuf [49];
	char *s;
	int i;

	if (hlen <= 0)
		habuf [0] = 0;
	else {
		s = habuf;
		for (i = 0; i < hlen; i++) {
			sprintf (s, "%02x", data [i]);
			s += strlen (s);
			*s++ = ':';
		}
		*--s = 0;
	}
	return habuf;
}

static void lpf_get_hw_addr(const char *name, u_char *local_mac) 
{
	int sock;
	struct ifreq tmp;
	struct sockaddr *sa;
    
	if (strlen(name) >= sizeof(tmp.ifr_name)) 
    {
		TRACE("> ERROR, Device name too long: \"%s\" %s %d\r\n", name, MDL);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) 
    {
		TRACE("> ERROR, Can't create socket for \"%s\" %s %d\r\n", name, MDL);
	}

	memset(&tmp, 0, sizeof(tmp));
	strcpy(tmp.ifr_name, name);
    tmp.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock, SIOCGIFHWADDR, &tmp) < 0) 
    {
		TRACE("> ERROR, Error getting hardware address for \"%s\" %s %d\r\n", name, MDL);
	}

	sa = &tmp.ifr_hwaddr;
    memcpy(local_mac, sa->sa_data, ETHER_ADDR_LEN);

#if 0
	switch (sa->sa_family) {
		case ARPHRD_ETHER:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_ETHER;
			memcpy(&hw->hbuf[1], sa->sa_data, 6);
			break;
		case ARPHRD_IEEE802:
#ifdef ARPHRD_IEEE802_TR
		case ARPHRD_IEEE802_TR:
#endif /* ARPHRD_IEEE802_TR */
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_IEEE802;
			memcpy(&hw->hbuf[1], sa->sa_data, 6);
			break;
		case ARPHRD_FDDI:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_FDDI;
			memcpy(&hw->hbuf[1], sa->sa_data, 6);
			break;
		default:
			printf("Unsupported device type %ld for \"%s\" \r\n",
				  (long int)sa->sa_family, name);
	}
#endif

	close(sock);
}

int lpf_if_register(struct dhcp_client *c)
{   
	int sock;
	union {
		struct sockaddr_ll ll;
		struct sockaddr common;
	} sa;
    
	struct ifreq ifr;

	/* Make an LPF socket. */
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons((short)ETH_P_ALL))) < 0) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT || errno == EINVAL) {

            TRACE("> ERROR, sock SOCK_RAW error. %s %d\r\n", MDL);
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, (const char *)c->ifp, sizeof(ifr.ifr_name));
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl (sock, SIOCGIFINDEX, &ifr)) 
    {
		TRACE("> ERROR, Failed to get interface index %s %d\r\n", MDL);
	}
    
	/* Bind to the interface name */
	memset (&sa, 0, sizeof(sa));
	sa.ll.sll_family = AF_PACKET;
	sa.ll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(sock, &sa.common, sizeof(sa))) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT || errno == EINVAL) 
		{
			TRACE("> ERROR, sock bind error. %s %d\r\n", MDL);
		}
	}

	lpf_get_hw_addr(c->iface_name, c->local_mac);

	return sock;
}

static void lpf_gen_filter_setup(struct dhcp_client *c)
{
	struct sock_fprog p;

	memset(&p, 0, sizeof(p));

	/* Set up the bpf filter program structure.    This is defined in bpf.c */
	p.len = dhcp_bpf_filter_len;
	p.filter = dhcp_bpf_filter;

        /* Patch the server port into the LPF  program...
	   XXX changes to filter program may require changes
	   to the insn number(s) used below! XXX */
	dhcp_bpf_filter[8].k = ntohs((short)(c->local_port));

	if (setsockopt(c->rfdesc, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p)) < 0) 
    {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT) {
			TRACE("> ERROR, Can't install packet filter program. %s %d\r\n", MDL);
		}		
	}
}

void lpf_if_register_send(struct dhcp_client *c)
{
	c->wfdesc = c->rfdesc;

	TRACE("* Sending on   LPF/%s/%s %s %d\r\n", 
            c->iface_name, lpf_print_hw_addr(ETHER_ADDR_LEN, c->local_mac), MDL);
}

void lpf_if_register_receive(struct dhcp_client *c)
{
    c->rfdesc = lpf_if_register(c);
        
	int val = 1;
	if (setsockopt(c->rfdesc, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) < 0) {
		if (errno != ENOPROTOOPT) {
			TRACE("> ERROR, Failed to set auxiliary packet data %s %d\r\n", MDL);
		}
	}
	
	lpf_gen_filter_setup(c);
    
	TRACE("* Listening on LPF/%s/%s %s %d\r\n", c->iface_name, 
        lpf_print_hw_addr(ETHER_ADDR_LEN, c->local_mac), MDL);
}

int lpf_init_dhcp_client(struct dhcp_client *client, const char *ifname, const char *wifissid)
{
    if (!client || !ifname)
    {
        return -1;
    }
    
    memset(client, 0, sizeof(struct dhcp_client));
    client->rfdesc = client->wfdesc = -1;
    client->timeout = TIME_OUT;
    
    strncpy(client->iface_name, ifname, sizeof(client->iface_name) - 1);
    
    if (wifissid && wifissid[0] != '\0')
    {
        strncpy(client->ssid, wifissid, sizeof(client->ssid) - 1);
    }

    client->local_port = htons(68);
    client->remote_port = htons(ntohs(client->local_port) - 1);   /* XXX */

    client->sockaddr_broadcast.sin_family = AF_INET;
	client->sockaddr_broadcast.sin_port = client->remote_port;
	client->sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
	client->inaddr_any.s_addr = INADDR_ANY;

    if (client->ifp == NULL)
    {
        client->ifp = (struct ifreq *)malloc(sizeof(struct ifreq));
        if (client->ifp == NULL)
	        TRACE("> ERROR, no space for ifp mockup. %s %d\r\n", MDL);
		strcpy(client->ifp->ifr_name, ifname);
    }

    lpf_if_register_receive(client);
    lpf_if_register_send(client);
    
    snprintf(client->opt.hostname_buff, sizeof(client->opt.hostname_buff) - 1, "MRJ_XXX");
    client->opt.hostname_buff[sizeof(client->opt.hostname_buff) - 1] = '\0';
    client->opt.hostname_flag = 1;
    
    return 0;
}

void lpf_deinit_dhcp_client(struct dhcp_client *client)
{
    if (client)
    {
        if (client->ifp) {
            free(client->ifp);
            client->ifp = NULL;
        }

        if (client->wfdesc >= 0)
        {
            close(client->wfdesc);
            client->wfdesc = -1;
            client->rfdesc = -1;
        }
    }
}

int lpf_do_dhclient(const char *ifname, const char *requestIp)
{
    int ret = -1;
    struct dhcp_client client;
    
    ret = lpf_init_dhcp_client(&client, ifname, "xiaozhou");
    if (0 != ret)
    {
        TRACE("> init dhcp client fail. %s %d\r\n", MDL);
        return -1;
    }

    if (requestIp)
    {
        set_option50(requestIp, &client.opt);
        ret = lpf_dhclient_discover(&client);
    }
    else
    {
        set_option50(NULL, &client.opt);
        ret = lpf_dhclient_discover(&client);
    }

    lpf_deinit_dhcp_client(&client);
    
    return ret;
}


int main(int argc, char **argv)
{
    TRACE("* USAGE: dhclient <interfaceName> <requestIp>\r\n");

    int ret = -1;
    
    if (argc == 2)
    {
        ret = lpf_do_dhclient(argv[1], NULL);
    }
    else if (argc == 3)
    {
        ret = lpf_do_dhclient(argv[1], argv[2]);
    }
    else
    {
        TRACE("* USAGE: dhclient <interfaceName> <requestIp> \r\n");   
    }

    return ret;
}


