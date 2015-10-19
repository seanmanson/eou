/*
 * Sean Manson COMP3301 Ass3
 * Header for Ethernet over UDP (eou)
 */

#ifndef _NET_EOU_H
#define _NET_EOU_H

#define EOU_PORT		3301
#define EOU_PING_TIMEOUT	30
#define EOU_PONG_TIMEOUT	100
#define EOU_KEY			{0x63, 0x6f, 0x6d, 0x70, 0x33, 0x33, 0x30, \
				 0x31, 0x63, 0x6f, 0x6d, 0x70, 0x37, 0x33, \
				 0x30, 0x38}
#define EOU_MTU			1500
#define EOU_INTERNAL_MTU	1506

struct eou_header {
	uint32_t		eou_network;
	uint16_t		eou_type;
} __packed;

#define EOU_T_DATA	0x0000
#define EOU_T_PING	0x8000
#define EOU_T_PONG	0x8001

struct eou_pingpong {
	struct eou_header	hdr;
	uint16_t		_pad;
	uint64_t		utime;
	uint8_t			random[32];
	uint8_t			mac[SIPHASH_DIGEST_LENGTH];
} __packed;

/*	 
* Each cloned interface may point to multiple of the same
* socket if the addresses and port are the same. Before closing/
* opening sockets we check to see if any other interfaces already
* have one with the addresses needed.
*/
struct eou_sock {
	struct socket		*so_s;		/* udp connected socket */
	struct sockaddr_in	 so_src;	/* bound address */
	struct sockaddr_in	 so_dst;	/* server address */
	
	SLIST_ENTRY(eou_sock)	 so_next; 	/* list of all eou_sock */
};

/* softnet struct for eou comms */
struct eou_softc {
	struct ifnet		*sc_ifp;
	struct arpcom		 sc_ac;
	struct ifmedia		 sc_media;

	struct mbuf_queue	 sc_mq;		/* all packets queued to send*/
	struct task		 sc_sndt;	/* task for sending above */
	struct task		 sc_rect;	/* task for getting data */

	uint32_t		 sc_network;	/* address of this eou */

	struct timeout		 sc_pingtmo;	/* tmo for sending pings */
	struct task		 sc_pingt; 	/* task for sending pings */
	struct timeout		 sc_pongtmo;	/* tmo for getting pongs */
	int			 sc_gotpong;	/* got pong in last 100s? */

	struct eou_sock		*sc_s;		/* socket for this conn */
	
	SLIST_ENTRY(eou_softc)	 sc_next;	/* list of all eou_softc */
};

#endif /* _NET_EOU_H */
