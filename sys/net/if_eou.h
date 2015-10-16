/*
 * Sean Manson COMP3301 Ass3
 * Header for Ethernet over UDP (eou)
 */

#ifndef _NET_EOU_H
#define _NET_EOU_H

#define EOU_PORT		3301

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
	uint8_t			mac[8];
} __packed;


/* softnet struct for eou comms */
struct eou_softc {
	struct arpcom		 sc_ac;
	struct ifmedia		 sc_media;

	uint32_t		 sc_network;	/* address of this eou */

	struct sockaddr_in	 sc_src;	/* this address */
	struct sockaddr_in	 sc_dst;	/* server address */
	in_port_t		 sc_dstport;	/* server port */

	/*
	 * Each cloned interface may point to multiple of the same
	 * socket if the addresses and port are the same. Before closing/
	 * opening sockets we check to see if any other interfaces already
	 * have one with the addresses needed.
	 */
	struct socket		*sc_s;		/* socket for this */
	
	SLIST_ENTRY(eou_softc)	sc_next; /* list of all eous */
};

#endif /* _NET_EOU_H */
