/*
 * Sean Manson COMP3301
 * Pseudodevice for ethernet over IP
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/ioctl.h>
#include <sys/task.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <crypto/siphash.h>

#include <net/if_eou.h>

/* TODO: socket list */
SLIST_HEAD(, eou_softc) eou_sclist;

void	eouattach(int);
int	eou_clone_create(struct if_clone *, int);
int	eou_clone_destroy(struct ifnet *);

int	eouioctl(struct ifnet *, u_long, caddr_t);
void	eoustart(struct ifnet *);
void	eousend(void *);
void	eourecv(struct socket *, caddr_t, int);
int	eou_media_change(struct ifnet *);
void	eou_media_status(struct ifnet *, struct ifmediareq *);

int	eou_set_address(struct ifnet *, struct sockaddr_in *,
    struct sockaddr_in *);
int	eou_sock_create(struct sockaddr_in *, struct sockaddr_in *,
    struct socket **);
int	eou_sock_delete(struct eou_softc *);
void	eou_timeout_ping(void *);
void	eou_timeout_pong(void *);

void	eou_gen_mac(struct eou_pingpong *, uint8_t *);

/* globals */
struct if_clone	eou_cloner =
    IF_CLONE_INITIALIZER("eou", eou_clone_create, eou_clone_destroy);

void
eouattach(int neou)
{
	printf("eouattach\n");
	SLIST_INIT(&eou_sclist);

	if_clone_attach(&eou_cloner);
}

int
eou_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet		*ifp;
	struct eou_softc	*sc;
	
	printf("creating eou clone\n");
	if ((sc = malloc(sizeof(*sc), M_DEVBUF, M_NOWAIT|M_ZERO)) == NULL)
		return (ENOMEM);

	/* basic address info settings */
	ifp = &sc->sc_ac.ac_if;
	snprintf(ifp->if_xname, sizeof(ifp->if_xname), "eou%d", unit);
	ifp->if_flags = IFF_SIMPLEX;
	ether_fakeaddr(ifp);
	ifp->if_softc = sc;
	/*ifp->if_capabilities = IFCAP_VLAN_MTU;*/
	
	/* softnet defaults */
	sc->sc_ifp = ifp;
	mq_init(&sc->sc_mq, 50, IPL_NET);
	task_set(&sc->sc_sndt, eousend, sc);
	sc->sc_dstport = 0;
	sc->sc_s = NULL;
	sc->sc_network = 0;
	sc->sc_gotpong = 0;

	/* timeouts */
	timeout_set(&sc->sc_pingtmo, eou_timeout_ping, sc);
	timeout_set(&sc->sc_pongtmo, eou_timeout_pong, sc);

	/* send queue */
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	IFQ_SET_READY(&ifp->if_snd);

	/* handlers */
	ifp->if_ioctl = eouioctl;
	ifp->if_start = eoustart;

	/* media */
	ifmedia_init(&sc->sc_media, 0, eou_media_change, eou_media_status);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);

	if_attach(ifp);
	ether_ifattach(ifp);

	/* add to overall list */
	SLIST_INSERT_HEAD(&eou_sclist, sc, sc_next);
	return (0);
}

int
eou_clone_destroy(struct ifnet *ifp)
{
	struct eou_softc	*sc = ifp->if_softc;
	int s, error = 0;

	printf("destroying eou clone\n");
	s = splnet();
	/* remove socket */
	error = eou_sock_delete(sc);
	if (error != 0)
		goto end;
	
	/* remove sub structures */
	ifmedia_delete_instance(&sc->sc_media, IFM_INST_ANY);
	ether_ifdetach(ifp);
	if_detach(ifp);

	/* remove main structures */
	SLIST_REMOVE(&eou_sclist, sc, eou_softc, sc_next);
	free(sc, M_DEVBUF, sizeof(*sc));

end:
	splx(s);
	return error;
}

/*
 * Handle IO commands given to us by ifconfig.
 */
/* ARGSUSED */
int
eouioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct eou_softc	*sc = (struct eou_softc *)ifp->if_softc;
	struct ifaddr		*ifa = (struct ifaddr *)data;
	struct ifreq		*ifr = (struct ifreq *)data;
	struct if_laddrreq	*lifr = (struct if_laddrreq *)data;
	struct proc		*p = curproc;
	int			 s, error = 0;

	switch (cmd) {
	case SIOCSIFADDR:
		printf("ioctl SIOCSIFADDR\n");
		ifp->if_flags |= IFF_UP;
		if (ifa->ifa_addr->sa_family == AF_INET)
			arp_ifinit(&sc->sc_ac, ifa);
		/* FALLTHROUGH */

	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_UP) && sc->sc_s != NULL) {
			ifp->if_flags |= IFF_RUNNING;
		} else
			ifp->if_flags &= ~IFF_RUNNING;
		break;
		
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/* should be already handled */
		break;

	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;
	
	case SIOCSLIFPHYADDR:
		printf("ioctl setting addr\n");
		if ((error = suser(p, 0)) != 0)
			break;

		s = splnet();
		error = eou_set_address(ifp, (struct sockaddr_in *)&lifr->addr,
		    (struct sockaddr_in *)&lifr->dstaddr);
		splx(s);
		break;

	case SIOCDIFPHYADDR:
		printf("ioctl deleting addr\n");
		if ((error = suser(p, 0)) != 0)
			break;
		s = splnet();
		error = eou_set_address(ifp, NULL, NULL);
		splx(s);
		break;

	case SIOCGLIFPHYADDR:
		printf("ioctl getting addr\n");
		if (sc->sc_s == NULL) {
			error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
			break; /* socket only exists if tunnel exists */
		}
		bzero(&lifr->addr, sizeof(lifr->addr));
		bzero(&lifr->dstaddr, sizeof(lifr->dstaddr));
		memcpy(&lifr->addr, &sc->sc_src, sizeof(&sc->sc_src));
		memcpy(&lifr->dstaddr, &sc->sc_dst, sizeof(&sc->sc_dst));
		break;

	case SIOCSVNETID:
		printf("ioctl setting vnetid\n");
		if ((error = suser(p, 0)) != 0)
			break;
		if (ifr->ifr_vnetid < 0 || ifr->ifr_vnetid > 0x00ffffff) {
			error = EINVAL;
			break;
		}
		s = splnet();
		sc->sc_network = (uint32_t)ifr->ifr_vnetid;
		error = eou_set_address(ifp, NULL, NULL);
		splx(s);
		break;

	case SIOCGVNETID:
		printf("ioctl getting vnetid\n");
		ifr->ifr_vnetid = (int)sc->sc_network;
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
		break;
	}

	return (error);
}

/*
 * Start sending queued packets for this interface.
 */
void
eoustart(struct ifnet *ifp)
{
	struct eou_softc *sc = (struct eou_softc *)ifp->if_softc;
	struct mbuf *m;
	int s;

	printf("eou started\n");
	while (1) {
		/* get packets until none remain */
		s = splnet();
		IFQ_DEQUEUE(&ifp->if_snd, m);
		splx(s);
		if (m == NULL) {
			/* begin sending */
			task_add(systq, &sc->sc_sndt);
			break;
		}

		/* ensure usable */	
		if ((ifp->if_flags & (IFF_OACTIVE | IFF_UP)) != IFF_UP ||
		    sc->sc_s == NULL) {
			printf("skipping mbuf - not usable\n");
			m_freem(m);
			continue;
		}

		/* add to send queue */
		if (mq_enqueue(&sc->sc_mq, m) != 0) {
			/* TODO: increment errors */
			m_freem(m);
		}
	}
}

/*
 * Receive a response on a socket.
 */
void
eourecv(struct socket *so, caddr_t upcallarg, int waitflag)
{
	struct mbuf	 *recv;
	struct eou_softc *sc = (struct eou_softc *)upcallarg;
	int s, error = 0, flag = (waitflag == M_DONTWAIT) ? MSG_DONTWAIT : 0;

	s = splnet();
	printf("got packet response\n");
	
	/* prevent receiving on a deleted socket */
	if (so == NULL || sc->sc_s == NULL) {
		printf("socket had been deleted - ignoring\n");
		goto end;	
	}


	error = soreceive(so, NULL, NULL, &recv, NULL, &flag, 0);
	if (error != 0) {
		printf("error receiving packet: %d\n", error);
		goto end;
	}

	/* parse packet */
	/*TODO*/

	/* hand parsed packet up a layer */
	/* TODO */
end:
	printf("finished handling res\n");
	splx(s);
	return;
}

/*
 * Send our entire queue of mbufs to the socket in a process context.
 */
void
eousend(void *arg)
{
	struct eou_softc	*sc = arg;
	struct mbuf_list	 ml;
	struct mbuf		*m;

	printf("eousend!\n");

	/* convert from queue to a list to write */
	mq_delist(&sc->sc_mq, &ml);

	/* write all of these, so long as our socket is valid */
	while ((m = ml_dequeue(&ml)) != NULL) {
		printf("eousend new mbuf\n");
		if (sc->sc_s != NULL) {
			/* TODO: error count */
			m_freem(m);
			continue;
		}

		if (sosend(sc->sc_s, NULL, NULL, m, NULL, MSG_NOSIGNAL) != 0) {
			/*TODO: error count */
			printf("eousend fail\n");
			m_freem(m);
			continue;
		}

		/* Increment sent packet count */
		sc->sc_ifp->if_opackets++;
		m_freem(m);
	}
}

/* MEDIA COMMANDS */	
int
eou_media_change(struct ifnet *ifp)
{
	return (0);
}

void
eou_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	struct eou_softc *sc = (struct eou_softc *)ifp->if_softc;

	/* Assume link up if socket exists and pong received */
	if (sc->sc_s != NULL && sc->sc_gotpong)
		imr->ifm_status = IFM_AVALID | IFM_ACTIVE;
	else
		imr->ifm_status = IFM_AVALID;
}

/* HELPER COMMANDS */	
/*
 * Set up the source and destination addresses as given, as well as the port.
 * Updates the socket as neccessary to match this information.
 * Must be called within splnet.
 */
int
eou_set_address(struct ifnet *ifp, struct sockaddr_in *src,
    struct sockaddr_in *dst)
{
	struct eou_softc	*sc = (struct eou_softc *)ifp->if_softc;
	struct socket		*new;
	int error = 0;

	if (src != NULL && dst != NULL) { /* setting new config */
		/* check addreses */
		if (src->sin_family != AF_INET || dst->sin_family != AF_INET)
			return (EAFNOSUPPORT); /* only support ipv4 */
		if (src->sin_len != sizeof(sc->sc_src) ||
		    dst->sin_len != sizeof(sc->sc_dst))
			return (EINVAL);

		/* set relevant port */

		/* create a new socket to match */
		error = eou_sock_create(src, dst, &new);
		if (error != 0)
			goto end;

		/* got socket; now try to delete previous one */
		if (sc->sc_s != NULL)
			eou_sock_delete(sc);

		/* deleted! now update current info */
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
		memcpy(&sc->sc_src, src, src->sin_len);
		memcpy(&sc->sc_dst, dst, dst->sin_len);
		if (dst->sin_port)
			sc->sc_dstport = dst->sin_port;
		else
			sc->sc_dstport = htons(EOU_PORT);
		sc->sc_s = new;
		sc->sc_s->so_upcallarg = (caddr_t)sc;
		sc->sc_s->so_upcall = eourecv;
		
		/* start ping/pong messages */
		sc->sc_gotpong = 0;
		timeout_add_sec(&sc->sc_pingtmo, 1);

		/* successfully tunnelled; set up */
		if_up(ifp);
	} else { /* just delete old config */
		/* delete socket if present */
		if (sc->sc_s != NULL)
			error = eou_sock_delete(sc);
		if (error != 0)
			goto end;

		/* remove old timeouts */
		timeout_del(&sc->sc_pingtmo);
		timeout_del(&sc->sc_pongtmo);
		sc->sc_gotpong = 0;
		
		/* reset */
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
		sc->sc_dstport = 0;

		/* not connected now; set down */
		if_down(ifp);
	}

end:
	return error;
}

/*
 * Creates and binds a new socket to match the addresses given.
 * Must be called within splnet.
 */
int
eou_sock_create(struct sockaddr_in *src, struct sockaddr_in *dst,
    struct socket **new)
{
	struct socket		*s;
	struct sockaddr_in	*sa;
	struct mbuf		*m;
	int error = 0;

	/* Determine if socket already exists */
	/*TODO*/

	/* Otherwise, create socket */
	printf("creating new socket\n");
	error = socreate(AF_INET, &s, SOCK_DGRAM, 17);
	if (error)
		return (error);

	/* Bind */
	MGET(m, M_WAITOK, MT_SONAME);
	m->m_len = src->sin_len;
	sa = mtod(m, struct sockaddr_in *);
	memcpy(sa, src, src->sin_len);

	printf("binding socket\n");
	error = sobind(s, m, curproc);
	m_freem(m);
	if (error) {
		soclose(s);
		return (error);
	}

	/* Connect */
	/*MGET(m, M_WAITOK, MT_SONAME);
	m->m_len = sizeof(sc->sc_dst);
	sa = mtod(m, struct sockaddr *);
	memcpy(sa, &sc->sc_dst, sizeof(sc->sc_dst));

	error = soconnect(s, m);
	m_freem(m);
	if (error) {
		soclose(s);
		return (error);
	}*/


	/* Socket settings */
	printf("created/assigned socket soccessfully\n");
	*new = s;

	return (0);
}

/*
 * Delete and free the socket for this ifp matching the given addresses, or
 * simply set to null if it is currently referenced by other things.
 * Must be called within splnet.
 */
int
eou_sock_delete(struct eou_softc *sc)
{
	struct socket		*s;

	printf("deleting socket\n");

	/* update pointers */
	s = sc->sc_s;
	s->so_upcall = NULL;
	sc->sc_s = NULL;

	/* close socket */
	soclose(s);

	/* TODO */
	return (0);
}

/*
 * Timer fires for sending a ping every 30 seconds.
 */
void
eou_timeout_ping(void *arg)
{
	struct eou_softc	*sc = arg;
	struct eou_pingpong	 msg, *mp;
	struct mbuf		*m;
	int s, i;
	
	/* do nothing if socket is no more */
	if (sc->sc_s == NULL)
		return;

	printf("ping timeout fired\n");

	/* create ping message */
	msg.hdr.eou_network = sc->sc_network;
	msg.hdr.eou_type = htons(EOU_T_PING);
	s = splclock();
	msg.utime = (uint64_t)time_second;
	splx(s);
	arc4random_buf(msg.random, sizeof(msg.random));
	eou_gen_mac(&msg, msg.mac);

	printf("creating new message:\n");
	printf("network id %d, type %x, time %llu\n", msg.hdr.eou_network,
	    msg.hdr.eou_type, msg.utime);
	printf("rand bytes: ");
	for (i = 0; i < sizeof(msg.random); i++) {
		printf("%x ", msg.random[i]);
	}
	printf("\nmac gen: ");
	for (i = 0; i < SIPHASH_DIGEST_LENGTH; i++) {
		printf("%x ", msg.mac[i]);
	}
	printf("\n\n");

	/* add to send queue */
	MGET(m, M_WAITOK, MT_DATA);
	m->m_len = sizeof(msg);
	mp = mtod(m, struct eou_pingpong *);
	memcpy(mp, &msg, sizeof(msg));

	if (mq_enqueue(&sc->sc_mq, m) == 0)
		task_add(systq, &sc->sc_sndt);
	else {
		/* TODO: add to fails */
		m_freem(m);
	}

	/* re-add timeout for next message */
	timeout_add_sec(&sc->sc_pingtmo, EOU_PING_TIMEOUT);
}

/*
 * Timer fires when we fail to receive a server pong for 100 seconds
 */
void
eou_timeout_pong(void *arg)
{
	struct eou_softc	*sc = arg;

	printf("pong timeout fired\n");

	/* No pong message received - we simply say we haven't got one */
	sc->sc_gotpong = 0;
}

/*
 * Generates a mac for the given ping/pong message, placing it in the mac
 * pointer given.
 */
void
eou_gen_mac(struct eou_pingpong *msg, uint8_t *mac)
{
	SIPHASH_CTX ctx;
	uint8_t keybytes[SIPHASH_KEY_LENGTH] = EOU_KEY;

	SipHash24_Init(&ctx, (SIPHASH_KEY *)keybytes);
	SipHash24_Update(&ctx, &msg->hdr.eou_network,
	    sizeof(msg->hdr.eou_network));
	SipHash24_Update(&ctx, &msg->utime, sizeof(msg->utime));
	SipHash24_Update(&ctx, msg->random, sizeof(msg->random));
	SipHash24_Final(mac, &ctx);
}
