/*
 * Sean Manson COMP3301
 * Pseudodevice for ethernet over IP
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/if_eou.h>

/* TODO: socket list */
SLIST_HEAD(, eou_softc) eou_sclist;

void	eouattach(int);
int	eou_clone_create(struct if_clone *, int);
int	eou_clone_destroy(struct ifnet *);
int	eouioctl(struct ifnet *, u_long, caddr_t);
void	eoustart(struct ifnet *);
int	eououtput(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	eou_media_change(struct ifnet *);
void	eou_media_status(struct ifnet *, struct ifmediareq *);
int	eou_set_address(struct ifnet *, struct sockaddr *, struct sockaddr *);
int	eou_sock_create(struct ifnet *);
int	eou_sock_delete(struct ifnet *);

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
	sc->sc_dstport = htons(EOU_PORT);
	sc->sc_s = NULL;
	sc->sc_network = 0;

	/* send queue */
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	IFQ_SET_READY(&ifp->if_snd);

	/* handlers */
	ifp->if_ioctl = eouioctl;
	ifp->if_start = eoustart;
	ifp->if_output = eououtput;

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
	error = eou_sock_delete(ifp);
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
	int			 error = 0, s;

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
		error = eou_set_address(ifp,
		    (struct sockaddr *)&lifr->addr,
		    (struct sockaddr *)&lifr->dstaddr);
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
 * The bridge has magically already done all the work for us,
 * and we only need to discard the packets.
 */
void
eoustart(struct ifnet *ifp)
{
	struct eou_softc *sc = (struct eou_softc *)ifp;
	struct mbuf		*m;
	int			 s;

	printf("eou started\n");
	while (1) {
		/* get packets until none remain */
		s = splnet();
		IFQ_DEQUEUE(&ifp->if_snd, m);
		splx(s);
		if (m == NULL)
			break;

		/* ensure usable */	
		if ((ifp->if_flags & (IFF_OACTIVE | IFF_UP)) != IFF_UP ||
		    sc->sc_s == NULL) {
			printf("skipping mbuf - not usable\n");
			m_freem(m);
			continue;
		}
		
		/* increment sent packets */
		ifp->if_opackets++;
		
		/* actually send packet */
		printf("sending mbuf\n");
		/* TODO */
		m_freem(m);
	}
}


int
eououtput(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
    struct rtentry *rt)
{
	struct eou_softc *sc = (struct eou_softc*)ifp;
	int error = 0;
	int s;

	printf("eououtput\n");
	if (!(ifp->if_flags & IFF_UP) || sc->sc_s == NULL) {
		m_freem(m);
		error = ENETDOWN;
		goto end;
	}

	/*
	 * Add headers etc.
	 * TODO
	 */

	/*
	 * Queue message on interface, and start output.
	 */
	printf("queueing mbuf\n");
	s = splnet();
	IFQ_ENQUEUE(&ifp->if_snd, m, NULL, error);
	if (error) {
		/* mbuf is already freed */
		splx(s);
		goto end;
	}
	ifp->if_obytes += m->m_pkthdr.len;
	if_start(ifp);
	splx(s);

end:
	if (error)
		ifp->if_oerrors++;
	return (error);
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
	imr->ifm_status = IFM_AVALID;
}

/* HELPER COMMANDS */	
/*
 * Set up the source and destination addresses as given, as well as the port.
 * Updates the socket as neccessary to match this information
 */
int
eou_set_address(struct ifnet *ifp, struct sockaddr *src, struct sockaddr *dst)
{
	struct eou_softc	*sc = (struct eou_softc *)ifp->if_softc;
	struct sockaddr_in	*src4, *dst4;
	int error = 0;

	if (src != NULL && dst != NULL) { /* setting new config */
		/* inet6 is not supported */
		if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
			return (EAFNOSUPPORT);

		/* get ipv4 addreses */
		src4 = satosin(src);
		dst4 = satosin(dst);
		if (src4->sin_len != sizeof(*src4) ||
		    dst4->sin_len != sizeof(*dst4))
			return (EINVAL);

		/* ensure port can be set */
		if (dst4->sin_port)
			sc->sc_dstport = dst4->sin_port;
		else
			sc->sc_dstport = htons(EOU_PORT);

		/* delete socket if present */
		if (sc->sc_s != NULL)
			error = eou_sock_delete(ifp);
		if (error != 0)
			goto end;

		/* reset */
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
		memcpy(&sc->sc_src, src, src->sa_len);
		memcpy(&sc->sc_dst, dst, dst->sa_len);

		/* create socket */
		error = eou_sock_create(ifp);
	} else { /* just delete old config */
		/* delete socket if present */
		if (sc->sc_s != NULL)
			error = eou_sock_delete(ifp);
		if (error != 0)
			goto end;
		
		/* reset */
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
	}

end:
	return error;
}

/*
 * Create a new socket* to match the internal structures on this ifp, or
 * simply update it to match a previous one if one already exists for these
 * addresses.
 */
int
eou_sock_create(struct ifnet *ifp)
{
	/* TODO */
	return 0;
}

/*
 * Delete and free the socket for this ifp matching the given addresses, or
 * simply set to null if it is currently referenced by other things.
 */
int
eou_sock_delete(struct ifnet *ifp)
{
	/* TODO */
	return 0;
}
