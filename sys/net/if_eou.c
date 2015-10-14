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

void	eouattach(int);
int	eou_clone_create(struct if_clone *, int);
int	eou_clone_destroy(struct ifnet *);
int	eouioctl(struct ifnet *, u_long, caddr_t);
void	eoustart(struct ifnet *);
int	eou_media_change(struct ifnet *);
void	eou_media_status(struct ifnet *, struct ifmediareq *);
int	eou_config(struct ifnet *, struct sockaddr *, struct sockaddr *);

struct if_clone	eou_cloner =
    IF_CLONE_INITIALIZER("eou", eou_clone_create, eou_clone_destroy);


void
eouattach(int neou)
{
	printf("eouattach\n");
	if_clone_attach(&eou_cloner);
}

int
eou_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet		*ifp;
	struct eou_softc	*sc;
	
	printf("creating eou clone\n");
	if ((sc = malloc(sizeof(*sc),
	    M_DEVBUF, M_NOWAIT|M_ZERO)) == NULL)
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
	sc->sc_network = 0;

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
	return (0);
}

int
eou_clone_destroy(struct ifnet *ifp)
{
	struct eou_softc	*sc = ifp->if_softc;

	printf("destroying eou clone\n");
	ifmedia_delete_instance(&sc->sc_media, IFM_INST_ANY);
	ether_ifdetach(ifp);
	if_detach(ifp);
	free(sc, M_DEVBUF, sizeof(*sc));
	return (0);
}

/*
 * The bridge has magically already done all the work for us,
 * and we only need to discard the packets.
 */
void
eoustart(struct ifnet *ifp)
{
	struct mbuf		*m;
	int			 s;

	printf("eou started\n");
	for (;;) {
		s = splnet();
		IFQ_DEQUEUE(&ifp->if_snd, m);
		splx(s);

		if (m == NULL)
			return;
		ifp->if_opackets++;
		m_freem(m);
	}
}

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
		printf("ioctl FLAGS\n");
		if (ifp->if_flags & IFF_UP) {
			ifp->if_flags |= IFF_RUNNING;
		} else {
			ifp->if_flags &= ~IFF_RUNNING;
		}
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
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
		error = eou_config(ifp,
		    (struct sockaddr *)&lifr->addr,
		    (struct sockaddr *)&lifr->dstaddr);
		splx(s);
		break;

	case SIOCDIFPHYADDR:
		printf("ioctl deleting addr\n");
		if ((error = suser(p, 0)) != 0)
			break;
		s = splnet();
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
		sc->sc_dstport = htons(EOU_PORT);
		splx(s);
		break;

	case SIOCGLIFPHYADDR:
		printf("ioctl getting addr\n");
		if (sc->sc_dst.ss_family == AF_UNSPEC) {
			error = EADDRNOTAVAIL;
			break;
		}
		bzero(&lifr->addr, sizeof(lifr->addr));
		bzero(&lifr->dstaddr, sizeof(lifr->dstaddr));
		memcpy(&lifr->addr, &sc->sc_src, sc->sc_src.ss_len);
		memcpy(&lifr->dstaddr, &sc->sc_dst, sc->sc_dst.ss_len);
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
		(void)eou_config(ifp, NULL, NULL);
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

/* MEDIA COMMANDS */	
int
eou_media_change(struct ifnet *ifp)
{
	return (0);
}

void
eou_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	/* only say valid once a connection is running */
	imr->ifm_active = IFM_ETHER | IFM_AUTO;
	imr->ifm_status = IFM_AVALID;
}

/* HELPER COMMANDS */	
int
eou_config(struct ifnet *ifp, struct sockaddr *src, struct sockaddr *dst)
{
	struct eou_softc	*sc = (struct eou_softc *)ifp->if_softc;
	struct sockaddr_in	*src4, *dst4;
	int			 reset = 0;

	if (src != NULL && dst != NULL) {
		/* XXX inet6 is not supported */
		if (src->sa_family != AF_INET || dst->sa_family != AF_INET)
			return (EAFNOSUPPORT);
	} else {
		/* Reset current configuration */
		src = (struct sockaddr *)&sc->sc_src;
		dst = (struct sockaddr *)&sc->sc_dst;
		reset = 1;
	}

	src4 = satosin(src);
	dst4 = satosin(dst);

	if (src4->sin_len != sizeof(*src4) || dst4->sin_len != sizeof(*dst4))
		return (EINVAL);

	if (dst4->sin_port)
		sc->sc_dstport = dst4->sin_port;

	if (!reset) {
		bzero(&sc->sc_src, sizeof(sc->sc_src));
		bzero(&sc->sc_dst, sizeof(sc->sc_dst));
		memcpy(&sc->sc_src, src, src->sa_len);
		memcpy(&sc->sc_dst, dst, dst->sa_len);
	}

	return (0);
}
