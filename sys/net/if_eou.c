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

void	eouattach(int);
int	eouioctl(struct ifnet *, u_long, caddr_t);
void	eoustart(struct ifnet *);
int	eou_clone_create(struct if_clone *, int);
int	eou_clone_destroy(struct ifnet *);
int	eou_media_change(struct ifnet *);
void	eou_media_status(struct ifnet *, struct ifmediareq *);

struct eou_softc {
	struct arpcom		sc_ac;
	struct ifmedia		sc_media;
};

struct if_clone	eou_cloner =
    IF_CLONE_INITIALIZER("eou", eou_clone_create, eou_clone_destroy);

int
eou_media_change(struct ifnet *ifp)
{
	return (0);
}

void
eou_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	imr->ifm_active = IFM_ETHER | IFM_AUTO;
	imr->ifm_status = IFM_AVALID | IFM_ACTIVE;
}

void
eouattach(int neou)
{
	if_clone_attach(&eou_cloner);
}

int
eou_clone_create(struct if_clone *ifc, int unit)
{
	struct ifnet		*ifp;
	struct eou_softc	*sc;

	if ((sc = malloc(sizeof(*sc),
	    M_DEVBUF, M_NOWAIT|M_ZERO)) == NULL)
		return (ENOMEM);

	ifp = &sc->sc_ac.ac_if;
	snprintf(ifp->if_xname, sizeof ifp->if_xname, "eou%d", unit);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ether_fakeaddr(ifp);

	ifp->if_softc = sc;
	ifp->if_ioctl = eouioctl;
	ifp->if_start = eoustart;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	IFQ_SET_READY(&ifp->if_snd);

	ifp->if_capabilities = IFCAP_VLAN_MTU;

	ifmedia_init(&sc->sc_media, 0, eou_media_change,
	    eou_media_status);
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
	int			 error = 0, link_state;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		if (ifa->ifa_addr->sa_family == AF_INET)
			arp_ifinit(&sc->sc_ac, ifa);
		/* FALLTHROUGH */

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			ifp->if_flags |= IFF_RUNNING;
			link_state = LINK_STATE_UP;
		} else {
			ifp->if_flags &= ~IFF_RUNNING;
			link_state = LINK_STATE_DOWN;
		}
		if (ifp->if_link_state != link_state) {
			ifp->if_link_state = link_state;
			if_link_state_change(ifp);
		}
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;

	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
	}
	return (error);
}
