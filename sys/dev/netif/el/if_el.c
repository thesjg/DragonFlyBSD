/* Copyright (c) 1994, Matthew E. Kimmel.  Permission is hereby granted
 * to use, copy, modify and distribute this software provided that both
 * the copyright notice and this permission notice appear in all copies
 * of the software, derivative works or modified versions, and any
 * portions thereof.
 *
 * Questions, comments, bug reports and fixes to kimmel@cs.umass.edu.
 *
 * $FreeBSD: src/sys/i386/isa/if_el.c,v 1.47.2.2 2000/07/17 21:24:30 archie Exp $
 * $DragonFly: src/sys/dev/netif/el/if_el.c,v 1.24 2008/09/07 07:48:29 swildner Exp $
 */
/* Except of course for the portions of code lifted from other FreeBSD
 * drivers (mainly elread, elget and el_ioctl)
 */
/* 3COM Etherlink 3C501 device driver for FreeBSD */
/* Yeah, I know these cards suck, but you can also get them for free
 * really easily...
 */
/* Bugs/possible improvements:
 *	- Does not currently support DMA
 *	- Does not currently support multicasts
 */
#include "use_el.h"
#include "opt_inet.h"
#include "opt_ipx.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/linker_set.h>
#include <sys/module.h>
#include <sys/serialize.h>
#include <sys/thread2.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/ifq_var.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/bpf.h>

#include <machine/clock.h>

#include <bus/isa/isa_device.h>
#include "if_elreg.h"

DECLARE_DUMMY_MODULE(if_el);

/* For debugging convenience */
#ifdef EL_DEBUG
#define dprintf(x) kprintf x
#else
#define dprintf(x)
#endif

/* el_softc: per line info and status */
static struct el_softc {
	struct arpcom arpcom;	/* Ethernet common */
	u_short el_base;	/* Base I/O addr */
	char el_pktbuf[EL_BUFSIZ]; 	/* Frame buffer */
} el_softc[NEL];

/* Prototypes */
static int el_attach(struct isa_device *);
static void el_init(void *);
static int el_ioctl(struct ifnet *, u_long, caddr_t, struct ucred *);
static int el_probe(struct isa_device *);
static void el_start(struct ifnet *);
static void el_reset(void *);
static void el_watchdog(struct ifnet *);

static void el_stop(void *);
static int el_xmit(struct el_softc *,int);
static void elintr(void *);
static __inline void elread(struct el_softc *,caddr_t,int);
static struct mbuf *elget(caddr_t,int,struct ifnet *);
static __inline void el_hardreset(void *);

/* isa_driver structure for autoconf */
struct isa_driver eldriver = {
	el_probe, el_attach, "el"
};

static struct lwkt_serialize el_serializer;

/* Probe routine.  See if the card is there and at the right place. */
static int
el_probe(struct isa_device *idev)
{
	struct el_softc *sc;
	u_short base; /* Just for convenience */
	u_char station_addr[ETHER_ADDR_LEN];
	int i;

	lwkt_serialize_init(&el_serializer);

	/* Grab some info for our structure */
	sc = &el_softc[idev->id_unit];
	sc->el_base = idev->id_iobase;
	base = sc->el_base;

	/* First check the base */
	if((base < 0x280) || (base > 0x3f0)) {
		kprintf("el%d: ioaddr must be between 0x280 and 0x3f0\n",
			idev->id_unit);
		return(0);
	}

	/* Now attempt to grab the station address from the PROM
	 * and see if it contains the 3com vendor code.
	 */
	dprintf(("Probing 3c501 at 0x%x...\n",base));

	/* Reset the board */
	dprintf(("Resetting board...\n"));
	outb(base+EL_AC,EL_AC_RESET);
	DELAY(5);
	outb(base+EL_AC,0);
	dprintf(("Reading station address...\n"));
	/* Now read the address */
	for(i=0;i<ETHER_ADDR_LEN;i++) {
		outb(base+EL_GPBL,i);
		station_addr[i] = inb(base+EL_EAW);
	}
	dprintf(("Address is %6D\n",station_addr, ":"));

	/* If the vendor code is ok, return a 1.  We'll assume that
	 * whoever configured this system is right about the IRQ.
	 */
	if((station_addr[0] != 0x02) || (station_addr[1] != 0x60)
	   || (station_addr[2] != 0x8c)) {
		dprintf(("Bad vendor code.\n"));
		return(0);
	} else {
		dprintf(("Vendor code ok.\n"));
		/* Copy the station address into the arpcom structure */
		bcopy(station_addr,sc->arpcom.ac_enaddr,ETHER_ADDR_LEN);
		return(1);
	}
}

/* Do a hardware reset of the 3c501.  Do not call until after el_probe()! */
static __inline void
el_hardreset(void *xsc)
{
	struct el_softc *sc = xsc;
	int base;
	int j;

	base = sc->el_base;

	/* First reset the board */
	outb(base+EL_AC,EL_AC_RESET);
	DELAY(5);
	outb(base+EL_AC,0);

	/* Then give it back its ethernet address.  Thanks to the mach
	 * source code for this undocumented goodie...
	 */
	for(j=0;j<ETHER_ADDR_LEN;j++)
		outb(base+j,sc->arpcom.ac_enaddr[j]);
}

/* Attach the interface to the kernel data structures.  By the time
 * this is called, we know that the card exists at the given I/O address.
 * We still assume that the IRQ given is correct.
 */
static int
el_attach(struct isa_device *idev)
{
	struct el_softc *sc;
	struct ifnet *ifp;

	dprintf(("Attaching el%d...\n",idev->id_unit));

	/* Get things pointing to the right places. */
	idev->id_intr = (inthand2_t *)elintr;
	sc = &el_softc[idev->id_unit];
	ifp = &sc->arpcom.ac_if;

	/* Now reset the board */
	dprintf(("Resetting board...\n"));
	el_hardreset(sc);

	/* Initialize ifnet structure */
	ifp->if_softc = sc;
	if_initname(ifp, "el", idev->id_unit);
	ifp->if_mtu = ETHERMTU;
	ifp->if_start = el_start;
	ifp->if_ioctl = el_ioctl;
	ifp->if_watchdog = el_watchdog;
	ifp->if_init = el_init;
	ifp->if_flags = (IFF_BROADCAST | IFF_SIMPLEX);
	ifq_set_maxlen(&ifp->if_snd, IFQ_MAXLEN);
	ifq_set_ready(&ifp->if_snd);

	/* Now we can attach the interface */
	dprintf(("Attaching interface...\n"));
	ether_ifattach(ifp, sc->arpcom.ac_enaddr, &el_serializer);

	dprintf(("el_attach() finished.\n"));
	return(1);
}

/* This routine resets the interface. */
static void 
el_reset(void *xsc)
{
	struct el_softc *sc = xsc;

	dprintf(("elreset()\n"));
	el_stop(sc);
	el_init(sc);
}

static void
el_stop(void *xsc)
{
	struct el_softc *sc = xsc;

	outb(sc->el_base+EL_AC,0);
}

/* Initialize interface.  */
static void 
el_init(void *xsc)
{
	struct el_softc *sc = xsc;
	struct ifnet *ifp = &sc->arpcom.ac_if;
	u_short base = sc->el_base;


	/* First, reset the board. */
	dprintf(("Resetting board...\n"));
	el_hardreset(sc);

	/* Configure rx */
	dprintf(("Configuring rx...\n"));
	if(ifp->if_flags & IFF_PROMISC)
		outb(base+EL_RXC,(EL_RXC_PROMISC|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
	else
		outb(base+EL_RXC,(EL_RXC_ABROAD|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
	outb(base+EL_RBC,0);

	/* Configure TX */
	dprintf(("Configuring tx...\n"));
	outb(base+EL_TXC,0);

	/* Start reception */
	dprintf(("Starting reception...\n"));
	outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));

	/* Set flags appropriately */
	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	/* And start output. */
	el_start(ifp);
}

/* Start output on interface.  Get datagrams from the queue and output
 * them, giving the receiver a chance between datagrams.  Call only
 * from splimp or interrupt level!
 */
static void
el_start(struct ifnet *ifp)
{
	struct el_softc *sc;
	u_short base;
	struct mbuf *m, *m0;
	int i, len, retries, done;

	/* Get things pointing in the right directions */
	sc = ifp->if_softc;
	base = sc->el_base;

	dprintf(("el_start()...\n"));

	/* Don't do anything if output is active */
	if (ifp->if_flags & IFF_OACTIVE)
		return;
	ifp->if_flags |= IFF_OACTIVE;

	/* The main loop.  They warned me against endless loops, but
	 * would I listen?  NOOO....
	 */
	while(1) {
		/* Dequeue the next datagram */
		m0 = ifq_dequeue(&ifp->if_snd, NULL);

		/* If there's nothing to send, return. */
		if(m0 == NULL) {
			sc->arpcom.ac_if.if_flags &= ~IFF_OACTIVE;
			return;
		}

		/* Disable the receiver */
		outb(base+EL_AC,EL_AC_HOST);
		outb(base+EL_RBC,0);

		/* Copy the datagram to the buffer. */
		len = 0;
		for(m = m0; m != NULL; m = m->m_next) {
			if(m->m_len == 0)
				continue;
			bcopy(mtod(m,caddr_t),sc->el_pktbuf+len,m->m_len);
			len += m->m_len;
		}
		m_freem(m0);

		len = max(len,ETHER_MIN_LEN);

		BPF_TAP(&sc->arpcom.ac_if, sc->el_pktbuf, len);

		/* Transfer datagram to board */
		dprintf(("el: xfr pkt length=%d...\n",len));
		i = EL_BUFSIZ - len;
		outb(base+EL_GPBL,(i & 0xff));
		outb(base+EL_GPBH,((i>>8)&0xff));
		outsb(base+EL_BUF,sc->el_pktbuf,len);

		/* Now transmit the datagram */
		retries=0;
		done=0;
		while(!done) {
			if(el_xmit(sc,len)) { /* Something went wrong */
				done = -1;
				break;
			}
			/* Check out status */
			i = inb(base+EL_TXS);
			dprintf(("tx status=0x%x\n",i));
			if(!(i & EL_TXS_READY)) {
				dprintf(("el: err txs=%x\n",i));
				sc->arpcom.ac_if.if_oerrors++;
				if(i & (EL_TXS_COLL|EL_TXS_COLL16)) {
					if((!(i & EL_TXC_DCOLL16)) && retries < 15) {
						retries++;
						outb(base+EL_AC,EL_AC_HOST);
					}
				}
				else
					done = 1;
			}
			else {
				sc->arpcom.ac_if.if_opackets++;
				done = 1;
			}
		}
		if(done == -1)  /* Packet not transmitted */
			continue;

		/* Now give the card a chance to receive.
		 * Gotta love 3c501s...
		 */
		inb(base+EL_AS);
		outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
	}
}

/* This function actually attempts to transmit a datagram downloaded
 * to the board.  Call at splimp or interrupt, after downloading data!
 * Returns 0 on success, non-0 on failure
 */
static int
el_xmit(struct el_softc *sc,int len)
{
	int gpl;
	int i;

	gpl = EL_BUFSIZ - len;
	dprintf(("el: xmit..."));
	outb((sc->el_base)+EL_GPBL,(gpl & 0xff));
	outb((sc->el_base)+EL_GPBH,((gpl>>8)&0xff));
	outb((sc->el_base)+EL_AC,EL_AC_TXFRX);
	i = 20000;
	while((inb((sc->el_base)+EL_AS) & EL_AS_TXBUSY) && (i>0))
		i--;
	if(i == 0) {
		dprintf(("tx not ready\n"));
		sc->arpcom.ac_if.if_oerrors++;
		return(-1);
	}
	dprintf(("%d cycles.\n",(20000-i)));
	return(0);
}

/* Pass a packet up to the higher levels. */
static __inline void
elread(struct el_softc *sc,caddr_t buf,int len)
{
	struct mbuf *m;

	/*
	 * Put packet into an mbuf chain
	 */
	m = elget(buf,len,&sc->arpcom.ac_if);
	if(m)
		sc->arpcom.ac_if.if_input(&sc->arpcom.ac_if, m);
}

/* controller interrupt */
static void
elintr(void *arg)
{
	int unit = (int)arg;
	struct el_softc *sc;
	int base;
	int stat, rxstat, len, done;

	lwkt_serialize_enter(&el_serializer);

	/* Get things pointing properly */
	sc = &el_softc[unit];
	base = sc->el_base;

	dprintf(("elintr: "));

	/* Check board status */
	stat = inb(base+EL_AS);
	if(stat & EL_AS_RXBUSY) {
		inb(base+EL_RXC);
		outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
		lwkt_serialize_exit(&el_serializer);
		return;
	}

	done = 0;
	while(!done) {
		rxstat = inb(base+EL_RXS);
		if(rxstat & EL_RXS_STALE) {
			inb(base+EL_RXC);
			outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
			lwkt_serialize_exit(&el_serializer);
			return;
		}

		/* If there's an overflow, reinit the board. */
		if(!(rxstat & EL_RXS_NOFLOW)) {
			dprintf(("overflow.\n"));
			el_hardreset(sc);
			/* Put board back into receive mode */
			if(sc->arpcom.ac_if.if_flags & IFF_PROMISC)
				outb(base+EL_RXC,(EL_RXC_PROMISC|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
			else
				outb(base+EL_RXC,(EL_RXC_ABROAD|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
			inb(base+EL_AS);
			outb(base+EL_RBC,0);
			inb(base+EL_RXC);
			outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
			lwkt_serialize_exit(&el_serializer);
			return;
		}

		/* Incoming packet */
		len = inb(base+EL_RBL);
		len |= inb(base+EL_RBH) << 8;
		dprintf(("receive len=%d rxstat=%x ",len,rxstat));
		outb(base+EL_AC,EL_AC_HOST);

		/* If packet too short or too long, restore rx mode and return
		 */
		if((len <= sizeof(struct ether_header)) || (len > ETHER_MAX_LEN)) {
			if(sc->arpcom.ac_if.if_flags & IFF_PROMISC)
				outb(base+EL_RXC,(EL_RXC_PROMISC|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
			else
				outb(base+EL_RXC,(EL_RXC_ABROAD|EL_RXC_AGF|EL_RXC_DSHORT|EL_RXC_DDRIB|EL_RXC_DOFLOW));
			inb(base+EL_AS);
			outb(base+EL_RBC,0);
			inb(base+EL_RXC);
			outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
			lwkt_serialize_exit(&el_serializer);
			return;
		}

		sc->arpcom.ac_if.if_ipackets++;

		/* Copy the data into our buffer */
		outb(base+EL_GPBL,0);
		outb(base+EL_GPBH,0);
		insb(base+EL_BUF,sc->el_pktbuf,len);
		outb(base+EL_RBC,0);
		outb(base+EL_AC,EL_AC_RX);
		dprintf(("%6D-->",sc->el_pktbuf+6,":"));
		dprintf(("%6D\n",sc->el_pktbuf,":"));

		/* Pass data up to upper levels */
		elread(sc,(caddr_t)(sc->el_pktbuf),len);

		/* Is there another packet? */
		stat = inb(base+EL_AS);

		/* If so, do it all again (i.e. don't set done to 1) */
		if(!(stat & EL_AS_RXBUSY))
			dprintf(("<rescan> "));
		else
			done = 1;
	}

	inb(base+EL_RXC);
	outb(base+EL_AC,(EL_AC_IRQE|EL_AC_RX));
	lwkt_serialize_exit(&el_serializer);
}

/*
 * Pull read data off a interface.
 * Len is length of data, with local net header stripped.
 */
static struct mbuf *
elget(caddr_t buf, int totlen, struct ifnet *ifp)
{
        struct mbuf *top, **mp, *m;
        int len;
        caddr_t cp;
        char *epkt;

        cp = buf;
        epkt = cp + totlen;

        MGETHDR(m, MB_DONTWAIT, MT_DATA);
        if (m == 0)
                return (0);
        m->m_pkthdr.len = totlen;
        m->m_len = MHLEN;
        top = 0;
        mp = &top;
        while (totlen > 0) {
                if (top) {
                        MGET(m, MB_DONTWAIT, MT_DATA);
                        if (m == 0) {
                                m_freem(top);
                                return (0);
                        }
                        m->m_len = MLEN;
                }
                len = min(totlen, epkt - cp);
                if (len >= MINCLSIZE) {
                        MCLGET(m, MB_DONTWAIT);
                        if (m->m_flags & M_EXT)
                                m->m_len = len = min(len, MCLBYTES);
                        else
                                len = m->m_len;
                } else {
                        /*
                         * Place initial small packet/header at end of mbuf.
                         */
                        if (len < m->m_len) {
                                if (top == 0 && len + max_linkhdr <= m->m_len)
                                        m->m_data += max_linkhdr;
                                m->m_len = len;
                        } else
                                len = m->m_len;
                }
                bcopy(cp, mtod(m, caddr_t), (unsigned)len);
                cp += len;
                *mp = m;
                mp = &m->m_next;
                totlen -= len;
                if (cp == epkt)
                        cp = buf;
        }
        return (top);
}

/*
 * Process an ioctl request. This code needs some work - it looks
 *	pretty ugly.
 */
static int
el_ioctl(struct ifnet *ifp, u_long command, caddr_t data, struct ucred *cr)
{
	int error = 0;

	switch (command) {
	case SIOCSIFFLAGS:
		/*
		 * If interface is marked down and it is running, then stop it
		 */
		if (((ifp->if_flags & IFF_UP) == 0) &&
		    (ifp->if_flags & IFF_RUNNING)) {
			el_stop(ifp->if_softc);
			ifp->if_flags &= ~IFF_RUNNING;
		} else {
		/*
		 * If interface is marked up and it is stopped, then start it
		 */
			if ((ifp->if_flags & IFF_UP) &&
		    	    ((ifp->if_flags & IFF_RUNNING) == 0))
				el_init(ifp->if_softc);
		}
		break;
	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}
	return (error);
}

/* Device timeout routine */
static void
el_watchdog(struct ifnet *ifp)
{
	log(LOG_ERR,"%s: device timeout\n", ifp->if_xname);
	ifp->if_oerrors++;
	el_reset(ifp->if_softc);
}
