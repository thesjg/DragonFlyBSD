#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: src/sbin/reboot/Makefile,v 1.6.8.3 2002/02/20 15:26:14 ru Exp $
# $DragonFly: src/sbin/reboot/Makefile,v 1.6 2007/01/20 19:18:02 swildner Exp $

PROG=	reboot
DPADD=	${LIBUTIL}
LDADD=	-lutil
MAN=	reboot.8
MLINKS=	reboot.8 halt.8 reboot.8 fastboot.8 reboot.8 fasthalt.8

.if exists(${.CURDIR}/boot_${MACHINE_PLATFORM}.8)
MAN+=	boot_${MACHINE_PLATFORM}.8
MLINKS+=boot_${MACHINE_PLATFORM}.8 boot.8
.endif

.if ${MACHINE_PLATFORM} == "pc64"
MAN+=	boot_pc32.8
MLINKS+=boot_pc32.8 boot.8
.endif

LINKS=	${BINDIR}/reboot ${BINDIR}/halt ${BINDIR}/reboot ${BINDIR}/fastboot \
	${BINDIR}/reboot ${BINDIR}/fasthalt

.include <bsd.prog.mk>
