# $FreeBSD: src/gnu/usr.bin/groff/src/preproc/tbl/Makefile,v 1.4 2003/05/01 13:22:20 ru Exp $
# $DragonFly: src/gnu/usr.bin/groff/src/preproc/tbl/Makefile,v 1.3 2005/09/01 20:47:13 asmodai Exp $

PROG_CXX=	tbl
SRCS=		main.cpp table.cpp
DPADD=		${LIBGROFF} ${LIBM}
LDADD=		${LIBGROFF} -lm
CLEANFILES=	${MAN}

.include <bsd.prog.mk>
