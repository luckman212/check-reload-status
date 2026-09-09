# $FreeBSD$

PORTNAME=	check_reload_status
PORTVERSION=	0.0.18
CATEGORIES?=	sysutils
MASTER_SITES=	# empty
DISTFILES=	# none
EXTRACT_ONLY=	# empty

MAINTAINER=	coreteam@pfsense.org
COMMENT=	Run pfSense scripts in response to system events

LICENSE=	APACHE20

WHERE=		sbin

PLIST_FILES=	${WHERE}/${PORTNAME} ${WHERE}/pfSctl ${WHERE}/fcgicli \
		/etc/rc.gateway_monitor_reconcile \
		etc/check_reload_status.conf.sample

CFLAGS+=	-I/usr/local/include -L/usr/local/lib

CFLAGS+=	-Wsystem-headers -Werror -Wall -Wno-format-y2k -W \
		-Wno-unused-parameter -Wstrict-prototypes \
		-Wmissing-prototypes -Wpointer-arith -Wreturn-type \
		-Wcast-qual -Wwrite-strings -Wswitch -Wshadow \
		-Wunused-parameter -Wchar-subscripts -Winline \
		-Wnested-externs -Wredundant-decls -Wno-pointer-sign

LIB_DEPENDS=	libevent.so:devel/libevent

do-extract:
	mkdir -p ${WRKSRC}

do-build:
	${CC} ${CFLAGS} -lsbuf -levent -o ${WRKSRC}/${PORTNAME} ${FILESDIR}/${PORTNAME}.c
	${CC} ${CFLAGS} -o ${WRKSRC}/pfSctl ${FILESDIR}/pfSctl.c
	${CC} ${CFLAGS} -lsbuf -o ${WRKSRC}/fcgicli ${FILESDIR}/fcgicli.c

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/check_reload_status ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_PROGRAM} ${WRKSRC}/pfSctl ${STAGEDIR}${PREFIX}/sbin/
	${INSTALL_PROGRAM} ${WRKSRC}/fcgicli ${STAGEDIR}${PREFIX}/sbin/
	${MKDIR} ${STAGEDIR}/etc
	${INSTALL_SCRIPT} ${FILESDIR}/rc.gateway_monitor_reconcile \
		${STAGEDIR}/etc/rc.gateway_monitor_reconcile
	${MKDIR} ${STAGEDIR}${PREFIX}/etc
	${INSTALL_DATA} ${FILESDIR}/check_reload_status.conf.sample \
		${STAGEDIR}${PREFIX}/etc/check_reload_status.conf.sample

.include <bsd.port.mk>
