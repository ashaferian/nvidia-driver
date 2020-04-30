NVIDIA_ROOT=	${.CURDIR}/..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

BSDVER!=	/sbin/sysctl -n kern.osreldate
NO_OBJ=	noobj

DOCS=	README \
	XF86Config.sample \
	license.txt

HTMLDOCS!=(ls ${NVIDIA_ROOT}/doc/html/)

DOCDIR=	${LOCALBASE}/share/doc/NVIDIA_GLX-1.0

all:   # dummy rule
clean: # dummy rule

install:
	@mkdir -p ${DESTDIR}${DOCDIR}
.for doc in ${DOCS}
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/${doc} \
		${DESTDIR}${DOCDIR}
.endfor
	@mkdir -p ${DESTDIR}${DOCDIR}/html
.for doc in ${HTMLDOCS}
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/html/${doc} \
		${DESTDIR}${DOCDIR}/html
.endfor
# XXX /usr/share/nvidia path hardcoded because that's where nvidia-settings
# will look for this file.
	@mkdir -p /usr/share/nvidia
	@${INSTALL} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${NVIDIA_ROOT}/doc/nvidia-application-profiles-key-documentation \
		/usr/share/nvidia
.include <bsd.prog.mk>
