NVIDIA_ROOT=	${.CURDIR}/../..

.if !defined(LOCALBASE)
LOCALBASE=	/usr/local
.endif

LIB=		GLX_nvidia
SHLIB_MAJOR=	0
LIBDIR=		${LOCALBASE}/lib
AUXLINK_LINK=   ${DESTDIR}${LIBDIR}/libGLX_indirect.so.0
AUXLINK_TGT_DIR=

EXTRADEPS=	nvidia-application-profiles-rc

# XXX /usr/share/nvidia path hardcoded, because that's where libGL will
# look for this file.

nvidia-application-profiles-rc:
	@mkdir -p /usr/share/nvidia
	@${INSTALL} -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
	${NVIDIA_ROOT}/obj/nvidia-application-profiles-rc \
	/usr/share/nvidia	

.include <${NVIDIA_ROOT}/mk/nvidia.lib.mk>
