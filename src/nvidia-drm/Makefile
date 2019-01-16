SRCS = 
KMOD = nvidia-drm

.ifndef BSDVER
BSDVER != /sbin/sysctl -n kern.osreldate
.endif

KMODDIR ?= /boot/modules

# So that the build can include machine/stdarg.h
CFLAGS += -Imachine

# So that the build can include sys/stddef.h
CFLAGS += -I${SYSDIR}/sys

CFLAGS += -I../common/inc
CFLAGS += -DNV_VERSION_STRING=\"415.25\"

include ../common/optional-cflags.mk

.include <bsd.kmod.mk>
