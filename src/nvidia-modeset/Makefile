SRCS = nvidia-modeset-freebsd.c
KMOD = nvidia-modeset

.ifndef BSDVER
BSDVER != /sbin/sysctl -n kern.osreldate
.endif

KMODDIR ?= /boot/modules

NVIDIA_MODESET_KERNEL = nv-modeset-kernel.o

OBJS += ${NVIDIA_MODESET_KERNEL}
NO_OBJ = true

clean:
	@rm -f ${CLEANFILES:S/${NVIDIA_MODESET_KERNEL}//}

beforeinstall:  ${KMOD}.ko

# So that the build can include machine/stdarg.h
CFLAGS += -Imachine

# So that the build can include sys/stddef.h
CFLAGS += -I${SYSDIR}/sys

CFLAGS += -I../common/inc
CFLAGS += -DNV_VERSION_STRING=\"415.25\"

include ../common/optional-cflags.mk

.include <bsd.kmod.mk>
