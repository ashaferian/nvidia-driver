#
# This Makefile was automatically generated; do not edit.
# Generated on 'U64-P08-10' on Wed Apr 1 19:46:29 UTC 2020.
#

OSOBJ=		nv-freebsd.o
KMOD=		nvidia
RMOBJ=		nv-kernel.o

.ifndef BSDVER
BSDVER!=	/sbin/sysctl -n kern.osreldate
.endif

KMODDIR?=	/boot/modules

SPECTRE_V2_RETPOLINE?=	1

include nvidia-sources.mk

SRCS=		${NVIDIA_SOURCES}
SRCS+=		acpi_if.h bus_if.h device_if.h opt_acpi.h pci_if.h vnode_if.h
CFLAGS+=	-I. -I../common/inc -DNV_VERSION_STRING=\"440.82\" -Wno-visibility
CFLAGS+=	-D__KERNEL__ -DNVRM  -Wno-unused-function -Wuninitialized -O2 -fno-strict-aliasing  -mno-red-zone -mcmodel=kernel     -UDEBUG -U_DEBUG -DNDEBUG
CFLAGS+=	-DNV_SPECTRE_V2=$(SPECTRE_V2_RETPOLINE)

include ../common/optional-cflags.mk

OBJS+=		${RMOBJ}
NO_OBJ=		true

stdarg.h:
	@ln -s machine/stdarg.h stdarg.h

*.c: stdarg.h

beforeinstall:	${KMOD}.ko

all:	${OSOBJ}

${OSOBJ}:	${KMOD}.ko
	@ld -r -o $@ ${OBJS:S/${RMOBJ}//}

CLEANFILES+=	${OSOBJ}

clean:
	@rm -f ${CLEANFILES:S/${RMOBJ}//}
	@rm -f stdarg.h

.include <bsd.kmod.mk>
