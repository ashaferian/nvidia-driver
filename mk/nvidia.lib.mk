.if defined(LIB) && defined(SHLIB_MAJOR)
SHLIB_NAME?=	lib${LIB}.so.${SHLIB_MAJOR}
.endif
.if defined(SHLIB_NAME)
.if !defined(SHLIB_NO_LINK)
SHLIB_LINK?=	${SHLIB_NAME:R}
.endif
.if defined(AUXLINK_LINK)
AUXLINK_TGT?=${AUXLINK_TGT_DIR}${SHLIB_NAME}
.endif
.endif
.if defined(STATIC_LIB) && ${STATIC_LIB} == "true"
STATICLIB_NAME?=     lib${LIB}.a
.endif

.if !defined(OBJDIR)
OBJDIR=		obj
.endif

all:   # dummy rule
clean: # dummy rule

install: ${EXTRADEPS}
.if defined(SHLIB_NAME)
	@mkdir -p ${DESTDIR}${LIBDIR}
	@rm -f ${DESTDIR}${LIBDIR}/${SHLIB_NAME}
	@${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/${OBJDIR}/${SHLIB_NAME} \
		${DESTDIR}${LIBDIR}
.endif
.if defined(SHLIB_LINK)
# If SHLIB_LINK_NOCLOBBER is defined, any symlinks will be removed (and a
# symlink to our library added), but regular files will not be removed.
.if defined(SHLIB_LINK_NOCLOBBER)
	@if [ ! -e ${DESTDIR}${LIBDIR}/${SHLIB_LINK} ] || \
		[ -L ${DESTDIR}${LIBDIR}/${SHLIB_LINK} ]; then \
	    rm -f ${DESTDIR}${LIBDIR}/${SHLIB_LINK}; \
	    ln -fs ${SHLIB_NAME} ${DESTDIR}${LIBDIR}/${SHLIB_LINK}; \
	else \
	    echo "Note: Not installing a symlink to ${SHLIB_NAME} "; \
	    echo "because ${DESTDIR}${LIBDIR}/${SHLIB_LINK} already exists."; \
	fi
.else
	@rm -f ${DESTDIR}${LIBDIR}/${SHLIB_LINK}
	@ln -fs ${SHLIB_NAME} ${DESTDIR}${LIBDIR}/${SHLIB_LINK}
.endif		
.endif
.if defined(AUXLINK_TGT)
	@rm -f ${AUXLINK_LINK}
	@ln -fs ${AUXLINK_TGT} ${AUXLINK_LINK}
.endif
.if defined(STATICLIB_NAME)
	@rm -f ${DESTDIR}${LIBDIR}/${STATICLIB_NAME}
	@${INSTALL} -C -o ${LIBOWN} -g ${LIBGRP} -m ${LIBMODE} \
		${NVIDIA_ROOT}/${OBJDIR}/${STATICLIB_NAME} \
		${DESTDIR}${LIBDIR}
.endif

.include <bsd.init.mk>
