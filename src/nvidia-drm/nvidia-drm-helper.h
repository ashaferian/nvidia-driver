/*
 * Copyright (c) 2016, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __NVIDIA_DRM_HELPER_H__
#define __NVIDIA_DRM_HELPER_H__

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#if defined(NV_DRM_DRMP_H_PRESENT)
#include <drm/drmP.h>
#endif

#if defined(NV_DRM_DRM_DRV_H_PRESENT)
#include <drm/drm_drv.h>
#endif

/*
 * drm_dev_put() is added by commit 9a96f55034e41b4e002b767e9218d55f03bdff7d
 * (2017-09-26) and drm_dev_unref() is removed by
 * ba1d345401476a5f7fbad622607c5a1f95e59b31 (2018-11-15).
 *
 * drm_dev_unref() has been added and drm_dev_free() removed by commit -
 *
 *      2014-01-29: 099d1c290e2ebc3b798961a6c177c3aef5f0b789
 */
static inline void nv_drm_dev_free(struct drm_device *dev)
{
#if defined(NV_DRM_DEV_PUT_PRESENT)
    drm_dev_put(dev);
#elif defined(NV_DRM_DEV_UNREF_PRESENT)
    drm_dev_unref(dev);
#else
    drm_dev_free(dev);
#endif
}

#if defined(NV_DRM_ATOMIC_MODESET_AVAILABLE)

/*
 * drm_for_each_connector(), drm_for_each_crtc(), drm_for_each_fb(),
 * drm_for_each_encoder and drm_for_each_plane() were added by kernel
 * commit 6295d607ad34ee4e43aab3f20714c2ef7a6adea1 which was
 * Signed-off-by:
 *     Daniel Vetter <daniel.vetter@intel.com>
 * drm_for_each_connector(), drm_for_each_crtc(), drm_for_each_fb(),
 * drm_for_each_encoder and drm_for_each_plane() are copied from
 *      include/drm/drm_crtc @
 *      6295d607ad34ee4e43aab3f20714c2ef7a6adea1
 * which has the following copyright and license information:
 *
 * Copyright © 2006 Keith Packard
 * Copyright © 2007-2008 Dave Airlie
 * Copyright © 2007-2008 Intel Corporation
 *   Jesse Barnes <jesse.barnes@intel.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include <drm/drm_crtc.h>

#if defined(drm_for_each_plane)
#define nv_drm_for_each_plane(plane, dev) \
    drm_for_each_plane(plane, dev)
#else
#define nv_drm_for_each_plane(plane, dev) \
    list_for_each_entry(plane, &(dev)->mode_config.plane_list, head)
#endif

#if defined(drm_for_each_crtc)
#define nv_drm_for_each_crtc(crtc, dev) \
    drm_for_each_crtc(crtc, dev)
#else
#define nv_drm_for_each_crtc(crtc, dev) \
    list_for_each_entry(crtc, &(dev)->mode_config.crtc_list, head)
#endif

#if defined(NV_DRM_CONNECTOR_LIST_ITER_PRESENT)
#define nv_drm_for_each_connector(connector, conn_iter, dev) \
        drm_for_each_connector_iter(connector, conn_iter)
#elif defined(drm_for_each_connector)
#define nv_drm_for_each_connector(connector, conn_iter, dev) \
    drm_for_each_connector(connector, dev)
#else
#define nv_drm_for_each_connector(connector, conn_iter, dev) \
    WARN_ON(!mutex_is_locked(&dev->mode_config.mutex));      \
    list_for_each_entry(connector, &(dev)->mode_config.connector_list, head)
#endif

#if defined(drm_for_each_encoder)
#define nv_drm_for_each_encoder(encoder, dev) \
    drm_for_each_encoder(encoder, dev)
#else
#define nv_drm_for_each_encoder(encoder, dev) \
    list_for_each_entry(encoder, &(dev)->mode_config.encoder_list, head)
#endif

#if defined(drm_for_each_fb)
#define nv_drm_for_each_fb(fb, dev) \
    drm_for_each_fb(fb, dev)
#else
#define nv_drm_for_each_fb(fb, dev) \
    list_for_each_entry(fb, &(dev)->mode_config.fb_list, head)
#endif

#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>

int nv_drm_atomic_helper_disable_all(struct drm_device *dev,
                                     struct drm_modeset_acquire_ctx *ctx);

/*
 * for_each_connector_in_state(), for_each_crtc_in_state() and
 * for_each_plane_in_state() were added by kernel commit
 * df63b9994eaf942afcdb946d27a28661d7dfbf2a which was Signed-off-by:
 *      Ander Conselvan de Oliveira <ander.conselvan.de.oliveira@intel.com>
 *      Daniel Vetter <daniel.vetter@ffwll.ch>
 *
 * for_each_connector_in_state(), for_each_crtc_in_state() and
 * for_each_plane_in_state() were copied from
 *      include/drm/drm_atomic.h @
 *      21a01abbe32a3cbeb903378a24e504bfd9fe0648
 * which has the following copyright and license information:
 *
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2014 Intel Corp.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 * Rob Clark <robdclark@gmail.com>
 * Daniel Vetter <daniel.vetter@ffwll.ch>
 */

/**
 * nv_drm_for_each_connector_in_state - iterate over all connectors in an
 * atomic update
 * @__state: &struct drm_atomic_state pointer
 * @connector: &struct drm_connector iteration cursor
 * @connector_state: &struct drm_connector_state iteration cursor
 * @__i: int iteration cursor, for macro-internal use
 *
 * This iterates over all connectors in an atomic update. Note that before the
 * software state is committed (by calling drm_atomic_helper_swap_state(), this
 * points to the new state, while afterwards it points to the old state. Due to
 * this tricky confusion this macro is deprecated.
 */
#if !defined(for_each_connector_in_state)
#define nv_drm_for_each_connector_in_state(__state,                         \
                                           connector, connector_state, __i) \
       for ((__i) = 0;                                                      \
            (__i) < (__state)->num_connector &&                             \
            ((connector) = (__state)->connectors[__i].ptr,                  \
            (connector_state) = (__state)->connectors[__i].state, 1);       \
            (__i)++)                                                        \
               for_each_if (connector)
#else
#define nv_drm_for_each_connector_in_state(__state,                         \
                                           connector, connector_state, __i) \
    for_each_connector_in_state(__state, connector, connector_state, __i)
#endif


/**
 * nv_drm_for_each_crtc_in_state - iterate over all CRTCs in an atomic update
 * @__state: &struct drm_atomic_state pointer
 * @crtc: &struct drm_crtc iteration cursor
 * @crtc_state: &struct drm_crtc_state iteration cursor
 * @__i: int iteration cursor, for macro-internal use
 *
 * This iterates over all CRTCs in an atomic update. Note that before the
 * software state is committed (by calling drm_atomic_helper_swap_state(), this
 * points to the new state, while afterwards it points to the old state. Due to
 * this tricky confusion this macro is deprecated.
 */
#if !defined(for_each_crtc_in_state)
#define nv_drm_for_each_crtc_in_state(__state, crtc, crtc_state, __i) \
       for ((__i) = 0;                                                \
            (__i) < (__state)->dev->mode_config.num_crtc &&           \
            ((crtc) = (__state)->crtcs[__i].ptr,                      \
            (crtc_state) = (__state)->crtcs[__i].state, 1);           \
            (__i)++)                                                  \
               for_each_if (crtc_state)
#else
#define nv_drm_for_each_crtc_in_state(__state, crtc, crtc_state, __i) \
    for_each_crtc_in_state(__state, crtc, crtc_state, __i)
#endif

/**
 * nv_drm_for_each_plane_in_state - iterate over all planes in an atomic update
 * @__state: &struct drm_atomic_state pointer
 * @plane: &struct drm_plane iteration cursor
 * @plane_state: &struct drm_plane_state iteration cursor
 * @__i: int iteration cursor, for macro-internal use
 *
 * This iterates over all planes in an atomic update. Note that before the
 * software state is committed (by calling drm_atomic_helper_swap_state(), this
 * points to the new state, while afterwards it points to the old state. Due to
 * this tricky confusion this macro is deprecated.
 */
#if !defined(for_each_plane_in_state)
#define nv_drm_for_each_plane_in_state(__state, plane, plane_state, __i) \
       for ((__i) = 0;                                                   \
            (__i) < (__state)->dev->mode_config.num_total_plane &&       \
            ((plane) = (__state)->planes[__i].ptr,                       \
            (plane_state) = (__state)->planes[__i].state, 1);            \
            (__i)++)                                                     \
               for_each_if (plane_state)
#else
#define nv_drm_for_each_plane_in_state(__state, plane, plane_state, __i) \
    for_each_plane_in_state(__state, plane, plane_state, __i)
#endif

static inline struct drm_crtc *nv_drm_crtc_find(struct drm_device *dev,
    uint32_t id)
{
#if defined(NV_DRM_MODE_OBJECT_FIND_HAS_FILE_PRIV_ARG)
    return drm_crtc_find(dev, NULL /* file_priv */, id);
#else
    return drm_crtc_find(dev, id);
#endif
}

static inline struct drm_encoder *nv_drm_encoder_find(struct drm_device *dev,
    uint32_t id)
{
#if defined(NV_DRM_MODE_OBJECT_FIND_HAS_FILE_PRIV_ARG)
    return drm_encoder_find(dev, NULL /* file_priv */, id);
#else
    return drm_encoder_find(dev, id);
#endif
}

/*
 * drm_connector_for_each_possible_encoder() is added by commit
 * 83aefbb887b59df0b3520965c3701e01deacfc52 which was Signed-off-by:
 *     Ville Syrjälä <ville.syrjala@linux.intel.com>
 *
 * drm_connector_for_each_possible_encoder() is copied from
 * include/drm/drm_connector.h and modified to use nv_drm_encoder_find()
 * instead of drm_encoder_find().
 *
 * drm_connector_for_each_possible_encoder() is copied from
 *      include/drm/drm_connector.h @
 *      83aefbb887b59df0b3520965c3701e01deacfc52
 * which has the following copyright and license information:
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#if defined(NV_DRM_DRM_CONNECTOR_H_PRESENT)
#include <drm/drm_connector.h>
#endif

/**
 * nv_drm_connector_for_each_possible_encoder - iterate connector's possible
 * encoders
 * @connector: &struct drm_connector pointer
 * @encoder: &struct drm_encoder pointer used as cursor
 * @__i: int iteration cursor, for macro-internal use
 */
#if !defined(drm_connector_for_each_possible_encoder)

#if !defined(for_each_if)
#define for_each_if(condition) if (!(condition)) {} else
#endif

#define __nv_drm_connector_for_each_possible_encoder(connector, encoder, __i) \
       for ((__i) = 0; (__i) < ARRAY_SIZE((connector)->encoder_ids) &&        \
                    (connector)->encoder_ids[(__i)] != 0; (__i)++)            \
               for_each_if((encoder) =                                        \
                           nv_drm_encoder_find((connector)->dev,              \
                                               (connector)->encoder_ids[(__i)]))

#define nv_drm_connector_for_each_possible_encoder(connector, encoder) \
    {                                                                  \
        unsigned int __i;                                              \
        __nv_drm_connector_for_each_possible_encoder(connector, encoder, __i)

#define nv_drm_connector_for_each_possible_encoder_end \
    }

#else

#if NV_DRM_CONNECTOR_FOR_EACH_POSSIBLE_ENCODER_ARGUMENT_COUNT == 3

#define nv_drm_connector_for_each_possible_encoder(connector, encoder) \
    {                                                                  \
        unsigned int __i;                                              \
        drm_connector_for_each_possible_encoder(connector, encoder, __i)

#define nv_drm_connector_for_each_possible_encoder_end \
    }

#else

#define nv_drm_connector_for_each_possible_encoder(connector, encoder) \
    drm_connector_for_each_possible_encoder(connector, encoder)

#define nv_drm_connector_for_each_possible_encoder_end

#endif

#endif

static inline int
nv_drm_connector_attach_encoder(struct drm_connector *connector,
                                struct drm_encoder *encoder)
{
#if defined(NV_DRM_CONNECTOR_FUNCS_HAVE_MODE_IN_NAME)
    return drm_mode_connector_attach_encoder(connector, encoder);
#else
    return drm_connector_attach_encoder(connector, encoder);
#endif
}

static inline int
nv_drm_connector_update_edid_property(struct drm_connector *connector,
                                      const struct edid *edid)
{
#if defined(NV_DRM_CONNECTOR_FUNCS_HAVE_MODE_IN_NAME)
    return drm_mode_connector_update_edid_property(connector, edid);
#else
    return drm_connector_update_edid_property(connector, edid);
#endif
}

#if defined(NV_DRM_CONNECTOR_LIST_ITER_PRESENT)
#include <drm/drm_connector.h>

static inline
void nv_drm_connector_list_iter_begin(struct drm_device *dev,
                                      struct drm_connector_list_iter *iter)
{
#if defined(NV_DRM_CONNECTOR_LIST_ITER_BEGIN_PRESENT)
    drm_connector_list_iter_begin(dev, iter);
#else
    drm_connector_list_iter_get(dev, iter);
#endif
}

static inline
void nv_drm_connector_list_iter_end(struct drm_connector_list_iter *iter)
{
#if defined(NV_DRM_CONNECTOR_LIST_ITER_BEGIN_PRESENT)
    drm_connector_list_iter_end(iter);
#else
    drm_connector_list_iter_put(iter);
#endif
}
#endif

#endif /* defined(NV_DRM_ATOMIC_MODESET_AVAILABLE) */

#endif /* defined(NV_DRM_AVAILABLE) */

#endif /* __NVIDIA_DRM_HELPER_H__ */
