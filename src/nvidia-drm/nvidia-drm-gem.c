/*
 * Copyright (c) 2015, NVIDIA CORPORATION. All rights reserved.
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

#include "nvidia-drm-conftest.h"

#if defined(NV_DRM_AVAILABLE)

#include "nvidia-drm-priv.h"
#include "nvidia-drm-ioctl.h"
#include "nvidia-drm-prime-fence.h"
#include "nvidia-drm-gem.h"
#include "nvidia-drm-gem-nvkms-memory.h"

#if defined(NV_DMA_BUF_OWNER_PRESENT)
#include "linux/dma-buf.h" /* To inspect dma_buf->owner during prime import */
#endif

void nv_drm_gem_free(struct drm_gem_object *gem)
{
    struct drm_device *dev = gem->dev;
    struct nv_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    WARN_ON(!mutex_is_locked(&dev->struct_mutex));

    /* Cleanup core gem object */

    drm_gem_object_release(&nv_gem->base);

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
    reservation_object_fini(&nv_gem->resv);
#endif

    nv_gem->ops->free(nv_gem);
}

struct drm_gem_object *nv_drm_gem_prime_import(struct drm_device *dev,
                                               struct dma_buf *dma_buf)
{
#if defined(NV_DMA_BUF_OWNER_PRESENT)
    struct drm_gem_object *gem_dst;
    struct nv_drm_gem_object *nv_gem_src;

    if (dma_buf->owner == dev->driver->fops->owner) {
        nv_gem_src = to_nv_gem_object(dma_buf->priv);

        if (nv_gem_src->base.dev != dev &&
            nv_gem_src->ops->prime_dup != NULL) {
            /*
             * If we're importing from another NV device, try to handle the
             * import internally rather than attaching through the dma-buf
             * mechanisms.  Importing from the same device is even easier,
             * and drm_gem_prime_import() handles that just fine.
             */
            gem_dst = nv_gem_src->ops->prime_dup(dev, nv_gem_src);

            if (gem_dst)
                return gem_dst;
        }
    }
#endif /* NV_DMA_BUF_OWNER_PRESENT */

    return drm_gem_prime_import(dev, dma_buf);
}

struct sg_table *nv_drm_gem_prime_get_sg_table(struct drm_gem_object *gem)
{
    struct nv_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->ops->prime_get_sg_table != NULL) {
        return nv_gem->ops->prime_get_sg_table(nv_gem);
    }

    return ERR_PTR(-ENOTSUPP);
}

void *nv_drm_gem_prime_vmap(struct drm_gem_object *gem)
{
    struct nv_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->ops->prime_vmap != NULL) {
        return nv_gem->ops->prime_vmap(nv_gem);
    }

    return ERR_PTR(-ENOTSUPP);
}

void nv_drm_gem_prime_vunmap(struct drm_gem_object *gem, void *address)
{
    struct nv_drm_gem_object *nv_gem = to_nv_gem_object(gem);

    if (nv_gem->ops->prime_vunmap != NULL) {
        nv_gem->ops->prime_vunmap(nv_gem, address);
    }
}

#if defined(NV_DRM_DRIVER_HAS_GEM_PRIME_RES_OBJ)
struct reservation_object* nv_drm_gem_prime_res_obj(struct drm_gem_object *obj)
{
    struct nv_drm_gem_object *nv_gem = to_nv_gem_object(obj);

    return &nv_gem->resv;
}
#endif

#endif /* NV_DRM_AVAILABLE */
