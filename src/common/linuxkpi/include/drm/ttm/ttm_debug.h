/**************************************************************************
 *
 * Copyright (c) 2017 Advanced Micro Devices, Inc.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 **************************************************************************/
/*
 * Authors: Tom St Denis <tom.stdenis@amd.com>
 */
#ifdef __linux__

extern void ttm_trace_dma_map(struct device *dev, struct ttm_dma_tt *tt);
extern void ttm_trace_dma_unmap(struct device *dev, struct ttm_dma_tt *tt);

#else

#include <drm/drmP.h>
#include "ttm_bo_driver.h"

static inline void
ttm_trace_dma_map(struct device *dev, struct ttm_dma_tt *tt){
	CTR2(KTR_DRM, "ttm_dma_map dev %p, ttm_dma_tt %p", dev, tt);
}

static inline void
ttm_trace_dma_unmap(struct device *dev, struct ttm_dma_tt *tt){
	CTR2(KTR_DRM, "ttm_dma_unmap dev %p, ttm_dma_tt %p", dev, tt);
}

#endif
