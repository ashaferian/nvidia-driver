/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2002 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include "nv-misc.h"
#include "os-interface.h"
#include "nv.h"
#include "nv-freebsd.h"

static d_open_t  nvidia_dev_open;
static d_ioctl_t nvidia_dev_ioctl;
static d_poll_t  nvidia_dev_poll;
static d_mmap_single_t nvidia_dev_mmap_single;

static struct cdevsw nvidia_dev_cdevsw = {
    .d_open =      nvidia_dev_open,
    .d_ioctl =     nvidia_dev_ioctl,
    .d_poll =      nvidia_dev_poll,
    .d_mmap_single = nvidia_dev_mmap_single,
    .d_name =      "nvidia",
    .d_version =   D_VERSION,
    .d_flags =     D_MEM
};

static int nvidia_dev_open(
    struct cdev *dev,
    int oflags,
    int devtype,
    struct thread *td
)
{
    int status;
    struct nvidia_softc *sc = dev->si_drv1;
    nv_state_t *nv = sc->nv_state;
    struct nvidia_filep *filep;

    filep = malloc(sizeof(nvidia_filep_t), M_NVIDIA, (M_WAITOK | M_ZERO));
    if (filep == NULL)
        return ENOMEM;

    filep->nv = nv;
    mtx_init(&filep->event_mtx, "event_mtx", NULL, (MTX_DEF | MTX_RECURSE));
    STAILQ_INIT(&filep->event_queue);

    nv_lock_api(nv);
    status = nvidia_open_dev(nv, filep);
    nv_unlock_api(nv);

    if (status != 0) {
        free(filep, M_NVIDIA);
        return status;
    }

    status = devfs_set_cdevpriv(filep, nvidia_dev_dtor);
    if (status != 0) {
        free(filep, M_NVIDIA);
        return status;
    }

    return 0;
}

void nvidia_dev_dtor(void *arg)
{
    int status;
    struct nvidia_filep *filep = arg;
    struct nvidia_event *et;
    nv_state_t *nv = filep->nv;

    nv_lock_api(nv);
    status = nvidia_close_dev(nv, filep);
    nv_unlock_api(nv);

    while ((et = STAILQ_FIRST(&filep->event_queue))) {
        STAILQ_REMOVE(&filep->event_queue, et, nvidia_event, queue);
        free(et, M_NVIDIA);
    }
    mtx_destroy(&filep->event_mtx);

    free(filep, M_NVIDIA);
}

static int nvidia_dev_ioctl(
    struct cdev *dev,
    u_long cmd,
    caddr_t data,
    int fflag,
    struct thread *td
)
{
    int status;
    struct nvidia_filep *filep;
    nv_state_t *nv;

    status = devfs_get_cdevpriv((void **)&filep);
    if (status != 0)
        return status;
    nv = filep->nv;

    if (__NV_IOC_TYPE(cmd) != NV_IOCTL_MAGIC)
        return ENOTTY;

    nv_lock_api(nv);
    status = nvidia_handle_ioctl(nv, filep, cmd, data);
    nv_unlock_api(nv);

    return status;
}

static int nvidia_dev_poll(
    struct cdev *dev,
    int events,
    struct thread *td
)
{
    struct nvidia_filep *filep;
    int status, mask = 0;

    status = devfs_get_cdevpriv((void **)&filep);
    if (status != 0)
        return 0;

    mtx_lock(&filep->event_mtx);

    if (STAILQ_EMPTY(&filep->event_queue) && !filep->event_pending)
        selrecord(td, &filep->event_rsel);
    else {
        mask = (events & (POLLIN | POLLPRI | POLLRDNORM));
        filep->event_pending = FALSE;
    }

    mtx_unlock(&filep->event_mtx);

    return mask;
}

static int nvidia_dev_mmap_single(
    struct cdev *dev,
    vm_ooffset_t *offset,
    vm_size_t size,
    vm_object_t *object,
    int nprot
)
{
    int status;
    struct nvidia_filep *filep;
    nv_state_t *nv;

    status = devfs_get_cdevpriv((void **)&filep);
    if (status != 0)
        return status;
    nv = filep->nv;

    nv_lock_api(nv);
    status = nvidia_mmap_dev_single(nv, filep, offset, size, object);
    nv_unlock_api(nv);

    return status;
}

int nvidia_dev_attach(struct nvidia_softc *sc)
{
    sc->cdev = make_dev(&nvidia_dev_cdevsw,
            device_get_unit(sc->dev),
            UID_ROOT, GID_WHEEL, 0666,
            "%s%d", nvidia_dev_cdevsw.d_name,
            device_get_unit(sc->dev));
    if (sc->cdev == NULL)
        return ENOMEM;

    sc->cdev->si_drv1 = sc;

    return 0;
}

int nvidia_dev_detach(struct nvidia_softc *sc)
{
    destroy_dev(sc->cdev);
    return 0;
}
