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

static d_open_t  nvidia_ctl_open;
static d_ioctl_t nvidia_ctl_ioctl;
static d_poll_t  nvidia_ctl_poll;
static d_mmap_single_t nvidia_ctl_mmap_single;

static struct cdevsw nvidia_ctl_cdevsw = {
    .d_open =      nvidia_ctl_open,
    .d_ioctl =     nvidia_ctl_ioctl,
    .d_poll =      nvidia_ctl_poll,
    .d_mmap_single = nvidia_ctl_mmap_single,
    .d_name =      "nvidiactl",
    .d_version =   D_VERSION,
};

static struct cdev *nvidia_ctl_cdev = NULL;
struct nvidia_softc nvidia_ctl_sc;

static int nvidia_count = 0;

static int nvidia_ctl_open(
    struct cdev *dev,
    int oflags,
    int devtype,
    struct thread *td
)
{
    int status;
    nv_state_t *nv = &nvidia_ctl_state;
    struct nvidia_filep *filep;

    filep = malloc(sizeof(nvidia_filep_t), M_NVIDIA, (M_WAITOK | M_ZERO));
    if (filep == NULL)
        return ENOMEM;

    status = devfs_set_cdevpriv(filep, nvidia_ctl_dtor);
    if (status != 0) {
        free(filep, M_NVIDIA);
        return status;
    }

    filep->nv = nv;
    mtx_init(&filep->event_mtx, "event_mtx", NULL, (MTX_DEF | MTX_RECURSE));
    STAILQ_INIT(&filep->event_queue);

    nv_lock_api(nv);
    status = nvidia_open_ctl(nv, filep);
    nv_unlock_api(nv);

    return status;
}

void nvidia_ctl_dtor(void *arg)
{
    int status;
    struct nvidia_filep *filep = arg;
    struct nvidia_event *et;
    nv_state_t *nv = filep->nv;

    nv_lock_api(nv);
    status = nvidia_close_ctl(nv, filep);
    nv_unlock_api(nv);

    while ((et = STAILQ_FIRST(&filep->event_queue))) {
        STAILQ_REMOVE(&filep->event_queue, et, nvidia_event, queue);
        free(et, M_NVIDIA);
    }
    mtx_destroy(&filep->event_mtx);

    free(filep, M_NVIDIA);
}

static int nvidia_ctl_ioctl(
    struct cdev *dev,
    u_long cmd,
    caddr_t data,
    int fflag,
    struct thread *td
)
{
    int status;
    nv_state_t *nv = &nvidia_ctl_state;
    struct nvidia_filep *filep;

    status = devfs_get_cdevpriv((void **)&filep);
    if (status != 0)
        return status;

    if (__NV_IOC_TYPE(cmd) != NV_IOCTL_MAGIC)
        return ENOTTY;

    nv_lock_api(nv);
    status = nvidia_handle_ioctl(nv, filep, cmd, data);
    nv_unlock_api(nv);

    return status;
}

static int nvidia_ctl_poll(
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

static int nvidia_ctl_mmap_single(
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
    status = nvidia_mmap_ctl_single(nv, filep, offset, size, object, nprot);
    nv_unlock_api(nv);

    return status;
}

int nvidia_ctl_attach(void)
{
    if (nvidia_count == 0) {
        nvidia_ctl_cdev = make_dev(&nvidia_ctl_cdevsw,
                CDEV_CTL_MINOR,
                UID_ROOT, GID_WHEEL, 0666,
                "%s", nvidia_ctl_cdevsw.d_name);
        if (nvidia_ctl_cdev == NULL)
            return ENOMEM;
    }

    nvidia_count++;
    return 0;
}

int nvidia_ctl_detach(void)
{
    struct nvidia_softc *sc;

    sc = &nvidia_ctl_sc;
    nvidia_count--;

    if (nvidia_count == 0)
        destroy_dev(nvidia_ctl_cdev);

    return 0;
}
