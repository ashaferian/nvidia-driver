/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2017 by NVIDIA Corporation.  All rights reserved.  All
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

#if defined(NVCPU_X86) && defined(NV_USE_OS_VM86_INT10CALL)
#include <machine/vm86.h>
#endif

uma_zone_t nvidia_stack_t_zone;
static nvidia_stack_t *__nvidia_init_sp = NULL;

devclass_t nvidia_devclass;
nv_state_t nvidia_ctl_state;

int nvidia_attach(device_t dev)
{
    NV_STATUS status;
    NvU32 i;
    struct nvidia_softc *sc;
    nv_state_t *nv;

    sc = device_get_softc(dev);
    nv = sc->nv_state;

    nv->os_state           = sc;
    nv->flags              = 0;
    nv->pci_info.domain    = pci_get_domain(dev);
    nv->pci_info.bus       = pci_get_bus(dev);
    nv->pci_info.slot      = pci_get_slot(dev);
    nv->pci_info.vendor_id = pci_get_vendor(dev);
    nv->pci_info.device_id = pci_get_device(dev);
    nv->handle             = dev;

    for (i = 0; i < NV_GPU_NUM_BARS; i++) {
        if (sc->BAR_recs[i] != NULL) {
            nv->bars[i].cpu_address = rman_get_start(sc->BAR_recs[i]);
            nv->bars[i].strapped_size = rman_get_size(sc->BAR_recs[i]);
            nv->bars[i].size = nv->bars[i].strapped_size;
        }
    }

    nv->fb   = &nv->bars[NV_GPU_BAR_INDEX_FB];
    nv->regs = &nv->bars[NV_GPU_BAR_INDEX_REGS];

    pci_enable_io(dev, SYS_RES_MEMORY);

    if ((rm_is_supported_device(sc->attach_sp, nv)) != NV_OK)
        return ENXIO;

    for (i = 0; i < NV_GPU_NUM_BARS; i++) {
        if (sc->BAR_recs[i] != NULL) {
            sc->BAR_sg_lists[i] = sglist_alloc(1, M_WAITOK);
            if (!sc->BAR_sg_lists[i])
                goto failed;

            sglist_append_phys(sc->BAR_sg_lists[i],
                    nv->bars[i].cpu_address, nv->bars[i].size);

            sc->BAR_objects[i] = NV_VM_PAGER_ALLOCATE(OBJT_SG,
                    sc->BAR_sg_lists[i],
                    nv->bars[i].size, (VM_PROT_READ | VM_PROT_WRITE),
                    0, NULL);
            if (!sc->BAR_objects[i])
                goto failed;

            VM_OBJECT_WLOCK(sc->BAR_objects[i]);
            switch (i) {
                case NV_GPU_BAR_INDEX_FB:
                    vm_object_set_memattr(sc->BAR_objects[i],
                            VM_MEMATTR_WRITE_COMBINING);
                    break;
                case NV_GPU_BAR_INDEX_REGS:
                default:
                    vm_object_set_memattr(sc->BAR_objects[i],
                            VM_MEMATTR_UNCACHEABLE);
                    break;
            }
            VM_OBJECT_WUNLOCK(sc->BAR_objects[i]);
        }
    }

    sc->dma_mask = 0xffffffffULL;

    if ((status = nvidia_dev_attach(sc)) != 0)
        return status;

    if ((status = nvidia_ctl_attach()) != 0)
        return status;

    nv->interrupt_line = rman_get_start(sc->irq);

    nv_sysctl_init(nv);

    return 0;

failed:
    for (i = 0; i < NV_GPU_NUM_BARS; i++) {
        if (sc->BAR_recs[i] != NULL) {
            if (sc->BAR_objects[i])
                NV_VM_OBJECT_DEALLOCATE(sc->BAR_objects[i]);
            if (sc->BAR_sg_lists[i])
                NV_SGLIST_FREE(sc->BAR_sg_lists[i]);
        }
    }

    return ENOMEM;
}

int nvidia_detach(device_t dev)
{
    int status;
    struct nvidia_softc *sc;
    uint32_t i;

    sc = device_get_softc(dev);
    nv_sysctl_exit(sc->nv_state);

    status = nvidia_dev_detach(sc);
    if (status) {
        device_printf(dev, "NVRM: NVIDIA driver DEV detach failed.\n");
        goto failed;
    }

    status = nvidia_ctl_detach();
    if (status) {
        device_printf(dev, "NVRM: NVIDIA driver CTL detach failed.\n");
        goto failed;
    }

    for (i = 0; i < NV_GPU_NUM_BARS; i++) {
        if (sc->BAR_recs[i] != NULL) {
            if (sc->BAR_objects[i])
                NV_VM_OBJECT_DEALLOCATE(sc->BAR_objects[i]);
            if (sc->BAR_sg_lists[i])
                NV_SGLIST_FREE(sc->BAR_sg_lists[i]);
        }
    }

failed:
    /* XXX Fix me? (state) */
    return status;
}


#ifdef NV_SUPPORT_ACPI_PM
int nvidia_suspend(device_t dev)
{
    nvidia_stack_t *sp;
    struct nvidia_softc *sc;
    nv_state_t *nv;
    int status;

    /* Only if ACPI is running */
    if (devclass_get_softc(devclass_find("acpi"), 0) == NULL)
        return ENODEV;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return ENOMEM;

    sc = device_get_softc(dev);
    nv = sc->nv_state;

    nvidia_modeset_suspend(nv->gpu_id);

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, TRUE);
    status = rm_power_management(sp, nv, 0, NV_PM_ACPI_STANDBY);

    nvidia_pci_save_config_space(sp, dev);

    NV_UMA_ZONE_FREE_STACK(sp);

    return (status == NV_OK) ? 0 : EIO;
}

int nvidia_resume(device_t dev)
{
    nvidia_stack_t *sp;
    struct nvidia_softc *sc;
    nv_state_t *nv;
    int status;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return ENOMEM;

    nvidia_pci_restore_config_space(sp, dev);

    sc = device_get_softc(dev);
    nv = sc->nv_state;

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, TRUE);
    status = rm_power_management(sp, nv, 0, NV_PM_ACPI_RESUME);

    NV_UMA_ZONE_FREE_STACK(sp);

    if (status == NV_OK)
    {
        nvidia_modeset_resume(nv->gpu_id);
    }

    return (status == NV_OK) ? 0 : EIO;
}
#endif /* NV_SUPPORT_ACPI_PM */


int nvidia_alloc_hardware(device_t dev)
{
    int status = 0;
    struct nvidia_softc *sc;
    NvU32 flags, i;
    NvU32 enable_msi = 0;
    int count;
    nvidia_stack_t *sp;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return ENOMEM;

    sc = device_get_softc(dev);
    sc->dev = dev;

    flags = 0; /* not RF_ACTIVE */
    for (i = 0; i < NV_GPU_NUM_BARS && sc->BAR_rids[i] != 0; i++) {
        struct resource *res;
        res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &sc->BAR_rids[i], flags);
        if (res == NULL) {
            /*
             * The most likely reason for this failure is that the SBIOS failed
             * to assign a valid address range to this BAR; FreeBSD is unable to
             * correct the problem and fails this BUS resource allocation. We
             * trust the kernel with BAR validation at this point, but later try
             * to catch cases where the X server "corrects" "invalid" BAR's.
             *
             * Please see to nvidia_pci_check_config_space() in nvidia_pci.c for
             * additional information.
             */
            device_printf(dev,
                "NVRM: NVIDIA MEM resource alloc failed, BAR%d @ 0x%02x.\n",
                i, sc->nv_state->bars[i].offset);
            status = ENXIO;
            goto failed;
        }
        sc->BAR_recs[i] = res;
    }

    if ((rm_read_registry_dword(sp, NULL, "NVreg",
            "EnableMSI", &enable_msi) == NV_OK) && (enable_msi != 0)) {
        count = pci_msi_count(dev);
        if ((count == 1) && (pci_alloc_msi(dev, &count) == 0))
            sc->irq_rid = 1;
    }
    flags = RF_SHAREABLE | RF_ACTIVE;
    sc->irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &sc->irq_rid, flags);
    if (sc->irq == NULL) {
        device_printf(dev, "NVRM: NVIDIA IRQ resource alloc failed.\n");
        status = ENXIO;
        goto failed;
    }

failed:
    NV_UMA_ZONE_FREE_STACK(sp);
    return status;
}

void nvidia_free_hardware(device_t dev)
{
    struct nvidia_softc *sc;
    NvU32 i;

    sc = device_get_softc(dev);

    for (i = 0; i < NV_GPU_NUM_BARS && sc->BAR_recs[i] != NULL; i++)
        bus_release_resource(dev, SYS_RES_MEMORY, sc->BAR_rids[i], sc->BAR_recs[i]);
    if (sc->irq != NULL)
        bus_release_resource(dev, SYS_RES_IRQ, sc->irq_rid, sc->irq);
    if (sc->irq_rid != 0)
        pci_release_msi(dev);
    if (sc->iop != NULL)
        bus_release_resource(dev, SYS_RES_IOPORT, sc->iop_rid, sc->iop);
}

void nvidia_intr(void *xsc)
{
    struct nvidia_softc *sc;
    nv_state_t *nv;
    NvU32 run_bottom_half = 0;
    nvidia_stack_t *sp;
    NvU32 faultsCopied = 0;

    sc = (struct nvidia_softc *) xsc;
    nv = sc->nv_state;

    sp = sc->sp[NV_DEV_STACK_ISR];

    if (sp == NULL)
        return;

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, FALSE);
    rm_isr(sp, nv, &run_bottom_half);

    if (run_bottom_half) {
        /*
         * As UVM with faulting is currently not supported in this plateform, we can copy
         * MMU faults after grabbing RM lock. With UVM, this routine should be called
         * before calling rm_isr and bottom_half should be scheduled unconditionally
         * with low priority thread as bottom_half can wait for lock
         */
        rm_gpu_copy_mmu_faults(sp, nv, &faultsCopied);

        /* We're not executing in an HW ISR context */
        rm_isr_bh(sp, nv);
    }
}

int nvidia_get_card_info(void *args, int size)
{
    struct nv_ioctl_card_info *ci;
    struct nv_ioctl_rm_api_old_version *av;
    unsigned int i;
    struct nvidia_softc *sc;
    nv_state_t *nv;

    if (size < (sizeof(*ci) * NV_MAX_DEVICES))
        return EINVAL;

    av = args;
    switch (av->magic) {
        case NV_RM_API_OLD_VERSION_MAGIC_OVERRIDE_REQ:
        case NV_RM_API_OLD_VERSION_MAGIC_LAX_REQ:
        case NV_RM_API_OLD_VERSION_MAGIC_REQ:
            /*
             * the client is using the old major-minor-patch API
             * version check; reject it.
             */
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: API mismatch: the client has the version %d.%d-%d, but\n"
                      "NVRM: this kernel module has the version %s.  Please\n"
                      "NVRM: make sure that this kernel module and all NVIDIA driver\n"
                      "NVRM: components have the same version.\n",
                      av->major, av->minor, av->patch,
                      NV_VERSION_STRING);
            return EINVAL;
        case NV_RM_API_OLD_VERSION_MAGIC_IGNORE:
            /*
             * the client is telling us to ignore the old version
             * scheme; it will do a version check via
             * NV_ESC_CHECK_VERSION_STR
             */
            break;
        default:
            return EINVAL;
    }

    ci = args;
    memset(ci, 0, size);

    for (i = 0; i < NV_MAX_DEVICES; i++) {
        sc = devclass_get_softc(nvidia_devclass, i);
        if (!sc)
            continue;
        nv = sc->nv_state;

        ci[i].flags              = NV_IOCTL_CARD_INFO_FLAG_PRESENT;
        ci[i].pci_info.domain    = nv->pci_info.domain;
        ci[i].pci_info.bus       = nv->pci_info.bus;
        ci[i].pci_info.slot      = nv->pci_info.slot;
        ci[i].pci_info.vendor_id = nv->pci_info.vendor_id;
        ci[i].pci_info.device_id = nv->pci_info.device_id;
        ci[i].gpu_id             = nv->gpu_id;
        ci[i].interrupt_line     = nv->interrupt_line;
        ci[i].fb_address         = nv->fb->cpu_address;
        ci[i].fb_size            = nv->fb->size;
        ci[i].reg_address        = nv->regs->cpu_address;
        ci[i].reg_size           = nv->regs->size;
        ci[i].minor_number       = i;
    }

    return 0;
}

int nvidia_handle_ioctl(
    nv_state_t *nv,
    struct nvidia_filep *filep,
    u_long cmd,
    caddr_t data
)
{
    struct nvidia_softc *sc;
    nvidia_stack_t *sp;
    void *args;
    nv_ioctl_xfer_t *xfer = NULL;
    int status;
    int nr, size;

    sc = nv->os_state;
    sp = sc->sp[NV_DEV_STACK_API];

    size = __NV_IOC_SIZE(cmd);
    nr = __NV_IOC_NR(cmd);

    args = (void *)data;

    if (nr == NV_ESC_IOCTL_XFER_CMD) {
        if (__NV_IOC_SIZE(cmd) != sizeof(nv_ioctl_xfer_t))
            return EINVAL;

        xfer = args;
        size = xfer->size;

        if (size > NV_ABSOLUTE_MAX_IOCTL_SIZE)
            return EINVAL;

        args = malloc(size, M_NVIDIA, M_WAITOK);
        if (args == NULL)
            return ENOMEM;

        if (copyin(NvP64_VALUE(xfer->ptr), args, size) != 0) {
            free(args, M_NVIDIA);
            return EFAULT;
        }

        nr = xfer->cmd;
    }

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, TRUE);

    switch (nr) {
        case NV_ESC_CHECK_VERSION_STR:
            status = ((rm_perform_version_check(sp,
                            args, size) == NV_OK) ? 0 : EINVAL);
            break;

        case NV_ESC_CARD_INFO:
            status = nvidia_get_card_info(args, size);
            break;

        default:
            status = ((rm_ioctl(sp, nv, filep, nr,
                            args, size) == NV_OK) ? 0 : EINVAL);
            break;
    }

    if (args != (void *)data) {
        if (copyout(args, NvP64_VALUE(xfer->ptr), size) != 0)
            status = EFAULT;
        free(args, M_NVIDIA);
    }

    return status;
}

int nvidia_open_ctl(
    nv_state_t *nv,
    struct nvidia_filep *filep
)
{
    struct nvidia_softc *sc = nv->os_state;

    if (sc->refcnt == 0) {
        NV_UMA_ZONE_ALLOC_STACK(sc->sp[NV_DEV_STACK_API]);
        if (sc->sp[NV_DEV_STACK_API] == NULL)
            return ENOMEM;
        nv->flags |= (NV_FLAG_OPEN | NV_FLAG_CONTROL);
    }

    sc->refcnt++;

    return 0;
}

int nvidia_close_ctl(
    nv_state_t *nv,
    struct nvidia_filep *filep
)
{
    struct nvidia_softc *sc = nv->os_state;
    nvidia_stack_t *sp;

    sp = sc->sp[NV_DEV_STACK_API];
    rm_free_unused_clients(sp, nv, filep);

    if (--sc->refcnt == 0) {
        NV_UMA_ZONE_FREE_STACK(sc->sp[NV_DEV_STACK_API]);
        nv->flags &= ~NV_FLAG_OPEN;
    }

    return 0;
}

static void nv_dev_free_stacks(nvidia_softc_t *sc)
{
    NvU32 i;
    for (i = 0; i < NV_DEV_STACK_COUNT; i++)
    {
        if (sc->sp[i])
            NV_UMA_ZONE_FREE_STACK(sc->sp[i]);
    }
}

static int nv_dev_alloc_stacks(nvidia_softc_t *sc)
{
    NvU32 i;
    for (i = 0; i < NV_DEV_STACK_COUNT; i++)
    {
        NV_UMA_ZONE_ALLOC_STACK(sc->sp[i]);
        if (sc->sp[i] == NULL)
        {
            nv_dev_free_stacks(sc);
            return ENOMEM;
        }
    }
    return 0;
}

static nv_state_t *nvidia_find_state(NvU32 gpu_id)
{
    unsigned int i;
    for (i = 0; i < NV_MAX_DEVICES; i++) {
        nv_state_t *nv;
        struct nvidia_softc *sc = devclass_get_softc(nvidia_devclass, i);
        if (sc == NULL) {
            continue;
        }
        nv = sc->nv_state;

        if (nv->gpu_id == gpu_id) {
            return nv;
        }
    }

    return NULL;
}

int nvidia_open_dev(
    nv_state_t *nv,
    struct nvidia_filep *filep
)
{
    int status = ENOMEM;
    struct nvidia_softc *sc = nv->os_state;
    nvidia_stack_t *sp = NULL;

    if (sc->refcnt == 0) {
        status = nv_dev_alloc_stacks(sc);
        if (status)
            goto failed;
    }

    sp = sc->sp[NV_DEV_STACK_API];
    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, TRUE);

    if (sc->refcnt == 0) {
        if (!rm_init_adapter(sp, nv)) {
            device_printf(sc->dev, "NVRM: rm_init_adapter() failed!\n");
            status = EIO;
            goto failed;
        }

        if (nv->ud.size != 0) {
            sc->UD_sg_list = sglist_alloc(1, M_WAITOK);
            if (!sc->UD_sg_list)
                goto failed;

            sglist_append_phys(sc->UD_sg_list, nv->ud.cpu_address, nv->ud.size);

            sc->UD_object = NV_VM_PAGER_ALLOCATE(OBJT_SG, sc->UD_sg_list,
                    nv->ud.size, (VM_PROT_READ | VM_PROT_WRITE),
                    0, NULL);
            if (!sc->UD_object)
                goto failed;

            VM_OBJECT_WLOCK(sc->UD_object);
            vm_object_set_memattr(sc->UD_object, VM_MEMATTR_UNCACHEABLE);
            VM_OBJECT_WUNLOCK(sc->UD_object);
        }

        nv->flags |= NV_FLAG_OPEN;
    }

    sc->refcnt++;

    return 0;

failed:
    if (sc->refcnt == 0) {
        if (sc->UD_object != NULL)
            NV_VM_OBJECT_DEALLOCATE(sc->UD_object);
        if (sc->UD_sg_list != NULL)
            NV_SGLIST_FREE(sc->UD_sg_list);

        if (status != EIO)
            NV_SHUTDOWN_ADAPTER(sp, nv);

        nv_dev_free_stacks(sc);
    }

    return status;
}

int nvidia_open_dev_kernel(
    NvU32 gpu_id,
    nvidia_stack_t *sp /* unused: nvidia_open_dev() will use its own stack */
)
{
    int status;
    nv_state_t *nv = nvidia_find_state(gpu_id);

    if (nv == NULL) {
        return EINVAL;
    }

    nv_lock_api(nv);
    status = nvidia_open_dev(nv, NULL /* filep */);
    nv_unlock_api(nv);

    return status;
}

int nvidia_close_dev(
    nv_state_t *nv,
    struct nvidia_filep *filep
)
{
    struct nvidia_softc *sc;
    nvidia_stack_t *sp;

    sc = nv->os_state;
    sp = sc->sp[NV_DEV_STACK_API];

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, TRUE);
    if (filep != NULL) {
        rm_free_unused_clients(sp, nv, filep);
    }

    if (--sc->refcnt == 0) {
        if (sc->UD_object != NULL)
            NV_VM_OBJECT_DEALLOCATE(sc->UD_object);
        if (sc->UD_sg_list != NULL)
            NV_SGLIST_FREE(sc->UD_sg_list);

        NV_SHUTDOWN_ADAPTER(sp, nv);

        nv_dev_free_stacks(sc);

        nv->flags &= ~NV_FLAG_OPEN;
    }

    return 0;
}

void nvidia_close_dev_kernel(
    NvU32 gpu_id,
    nvidia_stack_t *sp /* unused: nvidia_close_dev() will use its own stack */
)
{
    nv_state_t *nv = nvidia_find_state(gpu_id);

    if (nv == NULL) {
        return;
    }

    nv_lock_api(nv);
    nvidia_close_dev(nv, NULL /* filep */);
    nv_unlock_api(nv);
}

int nvidia_modevent(
    module_t mod,
    int what,
    void *arg
)
{
    nv_state_t *nv;
    struct nvidia_softc *sc;
    nvidia_stack_t *sp;

    switch (what) {
        case MOD_LOAD:
            /*
             * The module load event. Our KLD has just been loaded and is
             * ready to initialize. We setup the core resource manager in
             * this routine, further initialization takes place at attach
             * time.
             */
            sc = &nvidia_ctl_sc;

            nvidia_stack_t_zone = uma_zcreate("nvidia_stack_t", sizeof(nvidia_stack_t),
                    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);
            if (nvidia_stack_t_zone == NULL)
                return ENOMEM;

            NV_UMA_ZONE_ALLOC_STACK(sp);
            if (sp == NULL) {
                uma_zdestroy(nvidia_stack_t_zone);
                return ENOMEM;
            }

            bzero(sc, sizeof(nvidia_softc_t));

            if (!rm_init_rm(sp)) {
                printf("NVRM: rm_init_rm() failed!\n");
                NV_UMA_ZONE_FREE_STACK(sp);
                uma_zdestroy(nvidia_stack_t_zone);
                return EIO;
            }

            __nvidia_init_sp = sp;

            if (!nvidia_lock_init_locks(sp, &nvidia_ctl_state)) {
                rm_shutdown_rm(sp);
                NV_UMA_ZONE_FREE_STACK(sp);
                uma_zdestroy(nvidia_stack_t_zone);
                return ENOMEM;
            }

            callout_init(&sc->timer, CALLOUT_MPSAFE);
            sx_init(&sc->api_sx, "ctl.api_sx");

            nvidia_ctl_state.os_state = sc;
            sc->nv_state = (void *)&nvidia_ctl_state;

            nvidia_sysctl_init();
            nvidia_linux_init();

            break;

        case MOD_UNLOAD:
            /*
             * Check if the control device is still open and reject the
             * unload request if it is. This event can occur even when the
             * module usage count is non-zero!
             */
            nv = &nvidia_ctl_state;
            sc = nv->os_state;

            nv_lock_api(nv);

            if (sc->refcnt != 0) { /* XXX Fix me? (refcnt) */
                nv_unlock_api(nv);
                return EBUSY;
            }

            nv_unlock_api(nv);
            sx_destroy(&sc->api_sx);

            sp = __nvidia_init_sp;

            nvidia_lock_destroy_locks(sp, nv);

            rm_shutdown_rm(sp);

            NV_UMA_ZONE_FREE_STACK(sp);

            nvidia_sysctl_exit();
            nvidia_linux_exit();

            uma_zdestroy(nvidia_stack_t_zone);

            break;

        default:
            break;
    }

    return 0;
}

void nv_lock_api(nv_state_t *nv)
{
    struct nvidia_softc *sc = nv->os_state;
    sx_xlock(&sc->api_sx);
}

void nv_unlock_api(nv_state_t *nv)
{
    struct nvidia_softc *sc = nv->os_state;
    sx_xunlock(&sc->api_sx);
}

NV_STATUS NV_API_CALL nv_export_rm_object_to_fd(
    NvHandle  hExportedRmObject,
    NvS32     fd
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_import_rm_object_from_fd(
    NvS32     fd,
    NvHandle *pExportedObject
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_post_event(
    nv_state_t *nv,
    nv_event_t *event,
    NvHandle    hObject,
    NvU32       index,
    NvBool      data_valid
)
{
    struct nvidia_filep *filep = event->file;
    struct nvidia_event *et;

    mtx_lock(&filep->event_mtx);

    if (data_valid) {
        et = malloc(sizeof(nvidia_event_t), M_NVIDIA, M_NOWAIT);
        if (et == NULL) {
            mtx_unlock(&filep->event_mtx);
            return;
        }

        et->event = *event;
        et->event.hObject = hObject;
        et->event.index = index;

        STAILQ_INSERT_TAIL(&filep->event_queue, et, queue);
    }

    filep->event_pending = TRUE;
    mtx_unlock(&filep->event_mtx);

    selwakeup(&filep->event_rsel);
}

NvS32 NV_API_CALL nv_get_event(
    nv_state_t *nv,
    void *file,
    nv_event_t *event,
    NvU32 *pending
)
{
    struct nvidia_filep *filep = file;
    struct nvidia_event *et;

    mtx_lock(&filep->event_mtx);

    et = STAILQ_FIRST(&filep->event_queue);
    if (et == NULL) {
        mtx_unlock(&filep->event_mtx);
        return NV_ERR_GENERIC;
    }

    *event = et->event;

    STAILQ_REMOVE(&filep->event_queue, et, nvidia_event, queue);

    *pending = !STAILQ_EMPTY(&filep->event_queue);

    mtx_unlock(&filep->event_mtx);

    free(et, M_NVIDIA);

    return NV_OK;
}

void* NV_API_CALL nv_alloc_kernel_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       pageIndex,
    NvU32       pageOffset,
    NvU64       size,
    void      **ppPrivate
)
{
    struct nvidia_alloc *at = pAllocPrivate;
    vm_offset_t virtual_address;
    int status;

    if (at->alloc_type_contiguous) {
        *ppPrivate = NULL;
        return (void *)(NvUPtr)(at->pte_array[0].virtual_address +
                (pageIndex * PAGE_SIZE) + pageOffset);
    }

    size = (size + PAGE_MASK) & ~PAGE_MASK;

    vm_object_reference(at->object);
    virtual_address = vm_map_min(kernel_map);

    status = vm_map_find(kernel_map, at->object, (pageIndex * PAGE_SIZE),
            &virtual_address, size, 0, VMFS_ANY_SPACE,
            (VM_PROT_READ | VM_PROT_WRITE),
            (VM_PROT_READ | VM_PROT_WRITE), 0);
    if (status != KERN_SUCCESS) {
        NV_VM_OBJECT_DEALLOCATE(at->object);
        return NULL;
    }

    status = vm_map_wire(kernel_map, virtual_address,
            (virtual_address + size),
            (VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES));
    if (status != KERN_SUCCESS) {
        vm_map_remove(kernel_map, virtual_address,
            (virtual_address + size));
        return NULL;
    }

    *ppPrivate = (void *)(NvUPtr)size;

    return (void *)(virtual_address + pageOffset);
}

NV_STATUS NV_API_CALL nv_free_kernel_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    void       *address,
    void       *pPrivate
)
{
    vm_offset_t virtual_address;
    uint32_t size;

    if (pPrivate != NULL) {
        virtual_address = (vm_offset_t)address & ~PAGE_MASK;
        size = (NvUPtr)pPrivate;
        vm_map_remove(kernel_map, virtual_address,
            (virtual_address + size));
    }

    return NV_OK;
}

static nvidia_filep_t* nv_get_file_private(NvU32 fd, nv_state_t *nv)
{
    struct file *pFile = NULL;
    NV_STATUS status = EINVAL;
    nvidia_filep_t *nvfp = NULL;
    struct cdev_privdata *p;

#if __FreeBSD_version >= 1000053
    cap_rights_t rights;
#endif
    struct thread *td;

    td = curthread;

    status = fget(td, fd, cap_rights_init(&rights, CAP_READ), &pFile);
    if (status != 0)
        return NULL;

    p = pFile->f_cdevpriv;
    if(!p)
        goto done;

    if (NV_IS_CTL_DEVICE(nv))
    {
        if (p->cdpd_dtr != nvidia_ctl_dtor)
            goto done;
    }
    else
    {
        if (p->cdpd_dtr != nvidia_dev_dtor)
            goto done;
    }

    nvfp = (nvidia_filep_t*)p->cdpd_data;

done:
    /*
     * If we reach here, pFile is a valid struct file pointer, returned
     * by fget(9).
     *
     * fget(9) incremented the struct file's reference count, which
     * needs to be balanced with a call to fdrop(9).  It is safe to
     * decrement the reference count before returning filp->private_data
     * because we are holding the GPUs lock which prevents freeing the file out.
     */
    fdrop(pFile, td);

    return nvfp;
}

NV_STATUS NV_API_CALL nv_add_mapping_context_to_file(
    nv_state_t *nv,
    nv_usermap_access_params_t* nvuap,
    NvU32 prot,
    void *pAllocPriv,
    NvU64 pageIndex,
    NvU32 fd
)
{
    nv_alloc_mapping_context_t *nvamc = NULL;
    nvidia_filep_t *nvfp = NULL;

    /* Get the nvidia private file data from file descriptor */
    nvfp = nv_get_file_private(fd, nv);
    if (nvfp == NULL)
        return NV_ERR_INVALID_ARGUMENT;

    nvamc = &nvfp->mmap_context;

    if (nvamc->valid)
        return NV_ERR_STATE_IN_USE;

    if (NV_IS_CTL_DEVICE(nv))
    {
        nvamc->alloc = pAllocPriv;
        nvamc->page_index = pageIndex;
    }
    else
    {
        nvamc->mmap_start = nvuap->mmap_start;
        nvamc->mmap_size = nvuap->mmap_size;
        nvamc->access_start = nvuap->access_start;
        nvamc->access_size = nvuap->access_size;
        nvamc->remap_prot_extra = nvuap->remap_prot_extra;
    }

    nvamc->prot = prot;
    nvamc->valid = NV_TRUE;

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_alloc_user_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       pageIndex,
    NvU32       pageOffset,
    NvU64       size,
    NvU32       protect,
    NvU64      *pUserAddress,
    void      **ppPrivate
)
{
    struct nvidia_alloc *at = pAllocPrivate;

    if (at->alloc_type_contiguous)
        *pUserAddress = (at->pte_array[0].physical_address + (pageIndex * PAGE_SIZE) + pageOffset);
    else
        *pUserAddress = (at->pte_array[pageIndex].physical_address + pageOffset);

    return NV_OK;
}

NV_STATUS NV_API_CALL nv_free_user_mapping(
    nv_state_t *nv,
    void       *pAllocPrivate,
    NvU64       userAddress,
    void       *pPrivate
)
{
    return NV_OK;
}

NvS32 nv_alloc_contig_pages(
    nv_state_t *nv,
    NvU32       count,
    NvU32       cache_type,
    NvBool      zero,
    NvU64      *pte_array,
    void      **private
)
{
    struct nvidia_alloc *at;
    struct nvidia_softc *sc = nv->os_state;
    vm_memattr_t attr;
    vm_offset_t address;
    NvU32 size = (count * PAGE_SIZE);
    int flags = (zero ? M_ZERO : 0);
    int status;

    switch (cache_type) {
        case NV_MEMORY_UNCACHED:
            attr = VM_MEMATTR_UNCACHEABLE;
            break;
        case NV_MEMORY_DEFAULT:
        case NV_MEMORY_CACHED:
            attr = VM_MEMATTR_WRITE_BACK;
            break;
        case NV_MEMORY_UNCACHED_WEAK:
            attr = VM_MEMATTR_WEAK_UNCACHEABLE;
            break;
        case NV_MEMORY_WRITECOMBINED:
            attr = VM_MEMATTR_WRITE_COMBINING;
            break;
        default:
            nv_printf(NV_DBG_ERRORS,
                  "NVRM: unknown mode in nv_alloc_contig_pages()\n");
            return EINVAL;
    }

    at = malloc(sizeof(nvidia_alloc_t), M_NVIDIA, (M_WAITOK | M_ZERO));
    if (!at)
        return ENOMEM;

    at->size = size;
    at->alloc_type_contiguous = 1;
    at->attr = attr;

    at->pte_array = malloc(sizeof(nvidia_pte_t), M_NVIDIA,
            (M_WAITOK | M_ZERO));
    if (!at->pte_array) {
        free(at, M_NVIDIA);
        return ENOMEM;
    }

    address = NV_KMEM_ALLOC_CONTIG(size, flags, 0,
            sc->dma_mask, PAGE_SIZE, 0, attr);
    if (!address) {
        status = ENOMEM;
        goto failed;
    }
    malloc_type_allocated(M_NVIDIA, size);

    if (attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    at->pte_array[0].virtual_address = address;
    at->pte_array[0].physical_address = (NvU64)vtophys(address);

    at->sg_list = sglist_alloc(1, M_WAITOK);
    if (!at->sg_list) {
        status = ENOMEM;
        goto failed;
    }

    pte_array[0] = at->pte_array[0].physical_address;
    sglist_append_phys(at->sg_list, pte_array[0], size);

    at->object = NV_VM_PAGER_ALLOCATE(OBJT_SG, at->sg_list, size,
            (VM_PROT_READ | VM_PROT_WRITE), 0, NULL);
    if (!at->object) {
        status = ENOMEM;
        goto failed;
    }

    VM_OBJECT_WLOCK(at->object);
    vm_object_set_memattr(at->object, attr);
    VM_OBJECT_WUNLOCK(at->object);

    *private = at;
    SLIST_INSERT_HEAD(&sc->alloc_list, at, list);

    return 0;

failed:
    if (at->object)
        NV_VM_OBJECT_DEALLOCATE(at->object);
    if (at->sg_list)
        NV_SGLIST_FREE(at->sg_list);

    if (attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    if (at->pte_array[0].virtual_address != NULL) {
        NV_KMEM_FREE(at->pte_array[0].virtual_address, at->size);
        malloc_type_freed(M_NVIDIA, at->size);
    }

    free(at->pte_array, M_NVIDIA);
    free(at, M_NVIDIA);

    return status;
}

NvS32 nv_free_contig_pages(
    nv_state_t *nv,
    void *private
)
{
    struct nvidia_alloc *at = private;
    struct nvidia_softc *sc = nv->os_state;

    SLIST_REMOVE(&sc->alloc_list, at, nvidia_alloc, list);

    NV_VM_OBJECT_DEALLOCATE(at->object);
    NV_SGLIST_FREE(at->sg_list);

    if (at->attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    NV_KMEM_FREE(at->pte_array[0].virtual_address, at->size);
    malloc_type_freed(M_NVIDIA, at->size);

    free(at->pte_array, M_NVIDIA);
    free(at, M_NVIDIA);

    return 0;
}

NvS32 nv_alloc_system_pages(
    nv_state_t  *nv,
    NvU32        count,
    NvU32        cache_type,
    NvBool       zero,
    NvU64       *pte_array,
    void       **private
)
{
    struct nvidia_alloc *at;
    struct nvidia_softc *sc = nv->os_state;
    vm_offset_t address;
    uint32_t i;
    vm_memattr_t attr;
    uint32_t size = (count * PAGE_SIZE);
    int flags = (zero ? M_ZERO : 0);
    int status;

    switch (cache_type) {
        case NV_MEMORY_UNCACHED:
            attr = VM_MEMATTR_UNCACHEABLE;
            break;
        case NV_MEMORY_DEFAULT:
        case NV_MEMORY_CACHED:
            attr = VM_MEMATTR_WRITE_BACK;
            break;
        case NV_MEMORY_UNCACHED_WEAK:
            attr = VM_MEMATTR_WEAK_UNCACHEABLE;
            break;
        case NV_MEMORY_WRITECOMBINED:
            attr = VM_MEMATTR_WRITE_COMBINING;
            break;
        default:
            nv_printf(NV_DBG_ERRORS,
                  "NVRM: unknown mode in nv_alloc_system_pages()\n");
            return EINVAL;
    }

    at = malloc(sizeof(nvidia_alloc_t), M_NVIDIA, (M_WAITOK | M_ZERO));
    if (!at)
        return ENOMEM;

    at->size = size;
    at->alloc_type_contiguous = 0;
    at->attr = attr;

    at->pte_array = malloc((sizeof(nvidia_pte_t) * count),
            M_NVIDIA, (M_WAITOK | M_ZERO));
    if (!at->pte_array) {
        free(at, M_NVIDIA);
        return ENOMEM;
    }

    for (i = 0; i < count; i++) {
        address = NV_KMEM_ALLOC_CONTIG(PAGE_SIZE, flags, 0,
                sc->dma_mask, PAGE_SIZE, 0, attr);
        if (!address) {
            status = ENOMEM;
            goto failed;
        }
        malloc_type_allocated(M_NVIDIA, PAGE_SIZE);

        at->pte_array[i].virtual_address = address;
        at->pte_array[i].physical_address = (NvU64)vtophys(address);
    }

    if (attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    at->sg_list = sglist_alloc(count, M_WAITOK);
    if (!at->sg_list) {
        status = ENOMEM;
        goto failed;
    }

    for (i = 0; i < count; i++) {
        pte_array[i] = at->pte_array[i].physical_address;
        sglist_append_phys(at->sg_list, pte_array[i], PAGE_SIZE);
    }

    at->object = NV_VM_PAGER_ALLOCATE(OBJT_SG, at->sg_list, size,
            (VM_PROT_READ | VM_PROT_WRITE), 0, NULL);
    if (!at->object) {
        status = ENOMEM;
        goto failed;
    }

    VM_OBJECT_WLOCK(at->object);
    vm_object_set_memattr(at->object, attr);
    VM_OBJECT_WUNLOCK(at->object);

    *private = at;
    SLIST_INSERT_HEAD(&sc->alloc_list, at, list);

    return 0;

failed:
    if (at->object)
        NV_VM_OBJECT_DEALLOCATE(at->object);
    if (at->sg_list)
        NV_SGLIST_FREE(at->sg_list);

    if (attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    for (i = 0; i < count; i++) {
        if (at->pte_array[i].virtual_address == 0)
            break;
        NV_KMEM_FREE(at->pte_array[i].virtual_address, PAGE_SIZE);
        malloc_type_freed(M_NVIDIA, PAGE_SIZE);
    }

    free(at->pte_array, M_NVIDIA);
    free(at, M_NVIDIA);

    return status;
}

NvS32 nv_free_system_pages(
    nv_state_t *nv,
    void *private
)
{
    struct nvidia_alloc *at = private;
    struct nvidia_softc *sc = nv->os_state;
    uint32_t i, count;

    count = at->size / PAGE_SIZE;
    SLIST_REMOVE(&sc->alloc_list, at, nvidia_alloc, list);

    NV_VM_OBJECT_DEALLOCATE(at->object);
    NV_SGLIST_FREE(at->sg_list);

    if (at->attr != VM_MEMATTR_WRITE_BACK)
        os_flush_cpu_cache();

    for (i = 0; i < count; i++) {
        NV_KMEM_FREE(at->pte_array[i].virtual_address, PAGE_SIZE);
        malloc_type_freed(M_NVIDIA, PAGE_SIZE);
    }

    free(at->pte_array, M_NVIDIA);
    free(at, M_NVIDIA);

    return 0;
}

NV_STATUS NV_API_CALL nv_alias_pages(
    nv_state_t *nv,
    NvU32       count,
    NvU32       alloc_type_contiguous,
    NvU32       cache_type,
    NvU64       guest_id,
    NvU64      *pte_array,
    void      **priv_data
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_alloc_pages(
    nv_state_t *nv,
    NvU32       count,
    NvBool      alloc_type_contiguous,
    NvU32       cache_type,
    NvBool      alloc_type_zeroed,
    NvU64      *pte_array,
    void      **private
)
{
    NV_STATUS status = NV_OK;
    NvBool zero = alloc_type_zeroed;

    if (!alloc_type_contiguous) {
        if (nv_alloc_system_pages(nv, count, cache_type, zero,
                    pte_array, private)) {
            status = NV_ERR_NO_MEMORY;
        }
    } else {
        if (nv_alloc_contig_pages(nv, count, cache_type, zero,
                    pte_array, private)) {
            status = NV_ERR_NO_MEMORY;
        }
    }

    return status;
}

NV_STATUS NV_API_CALL nv_free_pages(
    nv_state_t *nv,
    NvU32 count,
    NvBool alloc_type_contiguous,
    NvU32 cache_type,
    void *private
)
{
    NV_STATUS status = NV_OK;

    if (!alloc_type_contiguous) {
        if (nv_free_system_pages(nv, private))
            status = NV_ERR_GENERIC;
    } else  {
        if (nv_free_contig_pages(nv, private))
            status = NV_ERR_GENERIC;
    }

    return status;
}

NvU64 NV_API_CALL nv_get_kern_phys_address(NvU64 address)
{
    vm_offset_t va = (vm_offset_t)address;

#if defined(NVCPU_X86_64)
    if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS)
        return DMAP_TO_PHYS(va);
#endif

    if (va < VM_MIN_KERNEL_ADDRESS) {
        os_dbg_breakpoint();
        return 0;
    }

    return vtophys(va);
}

NvU64 NV_API_CALL nv_get_user_phys_address(NvU64 address)
{
    struct vmspace *vm;
    vm_offset_t va = (vm_offset_t)address;

    if (va >= VM_MIN_KERNEL_ADDRESS) {
        os_dbg_breakpoint();
        return 0;
    }

    vm = curproc->p_vmspace;
    return pmap_extract(vmspace_pmap(vm), va);
}

int nvidia_mmap_ctl_single(
    nv_state_t *nv,
    struct nvidia_filep *filep,
    vm_ooffset_t *offset,
    vm_size_t size,
    vm_object_t *object
)
{
    struct nvidia_alloc *at;
    nvidia_stack_t *sp;
    NV_STATUS rmStatus;
    struct nvidia_softc *sc = nv->os_state;
    NvU64 pageIndex;
    NvU32 prot;
    nv_alloc_mapping_context_t *mmap_context;

    sp = sc->sp[NV_DEV_STACK_API];

    rmStatus = rm_acquire_api_lock(sp);
    if (rmStatus != NV_OK)
        return EAGAIN;

    mmap_context = &filep->mmap_context;

    /*
     * If no mmap context exists on this file descriptor, this mapping wasn't
     * previously validated with the RM so it must be rejected.
     */
    if (!mmap_context->valid)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: VM: invalid mmap\n");
        rm_release_api_lock(sp);
        return -EINVAL;
    }

    at = (struct nvidia_alloc *)mmap_context->alloc;
    pageIndex = mmap_context->page_index;
    prot = mmap_context->prot;

    vm_object_reference(at->object);
    *object = at->object;
    *offset = (pageIndex * PAGE_SIZE);

    rm_release_api_lock(sp);

    return 0;
}

int nvidia_mmap_dev_single(
    nv_state_t *nv,
    struct nvidia_filep *filep,
    vm_ooffset_t *offset,
    vm_size_t size,
    vm_object_t *object
)
{
    struct nvidia_softc *sc = nv->os_state;
    nv_alloc_mapping_context_t *mmap_context = &filep->mmap_context;

    /*
     * If no mmap context is valid on this file descriptor then this mapping
     * wasn't previously validated with the RM so it must be rejected.
     */
    if (!mmap_context->valid)
    {
        nv_printf(NV_DBG_ERRORS, "NVRM: VM: invalid mmap\n");
        return -EINVAL;
    }

    *offset = mmap_context->mmap_start;
    size = mmap_context->mmap_size;

    if (IS_UD_OFFSET(nv, *offset, size)) {
        *object = sc->UD_object;
        vm_object_reference(*object);
        *offset = (*offset - nv->ud.cpu_address);
        return 0;
    } else if (IS_FB_OFFSET(nv, *offset, size)) {
        *object = sc->BAR_objects[NV_GPU_BAR_INDEX_FB];
        vm_object_reference(*object);
        *offset = (*offset - nv->fb->cpu_address);
        return 0;
    } else if (IS_REG_OFFSET(nv, *offset, size)) {
        *object = sc->BAR_objects[NV_GPU_BAR_INDEX_REGS];
        vm_object_reference(*object);
        *offset = (*offset - nv->regs->cpu_address);
        return 0;
    }

    return EINVAL;
}

void nvidia_rc_timer(void *data)
{
    nv_state_t *nv = data;
    struct nvidia_softc *sc = nv->os_state;
    nvidia_stack_t *sp;

    sp = sc->sp[NV_DEV_STACK_TIMER];

    NV_PCI_CHECK_CONFIG_SPACE(sp, nv, TRUE, TRUE, FALSE);

    if (rm_run_rc_callback(sp, nv) == NV_OK)
        callout_reset(&sc->timer, hz, nvidia_rc_timer, (void *)nv);
}

int NV_API_CALL nv_start_rc_timer(
    nv_state_t *nv
)
{
    struct nvidia_softc *sc = nv->os_state;

    if (nv->rc_timer_enabled != 0)
        return EBUSY;

    callout_reset(&sc->timer, hz, nvidia_rc_timer, (void *)nv);
    nv->rc_timer_enabled = 1;

    return 0;
}

int NV_API_CALL nv_stop_rc_timer(
    nv_state_t *nv
)
{
    struct nvidia_softc *sc = nv->os_state;

    if (nv->rc_timer_enabled == 0)
        return EIO;

    callout_drain(&sc->timer);
    nv->rc_timer_enabled = 0;

    return 0;
}

void NV_API_CALL nv_set_dma_address_size(
    nv_state_t *nv,
    NvU32 phys_addr_bits
)
{
    struct nvidia_softc *sc = nv->os_state;
#if defined(NVCPU_X86_64)
    sc->dma_mask = (((uint64_t)1) << phys_addr_bits) - 1;
#else
    sc->dma_mask = 0xffffffffULL;
#endif
}

nv_state_t* NV_API_CALL nv_get_adapter_state(
    NvU32 domain,
    NvU8  bus,
    NvU8  slot
)
{
    unsigned int i;
    struct nvidia_softc *sc;
    nv_state_t *nv;

    for (i = 0; i < NV_MAX_DEVICES; i++) {
        sc = devclass_get_softc(nvidia_devclass, i);
        if (!sc)
            continue;
        nv = sc->nv_state;

        if ((nv->pci_info.domain == domain) &&
            (nv->pci_info.bus == bus) && (nv->pci_info.slot == slot)) {
            return nv;
        }
    }

    return NULL;
}

nv_state_t* NV_API_CALL nv_get_ctl_state(void)
{
    return &nvidia_ctl_state;
}

void NV_API_CALL nv_verify_pci_config(
    nv_state_t *nv,
    BOOL check_the_bars
)
{
    struct nvidia_softc *sc = nv->os_state;
    device_t dev = sc->dev;
    nvidia_stack_t *sp = sc->sp[NV_DEV_STACK_PCI_CFGCHK];

    nvidia_pci_check_config_space(sp, dev, check_the_bars, FALSE, FALSE);
}

NV_STATUS NV_API_CALL nv_dma_map_pages(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *pte_array,
    NvBool      contig,
    void      **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_unmap_pages(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *pte_array,
    void      **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_map_alloc(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *va_array,
    NvBool      contig,
    void      **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_unmap_alloc(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *va_array,
    void      **priv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_dma_map_peer(
    nv_state_t *nv,
    nv_state_t *peer,
    NvU8        bar_index,
    NvU64       page_count,
    NvU64      *va
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_dma_unmap_peer(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64       va
)
{
}

NV_STATUS NV_API_CALL nv_dma_map_mmio(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *va
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_dma_unmap_mmio(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64       va
)
{
}

NV_STATUS NV_API_CALL nv_log_error(
    nv_state_t *nv,
    NvU32       error_number,
    const char *format,
    va_list    ap
)
{
    return NV_OK;
}

NvU64 NV_API_CALL nv_get_dma_start_address(
    nv_state_t *nv
)
{
    return 0;
}

NV_STATUS NV_API_CALL nv_set_primary_vga_status(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_pci_trigger_recovery(
    nv_state_t *nv
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL nv_requires_dma_remap(
    nv_state_t *nv
)
{
    return NV_FALSE;
}

NV_STATUS NV_API_CALL nv_register_user_pages(
    nv_state_t *nv,
    NvU64       page_count,
    NvU64      *phys_addr,
    void      **priv
)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL nv_unregister_user_pages(
    nv_state_t *nv,
    NvU64       page_count,
    void      **priv
)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL nv_get_device_memory_config(
    nv_state_t *nv,
    NvU32 *pAddrSysPhys,
    NvU32 *pAddrGuestPhys,
    NvU32 *pAddrWidth,
    NvU32 *pGranularity,
    NvS32 *pNodeId
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_usermap_access_params(
    nv_state_t *nv,
    nv_usermap_access_params_t *nvuap
)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL nv_register_peer_io_mem(
    nv_state_t *nv,
    NvU64      *phys_addr,
    NvU64       page_count,
    void      **priv_data
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_peer_io_mem(
    nv_state_t *nv,
    void       *priv_data
)
{
}

NV_STATUS NV_API_CALL nv_register_phys_pages(
    nv_state_t *nv,
    NvU64      *phys_addr,
    NvU64       page_count,
    void      **priv_data
)
{
    return NV_OK;
}

void NV_API_CALL nv_unregister_phys_pages(
    nv_state_t *nv,
    void       *priv_data
)
{
}

NV_STATUS NV_API_CALL nv_get_ibmnpu_genreg_info(
    nv_state_t *nv,
    NvU64      *addr,
    NvU64      *size,
    void      **device
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL nv_get_ibmnpu_relaxed_ordering_mode(
    nv_state_t *nv,
    NvBool *mode
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL nv_register_backlight(
    nv_state_t *nv,
    NvU32 displayId,
    NvU32 currentBrightness
)
{
    /* not implemented */
}

void NV_API_CALL nv_unregister_backlight(
    nv_state_t *nv
)
{
    /* not implemented */
}

void NV_API_CALL nv_wait_for_ibmnpu_rsync(nv_state_t *nv)
{
}
