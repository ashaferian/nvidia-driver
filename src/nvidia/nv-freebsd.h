/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2013 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#ifndef __NV_FREEBSD_H__
#define __NV_FREEBSD_H__

#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#include <sys/param.h>

#if __FreeBSD_version >= 1300000
//#error This driver does not support FreeBSD 13.x/-CURRENT!
#endif
#if __FreeBSD_version >= 1200000 && __FreeBSD_version < 1200086
#error This driver requires FreeBSD 12.0-RC3 or later!
#endif
#if __FreeBSD_version >= 1100000 && __FreeBSD_version < 1100122
#error This driver requires FreeBSD 11.0 or later!
#endif
#if __FreeBSD_version >= 1000000 && __FreeBSD_version < 1000510
#error This driver requires FreeBSD 10.0 or later!
#endif
#if __FreeBSD_version >= 900000 && __FreeBSD_version < 900044
#error This driver requires FreeBSD 9.0 or later!
#endif
#if __FreeBSD_version >= 800000 && __FreeBSD_version < 800107
#error This driver requires FreeBSD 8.0 or later!
#endif
#if __FreeBSD_version < 702106
#error This driver requires FreeBSD 7.3 or later!
#endif

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/pciio.h>
#include <sys/vnode.h>

#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/sysent.h>
#include <sys/ctype.h>
#include <sys/sysctl.h>

#include <machine/cpu.h>
#include <machine/resource.h>
#include <machine/clock.h>
#include <machine/bus.h>
#include <machine/specialreg.h>

#include <sys/conf.h>
#include <sys/rman.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/poll.h>
#include <sys/rwlock.h>

#include <sys/syscall.h>
#include <sys/bus.h>
#include <sys/memrange.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>
#include <vm/uma.h>

#include <sys/smp.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <sys/kdb.h>
#include <sys/filedesc.h>

#include <sys/priv.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/condvar.h>
#include <sys/sglist.h>
#include <sys/taskqueue.h>

#include <fs/devfs/devfs_int.h>

#define CURTHREAD curthread

#if __FreeBSD_version >= 800049
#define suser(_td) priv_check((_td), PRIV_DRIVER)
#endif

#if __FreeBSD_version >= 1100012
#include <sys/capsicum.h>
#elif __FreeBSD_version >= 900041
#include <sys/capability.h>
#if __FreeBSD_version < 1000053
#define cap_rights_init(rights, cap) (cap)
#endif
#else
#define fget(td, fd, rights, fp) fget(td, fd, fp)
#endif

#define __NV_ITHREAD() (curthread->td_pflags & TDP_ITHREAD)

/*
 * The NVIDIA kernel module's malloc identifier, needed for both tracking
 * and actual allocation/freeing purposes - declared here, but defined in
 * nvidia_os.c.
 */

MALLOC_DECLARE(M_NVIDIA);

/*
 * This option decides if the driver will be built with support for Linux
 * or Linux 32-bit (FreeBSD/amd64) compatibility. This makes nvidia.ko
 * dependent on linux.ko; if you don't need Linux compatibility, then you
 * can safely unset this flag.
 */

#define NV_SUPPORT_LINUX_COMPAT

/*
 * Enable/Disable support for ACPI method (_DOD, _ROM, etc.) invocation
 * from the core driver.
 */

#if __FreeBSD_version >= 900044
#define NV_SUPPORT_ACPI
#else
#undef NV_SUPPORT_ACPI
#endif

/*
 * Enable/Disable support for ACPI Power Management.
 */

#define NV_SUPPORT_ACPI_PM

/*
 * Enable/Disable heavy-weight cache-flush logic. By default, the driver
 * relies on the kernel to perform cache flushes using optimized
 * routines.
 */

#undef NV_USE_WBINVD

typedef
struct nvidia_pte {
    vm_offset_t virtual_address;
    uint64_t physical_address;
} nvidia_pte_t;

typedef
struct nvidia_alloc {
    vm_memattr_t attr;
    uint32_t size;
    int alloc_type_contiguous;
    struct nvidia_pte *pte_array;
    struct sglist *sg_list;
    vm_object_t object;
} nvidia_alloc_t;

typedef
struct nvidia_event {
    STAILQ_ENTRY(nvidia_event) queue;
    nv_event_t event;
} nvidia_event_t;

typedef
struct nvidia_filep {
    nv_state_t *nv;
    STAILQ_HEAD(event_queue, nvidia_event) event_queue;
    int event_pending;
    struct mtx event_mtx;
    struct selinfo event_rsel;
    nv_alloc_mapping_context_t mmap_context;
} nvidia_filep_t;

typedef
struct nvidia_work {
    struct task task;
    void *data;
} nvidia_work_t;

typedef
enum nvidia_softc_dev_stack {
    NV_DEV_STACK_API,
    NV_DEV_STACK_ISR,
    NV_DEV_STACK_TIMER,
    NV_DEV_STACK_COUNT
} nvidia_softc_dev_stack_t;

typedef
struct nvidia_softc {
    device_t dev;

    struct sglist *UD_sg_list;
    vm_object_t UD_object;

    struct resource *BAR_recs[NV_GPU_NUM_BARS];
    int BAR_rids[NV_GPU_NUM_BARS];
    struct sglist *BAR_sg_lists[NV_GPU_NUM_BARS];
    vm_object_t BAR_objects[NV_GPU_NUM_BARS];

    struct resource *irq;
    void *irq_ih;
    int   irq_rid;

    /* attach_sp is created on PCI attach */
    nvidia_stack_t *attach_sp;

    /* These stacks are all created on first device file open */
    nvidia_stack_t *sp[NV_DEV_STACK_COUNT];

    struct resource *iop;
    int iop_rid;

    bus_space_handle_t bs_handle;
    bus_space_tag_t bs_tag;

    struct cdev *cdev;
    nv_state_t *nv_state;

    struct sysctl_ctx_list sysctl_ctx;

    struct callout timer;

    uint64_t dma_mask;

    uint32_t refcnt;

    struct sx api_sx;

} nvidia_softc_t;

#define CDEV_CTL_MINOR  255

extern devclass_t nvidia_devclass;

extern struct nvidia_softc nvidia_ctl_sc;
extern nv_state_t nvidia_ctl_state;

#define PCIR_CAP_LIST_ID   0x00
#define PCIR_CAP_LIST_NEXT 0x01
#define PCIR_CAP_ID_AGP    0x02
#define PCIR_CAP_ID_EXP    0x10

#if !defined(PCIS_DISPLAY_3D)
#define PCIS_DISPLAY_3D    0x002
#endif
#if !defined(PCIM_CMD_INTXDIS)
#define PCIM_CMD_INTXDIS   0x400
#endif

#if !defined(VM_MEMATTR_WEAK_UNCACHEABLE)
#define VM_MEMATTR_WEAK_UNCACHEABLE VM_MEMATTR_UNCACHED
#endif

#if !defined(PAT_UNCACHEABLE)
#define PAT_UNCACHEABLE         0x00
#endif
#if !defined(PAT_WRITE_COMBINING)
#define PAT_WRITE_COMBINING     0x01
#endif
#if !defined(PAT_WRITE_BACK)
#define PAT_WRITE_BACK          0x06
#endif

/*
 * These macros extract the encoded ioctl type and number from the
 * command; we inspect the type to verify that device/control ioctls
 * originate from NVIDIA RM clients and use the number to allow the
 * core resource manager's ioctl handler to be ignorant of operating
 * specific ioctl encodings.
 */

#define __NV_IOC_TYPE(_cmd) (((_cmd) >> 8) & 0xff)
#define __NV_IOC_NR(_cmd)   (((_cmd) >> 0) & 0xff)
#define __NV_IOC_SIZE(_cmd) (((_cmd) >> 16) & 0x1fff)

extern uma_zone_t nvidia_stack_t_zone;

#define NV_UMA_ZONE_ALLOC_STACK(ptr)                             \
    {                                                            \
        (ptr) = uma_zalloc(nvidia_stack_t_zone, M_WAITOK);       \
        if ((ptr) != NULL)                                       \
        {                                                        \
            (ptr)->size = sizeof((ptr)->stack);                  \
            (ptr)->top = (ptr)->stack + (ptr)->size;             \
        }                                                        \
    }

#define NV_UMA_ZONE_FREE_STACK(ptr)                              \
    {                                                            \
        uma_zfree(nvidia_stack_t_zone, (ptr));                   \
        (ptr) = NULL;                                            \
    }

/* nvidia_dev.c */
int    nvidia_dev_attach     (struct nvidia_softc *);
int    nvidia_dev_detach     (struct nvidia_softc *);

/* nvidia_ctl.c */
int    nvidia_ctl_attach     (void);
int    nvidia_ctl_detach     (void);

/* nvidia_pci.c */
void   nvidia_pci_save_config_space   (nvidia_stack_t *, device_t dev);
void   nvidia_pci_restore_config_space(nvidia_stack_t *, device_t dev);
int    nvidia_pci_setup_intr          (device_t dev);
int    nvidia_pci_teardown_intr       (device_t dev);
NvU8   nvidia_pci_find_capability     (device_t dev, NvU8);

#define NV_SHUTDOWN_ADAPTER(sp,nv)                                      \
    {                                                                   \
        rm_disable_adapter(sp, nv);                                     \
        rm_shutdown_adapter(sp, nv);                                    \
    }

/* nvidia_subr.c */
int    nvidia_attach         (device_t);
int    nvidia_detach         (device_t);
int    nvidia_suspend        (device_t);
int    nvidia_resume         (device_t);
int    nvidia_alloc_hardware (device_t);
void   nvidia_free_hardware  (device_t);
void   nvidia_intr           (void *);
int    nvidia_modevent       (module_t, int, void *);

void   nvidia_rc_timer       (void *);

void   nv_lock_api           (nv_state_t *);
void   nv_unlock_api         (nv_state_t *);

#define NV_SGLIST_FREE(sgl)             \
    {                                   \
        sglist_free(sgl);               \
        (sgl) = NULL;                   \
    }

#define NV_VM_OBJECT_DEALLOCATE(obj)    \
    {                                   \
        vm_object_deallocate(obj);      \
        (obj) = NULL;                   \
    }

#if __FreeBSD_version < 1000030
#define VM_OBJECT_WLOCK(object) VM_OBJECT_LOCK(object)
#define VM_OBJECT_WUNLOCK(object) VM_OBJECT_UNLOCK(object)
#endif

#if __FreeBSD_version < 1000055
#define vm_map_find(map, object, offset, addr, length, \
        max_addr, find_space, prot, max, cow) \
  vm_map_find(map, object, offset, addr, length, find_space, prot, max, cow)
#endif

#if __FreeBSD_version < 1000042
#define kmem_arena kernel_map
#endif

#if __FreeBSD_version >= 1200083
#define NV_KMEM_ALLOC_CONTIG(size, flags, low, high, align, boundary, memattr) \
    kmem_alloc_contig(size, flags, low, high, align, boundary, memattr)

#define NV_KMEM_FREE(address, size) \
    kmem_free(address, size)

#else
#define NV_KMEM_ALLOC_CONTIG(size, flags, low, high, align, boundary, memattr) \
    kmem_alloc_contig(kmem_arena, size, flags, low, high, align, boundary, memattr)

#define NV_KMEM_FREE(address, size) \
    kmem_free(kmem_arena, address, size)
#endif

#if __FreeBSD_version >= 800000
#define NV_VM_PAGER_ALLOCATE(type, handle, size, prot, off, cred) \
  vm_pager_allocate(type, handle, size, prot, off, cred)
#else
#define NV_VM_PAGER_ALLOCATE(type, handle, size, prot, off, cred) \
  vm_pager_allocate(type, handle, size, prot, off)
#endif

#if __FreeBSD_version >= 800000
#define NV_KDB_ENTER(why,msg) kdb_enter(why, msg)
#else
#define NV_KDB_ENTER(why,msg) kdb_enter(msg)
#endif

/* nvidia_sysctl.c */
void   nvidia_sysctl_init    (void);
void   nvidia_sysctl_exit    (void);

int    nvidia_sysctl_gpu_model  (SYSCTL_HANDLER_ARGS);
int    nvidia_sysctl_gpu_uuid   (SYSCTL_HANDLER_ARGS);
int    nvidia_sysctl_gpu_vbios  (SYSCTL_HANDLER_ARGS);
int    nvidia_sysctl_bus_type   (SYSCTL_HANDLER_ARGS);

int    nvidia_sysctl_registry_key     (SYSCTL_HANDLER_ARGS);
int    nvidia_sysctl_registry_dwords  (SYSCTL_HANDLER_ARGS);

void   nv_sysctl_init        (nv_state_t *);
void   nv_sysctl_exit        (nv_state_t *);

/* nvidia_linux.c */
void   nvidia_linux_init     (void);
void   nvidia_linux_exit     (void);

/* nvidia_os_registry.c */

void   nvidia_update_registry (char *);

/* ioctl helpers */
int    nvidia_get_card_info  (void *, int);
int    nvidia_handle_ioctl   (nv_state_t *, struct nvidia_filep *, u_long, caddr_t);

/* device helpers */
int    nvidia_open_ctl       (nv_state_t *, struct nvidia_filep *);
int    nvidia_open_dev       (nv_state_t *, struct nvidia_filep *);
int    nvidia_open_dev_kernel(NvU32 gpu_id, nvidia_stack_t *sp);
int    nvidia_close_ctl      (nv_state_t *, struct nvidia_filep *);
int    nvidia_close_dev      (nv_state_t *, struct nvidia_filep *);
void   nvidia_close_dev_kernel(NvU32 gpu_id, nvidia_stack_t *sp);
int    nvidia_mmap_ctl_single(nv_state_t *, struct nvidia_filep *, vm_ooffset_t *,
        vm_size_t, vm_object_t *, int nprot);
int    nvidia_mmap_dev_single(nv_state_t *, struct nvidia_filep *, vm_ooffset_t *,
        vm_size_t, vm_object_t *, int nprot);

/* nvidia_modeset_interface.c */
void   nvidia_modeset_suspend(NvU32 gpu_id);
void   nvidia_modeset_resume (NvU32 gpu_id);

static inline NvBool nvidia_lock_init_locks(nvidia_stack_t *sp, nv_state_t *nv)
{
    return rm_init_event_locks(sp, nv);
}

static inline void nvidia_lock_destroy_locks(nvidia_stack_t *sp, nv_state_t *nv)
{
    rm_destroy_event_locks(sp, nv);
}

void nvidia_ctl_dtor(void *arg);
void nvidia_dev_dtor(void *arg);

#endif /* __NV_FREEBSD_H__ */
