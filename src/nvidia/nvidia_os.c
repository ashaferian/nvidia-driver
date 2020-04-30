/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2001-2019 by NVIDIA Corporation.  All rights reserved.  All
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
#include "nv-retpoline.h"

#include <sys/consio.h>
#include <sys/fbio.h>
#include <sys/linker.h>
#include <sys/timex.h>
#include <dev/syscons/syscons.h>

// This bootloader metadata interface was added to metadata.h in FreeBSD 10.1
// with commit 3a7cd99956b1 and FreeBSD 11 with commit d2c99117cd3b.
// https://github.com/freebsd/freebsd/blob/master/sys/x86/include/metadata.h
#define NV_HAVE_EFI_FB (__FreeBSD_version >= 1001000)
#define MODINFOMD_EFI_FB 0x1005
struct efi_fb {
    uint64_t fb_addr;
    uint64_t fb_size;
    uint32_t fb_height;
    uint32_t fb_width;
    uint32_t fb_stride;
    uint32_t fb_mask_red;
    uint32_t fb_mask_green;
    uint32_t fb_mask_blue;
    uint32_t fb_mask_reserved;
};

MALLOC_DEFINE(M_NVIDIA, "nvidia", "NVIDIA memory allocations");
TASKQUEUE_DEFINE_THREAD(nvidia);

NV_STATUS NV_API_CALL os_alloc_mem(
    void **address,
    NvU64 size
)
{
    unsigned long alloc_size;

    /*
     * malloc takes an input of unsigned long (8 bytes in x64, 4 bytes in x86).
     * To avoid truncation and wrong allocation, below check is required.
     */
    alloc_size = size;

    if (alloc_size != size)
        return NV_ERR_INVALID_PARAMETER;

    // XXX Fix me? (malloc flags)
    *address = malloc(alloc_size, M_NVIDIA, M_NOWAIT | M_ZERO);
    return *address ? NV_OK : NV_ERR_NO_MEMORY;
}

void NV_API_CALL os_free_mem(void *address)
{
    free(address, M_NVIDIA);
}

#define NV_MSECS_PER_TICK       (1000 / hz)
#define NV_MSECS_TO_TICKS(ms)   ((ms) * hz / 1000)
#define NV_USECS_PER_TICK       (1000000 / hz)
#define NV_USECS_TO_TICKS(us)   ((us) * hz / 1000000)

NV_STATUS NV_API_CALL os_delay(NvU32 MilliSeconds)
{
    unsigned long MicroSeconds;
    unsigned long ticks;
    struct timeval tv_end, tv_aux;

    getmicrotime(&tv_aux);

    if (__NV_ITHREAD() && (MilliSeconds > NV_MAX_ISR_DELAY_MS))
        return NV_ERR_GENERIC;

    if (__NV_ITHREAD()) {
        DELAY(MilliSeconds * 1000);
        return NV_OK;
    }

    MicroSeconds = MilliSeconds * 1000;
    tv_end.tv_usec = MicroSeconds;
    tv_end.tv_sec = 0;
    /* tv_end = tv_aux + tv_end */
    NV_TIMERADD(&tv_aux, &tv_end, &tv_end);

    ticks = NV_USECS_TO_TICKS(MicroSeconds);

    if (ticks > 0) {
        do {
            tsleep((void *)os_delay, PUSER | PCATCH, "delay", ticks);
            getmicrotime(&tv_aux);
            if (NV_TIMERCMP(&tv_aux, &tv_end, <)) {
                /* tv_aux = tv_end - tv_aux */
                NV_TIMERSUB(&tv_end, &tv_aux, &tv_aux);
                MicroSeconds = tv_aux.tv_usec + (tv_aux.tv_sec * 1000000);
            } else
                MicroSeconds = 0;
        } while ((ticks = NV_USECS_TO_TICKS(MicroSeconds)) > 0);
    }

    if (MicroSeconds > 0)
        DELAY(MicroSeconds);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_delay_us(NvU32 MicroSeconds)
{
    if (__NV_ITHREAD() && (MicroSeconds > NV_MAX_ISR_DELAY_US))
        return NV_ERR_GENERIC;
    DELAY(MicroSeconds);
    return NV_OK;
}

NvU64 NV_API_CALL os_get_cpu_frequency(void)
{
    /* round up by 4999 before division by 1000000 in osGetCpuFrequency() */
    return (tsc_freq + 4999);
}

NvU32 NV_API_CALL os_get_current_process(void)
{
    return curproc->p_pid;
}

void NV_API_CALL os_get_current_process_name(char *buf, NvU32 len)
{
    // Unsupported
    buf[0] = '\0';
}

NvU32 NV_API_CALL os_get_current_pasid(void)
{
    // Unsupported. Return "0" as it's invalid PASID
    return 0;
}

NV_STATUS NV_API_CALL os_get_current_thread(NvU64 *threadId)
{
    if (__NV_ITHREAD())
        *threadId = 0;
    else
        *threadId = (NvU64) CURTHREAD->td_tid;

    return NV_OK;
}

NV_STATUS NV_API_CALL os_get_current_time(
    NvU32 *sec,
    NvU32 *usec
)
{
    struct timeval tv;

    getmicrotime(&tv);

    *sec  = tv.tv_sec;
    *usec = tv.tv_usec;

    return NV_OK;
}

#define NANOSECOND_PER_USEC 1000

void NV_API_CALL os_get_current_tick(NvU64 *nsec)
{
    NvU32 sec, usec;

    /* TODO: can we use getnanouptime() for this? */
    (void) os_get_current_time(&sec, &usec);

    *nsec = (NvU64)sec * NANOSECOND + (NvU64)usec * NANOSECOND_PER_USEC;
}

NvU64 NV_API_CALL os_get_tick_resolution(void)
{
    /* Currently using os_get_current_time() which has microsecond resolution */
    return NANOSECOND_PER_USEC;
}

BOOL NV_API_CALL os_is_administrator(void)
{
    return suser(CURTHREAD) ? FALSE : TRUE;
}

BOOL NV_API_CALL os_allow_priority_override(void)
{
    return os_is_administrator();
}

NvU8 NV_API_CALL os_io_read_byte(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inb(address);
}

void NV_API_CALL os_io_write_byte(
    NvU32 address,
    NvU8  value
)
{
    /* XXX Fix me? (bus_space access) */
    outb(address, value);
}

NvU16 NV_API_CALL os_io_read_word(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inw(address);
}

void NV_API_CALL os_io_write_word(
    NvU32 address,
    NvU16 value
)
{
    /* XXX Fix me? (bus_space access) */
    return outw(address, value);
}

NvU32 NV_API_CALL os_io_read_dword(
    NvU32 address
)
{
    /* XXX Fix me? (bus_space access) */
    return inl(address);
}

void NV_API_CALL os_io_write_dword(
    NvU32 address,
    NvU32 value
)
{
    /* XXX Fix me? (bus_space access) */
    outl(address, value);
}

void* NV_API_CALL os_map_kernel_space(
    NvU64 start,
    NvU64 size,
    NvU32 mode,
    NvU32 memType
)
{
    int map_mode;

#if defined(NVCPU_X86) && !defined(PAE)
    if (start > 0xffffffffULL)
        return NULL;
#endif

    switch (mode) {
        case NV_MEMORY_CACHED:
            map_mode = PAT_WRITE_BACK;
            break;
        case NV_MEMORY_WRITECOMBINED:
            map_mode = PAT_WRITE_COMBINING;
            break;
        case NV_MEMORY_UNCACHED:
        case NV_MEMORY_DEFAULT:
            map_mode = PAT_UNCACHEABLE;
            break;
        default:
            nv_printf(NV_DBG_ERRORS,
                      "NVRM: unknown mode in os_map_kernel_space()\n");
            return NULL;
    }

    return pmap_mapdev_attr(start, size, map_mode);
}

void NV_API_CALL os_unmap_kernel_space(
    void *address,
    NvU64 size
)
{
    pmap_unmapdev((vm_offset_t)address, size);
}

void* NV_API_CALL os_map_user_space(
    NvU64   start,
    NvU64   size_bytes,
    NvU32   mode,
    NvU32   protect,
    void  **priv_data
)
{
    return (void *)(NvUPtr)start;
}

void NV_API_CALL os_unmap_user_space(
    void  *address,
    NvU64  size,
    void  *priv_data
)
{
}

/*
 * The current debug level is used to determine if certain debug messages
 * are printed to the system console/log files or not. It defaults to the
 * highest debug level, i.e. the lowest debug output.
 */

NvU32 cur_debuglevel = 0xffffffff;

void NV_API_CALL os_dbg_init(void)
{
    NvU32 new_debuglevel;
    nvidia_stack_t *sp;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL)
        return;

    if (rm_read_registry_dword(sp, NULL, "NVreg", "ResmanDebugLevel",
            &new_debuglevel) == NV_OK) {
        if (new_debuglevel != 0xffffffff)
            cur_debuglevel = new_debuglevel;
    }

    NV_UMA_ZONE_FREE_STACK(sp);
}

NV_STATUS NV_API_CALL os_schedule(void)
{
    int ret = pause("sched", 1 /* timeout in 1/hz units */);

    switch (ret)
    {
    case 0:
    case EWOULDBLOCK:
        return NV_OK;
    default:
        return NV_ERR_OPERATING_SYSTEM;
    }
}

static void os_execute_work_item(void *context, int pending)
{
    nvidia_work_t *work = (nvidia_work_t *)context;
    nvidia_stack_t *sp = NULL;

    NV_UMA_ZONE_ALLOC_STACK(sp);
    if (sp == NULL) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate stack!\n");
        return;
    }

    rm_execute_work_item(sp, work->data);
    os_free_mem((void *)work);

    NV_UMA_ZONE_FREE_STACK(sp);
}

NV_STATUS NV_API_CALL os_queue_work_item(struct os_work_queue *queue, void *data)
{
    NV_STATUS status;
    nvidia_work_t *work;

    status = os_alloc_mem((void **)&work, sizeof(nvidia_work_t));
    if (status != NV_OK)
        return status;

    work->data = data;

    TASK_INIT(&work->task, 0, os_execute_work_item, (void *)work);
    taskqueue_enqueue(taskqueue_nvidia, &work->task);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_flush_work_queue(struct os_work_queue *queue)
{
    taskqueue_run(taskqueue_nvidia);
    return NV_OK;
}

void NV_API_CALL os_dbg_set_level(NvU32 new_debuglevel)
{
    cur_debuglevel = new_debuglevel;
}

void NV_API_CALL os_dbg_breakpoint(void)
{
#ifdef DEBUG
    NV_KDB_ENTER("breakpoint", "DEBUG breakpoint");
#endif
}

#define MAX_ERROR_STRING 512
static char nv_error_string[MAX_ERROR_STRING];

/*
 * The binary core of RM (nv-kernel.o) calls this:
 */
void NV_API_CALL out_string(const char *message)
{
    printf("%s", message);
}

int NV_API_CALL nv_printf(NvU32 debuglevel, const char *format, ...)
{
    char *message = nv_error_string;
    va_list arglist;
    int chars_written = 0;

    if (debuglevel >= ((cur_debuglevel >> 4) & 3)) {
        va_start(arglist, format);
        chars_written = vsnprintf(message, sizeof(nv_error_string), format, arglist);
        va_end(arglist);
        printf("%s", message);
    }

    return chars_written;
}

NvS32 NV_API_CALL os_snprintf(char *buf, NvU32 size, const char *fmt, ...)
{
    va_list arglist;
    int chars_written;

    va_start(arglist, fmt);
    chars_written = vsnprintf(buf, size, fmt, arglist);
    va_end(arglist);

    return chars_written;
}

void NV_API_CALL os_log_error(const char *fmt, va_list ap)
{
    vsnprintf(nv_error_string, MAX_ERROR_STRING, fmt, ap);
    printf("%s", nv_error_string);
}

NvS32 NV_API_CALL os_mem_cmp(
    const NvU8 *buf0,
    const NvU8 *buf1,
    NvU32 length
)
{
    return memcmp(buf0, buf1, length);
}

NvU8* NV_API_CALL os_mem_copy(
    NvU8       *dst,
    const NvU8 *src,
    NvU32       length
)
{
    NvU8 *ret = dst;
    NvU32 dwords, bytes = length;

    if ((length >= 128) &&
        (((NvUPtr)dst & 3) == 0) & (((NvUPtr)src & 3) == 0))
    {
        dwords = (length / sizeof(NvU32));
        bytes = (length % sizeof(NvU32));

        while (dwords != 0)
        {
            *(NvU32 *)dst = *(const NvU32 *)src;
            dst += sizeof(NvU32);
            src += sizeof(NvU32);
            dwords--;
        }
    }

    while (bytes != 0)
    {
        *dst = *src;
        dst++;
        src++;
        bytes--;
    }

    return ret;
}

NV_STATUS NV_API_CALL os_memcpy_from_user(
    void *dst,
    const void *src,
    NvU32 length
)
{
    return copyin(src, dst, length)  ? NV_ERR_INVALID_POINTER : NV_OK;
}

NV_STATUS NV_API_CALL os_memcpy_to_user(
    void *dst,
    const void *src,
    NvU32 length
)
{
    return copyout(src, dst, length) ? NV_ERR_INVALID_POINTER : NV_OK;
}

void* NV_API_CALL os_mem_set(
    void  *dst,
    NvU8   c,
    NvU32  length
)
{
    NvU8 *ret = dst;
    NvU32 bytes = length;

    while (bytes != 0)
    {
        *(NvU8 *)dst = c;
        dst = ((NvU8 *)dst + 1);
        bytes--;
    }

    return ret;
}

char* NV_API_CALL os_string_copy(
    char *dst,
    const char *src
)
{
    return strcpy(dst, src);
}

NvU32 NV_API_CALL os_string_length(const char* s)
{
    return strlen(s);
}

NvU32 NV_API_CALL os_strtoul(const char *str, char **endp, NvU32 base)
{
    return (NvU32)strtoul(str, endp, base);
}

NvS32 NV_API_CALL os_string_compare(const char *str1, const char *str2)
{
    return strcmp(str1, str2);
}

NvU32 NV_API_CALL os_get_page_size(void)
{
    return PAGE_SIZE;
}

NvU64 NV_API_CALL os_get_page_mask(void)
{
    return ~PAGE_MASK;
}

NvU8 NV_API_CALL os_get_page_shift(void)
{
    return PAGE_SHIFT;
}

NvU64 NV_API_CALL os_get_num_phys_pages(void)
{
    return (NvU64)physmem;
}

NvU32 NV_API_CALL os_get_cpu_count(void)
{
    return mp_ncpus;
}

NvU32 NV_API_CALL os_get_cpu_number(void)
{
    return curcpu;
}

#ifdef NV_USE_WBINVD
static void wbinvd_action_func(void *arg)
{
    __asm__ __volatile__("wbinvd": : :"memory");
}

NV_STATUS NV_API_CALL os_flush_cpu_cache(void)
{
    smp_rendezvous(NULL, wbinvd_action_func, NULL, NULL);
    wbinvd_action_func(NULL);
    return NV_OK;
}
#else
NV_STATUS NV_API_CALL os_flush_cpu_cache(void)
{
    pmap_invalidate_cache();
    return NV_OK;
}
#endif

NV_STATUS NV_API_CALL os_flush_user_cache(
    NvU64 start,
    NvU64 end,
    NvU64 physStart,
    NvU64 physEnd,
    NvU32 flags
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_flush_cpu_cache_all(void)
{
    return NV_ERR_NOT_SUPPORTED;
}

static void sfence_action_func(void *arg)
{
    __asm__ __volatile__("sfence": : :"memory");
}

void NV_API_CALL os_flush_cpu_write_combine_buffer(void)
{
    smp_rendezvous(NULL, sfence_action_func, NULL, NULL);
    sfence_action_func(NULL);
}

NV_STATUS NV_API_CALL os_alloc_mutex(void **mutex)
{
    NV_STATUS status;
    struct sx *sx;

    status = os_alloc_mem((void **)&sx, sizeof(struct sx));
    if (status != NV_OK)
        return status;

    sx_init(sx, "os.lock_sx");
    *mutex = (void *)sx;

    return NV_OK;
}

void NV_API_CALL os_free_mutex(void *mutex)
{
    struct sx *sx = mutex;

    if (sx != NULL) {
        sx_destroy(sx);
        os_free_mem(sx);
    }
}

NV_STATUS NV_API_CALL os_acquire_mutex(void *mutex)
{
    struct sx *sx = mutex;

    if (__NV_ITHREAD())
        return NV_ERR_INVALID_REQUEST;

    sx_xlock(sx);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_mutex(void *mutex)
{
    struct sx *sx = mutex;

    if (__NV_ITHREAD())
        return NV_ERR_INVALID_REQUEST;

    if (sx_try_xlock(sx) == 0)
        return NV_ERR_TIMEOUT_RETRY;

    return NV_OK;
}

void NV_API_CALL os_release_mutex(void *mutex)
{
    struct sx *sx = mutex;

    sx_xunlock(sx);
}

struct os_semaphore {
    struct mtx mutex_mtx;
    struct cv mutex_cv;
    NvS32  count;
};

void* NV_API_CALL os_alloc_semaphore(NvU32 initialValue)
{
    NV_STATUS status;
    struct os_semaphore *os_sema;

    status = os_alloc_mem((void **)&os_sema, sizeof(struct os_semaphore));
    if (status != NV_OK) {
        nv_printf(NV_DBG_ERRORS, "NVRM: failed to allocate semaphore!\n");
        return NULL;
    }

    mtx_init(&os_sema->mutex_mtx, "os.sema_mtx", NULL, MTX_DEF);
    cv_init(&os_sema->mutex_cv, "os.sema_cv");

    os_sema->count = initialValue;

    return (void *)os_sema;
}

void NV_API_CALL os_free_semaphore(void *semaphore)
{
    struct os_semaphore *os_sema = (struct os_semaphore *)semaphore;

    mtx_destroy(&os_sema->mutex_mtx);
    cv_destroy(&os_sema->mutex_cv);

    os_free_mem(os_sema);
}

NV_STATUS NV_API_CALL os_acquire_semaphore(void *semaphore)
{
    struct os_semaphore *os_sema = (struct os_semaphore *)semaphore;

    mtx_lock(&os_sema->mutex_mtx);
    os_sema->count--;
    if (os_sema->count < 0)
        cv_wait_unlock(&os_sema->mutex_cv, &os_sema->mutex_mtx);
    else
        mtx_unlock(&os_sema->mutex_mtx);

    return NV_OK;
}

NV_STATUS NV_API_CALL os_cond_acquire_semaphore(void *semaphore)
{
    NV_STATUS status = NV_ERR_TIMEOUT_RETRY;
    struct os_semaphore *os_sema = (struct os_semaphore *)semaphore;

    if (mtx_trylock(&os_sema->mutex_mtx) != 0) {
        if (os_sema->count > 0) {
            os_sema->count--;
            status = NV_OK;
        }
        mtx_unlock(&os_sema->mutex_mtx);
    }

    return status;
}

NV_STATUS NV_API_CALL os_release_semaphore(void *semaphore)
{
    struct os_semaphore *os_sema = (struct os_semaphore *)semaphore;

    mtx_lock(&os_sema->mutex_mtx);
    if (os_sema->count < 0) {
        cv_signal(&os_sema->mutex_cv);
    }
    os_sema->count++;
    mtx_unlock(&os_sema->mutex_mtx);

    return NV_OK;
}

BOOL NV_API_CALL os_semaphore_may_sleep(void)
{
    return (!__NV_ITHREAD());
}

BOOL NV_API_CALL os_is_isr(void)
{
    return (__NV_ITHREAD());
}

BOOL NV_API_CALL os_pat_supported(void)
{
    return TRUE;
}

BOOL NV_API_CALL os_is_efi_enabled(void)
{
    return FALSE;
}

BOOL NV_API_CALL os_iommu_is_snooping_enabled(void)
{
    return TRUE;
}

void NV_API_CALL os_get_screen_info(
    NvU64 *pPhysicalAddress,
    NvU16 *pFbWidth,
    NvU16 *pFbHeight,
    NvU16 *pFbDepth,
    NvU16 *pFbPitch
)
{
#if NV_HAVE_EFI_FB
    /*
     * Look up EFI framebuffer information passed to the FreeBSD kernel by the
     * bootloader.
     *
     * Adapted from a suggestion by Conrad Meyer <cem@freebsd.org>.
     */
    caddr_t kmdp = preload_search_by_type("elf kernel") ?:
                   preload_search_by_type("elf64 kernel");

    if (kmdp != NULL)
    {
        const struct efi_fb *efifb =
            (const struct efi_fb *)preload_search_info(kmdp, MODINFO_METADATA |
                                                             MODINFOMD_EFI_FB);
        if (efifb != NULL)
        {
            int depth = fls(efifb->fb_mask_red | efifb->fb_mask_green |
                            efifb->fb_mask_blue | efifb->fb_mask_reserved);
            int bpp = roundup2(depth, NBBY);

            *pPhysicalAddress = efifb->fb_addr;
            *pFbWidth = efifb->fb_width;
            *pFbHeight = efifb->fb_height;
            *pFbDepth = depth;
            /* fb_stride is in pixels. Convert to bytes */
            *pFbPitch = efifb->fb_stride * (bpp / NBBY);
            return;
        }
    }
#endif
    {
        const sc_softc_t *sc = sc_get_softc(0, SC_KERNEL_CONSOLE);

        if (sc)
        {
            const video_adapter_t *adp = sc->adp;

            if (adp)
            {
                const struct video_info *vi = &adp->va_info;

                if (vi && (vi->vi_flags & V_INFO_LINEAR))
                {
                    *pPhysicalAddress = vi->vi_buffer;
                    *pFbWidth = vi->vi_width;
                    *pFbHeight = vi->vi_height;
                    *pFbDepth = vi->vi_depth;
                    *pFbPitch = adp->va_line_width;
                    return;
                }
            }
        }
    }

    *pPhysicalAddress = 0;
    *pFbWidth = *pFbHeight = *pFbDepth = *pFbPitch = 0;
}

NV_STATUS NV_API_CALL os_disable_console_access(void)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL os_enable_console_access(void)
{
    return NV_OK;
}

NV_STATUS NV_API_CALL os_alloc_spinlock(void **lock)
{
    NV_STATUS status;
    struct mtx *mtx;

    status = os_alloc_mem((void **)&mtx, sizeof(struct mtx));
    if (status != NV_OK)
        return status;

    mtx_init(mtx, "os.lock_mtx", NULL, MTX_DEF);

    *lock = (void *)mtx;

    return NV_OK;
}

void NV_API_CALL os_free_spinlock(void *lock)
{
    struct mtx *mtx = lock;

    if (mtx != NULL) {
        mtx_assert(mtx, MA_OWNED);
        mtx_destroy(mtx);
        os_free_mem(mtx);
    }
}

NvU64 NV_API_CALL os_acquire_spinlock(void *lock)
{
    struct mtx *mtx = lock;

    mtx_lock(mtx);

    return 0;
}

void NV_API_CALL os_release_spinlock(void *lock, NvU64 oldIrql)
{
    struct mtx *mtx = lock;

    mtx_unlock(mtx);
}

NV_STATUS NV_API_CALL os_get_address_space_info(
    NvU64 *userStartAddress,
    NvU64 *userEndAddress,
    NvU64 *kernelStartAddress,
    NvU64 *kernelEndAddress
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_version_info(os_version_info * pOsVersionInfo)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_xen_dom0(void)
{
    return FALSE;
}

NvBool NV_API_CALL os_is_vgx_hyper(void)
{
    return FALSE;
}

NV_STATUS NV_API_CALL os_inject_vgx_msi(NvU16 guestID, NvU64 msiAddr, NvU32 msiData)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvBool NV_API_CALL os_is_grid_supported(void)
{
    return FALSE;
}

NvU32 NV_API_CALL os_get_grid_csp_support(void)
{
    return 0;
}

void NV_API_CALL os_bug_check(NvU32 bugCode, const char *bugCodeStr)
{
}

NV_STATUS NV_API_CALL os_lock_user_pages(
    void   *address,
    NvU64   page_count,
    void  **page_array
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_unlock_user_pages(
    NvU64  page_count,
    void  *page_array
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_lookup_user_io_memory(
    void   *address,
    NvU64   page_count,
    NvU64 **pte_array
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_match_mmap_offset(
    void  *pAllocPrivate,
    NvU64  offset,
    NvU64 *pPageIndex
)
{
    struct nvidia_alloc *at = pAllocPrivate;
    NvU64 i;

    for (i = 0; i < (at->size / PAGE_SIZE); i++) {
        if (at->alloc_type_contiguous) {
            if (offset == (at->pte_array[0].physical_address + (i * PAGE_SIZE))) {
                *pPageIndex = i;
                return NV_OK;
            }
        } else {
            if (offset == at->pte_array[i].physical_address) {
                *pPageIndex = i;
                return NV_OK;
            }
        }
    }

    return NV_ERR_OBJECT_NOT_FOUND;
}

NV_STATUS NV_API_CALL os_get_euid(NvU32 *pSecToken)
{
    *pSecToken = (NvU32)CURTHREAD->td_ucred->cr_uid;
    return NV_OK;
}

NV_STATUS NV_API_CALL os_get_smbios_header(NvU64 *pSmbsAddr)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_acpi_rsdp_from_uefi
(
    NvU32  *pRsdpAddr
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_add_record_for_crashLog(void *pbuffer, NvU32 size)
{
}

void NV_API_CALL os_delete_record_for_crashLog(void *pbuffer)
{
}

NV_STATUS NV_API_CALL os_call_vgpu_vfio(void *pvgpu_vfio_info, NvU32 cmd_type)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_numa_memblock_size(NvU64 *memblock_size)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_alloc_pages_node
(
    NvS32  nid,
    NvU32  size,
    NvU32  flag,
    NvU64 *pAddress
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_get_page
(
    NvU64 address
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL  os_put_page
(
    NvU64 address
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NvU32 NV_API_CALL os_get_page_refcount
(
    NvU64 address
)
{
    return 0;
}

NvU32 NV_API_CALL os_count_tail_pages
(
    NvU64 address
)
{
    return 0;
}

void NV_API_CALL os_free_pages_phys
(
    NvU64 address,
    NvU32 size
)
{
}

NV_STATUS NV_API_CALL os_ipmi_connect(NvU32 devIndex, NvU8 myAddr, void **ppOsPriv)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_ipmi_disconnect(void *pOsPriv)
{
}

NV_STATUS NV_API_CALL os_ipmi_send_receive_cmd(void *pOsPriv, nvipmi_req_resp_t *pReq)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_call_nv_vmbus(NvU32 vmbus_cmd, void *input)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_open_temporary_file
(
    void **ppFile
)
{
    return NV_ERR_NOT_SUPPORTED;
}

void NV_API_CALL os_close_file
(
    void *pFile
)
{
}

NV_STATUS NV_API_CALL os_write_file
(
    void *pFile,
    NvU8 *pBuffer,
    NvU64 size,
    NvU64 offset
)
{
    return NV_ERR_NOT_SUPPORTED;
}

NV_STATUS NV_API_CALL os_read_file
(
    void *pFile,
    NvU8 *pBuffer,
    NvU64 size,
    NvU64 offset
)
{
    return NV_ERR_NOT_SUPPORTED;
}
