/* _NVRM_COPYRIGHT_BEGIN_
 *
 * Copyright 2015 by NVIDIA Corporation.  All rights reserved.  All
 * information contained herein is proprietary and confidential to NVIDIA
 * Corporation.  Any use, reproduction, or disclosure without the written
 * permission of NVIDIA Corporation is prohibited.
 *
 * _NVRM_COPYRIGHT_END_
 */

#include <sys/types.h>
#include <sys/module.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/conf.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/mutex.h>

#include "nvkms-ioctl.h"
#include "nvidia-modeset-os-interface.h"
#include "nvkms.h"
#include "nv-modeset-interface.h"

/*
 * This option decides if nvidia-modeset.ko will be built with support
 * for Linux or Linux 32-bit (FreeBSD/amd64) compatibility.  This
 * makes nvidia-modeset.ko dependent on linux.ko; if you don't need
 * Linux compatibility, then you can safely unset this flag.
 */
#define NVKMS_SUPPORT_LINUX_COMPAT

#if defined(NVKMS_SUPPORT_LINUX_COMPAT)
  #if defined(NVCPU_X86)
    #include "machine/../linux/linux.h"
    #include "machine/../linux/linux_proto.h"
  #elif defined(NVCPU_X86_64)
    #include "machine/../linux32/linux.h"
    #include "machine/../linux32/linux32_proto.h"
  #endif
  #include <compat/linux/linux_ioctl.h>
#endif


#define NVKMS_LOG_PREFIX "nvidia-modeset: "

#define NVKMS_CDEV_MINOR 254

#define NVKMS_USECS_TO_TICKS(usec) ((usec) * hz / 1000000)

MALLOC_DEFINE(M_NVIDIA_MODESET,
              "nvidia-modeset", "NVIDIA modeset memory allocations");

static void nvkms_close(void *arg);

/*************************************************************************
 * NVKMS uses a global lock, nvkms_lock.  The lock is taken in the
 * file operation callback functions when calling into core NVKMS.
 *************************************************************************/

static struct sx nvkms_lock;

/*************************************************************************
 * NVKMS uses a global clients counter and boolean unloading flag. This is
 * used to determine whether module can be safely unloaded.
 *************************************************************************/
static struct {
    struct sx lock;
    unsigned int client_counter;
    NvBool is_unloading;
} nvkms_module;

/*************************************************************************
 * The nvkms_per_open structure tracks data that is specific to a
 * single file open./
 *************************************************************************/

struct nvkms_per_open {
    void *data;
   /* NVKMS_CLIENT_USER_SPACE callouts */
    struct {
        struct mtx lock;
        uint32_t available;
        struct selinfo select;
    } events;
    /* NVKMS_CLIENT_KERNEL_SPACE callouts */
    struct {
	    struct mtx lock;
	    struct task task;
    } tasks;
};


/*************************************************************************
 * nvidia-modeset-os-interface.h functions.  It is assumed that these
 * are called while nvkms_lock is held.
 *************************************************************************/

void* NVKMS_API_CALL nvkms_alloc(size_t size, NvBool zero)
{
	//printf("nvkms_alloc: %zu\n", size);
	void *ret = malloc(size, M_NVIDIA_MODESET, M_WAITOK | (zero ? M_ZERO : 0));
	//printf("nvkms_alloc:return: 0x%x\n", (unsigned int)ret);
	return ret;
}

void NVKMS_API_CALL nvkms_free(void *ptr, size_t size)
{
	//printf("nvkms_free: 0x%x\n", (unsigned int)ptr);
    free(ptr, M_NVIDIA_MODESET);
}

void* NVKMS_API_CALL nvkms_memset(void *ptr, NvU8 c, size_t size)
{
	//printf("nvkms_memset: 0x%x\n", (unsigned int)ptr);
    return memset(ptr, c, size);
}

void* NVKMS_API_CALL nvkms_memcpy(void *dest, const void *src, size_t n)
{
	//printf("nvkms_memcpy: to 0x%x\n", (unsigned int)dest);
    return memcpy(dest, src, n);
}

void* NVKMS_API_CALL nvkms_memmove(void *dest, const void *src, size_t n)
{
	//printf("nvkms_memmove: to 0x%x\n", (unsigned int)dest);
    return memmove(dest, src, n);
}

int NVKMS_API_CALL nvkms_memcmp(const void *s1, const void *s2, size_t n)
{
	//printf("nvkms_memcmp: 0x%x vs 0x%x\n", (unsigned int)s1, (unsigned int)s2);
    return memcmp(s1, s2, n);
}

size_t NVKMS_API_CALL nvkms_strlen(const char *s)
{
	//printf("nvkms_strlen: %s\n", s);
    return strlen(s);
}

int NVKMS_API_CALL nvkms_strcmp(const char *s1, const char *s2)
{
	//printf("nvkms_strcmp: %s %s\n", s1, s2);
    return strcmp(s1, s2);
}

char* NVKMS_API_CALL nvkms_strncpy(char *dest, const char *src, size_t n)
{
	//printf("nvkms_strncpy: to 0x%x\n", (unsigned int)dest);
    return strncpy(dest, src, n);
}

void NVKMS_API_CALL nvkms_usleep(NvU64 usec)
{
	//printf("nvkms_usleep:");
    DELAY(usec);
}

NvU64 NVKMS_API_CALL nvkms_get_usec(void)
{
    struct timeval tv;

    getmicrotime(&tv);

    //printf("nvkms_get_usec:return: %llu\n", (((NvU64)tv.tv_sec) * 1000000) + tv.tv_usec);
    return (((NvU64)tv.tv_sec) * 1000000) + tv.tv_usec;
}

int NVKMS_API_CALL nvkms_copyin(void *kptr, NvU64 uaddr, size_t n)
{
	if (!nvKmsNvU64AddressIsSafe(uaddr)) {
		return EINVAL;
	}

	int ret = copyin(nvKmsNvU64ToPointer(uaddr), kptr, n);
	return ret;
}

int NVKMS_API_CALL nvkms_copyout(NvU64 uaddr, const void *kptr, size_t n)
{
    if (!nvKmsNvU64AddressIsSafe(uaddr)) {
        return EINVAL;
    }

    int ret = copyout(kptr, nvKmsNvU64ToPointer(uaddr), n);
    return ret;
}

void NVKMS_API_CALL nvkms_yield(void)
{
    pause("yield", 1 /* timeout in 1/hz units */);
}

int NVKMS_API_CALL nvkms_snprintf(char *str, size_t size, const char *format, ...)
{
    int ret;
    va_list ap;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
}

int NVKMS_API_CALL nvkms_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    return vsnprintf(str, size, format, ap);
}

void NVKMS_API_CALL nvkms_log(const int level, const char *gpuPrefix, const char *msg)
{
    int priority;
    const char *levelPrefix;

    switch (level) {
    default:
    case NVKMS_LOG_LEVEL_INFO:
        levelPrefix = "";
        priority = LOG_INFO;
        break;
    case NVKMS_LOG_LEVEL_WARN:
        levelPrefix = "WARNING: ";
        priority = LOG_WARNING;
        break;
    case NVKMS_LOG_LEVEL_ERROR:
        levelPrefix = "ERROR: ";
        priority = LOG_ERR;
        break;
    }

    log(priority, "%s%s%s%s\n", NVKMS_LOG_PREFIX, levelPrefix, gpuPrefix, msg);
}

void NVKMS_API_CALL
nvkms_event_queue_changed(nvkms_per_open_handle_t *pOpenKernel,
                          NvBool eventsAvailable)
{
	//printf("nvkms_event_queue_changed: \n");

    struct nvkms_per_open *popen = pOpenKernel;

    mtx_lock(&popen->events.lock);

    popen->events.available = eventsAvailable;

    selwakeup(&popen->events.select);

    mtx_unlock(&popen->events.lock);
}

/*************************************************************************
 * ref_ptr implementation.
 *************************************************************************/

struct nvkms_ref_ptr {
    struct mtx lock;
    int refcnt;
    // Access to ptr is guarded by the nvkms_lock.
    void *ptr;
};

struct nvkms_ref_ptr* NVKMS_API_CALL nvkms_alloc_ref_ptr(void *ptr)
{
	//printf("nvkms_alloc_ref_ptr: 0x%x\n", (unsigned int)ptr);
    struct nvkms_ref_ptr *ref_ptr = nvkms_alloc(sizeof(*ref_ptr), NV_FALSE);
    if (ref_ptr) {
        mtx_init(&ref_ptr->lock, "nvkms-ref-ptr-lock", NULL, MTX_SPIN);
        // The ref_ptr owner counts as a reference on the ref_ptr itself.
        ref_ptr->refcnt = 1;
        ref_ptr->ptr = ptr;
    }
    //printf("nvkms_alloc_ref_ptr:return: 0x%x\n", (unsigned int)ref_ptr);
    return ref_ptr;
}

void NVKMS_API_CALL nvkms_free_ref_ptr(struct nvkms_ref_ptr *ref_ptr)
{
	//printf("nvkms_free_ref_ptr: \n");
    if (ref_ptr) {
        ref_ptr->ptr = NULL;
        // Release the owner's reference of the ref_ptr.
        nvkms_dec_ref(ref_ptr);
    }
}

void NVKMS_API_CALL nvkms_inc_ref(struct nvkms_ref_ptr *ref_ptr)
{
	//printf("nvkms_inc_ref: \n");
    mtx_lock_spin(&ref_ptr->lock);
    ref_ptr->refcnt++;
    mtx_unlock_spin(&ref_ptr->lock);
}

void* NVKMS_API_CALL nvkms_dec_ref(struct nvkms_ref_ptr *ref_ptr)
{
    void *ptr = ref_ptr->ptr;

    //printf("nvkms_dec_ref: \n");
    mtx_lock_spin(&ref_ptr->lock);
    if (--ref_ptr->refcnt == 0) {
        mtx_destroy(&ref_ptr->lock);
        nvkms_free(ref_ptr, sizeof(*ref_ptr));
    } else {
        mtx_unlock_spin(&ref_ptr->lock);
    }

    //printf("nvkms_dec_ref:return: 0x%x\n", (unsigned int)ptr);
    return ptr;
}

/*************************************************************************
 * Timer support
 *
 * Core NVKMS needs to be able to schedule work to execute in the
 * future, within process context.
 *
 * To achieve this, use the 'callout' mechanism to schedule a
 * callback, nvkms_callout_callback().  This will execute in softirq
 * context, so from there schedule a taskqueue task,
 * nvkms_taskqueue_callback(), which will execute in process context.
 *
 * This could be simpler with the taskqueue_enqueue_timeout(9) family
 * of functions to defer work until a mininum period of time has
 * passed.  Unfortunately, the taskqueue_enqueue_timeout(9) interface
 * is only available on FreeBSD 9.0 and higher.
 *
 * References:
 *
 * callout_reset(9)
 * taskqueue_enqueue(9)
 * https://www.freebsd.org/doc/en_US.ISO8859-1/books/arch-handbook/smp-design.html
 * https://svnweb.freebsd.org/base?view=revision&revision=221059
 *************************************************************************/

TASKQUEUE_DEFINE_THREAD(nvkms);

struct nvkms_timer_t {
    struct callout callout;
    struct task task;
    NvBool cancel;
    NvBool complete;
    NvBool isRefPtr;
    NvBool callout_created;
    nvkms_timer_proc_t *proc;
    void *dataPtr;
    NvU32 dataU32;
    LIST_ENTRY(nvkms_timer_t) timers_list;
};

/*
 * Global list with pending timers, any change requires acquiring lock
 */
static struct {
    struct sx lock;
    LIST_HEAD(nvkms_timers_head, nvkms_timer_t) list;
} nvkms_timers;

static void nvkms_taskqueue_callback(void *arg, int pending)
{
    struct nvkms_timer_t *timer = arg;
    void *dataPtr;

    /*
     * We can delete this timer from pending timers list - it's being
     * processed now.
     */
    sx_xlock(&nvkms_timers.lock);
    LIST_REMOVE(timer, timers_list);
    sx_xunlock(&nvkms_timers.lock);

    /*
     * After taskqueue_callback we want to be sure that callout_callback
     * for this timer also have finished. It's important during module
     * unload - this way we can safely unload this module by first deleting
     * pending timers and than waiting for taskqueue callbacks.
     */
    if (timer->callout_created) {
        callout_drain(&timer->callout);
    }

    sx_xlock(&nvkms_lock);

    if (timer->isRefPtr) {
        // If the object this timer refers to was destroyed, treat the timer as
        // canceled.
        dataPtr = nvkms_dec_ref(timer->dataPtr);
        if (!dataPtr) {
            timer->cancel = NV_TRUE;
        }
    } else {
        dataPtr = timer->dataPtr;
    }

    if (!timer->cancel) {
        timer->proc(dataPtr, timer->dataU32);
        timer->complete = NV_TRUE;
    }

    if (timer->cancel || timer->isRefPtr) {
        nvkms_free(timer, sizeof(*timer));
    }

    sx_xunlock(&nvkms_lock);
}

static void nvkms_callout_callback(void *arg)
{
    struct nvkms_timer_t *timer = arg;

    /* In softirq context, so schedule nvkms_taskqueue_callback(). */
    taskqueue_enqueue(taskqueue_nvkms, &timer->task);
}

static void
nvkms_init_timer(struct nvkms_timer_t *timer, nvkms_timer_proc_t *proc,
                 void *dataPtr, NvU32 dataU32, NvBool isRefPtr, NvU64 usec)
{
    timer->cancel = NV_FALSE;
    timer->complete = NV_FALSE;
    timer->isRefPtr = isRefPtr;

    timer->proc = proc;
    timer->dataPtr = dataPtr;
    timer->dataU32 = dataU32;

    TASK_INIT(&timer->task,
              0 /* priority */,
              nvkms_taskqueue_callback, (void *)timer);

    /*
     * After adding timer to timers_list we need to finish referencing it
     * (calling taskqueue_enqueue() or callout_reset()) before releasing
     * the lock. Otherwise, if the code to free the timer were ever updated to
     * run in parallel with this, it could race against nvkms_init_timer()
     * and free the timer before its initialization is complete.
     */
    sx_xlock(&nvkms_timers.lock);
    LIST_INSERT_HEAD(&nvkms_timers.list, timer, timers_list);

    if (usec == 0) {
        timer->callout_created = NV_FALSE;
        taskqueue_enqueue(taskqueue_nvkms, &timer->task);
    } else {
        /* CALLOUT_MPSAFE means that the callout handler is SMP-safe. */
        callout_init(&timer->callout, CALLOUT_MPSAFE);
        timer->callout_created = NV_TRUE;
        callout_reset(&timer->callout,
                      NVKMS_USECS_TO_TICKS(usec),
                      nvkms_callout_callback, (void *) timer);
    }
    sx_xunlock(&nvkms_timers.lock);
}

nvkms_timer_handle_t*
NVKMS_API_CALL nvkms_alloc_timer(nvkms_timer_proc_t *proc,
                                 void *dataPtr, NvU32 dataU32,
                                 NvU64 usec)
{
    // nvkms_alloc_timer cannot be called from an interrupt context.
    struct nvkms_timer_t *timer = nvkms_alloc(sizeof(*timer), NV_TRUE);
    if (timer) {
        nvkms_init_timer(timer, proc, dataPtr, dataU32, NV_FALSE, usec);
    }
    return timer;
}

NvBool NVKMS_API_CALL
nvkms_alloc_timer_with_ref_ptr(nvkms_timer_proc_t *proc,
                               struct nvkms_ref_ptr *ref_ptr,
                               NvU32 dataU32, NvU64 usec)
{
    // nvkms_alloc_timer_with_ref_ptr is called from an interrupt bottom half
    // handler.
    // TODO: Determine whether we really need to use M_NOWAIT here.
    struct nvkms_timer_t *timer = malloc(sizeof(*timer), M_NVIDIA_MODESET,
                                         M_NOWAIT | M_ZERO);
    if (timer) {
        // Reference the ref_ptr to make sure that it doesn't get freed before
        // the timer fires.
        nvkms_inc_ref(ref_ptr);
        nvkms_init_timer(timer, proc, ref_ptr, dataU32, NV_TRUE, usec);
    }

    return timer != NULL;
}

void NVKMS_API_CALL nvkms_free_timer(nvkms_timer_handle_t *handle)
{
    struct nvkms_timer_t *timer = handle;

    if (timer == NULL) {
        return;
    }

    if (timer->complete) {
        nvkms_free(timer, sizeof(*timer));
        return;
    }

    timer->cancel = NV_TRUE;
}

static void nvkms_suspend(NvU32 gpuId)
{
    sx_xlock(&nvkms_lock);
    nvKmsSuspend(gpuId);
    sx_xunlock(&nvkms_lock);
}

static void nvkms_resume(NvU32 gpuId)
{
    sx_xlock(&nvkms_lock);
    nvKmsResume(gpuId);
    sx_xunlock(&nvkms_lock);
}


/*************************************************************************
 * Interface with resman.
 *
 * Due to the global nvkms_lock, all NVKMS calls to RM are serialized,
 * so we can use a single nvidia_modeset_stack_ptr for calling RM.
 *************************************************************************/

static nvidia_modeset_rm_ops_t __rm_ops = { 0 };
static nvidia_modeset_stack_ptr nvkms_nvidia_stack = NULL;
static nvidia_modeset_callbacks_t nvkms_rm_callbacks = {
    nvkms_suspend,
    nvkms_resume
};

static int nvkms_alloc_rm(void)
{
    NV_STATUS nvstatus;
    int ret;

    printf("nvkms_alloc_rm: \n");
    __rm_ops.version_string = NV_VERSION_STRING;

    nvstatus = nvidia_get_rm_ops(&__rm_ops);

    if (nvstatus != NV_OK) {
        printf(NVKMS_LOG_PREFIX "Version mismatch: "
               "nvidia.ko(%s) nvidia-modeset.ko(%s)\n",
               __rm_ops.version_string, NV_VERSION_STRING);
        return EINVAL;
    }

    ret = __rm_ops.set_callbacks(&nvkms_rm_callbacks);
    if (ret < 0) {
        printf(NVKMS_LOG_PREFIX "Failed to register callbacks\n");
        return ret;
    }

    ret = __rm_ops.alloc_stack(&nvkms_nvidia_stack);
    printf("nvkms_alloc_rm:return: %d \n", ret);
    return ret;
}

static void nvkms_free_rm(void)
{
	printf("nvkms_free_rm:return:\n");
    __rm_ops.set_callbacks(NULL);
    if (__rm_ops.free_stack != NULL) {
        __rm_ops.free_stack(nvkms_nvidia_stack);
    }
}

void NVKMS_API_CALL nvkms_call_rm(void *ops)
{
	//printf("nvkms_call_rm:\n");
    __rm_ops.op(nvkms_nvidia_stack, ops);
}

void NVKMS_API_CALL nvkms_get_random(void *ptr, size_t size)
{
    arc4rand(ptr, size, 0);
}

/*
 * fget(9) was updated in FreeBSD 9.0 to take a cap_rights_t pointer.
 */
#if __FreeBSD_version >= 900000
  #define NV_FGET_HAS_CAP_RIGHTS_T_ARG 1
#else
  #define NV_FGET_HAS_CAP_RIGHTS_T_ARG 0
#endif

#if NV_FGET_HAS_CAP_RIGHTS_T_ARG
  #include <sys/caprights.h>
  #if __FreeBSD_version >= 1100012
    #include <sys/capsicum.h>
  #else
    #include <sys/capability.h>
  #endif
#endif

/*
 * There doesn't appear to be a clean API to retrieve the cdevpriv (as
 * set by devfs_set_cdevpriv(9)) of an arbitrary 'struct file', so
 * reach into the cdev_privdata.
 *
 * It would be nice if the kernel provided something like
 * devfs_get_cdevpriv_from_file() as proposed here:
 *
 * https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=201611
 */

#define NV_KERNEL_HAS_DEVFS_GET_CDEVPRIV_FROM_FILE 0

#if !NV_KERNEL_HAS_DEVFS_GET_CDEVPRIV_FROM_FILE
  #include <fs/devfs/devfs_int.h>
#endif

void* NVKMS_API_CALL nvkms_get_per_open_data(int fd)
{
    struct file *fp = NULL;
    struct nvkms_per_open *popen = NULL;
    int status;
    void *data = NULL;

#if NV_FGET_HAS_CAP_RIGHTS_T_ARG
    cap_rights_t rights;
    status = fget(curthread, fd, cap_rights_init(&rights, CAP_IOCTL), &fp);
#else
    status = fget(curthread, fd, &fp);
#endif

    if (status != 0) {
        return NULL;
    }

#if NV_KERNEL_HAS_DEVFS_GET_CDEVPRIV_FROM_FILE
    status = devfs_get_cdevpriv_from_file(&popen, fp);

    if (status != 0) {
        goto done;
    }
#else
    {
        struct cdev_privdata *p = fp->f_cdevpriv;

        /*
         * devfs_set_cdevpriv() assigns nvkms_close to
         * cdev_privdata::cdpd_dtr if this is an nvidia-modeset struct
         * file.
         */
        if ((p == NULL) || (p->cdpd_dtr != nvkms_close)) {
            goto done;
        }

        popen = p->cdpd_data;
    }
#endif

    if (popen == NULL) {
        goto done;
    }

    data = popen->data;

done:
    /*
     * If we reach here, fp is a valid struct file pointer, returned
     * by fget(9).
     *
     * fget(9) incremented the struct file's reference count, which
     * needs to be balanced with a call to fdrop(9).  It is safe to
     * decrement the reference count before returning the cdevpriv
     * value because core NVKMS is currently holding the nvkms_lock,
     * which prevents the nvkms_close() => nvKmsClose() call chain
     * from freeing the file out from under the caller of
     * nvkms_get_per_open_data().
     */
    fdrop(fp, curthread);

    return data;
}

NvBool NVKMS_API_CALL nvkms_open_gpu(NvU32 gpuId)
{
	printf("__rm_ops.open_gpu = 0x%x\n", (unsigned int)__rm_ops.open_gpu);
    int ret = __rm_ops.open_gpu(gpuId, nvkms_nvidia_stack);
    printf("nvkms_open_gpu:return: %d\n", ret);
    return ret == 0;
}

void NVKMS_API_CALL nvkms_close_gpu(NvU32 gpuId)
{
	printf("nvkms_close_gpu:\n");
    __rm_ops.close_gpu(gpuId, nvkms_nvidia_stack);
}

NvU32 NVKMS_API_CALL nvkms_enumerate_gpus(nv_gpu_info_t *gpu_info)
{
    int ret = __rm_ops.enumerate_gpus(gpu_info);
	printf("nvkms_enumerate_gpus:return: %d\n", ret);
    return ret;
}

NvBool NVKMS_API_CALL nvkms_allow_write_combining(void)
{
	printf("nvkms_allow_write_combining:\n");
    return __rm_ops.system_info.allow_write_combining;
}

/*************************************************************************
 * Common to both user-space and kapi NVKMS interfaces
 *************************************************************************/

static void nvkms_kapi_task_callback(void *arg, int pending __unused)
{
	struct NvKmsKapiDevice *device = arg;

	printf("nvkms_kapi_task_callback: device = 0x%lx\n", (unsigned long)device);
	nvKmsKapiHandleEventQueueChange(device);
}

/* 
 * a mirror of nvkms_open. Does the kernel space opening
 * - don't add character device 
 * - don't handle NVKMS_CLIENT_USER_SPACE (thats nvkms_open)
 * - doesn't do select, uses task queueing
 */
struct nvkms_per_open *nvkms_open_common(enum NvKmsClientType type,
                                         struct NvKmsKapiDevice *device,
                                         int *status)
{
    struct nvkms_per_open *popen = NULL;

    printf("nvkms_open_common:\n");
    popen = nvkms_alloc(sizeof(*popen), NV_TRUE);

    if (popen == NULL) {
        *status = -ENOMEM;
	printf("nvkms_open_common: nvkms_alloc failed\n");
        goto failed;
    }

    mtx_init(&popen->tasks.lock, "nvidia-modeset-tasks", NULL, MTX_DEF);

    sx_xlock(&nvkms_lock);
    popen->data = nvKmsOpen(curproc->p_pid, type, popen);
    sx_xunlock(&nvkms_lock);

    if (popen->data == NULL) {	    
        *status = -EPERM;
	printf("nvkms_open_common: nvKmsOpen failed\n");
        goto failed;
    }

    /* init and enqueue our new task */
    TASK_INIT(&popen->tasks.task, 0,
	      nvkms_kapi_task_callback, (void *)device);
    taskqueue_enqueue(taskqueue_thread, &popen->tasks.task);

    *status = 0;

    printf("nvkms_open_common: return 0x%x\n", (unsigned int)popen);
    return popen;

failed:

    nvkms_free(popen, sizeof(*popen));

    return NULL;
}

void NVKMS_API_CALL nvkms_close_common(struct nvkms_per_open *popen)
{
	printf("nvkms_close_common:\n");
    sx_xlock(&nvkms_lock);

    nvKmsClose(popen->data);

    popen->data = NULL;

    sx_xunlock(&nvkms_lock);

    /*
     * Flush any outstanding nvkms_kapi_task_callback() work
     * items before freeing popen.
     *
     * Note that this must be done after the above nvKmsClose() call, to
     * guarantee that no more nvkms_kapi_task_callback() work
     * items get scheduled.
     *
     * Also, note that though popen->data is freed above, any subsequent
     * nvkms_kapi_task_callback()'s for this popen should be
     * safe: if any nvkms_kapi_task_callback()-initiated work
     * attempts to call back into NVKMS, the popen->data==NULL check in
     * nvkms_ioctl_common() should reject the request.
     */

    taskqueue_drain(taskqueue_thread, &popen->tasks.task);
    mtx_destroy(&popen->tasks.lock);

    nvkms_free(popen, sizeof(*popen));
}

int NVKMS_API_CALL nvkms_ioctl_common
(
    struct nvkms_per_open *popen,
    NvU32 cmd, NvU64 address, const size_t size
)
{
    NvBool ret;

    printf("nvkms_ioctl_common: \n");
    sx_xlock(&nvkms_lock);

    if (popen && popen->data) {
        ret = nvKmsIoctl(popen->data, cmd, address, size);
    } else {
        ret = NV_FALSE;
    }

    sx_xunlock(&nvkms_lock);

    printf("nvkms_ioctl_common: return 0x%x\n", ret);
    return ret ? 0 : -EPERM;
}

/*************************************************************************
 * NVKMS interface for kernel space NVKMS clients like KAPI
 *************************************************************************/

struct nvkms_per_open* NVKMS_API_CALL nvkms_open_from_kapi
(
    struct NvKmsKapiDevice *device
)
{
	printf("nvkms_open_from_kapi: \n");
	int status = 0;
	struct nvkms_per_open *ret = nvkms_open_common(NVKMS_CLIENT_KERNEL_SPACE, device, &status);
	printf("nvkms_open_from_kapi:return: 0x%x\n", (unsigned int)ret);
	return ret;
}

void NVKMS_API_CALL nvkms_close_from_kapi(struct nvkms_per_open *popen)
{
	printf("nvkms_close_from_kapi: \n");
	nvkms_close_common(popen);
}

NvBool NVKMS_API_CALL nvkms_ioctl_from_kapi
(
    struct nvkms_per_open *popen,
    NvU32 cmd, void *params_address, const size_t params_size
)
{
	printf("nvkms_ioctl_from_kapi: \n");
	return nvkms_ioctl_common(popen,
                              cmd,
                              (NvU64)(NvUPtr)params_address, params_size) == 0;
}


/*************************************************************************
 * APIs for locking.
 *************************************************************************/
/* according to man mutexes on bsd are faster than semaphores */
struct nvkms_sema_t {
	struct mtx nvs_mutex;
};

nvkms_sema_handle_t* NVKMS_API_CALL nvkms_sema_alloc(void)
{
	printf("nvkms_sema_alloc:\n");
	nvkms_sema_handle_t *sema = nvkms_alloc(sizeof(nvkms_sema_handle_t), NV_TRUE);
	if (sema) {
		printf("nvkms_sema_alloc: creating mutex\n");
		mtx_init(&(sema->nvs_mutex), "NVIDIA Mutex", NULL, MTX_DEF);
	}

	printf("nvkms_sema_alloc:return: 0x%x\n", (unsigned int)sema);
	return sema;
}

void NVKMS_API_CALL nvkms_sema_free(nvkms_sema_handle_t *sema)
{
	printf("nvkms_sema_free:\n");
	mtx_destroy(&sema->nvs_mutex);
	nvkms_free(sema, sizeof(*sema));
}

void NVKMS_API_CALL nvkms_sema_down(nvkms_sema_handle_t *sema)
{
	printf("nvkms_sema_down:\n");
	mtx_lock(&sema->nvs_mutex);
}

void NVKMS_API_CALL nvkms_sema_up(nvkms_sema_handle_t *sema)
{
	printf("nvkms_sema_up:\n");
	mtx_unlock(&sema->nvs_mutex);
}

/*************************************************************************
 * NVKMS KAPI functions
 ************************************************************************/

NvBool NVKMS_KAPI_CALL nvKmsKapiGetFunctionsTable
(
    struct NvKmsKapiFunctionsTable *funcsTable
)
{
	printf("nvKmsKapiGetFunctionsTable:\n");
    return nvKmsKapiGetFunctionsTableInternal(funcsTable);
}

/*************************************************************************
 * File operation callback functions.
 *************************************************************************/

static void nvkms_close(void *arg)
{
    struct nvkms_per_open *popen = arg;

    sx_xlock(&nvkms_lock);
    nvKmsClose(popen->data);
    sx_xunlock(&nvkms_lock);

    mtx_destroy(&popen->events.lock);

    nvkms_free(popen, sizeof(*popen));

    sx_xlock(&nvkms_module.lock);
    nvkms_module.client_counter -= 1;
    sx_xunlock(&nvkms_module.lock);
}

static int nvkms_ioctl(
    struct cdev *dev,
    u_long cmd,
    caddr_t data,
    int fflag,
    struct thread *td
)
{
    u_long nr, size;
    NvBool ret;
    struct NvKmsIoctlParams *params;
    struct nvkms_per_open *popen;
    int status;

    status = devfs_get_cdevpriv((void **)&popen);
    if (status != 0) {
        return status;
    }

    size = IOCPARM_LEN(cmd);
    nr = cmd & 0xFF;

    /* The only supported ioctl is NVKMS_IOCTL_CMD. */

    if ((nr != NVKMS_IOCTL_CMD) || (size != sizeof(struct NvKmsIoctlParams))) {
        return EINVAL;
    }

    /* The OS already copied in the ioctl data. */

    params = (struct NvKmsIoctlParams*) data;

    sx_xlock(&nvkms_lock);
    ret = nvKmsIoctl(popen->data,
                     params->cmd,
                     params->address,
                     params->size);
    sx_xunlock(&nvkms_lock);

    return ret ? 0 : EPERM;
}

static int nvkms_open(
    struct cdev *dev,
    int oflags,
    int devtype,
    struct thread *td
)
{
	printf("nvkms_open:\n");
    struct nvkms_per_open *popen;
    int status;

    sx_xlock(&nvkms_module.lock);

    if (nvkms_module.is_unloading) {
        sx_xunlock(&nvkms_module.lock);
	printf("nvkms_open:return ENXIO\n");
        return ENXIO;
    }

    nvkms_module.client_counter += 1;
    sx_xunlock(&nvkms_module.lock);

    popen = nvkms_alloc(sizeof(*popen), NV_TRUE);
    if (popen == NULL) {
	    printf("nvkms_open:return ENNOMEM\n");
        return ENOMEM;
    }

    /*
     * Associate popen with the file open of the current process
     * context.  Register nvkms_close() to be called when the file
     * descriptor is closed.
     */
    status = devfs_set_cdevpriv(popen, nvkms_close);
    if (status != 0) {
        nvkms_free(popen, sizeof(*popen));
	printf("nvkms_open:return status = %d\n", status);
        return status;
    }

    mtx_init(&popen->events.lock, "nvkms-events-lock", NULL, 0);

    sx_xlock(&nvkms_lock);
    popen->data = nvKmsOpen(curproc->p_pid, NVKMS_CLIENT_USER_SPACE, popen);
    sx_xunlock(&nvkms_lock);

    /*
     * If nvkms_open() fails, the file descriptor will be closed, and
     * nvkms_close() will be called to free popen.
     */
    printf("nvkms_open:return: %d\n", (popen->data == NULL) ? EPERM : 0);
    return (popen->data == NULL) ? EPERM : 0;
}

static int nvkms_poll(
    struct cdev *dev,
    int events,
    struct thread *td
)
{
    struct nvkms_per_open *popen;
    int status;
    int mask = 0;

    status = devfs_get_cdevpriv((void **)&popen);
    if (status != 0) {
        return 0;
    }

    mtx_lock(&popen->events.lock);

    if (!popen->events.available) {
        selrecord(td, &popen->events.select);
    } else {
        mask = (events & (POLLIN | POLLPRI | POLLRDNORM));
    }

    mtx_unlock(&popen->events.lock);

    return mask;
}


/*************************************************************************
 * Linux compatibility support.
 *
 * Register the the linux compatiblity ioctl handler function, and the
 * range of ioctls, with the linux compatibility layer.
 *************************************************************************/

#if defined(NVKMS_SUPPORT_LINUX_COMPAT)

static int nvkms_linux_ioctl_function(
    struct thread *td,
    struct linux_ioctl_args *args
)
{
    struct file *fp;
    int status;
    u_long cmd;

#if NV_FGET_HAS_CAP_RIGHTS_T_ARG
    cap_rights_t rights;
    status = fget(td, args->fd, cap_rights_init(&rights, CAP_IOCTL), &fp);
#else
    status = fget(td, args->fd, &fp);
#endif

    if (status != 0) {
        return status;
    }

    cmd = args->cmd;

    status = fo_ioctl(fp, cmd, (caddr_t)args->arg, td->td_ucred, td);
    fdrop(fp, td);

    return status;
}

#define NVKMS_LINUX_IOCTL_MIN _IOC(0, NVKMS_IOCTL_MAGIC, NVKMS_IOCTL_CMD, 0)
#define NVKMS_LINUX_IOCTL_MAX NVKMS_LINUX_IOCTL_MIN

static struct linux_ioctl_handler nvkms_linux_ioctl_handler = {
    nvkms_linux_ioctl_function,
    NVKMS_LINUX_IOCTL_MIN,
    NVKMS_LINUX_IOCTL_MAX,
};
#endif

static void nvkms_linux_compat_load(void)
{
#if defined(NVKMS_SUPPORT_LINUX_COMPAT)
    linux_ioctl_register_handler(&nvkms_linux_ioctl_handler);
#endif
}

static void nvkms_linux_compat_unload(void)
{
#if defined(NVKMS_SUPPORT_LINUX_COMPAT)
    linux_ioctl_unregister_handler(&nvkms_linux_ioctl_handler);
#endif
}

/*************************************************************************
 * Module loading support code.
 *************************************************************************/

static struct cdevsw nvkms_cdevsw = {
    .d_open =      nvkms_open,
    .d_ioctl =     nvkms_ioctl,
    .d_poll =      nvkms_poll,
    .d_name =      "nvidia-modeset",
    .d_version =   D_VERSION,
};

static int
nvidia_modeset_loader(struct module *m, int what, void *arg)
{
    int ret;

    /*
     * nvkms_dev is static, so that its value is preserved across
     * nvidia_modeset_loader(MOD_LOAD) and
     * nvidia_modeset_loader(MOD_UNLOAD) calls.
     */
    static struct cdev *nvkms_dev;
    /*
     * FreeBSD calls MOD_UNLOAD if MOD_LOAD fails. To avoid problems
     * with referencing uninitialized structures we create
     * nvkms_module_loaded static variable which indicates whether we
     * succeeded during MOD_LOAD.
     */
    static NvBool nvkms_module_loaded = NV_FALSE;
    struct nvkms_timer_t *timer, *tmp;

    switch (what) {
    case MOD_LOAD:
        ret = nvkms_alloc_rm();

        if (ret != 0) {
            return ret;
        }

        sx_init(&nvkms_lock, "nvidia-modeset lock");
        sx_init(&nvkms_module.lock, "nvidia-modeset module data lock");
        nvkms_module.client_counter = 0;
        nvkms_module.is_unloading = NV_FALSE;

        LIST_INIT(&nvkms_timers.list);
        sx_init(&nvkms_timers.lock, "nvidia-modeset timer lock");

        nvkms_dev = make_dev(&nvkms_cdevsw,
                             NVKMS_CDEV_MINOR,
                             UID_ROOT, GID_WHEEL, 0666,
                             "nvidia-modeset");

        if (nvkms_dev == NULL) {
            sx_destroy(&nvkms_module.lock);
            sx_destroy(&nvkms_timers.lock);
            sx_destroy(&nvkms_lock);

            nvkms_free_rm();
            return ENOMEM;
        }

        /*  MOD_LOAD succeeded */
        nvkms_module_loaded = NV_TRUE;

        sx_xlock(&nvkms_lock);
        nvKmsModuleLoad();
        sx_xunlock(&nvkms_lock);

        nvkms_linux_compat_load();

        return 0;

    case MOD_QUIESCE:
        if (!nvkms_module_loaded) {
            return 0;
        }

        sx_xlock(&nvkms_module.lock);

        if (nvkms_module.client_counter > 0) {
            sx_xunlock(&nvkms_module.lock);
            return EBUSY;
        }

        sx_xunlock(&nvkms_module.lock);

        return 0;

    case MOD_UNLOAD:
    case MOD_SHUTDOWN:
        if (!nvkms_module_loaded) {
            return 0;
        }

        sx_xlock(&nvkms_module.lock);

        if (nvkms_module.client_counter > 0) {
            sx_xunlock(&nvkms_module.lock);
            return EBUSY;
        }

        nvkms_module.is_unloading = NV_TRUE;

        sx_xunlock(&nvkms_module.lock);

        nvkms_linux_compat_unload();

        sx_xlock(&nvkms_lock);
        nvKmsModuleUnload();
        sx_xunlock(&nvkms_lock);

        /*
         * At this point, any pending tasks should be marked canceled,
         * but we still need to drain them, so that
         * nvkms_taskqueue_callback() doesn't get called after the
         * module is unloaded.
         */
        sx_xlock(&nvkms_timers.lock);

        LIST_FOREACH_SAFE(timer, &nvkms_timers.list, timers_list, tmp) {
            if (timer->callout_created) {
                /*
                 * We delete pending timers and check whether it was being executed
                 * (returns 0) or we have deactivated it before execution (returns >0).
                 * If it began execution, the taskqueue callback will wait for callout
                 * completion, and we wait for taskqueue completion with
                 * taskqueue_run below.
                 */
                if (callout_drain(&timer->callout) > 0) {
                    /*  We've deactivated timer so we need to clean after it */
                    LIST_REMOVE(timer, timers_list);
                    if (timer->isRefPtr) {
                        nvkms_dec_ref(timer->dataPtr);
                    }
                    nvkms_free(timer, sizeof(*timer));
                }
            }
        }

        sx_xunlock(&nvkms_timers.lock);

        taskqueue_run(taskqueue_nvkms);

        destroy_dev(nvkms_dev);
        nvkms_dev = NULL;

        sx_destroy(&nvkms_module.lock);
        sx_destroy(&nvkms_timers.lock);
        sx_destroy(&nvkms_lock);

        nvkms_free_rm();
        return 0;

    default:
        break;
    }

    return EOPNOTSUPP;
}

static moduledata_t nvidia_modeset_moduledata = {
    "nvidia-modeset",       /* module name */
    nvidia_modeset_loader,  /* load/unload notification */
    NULL                    /* extra data */
};

DECLARE_MODULE(nvidia_modeset,              /* module name */
               nvidia_modeset_moduledata,   /* moduledata_t */
               SI_SUB_DRIVERS,              /* subsystem */
               SI_ORDER_ANY);               /* initialization order */

MODULE_VERSION(nvidia_modeset, 1);

MODULE_DEPEND(nvidia_modeset,               /* module name */
              nvidia,                       /* prerequisite module */
              1, 1, 1);                     /* vmin, vpref, vmax */

#if defined(NVKMS_SUPPORT_LINUX_COMPAT)
MODULE_DEPEND(nvidia_modeset,               /* module name */
              linux,                        /* prerequisite module */
              1, 1, 1);                     /* vmin, vpref, vmax */
#endif
