/*******************************************************************************
    Copyright (c) 2016-2019 NVidia Corporation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be
        included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*******************************************************************************/


#ifndef _NVSWITCH_EXPORT_H_
#define _NVSWITCH_EXPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "nvlink_common.h"

#define NVSWITCH_DRIVER_NAME            "nvidia-nvswitch"

#define NVSWITCH_MAX_BARS               1

#define NVSWITCH_DEVICE_INSTANCE_MAX    64

#define PCI_CLASS_BRIDGE_NVSWITCH       0x0680

#ifndef PCI_VENDOR_ID_NVIDIA
#define PCI_VENDOR_ID_NVIDIA            0x10DE
#endif

#define PCI_ADDR_OFFSET_VENDOR          0
#define PCI_ADDR_OFFSET_DEVID           2

#define NVSWITCH_NSEC_PER_SEC           1000000000ULL

#define NVSWITCH_DBG_LEVEL_MMIO         0x0
#define NVSWITCH_DBG_LEVEL_INFO         0x1
#define NVSWITCH_DBG_LEVEL_SETUP        0x2
#define NVSWITCH_DBG_LEVEL_WARN         0x3
#define NVSWITCH_DBG_LEVEL_ERROR        0x4

#define NVSWITCH_DMA_DIR_TO_SYSMEM      0
#define NVSWITCH_DMA_DIR_FROM_SYSMEM    1
#define NVSWITCH_DMA_DIR_BIDIRECTIONAL  2

typedef struct nvswitch_device nvswitch_device;

/*
 * @Brief : The interface will check if the client's version is supported by the
 *          driver.
 *
 * @param[in] user_major     Major version of the interface that the client is
 *                           compiled with.
 * @param[in] user_minor     Minor version of the interface that the client is
 *                           compiled with.
 * @param[out] kennel_major  Major version of the interface that the kernel
 *                           driver is compiled with. This information will be
 *                           filled even if the CTRL call returns
 *                           -NVL_ERR_NOT_SUPPORTED due to version mismatch.
 * @param[out] kennel_minor  Minor version of the interface that the kernel
 *                           driver is compiled with. This information will be
 *                           filled even if the CTRL call returns
 *                           -NVL_ERR_NOT_SUPPORTED due to version mismatch.
 *
 * @returns                  NVL_SUCCESS if the client is using compatible
 *                           interface.
 *                           -NVL_ERR_NOT_SUPPORTED if the client is using
 *                           incompatible interface.
 *                           Or, Other NVL_XXX status value.
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_check_api_version
(
    NvU32 user_major,
    NvU32 user_minor,
    NvU32 *kernel_major,
    NvU32 *kernel_minor
);

/*
 * @Brief : Allocate a new nvswitch lib device instance.
 *
 * @Description : Creates and registers a new nvswitch device and registers
 *   with the nvlink library.  This only initializes software state,
 *   it does not initialize the hardware state.
 *
 * @param[in] pci_domain    pci domain of the device
 * @param[in] pci_bus       pci bus of the device
 * @param[in] pci_device    pci device of the device
 * @param[in] pci_func      pci function of the device
 * @param[in] device_id     pci device ID of the device
 * @param[in] os_handle     Device handle used to interact with OS layer
 * @param[in] os_instance   instance number of this device
 * @param[out] device       return device handle for interfacing with library
 *
 * @returns                 NVL_SUCCESS if the action succeeded
 *                          an NVL error code otherwise
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_register_device
(
    NvU16 pci_domain,
    NvU8 pci_bus,
    NvU8 pci_device,
    NvU8 pci_func,
    NvU16 device_id,
    void *os_handle,
    NvU32 os_instance,
    nvswitch_device **device
);

/*
 * @Brief : Clean-up the software state for a nvswitch device.
 *
 * @Description :
 *
 * @param[in] device        device handle to destroy
 *
 * @returns                 none
 */
void NVLINK_API_CALL
nvswitch_lib_unregister_device
(
    nvswitch_device *device
);

/*
 * @Brief : Initialize the hardware for a nvswitch device.
 *
 * @Description :
 *
 * @param[in] device        a reference to the device to initialize
 *
 * @returns                 NVL_SUCCESS if the action succeeded
 *                          -NVL_BAD_ARGS if bad arguments provided
 *                          -NVL_PCI_ERROR if bar info unable to be retrieved
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_initialize_device
(
    nvswitch_device *device
);

/*
 * @Brief : Shutdown the hardware for a nvswitch device.
 *
 * @Description :
 *
 * @param[in] device        a reference to the device to initialize
 *
 * @returns                 NVL_SUCCESS if the action succeeded
 *                          -NVL_BAD_ARGS if bad arguments provided
 *                          -NVL_PCI_ERROR if bar info unable to be retrieved
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_shutdown_device
(
    nvswitch_device *device
);

/*
 * @Brief Control call (ioctl) interface.
 *
 * @param[in] device        device to operate on
 * @param[in] cmd           Enumerated command to execute.
 * @param[in] params        Params structure to pass to the command.
 * @param[in] params_size   Size of the parameter structure.
 *
 * @return                  NVL_SUCCESS on a successful command
 *                          -NVL_NOT_FOUND if target device unable to be found
 *                          -NVL_BAD_ARGS if an invalid cmd is provided
 *                          -NVL_BAD_ARGS if a null arg is provided
 *                          -NVL_ERR_GENERIC otherwise
 */
NvlStatus NVLINK_API_CALL nvswitch_lib_ctrl
(
    nvswitch_device *device,
    NvU32 cmd,
    void *params,
    NvU64 size
);

/*
 * @Brief: Retrieve PCI information for a switch based from device instance
 *
 * @Description :
 *
 * @param[in]  lib_handle   device to query
 * @param[out] pciInfo      return pointer to nvswitch lib copy of device info
 */
void NVLINK_API_CALL nvswitch_lib_get_device_info
(
    nvswitch_device *lib_handle,
    struct nvlink_pci_info **pciInfo
);

/*
 * @Brief: Load platform information (emulation, simulation etc.).
 *
 * @param[in]  lib_handle   device
 *
 * @return                  NVL_SUCCESS on a successful command
 *                          -NVL_BAD_ARGS if an invalid device is provided
 */
NvlStatus NVLINK_API_CALL nvswitch_lib_load_platform_info
(
    nvswitch_device *lib_handle
);

/*
 * @Brief : Enable interrupts for this device
 *
 * @Description :
 *
 * @param[in] device        device to enable
 *
 * @returns                 NVL_SUCCESS
 *                          -NVL_PCI_ERROR if there was a register access error
 */
void NVLINK_API_CALL
nvswitch_lib_enable_interrupts
(
    nvswitch_device *device
);

/*
 * @Brief : Disable interrupts for this device
 *
 * @Description :
 *
 * @param[in] device        device to enable
 *
 * @returns                 NVL_SUCCESS
 *                          -NVL_PCI_ERROR if there was a register access error
 */
void NVLINK_API_CALL
nvswitch_lib_disable_interrupts
(
    nvswitch_device *device
);

/*
 * @Brief : Check if interrupts are pending on this device
 *
 * @Description :
 *
 * @param[in] device        device to check
 *
 * @returns                 NVL_SUCCESS if there were no errors and interrupts were handled
 *                          -NVL_BAD_ARGS if bad arguments provided
 *                          -NVL_PCI_ERROR if there was a register access error
 *                          -NVL_MORE_PROCESSING_REQUIRED no interrupts were found for this device
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_check_interrupts
(
    nvswitch_device *device
);

/*
 * @Brief : Services interrupts for this device
 *
 * @Description :
 *
 * @param[in] device        device to service
 *
 * @returns                 NVL_SUCCESS if there were no errors and interrupts were handled
 *                          -NVL_BAD_ARGS if bad arguments provided
 *                          -NVL_PCI_ERROR if there was a register access error
 *                          -NVL_MORE_PROCESSING_REQUIRED no interrupts were found for this device
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_service_interrupts
(
    nvswitch_device *device
);

/*
 * @Brief : Get depth of error logs
 *
 * @Description :
 *
 * @param[in]  device       device to check
 *
 * @param[out] fatal        Count of fatal errors
 * @param[out] nonfatal     Count of non-fatal errors
 *
 * @returns                 NVL_SUCCESS if there were no errors and interrupts were handled
 *                          -NVL_NOT_FOUND if bad arguments provided
 */
NvlStatus NVLINK_API_CALL
nvswitch_lib_get_log_count
(
    nvswitch_device *device,
    NvU32 *fatal, NvU32 *nonfatal
);

/*
 * @Brief : Periodic thread-based dispatcher for kernel functions
 *
 * @Description : Its purpose is to do any background subtasks (data collection, thermal
 * monitoring, etc.  These subtasks may need to run at varying intervals, and
 * may even wish to adjust their execution period based on other factors.
 * Each subtask's entry notes the last time it was executed and its desired
 * execution period.  This function returns back to the dispatcher the desired
 * time interval before it should be called again.
 *
 * @param[in] device          The device to run background tasks on
 *
 * @returns nsec interval to wait before the next call.
 */
NvU64 NVLINK_API_CALL
nvswitch_lib_deferred_task_dispatcher
(
    nvswitch_device *device
);

/*
 * @Brief : Perform post init tasks 
 *
 * @Description : Any device initialization/tests which need the device to be
 * initialized to a sane state go here.
 *
 * @param[in] device    The device to run the post-init on
 *
 * @returns             void
 */
void NVLINK_API_CALL
nvswitch_lib_post_init_device
(
    nvswitch_device *device
);

/*
 * @Brief : Validates PCI device id
 *
 * @Description : Validates PCI device id
 *
 * @param[in] device    The device id to be validated
 *
 * @returns             True if device id is valid
 */
NvBool NVLINK_API_CALL
nvswitch_lib_validate_device_id
(
    NvU32 device_id
);

/*
 * Returns count of registered NvSwitch devices.
 */
NvU32 NVLINK_API_CALL
nvswitch_os_get_device_count
(
    void
);

/*
 * Get current time in nanoseconds
 * The time is since epoch time (midnight UTC of January 1, 1970)
 */
NvU64 NVLINK_API_CALL
nvswitch_os_get_platform_time
(
    void
);

/*
 * printf wrapper
 */
void NVLINK_API_CALL
__attribute__ ((format (printf, 2, 3)))
nvswitch_os_print
(
    int         log_level,
    const char *pFormat,
    ...
);

/*
 * "Registry" interface for dword
 */
NvlStatus NVLINK_API_CALL
nvswitch_os_read_registry_dword
(
    void *os_handle,
    const char *name,
    NvU32 *data
);

/*
 * "Registry" interface for binary data
 */
NvlStatus NVLINK_API_CALL
nvswitch_os_read_registery_binary
(
    void *os_handle,
    const char *name,
    NvU8 *data,
    NvU32 length
);

/*
 * Override platform/simulation settings for cases
 */
void
NVLINK_API_CALL
nvswitch_os_override_platform
(
    void *os_handle,
    NvBool *rtlsim
);

#ifdef __cplusplus
}
#endif

NvlStatus
NVLINK_API_CALL
nvswitch_os_alloc_contig_memory
(
    void **virt_addr,
    NvU32 size,
    NvBool force_dma32
);

void
NVLINK_API_CALL
nvswitch_os_free_contig_memory
(
    void *virt_addr
);

NvlStatus
NVLINK_API_CALL
nvswitch_os_map_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 *dma_handle,
    NvU32 size,
    NvU32 direction
);

NvlStatus
NVLINK_API_CALL
nvswitch_os_unmap_dma_region
(
    void *os_handle,
    void *cpu_addr,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
);

NvlStatus
NVLINK_API_CALL
nvswitch_os_set_dma_mask
(
    void *os_handle,
    NvU32 dma_addr_width
);

NvlStatus
NVLINK_API_CALL
nvswitch_os_sync_dma_region_for_cpu
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
);

NvlStatus
NVLINK_API_CALL
nvswitch_os_sync_dma_region_for_device
(
    void *os_handle,
    NvU64 dma_handle,
    NvU32 size,
    NvU32 direction
);

#endif //_NVSWITCH_EXPORT_H_
