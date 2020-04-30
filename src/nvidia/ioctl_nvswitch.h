/*******************************************************************************
    Copyright (c) 2017-2018 NVidia Corporation

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

#ifndef _IOCTL_NVSWITCH_H_
#define _IOCTL_NVSWITCH_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * This file defines IOCTL calls that work with nvidia-nvswitchctl
 * (device agnostic) node.
 */

#define NVSWITCH_DEV_IO_TYPE 'd'
#define NVSWITCH_CTL_IO_TYPE 'c'

/*
 * NVSwitch version consists of,
 *   major - no compatibility.
 *   minor - only backwards compatible.
 */
typedef struct
{
    NvU32 major;
    NvU32 minor;
    /* This is an immutable struct. Do not change */
} NVSWITCH_VERSION;

/*
 * NVSWITCH_CTL_CHECK_VERSION
 *
 * The interface will check if the client's version is supported by the driver.
 *
 * Parameters:
 * user[in]
 *    Version of the interface that the client is compiled with.
 * kernel[out]
 *    Version of the interface that the kernel driver is compiled with.
 * is_compatible[out]
 *    Set to true, if user and kernel version are compatible.
 */
typedef struct
{
    NVSWITCH_VERSION user;
    NVSWITCH_VERSION kernel;
    NvBool is_compatible;
    /* This is an immutable struct. Do not change */
} NVSWITCH_CHECK_VERSION_PARAMS;

/*
 * Max devices supported by the driver
 *
 * See ctrl_dev_nvswitch.h for preprocessor definition modification guidelines.
 */
#define NVSWITCH_MAX_DEVICES 64

/*
 * NVSWITCH_CTL_GET_DEVICES
 *
 * Provides information about registered NvSwitch devices.
 *
 * Parameters:
 * deviceInstance[out]
 *    Device instance of the device. This is same as the device minor number
 *    for Linux platforms.
 */
typedef struct
{
    NvU32 deviceInstance;
    NvU32 pciDomain;
    NvU32 pciBus;
    NvU32 pciDevice;
    NvU32 pciFunction;
    /* See ctrl_dev_nvswitch.h for struct definition modification guidelines */
} NVSWITCH_DEVICE_INSTANCE_INFO;

typedef struct
{
    NvU32 deviceCount;
    NVSWITCH_DEVICE_INSTANCE_INFO info[NVSWITCH_MAX_DEVICES];
    /* See ctrl_dev_nvswitch.h for struct definition modification guidelines */
} NVSWITCH_GET_DEVICES_PARAMS;

#define CTRL_NVSWITCH_GET_DEVICES         0x01
#define CTRL_NVSWITCH_CHECK_VERSION       0x02

/*
 * Nvswitchctl (device agnostic) IOCTLs
 */

#define IOCTL_NVSWITCH_GET_DEVICES \
    _IOR(NVSWITCH_CTL_IO_TYPE, CTRL_NVSWITCH_GET_DEVICES, NVSWITCH_GET_DEVICES_PARAMS)
#define IOCTL_NVSWITCH_CHECK_VERSION \
    _IOWR(NVSWITCH_CTL_IO_TYPE, CTRL_NVSWITCH_CHECK_VERSION, NVSWITCH_CHECK_VERSION_PARAMS)

#ifdef __cplusplus
}
#endif

#endif //_IOCTL_NVSWITCH_H_
