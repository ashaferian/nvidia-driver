/*******************************************************************************
    Copyright (c) 2016 NVidia Corporation

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

/*!
 * @file   nvswitch_freebsd.c
 * @brief  NVSwitch driver kernel interface.
 *         TODO: Implement stubs. 
 */

#include "nvlink_common.h"
#include "export_nvswitch.h"

NvU64 NVLINK_API_CALL
nvswitch_os_get_platform_time
(
    void
)
{
    return 0ULL;
}

void NVLINK_API_CALL
nvswitch_os_print
(
    const int  log_level,
    const char *fmt,
    ...
)
{
    return;
}

NvlStatus NVLINK_API_CALL
nvswitch_os_read_registry_dword
(
    void *os_handle,
    const char *name,
    NvU32 *data
)
{
    return -1;
}

void NVLINK_API_CALL
nvswitch_os_override_platform
(
    void *os_handle,
    NvBool *rtlsim
)
{
    return;
}

NvU32 NVLINK_API_CALL
nvswitch_os_get_device_count
(
    void
)
{
    return 0;
}
