/*++

          ##     ## ######## ##     ## ########
          ##     ## ##       ##     ## ##     ##
          ##     ## ##       ##     ## ##     ##
          ######### ######   ##     ## ##     ##
          ##     ## ##        ##   ##  ##     ##
          ##     ## ##         ## ##   ##     ##
          ##     ## ########    ###    ########

            HackSys Extreme Vulnerable Driver

Author : Ashfaq Ansari
Contact: ashfaq[at]hacksys[dot]io
Website: https://hacksys.io/

Copyright (C) 2021-2023 HackSys Inc. All rights reserved.
Copyright (C) 2015-2020 Payatu Software Labs LLP. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version
3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See the file 'LICENSE' for complete copying permission.

Module Name:
    HackSysExtremeVulnerableDriver.h

Abstract:
    This module implements the data structures for main
    driver module.

--*/

#pragma once

#ifndef __HACKSYS_EXTREME_VULNERABLE_DRIVER_H__
#define __HACKSYS_EXTREME_VULNERABLE_DRIVER_H__

#include "Common.h"


/**
 * Defines
 */

#define BANNER \
         "                                        \n" \
         " ##     ## ######## ##     ## ########  \n" \
         " ##     ## ##       ##     ## ##     ## \n" \
         " ##     ## ##       ##     ## ##     ## \n" \
         " ######### ######   ##     ## ##     ## \n" \
         " ##     ## ##        ##   ##  ##     ## \n" \
         " ##     ## ##         ## ##   ##     ## \n" \
         " ##     ## ########    ###    ########  \n" \
         "   HackSys Extreme Vulnerable Driver    \n" \
         "             Version: 4.00              \n"

#define IOCTL(NUM) _IOWR('h', NUM, struct hevd_io)


/**
 * IOCTL Definitions 
 */

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                IOCTL(0)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS             IOCTL(1)
#define HEVD_IOCTL_ARBITRARY_WRITE                      IOCTL(2)
#define HEVD_IOCTL_BUFFER_OVERFLOW_KERNEL_HEAP          IOCTL(3)
#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_KERNEL_HEAP      IOCTL(4)
#define HEVD_IOCTL_USE_UAF_OBJECT_KERNEL_HEAP           IOCTL(5)
#define HEVD_IOCTL_FREE_UAF_OBJECT_KERNEL_HEAP          IOCTL(6)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_KERNEL_HEAP     IOCTL(7)
#define HEVD_IOCTL_TYPE_CONFUSION                       IOCTL(8)
#define HEVD_IOCTL_INTEGER_OVERFLOW                     IOCTL(9)
#define HEVD_IOCTL_NULL_POINTER_DEREFERENCE             IOCTL(0xA)
#define HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK           IOCTL(0xB)
#define HEVD_IOCTL_UNINITIALIZED_MEMORY_KERNEL_HEAP     IOCTL(0xC)
#define HEVD_IOCTL_DOUBLE_FETCH                         IOCTL(0xD)
//#define HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS        IOCTL(0x80E)
#define HEVD_IOCTL_MEMORY_DISCLOSURE_KERNEL_HEAP        IOCTL(0xF)
//#define HEVD_IOCTL_BUFFER_OVERFLOW_PAGED_POOL_SESSION IOCTL(0x810)
#define HEVD_IOCTL_WRITE_NULL                           IOCTL(0x11)
//#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX             IOCTL(0x812)
//#define HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX           IOCTL(0x813)
//#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX         IOCTL(0x814)
//#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL_NX              IOCTL(0x815)
//#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL_NX             IOCTL(0x816)
//#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL_NX        IOCTL(0x817)
//#define HEVD_IOCTL_CREATE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX    IOCTL(0x818)
//#define HEVD_IOCTL_SET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX  IOCTL(0x819)
//#define HEVD_IOCTL_GET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX  IOCTL(0x81A)
//#define HEVD_IOCTL_DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX    IOCTL(0x81B)


/**
 * Function Definitions
 */

static int __init hevd_init(void);
static void __exit hevd_exit(void);
static long hevd_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif  // !__HACKSYS_EXTREME_VULNERABLE_DRIVER_H__
